use crate::constants;
use crate::data::{Transaction, TransactionInclusionProof};
use crate::libernet;
use crate::smt;
use crate::store::{EmptyHeaderData, MappedHashSet, NodeData, Stored, StoredHeap, StoredU64};
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::merkle;
use ff::Field;
use memmap2::MmapMut;
use prost::Message;

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
struct GlobalTransactionIndex {
    index: StoredU64,
}

impl GlobalTransactionIndex {
    fn index(&self) -> usize {
        self.index.to_u64() as usize
    }
}

impl Stored for GlobalTransactionIndex {}

impl NodeData for GlobalTransactionIndex {
    fn hash(&self) -> Scalar {
        // TODO: make `MappedHashSet` tolerant to this.
        // Essentially it means we can only insert by `insert_hashed` and not `insert`, but we need
        // to formalize it in the API.
        unimplemented!()
    }
}

type TransactionForest = smt::Forest<2, 32>;
type TransactionIndices = MappedHashSet<EmptyHeaderData, GlobalTransactionIndex>;
type TransactionHeap = StoredHeap<EmptyHeaderData>;

/// Iterates over the transactions of a block.
///
/// Instances are constructed by `TransactionStore::iter`.
#[derive(Debug)]
pub struct TransactionIterator<'a> {
    parent: &'a TransactionStore,
    version: usize,
    index: usize,
    index_back: Option<usize>,
}

impl<'a> TransactionIterator<'a> {
    fn new(parent: &'a TransactionStore, version: usize) -> Self {
        Self {
            parent,
            version,
            index: 0,
            index_back: None,
        }
    }

    fn lookup_transaction(
        &self,
        proof: merkle::Proof<Scalar, Scalar, 2, 32>,
    ) -> Result<TransactionInclusionProof> {
        let transaction_hash = *proof.value();
        let heap_index = self
            .parent
            .indices
            .get(transaction_hash)
            .context("transaction not found")?;
        let bytes = self.parent.heap.get(heap_index.index());
        let proto = libernet::Transaction::decode(bytes)?;
        let transaction = Transaction::from_proto_verify(proto)?;
        Ok(proof.map(transaction).unwrap())
    }
}

impl<'a> Iterator for TransactionIterator<'a> {
    type Item = Result<TransactionInclusionProof>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(index_back) = self.index_back {
            if self.index > index_back {
                return None;
            }
        }
        let proof = match self.parent.forest.get_proof(
            self.parent.root_hash(self.version),
            Scalar::from(self.index as u64),
        ) {
            Some(proof) => proof,
            None => {
                return Some(Err(anyhow!("invalid root hash")));
            }
        };
        let transaction_hash = *proof.value();
        if transaction_hash == Scalar::ZERO {
            return None;
        }
        self.index += 1;
        Some(self.lookup_transaction(proof))
    }
}

impl<'a> DoubleEndedIterator for TransactionIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let mut index = match self.index_back {
            Some(index) => index,
            None => {
                let index = self.parent.get_size(self.version).unwrap();
                self.index_back = Some(index);
                index
            }
        };
        if index <= self.index {
            return None;
        }
        index -= 1;
        self.index_back = Some(index);
        let proof = match self.parent.forest.get_proof(
            self.parent.root_hash(self.version),
            Scalar::from(index as u64),
        ) {
            Some(proof) => proof,
            None => {
                return Some(Err(anyhow!("invalid root hash")));
            }
        };
        Some(self.lookup_transaction(proof))
    }
}

/// Stores transactions.
///
/// Each block has a Merkle tree of included transactions. The tree is binary and keyed by
/// transaction number within the block (ie. 0 for the first transaction of the block, 1 for the
/// second, etc.), with a height of 32. That assumes a block can have at most 2^32 transactions.
///
/// Transactions don't have a fixed size, not even if they are of the same type (for example,
/// `CreateProgram` transactions contain WASM ASTs of arbitrary sizes), so we use a `StoredHeap` to
/// store the actual signed transaction protobufs.
///
/// `StoredHeap` elements are addressed by their incremental index, so we associate heap indices to
/// their respective transaction hashes in the TransactionIndices data structure, which is a
/// `MappedHashSet`.
///
/// The actual forest of Merkle trees (one tree for each block) is managed by the
/// `TransactionForest` data structure. The leaves of a `TransactionForest` are transaction hashes.
#[derive(Debug)]
pub struct TransactionStore {
    forest: TransactionForest,
    indices: TransactionIndices,
    heap: TransactionHeap,
    root_hashes: Vec<Scalar>,
    next_index: usize,
}

impl TransactionStore {
    /// Constructs a new empty `TransactionStore`.
    pub fn default() -> Result<Self> {
        let forest = smt::Forest::new(
            MmapMut::map_anon(
                TransactionForest::PADDED_HEADER_SIZE
                    + TransactionForest::optimal_initial_capacity()
                        * TransactionForest::padded_node_size(),
            )?,
            constants::DATA_FILE_TYPE_TRANSACTION_FOREST,
            Box::new(smt::NoopExternalNodeManager::default()),
            Scalar::ZERO,
        )?;
        let indices = TransactionIndices::default(constants::DATA_FILE_TYPE_TRANSACTION_INDICES)?;
        let heap = StoredHeap::default(constants::DATA_FILE_TYPE_TRANSACTION_HEAP)?;
        let root_hashes = vec![forest.empty_root_hash()];
        Ok(Self {
            forest,
            indices,
            heap,
            root_hashes,
            next_index: 0,
        })
    }

    /// Returns the current version number.
    pub fn current_version(&self) -> usize {
        self.root_hashes.len() - 1
    }

    /// Returns the Merkle root hash at the specified revision.
    ///
    /// REQUIRES: `version` must be less than or equal to `current_version()`.
    pub fn root_hash(&self, version: usize) -> Scalar {
        self.root_hashes[version]
    }

    /// Returns the Merkle root hash at the current version.
    pub fn current_root_hash(&self) -> Scalar {
        self.root_hashes[self.root_hashes.len() - 1]
    }

    /// Returns the number of transactions in the current version.
    ///
    /// This gets incremented by 1 at every push and reset to zero at every commit.
    pub fn size(&self) -> usize {
        self.next_index
    }

    /// Returns the number of transactions in an arbitrary revision.
    ///
    /// This algorithm runs in O(log(N)) and works by performing a search for the first null
    /// transaction hash in the SMT for the specified version.
    pub fn get_size(&self, version: usize) -> Result<usize> {
        let root_hash = self.root_hash(version);
        let hash = self
            .forest
            .get(root_hash, Scalar::ZERO)
            .context("invalid root hash")?;
        if hash == Scalar::ZERO {
            return Ok(0);
        }
        let mut i = 0;
        for s in 0..32 {
            let mut j = 1u64 << s;
            let hash = self.forest.get(root_hash, j.into()).unwrap();
            if hash != Scalar::ZERO {
                i = j;
            } else {
                while j > i {
                    let k = i + ((j - i) >> 1);
                    let hash = self.forest.get(root_hash, k.into()).unwrap();
                    if hash != Scalar::ZERO {
                        i = k + 1;
                    } else {
                        j = k;
                    }
                }
                break;
            }
        }
        Ok(i as usize)
    }

    /// Adds a transaction to (the current revision of) the store.
    ///
    /// Returns the index of the newly added transaction. Note that the returned value corresponds
    /// to `size()` before calling `push()`.
    pub fn push(&mut self, transaction: &Transaction) -> Result<usize> {
        let transaction_hash = transaction.hash();
        let bytes = transaction.diff().encode_to_vec();
        let index = self.next_index;
        self.next_index += 1;
        let current_version = self.current_version();
        let root_hash = &mut self.root_hashes[current_version];
        *root_hash = self
            .forest
            .put(*root_hash, Scalar::from(index as u64), transaction_hash)?;
        let heap_index = self.heap.append(bytes.as_slice())?;
        self.indices.insert_hashed(
            GlobalTransactionIndex {
                index: (heap_index as u64).into(),
            },
            transaction_hash,
        )?;
        Ok(index)
    }

    /// Looks up a transaction by its hash, returning an error if it's not found.
    pub fn get_by_hash(&self, transaction_hash: Scalar) -> Result<Transaction> {
        let heap_index = self
            .indices
            .get(transaction_hash)
            .context("transaction not found")?;
        let bytes = self.heap.get(heap_index.index());
        let proto = libernet::Transaction::decode(bytes)?;
        Transaction::from_proto_verify(proto)
    }

    /// Retrieves the i-th transaction of the specified version.
    pub fn get(&self, version: usize, index: usize) -> Result<Transaction> {
        let transaction_hash = self
            .forest
            .get(self.root_hash(version), Scalar::from(index as u64))
            .context("invalid root hash")?;
        if transaction_hash == Scalar::ZERO {
            return Err(anyhow!("transaction not found"));
        }
        let heap_index = self
            .indices
            .get(transaction_hash)
            .context("invalid transaction hash")?;
        let bytes = self.heap.get(heap_index.index());
        let proto = libernet::Transaction::decode(bytes)?;
        Transaction::from_proto_verify(proto)
    }

    /// Retrieves the i-th transaction of the specified version, along with a Merkle proof for it.
    pub fn get_proof(&self, version: usize, index: usize) -> Result<TransactionInclusionProof> {
        let proof = self
            .forest
            .get_proof(self.root_hash(version), Scalar::from(index as u64))
            .context("invalid root hash")?;
        let transaction_hash = *proof.value();
        if transaction_hash == Scalar::ZERO {
            return Err(anyhow!("transaction not found"));
        }
        let heap_index = self
            .indices
            .get(transaction_hash)
            .context("invalid transaction hash")?;
        let bytes = self.heap.get(heap_index.index());
        let proto = libernet::Transaction::decode(bytes)?;
        let transaction = Transaction::from_proto_verify(proto)?;
        Ok(proof.map(transaction).unwrap())
    }

    /// Returns the hashes of all transactions of a block in chronological order (the first element
    /// is the hash of the first transaction of the block, the second element is the hash of the
    /// second one, and so on).
    ///
    /// REQUIRES: `version` must be less than or equal to `current_version()`.
    pub fn get_hashes(&self, version: usize) -> Result<Vec<Scalar>> {
        let root_hash = self.root_hash(version);
        let mut hashes = vec![];
        let mut index = 0u64;
        loop {
            let transaction_hash = self
                .forest
                .get(root_hash, index.into())
                .context("invalid root hash")?;
            if transaction_hash != Scalar::ZERO {
                hashes.push(transaction_hash);
                index += 1;
            } else {
                return Ok(hashes);
            }
        }
    }

    /// Iterates over the transactions of a block.
    ///
    /// REQUIRES: `version` must be less than or equal to `current_version()`.
    pub fn iter<'a>(&'a self, version: usize) -> TransactionIterator<'a> {
        TransactionIterator::new(self, version)
    }

    /// Seals the current version, locking it into the version history. Returns the root hash of the
    /// committed version.
    ///
    /// After this call `current_version()` will increase by 1.
    pub fn commit(&mut self) -> Scalar {
        let root_hash = self.current_root_hash();
        self.root_hashes.push(self.forest.empty_root_hash());
        self.next_index = 0;
        root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{self, Account};
    use crate::testing::parse_scalar;
    use anyhow::anyhow;

    const TEST_CHAIN_ID: u64 = 42;

    fn test_account1() -> Account {
        account::testing::account1()
    }

    fn test_account2() -> Account {
        account::testing::account2()
    }

    fn test_account3() -> Account {
        account::testing::account3()
    }

    fn lookup(store: &TransactionStore, version: usize, index: usize) -> Result<Transaction> {
        let transaction = store.get(version, index)?;
        if store.get_by_hash(transaction.hash())? != transaction {
            return Err(anyhow!("inconsistent lookup"));
        }
        let proof = store.get_proof(version, index)?;
        if proof.key() != Scalar::from(index as u64) {
            return Err(anyhow!(
                "Merkle proof key mismatch (got {}, want {})",
                proof.key(),
                index
            ));
        }
        if *proof.value() != transaction {
            return Err(anyhow!(
                "Merkle proof value mismatch (got {}, want {})",
                proof.value().hash(),
                transaction.hash()
            ));
        }
        Ok(transaction)
    }

    fn iterate(store: &TransactionStore, version: usize) -> Result<Vec<Scalar>> {
        store
            .iter(version)
            .map(|proof| match proof {
                Ok(proof) => Ok(proof.value().hash()),
                Err(error) => Err(error),
            })
            .collect()
    }

    fn reverse_iteration(store: &TransactionStore, version: usize) -> Result<Vec<Scalar>> {
        store
            .iter(version)
            .rev()
            .map(|proof| match proof {
                Ok(proof) => Ok(proof.value().hash()),
                Err(error) => Err(error),
            })
            .collect()
    }

    #[test]
    fn test_initial_state() {
        let store = TransactionStore::default().unwrap();
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(store.size(), 0);
        assert_eq!(store.get_size(0).unwrap(), 0);
        assert_eq!(store.get_hashes(0).unwrap(), vec![]);
        assert_eq!(iterate(&store, 0).unwrap(), vec![]);
        assert_eq!(reverse_iteration(&store, 0).unwrap(), vec![]);
    }

    #[test]
    fn test_push_one() {
        let mut store = TransactionStore::default().unwrap();
        let transaction = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction).unwrap(), 0);
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x4d1c17a2777911106c2e4ab0bd33dbaf5e6380ab323d5fdc7c92345bfc135f80")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x4d1c17a2777911106c2e4ab0bd33dbaf5e6380ab323d5fdc7c92345bfc135f80")
        );
        assert_eq!(store.size(), 1);
        assert_eq!(store.get_size(0).unwrap(), 1);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction);
        assert!(lookup(&store, 0, 1).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![parse_scalar(
                "0x157a7dbfaab92ba8e6ba287d7ec853f9877ce441dc73a59c53b0ff65cb1f091c"
            )]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x157a7dbfaab92ba8e6ba287d7ec853f9877ce441dc73a59c53b0ff65cb1f091c"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x157a7dbfaab92ba8e6ba287d7ec853f9877ce441dc73a59c53b0ff65cb1f091c"
            )]
        );
    }

    #[test]
    fn test_push_two() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                456.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                789.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(store.push(&transaction2).unwrap(), 1);
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x2088e0e8b7acbb227397952eecaa8d308494bb975cef6c1c1a8f3f855981626b")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x2088e0e8b7acbb227397952eecaa8d308494bb975cef6c1c1a8f3f855981626b")
        );
        assert_eq!(store.size(), 2);
        assert_eq!(store.get_size(0).unwrap(), 2);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert_eq!(lookup(&store, 0, 1).unwrap(), transaction2);
        assert!(lookup(&store, 0, 2).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![
                parse_scalar("0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"),
                parse_scalar("0x2eb13676f6b8d61232fcc5c2cb8073ecb7ee27bdb8edf2c88972555db92334a8"),
            ]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"),
                parse_scalar("0x2eb13676f6b8d61232fcc5c2cb8073ecb7ee27bdb8edf2c88972555db92334a8"),
            ]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x2eb13676f6b8d61232fcc5c2cb8073ecb7ee27bdb8edf2c88972555db92334a8"),
                parse_scalar("0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"),
            ]
        );
    }

    #[test]
    fn test_push_three() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                12.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                34.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account3(),
                TEST_CHAIN_ID,
                1,
                test_account1().address(),
                56.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(store.push(&transaction2).unwrap(), 1);
        assert_eq!(store.push(&transaction3).unwrap(), 2);
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x20fee7ba3c0979d156b5cf34af146bbe60fb89ef8d75f57980458ff8d8ebf972")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x20fee7ba3c0979d156b5cf34af146bbe60fb89ef8d75f57980458ff8d8ebf972")
        );
        assert_eq!(store.size(), 3);
        assert_eq!(store.get_size(0).unwrap(), 3);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert_eq!(lookup(&store, 0, 1).unwrap(), transaction2);
        assert_eq!(lookup(&store, 0, 2).unwrap(), transaction3);
        assert!(lookup(&store, 0, 3).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![
                parse_scalar("0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"),
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
                parse_scalar("0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"),
            ]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"),
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
                parse_scalar("0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"),
            ]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"),
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
                parse_scalar("0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"),
            ]
        );
    }

    #[test]
    fn test_commit_empty() {
        let mut store = TransactionStore::default().unwrap();
        assert_eq!(
            store.commit(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(store.size(), 0);
        assert_eq!(store.get_size(0).unwrap(), 0);
        assert_eq!(store.get_size(1).unwrap(), 0);
        assert!(lookup(&store, 0, 0).is_err());
        assert!(lookup(&store, 1, 0).is_err());
        assert_eq!(store.get_hashes(0).unwrap(), vec![]);
        assert_eq!(store.get_hashes(1).unwrap(), vec![]);
        assert_eq!(iterate(&store, 0).unwrap(), vec![]);
        assert_eq!(iterate(&store, 1).unwrap(), vec![]);
        assert_eq!(reverse_iteration(&store, 0).unwrap(), vec![]);
        assert_eq!(reverse_iteration(&store, 1).unwrap(), vec![]);
    }

    #[test]
    fn test_push_one_and_commit() {
        let mut store = TransactionStore::default().unwrap();
        let transaction = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction).unwrap(), 0);
        assert_eq!(
            store.commit(),
            parse_scalar("0x4d1c17a2777911106c2e4ab0bd33dbaf5e6380ab323d5fdc7c92345bfc135f80")
        );
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x4d1c17a2777911106c2e4ab0bd33dbaf5e6380ab323d5fdc7c92345bfc135f80")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(store.size(), 0);
        assert_eq!(store.get_size(0).unwrap(), 1);
        assert_eq!(store.get_size(1).unwrap(), 0);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction);
        assert!(lookup(&store, 0, 1).is_err());
        assert!(lookup(&store, 1, 0).is_err());
        assert!(lookup(&store, 1, 1).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![parse_scalar(
                "0x157a7dbfaab92ba8e6ba287d7ec853f9877ce441dc73a59c53b0ff65cb1f091c"
            )]
        );
        assert_eq!(store.get_hashes(1).unwrap(), vec![]);
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x157a7dbfaab92ba8e6ba287d7ec853f9877ce441dc73a59c53b0ff65cb1f091c"
            )]
        );
        assert_eq!(iterate(&store, 1).unwrap(), vec![]);
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x157a7dbfaab92ba8e6ba287d7ec853f9877ce441dc73a59c53b0ff65cb1f091c"
            )]
        );
        assert_eq!(reverse_iteration(&store, 1).unwrap(), vec![]);
    }

    #[test]
    fn test_push_two_and_commit() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                456.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                789.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(store.push(&transaction2).unwrap(), 1);
        assert_eq!(
            store.commit(),
            parse_scalar("0x2088e0e8b7acbb227397952eecaa8d308494bb975cef6c1c1a8f3f855981626b")
        );
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x2088e0e8b7acbb227397952eecaa8d308494bb975cef6c1c1a8f3f855981626b")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(store.size(), 0);
        assert_eq!(store.get_size(0).unwrap(), 2);
        assert_eq!(store.get_size(1).unwrap(), 0);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert_eq!(lookup(&store, 0, 1).unwrap(), transaction2);
        assert!(lookup(&store, 0, 2).is_err());
        assert!(lookup(&store, 1, 0).is_err());
        assert!(lookup(&store, 1, 1).is_err());
        assert!(lookup(&store, 1, 2).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![
                parse_scalar("0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"),
                parse_scalar("0x2eb13676f6b8d61232fcc5c2cb8073ecb7ee27bdb8edf2c88972555db92334a8"),
            ]
        );
        assert_eq!(store.get_hashes(1).unwrap(), vec![]);
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"),
                parse_scalar("0x2eb13676f6b8d61232fcc5c2cb8073ecb7ee27bdb8edf2c88972555db92334a8"),
            ]
        );
        assert_eq!(iterate(&store, 1).unwrap(), vec![]);
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x2eb13676f6b8d61232fcc5c2cb8073ecb7ee27bdb8edf2c88972555db92334a8"),
                parse_scalar("0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"),
            ]
        );
        assert_eq!(reverse_iteration(&store, 1).unwrap(), vec![]);
    }

    #[test]
    fn test_push_commit_push() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                456.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                789.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(
            store.commit(),
            parse_scalar("0x2eea4ac9e18c1bf75317b03b596cfa8b3a6e635e3194fefc08e60c83455e09c0")
        );
        assert_eq!(store.push(&transaction2).unwrap(), 0);
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x2eea4ac9e18c1bf75317b03b596cfa8b3a6e635e3194fefc08e60c83455e09c0")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x41063a752b9839d08e2a18cb279599be4646db7bb7153e652ab6d0774ec9006a")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x41063a752b9839d08e2a18cb279599be4646db7bb7153e652ab6d0774ec9006a")
        );
        assert_eq!(store.size(), 1);
        assert_eq!(store.get_size(0).unwrap(), 1);
        assert_eq!(store.get_size(1).unwrap(), 1);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert!(lookup(&store, 0, 1).is_err());
        assert_eq!(lookup(&store, 1, 0).unwrap(), transaction2);
        assert!(lookup(&store, 1, 1).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![parse_scalar(
                "0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"
            )]
        );
        assert_eq!(
            store.get_hashes(1).unwrap(),
            vec![parse_scalar(
                "0x0aabfb03d78c59db731defcce16097cb2d8f85f2d6507d0d7b730748418165cb"
            )]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"
            )]
        );
        assert_eq!(
            iterate(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x0aabfb03d78c59db731defcce16097cb2d8f85f2d6507d0d7b730748418165cb"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x0aabfb03d78c59db731defcce16097cb2d8f85f2d6507d0d7b730748418165cb"
            )]
        );
    }

    #[test]
    fn test_push_two_commit_push_one() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                12.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                34.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account3(),
                TEST_CHAIN_ID,
                1,
                test_account1().address(),
                56.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(store.push(&transaction2).unwrap(), 1);
        assert_eq!(
            store.commit(),
            parse_scalar("0x47d91237bf3f720aedb3a6ef99d64917c0f9a099adcda7bb5b5ff2b2c6a013cc")
        );
        assert_eq!(store.push(&transaction3).unwrap(), 0);
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x47d91237bf3f720aedb3a6ef99d64917c0f9a099adcda7bb5b5ff2b2c6a013cc")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x3af42be549ae68dcf67c9150700992f1066fb2f54d0ec413fc5f5732f9649d85")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x3af42be549ae68dcf67c9150700992f1066fb2f54d0ec413fc5f5732f9649d85")
        );
        assert_eq!(store.size(), 1);
        assert_eq!(store.get_size(0).unwrap(), 2);
        assert_eq!(store.get_size(1).unwrap(), 1);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert_eq!(lookup(&store, 0, 1).unwrap(), transaction2);
        assert!(lookup(&store, 0, 2).is_err());
        assert_eq!(lookup(&store, 1, 0).unwrap(), transaction3);
        assert!(lookup(&store, 1, 1).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![
                parse_scalar("0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"),
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
            ]
        );
        assert_eq!(
            store.get_hashes(1).unwrap(),
            vec![parse_scalar(
                "0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"
            )]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"),
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
            ]
        );
        assert_eq!(
            iterate(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
                parse_scalar("0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"),
            ]
        );
        assert_eq!(
            reverse_iteration(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"
            )]
        );
    }

    #[test]
    fn test_push_one_commit_push_two() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                12.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                34.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &test_account3(),
                TEST_CHAIN_ID,
                1,
                test_account1().address(),
                56.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(
            store.commit(),
            parse_scalar("0x0052cef49aa5dc83a484041bc51eb7cf76f3adfd8de0141073e710ecb4f78e88")
        );
        assert_eq!(store.push(&transaction2).unwrap(), 0);
        assert_eq!(store.push(&transaction3).unwrap(), 1);
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x0052cef49aa5dc83a484041bc51eb7cf76f3adfd8de0141073e710ecb4f78e88")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x14a76f5cdbb69c17cc4727b4dd5cf7f19c287cab96a9376fc748a4592e117e44")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x14a76f5cdbb69c17cc4727b4dd5cf7f19c287cab96a9376fc748a4592e117e44")
        );
        assert_eq!(store.size(), 2);
        assert_eq!(store.get_size(0).unwrap(), 1);
        assert_eq!(store.get_size(1).unwrap(), 2);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert!(lookup(&store, 0, 1).is_err());
        assert_eq!(lookup(&store, 1, 0).unwrap(), transaction2);
        assert_eq!(lookup(&store, 1, 1).unwrap(), transaction3);
        assert!(lookup(&store, 1, 2).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![parse_scalar(
                "0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"
            )]
        );
        assert_eq!(
            store.get_hashes(1).unwrap(),
            vec![
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
                parse_scalar("0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"),
            ]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"
            )]
        );
        assert_eq!(
            iterate(&store, 1).unwrap(),
            vec![
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
                parse_scalar("0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"),
            ]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x60c348af4e8645e0accfb09c7e415b2ba19dd61ef4891106d01ece21e1eea544"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 1).unwrap(),
            vec![
                parse_scalar("0x12cb8b51585d17a587a5711af4f1e5703ce652c4dcc80b284a239ce37c0fc7b4"),
                parse_scalar("0x730d84c403c42286a1891c206127f60d4fba2399cb484f3b2db109e28a25342f"),
            ]
        );
    }

    #[test]
    fn test_push_commit_push_commit() {
        let mut store = TransactionStore::default().unwrap();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account1(),
                TEST_CHAIN_ID,
                1,
                test_account2().address(),
                456.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &test_account2(),
                TEST_CHAIN_ID,
                1,
                test_account3().address(),
                789.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(store.push(&transaction1).unwrap(), 0);
        assert_eq!(
            store.commit(),
            parse_scalar("0x2eea4ac9e18c1bf75317b03b596cfa8b3a6e635e3194fefc08e60c83455e09c0")
        );
        assert_eq!(store.push(&transaction2).unwrap(), 0);
        assert_eq!(
            store.commit(),
            parse_scalar("0x41063a752b9839d08e2a18cb279599be4646db7bb7153e652ab6d0774ec9006a")
        );
        assert_eq!(store.current_version(), 2);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x2eea4ac9e18c1bf75317b03b596cfa8b3a6e635e3194fefc08e60c83455e09c0")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x41063a752b9839d08e2a18cb279599be4646db7bb7153e652ab6d0774ec9006a")
        );
        assert_eq!(
            store.root_hash(2),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        assert_eq!(store.size(), 0);
        assert_eq!(store.get_size(0).unwrap(), 1);
        assert_eq!(store.get_size(1).unwrap(), 1);
        assert_eq!(store.get_size(2).unwrap(), 0);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert!(lookup(&store, 0, 1).is_err());
        assert_eq!(lookup(&store, 1, 0).unwrap(), transaction2);
        assert!(lookup(&store, 1, 1).is_err());
        assert!(lookup(&store, 2, 0).is_err());
        assert!(lookup(&store, 2, 1).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![parse_scalar(
                "0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"
            )]
        );
        assert_eq!(
            store.get_hashes(1).unwrap(),
            vec![parse_scalar(
                "0x0aabfb03d78c59db731defcce16097cb2d8f85f2d6507d0d7b730748418165cb"
            )]
        );
        assert_eq!(store.get_hashes(2).unwrap(), vec![]);
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"
            )]
        );
        assert_eq!(
            iterate(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x0aabfb03d78c59db731defcce16097cb2d8f85f2d6507d0d7b730748418165cb"
            )]
        );
        assert_eq!(iterate(&store, 2).unwrap(), vec![]);
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x3ad8dc6b5e81af9086c088a12a7e24ad767cf82dec876c0c104fea2a93018282"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x0aabfb03d78c59db731defcce16097cb2d8f85f2d6507d0d7b730748418165cb"
            )]
        );
        assert_eq!(reverse_iteration(&store, 2).unwrap(), vec![]);
    }
}
