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

/// Stores block transactions.
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
    pub fn push(&mut self, transaction: &Transaction) -> Result<Scalar> {
        let transaction_hash = transaction.hash();
        let bytes = transaction.diff().encode_to_vec();
        let index = self.next_index;
        self.next_index += 1;
        let current_version = self.current_version();
        let root_hash = &mut self.root_hashes[current_version];
        *root_hash = self
            .forest
            .put(*root_hash, Scalar::from(index as u64), transaction_hash)?;
        let root_hash = *root_hash;
        let heap_index = self.heap.append(bytes.as_slice())?;
        self.indices.insert_hashed(
            GlobalTransactionIndex {
                index: (heap_index as u64).into(),
            },
            transaction_hash,
        )?;
        Ok(root_hash)
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
        assert_eq!(
            store.push(&transaction).unwrap(),
            parse_scalar("0x738275ee4bd33ed0962fb83e5c29a5ed761d821e52026a88b049238327438194")
        );
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x738275ee4bd33ed0962fb83e5c29a5ed761d821e52026a88b049238327438194")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x738275ee4bd33ed0962fb83e5c29a5ed761d821e52026a88b049238327438194")
        );
        assert_eq!(store.size(), 1);
        assert_eq!(store.get_size(0).unwrap(), 1);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction);
        assert!(lookup(&store, 0, 1).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![parse_scalar(
                "0x56dfe0c69422410d258fdff9aa0419c38e0c5e91afddb2f45f76cb6ec17f6a38"
            )]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x56dfe0c69422410d258fdff9aa0419c38e0c5e91afddb2f45f76cb6ec17f6a38"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x56dfe0c69422410d258fdff9aa0419c38e0c5e91afddb2f45f76cb6ec17f6a38"
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
        assert_eq!(
            store.push(&transaction1).unwrap(),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.push(&transaction2).unwrap(),
            parse_scalar("0x0904abc2b8dc27364d53f2afa5e696fd8a4f86356ba615dd56ca81b914a97c86")
        );
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x0904abc2b8dc27364d53f2afa5e696fd8a4f86356ba615dd56ca81b914a97c86")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x0904abc2b8dc27364d53f2afa5e696fd8a4f86356ba615dd56ca81b914a97c86")
        );
        assert_eq!(store.size(), 2);
        assert_eq!(store.get_size(0).unwrap(), 2);
        assert_eq!(lookup(&store, 0, 0).unwrap(), transaction1);
        assert_eq!(lookup(&store, 0, 1).unwrap(), transaction2);
        assert!(lookup(&store, 0, 2).is_err());
        assert_eq!(
            store.get_hashes(0).unwrap(),
            vec![
                parse_scalar("0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"),
                parse_scalar("0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"),
            ]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"),
                parse_scalar("0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"),
            ]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"),
                parse_scalar("0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"),
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
        assert_eq!(
            store.push(&transaction1).unwrap(),
            parse_scalar("0x19ec75a9eb0522698a3f57c1c11c648b87943e5aa35d422883269c7b06010256")
        );
        assert_eq!(
            store.push(&transaction2).unwrap(),
            parse_scalar("0x2666817884a22839c054e44cb585ea83074c1a84d1fa8964a7a2b3ff3141b0c2")
        );
        assert_eq!(
            store.push(&transaction3).unwrap(),
            parse_scalar("0x0b88fea6dc3924b70be94c1c99c10ca45f8043f0a114f5e57200ca626c2c9fae")
        );
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x0b88fea6dc3924b70be94c1c99c10ca45f8043f0a114f5e57200ca626c2c9fae")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x0b88fea6dc3924b70be94c1c99c10ca45f8043f0a114f5e57200ca626c2c9fae")
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
                parse_scalar("0x5eacb6a3156699a9d2242d2a2c150ec764b35eb2afc65d47a97620f23a94e048"),
                parse_scalar("0x2448aca07f3986bf1f3c0f7a87d9498dcf8b97789953c8115313f3e9309711d3"),
                parse_scalar("0x4eb98e66c5b805c1f7598bac3e7af05798e07e608aed935e9609bc4809722871"),
            ]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x5eacb6a3156699a9d2242d2a2c150ec764b35eb2afc65d47a97620f23a94e048"),
                parse_scalar("0x2448aca07f3986bf1f3c0f7a87d9498dcf8b97789953c8115313f3e9309711d3"),
                parse_scalar("0x4eb98e66c5b805c1f7598bac3e7af05798e07e608aed935e9609bc4809722871"),
            ]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x4eb98e66c5b805c1f7598bac3e7af05798e07e608aed935e9609bc4809722871"),
                parse_scalar("0x2448aca07f3986bf1f3c0f7a87d9498dcf8b97789953c8115313f3e9309711d3"),
                parse_scalar("0x5eacb6a3156699a9d2242d2a2c150ec764b35eb2afc65d47a97620f23a94e048"),
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
        assert_eq!(
            store.push(&transaction).unwrap(),
            parse_scalar("0x738275ee4bd33ed0962fb83e5c29a5ed761d821e52026a88b049238327438194")
        );
        assert_eq!(
            store.commit(),
            parse_scalar("0x738275ee4bd33ed0962fb83e5c29a5ed761d821e52026a88b049238327438194")
        );
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x738275ee4bd33ed0962fb83e5c29a5ed761d821e52026a88b049238327438194")
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
                "0x56dfe0c69422410d258fdff9aa0419c38e0c5e91afddb2f45f76cb6ec17f6a38"
            )]
        );
        assert_eq!(store.get_hashes(1).unwrap(), vec![]);
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x56dfe0c69422410d258fdff9aa0419c38e0c5e91afddb2f45f76cb6ec17f6a38"
            )]
        );
        assert_eq!(iterate(&store, 1).unwrap(), vec![]);
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x56dfe0c69422410d258fdff9aa0419c38e0c5e91afddb2f45f76cb6ec17f6a38"
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
        assert_eq!(
            store.push(&transaction1).unwrap(),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.push(&transaction2).unwrap(),
            parse_scalar("0x0904abc2b8dc27364d53f2afa5e696fd8a4f86356ba615dd56ca81b914a97c86")
        );
        assert_eq!(
            store.commit(),
            parse_scalar("0x0904abc2b8dc27364d53f2afa5e696fd8a4f86356ba615dd56ca81b914a97c86")
        );
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x0904abc2b8dc27364d53f2afa5e696fd8a4f86356ba615dd56ca81b914a97c86")
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
                parse_scalar("0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"),
                parse_scalar("0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"),
            ]
        );
        assert_eq!(store.get_hashes(1).unwrap(), vec![]);
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![
                parse_scalar("0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"),
                parse_scalar("0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"),
            ]
        );
        assert_eq!(iterate(&store, 1).unwrap(), vec![]);
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![
                parse_scalar("0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"),
                parse_scalar("0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"),
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
        assert_eq!(
            store.push(&transaction1).unwrap(),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.commit(),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.push(&transaction2).unwrap(),
            parse_scalar("0x199913e12c2efa797495ba08941e106dc94f05832e3792927f7b5a6ba15dbdfd")
        );
        assert_eq!(store.current_version(), 1);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x199913e12c2efa797495ba08941e106dc94f05832e3792927f7b5a6ba15dbdfd")
        );
        assert_eq!(
            store.current_root_hash(),
            parse_scalar("0x199913e12c2efa797495ba08941e106dc94f05832e3792927f7b5a6ba15dbdfd")
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
                "0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"
            )]
        );
        assert_eq!(
            store.get_hashes(1).unwrap(),
            vec![parse_scalar(
                "0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"
            )]
        );
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"
            )]
        );
        assert_eq!(
            iterate(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"
            )]
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
        assert_eq!(
            store.push(&transaction1).unwrap(),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.commit(),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.push(&transaction2).unwrap(),
            parse_scalar("0x199913e12c2efa797495ba08941e106dc94f05832e3792927f7b5a6ba15dbdfd")
        );
        assert_eq!(
            store.commit(),
            parse_scalar("0x199913e12c2efa797495ba08941e106dc94f05832e3792927f7b5a6ba15dbdfd")
        );
        assert_eq!(store.current_version(), 2);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x1ec6dcb0dd77ccadbf50b502a7b61fe083ef564505c17da2e889becbb8a87558")
        );
        assert_eq!(
            store.root_hash(1),
            parse_scalar("0x199913e12c2efa797495ba08941e106dc94f05832e3792927f7b5a6ba15dbdfd")
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
                "0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"
            )]
        );
        assert_eq!(
            store.get_hashes(1).unwrap(),
            vec![parse_scalar(
                "0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"
            )]
        );
        assert_eq!(store.get_hashes(2).unwrap(), vec![]);
        assert_eq!(
            iterate(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"
            )]
        );
        assert_eq!(
            iterate(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"
            )]
        );
        assert_eq!(iterate(&store, 2).unwrap(), vec![]);
        assert_eq!(
            reverse_iteration(&store, 0).unwrap(),
            vec![parse_scalar(
                "0x368b8dcd0fac05961817bee3af225d68a47cd508b275ff97eb9e2e9a5ea398dc"
            )]
        );
        assert_eq!(
            reverse_iteration(&store, 1).unwrap(),
            vec![parse_scalar(
                "0x533824197efd76b0d7f5db6ee96de839e6f5894350501ae54f27c9b1f94dd5d8"
            )]
        );
        assert_eq!(reverse_iteration(&store, 2).unwrap(), vec![]);
    }
}
