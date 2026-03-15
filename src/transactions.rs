use crate::constants;
use crate::data::{Transaction, TransactionInclusionProof};
use crate::libernet;
use crate::smt;
use crate::store::{EmptyHeaderData, MappedHashSet, NodeData, Stored, StoredHeap, StoredU64};
use anyhow::{Context, Result};
use blstrs::Scalar;
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

    /// Adds a transaction to (the current revision of) the store.
    pub fn push(&mut self, transaction: &Transaction) -> Result<Scalar> {
        let transaction_hash = transaction.hash();
        let bytes = transaction.diff().encode_to_vec();
        let index = self.next_index;
        self.next_index += 1;
        let current_version = self.current_version();
        let root_hash = &mut self.root_hashes[current_version - 1];
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

    /// Retrieves the i-th transaction of the specified version.
    pub fn get(&self, version: usize, index: usize) -> Result<Transaction> {
        let transaction_hash = self
            .forest
            .get(self.root_hash(version), Scalar::from(index as u64))
            .context("transaction not found")?;
        let heap_index = self.indices.get(transaction_hash).unwrap();
        let bytes = self.heap.get(heap_index.index());
        let proto = libernet::Transaction::decode(bytes)?;
        Transaction::from_proto_verify(proto)
    }

    /// Retrieves the i-th transaction of the specified version, along with a Merkle proof for it.
    pub fn get_proof(&self, version: usize, index: usize) -> Result<TransactionInclusionProof> {
        let proof = self
            .forest
            .get_proof(self.root_hash(version), Scalar::from(index as u64))
            .context("transaction not found")?;
        let transaction_hash = *proof.value();
        let heap_index = self.indices.get(transaction_hash).unwrap();
        let bytes = self.heap.get(heap_index.index());
        let proto = libernet::Transaction::decode(bytes)?;
        let transaction = Transaction::from_proto_verify(proto)?;
        Ok(proof.map(transaction).unwrap())
    }

    /// Seals the current version, locking it into the version history. Returns the root hash of the
    /// committed version.
    ///
    /// After this call `current_version()` will increase by 1.
    pub fn commit(&mut self) -> Scalar {
        let root_hash = self.current_root_hash();
        self.root_hashes.push(self.forest.empty_root_hash());
        root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;

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
    }

    // TODO
}
