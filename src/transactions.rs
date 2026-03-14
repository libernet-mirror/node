use crate::constants;
use crate::data::Transaction;
use crate::smt;
use crate::store::{EmptyHeaderData, MappedHashSet, NodeData, Stored, StoredHeap, StoredU64};
use anyhow::Result;
use blstrs::Scalar;

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
    fn hash(&self) -> blstrs::Scalar {
        // TODO: make `MappedHashSet` tolerant to this.
        // Essentially it means we can only insert by `insert_hashed` and not `insert`, but we need
        // to formalize it in the API.
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct TransactionStore {
    forest: smt::Forest<3, 161>,
    indices: MappedHashSet<EmptyHeaderData, GlobalTransactionIndex>,
    heap: StoredHeap<EmptyHeaderData>,
}

impl TransactionStore {
    pub fn default() -> Result<Self> {
        Ok(Self {
            forest: smt::Forest::default(constants::DATA_FILE_TYPE_TRANSACTION_FOREST)?,
            indices: MappedHashSet::default(constants::DATA_FILE_TYPE_TRANSACTION_INDICES)?,
            heap: StoredHeap::default(constants::DATA_FILE_TYPE_TRANSACTION_HEAP)?,
        })
    }

    pub fn insert(
        &mut self,
        root_hash: Scalar,
        transaction: &Transaction,
        index: usize,
    ) -> Result<Scalar> {
        let transaction_hash = transaction.hash();
        let root_hash = self
            .forest
            .put(root_hash, Scalar::from(index as u64), transaction_hash)?;
        // TODO
        Ok(root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
