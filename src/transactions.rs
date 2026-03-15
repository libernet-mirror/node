use crate::constants;
use crate::data::Transaction;
use crate::proto::{self, EncodeToAny};
use crate::smt;
use crate::store::{EmptyHeaderData, MappedHashSet, NodeData, Stored, StoredHeap, StoredU64};
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::utils;
use ff::Field;
use memmap2::MmapMut;

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

type TransactionForest = smt::Forest<3, 161>;
type TransactionIndices = MappedHashSet<EmptyHeaderData, GlobalTransactionIndex>;
type TransactionHeap = StoredHeap<EmptyHeaderData>;

#[derive(Debug)]
pub struct TransactionStore {
    forest: TransactionForest,
    indices: TransactionIndices,
    heap: TransactionHeap,
}

impl TransactionStore {
    pub fn default() -> Result<Self> {
        Ok(Self {
            forest: smt::Forest::new(
                MmapMut::map_anon(
                    smt::Forest::<3, 161>::PADDED_HEADER_SIZE
                        + smt::Forest::<3, 161>::optimal_initial_capacity()
                            * smt::Forest::<3, 161>::padded_node_size(),
                )?,
                constants::DATA_FILE_TYPE_TRANSACTION_FOREST,
                Box::new(smt::NoopExternalNodeManager::default()),
                Scalar::ZERO,
            )?,
            indices: TransactionIndices::default(constants::DATA_FILE_TYPE_TRANSACTION_INDICES)?,
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
        let bytes = proto::encode_any_canonical(&transaction.encode_to_any()?);
        let root_hash = self
            .forest
            .put(root_hash, Scalar::from(index as u64), transaction_hash)?;
        let heap_index = self.heap.append(bytes.as_slice())?;
        let (_, inserted) = self.indices.insert_hashed(
            GlobalTransactionIndex {
                index: (heap_index as u64).into(),
            },
            transaction_hash,
        )?;
        if !inserted {
            return Err(anyhow!(
                "duplicated transaction {}",
                utils::format_scalar(transaction_hash)
            ));
        }
        Ok(root_hash)
    }

    pub fn get(&self, root_hash: Scalar, index: usize) -> Option<Transaction> {
        // TODO
        todo!()
    }

    pub fn commit(&mut self) -> Scalar {
        // TODO
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
