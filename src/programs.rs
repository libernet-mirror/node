use crate::constants;
use crate::smt;
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::utils;
use memmap2::MmapMut;
use std::sync::{Arc, Mutex};

type MasterTree = smt::Tree<3, 161>;
type HeapForest = smt::Forest<2, 30>;

#[derive(Debug)]
struct LeafManager {
    leaves: Arc<Mutex<HeapForest>>,
}

impl smt::ExternalNodeManager for LeafManager {
    fn r#ref(&mut self, label: Scalar) {
        let mut leaves = self.leaves.lock().unwrap();
        leaves.ref_root(label);
    }

    fn unref(&mut self, label: Scalar) -> bool {
        let mut leaves = self.leaves.lock().unwrap();
        leaves.unref_root(label).unwrap()
    }
}

#[derive(Debug)]
pub struct ProgramHeapStore {
    heap_forest: Arc<Mutex<HeapForest>>,
    master_tree: MasterTree,
}

impl ProgramHeapStore {
    pub fn default() -> Result<Self> {
        let heap_forest =
            smt::Forest::<2, 30>::default(constants::DATA_FILE_TYPE_PROGRAM_STORAGE_FOREST)?;
        let empty_heap_root_hash = heap_forest.empty_root_hash();
        let heap_forest = Arc::new(Mutex::new(heap_forest));
        let master_tree = MasterTree::new(
            MmapMut::map_anon(
                MasterTree::PADDED_HEADER_SIZE
                    + MasterTree::optimal_initial_capacity() * MasterTree::padded_node_size(),
            )?,
            constants::DATA_FILE_TYPE_PROGRAM_STORAGE_TREE,
            Box::new(LeafManager {
                leaves: heap_forest.clone(),
            }),
            empty_heap_root_hash,
        )?;
        Ok(Self {
            heap_forest,
            master_tree,
        })
    }

    pub fn root_hash(&self) -> Scalar {
        self.master_tree.root_hash()
    }

    /// Performs a 32-bit aligned read of a memory location from the heap of a program.
    ///
    /// REQUIRES: `memory_address` must be a multiple of 4.
    pub fn read_aligned(&self, program_address: Scalar, memory_address: u32) -> Result<u32> {
        assert_eq!(memory_address & 3, 0);
        let root_hash = self.master_tree.get(program_address);
        let memory_address = memory_address as u64 >> 2;
        let value = self
            .heap_forest
            .lock()
            .unwrap()
            .get(root_hash, memory_address.into())
            .context("invalid root hash")?;
        if value > Scalar::from(u32::MAX as u64) {
            return Err(anyhow!(
                "invalid 32-bit value stored at address {:#018x} for program {}: {}",
                memory_address << 4,
                utils::format_scalar(program_address),
                utils::format_scalar(value)
            ));
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&value.to_bytes_le()[0..4]);
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn write_aligned(
        &mut self,
        program_address: Scalar,
        memory_address: u32,
        value: u32,
    ) -> Result<()> {
        // TODO
    }

    // TODO

    pub fn commit(&mut self) -> Scalar {
        self.master_tree.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;

    fn test_program_address1() -> Scalar {
        parse_scalar("0x65db5a50c5bb213cc5921f358c42adb357beecea9d301f479a8e147869f1872d")
    }

    #[test]
    fn test_initial_state() {
        let store = ProgramHeapStore::default().unwrap();
        assert_eq!(
            store.root_hash(),
            parse_scalar("0x60f1584df6651304bf473904c2195584fb89cccb9a59af849a17934e0852ba10")
        );
        assert_eq!(store.read_aligned(test_program_address1(), 0).unwrap(), 0);
        assert_eq!(store.read_aligned(test_program_address1(), 4).unwrap(), 0);
        assert_eq!(store.read_aligned(test_program_address1(), 8).unwrap(), 0);
        assert_eq!(store.read_aligned(test_program_address1(), 12).unwrap(), 0);
    }

    // TODO
}
