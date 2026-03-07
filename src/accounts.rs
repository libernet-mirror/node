use crate::constants;
use crate::data::AccountInfo;
use crate::smt;
use crate::store::{EmptyHeaderData, MappedHashSet, NodeData, Stored, StoredRefCount};
use anyhow::Result;
use blstrs::Scalar;
use memmap2::MmapMut;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
struct AccountNode {
    ref_count: StoredRefCount,
    account: AccountInfo,
}

impl AccountNode {
    fn new(account: AccountInfo) -> Self {
        Self {
            ref_count: 1.into(),
            account,
        }
    }

    fn r#ref(&mut self) {
        self.ref_count.r#ref();
    }

    fn unref(&mut self) -> bool {
        self.ref_count.unref()
    }

    fn account(&self) -> &AccountInfo {
        &self.account
    }
}

impl Stored for AccountNode {}

impl NodeData for AccountNode {
    fn hash(&self) -> Scalar {
        self.account.hash()
    }
}

type AccountHashSet = MappedHashSet<EmptyHeaderData, AccountNode>;
type AccountTree = smt::Tree<3, 161>;

#[derive(Debug)]
pub struct AccountStore {
    data: AccountHashSet,
    tree: AccountTree,
    roots: Vec<Scalar>,
}

impl AccountStore {
    pub fn default() -> Result<Self> {
        let mut store = Self {
            data: AccountHashSet::new(
                MmapMut::map_anon(
                    AccountHashSet::PADDED_HEADER_SIZE
                        + AccountHashSet::get_max_capacity_for(1)
                            * AccountHashSet::padded_node_size(),
                )?,
                constants::DATA_FILE_TYPE_ACCOUNT_DATA,
            )?,
            tree: AccountTree::default(constants::DATA_FILE_TYPE_ACCOUNT_TREE)?,
            roots: vec![],
        };
        store.data.insert(AccountNode::default())?;
        Ok(store)
    }

    pub fn root_hash(&self, version: usize) -> Scalar {
        self.roots[version]
    }

    pub fn get(&self, address: Scalar, version: usize) -> &AccountInfo {
        let root_hash = self.roots[version];
        let hash = self.tree.get_at(root_hash, address).unwrap();
        self.data.get(hash).unwrap().account()
    }

    pub fn put(&mut self, address: Scalar, account: AccountInfo) -> Result<()> {
        let old_hash = self.tree.get(address);
        let new_hash = account.hash();
        self.data
            .insert_hashed(AccountNode::new(account), new_hash)?;
        let empty_hash = AccountInfo::default().hash();
        if old_hash != empty_hash {
            self.data.erase_and_shrink(old_hash)?;
        }
        self.tree.put(address, new_hash)?;
        Ok(())
    }

    pub fn commit(&mut self) -> Scalar {
        let root_hash = self.tree.commit();
        self.roots.push(root_hash);
        root_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
