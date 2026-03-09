use crate::constants;
use crate::data::AccountInfo;
use crate::smt;
use crate::store::{EmptyHeaderData, MappedHashSet, NodeData, Stored, StoredRefCount};
use anyhow::Result;
use blstrs::Scalar;
use crypto::merkle;
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
            ref_count: 0.into(),
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
        let default_account = AccountNode::default();
        let default_hash = default_account.hash();
        let mut store = Self {
            data: AccountHashSet::new(
                MmapMut::map_anon(
                    AccountHashSet::PADDED_HEADER_SIZE
                        + AccountHashSet::get_max_capacity_for(1)
                            * AccountHashSet::padded_node_size(),
                )?,
                constants::DATA_FILE_TYPE_ACCOUNT_DATA,
            )?,
            tree: AccountTree::new(
                MmapMut::map_anon(
                    AccountTree::PADDED_HEADER_SIZE
                        + AccountTree::optimal_initial_capacity() * AccountTree::padded_node_size(),
                )?,
                constants::DATA_FILE_TYPE_ACCOUNT_TREE,
                default_hash,
            )?,
            roots: vec![],
        };
        store.data.insert(default_account)?;
        Ok(store)
    }

    pub fn current_version(&self) -> usize {
        self.roots.len()
    }

    pub fn root_hash(&self, version: usize) -> Scalar {
        if version < self.roots.len() {
            self.roots[version]
        } else {
            self.tree.root_hash()
        }
    }

    pub fn get(&self, address: Scalar, version: usize) -> &AccountInfo {
        let root_hash = self.root_hash(version);
        let hash = self.tree.get_at(root_hash, address).unwrap();
        self.data.get(hash).unwrap().account()
    }

    pub fn get_proof(
        &self,
        address: Scalar,
        version: usize,
    ) -> merkle::Proof<Scalar, AccountInfo, 3, 161> {
        let root_hash = self.root_hash(version);
        let proof = self.tree.get_proof_at(root_hash, address).unwrap();
        let account = *self.data.get(*proof.value()).unwrap().account();
        proof.map(account).unwrap()
    }

    pub fn put(&mut self, address: Scalar, account: AccountInfo) -> Result<()> {
        let old_hash = self.tree.get(address);
        let new_hash = account.hash();
        if new_hash == old_hash {
            return Ok(());
        }
        let (node, _) = self
            .data
            .insert_hashed(AccountNode::new(account), new_hash)?;
        let default_hash = AccountInfo::default().hash();
        if new_hash != default_hash {
            node.r#ref();
        }
        if old_hash != default_hash {
            if self.data.get_mut(old_hash).unwrap().unref() {
                self.data.erase_and_shrink(old_hash)?;
            }
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
    use crypto::utils;

    use super::*;
    use crate::testing::parse_scalar;

    fn test_key1() -> Scalar {
        parse_scalar("0x46e9d1f65e08ba9a338f124e31fb07ad76ce985be9fbc996c1b9df57e2566f75")
    }

    fn test_key2() -> Scalar {
        parse_scalar("0x6c46cd2477a2e51f8c774cd2280e6646f871268a1d22eeea9a7df98c6e86a247")
    }

    fn test_key3() -> Scalar {
        let x = utils::get_random_scalar();
        println!("{}", x);
        x
    }

    fn lookup(store: &AccountStore, address: Scalar, version: usize) -> AccountInfo {
        let account = *store.get(address, version);
        let proof = store.get_proof(address, version);
        assert!(proof.verify().is_ok());
        assert_eq!(proof.take_value(), account);
        account
    }

    #[test]
    fn test_initial_state() {
        let store = AccountStore::default().unwrap();
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x490222871f1d15b49498ecad22a0be514a3a4b9744df61b80886856bf9230176")
        );
        assert_eq!(lookup(&store, test_key1(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
    }

    #[test]
    fn test_one_empty_commit() {
        let root_hash =
            parse_scalar("0x490222871f1d15b49498ecad22a0be514a3a4b9744df61b80886856bf9230176");
        let mut store = AccountStore::default().unwrap();
        assert_eq!(store.commit(), root_hash);
        assert_eq!(store.current_version(), 1);
        assert_eq!(store.root_hash(0), root_hash);
        assert_eq!(store.root_hash(1), root_hash);
        assert_eq!(lookup(&store, test_key1(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key1(), 1), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 1), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 1), AccountInfo::default());
    }

    #[test]
    fn test_two_empty_commits() {
        let root_hash =
            parse_scalar("0x490222871f1d15b49498ecad22a0be514a3a4b9744df61b80886856bf9230176");
        let mut store = AccountStore::default().unwrap();
        assert_eq!(store.commit(), root_hash);
        assert_eq!(store.commit(), root_hash);
        assert_eq!(store.current_version(), 2);
        assert_eq!(store.root_hash(0), root_hash);
        assert_eq!(store.root_hash(1), root_hash);
        assert_eq!(store.root_hash(2), root_hash);
        assert_eq!(lookup(&store, test_key1(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key1(), 1), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 1), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 1), AccountInfo::default());
        assert_eq!(lookup(&store, test_key1(), 2), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 2), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 2), AccountInfo::default());
    }

    #[test]
    fn test_set_one_1() {
        let mut store = AccountStore::default().unwrap();
        let account = AccountInfo::default()
            .set_last_nonce(42)
            .add_to_balance(123.into())
            .unwrap();
        assert!(store.put(test_key1(), account).is_ok());
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x39ba09774c00f627745f2c915055684141923129d9bef8c3fc79438618eaba44")
        );
        assert_eq!(lookup(&store, test_key1(), 0), account);
        assert_eq!(lookup(&store, test_key2(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
    }

    #[test]
    fn test_set_one_2() {
        let mut store = AccountStore::default().unwrap();
        let account = AccountInfo::default()
            .set_last_nonce(42)
            .add_to_balance(123.into())
            .unwrap();
        assert!(store.put(test_key2(), account).is_ok());
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x4a89ae1727e0454819203d393c1868aefd8b02fc1d151a70825617380b3b1143")
        );
        assert_eq!(lookup(&store, test_key1(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key2(), 0), account);
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
    }

    #[test]
    fn test_set_two() {
        let mut store = AccountStore::default().unwrap();
        let account1 = AccountInfo::default()
            .set_last_nonce(42)
            .add_to_balance(123.into())
            .unwrap();
        let account2 = AccountInfo::default()
            .set_last_nonce(43)
            .add_to_balance(456.into())
            .unwrap();
        assert!(store.put(test_key1(), account1).is_ok());
        assert!(store.put(test_key2(), account2).is_ok());
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x370ca8d84234ce10f0d40bd56a55fbbde0280dad0d751e4cdc68c4bd84536dbd")
        );
        assert_eq!(lookup(&store, test_key1(), 0), account1);
        assert_eq!(lookup(&store, test_key2(), 0), account2);
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
    }

    #[test]
    fn test_set_one_twice() {
        let mut store = AccountStore::default().unwrap();
        let account1 = AccountInfo::default()
            .set_last_nonce(42)
            .add_to_balance(123.into())
            .unwrap();
        let account2 = AccountInfo::default()
            .set_last_nonce(43)
            .add_to_balance(456.into())
            .unwrap();
        assert!(store.put(test_key1(), account1).is_ok());
        assert!(store.put(test_key1(), account2).is_ok());
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x105b50978f14c59d6776ead97523874f574dea4cf3f5ed2bc2a195a3ddab101d")
        );
        assert_eq!(lookup(&store, test_key1(), 0), account2);
        assert_eq!(lookup(&store, test_key2(), 0), AccountInfo::default());
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
    }

    #[test]
    fn test_update_one_out_of_two() {
        let mut store = AccountStore::default().unwrap();
        let account1 = AccountInfo::default()
            .set_last_nonce(42)
            .add_to_balance(123.into())
            .unwrap();
        let account2 = AccountInfo::default()
            .set_last_nonce(43)
            .add_to_balance(456.into())
            .unwrap();
        let account3 = AccountInfo::default()
            .set_last_nonce(44)
            .add_to_balance(789.into())
            .unwrap();
        assert!(store.put(test_key1(), account1).is_ok());
        assert!(store.put(test_key2(), account2).is_ok());
        assert!(store.put(test_key1(), account3).is_ok());
        assert_eq!(store.current_version(), 0);
        assert_eq!(
            store.root_hash(0),
            parse_scalar("0x2013945dbf9027583e24bea6311122371f80c3a0dc9eeb65386454c3f6a93622")
        );
        assert_eq!(lookup(&store, test_key1(), 0), account3);
        assert_eq!(lookup(&store, test_key2(), 0), account2);
        assert_eq!(lookup(&store, test_key3(), 0), AccountInfo::default());
    }

    // TODO
}
