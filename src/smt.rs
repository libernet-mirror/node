use crate::store::{HeaderData, MappedHashSet, NodeData, Stored, StoredScalar, StoredU64};
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::{merkle, poseidon, xits};
use ff::{Field, PrimeField};
use memmap2::MmapMut;
use std::fmt::Debug;

/// A node of the tree.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Node<const W: usize> {
    /// Tracks how many other nodes refer to this node.
    ref_count: StoredU64,

    /// For leaf nodes these are arbitrary values, while for internal nodes they're the hashes of
    /// the child nodes.
    children: [StoredScalar; W],
}

impl<const W: usize> Node<W> {
    fn hash_node(children: &[Scalar; W]) -> Scalar {
        match W {
            2 => poseidon::hash_t3(children),
            3 => poseidon::hash_t4(children),
            _ => unimplemented!(),
        }
    }

    fn new(children: &[Scalar; W]) -> Self {
        Self {
            ref_count: 0.into(),
            children: children.map(StoredScalar::from),
        }
    }

    fn r#ref(&mut self) {
        self.ref_count = (self.ref_count.to_u64() + 1).into();
    }

    fn unref(&mut self) -> bool {
        let mut ref_count = self.ref_count.to_u64();
        assert!(ref_count > 0);
        ref_count -= 1;
        let is_zero = ref_count == 0;
        self.ref_count = ref_count.into();
        is_zero
    }

    fn children(&self) -> [Scalar; W] {
        self.children.map(|child| child.to_scalar())
    }

    fn child(&self, i: usize) -> Scalar {
        self.children[i].to_scalar()
    }
}

impl<const W: usize> Default for Node<W> {
    fn default() -> Self {
        Self {
            ref_count: 0.into(),
            children: std::array::from_fn(|_| StoredScalar::default()),
        }
    }
}

impl<const W: usize> Stored for Node<W> {}

impl<const W: usize> NodeData for Node<W> {
    fn hash(&self) -> Scalar {
        Self::hash_node(&self.children.map(|child_hash| child_hash.to_scalar()))
    }
}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
struct TreeHeader {
    root_hash: StoredScalar,
}

impl TreeHeader {
    fn root_hash(&self) -> Scalar {
        self.root_hash.to_scalar()
    }

    fn set_root_hash(&mut self, hash: Scalar) {
        self.root_hash = hash.into();
    }
}

impl Stored for TreeHeader {}
impl HeaderData for TreeHeader {}

/// A Sparse Merkle Tree backed by a `MappedHashSet`.
///
/// The nodes of the tree are immutable and are indexed in the underlying hash set by their actual
/// Merkle hash.
///
/// The nodes are reference counted and are automatically removed when their reference count drops
/// to zero. Cyclic references are not a concern because a tree is an acyclic graph by definition.
///
/// Note that a node may appear as the child of another node more than once. For example, if the two
/// subtrees of a binary tree node are identical they won't be stored twice; instead they'll have
/// node-by-node identical hashes, so they'll be stored as a single subtree referenced by the parent
/// node twice. Case in point, an empty tree with height `H` only requires storing `H` nodes in our
/// implementation.
#[derive(Debug)]
pub struct Tree<const W: usize, const H: usize> {
    hash_set: MappedHashSet<TreeHeader, Node<W>>,
}

impl<const W: usize, const H: usize> Tree<W, H> {
    /// Calculates the space allocated for the header.
    pub const fn padded_header_size() -> usize {
        MappedHashSet::<TreeHeader, Node<W>>::padded_header_size()
    }

    /// Calculates the space allocated for every node.
    pub const fn padded_node_size() -> usize {
        MappedHashSet::<TreeHeader, Node<W>>::padded_node_size()
    }

    /// Returns the minimum capacity (in terms of number of nodes) required to host `size` nodes.
    pub const fn get_min_capacity_for(size: usize) -> usize {
        MappedHashSet::<TreeHeader, Node<W>>::get_min_capacity_for(size)
    }

    /// Returns the minimum capacity (in terms of number of nodes) required for this type of tree.
    ///
    /// The data slice provided upon construction must be at least
    /// `padded_header_size() + min_capacity() * padded_node_size()` bytes long.
    pub const fn min_capacity() -> usize {
        Self::get_min_capacity_for(H)
    }

    fn ref_node(&mut self, hash: Scalar) {
        self.hash_set.get_mut(hash).unwrap().r#ref();
    }

    /// Ensures that a node with the given children exists.
    ///
    /// The node is created and inserted if it doesn't exist.
    ///
    /// The `leaf` flag specifies whether the node being allocated is a leaf or an internal node. If
    /// it's a leaf the children are arbitrary values, while if it's an internal node the children
    /// MUST be the hashes of other existing nodes. For internal nodes this algorithm will
    /// automatically increase the reference count of all children.
    fn make_node(&mut self, children: &[Scalar; W], leaf: bool) -> Result<&mut Node<W>> {
        let hash = Node::<W>::hash_node(children);
        self.hash_set.insert_hashed(Node::new(children), hash)?;
        if !leaf {
            for child_hash in children {
                self.ref_node(*child_hash);
            }
        }
        Ok(self.hash_set.get_mut(hash).unwrap())
    }

    fn unref_node_impl(&mut self, hash: Scalar, level: usize) -> bool {
        if let Some(node) = self.hash_set.get_mut(hash) {
            if !node.unref() {
                return false;
            }
        } else {
            return true;
        };
        let node = self.hash_set.extract(hash).unwrap();
        if level > 0 {
            for child_hash in node.children() {
                self.unref_node_impl(child_hash, level - 1);
            }
        }
        true
    }

    /// Unreferences a node and erases it from the tree along with its entire subtree if it's no
    /// longer referenced.
    ///
    /// If no node identified by the provided hash exists this function does nothing and returns
    /// true.
    ///
    /// If a node identified by the provided hash exists its reference count is decremented. If the
    /// reference count becomes zero after decrementing, this function will erase the node. If the
    /// node is an internal one rather than a leaf, and therefore its children are hashes referring
    /// to other nodes, this function will also decrement the reference counts of those nodes. This
    /// may in turn start a recursive cascade that frees all branches that are no longer referenced.
    ///
    /// If one or more nodes were actually deleted in the process this function returns true,
    /// otherwise it returns false.
    ///
    /// At the end of all (possibly recursive) removals, the new minimum capacity is reassessed and
    /// if it's less than the current capacity the underlying hash set is shrunk and rehashed.
    fn unref_node(&mut self, hash: Scalar, level: usize) -> Result<bool> {
        if !self.unref_node_impl(hash, level) {
            return Ok(false);
        }
        self.hash_set.shrink()?;
        Ok(true)
    }

    /// Constructs a `Tree` from the provided data slice.
    pub fn load(mmap: MmapMut, expected_flags: u32) -> Result<Self> {
        let min_size = Self::padded_header_size() + Self::min_capacity() * Self::padded_node_size();
        if mmap.len() < min_size {
            return Err(anyhow!(
                "the mmap is too small (was {} bytes, need at least {})",
                mmap.len(),
                min_size
            ));
        }
        Ok(Self {
            hash_set: MappedHashSet::load(mmap, expected_flags)?,
        })
    }

    fn init_empty(&mut self) -> Result<()> {
        let mut hash = Scalar::ZERO;
        for _ in 0..H {
            hash = self
                .make_node(&std::array::from_fn(|_| hash), H == 0)?
                .hash();
        }
        self.ref_node(hash);
        self.hash_set.header_data_mut().set_root_hash(hash);
        Ok(())
    }

    /// Initializes a new empty tree over the provided byte slice.
    ///
    /// REQUIRES: `data` MUST be 8-byte aligned.
    pub fn new(mmap: MmapMut, flags: u32) -> Result<Self> {
        let mut tree = Self {
            hash_set: MappedHashSet::new(mmap, flags)?,
        };
        tree.init_empty()?;
        Ok(tree)
    }

    /// Returns the number of nodes in the underlying hash table.
    pub fn size(&self) -> usize {
        self.hash_set.size()
    }

    /// Returns the capacity (in terms of number of nodes) of the underlying hash table.
    ///
    /// NOTE: this will always return a power of 2.
    pub fn capacity(&self) -> usize {
        self.hash_set.capacity()
    }

    /// Destroys the `Tree` and returns the wrapped memory map.
    pub fn take(self) -> MmapMut {
        self.hash_set.take()
    }

    /// Returns the current root hash.
    pub fn root_hash(&self) -> Scalar {
        self.hash_set.header_data().root_hash()
    }

    /// REQUIRES: `hash` must refer to an existing node at level H-1.
    fn set_root(&mut self, hash: Scalar) -> Result<()> {
        self.ref_node(hash);
        self.unref_node(self.root_hash(), H - 1)?;
        self.hash_set.header_data_mut().set_root_hash(hash);
        Ok(())
    }

    /// Adds an extra ref to the current root so that it can no longer be discarded.
    ///
    /// The returned scalar is the reffed root hash.
    ///
    /// This method is useful for implementing block closure: at closure time the latest root can be
    /// "sealed" by calling this method and the returned root hash can be used along with other
    /// block data to compute the block hash.
    ///
    /// NOTE: if a tree doesn't change for K consecutive blocks, the same root node will end up
    /// getting reffed K times. That is not a problem.
    pub fn commit(&mut self) -> Scalar {
        let root_hash = self.root_hash();
        self.ref_node(root_hash);
        root_hash
    }
}

impl<const H: usize> Tree<2, H> {
    /// Returns the value associated with the specified key.
    pub fn get(&self, key: Scalar) -> Scalar {
        let mut node = self.hash_set.get(self.root_hash()).unwrap();
        for i in (1..H).rev() {
            let bit = xits::and1(xits::shr(key, i)).to_repr()[0];
            let child_hash = node.child(bit as usize);
            node = self.hash_set.get(child_hash).unwrap();
        }
        let bit = xits::and1(key).to_repr()[0];
        node.child(bit as usize)
    }

    /// Looks up an element and returns it along with a Merkle proof for it.
    ///
    /// Returns `None` if the element is not found.
    pub fn get_proof(&self, key: Scalar) -> merkle::Proof<Scalar, Scalar, 2, H> {
        let mut path = [[Scalar::ZERO; 2]; H];
        let mut node = self.hash_set.get(self.root_hash()).unwrap();
        for i in (1..H).rev() {
            path[i] = node.children();
            let bit = xits::and1(xits::shr(key, i)).to_repr()[0];
            let child_hash = node.child(bit as usize);
            node = self.hash_set.get(child_hash).unwrap();
        }
        path[0] = node.children();
        let bit = xits::and1(key).to_repr()[0];
        let value = node.child(bit as usize);
        merkle::Proof::new(key, value, path, self.root_hash())
    }

    fn update(&mut self, hash: Scalar, level: usize, key: Scalar, value: Scalar) -> Result<Scalar> {
        let node = self.hash_set.get(hash).unwrap();
        let mut children = node.children();
        let bit = xits::and1(xits::shr(key, level)).to_repr()[0];
        children[bit as usize] = if level > 0 {
            self.update(children[bit as usize], level - 1, key, value)?
        } else {
            value
        };
        Ok(self.make_node(&children, level == 0)?.hash())
    }

    /// Updates the value associated with the specified key.
    pub fn put(&mut self, key: Scalar, value: Scalar) -> Result<()> {
        let new_root = self.update(self.root_hash(), H - 1, key, value)?;
        self.set_root(new_root)?;
        Ok(())
    }
}

impl<const H: usize> Tree<3, H> {
    /// Returns the value associated with the specified key.
    pub fn get(&self, key: Scalar) -> Scalar {
        let mut node = self.hash_set.get(self.root_hash()).unwrap();
        for i in (1..H).rev() {
            let trit = xits::mod3(xits::div_pow3(key, i)).to_repr()[0];
            let child_hash = node.child(trit as usize);
            node = self.hash_set.get(child_hash).unwrap();
        }
        let trit = xits::mod3(key).to_repr()[0];
        node.child(trit as usize)
    }

    /// Looks up an element and returns it along with a Merkle proof for it.
    ///
    /// Returns `None` if the element is not found.
    pub fn get_proof(&self, key: Scalar) -> merkle::Proof<Scalar, Scalar, 3, H> {
        let mut path = [[Scalar::ZERO; 3]; H];
        let mut node = self.hash_set.get(self.root_hash()).unwrap();
        for i in (1..H).rev() {
            path[i] = node.children();
            let trit = xits::mod3(xits::div_pow3(key, i)).to_repr()[0];
            let child_hash = node.child(trit as usize);
            node = self.hash_set.get(child_hash).unwrap();
        }
        path[0] = node.children();
        let trit = xits::mod3(key).to_repr()[0];
        let value = node.child(trit as usize);
        merkle::Proof::new(key, value, path, self.root_hash())
    }

    fn update(&mut self, hash: Scalar, level: usize, key: Scalar, value: Scalar) -> Result<Scalar> {
        let node = self.hash_set.get(hash).unwrap();
        let mut children = node.children();
        let trit = xits::mod3(xits::div_pow3(key, level)).to_repr()[0];
        children[trit as usize] = if level > 0 {
            self.update(children[trit as usize], level - 1, key, value)?
        } else {
            value
        };
        Ok(self.make_node(&children, level == 0)?.hash())
    }

    /// Updates the value associated with the specified key.
    pub fn put(&mut self, key: Scalar, value: Scalar) -> Result<()> {
        let new_root = self.update(self.root_hash(), H - 1, key, value)?;
        self.set_root(new_root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants, testing::parse_scalar};
    use crypto::utils;
    use primitive_types::U256;

    const TEST_FLAGS: u32 = constants::DATA_FILE_TYPE_TEST_TREE;

    fn test_key1() -> Scalar {
        parse_scalar("0x37c75d7b351d02bc8d5193a1d445f1e8e453df601a2b0a7b8ec33a23cab82611")
    }

    fn test_key2() -> Scalar {
        parse_scalar("0x08579a2aff29eb5764cbae109a4e47c68537877ade4cfd317f21cc8984a4f4a1")
    }

    #[test]
    fn test_assumptions1() {
        let mut value = utils::scalar_to_u256(-Scalar::from(1));
        let zero = U256::from(0);
        let three = U256::from(3);
        let mut counter = 0;
        while value != zero {
            value /= three;
            counter += 1;
        }
        // Check that a BLS12-381 scalar decomposes into 161 trits.
        assert_eq!(counter, 161);
    }

    #[test]
    fn test_assumptions2() {
        let max = -Scalar::from(1);
        let msb1 = xits::and1(xits::shr(max, 255));
        let msb2 = xits::and1(xits::shr(max, 254));
        let mst1 = xits::mod3(xits::div_pow3(max, 161));
        let mst2 = xits::mod3(xits::div_pow3(max, 160));
        assert_eq!(msb1, 0.into());
        assert_eq!(msb2, 1.into());
        assert_eq!(mst1, 0.into());
        assert_eq!(mst2, 2.into());
    }

    #[test]
    fn test_binary_tree_format() {
        type TestTree = Tree<2, 256>;
        assert_eq!(TestTree::padded_header_size(), 64);
        assert_eq!(TestTree::padded_node_size(), 104);
    }

    #[test]
    fn test_ternary_tree_format() {
        type TestTree = Tree<3, 161>;
        assert_eq!(TestTree::padded_header_size(), 64);
        assert_eq!(TestTree::padded_node_size(), 136);
    }

    fn make_test_tree<const W: usize, const H: usize>(capacity: usize) -> Result<Tree<W, H>> {
        Tree::new(
            MmapMut::map_anon(
                Tree::<W, H>::padded_header_size() + capacity * Tree::<W, H>::padded_node_size(),
            )?,
            TEST_FLAGS,
        )
    }

    fn make_default_test_tree<const W: usize, const H: usize>() -> Result<Tree<W, H>> {
        make_test_tree(Tree::<W, H>::min_capacity())
    }

    fn lookup2<const H: usize>(tree: &Tree<2, H>, key: Scalar) -> Scalar {
        let value = tree.get(key);
        let proof = tree.get_proof(key);
        assert!(proof.verify().is_ok());
        assert_eq!(*proof.value(), value);
        value
    }

    fn lookup3<const H: usize>(tree: &Tree<3, H>, key: Scalar) -> Scalar {
        let value = tree.get(key);
        let proof = tree.get_proof(key);
        assert!(proof.verify().is_ok());
        assert_eq!(*proof.value(), value);
        value
    }

    #[test]
    fn test_new_binary_tree_h1() {
        const CAPACITY: usize = Tree::<2, 1>::min_capacity();
        let tree = make_test_tree::<2, 1>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x44fbea4934de59fe3dea4bb6ce5f053fe967f8c43a872b343a6d12fe40d75ca3")
        );
        assert_eq!(lookup2(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 1.into()), Scalar::ZERO);
    }

    #[test]
    fn test_new_binary_tree_h2() {
        const CAPACITY: usize = Tree::<2, 2>::min_capacity();
        let tree = make_test_tree::<2, 2>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 2);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x1642477fce8a9cfc7fef8c1adac8bb6212a12603545af958b6fa28f0099cdf1e")
        );
        assert_eq!(lookup2(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 3.into()), Scalar::ZERO);
    }

    #[test]
    fn test_new_binary_tree_h3() {
        const CAPACITY: usize = Tree::<2, 3>::min_capacity();
        let tree = make_test_tree::<2, 3>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 3);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x30ac7c720131f3ab706f3c8542a0ecdd6ca65b0f690cbea695b699fb2a6a0a6b")
        );
        assert_eq!(lookup2(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 3.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 4.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 5.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 6.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 7.into()), Scalar::ZERO);
    }

    #[test]
    fn test_new_ternary_tree_h1() {
        const CAPACITY: usize = Tree::<3, 1>::min_capacity();
        let tree = make_test_tree::<3, 1>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x447e7f6236dfaf8f3ddf7f0cd38eae309b9bff95f4ea6ecf2a46d106abd0623c")
        );
        assert_eq!(lookup3(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 2.into()), Scalar::ZERO);
    }

    #[test]
    fn test_new_ternary_tree_h2() {
        const CAPACITY: usize = Tree::<3, 2>::min_capacity();
        let tree = make_test_tree::<3, 2>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 2);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x0813d9fa859ac9c7c3c147af1bf38a8d34a95d71dddb59cb362741af4a5ce374")
        );
        assert_eq!(lookup3(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 3.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 4.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 5.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 6.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 7.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 8.into()), Scalar::ZERO);
    }

    #[test]
    fn test_new_ternary_tree_h3() {
        const CAPACITY: usize = Tree::<3, 3>::min_capacity();
        let tree = make_test_tree::<3, 3>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 3);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x0d59114550233029c2dd76cb35aed5d87d0c11af9dcc16d59aea354cdf7b1904")
        );
        assert_eq!(lookup3(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 3.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 4.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 5.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 6.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 7.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 8.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 9.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 10.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 11.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 12.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 13.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 14.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 15.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 16.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 17.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 18.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 19.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 20.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 21.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 22.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 23.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 24.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 25.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 26.into()), Scalar::ZERO);
    }

    #[test]
    fn test_update_binary_tree_h1_0() {
        const CAPACITY: usize = Tree::<2, 1>::min_capacity();
        let mut tree = make_test_tree::<2, 1>(CAPACITY).unwrap();
        assert!(tree.put(0.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x3096077a3d12ab01b506e6aceda3c0dda9fe86c329ce2996ee63e1517b729e29")
        );
        assert_eq!(lookup2(&tree, 0.into()), 42.into());
        assert_eq!(lookup2(&tree, 1.into()), Scalar::ZERO);
    }

    #[test]
    fn test_update_binary_tree_h1_1() {
        const CAPACITY: usize = Tree::<2, 1>::min_capacity();
        let mut tree = make_test_tree::<2, 1>(CAPACITY).unwrap();
        assert!(tree.put(1.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x6efc51a0910e467104e12e8667bed7d2f15928ec6f33608bb2432face70aed53")
        );
        assert_eq!(lookup2(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, 1.into()), 42.into());
    }

    #[test]
    fn test_update_binary_tree_h2() {
        let mut tree = make_test_tree::<2, 2>(4).unwrap();
        assert!(tree.put(0.into(), 12.into()).is_ok());
        assert!(tree.put(1.into(), 34.into()).is_ok());
        assert!(tree.put(2.into(), 56.into()).is_ok());
        assert!(tree.put(3.into(), 78.into()).is_ok());
        assert_eq!(tree.size(), 3);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x23531e38b11a44fa07a42dd66cd777dc0b57c1bab00b8b3ceae7915790fcc544")
        );
        assert_eq!(lookup2(&tree, 0.into()), 12.into());
        assert_eq!(lookup2(&tree, 1.into()), 34.into());
        assert_eq!(lookup2(&tree, 2.into()), 56.into());
        assert_eq!(lookup2(&tree, 3.into()), 78.into());
    }

    #[test]
    fn test_update_ternary_tree_h1_0() {
        const CAPACITY: usize = Tree::<3, 1>::min_capacity();
        let mut tree = make_test_tree::<3, 1>(CAPACITY).unwrap();
        assert!(tree.put(0.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x371862e4591023f4be2dd1b86827e2ef6dac40c430beab9d12344ddeef2a5802")
        );
        assert_eq!(lookup3(&tree, 0.into()), 42.into());
        assert_eq!(lookup3(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 2.into()), Scalar::ZERO);
    }

    #[test]
    fn test_update_ternary_tree_h1_1() {
        const CAPACITY: usize = Tree::<3, 1>::min_capacity();
        let mut tree = make_test_tree::<3, 1>(CAPACITY).unwrap();
        assert!(tree.put(1.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x438559edc8c31ac7792ecd45400af39cc7f4bef768b0ab368e9dc156590c712d")
        );
        assert_eq!(lookup3(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 1.into()), 42.into());
        assert_eq!(lookup3(&tree, 2.into()), Scalar::ZERO);
    }

    #[test]
    fn test_update_ternary_tree_h1_2() {
        const CAPACITY: usize = Tree::<3, 1>::min_capacity();
        let mut tree = make_test_tree::<3, 1>(CAPACITY).unwrap();
        assert!(tree.put(2.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x1b4a382ee991eaadbf46b52b4806a2871b2a79a5486468aa74eea1025214cb80")
        );
        assert_eq!(lookup3(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, 2.into()), 42.into());
    }

    #[test]
    fn test_update_ternary_tree_h2() {
        let mut tree = make_test_tree::<3, 2>(4).unwrap();
        assert!(tree.put(0.into(), 123.into()).is_ok());
        assert!(tree.put(1.into(), 456.into()).is_ok());
        assert!(tree.put(2.into(), 789.into()).is_ok());
        assert!(tree.put(3.into(), 231.into()).is_ok());
        assert!(tree.put(4.into(), 564.into()).is_ok());
        assert!(tree.put(5.into(), 897.into()).is_ok());
        assert!(tree.put(6.into(), 312.into()).is_ok());
        assert!(tree.put(7.into(), 645.into()).is_ok());
        assert!(tree.put(8.into(), 978.into()).is_ok());
        assert_eq!(tree.size(), 4);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x48342267b9354cf2846a25aa333559c0123d339c81cef6cd385c14bc44232d34")
        );
        assert_eq!(lookup3(&tree, 0.into()), 123.into());
        assert_eq!(lookup3(&tree, 1.into()), 456.into());
        assert_eq!(lookup3(&tree, 2.into()), 789.into());
        assert_eq!(lookup3(&tree, 3.into()), 231.into());
        assert_eq!(lookup3(&tree, 4.into()), 564.into());
        assert_eq!(lookup3(&tree, 5.into()), 897.into());
        assert_eq!(lookup3(&tree, 6.into()), 312.into());
        assert_eq!(lookup3(&tree, 7.into()), 645.into());
        assert_eq!(lookup3(&tree, 8.into()), 978.into());
    }

    #[test]
    fn test_new_tall_binary_tree() {
        const CAPACITY: usize = Tree::<2, 256>::min_capacity();
        let tree = make_test_tree::<2, 256>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 256);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x705e15516059a313b2ffe555adaba446dda553dd38588b322f4415d62dcd0595")
        );
        assert_eq!(lookup2(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, test_key2()), Scalar::ZERO);
    }

    #[test]
    fn test_new_tall_ternary_tree() {
        const CAPACITY: usize = Tree::<3, 161>::min_capacity();
        let tree = make_test_tree::<3, 161>(CAPACITY).unwrap();
        assert_eq!(tree.size(), 161);
        assert_eq!(tree.capacity(), CAPACITY);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x54da9bb9b3fa9ac90efeef9e08ef2e7c18096f37b739fa4a20bf838905a2df0e")
        );
        assert_eq!(lookup3(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, test_key2()), Scalar::ZERO);
    }

    #[test]
    fn test_update_tall_binary_tree1() {
        let mut tree = make_default_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 511);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x41888c7fcb9ae568fd2d8f06451c53cd4e9a4467b43cddf99dd85c0ebe2a9eba")
        );
        assert_eq!(lookup2(&tree, test_key1()), 42.into());
        assert_eq!(lookup2(&tree, test_key2()), Scalar::ZERO);
    }

    #[test]
    fn test_update_tall_binary_tree2() {
        let mut tree = make_default_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key2(), 42.into()).is_ok());
        assert_eq!(tree.size(), 511);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x54c178302d47924841f468ec60fe19c7ba00ab7f462033addbf2017883674394")
        );
        assert_eq!(lookup2(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup2(&tree, test_key2()), 42.into());
    }

    #[test]
    fn test_update_tall_binary_tree3() {
        let mut tree = make_default_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key1(), 12.into()).is_ok());
        assert!(tree.put(test_key2(), 34.into()).is_ok());
        assert_eq!(tree.size(), 764);
        assert_eq!(tree.capacity(), 2048);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x1f25951405498baaf9350017b7a798219489047db7482a071e74fca027d9f32b")
        );
        assert_eq!(lookup2(&tree, test_key1()), 12.into());
        assert_eq!(lookup2(&tree, test_key2()), 34.into());
    }

    #[test]
    fn test_update_tall_binary_tree_twice() {
        let mut tree = make_default_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key1(), 123.into()).is_ok());
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 511);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x41888c7fcb9ae568fd2d8f06451c53cd4e9a4467b43cddf99dd85c0ebe2a9eba")
        );
        assert_eq!(lookup2(&tree, test_key1()), 42.into());
        assert_eq!(lookup2(&tree, test_key2()), Scalar::ZERO);
    }

    #[test]
    fn test_update_tall_ternary_tree1() {
        let mut tree = make_default_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 321);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x2fc22d9cc6ce2f9377943565491dc6bdc235d92feed593822450de771dc81da7")
        );
        assert_eq!(lookup3(&tree, test_key1()), 42.into());
        assert_eq!(lookup3(&tree, test_key2()), Scalar::ZERO);
    }

    #[test]
    fn test_update_tall_ternary_tree2() {
        let mut tree = make_default_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key2(), 42.into()).is_ok());
        assert_eq!(tree.size(), 321);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x2b29d23dcca6d4e20382956f22d69da75780fd29901fd04009bd1495ca629b85")
        );
        assert_eq!(lookup3(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup3(&tree, test_key2()), 42.into());
    }

    #[test]
    fn test_update_tall_ternary_tree3() {
        let mut tree = make_default_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key1(), 12.into()).is_ok());
        assert!(tree.put(test_key2(), 34.into()).is_ok());
        assert_eq!(tree.size(), 481);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x5a588281d792add7c1fc9fda9a10bf136559e6be638fcf19f41876cb0acd0637")
        );
        assert_eq!(lookup3(&tree, test_key1()), 12.into());
        assert_eq!(lookup3(&tree, test_key2()), 34.into());
    }

    #[test]
    fn test_update_tall_ternary_tree_twice() {
        let mut tree = make_default_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key1(), 123.into()).is_ok());
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 321);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x2fc22d9cc6ce2f9377943565491dc6bdc235d92feed593822450de771dc81da7")
        );
        assert_eq!(lookup3(&tree, test_key1()), 42.into());
        assert_eq!(lookup3(&tree, test_key2()), Scalar::ZERO);
    }

    #[test]
    fn test_reload_binary_tree() {
        let (mmap, root_hash) = {
            let mut tree = make_default_test_tree::<2, 256>().unwrap();
            assert!(tree.put(test_key1(), 42.into()).is_ok());
            let root_hash = tree.root_hash();
            (tree.take(), root_hash)
        };
        let tree = Tree::<2, 256>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(tree.root_hash(), root_hash);
    }

    #[test]
    fn test_reload_ternary_tree() {
        let (mmap, root_hash) = {
            let mut tree = make_default_test_tree::<3, 161>().unwrap();
            assert!(tree.put(test_key1(), 42.into()).is_ok());
            let root_hash = tree.root_hash();
            (tree.take(), root_hash)
        };
        let tree = Tree::<3, 161>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(tree.root_hash(), root_hash);
    }
}
