use crate::store::{
    HeaderData, MappedHashSet, NodeData, Stored, StoredCircularBuffer, StoredScalar, StoredU64,
};
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::{merkle, poseidon, utils, xits};
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

/// Internal implementation shared by `Tree` and `Forest`.
#[derive(Debug)]
struct Repr<HD: HeaderData, const W: usize, const H: usize> {
    hash_set: MappedHashSet<HD, Node<W>>,
}

impl<HD: HeaderData, const W: usize, const H: usize> Repr<HD, W, H> {
    const PADDED_HEADER_SIZE: usize = MappedHashSet::<HD, Node<W>>::PADDED_HEADER_SIZE;
    const MAX_HEADER_DATA_SIZE: usize = MappedHashSet::<HD, Node<W>>::MAX_HEADER_DATA_SIZE;

    const fn padded_node_size() -> usize {
        MappedHashSet::<HD, Node<W>>::padded_node_size()
    }

    const fn get_max_capacity_for(size: usize) -> usize {
        MappedHashSet::<HD, Node<W>>::get_max_capacity_for(size)
    }

    /// Returns true if the underlying hash set contains the element identified by the specified
    /// hash, false otheriwse.
    fn has_node(&self, hash: Scalar) -> bool {
        self.hash_set.has(hash)
    }

    /// Increments the reference count of a node.
    ///
    /// REQUIRES: `hash` must refer to an existing node.
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
        self.hash_set.shrink_to_fit()?;
        Ok(true)
    }

    /// Constructs a new `Repr` over the provided memory-mapped region.
    fn new(mmap: MmapMut, expected_flags: u32) -> Result<Self> {
        Ok(Self {
            hash_set: MappedHashSet::new(mmap, expected_flags)?,
        })
    }

    /// Loads a `Repr` from the provided memory-mapped data.
    fn load(mmap: MmapMut, expected_flags: u32) -> Result<Self> {
        Ok(Self {
            hash_set: MappedHashSet::load(mmap, expected_flags)?,
        })
    }

    /// Returns a reference to the header.
    fn header(&self) -> &HD {
        self.hash_set.header_data()
    }

    /// Returns a mutable reference to the header.
    fn header_mut(&mut self) -> &mut HD {
        self.hash_set.header_data_mut()
    }

    /// Returns the number of nodes in the underlying hash table.
    ///
    /// NOTE: this is only the number of physical nodes in the underlying hash set. The number of
    /// logical nodes of an SMT is always W^H, eg. 2^256 for a binary tree with height 256.
    fn size(&self) -> usize {
        self.hash_set.size()
    }

    /// Returns the capacity (in terms of number of nodes) of the underlying hash table.
    ///
    /// NOTE: this will always return a power of 2.
    fn capacity(&self) -> usize {
        self.hash_set.capacity()
    }

    /// Extracts the wrapped memory map.
    fn take(self) -> MmapMut {
        self.hash_set.take()
    }

    /// Constructs the `H` nodes of an empty tree, referencing all of them exactly once.
    ///
    /// The returned scalar is the hash of the root node.
    ///
    /// NOTE: if the nodes of the empty tree already exist, the only effect of this function is to
    /// reference the root one more time.
    fn init_empty(&mut self) -> Result<Scalar> {
        let mut hash = Scalar::ZERO;
        for i in 0..H {
            hash = self
                .make_node(&std::array::from_fn(|_| hash), i == 0)?
                .hash();
        }
        self.ref_node(hash);
        Ok(hash)
    }
}

impl<HD: HeaderData, const H: usize> Repr<HD, 2, H> {
    /// Returns the value associated with the specified key.
    ///
    /// REQUIRES: `root_hash` must refer to an existing node.
    fn get(&self, root_hash: Scalar, key: Scalar) -> Scalar {
        let mut node = self.hash_set.get(root_hash).unwrap();
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
    ///
    /// REQUIRES: `root_hash` must refer to an existing node.
    fn get_proof(&self, root_hash: Scalar, key: Scalar) -> merkle::Proof<Scalar, Scalar, 2, H> {
        let mut path = [[Scalar::ZERO; 2]; H];
        let mut node = self.hash_set.get(root_hash).unwrap();
        for i in (1..H).rev() {
            path[i] = node.children();
            let bit = xits::and1(xits::shr(key, i)).to_repr()[0];
            let child_hash = node.child(bit as usize);
            node = self.hash_set.get(child_hash).unwrap();
        }
        path[0] = node.children();
        let bit = xits::and1(key).to_repr()[0];
        let value = node.child(bit as usize);
        merkle::Proof::new(key, value, path, root_hash)
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
    ///
    /// REQUIRES: `root_hash` must refer to an existing node.
    fn put(&mut self, root_hash: Scalar, key: Scalar, value: Scalar) -> Result<Scalar> {
        self.update(root_hash, H - 1, key, value)
    }
}

impl<HD: HeaderData, const H: usize> Repr<HD, 3, H> {
    /// Returns the value associated with the specified key.
    ///
    /// REQUIRES: `root_hash` must refer to an existing node.
    pub fn get(&self, root_hash: Scalar, key: Scalar) -> Scalar {
        let mut node = self.hash_set.get(root_hash).unwrap();
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
    ///
    /// REQUIRES: `root_hash` must refer to an existing node.
    pub fn get_proof(&self, root_hash: Scalar, key: Scalar) -> merkle::Proof<Scalar, Scalar, 3, H> {
        let mut path = [[Scalar::ZERO; 3]; H];
        let mut node = self.hash_set.get(root_hash).unwrap();
        for i in (1..H).rev() {
            path[i] = node.children();
            let trit = xits::mod3(xits::div_pow3(key, i)).to_repr()[0];
            let child_hash = node.child(trit as usize);
            node = self.hash_set.get(child_hash).unwrap();
        }
        path[0] = node.children();
        let trit = xits::mod3(key).to_repr()[0];
        let value = node.child(trit as usize);
        merkle::Proof::new(key, value, path, root_hash)
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
    ///
    /// REQUIRES: `root_hash` must refer to an existing node.
    pub fn put(&mut self, root_hash: Scalar, key: Scalar, value: Scalar) -> Result<Scalar> {
        self.update(root_hash, H - 1, key, value)
    }
}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
struct TreeHeader {
    root_hashes: StoredCircularBuffer<StoredScalar, 126>,
}

impl TreeHeader {
    fn root_hash(&self) -> Scalar {
        self.root_hashes.top().to_scalar()
    }

    fn set_root_hash(&mut self, hash: Scalar) {
        *self.root_hashes.top_mut() = hash.into();
    }

    fn add_root_hash(&mut self, hash: Scalar) {
        self.root_hashes.push(hash.into());
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
/// to zero. Cyclic references are not possible because a tree is an acyclic graph by definition.
///
/// Note that a node may appear as the child of another node more than once. For example, if the two
/// subtrees of a binary tree node are identical they won't be stored twice; instead they'll have
/// node-by-node identical hashes, so they'll be stored as a single subtree referenced by the parent
/// node twice. Case in point, an empty tree with height `H` only requires storing `H` nodes in our
/// implementation.
#[derive(Debug)]
pub struct Tree<const W: usize, const H: usize> {
    repr: Repr<TreeHeader, W, H>,
}

impl<const W: usize, const H: usize> Tree<W, H> {
    /// The byte size allocated for the header.
    pub const PADDED_HEADER_SIZE: usize = Repr::<TreeHeader, W, H>::PADDED_HEADER_SIZE;

    const MAX_HEADER_DATA_SIZE: usize = Repr::<TreeHeader, W, H>::MAX_HEADER_DATA_SIZE;

    /// Returns the byte size allocated for every node.
    pub const fn padded_node_size() -> usize {
        Repr::<TreeHeader, W, H>::padded_node_size()
    }

    /// Returns the optimal initial capacity (in terms of number of nodes) for this type of tree.
    ///
    /// The memory-mapped data slice provided at construction should be
    /// `PADDED_HEADER_SIZE + optimal_initial_capacity() * padded_node_size()` bytes long.
    pub const fn optimal_initial_capacity() -> usize {
        Repr::<TreeHeader, W, H>::get_max_capacity_for(H)
    }

    fn init_empty(&mut self) -> Result<()> {
        let root_hash = self.repr.init_empty()?;
        self.repr.header_mut().add_root_hash(root_hash);
        Ok(())
    }

    /// Initializes a new empty tree over the provided memory-mapped region.
    pub fn new(mmap: MmapMut, flags: u32) -> Result<Self> {
        let mut tree = Self {
            repr: Repr::new(mmap, flags)?,
        };
        tree.init_empty()?;
        Ok(tree)
    }

    /// Constructs a `Tree` from the provided memory-mapped data.
    pub fn load(mmap: MmapMut, expected_flags: u32) -> Result<Self> {
        let tree = Self {
            repr: Repr::load(mmap, expected_flags)?,
        };
        let root_hash = tree.root_hash();
        if !tree.repr.has_node(root_hash) {
            return Err(anyhow!(
                "invalid root hash {}",
                utils::format_scalar(root_hash)
            ));
        }
        Ok(tree)
    }

    /// Returns the number of nodes in the underlying hash table.
    ///
    /// NOTE: this is only the number of physical nodes in the underlying hash set. The number of
    /// logical nodes of an SMT is always W^H, eg. 2^256 for a binary tree with height 256.
    pub fn size(&self) -> usize {
        self.repr.size()
    }

    /// Returns the capacity (in terms of number of nodes) of the underlying hash table.
    ///
    /// NOTE: this will always return a power of 2.
    pub fn capacity(&self) -> usize {
        self.repr.capacity()
    }

    /// Extracts the wrapped memory map.
    pub fn take(self) -> MmapMut {
        self.repr.take()
    }

    /// Returns the current root hash.
    pub fn root_hash(&self) -> Scalar {
        self.repr.header().root_hash()
    }

    /// REQUIRES: `hash` must refer to an existing node at level H-1.
    fn set_root(&mut self, hash: Scalar) -> Result<()> {
        self.repr.ref_node(hash);
        self.repr.unref_node(self.root_hash(), H - 1)?;
        self.repr.header_mut().set_root_hash(hash);
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
        self.repr.ref_node(root_hash);
        self.repr.header_mut().add_root_hash(root_hash);
        root_hash
    }
}

impl<const H: usize> Tree<2, H> {
    /// Returns the value associated with the specified key.
    pub fn get(&self, key: Scalar) -> Scalar {
        self.repr.get(self.root_hash(), key)
    }

    /// Looks up an element and returns it along with a Merkle proof for it.
    ///
    /// Returns `None` if the element is not found.
    pub fn get_proof(&self, key: Scalar) -> merkle::Proof<Scalar, Scalar, 2, H> {
        self.repr.get_proof(self.root_hash(), key)
    }

    /// Updates the value associated with the specified key.
    pub fn put(&mut self, key: Scalar, value: Scalar) -> Result<()> {
        let new_root = self.repr.put(self.root_hash(), key, value)?;
        self.set_root(new_root)?;
        Ok(())
    }
}

impl<const H: usize> Tree<3, H> {
    /// Returns the value associated with the specified key.
    pub fn get(&self, key: Scalar) -> Scalar {
        self.repr.get(self.root_hash(), key)
    }

    /// Looks up an element and returns it along with a Merkle proof for it.
    ///
    /// Returns `None` if the element is not found.
    pub fn get_proof(&self, key: Scalar) -> merkle::Proof<Scalar, Scalar, 3, H> {
        self.repr.get_proof(self.root_hash(), key)
    }

    /// Updates the value associated with the specified key.
    pub fn put(&mut self, key: Scalar, value: Scalar) -> Result<()> {
        let new_root = self.repr.put(self.root_hash(), key, value)?;
        self.set_root(new_root)?;
        Ok(())
    }
}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
struct ForestHeader {
    empty_root_hash: StoredScalar,
}

impl ForestHeader {
    fn empty_root_hash(&self) -> Scalar {
        self.empty_root_hash.to_scalar()
    }

    fn set_empty_root_hash(&mut self, empty_root_hash: Scalar) {
        self.empty_root_hash = empty_root_hash.into();
    }
}

impl Stored for ForestHeader {}
impl HeaderData for ForestHeader {}

/// A forest of Sparse Merkle Trees.
///
/// This data structure is used to store nested merkle trees, such as the ones used for
/// smartcontract storage. We can't store a separate tree file for every smartcontract, so we store
/// all smartcontract storage trees in a single file instead. As an added benefit, the trees will
/// share identical subtree portions and save some disk space.
///
/// NOTE: this data structure does not keep track of all the roots. That is up to the user. For
/// smartcontract storage, the root hashes are stored in the leaves of the singleton parent tree.
#[derive(Debug)]
pub struct Forest<const W: usize, const H: usize> {
    repr: Repr<ForestHeader, W, H>,
}

impl<const W: usize, const H: usize> Forest<W, H> {
    /// The byte size allocated for the header.
    pub const PADDED_HEADER_SIZE: usize = Repr::<ForestHeader, W, H>::PADDED_HEADER_SIZE;

    const MAX_HEADER_DATA_SIZE: usize = Repr::<ForestHeader, W, H>::MAX_HEADER_DATA_SIZE;

    /// Returns the byte size allocated for every node.
    pub const fn padded_node_size() -> usize {
        Repr::<ForestHeader, W, H>::padded_node_size()
    }

    /// Returns the optimal initial capacity (in terms of number of nodes) for this type of tree.
    ///
    /// The memory-mapped data slice provided at construction should be
    /// `PADDED_HEADER_SIZE + optimal_initial_capacity() * padded_node_size()` bytes long.
    pub const fn optimal_initial_capacity() -> usize {
        Repr::<ForestHeader, W, H>::get_max_capacity_for(H)
    }

    /// Returns the root hash of the empty tree, which can always be assumed to be in the forest and
    /// can be used to create new trees.
    pub fn empty_root_hash(&self) -> Scalar {
        self.repr.header().empty_root_hash()
    }

    fn init_empty(&mut self) -> Result<()> {
        let empty_root_hash = self.repr.init_empty()?;
        self.repr.header_mut().set_empty_root_hash(empty_root_hash);
        Ok(())
    }

    /// Initializes a new empty forest over the provided memory-mapped region.
    pub fn new(mmap: MmapMut, flags: u32) -> Result<Self> {
        let mut forest = Self {
            repr: Repr::new(mmap, flags)?,
        };
        forest.init_empty()?;
        Ok(forest)
    }

    fn calculate_empty_root_hash() -> Scalar {
        let mut hash = Scalar::ZERO;
        for _ in 0..H {
            hash = match W {
                2 => poseidon::hash_t3(&[hash, hash]),
                3 => poseidon::hash_t4(&[hash, hash, hash]),
                _ => unimplemented!(),
            };
        }
        hash
    }

    /// Constructs a `Forest` from the provided memory-mapped data.
    pub fn load(mmap: MmapMut, expected_flags: u32) -> Result<Self> {
        let forest = Self {
            repr: Repr::load(mmap, expected_flags)?,
        };
        let empty_root_hash = forest.empty_root_hash();
        let expected_empty_root_hash = Self::calculate_empty_root_hash();
        if empty_root_hash != expected_empty_root_hash {
            return Err(anyhow!(
                "incorrect empty root hash (got {}, want {})",
                empty_root_hash,
                expected_empty_root_hash
            ));
        }
        if !forest.repr.has_node(empty_root_hash) {
            return Err(anyhow!(
                "empty tree {} not found in forest",
                utils::format_scalar(empty_root_hash)
            ));
        }
        Ok(forest)
    }

    /// Returns the number of nodes in the underlying hash table.
    ///
    /// NOTE: this is only the number of physical nodes in the underlying hash set. The number of
    /// logical nodes of an SMT is always W^H, eg. 2^256 for a binary tree with height 256.
    pub fn size(&self) -> usize {
        self.repr.size()
    }

    /// Returns the capacity (in terms of number of nodes) of the underlying hash table.
    ///
    /// NOTE: this will always return a power of 2.
    pub fn capacity(&self) -> usize {
        self.repr.capacity()
    }

    /// Extracts the wrapped memory map.
    pub fn take(self) -> MmapMut {
        self.repr.take()
    }
}

impl<const H: usize> Forest<2, H> {
    /// Looks up an element in the tree rooted at `root_hash` and returns its value.
    ///
    /// REQUIRES: `root_hash` must refer to a valid tree root.
    pub fn get(&self, root_hash: Scalar, key: Scalar) -> Scalar {
        self.repr.get(root_hash, key)
    }

    /// Looks up an element in the tree rooted at `root_hash` and returns its value along with a
    /// Merkle proof for it.
    ///
    /// Returns `None` if the element is not found.
    ///
    /// REQUIRES: `root_hash` must refer to a valid tree root.
    pub fn get_proof(&self, root_hash: Scalar, key: Scalar) -> merkle::Proof<Scalar, Scalar, 2, H> {
        self.repr.get_proof(root_hash, key)
    }

    /// Updates the value associated with the specified `key` in the tree rooted at `root_hash` and
    /// returns the new root hash of that tree.
    ///
    /// REQUIRES: `root_hash` must refer to a valid tree root.
    pub fn put(&mut self, root_hash: Scalar, key: Scalar, value: Scalar) -> Result<Scalar> {
        let new_root_hash = self.repr.put(root_hash, key, value)?;
        self.repr.ref_node(new_root_hash);
        if root_hash != self.repr.header().empty_root_hash() {
            self.repr.unref_node(root_hash, H - 1)?;
        }
        Ok(new_root_hash)
    }
}

impl<const H: usize> Forest<3, H> {
    /// Looks up an element in the tree rooted at `root_hash` and returns its value.
    ///
    /// REQUIRES: `root_hash` must refer to a valid tree root.
    pub fn get(&self, root_hash: Scalar, key: Scalar) -> Scalar {
        self.repr.get(root_hash, key)
    }

    /// Looks up an element in the tree rooted at `root_hash` and returns its value along with a
    /// Merkle proof for it.
    ///
    /// Returns `None` if the element is not found.
    ///
    /// REQUIRES: `root_hash` must refer to a valid tree root.
    pub fn get_proof(&self, root_hash: Scalar, key: Scalar) -> merkle::Proof<Scalar, Scalar, 3, H> {
        self.repr.get_proof(root_hash, key)
    }

    /// Updates the value associated with the specified `key` in the tree rooted at `root_hash` and
    /// returns the new root hash of that tree.
    ///
    /// REQUIRES: `root_hash` must refer to a valid tree root.
    pub fn put(&mut self, root_hash: Scalar, key: Scalar, value: Scalar) -> Result<Scalar> {
        let new_root_hash = self.repr.put(root_hash, key, value)?;
        self.repr.ref_node(new_root_hash);
        if root_hash != self.repr.header().empty_root_hash() {
            self.repr.unref_node(root_hash, H - 1)?;
        }
        Ok(new_root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants, testing::parse_scalar};
    use primitive_types::U256;
    use std::collections::{BTreeMap, BTreeSet};

    const TEST_FLAGS: u32 = constants::DATA_FILE_TYPE_TEST_TREE;

    #[derive(Debug)]
    struct ConsistencyChecker<'a, HD: HeaderData, const W: usize, const H: usize> {
        repr: &'a Repr<HD, W, H>,
        ref_counts: BTreeMap<Scalar, u64>,
    }

    impl<'a, HD: HeaderData, const W: usize, const H: usize> ConsistencyChecker<'a, HD, W, H> {
        fn new(repr: &'a Repr<HD, W, H>) -> Self {
            Self {
                repr,
                ref_counts: BTreeMap::default(),
            }
        }

        fn check_impl(&mut self, hash: Scalar, level: usize) -> Result<()> {
            if let Some(ref_count) = self.ref_counts.get_mut(&hash) {
                *ref_count -= 1;
                return Ok(());
            }
            match self.repr.hash_set.get(hash) {
                Some(node) => {
                    if node.hash() != hash {
                        return Err(anyhow!("wrong hash (got {}, want {})", hash, node.hash()));
                    }
                    let ref_count = node.ref_count.to_u64();
                    if ref_count == 0 {
                        return Err(anyhow!(
                            "unreferenced node {} hasn't been removed",
                            utils::format_scalar(node.hash())
                        ));
                    }
                    self.ref_counts.insert(hash, ref_count - 1);
                    if level > 0 {
                        node.children()
                            .iter()
                            .map(|child_hash| self.check_impl(*child_hash, level - 1))
                            .collect::<Result<()>>()?;
                    }
                    Ok(())
                }
                None => Err(anyhow!("node {} not found", utils::format_scalar(hash))),
            }
        }

        fn check(&mut self, root_hashes: &[Scalar]) -> Result<()> {
            for root_hash in root_hashes {
                self.check_impl(*root_hash, H - 1)?;
            }
            if self.ref_counts.len() != self.repr.size() {
                return Err(anyhow!(
                    "incorrect size (got {}, want {})",
                    self.repr.size(),
                    self.ref_counts.len()
                ));
            }
            for (hash, ref_count) in &self.ref_counts {
                if *ref_count != 0 {
                    return Err(anyhow!(
                        "node {} has {} stray references",
                        utils::format_scalar(*hash),
                        *ref_count
                    ));
                }
            }
            Ok(())
        }
    }

    fn check_tree_consistency<const W: usize, const H: usize>(tree: &Tree<W, H>) -> Result<()> {
        tree.repr.hash_set.check_consistency()?;
        ConsistencyChecker::new(&tree.repr).check(&[tree.root_hash()])
    }

    fn check_forest_consistency<const W: usize, const H: usize>(
        forest: &Forest<W, H>,
        root_hashes: &[Scalar],
    ) -> Result<()> {
        forest.repr.hash_set.check_consistency()?;
        let empty_root_hash = forest.empty_root_hash();
        let expected_empty_root_hash = Forest::<W, H>::calculate_empty_root_hash();
        if empty_root_hash != expected_empty_root_hash {
            return Err(anyhow!(
                "incorrect empty root hash (got {}, want {})",
                empty_root_hash,
                expected_empty_root_hash
            ));
        }
        let mut root_hashes = root_hashes
            .iter()
            .map(|hash| *hash)
            .collect::<BTreeSet<Scalar>>();
        root_hashes.insert(empty_root_hash);
        ConsistencyChecker::new(&forest.repr)
            .check(root_hashes.into_iter().collect::<Vec<Scalar>>().as_slice())
    }

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
        assert!(std::mem::size_of::<TreeHeader>() < TestTree::MAX_HEADER_DATA_SIZE);
        assert_eq!(TestTree::PADDED_HEADER_SIZE, 0x1000);
        assert_eq!(TestTree::padded_node_size(), 104);
    }

    #[test]
    fn test_ternary_tree_format() {
        type TestTree = Tree<3, 161>;
        assert!(std::mem::size_of::<TreeHeader>() < TestTree::MAX_HEADER_DATA_SIZE);
        assert_eq!(TestTree::PADDED_HEADER_SIZE, 0x1000);
        assert_eq!(TestTree::padded_node_size(), 136);
    }

    fn make_test_tree<const W: usize, const H: usize>() -> Result<Tree<W, H>> {
        let capacity = Tree::<W, H>::optimal_initial_capacity();
        Tree::new(
            MmapMut::map_anon(
                Tree::<W, H>::PADDED_HEADER_SIZE + capacity * Tree::<W, H>::padded_node_size(),
            )?,
            TEST_FLAGS,
        )
    }

    fn lookup_binary_tree<const H: usize>(tree: &Tree<2, H>, key: Scalar) -> Scalar {
        let value = tree.get(key);
        let proof = tree.get_proof(key);
        assert!(proof.verify().is_ok());
        assert_eq!(*proof.value(), value);
        value
    }

    fn lookup_ternary_tree<const H: usize>(tree: &Tree<3, H>, key: Scalar) -> Scalar {
        let value = tree.get(key);
        let proof = tree.get_proof(key);
        assert!(proof.verify().is_ok());
        assert_eq!(*proof.value(), value);
        value
    }

    #[test]
    fn test_new_binary_tree_h1() {
        let tree = make_test_tree::<2, 1>().unwrap();
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x44fbea4934de59fe3dea4bb6ce5f053fe967f8c43a872b343a6d12fe40d75ca3")
        );
        assert_eq!(lookup_binary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 1.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_binary_tree_h2() {
        let tree = make_test_tree::<2, 2>().unwrap();
        assert_eq!(tree.size(), 2);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x1642477fce8a9cfc7fef8c1adac8bb6212a12603545af958b6fa28f0099cdf1e")
        );
        assert_eq!(lookup_binary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 3.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_binary_tree_h3() {
        let tree = make_test_tree::<2, 3>().unwrap();
        assert_eq!(tree.size(), 3);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x30ac7c720131f3ab706f3c8542a0ecdd6ca65b0f690cbea695b699fb2a6a0a6b")
        );
        assert_eq!(lookup_binary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 3.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 4.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 5.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 6.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 7.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_ternary_tree_h1() {
        let tree = make_test_tree::<3, 1>().unwrap();
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x447e7f6236dfaf8f3ddf7f0cd38eae309b9bff95f4ea6ecf2a46d106abd0623c")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_ternary_tree_h2() {
        let tree = make_test_tree::<3, 2>().unwrap();
        assert_eq!(tree.size(), 2);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x0813d9fa859ac9c7c3c147af1bf38a8d34a95d71dddb59cb362741af4a5ce374")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 3.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 4.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 5.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 6.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 7.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 8.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_ternary_tree_h3() {
        let tree = make_test_tree::<3, 3>().unwrap();
        assert_eq!(tree.size(), 3);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x0d59114550233029c2dd76cb35aed5d87d0c11af9dcc16d59aea354cdf7b1904")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 3.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 4.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 5.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 6.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 7.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 8.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 9.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 10.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 11.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 12.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 13.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 14.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 15.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 16.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 17.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 18.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 19.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 20.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 21.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 22.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 23.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 24.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 25.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 26.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_binary_tree_h1_0() {
        let mut tree = make_test_tree::<2, 1>().unwrap();
        assert!(tree.put(0.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x3096077a3d12ab01b506e6aceda3c0dda9fe86c329ce2996ee63e1517b729e29")
        );
        assert_eq!(lookup_binary_tree(&tree, 0.into()), 42.into());
        assert_eq!(lookup_binary_tree(&tree, 1.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_binary_tree_h1_1() {
        let mut tree = make_test_tree::<2, 1>().unwrap();
        assert!(tree.put(1.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x6efc51a0910e467104e12e8667bed7d2f15928ec6f33608bb2432face70aed53")
        );
        assert_eq!(lookup_binary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, 1.into()), 42.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_binary_tree_h2() {
        let mut tree = make_test_tree::<2, 2>().unwrap();
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
        assert_eq!(lookup_binary_tree(&tree, 0.into()), 12.into());
        assert_eq!(lookup_binary_tree(&tree, 1.into()), 34.into());
        assert_eq!(lookup_binary_tree(&tree, 2.into()), 56.into());
        assert_eq!(lookup_binary_tree(&tree, 3.into()), 78.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_ternary_tree_h1_0() {
        let mut tree = make_test_tree::<3, 1>().unwrap();
        assert!(tree.put(0.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x371862e4591023f4be2dd1b86827e2ef6dac40c430beab9d12344ddeef2a5802")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), 42.into());
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_ternary_tree_h1_1() {
        let mut tree = make_test_tree::<3, 1>().unwrap();
        assert!(tree.put(1.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x438559edc8c31ac7792ecd45400af39cc7f4bef768b0ab368e9dc156590c712d")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), 42.into());
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_ternary_tree_h1_2() {
        let mut tree = make_test_tree::<3, 1>().unwrap();
        assert!(tree.put(2.into(), 42.into()).is_ok());
        assert_eq!(tree.size(), 1);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x1b4a382ee991eaadbf46b52b4806a2871b2a79a5486468aa74eea1025214cb80")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), 42.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_ternary_tree_h2() {
        let mut tree = make_test_tree::<3, 2>().unwrap();
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
        assert_eq!(tree.capacity(), 16);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x48342267b9354cf2846a25aa333559c0123d339c81cef6cd385c14bc44232d34")
        );
        assert_eq!(lookup_ternary_tree(&tree, 0.into()), 123.into());
        assert_eq!(lookup_ternary_tree(&tree, 1.into()), 456.into());
        assert_eq!(lookup_ternary_tree(&tree, 2.into()), 789.into());
        assert_eq!(lookup_ternary_tree(&tree, 3.into()), 231.into());
        assert_eq!(lookup_ternary_tree(&tree, 4.into()), 564.into());
        assert_eq!(lookup_ternary_tree(&tree, 5.into()), 897.into());
        assert_eq!(lookup_ternary_tree(&tree, 6.into()), 312.into());
        assert_eq!(lookup_ternary_tree(&tree, 7.into()), 645.into());
        assert_eq!(lookup_ternary_tree(&tree, 8.into()), 978.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_tall_binary_tree() {
        let tree = make_test_tree::<2, 256>().unwrap();
        assert_eq!(tree.size(), 256);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x705e15516059a313b2ffe555adaba446dda553dd38588b322f4415d62dcd0595")
        );
        assert_eq!(lookup_binary_tree(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, test_key2()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_tall_ternary_tree() {
        let tree = make_test_tree::<3, 161>().unwrap();
        assert_eq!(tree.size(), 161);
        assert_eq!(tree.capacity(), 512);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x54da9bb9b3fa9ac90efeef9e08ef2e7c18096f37b739fa4a20bf838905a2df0e")
        );
        assert_eq!(lookup_ternary_tree(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, test_key2()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_binary_tree1() {
        let mut tree = make_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 511);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x41888c7fcb9ae568fd2d8f06451c53cd4e9a4467b43cddf99dd85c0ebe2a9eba")
        );
        assert_eq!(lookup_binary_tree(&tree, test_key1()), 42.into());
        assert_eq!(lookup_binary_tree(&tree, test_key2()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_binary_tree2() {
        let mut tree = make_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key2(), 42.into()).is_ok());
        assert_eq!(tree.size(), 511);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x54c178302d47924841f468ec60fe19c7ba00ab7f462033addbf2017883674394")
        );
        assert_eq!(lookup_binary_tree(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup_binary_tree(&tree, test_key2()), 42.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_binary_tree3() {
        let mut tree = make_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key1(), 12.into()).is_ok());
        assert!(tree.put(test_key2(), 34.into()).is_ok());
        assert_eq!(tree.size(), 764);
        assert_eq!(tree.capacity(), 2048);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x1f25951405498baaf9350017b7a798219489047db7482a071e74fca027d9f32b")
        );
        assert_eq!(lookup_binary_tree(&tree, test_key1()), 12.into());
        assert_eq!(lookup_binary_tree(&tree, test_key2()), 34.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_binary_tree_twice() {
        let mut tree = make_test_tree::<2, 256>().unwrap();
        assert!(tree.put(test_key1(), 123.into()).is_ok());
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 511);
        assert_eq!(tree.capacity(), 2048);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x41888c7fcb9ae568fd2d8f06451c53cd4e9a4467b43cddf99dd85c0ebe2a9eba")
        );
        assert_eq!(lookup_binary_tree(&tree, test_key1()), 42.into());
        assert_eq!(lookup_binary_tree(&tree, test_key2()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_ternary_tree1() {
        let mut tree = make_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 321);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x2fc22d9cc6ce2f9377943565491dc6bdc235d92feed593822450de771dc81da7")
        );
        assert_eq!(lookup_ternary_tree(&tree, test_key1()), 42.into());
        assert_eq!(lookup_ternary_tree(&tree, test_key2()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_ternary_tree2() {
        let mut tree = make_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key2(), 42.into()).is_ok());
        assert_eq!(tree.size(), 321);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x2b29d23dcca6d4e20382956f22d69da75780fd29901fd04009bd1495ca629b85")
        );
        assert_eq!(lookup_ternary_tree(&tree, test_key1()), Scalar::ZERO);
        assert_eq!(lookup_ternary_tree(&tree, test_key2()), 42.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_ternary_tree3() {
        let mut tree = make_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key1(), 12.into()).is_ok());
        assert!(tree.put(test_key2(), 34.into()).is_ok());
        assert_eq!(tree.size(), 481);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x5a588281d792add7c1fc9fda9a10bf136559e6be638fcf19f41876cb0acd0637")
        );
        assert_eq!(lookup_ternary_tree(&tree, test_key1()), 12.into());
        assert_eq!(lookup_ternary_tree(&tree, test_key2()), 34.into());
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_update_tall_ternary_tree_twice() {
        let mut tree = make_test_tree::<3, 161>().unwrap();
        assert!(tree.put(test_key1(), 123.into()).is_ok());
        assert!(tree.put(test_key1(), 42.into()).is_ok());
        assert_eq!(tree.size(), 321);
        assert_eq!(tree.capacity(), 1024);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x2fc22d9cc6ce2f9377943565491dc6bdc235d92feed593822450de771dc81da7")
        );
        assert_eq!(lookup_ternary_tree(&tree, test_key1()), 42.into());
        assert_eq!(lookup_ternary_tree(&tree, test_key2()), Scalar::ZERO);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_reload_binary_tree() {
        let (mmap, root_hash) = {
            let mut tree = make_test_tree::<2, 256>().unwrap();
            assert!(tree.put(test_key1(), 42.into()).is_ok());
            let root_hash = tree.root_hash();
            (tree.take(), root_hash)
        };
        let tree = Tree::<2, 256>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(tree.root_hash(), root_hash);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_reload_ternary_tree() {
        let (mmap, root_hash) = {
            let mut tree = make_test_tree::<3, 161>().unwrap();
            assert!(tree.put(test_key1(), 42.into()).is_ok());
            let root_hash = tree.root_hash();
            (tree.take(), root_hash)
        };
        let tree = Tree::<3, 161>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(tree.root_hash(), root_hash);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_random_binary_tree() {
        let mut tree = make_test_tree::<2, 256>().unwrap();
        for _ in 0..100 {
            assert!(
                tree.put(utils::get_random_scalar(), utils::get_random_scalar())
                    .is_ok()
            );
        }
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_new_random_ternary_tree() {
        let mut tree = make_test_tree::<3, 161>().unwrap();
        for _ in 0..100 {
            assert!(
                tree.put(utils::get_random_scalar(), utils::get_random_scalar())
                    .is_ok()
            );
        }
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_reload_random_binary_tree() {
        let (mmap, root_hash) = {
            let mut tree = make_test_tree::<2, 256>().unwrap();
            for _ in 0..100 {
                assert!(
                    tree.put(utils::get_random_scalar(), utils::get_random_scalar())
                        .is_ok()
                );
            }
            let root_hash = tree.root_hash();
            (tree.take(), root_hash)
        };
        let tree = Tree::<2, 256>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(tree.root_hash(), root_hash);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_reload_random_ternary_tree() {
        let (mmap, root_hash) = {
            let mut tree = make_test_tree::<3, 161>().unwrap();
            for _ in 0..100 {
                assert!(
                    tree.put(utils::get_random_scalar(), utils::get_random_scalar())
                        .is_ok()
                );
            }
            let root_hash = tree.root_hash();
            (tree.take(), root_hash)
        };
        let tree = Tree::<3, 161>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(tree.root_hash(), root_hash);
        assert!(check_tree_consistency(&tree).is_ok());
    }

    #[test]
    fn test_binary_forest_format() {
        type TestForest = Forest<2, 256>;
        assert!(std::mem::size_of::<ForestHeader>() < TestForest::MAX_HEADER_DATA_SIZE);
        assert_eq!(TestForest::PADDED_HEADER_SIZE, 0x1000);
        assert_eq!(TestForest::padded_node_size(), 104);
    }

    #[test]
    fn test_ternary_forest_format() {
        type TestForest = Forest<3, 161>;
        assert!(std::mem::size_of::<ForestHeader>() < TestForest::MAX_HEADER_DATA_SIZE);
        assert_eq!(TestForest::PADDED_HEADER_SIZE, 0x1000);
        assert_eq!(TestForest::padded_node_size(), 136);
    }

    fn make_test_forest<const W: usize, const H: usize>() -> Result<Forest<W, H>> {
        let capacity = Forest::<W, H>::optimal_initial_capacity();
        Forest::new(
            MmapMut::map_anon(
                Tree::<W, H>::PADDED_HEADER_SIZE + capacity * Tree::<W, H>::padded_node_size(),
            )?,
            TEST_FLAGS,
        )
    }

    fn lookup_binary_forest<const H: usize>(
        forest: &Forest<2, H>,
        root_hash: Scalar,
        key: Scalar,
    ) -> Scalar {
        let value = forest.get(root_hash, key);
        let proof = forest.get_proof(root_hash, key);
        assert!(proof.verify().is_ok());
        assert_eq!(*proof.value(), value);
        value
    }

    fn lookup_ternary_forest<const H: usize>(
        forest: &Forest<3, H>,
        root_hash: Scalar,
        key: Scalar,
    ) -> Scalar {
        let value = forest.get(root_hash, key);
        let proof = forest.get_proof(root_hash, key);
        assert!(proof.verify().is_ok());
        assert_eq!(*proof.value(), value);
        value
    }

    #[test]
    fn test_new_binary_forest_h1() {
        let forest = make_test_forest::<2, 1>().unwrap();
        let erh = forest.empty_root_hash();
        assert_eq!(forest.size(), 1);
        assert_eq!(forest.capacity(), 4);
        assert_eq!(
            erh,
            parse_scalar("0x44fbea4934de59fe3dea4bb6ce5f053fe967f8c43a872b343a6d12fe40d75ca3")
        );
        assert_eq!(lookup_binary_forest(&forest, erh, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 1.into()), Scalar::ZERO);
        assert!(check_forest_consistency(&forest, &[erh]).is_ok());
    }

    #[test]
    fn test_new_binary_forest_h2() {
        let forest = make_test_forest::<2, 2>().unwrap();
        let erh = forest.empty_root_hash();
        assert_eq!(forest.size(), 2);
        assert_eq!(forest.capacity(), 8);
        assert_eq!(
            erh,
            parse_scalar("0x1642477fce8a9cfc7fef8c1adac8bb6212a12603545af958b6fa28f0099cdf1e")
        );
        assert_eq!(lookup_binary_forest(&forest, erh, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 3.into()), Scalar::ZERO);
        assert!(check_forest_consistency(&forest, &[erh]).is_ok());
    }

    #[test]
    fn test_new_binary_forest_h3() {
        let forest = make_test_forest::<2, 3>().unwrap();
        let erh = forest.empty_root_hash();
        assert_eq!(forest.size(), 3);
        assert_eq!(forest.capacity(), 8);
        assert_eq!(
            erh,
            parse_scalar("0x30ac7c720131f3ab706f3c8542a0ecdd6ca65b0f690cbea695b699fb2a6a0a6b")
        );
        assert_eq!(lookup_binary_forest(&forest, erh, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 3.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 4.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 5.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 6.into()), Scalar::ZERO);
        assert_eq!(lookup_binary_forest(&forest, erh, 7.into()), Scalar::ZERO);
        assert!(check_forest_consistency(&forest, &[erh]).is_ok());
    }

    #[test]
    fn test_new_ternary_forest_h1() {
        let forest = make_test_forest::<3, 1>().unwrap();
        let erh = forest.empty_root_hash();
        assert_eq!(forest.size(), 1);
        assert_eq!(forest.capacity(), 4);
        assert_eq!(
            erh,
            parse_scalar("0x447e7f6236dfaf8f3ddf7f0cd38eae309b9bff95f4ea6ecf2a46d106abd0623c")
        );
        assert_eq!(lookup_ternary_forest(&forest, erh, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 2.into()), Scalar::ZERO);
        assert!(check_forest_consistency(&forest, &[erh]).is_ok());
    }

    #[test]
    fn test_new_ternary_forest_h2() {
        let forest = make_test_forest::<3, 2>().unwrap();
        let erh = forest.empty_root_hash();
        assert_eq!(forest.size(), 2);
        assert_eq!(forest.capacity(), 8);
        assert_eq!(
            erh,
            parse_scalar("0x0813d9fa859ac9c7c3c147af1bf38a8d34a95d71dddb59cb362741af4a5ce374")
        );
        assert_eq!(lookup_ternary_forest(&forest, erh, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 3.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 4.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 5.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 6.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 7.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 8.into()), Scalar::ZERO);
        assert!(check_forest_consistency(&forest, &[erh]).is_ok());
    }

    #[test]
    fn test_new_ternary_forest_h3() {
        let forest = make_test_forest::<3, 3>().unwrap();
        let erh = forest.empty_root_hash();
        assert_eq!(forest.size(), 3);
        assert_eq!(forest.capacity(), 8);
        assert_eq!(
            erh,
            parse_scalar("0x0d59114550233029c2dd76cb35aed5d87d0c11af9dcc16d59aea354cdf7b1904")
        );
        assert_eq!(lookup_ternary_forest(&forest, erh, 0.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 1.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 2.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 3.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 4.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 5.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 6.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 7.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 8.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 9.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 10.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 11.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 12.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 13.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 14.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 15.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 16.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 17.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 18.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 19.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 20.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 21.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 22.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 23.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 24.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 25.into()), Scalar::ZERO);
        assert_eq!(lookup_ternary_forest(&forest, erh, 26.into()), Scalar::ZERO);
        assert!(check_forest_consistency(&forest, &[erh]).is_ok());
    }
}
