use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::{poseidon, utils, xits};
use ff::{Field, PrimeField};
use primitive_types::U256;
use std::cmp::Ordering;
use std::fmt::Debug;

/// Indicates that a type is suitable for storage in a memory-mapped region.
pub trait Stored: Sized + Copy + Clone + 'static {}

/// A BLS12-381 scalar stored in the memory-mapped region, in little endian order.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
struct StoredScalar(pub [u8; 32]);

impl StoredScalar {
    fn to_scalar(&self) -> Scalar {
        Scalar::from_repr_vartime(self.0).unwrap()
    }
}

impl Stored for StoredScalar {}

impl From<Scalar> for StoredScalar {
    fn from(value: Scalar) -> Self {
        Self(value.to_bytes_le())
    }
}

impl Ord for StoredScalar {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..32).rev() {
            if self.0[i] < other.0[i] {
                return Ordering::Less;
            } else if self.0[i] > other.0[i] {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for StoredScalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Manages access to a node in the mapped memory region.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Node<const W: usize> {
    /// Tracks how many other nodes refer to this node.
    ref_count: u64,

    /// The hash of the node.
    ///
    /// Set to zero for empty node slots.
    hash: StoredScalar,

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

    fn init_with_hash(&mut self, hash: Scalar, children: &[Scalar; W]) {
        self.ref_count = 0;
        self.hash = hash.into();
        self.children = children.map(StoredScalar::from);
    }

    fn init(&mut self, children: &[Scalar; W]) {
        let hash = Self::hash_node(&children);
        self.init_with_hash(hash, children);
    }

    fn erase(&mut self) {
        self.hash = Scalar::ZERO.into();
        self.children = std::array::from_fn(|_| Scalar::ZERO.into());
    }

    fn is_empty(&self) -> bool {
        self.hash.to_scalar() == Scalar::ZERO
    }

    fn is_reffed(&self) -> bool {
        self.ref_count > 0
    }

    fn r#ref(&mut self) {
        self.ref_count += 1;
    }

    fn unref(&mut self) -> bool {
        self.ref_count -= 1;
        self.ref_count == 0
    }

    fn hash(&self) -> Scalar {
        self.hash.to_scalar()
    }

    fn children(&self) -> [Scalar; W] {
        self.children.map(|child| child.to_scalar())
    }

    fn child(&self, i: usize) -> Scalar {
        self.children[i].to_scalar()
    }
}

impl<const W: usize> PartialEq for Node<W> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<const W: usize> Eq for Node<W> {}

#[derive(Debug)]
#[repr(C)]
struct TreeHeader {
    size: u64,
    root_hash: StoredScalar,
}

impl TreeHeader {
    fn size(&self) -> usize {
        self.size as usize
    }

    fn set_size(&mut self, size: usize) {
        self.size = size as u64;
    }

    fn root_hash(&self) -> Scalar {
        self.root_hash.to_scalar()
    }

    fn set_root_hash(&mut self, hash: Scalar) {
        self.root_hash = hash.into();
    }
}

/// Manages a Sparse Merkle Tree of nodes backed by a hash map.
///
/// The underlying hash map has open addressing with quadratic probing and is implemented as a
/// simple node array over the memory-mapped region.
#[derive(Debug)]
pub struct Tree<'a, const W: usize, const H: usize> {
    /// Refers to the memory-mapped region.
    data: &'a mut [u8],
}

impl<'a, const W: usize, const H: usize> Tree<'a, W, H> {
    const MAX_LOAD_FACTOR_NUMERATOR: usize = 3;
    const MAX_LOAD_FACTOR_DENOMINATOR: usize = 4;

    /// Calculates the space allocated for the header.
    const fn padded_header_size() -> usize {
        std::mem::size_of::<TreeHeader>().next_multiple_of(8)
    }

    /// Calculates the space allocated for every node.
    const fn padded_node_size() -> usize {
        std::mem::size_of::<Node<W>>().next_multiple_of(8)
    }

    const fn get_min_capacity_for(size: usize) -> usize {
        (size * Self::MAX_LOAD_FACTOR_DENOMINATOR / Self::MAX_LOAD_FACTOR_NUMERATOR)
            .next_power_of_two()
    }

    /// Returns an immutable reference to the header.
    fn header(&self) -> &TreeHeader {
        unsafe {
            // SAFETY: the data slice gets checked extensively upon construction of the `Tree`, it's
            // guaranteed to have enough space for the header.
            &*(self.data.as_ptr() as *const TreeHeader)
        }
    }

    /// Returns a mutable reference to the header.
    fn header_mut(&mut self) -> &mut TreeHeader {
        unsafe {
            // SAFETY: the data slice gets checked extensively upon construction of the `Tree`, it's
            // guaranteed to have enough space for the header.
            &mut *(self.data.as_ptr() as *mut TreeHeader)
        }
    }

    /// Returns an immutable reference to the node at the i-th slot.
    fn node(&self, i: usize) -> &Node<W> {
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe {
            // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the bytes
            // for the node. The caller is assumed to provide a valid index `i`, in which case
            // `offset` will point to a valid node within the data slice.
            &*(self.data.as_ptr().add(offset) as *const Node<W>)
        }
    }

    /// Returns a mutable reference to the node at the i-th slot.
    fn node_mut(&mut self, i: usize) -> &mut Node<W> {
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe {
            // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the bytes
            // for the node. The caller is assumed to provide a valid index `i`, in which case
            // `offset` will point to a valid node within the data slice.
            &mut *(self.data.as_ptr().add(offset) as *mut Node<W>)
        }
    }

    fn probe(&self, hash: Scalar) -> usize {
        let mask = self.capacity() as u64 - 1;
        let mut i = (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64();
        let mut j = 0;
        loop {
            let index = (i & mask) as usize;
            let node = self.node(index);
            if node.is_empty() || node.hash() == hash {
                return index;
            }
            j += 1;
            i += j;
        }
    }

    fn find_node(&self, hash: Scalar) -> Option<&Node<W>> {
        let index = self.probe(hash);
        let node = self.node(index);
        if node.hash() != hash {
            None
        } else {
            Some(node)
        }
    }

    fn find_node_mut(&mut self, hash: Scalar) -> Option<&mut Node<W>> {
        let index = self.probe(hash);
        let node = self.node_mut(index);
        if node.hash() != hash {
            None
        } else {
            Some(node)
        }
    }

    fn ref_node(&mut self, hash: Scalar) {
        self.find_node_mut(hash).unwrap().r#ref();
    }

    /// Ensures that a node with the given children exists.
    ///
    /// The node is created and inserted if it doesn't exist. This may result in a rehash because
    /// the hash table grows when the capacity is scarce.
    ///
    /// The `leaf` flag specifies whether the node being allocated is a leaf or an internal node. If
    /// it's a leaf the children are arbitrary values, while if it's an internal node the children
    /// MUST be the hashes of other existing nodes. For internal nodes this algorithm will
    /// automatically increase the reference count of all children.
    fn make_node(&mut self, children: &[Scalar; W], leaf: bool) -> &mut Node<W> {
        let hash = Node::<W>::hash_node(children);
        let index = self.probe(hash);
        if self.node(index).is_empty() {
            let current_size = self.header().size();
            let min_capacity = Self::get_min_capacity_for(current_size + 1);
            if min_capacity > self.capacity() {
                // TODO: grow & rehash.
                unimplemented!()
            }
            self.header_mut().set_size(current_size + 1);
        }
        let node = self.node_mut(index);
        if node.is_empty() || !node.is_reffed() {
            node.init_with_hash(hash, children);
            if !leaf {
                for child_hash in children {
                    self.ref_node(*child_hash);
                }
            }
        }
        self.node_mut(index)
    }

    fn probe_for_unref(&self, hash: Scalar) -> (usize, usize) {
        let mask = self.capacity() as u64 - 1;
        let mut i = (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64();
        let mut j = 0;
        let mut node_index;
        loop {
            node_index = (i & mask) as usize;
            let node = self.node(node_index);
            if node.is_empty() {
                return (node_index, node_index);
            }
            if node.hash() == hash {
                break;
            }
            j += 1;
            i += j;
        }
        let mut last_bucket_index = node_index;
        loop {
            let index = (i & mask) as usize;
            if self.node(index).is_empty() {
                return (node_index, last_bucket_index);
            }
            last_bucket_index = index;
            j += 1;
            i += j;
        }
    }

    fn unref_node_impl(&mut self, hash: Scalar, level: usize) -> bool {
        let (node_index, last_bucket_index) = self.probe_for_unref(hash);
        let node = self.node_mut(node_index);
        if node.is_empty() {
            return true;
        }
        if !node.unref() {
            return false;
        }
        if level > 0 {
            for child_hash in self.node(node_index).children() {
                self.unref_node_impl(child_hash, level - 1);
            }
        }
        if last_bucket_index != node_index {
            *self.node_mut(node_index) = *self.node(last_bucket_index);
        }
        self.node_mut(last_bucket_index).erase();
        true
    }

    /// Unreferences a node and erases it from the tree along with its entire subtree if it's no
    /// longer referenced.
    ///
    /// If no node identified by the provided hash exists this function does nothing and returns
    /// false.
    ///
    /// If a node identified by the provided hash exists but its reference count is not zero this
    /// function does nothing and returns false.
    ///
    /// If a node identified by the provided hash exists and its reference count is zero, the node
    /// is erased and the function returns true. If the node is an internal node (ie. `level > 0`)
    /// all children are automatically unreffed and freed recursively if their reference count
    /// reaches zero. Subtrees whose reference count doesn't reach zero are retained.
    ///
    /// At the end of all (possibly recursive) removals, the new minimum capacity is reassessed and
    /// if it's less than the current capacity the hash map is shrunk and rehashed.
    fn unref_node(&mut self, hash: Scalar, level: usize) -> bool {
        if !self.unref_node_impl(hash, level) {
            return false;
        }
        let min_capacity = Self::get_min_capacity_for(std::cmp::max(self.size(), H));
        if min_capacity < self.capacity() {
            // TODO: shrink & rehash.
            unimplemented!()
        }
        true
    }

    /// REQUIRES: `data` MUST be 8-byte aligned.
    pub fn from_data(data: &'a mut [u8]) -> Result<Self> {
        let min_size =
            Self::padded_header_size() + Self::get_min_capacity_for(H) * Self::padded_node_size();
        if data.len() < min_size {
            return Err(anyhow!(
                "data slice too short (was {} bytes, need at least {})",
                data.len(),
                min_size
            ));
        }
        let tree = Self { data };
        let capacity = tree.capacity();
        if capacity != capacity.next_power_of_two() {
            return Err(anyhow!(
                "the data capacity must be a power of 2 (was {})",
                capacity
            ));
        }
        Ok(tree)
    }

    fn init_empty(&mut self) {
        let mut hash = Scalar::ZERO;
        for _ in 0..H {
            hash = self
                .make_node(&std::array::from_fn(|_| hash), H == 0)
                .hash();
        }
        self.ref_node(hash);
        self.header_mut().set_root_hash(hash);
    }

    /// REQUIRES: `data` MUST be 8-byte aligned.
    pub fn new(data: &'a mut [u8]) -> Result<Self> {
        let mut tree = Self::from_data(data)?;
        tree.init_empty();
        Ok(tree)
    }

    /// Returns the number of nodes in the underlying hashmap.
    pub fn size(&self) -> usize {
        self.header().size()
    }

    /// Returns the capacity (in terms of number of nodes) of the underlying hashmap.
    ///
    /// NOTE: this will always return a power of 2.
    pub fn capacity(&self) -> usize {
        (self.data.len() - Self::padded_header_size()) / Self::padded_node_size()
    }

    pub fn root_hash(&self) -> Scalar {
        self.header().root_hash()
    }

    /// REQUIRES: `hash` must refer to an existing node at level H-1.
    fn set_root(&mut self, hash: Scalar) {
        self.ref_node(hash);
        self.unref_node(self.root_hash(), H - 1);
        self.header_mut().set_root_hash(hash);
    }
}

impl<'a, const H: usize> Tree<'a, 2, H> {
    pub fn get(&self, key: Scalar) -> Scalar {
        let mut node = self.find_node(self.header().root_hash()).unwrap();
        for i in (1..H).rev() {
            let bit = xits::and1(xits::shr(key, i)).to_repr()[0];
            let child_hash = node.child(bit as usize);
            node = self.find_node(child_hash).unwrap();
        }
        let bit = xits::and1(key).to_repr()[0];
        node.child(bit as usize)
    }

    fn update(&mut self, hash: Scalar, level: usize, key: Scalar, value: Scalar) -> Scalar {
        // TODO
        todo!()
    }

    pub fn put(&mut self, key: Scalar, value: Scalar) {
        let new_root = self.update(self.root_hash(), H - 1, key, value);
        self.set_root(new_root);
    }
}

impl<'a, const H: usize> Tree<'a, 3, H> {
    pub fn get(&self, key: Scalar) -> Scalar {
        let mut node = self.find_node(self.header().root_hash()).unwrap();
        for i in (1..H).rev() {
            let trit = xits::mod3(xits::div_pow3(key, i)).to_repr()[0];
            let child_hash = node.child(trit as usize);
            node = self.find_node(child_hash).unwrap();
        }
        let trit = xits::mod3(key).to_repr()[0];
        node.child(trit as usize)
    }

    fn update(&mut self, hash: Scalar, level: usize, key: Scalar, value: Scalar) -> Scalar {
        // TODO
        todo!()
    }

    pub fn put(&mut self, key: Scalar, value: Scalar) {
        let new_root = self.update(self.root_hash(), H - 1, key, value);
        self.set_root(new_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;

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
        let msb = xits::and1(xits::shr(max, 255));
        let mst = xits::mod3(xits::div_pow3(max, 161));
        assert_eq!(msb, 0.into());
        assert_eq!(mst, 0.into());
    }

    #[test]
    fn test_new_binary_tree() {
        const HEADER_SIZE: usize = Tree::<2, 256>::padded_header_size();
        const NODE_SIZE: usize = Tree::<2, 256>::padded_node_size();
        let mut data = [0u8; HEADER_SIZE + 512 * NODE_SIZE];
        let tree = Tree::<2, 256>::new(&mut data).unwrap();
        assert_eq!(tree.size(), 256);
        assert_eq!(tree.capacity(), 512);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x705e15516059a313b2ffe555adaba446dda553dd38588b322f4415d62dcd0595")
        );
        assert_eq!(
            tree.get(parse_scalar(
                "0x37c75d7b351d02bc8d5193a1d445f1e8e453df601a2b0a7b8ec33a23cab82611"
            )),
            Scalar::ZERO
        );
    }

    #[test]
    fn test_new_ternary_tree() {
        const HEADER_SIZE: usize = Tree::<3, 161>::padded_header_size();
        const NODE_SIZE: usize = Tree::<3, 161>::padded_node_size();
        let mut data = [0u8; HEADER_SIZE + 256 * NODE_SIZE];
        let tree = Tree::<3, 161>::new(&mut data).unwrap();
        assert_eq!(tree.size(), 161);
        assert_eq!(tree.capacity(), 256);
        assert_eq!(
            tree.root_hash(),
            parse_scalar("0x54da9bb9b3fa9ac90efeef9e08ef2e7c18096f37b739fa4a20bf838905a2df0e")
        );
        assert_eq!(
            tree.get(parse_scalar(
                "0x37c75d7b351d02bc8d5193a1d445f1e8e453df601a2b0a7b8ec33a23cab82611"
            )),
            Scalar::ZERO
        );
    }

    // TODO
}
