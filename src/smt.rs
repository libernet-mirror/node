use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::{poseidon, utils, xits};
use ff::{Field, PrimeField};
use primitive_types::U256;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Mutex, atomic::AtomicU64};

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
///
/// REQUIRES: the address of a `Node` must be 8-byte aligned.
#[derive(Debug)]
#[repr(C)]
struct Node<const W: usize> {
    /// Tracks how many other nodes refer to this node.
    ref_count1: u64,

    /// Tracks how many `NodeRef`s refer to this node.
    ///
    /// NOTE: the `ref_count2`s of all nodes must be set to zero when constructing a `Tree` on a
    /// data slice, regardless of the state of the rest of the slice. This is achieved by
    /// `Tree::clear_ref_count2`.
    ref_count2: u64,

    /// The hash of the node.
    ///
    /// Set to zero for empty node slots.
    hash: StoredScalar,

    /// If the children are leaves then these are the values of the leaves, otherwise they're the
    /// hashes of the child nodes.
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

    fn init_with_hash(&mut self, hash: Scalar, children: [Scalar; W]) {
        self.ref_count1 = 0;
        self.ref_count2 = 0;
        self.hash = hash.into();
        self.children = children.map(StoredScalar::from);
    }

    fn init(&mut self, children: [Scalar; W]) {
        let hash = Self::hash_node(&children);
        self.init_with_hash(hash, children);
    }

    unsafe fn to_mut(&self) -> &mut Self {
        unsafe {
            // SAFETY: this function unsafely makes `self` mutable by definition.
            &mut *(std::ptr::from_ref(self) as *mut Self)
        }
    }

    fn erase(&mut self) {
        self.hash = Scalar::ZERO.into();
        self.children = std::array::from_fn(|_| Scalar::ZERO.into());
    }

    fn is_empty(&self) -> bool {
        self.hash.to_scalar() == Scalar::ZERO
    }

    fn ref1(&mut self) {
        self.ref_count1 += 1;
    }

    fn unref1(&mut self) -> bool {
        self.ref_count1 -= 1;
        self.ref_count1 == 0
    }

    fn ref_count2(&self) -> &AtomicU64 {
        unsafe {
            // SAFETY: the pointer supplied to `AtomicU64::from_ptr` is 8-byte aligned because:
            //  - the `data` slice managed by the parent `Tree` is required to be 8-byte aligned;
            //  - the padded header size is a multiple of 8 bytes;
            //  - the only field before `ref_count2` is `ref_count1`, which takes 8 bytes.
            &*AtomicU64::from_ptr(std::ptr::from_ref(&self.ref_count2) as *mut u64)
        }
    }

    fn clear_ref_count2(&self) {
        self.ref_count2()
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    fn ref2(&self) {
        self.ref_count2()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn unref2(&self) -> bool {
        self.ref_count2()
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
    }

    fn is_reffed(&self) -> bool {
        self.ref_count1 + self.ref_count2().load(std::sync::atomic::Ordering::Acquire) > 0
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
struct NodeRef<'tree, 'node, const W: usize, const H: usize> {
    tree: &'tree Tree<'node, W, H>,
    node: &'node Node<W>,
}

impl<'tree, 'node, const W: usize, const H: usize> NodeRef<'tree, 'node, W, H> {
    fn new(tree: &'tree Tree<'node, W, H>, node: &'node Node<W>) -> Self {
        node.ref2();
        Self { tree, node }
    }
}

impl<'tree, 'node, const W: usize, const H: usize> Clone for NodeRef<'tree, 'node, W, H> {
    fn clone(&self) -> Self {
        Self::new(self.tree, self.node)
    }
}

impl<'tree, 'node, const W: usize, const H: usize> Deref for NodeRef<'tree, 'node, W, H> {
    type Target = Node<W>;

    fn deref(&self) -> &Self::Target {
        self.node
    }
}

impl<'tree, 'node, const W: usize, const H: usize> Drop for NodeRef<'tree, 'node, W, H> {
    fn drop(&mut self) {
        if self.node.unref2() {
            self.tree.maybe_deallocate_node(self.node);
        }
    }
}

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

    fn root_hash(&self) -> Scalar {
        self.root_hash.to_scalar()
    }
}

/// Manages a Sparse Merkle Tree of nodes backed by a hash map.
///
/// The underlying hash map has open addressing with quadratic probing and is implemented as a
/// simple node array over the memory-mapped region.
#[derive(Debug)]
pub struct Tree<'data, const W: usize, const H: usize> {
    /// Refers to the memory-mapped region.
    data: &'data mut [u8],

    /// Guards mutable access to certain parts of `data`.
    ///
    /// TODO: more details.
    ///
    /// NOTE: the `ref_count2` fiels of each node are handled with atomic operations, which have
    /// internal mutability, so those are not considered mutable access to the data slice and are
    /// normally carried out outside of the mutex lock.
    mutex: Mutex<()>,
}

impl<'data, const W: usize, const H: usize> Tree<'data, W, H> {
    const MAX_LOAD_FACTOR_NUMERATOR: usize = 3;
    const MAX_LOAD_FACTOR_DENOMINATOR: usize = 4;

    /// Calculates the space allocated for the header.
    fn padded_header_size() -> usize {
        std::mem::size_of::<TreeHeader>().next_multiple_of(8)
    }

    /// Calculates the space allocated for every node.
    fn padded_node_size() -> usize {
        std::mem::size_of::<Node<W>>().next_multiple_of(8)
    }

    /// Returns a reference to the header.
    fn header(&self) -> &'data TreeHeader {
        unsafe {
            // SAFETY: the data slice gets checked extensively upon construction of the `Tree`, it's
            // guaranteed to have enough space for the header.
            &*(self.data.as_ptr() as *const TreeHeader)
        }
    }

    fn clear_ref_count2(&mut self) {
        let capacity = self.capacity();
        let data: &mut [u8] = self.data;
        let offset = Self::padded_header_size();
        for i in 0..capacity {
            let offset = offset + i * Self::padded_node_size();
            let node = unsafe {
                // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the
                // bytes for the node. The data slice gets checked extensively upon construction of
                // the `Tree` and is guaranteed to have `capacity` nodes.
                &mut *(data.as_ptr().add(offset) as *mut Node<W>)
            };
            node.clear_ref_count2();
        }
    }

    fn raw_node<'tree: 'data>(&'tree self, i: usize) -> &'data Node<W> {
        let data: &'data [u8] = self.data;
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe {
            // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the bytes
            // for the node. The caller is assumed to provide a valid index `i`, in which case
            // `offset` will point to a valid node within the data slice.
            &*(data.as_ptr().add(offset) as *const Node<W>)
        }
    }

    fn node<'tree: 'data>(&'tree self, i: usize) -> NodeRef<'tree, 'data, W, H> {
        let node = self.raw_node(i);
        NodeRef::new(self, node)
    }

    fn get_node_by_hash<'tree: 'data>(
        &'tree self,
        hash: Scalar,
    ) -> Option<NodeRef<'tree, 'data, W, H>> {
        let mask = self.capacity() as u64 - 1;
        let mut i = (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64();
        let mut j = 0;
        loop {
            let index = ((i + j) & mask) as usize;
            let node = self.node(index);
            if node.is_empty() {
                return None;
            }
            if node.hash() == hash {
                return Some(node);
            }
            j += 1;
            i += j;
        }
    }

    fn allocate_node<'tree: 'data>(
        &'tree self,
        children: [Scalar; W],
    ) -> NodeRef<'tree, 'data, W, H> {
        let hash = Node::<W>::hash_node(&children);
        if let Some(node) = self.get_node_by_hash(hash) {
            return node;
        }
        let mask = self.capacity() as u64 - 1;
        let mut i = (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64();
        let mut j = 0;
        let _guard = self.mutex.lock().unwrap();
        loop {
            let node = self.raw_node(((i + j) & mask) as usize);
            if node.is_empty() || !node.is_reffed() {
                unsafe {
                    // SAFETY: mutating the node is OK here because we're working on an unused slot
                    // and we've got the mutex lock, so no other thread can be working on it.
                    node.to_mut()
                }
                .init_with_hash(hash, children);
                return NodeRef::new(self, node);
            }
            j += 1;
            i += j;
        }
    }

    fn maybe_deallocate_node(&self, node: &'data Node<W>) {
        let _guard = self.mutex.lock().unwrap();
        if !node.is_reffed() {
            let node_mut = unsafe {
                // SAFETY: the node has both reference counts sets to 0 (as per `is_reffed`) so it's
                // undiscoverable. No other thread can be reading it. We've got the mutex lock so no
                // other thread can be probing it either.
                node.to_mut()
            };
            node_mut.erase();
        }
    }

    /// REQUIRES: `data` MUST be 8-byte aligned.
    pub fn from_data(data: &'data mut [u8]) -> Result<Self> {
        let min_size = Self::padded_header_size()
            + (H * Self::MAX_LOAD_FACTOR_DENOMINATOR / Self::MAX_LOAD_FACTOR_NUMERATOR)
                .next_power_of_two()
                * Self::padded_node_size();
        if data.len() < min_size {
            return Err(anyhow!(
                "data slice too short (was {} bytes, need at least {})",
                data.len(),
                min_size
            ));
        }
        let mut tree = Self {
            data,
            mutex: Mutex::default(),
        };
        let capacity = tree.capacity();
        if capacity != capacity.next_power_of_two() {
            return Err(anyhow!(
                "the data capacity must be a power of 2 (was {})",
                capacity
            ));
        }
        tree.clear_ref_count2();
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

    // TODO
}

impl<'data, const H: usize> Tree<'data, 2, H> {
    pub fn lookup(&self, key: Scalar) -> Scalar {
        let mut node = self.get_node_by_hash(self.header().root_hash()).unwrap();
        for i in (1..H).rev() {
            let bit = xits::and1(xits::shr(key, i)).to_repr()[0];
            let child_hash = node.child(bit as usize);
            node = self.get_node_by_hash(child_hash).unwrap();
        }
        let bit = xits::and1(key).to_repr()[0];
        node.child(bit as usize)
    }
}

impl<'data, const H: usize> Tree<'data, 3, H> {
    pub fn lookup(&self, key: Scalar) -> Scalar {
        let mut node = self.get_node_by_hash(self.header().root_hash()).unwrap();
        for i in (1..H).rev() {
            let trit = xits::mod3(xits::div_pow3(key, i)).to_repr()[0];
            let child_hash = node.child(trit as usize);
            node = self.get_node_by_hash(child_hash).unwrap();
        }
        let trit = xits::mod3(key).to_repr()[0];
        node.child(trit as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_data() {
        let mut data = [0u8; 57384];
        let tree = Tree::<2, 256>::from_data(&mut data).unwrap();
        // TODO
    }

    // TODO
}
