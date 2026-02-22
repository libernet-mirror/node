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
///
/// REQUIRES: the address of a `Node` must be 8-byte aligned.
#[derive(Debug)]
#[repr(C)]
struct Node<const W: usize> {
    /// Tracks how many other nodes refer to this node.
    ref_count: u64,

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

    fn root_hash(&self) -> Scalar {
        self.root_hash.to_scalar()
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

    /// Returns a reference to the header.
    fn header(&self) -> &TreeHeader {
        unsafe {
            // SAFETY: the data slice gets checked extensively upon construction of the `Tree`, it's
            // guaranteed to have enough space for the header.
            &*(self.data.as_ptr() as *const TreeHeader)
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

    fn find_node(&self, hash: Scalar) -> Option<&Node<W>> {
        let mask = self.capacity() as u64 - 1;
        let mut i = (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64();
        let mut j = 0;
        loop {
            let node = self.node(((i + j) & mask) as usize);
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

    /// REQUIRES: `data` MUST be 8-byte aligned.
    pub fn from_data(data: &'a mut [u8]) -> Result<Self> {
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

    /// REQUIRES: `data` MUST be 8-byte aligned.
    pub fn new(data: &'a mut [u8]) -> Result<Self> {
        let tree = Self::from_data(data)?;
        // TODO: initialize.
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
}

impl<'a, const H: usize> Tree<'a, 2, H> {
    pub fn lookup(&self, key: Scalar) -> Scalar {
        let mut node = self.find_node(self.header().root_hash()).unwrap();
        for i in (1..H).rev() {
            let bit = xits::and1(xits::shr(key, i)).to_repr()[0];
            let child_hash = node.child(bit as usize);
            node = self.find_node(child_hash).unwrap();
        }
        let bit = xits::and1(key).to_repr()[0];
        node.child(bit as usize)
    }
}

impl<'a, const H: usize> Tree<'a, 3, H> {
    pub fn lookup(&self, key: Scalar) -> Scalar {
        let mut node = self.find_node(self.header().root_hash()).unwrap();
        for i in (1..H).rev() {
            let trit = xits::mod3(xits::div_pow3(key, i)).to_repr()[0];
            let child_hash = node.child(trit as usize);
            node = self.find_node(child_hash).unwrap();
        }
        let trit = xits::mod3(key).to_repr()[0];
        node.child(trit as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;

    #[test]
    fn test_from_data() {
        const HEADER_SIZE: usize = Tree::<2, 256>::padded_header_size();
        const NODE_SIZE: usize = Tree::<2, 256>::padded_node_size();
        let mut data = [0u8; HEADER_SIZE + 512 * NODE_SIZE];
        let tree = Tree::<2, 256>::new(&mut data).unwrap();
        assert_eq!(tree.root_hash(), parse_scalar(""));
    }

    // TODO
}
