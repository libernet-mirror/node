use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::{poseidon, utils, xits};
use ff::{Field, PrimeField};
use primitive_types::U256;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::sync::Mutex;

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

#[derive(Debug)]
#[repr(C)]
struct Node<const W: usize> {
    ref_count: u64,
    label: StoredScalar,
    children: [StoredScalar; W],
}

impl<const W: usize> Node<W> {
    fn init(&mut self, children: [Scalar; W]) {
        self.ref_count = 0;
        self.label = match W {
            2 => poseidon::hash_t3(&children),
            3 => poseidon::hash_t4(&children),
            _ => unimplemented!(),
        }
        .into();
        self.children = children.map(StoredScalar::from)
    }

    fn is_empty(&self) -> bool {
        self.label.to_scalar() == Scalar::ZERO
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

    fn label(&self) -> Scalar {
        self.label.to_scalar()
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
        self.label == other.label
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

#[derive(Debug)]
pub struct Tree<'a, const W: usize, const H: usize> {
    data: &'a mut [u8],
    mutex: Mutex<()>,
}

impl<'a, const W: usize, const H: usize> Tree<'a, W, H> {
    const MAX_LOAD_FACTOR_NUMERATOR: usize = 3;
    const MAX_LOAD_FACTOR_DENOMINATOR: usize = 4;

    fn padded_header_size() -> usize {
        std::mem::size_of::<TreeHeader>().next_multiple_of(8)
    }

    fn padded_node_size() -> usize {
        std::mem::size_of::<Node<W>>().next_multiple_of(8)
    }

    fn header(&self) -> &'a TreeHeader {
        unsafe { &mut *(self.data.as_ptr() as *mut TreeHeader) }
    }

    fn node(&self, i: usize) -> &'a Node<W> {
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe { &*(self.data.as_ptr().add(offset) as *const Node<W>) }
    }

    fn node_mut(&self, i: usize) -> &'a mut Node<W> {
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe { &mut *(self.data.as_ptr().add(offset) as *mut Node<W>) }
    }

    fn get_node_by_hash(&self, hash: Scalar) -> Option<&'a Node<W>> {
        let mask = self.capacity() as u64 - 1;
        let mut i = (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64();
        let mut j = 0;
        loop {
            let index = ((i + j) & mask) as usize;
            let node = self.node(index);
            if node.is_empty() {
                return None;
            }
            if node.label() == hash {
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
        let tree = Self {
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

impl<'a, const H: usize> Tree<'a, 2, H> {
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

impl<'a, const H: usize> Tree<'a, 3, H> {
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

    // TODO
}
