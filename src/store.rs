use crate::constants;
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::utils;
use ff::{Field, PrimeField};
use memmap2::MmapMut;
use primitive_types::U256;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::marker::PhantomData;

/// Indicates that a type is suitable for storage in a memory-mapped region.
pub trait Stored: Sized + Debug + Copy + Clone + 'static {}

/// A BLS12-381 scalar stored in the memory-mapped region, in little endian order.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StoredScalar(pub [u8; 32]);

impl StoredScalar {
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn to_scalar(&self) -> Scalar {
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

/// Trait for data that is stored in the header of a `MappedHashSet`.
pub trait HeaderData: Stored {}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Header<T: HeaderData> {
    signature: [u8; 8],
    size: u64,
    data: T,
}

impl<T: HeaderData> Header<T> {
    fn size(&self) -> usize {
        self.size as usize
    }

    fn set_size(&mut self, size: usize) {
        self.size = size as u64;
    }

    fn increment_size(&mut self) {
        self.size += 1;
    }

    fn decrement_size(&mut self) {
        assert!(self.size > 0);
        self.size -= 1;
    }

    fn data(&self) -> &T {
        &self.data
    }

    fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

/// Makes a type suitable for storage in a `MappedHashSet`.
pub trait NodeData: Stored {
    /// Hashes the value.
    fn hash(&self) -> Scalar;

    /// Erases the value from storage.
    fn erase(&mut self);
}

/// Manages access to a node in the mapped memory region.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Node<T: NodeData> {
    /// The hash of the node.
    ///
    /// Set to zero for empty node slots.
    hash: StoredScalar,

    /// The content of the node.
    value: T,
}

impl<T: NodeData> Node<T> {
    fn init(&mut self, hash: Scalar, value: T) {
        self.hash = hash.into();
        self.value = value;
    }

    fn erase(&mut self) {
        self.hash = Scalar::ZERO.into();
        self.value.erase();
    }

    fn is_empty(&self) -> bool {
        self.hash.is_zero()
    }

    fn hash(&self) -> Scalar {
        self.hash.to_scalar()
    }
}

/// A generic hash table that works on a memory-mapped file.
///
/// Our implementation uses open addressing (https://en.wikipedia.org/wiki/Open_addressing) with
/// linear probing.
#[derive(Debug)]
pub struct MappedHashSet<H: HeaderData, T: NodeData> {
    mmap: MmapMut,
    _data: PhantomData<(H, T)>,
}

impl<H: HeaderData, T: NodeData> MappedHashSet<H, T> {
    const MAX_LOAD_FACTOR_NUMERATOR: usize = 1;
    const MAX_LOAD_FACTOR_DENOMINATOR: usize = 2;

    /// Calculates the space allocated for the header.
    pub const fn padded_header_size() -> usize {
        std::mem::size_of::<Header<H>>().next_multiple_of(8)
    }

    /// Calculates the space allocated for every node.
    pub const fn padded_node_size() -> usize {
        std::mem::size_of::<Node<T>>().next_multiple_of(8)
    }

    /// Returns the minimum capacity (in terms of number of nodes) required to host `size` nodes.
    pub const fn get_min_capacity_for(size: usize) -> usize {
        let dividend = size * Self::MAX_LOAD_FACTOR_DENOMINATOR;
        let remainder = dividend % Self::MAX_LOAD_FACTOR_NUMERATOR;
        let quotient =
            dividend / Self::MAX_LOAD_FACTOR_NUMERATOR + if remainder != 0 { 1 } else { 0 };
        quotient.next_power_of_two()
    }

    /// Returns the minimum capacity (in terms of number of nodes) required for a default empty
    /// `MappedHashSet`.
    ///
    /// The data slice provided upon construction must be at least
    /// `padded_header_size() + min_capacity() * padded_node_size()` bytes long.
    pub const fn min_capacity() -> usize {
        Self::get_min_capacity_for(1)
    }

    fn data(&self) -> &[u8] {
        &self.mmap[..]
    }

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.mmap[..]
    }

    /// Returns an immutable reference to the header.
    fn header(&self) -> &Header<H> {
        let data = self.data();
        unsafe {
            // SAFETY: the memory-mapped region gets checked extensively upon construction of the
            // `Tree`, it's guaranteed to have enough space for the header. No changes in lifetime
            // or mutability.
            &*(data.as_ptr() as *const Header<H>)
        }
    }

    /// Returns a mutable reference to the header.
    fn header_mut(&mut self) -> &mut Header<H> {
        let data = self.data_mut();
        unsafe {
            // SAFETY: the memory-mapped region gets checked extensively upon construction of the
            // `Tree`, it's guaranteed to have enough space for the header. No changes in lifetime
            // or mutability.
            &mut *(data.as_ptr() as *mut Header<H>)
        }
    }

    /// Returns an immutable reference to the node at the i-th slot.
    fn node(&self, i: usize) -> &Node<T> {
        let data = self.data();
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe {
            // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the bytes
            // for the node. The caller is assumed to provide a valid index `i`, in which case
            // `offset` will point to a valid node within the data slice.
            &*(data.as_ptr().add(offset) as *const Node<T>)
        }
    }

    /// Returns a mutable reference to the node at the i-th slot.
    fn node_mut(&mut self, i: usize) -> &mut Node<T> {
        let data = self.data_mut();
        let offset = Self::padded_header_size() + i * Self::padded_node_size();
        unsafe {
            // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the bytes
            // for the node. The caller is assumed to provide a valid index `i`, in which case
            // `offset` will point to a valid node within the data slice.
            &mut *(data.as_ptr().add(offset) as *mut Node<T>)
        }
    }

    /// Constructs a hash set from the provided data.
    pub fn load(mut mmap: MmapMut) -> Result<Self> {
        let data = &mut mmap[..];
        {
            let address = data.as_ptr() as usize;
            if address % 8 != 0 {
                return Err(anyhow!("the memory-mapped address is not 8-byte aligned"));
            }
        }
        let min_size = Self::padded_header_size() + Self::min_capacity() * Self::padded_node_size();
        if mmap.len() < min_size {
            return Err(anyhow!(
                "the mmap is too small (was {} bytes, need at least {})",
                mmap.len(),
                min_size
            ));
        }
        let set = Self {
            mmap,
            _data: Default::default(),
        };
        if set.header().signature != *constants::DATA_FILE_SIGNATURE {
            return Err(anyhow!("invalid file signature"));
        }
        let capacity = set.capacity();
        if capacity != capacity.next_power_of_two() {
            return Err(anyhow!(
                "the data capacity must be a power of 2 (was {})",
                capacity
            ));
        }
        Ok(set)
    }

    /// Initializes a new hash set on the provided memory-mapped region.
    pub fn new(mut mmap: MmapMut) -> Result<Self> {
        let data = &mut mmap[..];
        data.fill(0);
        data[0..8].copy_from_slice(constants::DATA_FILE_SIGNATURE);
        Self::load(mmap)
    }

    /// Returns the number of nodes in the underlying hash set.
    pub fn size(&self) -> usize {
        self.header().size()
    }

    /// Returns the capacity (in terms of number of nodes) of the hash set.
    ///
    /// NOTE: this will always return a power of 2.
    pub fn capacity(&self) -> usize {
        (self.mmap.len() - Self::padded_header_size()) / Self::padded_node_size()
    }

    /// Destroys the `MappedHashSet` and returns the wrapped memory map.
    pub fn take(self) -> MmapMut {
        self.mmap
    }

    /// Returns a reference to the header data.
    pub fn header_data(&self) -> &H {
        self.header().data()
    }

    /// Returns a mutable reference to the header data.
    pub fn header_data_mut(&mut self) -> &mut H {
        self.header_mut().data_mut()
    }

    fn get_slot_index(&self, hash: Scalar) -> u64 {
        let mask = self.capacity() as u64 - 1;
        (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64()
    }

    fn probe(&self, hash: Scalar) -> usize {
        let mask = self.capacity() as u64 - 1;
        let mut i = self.get_slot_index(hash);
        loop {
            let index = (i & mask) as usize;
            let node = self.node(index);
            if node.is_empty() || node.hash() == hash {
                return index;
            }
            i += 1;
        }
    }

    /// Looks up an element by hash, returning `None` if it's not found.
    pub fn get(&self, hash: Scalar) -> Option<&T> {
        let node = self.node(self.probe(hash));
        if node.hash() != hash {
            None
        } else {
            Some(&node.value)
        }
    }

    /// Mutably looks up an element by hash, returning `None` if it's not found.
    pub fn get_mut(&mut self, hash: Scalar) -> Option<&mut T> {
        let node = self.node_mut(self.probe(hash));
        if node.hash() != hash {
            None
        } else {
            Some(&mut node.value)
        }
    }

    fn rehash(&mut self, target_capacity: usize) -> Result<()> {
        let mut new_set = MappedHashSet::<H, T>::new(MmapMut::map_anon(
            Self::padded_header_size() + target_capacity * Self::padded_node_size(),
        )?)?;
        *new_set.header_data_mut() = *self.header_data();
        for i in 0..self.capacity() {
            let node = self.node(i);
            if !node.is_empty() {
                new_set.insert_hashed(node.value, node.hash())?;
            }
        }
        self.mmap = new_set.take();
        Ok(())
    }

    /// Inserts an element into the hash set.
    ///
    /// If an equivalent element (one with the same hash) is already present in the hash set, the
    /// element is updated by copying the bytes of `value` into it.
    pub fn insert(&mut self, value: T) -> Result<&mut T> {
        let hash = value.hash();
        self.insert_hashed(value, hash)
    }

    /// Inserts an element into the hash set, associating it with the given `hash`.
    ///
    /// REQUIRES: `value.hash()` must return the same value as `hash`.
    ///
    /// If an equivalent element (one with the same hash) is already present in the hash set, the
    /// element is updated by copying the bytes of `value` into it.
    pub fn insert_hashed(&mut self, value: T, hash: Scalar) -> Result<&mut T> {
        let mut index = self.probe(hash);
        if self.node(index).is_empty() {
            let new_size = self.header().size() + 1;
            let min_capacity = Self::get_min_capacity_for(new_size);
            if min_capacity > self.capacity() {
                self.rehash(min_capacity)?;
                index = self.probe(hash);
            }
            self.header_mut().set_size(new_size);
        }
        let node = self.node_mut(index);
        node.init(hash, value);
        Ok(&mut node.value)
    }

    /// Erases an element from the hash set.
    ///
    /// Returns true if the element was found and erased, false otherwise.
    pub fn erase(&mut self, hash: Scalar) -> bool {
        self.extract(hash).is_some()
    }

    /// Removes an element from the hash set and returns it if found.
    pub fn extract(&mut self, hash: Scalar) -> Option<T> {
        let mask = (self.capacity() - 1) as u64;
        let mut i = self.get_slot_index(hash);
        let value;
        loop {
            let node = self.node_mut(i as usize);
            if node.is_empty() {
                return None;
            }
            if node.hash() == hash {
                value = node.value;
                node.erase();
                self.header_mut().decrement_size();
                break;
            }
            i = (i + 1) & mask;
        }
        let mut j = (i + 1) & mask;
        loop {
            let node = self.node(j as usize);
            if node.is_empty() {
                return Some(value);
            }
            let k = self.get_slot_index(node.hash());
            if k <= i || k > j {
                *self.node_mut(i as usize) = *node;
                i = j;
            }
            j = (j + 1) & mask;
        }
    }

    /// Shrinks the capacity to the minimum required to hold the current elements (based on the
    /// maximum load factor).
    ///
    /// This function is a no-op if the current capacity is already the minimum required.
    ///
    /// The returned boolean is true iff the capacity was reduced. An error is returned in case
    /// reallocation fails due to I/O etc.
    pub fn shrink(&mut self) -> Result<bool> {
        let target_capacity = Self::get_min_capacity_for(std::cmp::max(self.size(), 1));
        if target_capacity < self.capacity() {
            self.rehash(target_capacity)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Erases an element and shrinks to the minimum required capacity if necessary.
    pub fn erase_and_shrink(&mut self, hash: Scalar) -> Result<bool> {
        if !self.erase(hash) {
            return Ok(false);
        }
        self.shrink()?;
        Ok(true)
    }

    /// Removes an element and shrinks to the minimum required capacity if necessary.
    pub fn extract_and_shrink(&mut self, hash: Scalar) -> Result<Option<T>> {
        let value = self.extract(hash);
        self.shrink()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::poseidon;

    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[repr(C)]
    struct TestHeaderData(StoredScalar);

    impl TestHeaderData {
        fn test_data() -> Self {
            Self(Scalar::from(42).into())
        }
    }

    impl Stored for TestHeaderData {}
    impl HeaderData for TestHeaderData {}

    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[repr(C)]
    struct TestNodeData(StoredScalar, StoredScalar, StoredScalar);

    impl TestNodeData {
        fn test_data1() -> Self {
            Self(
                Scalar::from(12).into(),
                Scalar::from(34).into(),
                Scalar::from(1).into(),
            )
        }

        fn test_hash1() -> Scalar {
            Self::test_data1().hash()
        }

        fn test_data2() -> Self {
            Self(
                Scalar::from(56).into(),
                Scalar::from(78).into(),
                Scalar::from(2).into(),
            )
        }

        fn test_hash2() -> Scalar {
            Self::test_data2().hash()
        }

        fn test_data3() -> Self {
            Self(
                Scalar::from(90).into(),
                Scalar::from(12).into(),
                Scalar::from(3).into(),
            )
        }

        fn test_hash3() -> Scalar {
            Self::test_data3().hash()
        }
    }

    impl Stored for TestNodeData {}

    impl NodeData for TestNodeData {
        fn hash(&self) -> Scalar {
            poseidon::hash_t3(&[self.0.to_scalar(), self.1.to_scalar()])
        }

        fn erase(&mut self) {
            self.0 = Scalar::ZERO.into();
            self.1 = Scalar::ZERO.into();
        }
    }

    type TestMappedHashSet = MappedHashSet<TestHeaderData, TestNodeData>;

    fn make_test_hash_set(size: usize) -> Result<TestMappedHashSet> {
        let capacity = TestMappedHashSet::get_min_capacity_for(std::cmp::max(size, 1));
        let mmap = MmapMut::map_anon(
            TestMappedHashSet::padded_header_size()
                + capacity * TestMappedHashSet::padded_node_size(),
        )?;
        MappedHashSet::new(mmap)
    }

    #[test]
    fn test_default_stored_scalar() {
        let scalar = StoredScalar::default();
        assert_eq!(scalar, Scalar::ZERO.into());
        assert!(scalar.is_zero());
        assert_eq!(scalar.to_scalar(), Scalar::ZERO);
    }

    #[test]
    fn test_stored_scalar() {
        let scalar: StoredScalar = Scalar::from(42).into();
        assert!(!scalar.is_zero());
        assert_eq!(scalar.to_scalar(), Scalar::from(42));
    }

    #[test]
    fn test_initial_state() {
        let mut set = make_test_hash_set(0).unwrap();
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_update_header_data() {
        let mut set = make_test_hash_set(0).unwrap();
        let header = TestHeaderData::test_data();
        *set.header_data_mut() = header;
        assert_eq!(*set.header_data(), header);
        assert_eq!(*set.header_data_mut(), header);
    }

    #[test]
    fn test_insert_one_element1() {
        let mut set = make_test_hash_set(1).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_insert_one_element2() {
        let mut set = make_test_hash_set(2).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_insert_one_element3() {
        let mut set = make_test_hash_set(1).unwrap();
        let element = TestNodeData::test_data2();
        assert!(set.insert(element).is_ok());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element);
    }

    #[test]
    fn test_insert_two_elements() {
        let mut set = make_test_hash_set(2).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert_eq!(set.size(), 2);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
    }

    #[test]
    fn test_insert_two_elements_and_grow() {
        let mut set = make_test_hash_set(1).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert_eq!(set.size(), 2);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
    }

    #[test]
    fn test_insert_three_elements() {
        let mut set = make_test_hash_set(3).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        let element3 = TestNodeData::test_data3();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.insert(element3).is_ok());
        assert_eq!(set.size(), 3);
        assert_eq!(set.capacity(), 8);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert_eq!(*set.get(TestNodeData::test_hash3()).unwrap(), element3);
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert_eq!(*set.get_mut(TestNodeData::test_hash3()).unwrap(), element3);
    }

    #[test]
    fn test_insert_three_elements_and_grow() {
        let mut set = make_test_hash_set(2).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        let element3 = TestNodeData::test_data3();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.insert(element3).is_ok());
        assert_eq!(set.size(), 3);
        assert_eq!(set.capacity(), 8);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert_eq!(*set.get(TestNodeData::test_hash3()).unwrap(), element3);
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element1);
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert_eq!(*set.get_mut(TestNodeData::test_hash3()).unwrap(), element3);
    }

    #[test]
    fn test_insert_element_twice() {
        let mut set = make_test_hash_set(1).unwrap();
        let mut element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        element.2 = element.2.to_scalar().square().into();
        assert_eq!(element.hash(), TestNodeData::test_hash1());
        assert!(set.insert(element).is_ok());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_erase_from_empty() {
        let mut set = make_test_hash_set(0).unwrap();
        assert!(!set.erase(TestNodeData::test_hash2()));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_extract_from_empty() {
        let mut set = make_test_hash_set(0).unwrap();
        assert!(set.extract(TestNodeData::test_hash2()).is_none());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_erase_missing_element() {
        let mut set = make_test_hash_set(0).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert!(!set.erase(TestNodeData::test_hash2()));
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_extract_missing_element() {
        let mut set = make_test_hash_set(0).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert!(set.extract(TestNodeData::test_hash2()).is_none());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_erase_one_element() {
        let mut set = make_test_hash_set(0).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert!(set.erase(element.hash()));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_extract_one_element() {
        let mut set = make_test_hash_set(0).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        let extracted = set.extract(element.hash()).unwrap();
        assert_eq!(extracted, element);
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_erase_one_element_and_shrink() {
        let mut set = make_test_hash_set(0).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert!(set.erase_and_shrink(element.hash()).unwrap());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_extract_one_element_and_shrink() {
        let mut set = make_test_hash_set(0).unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        let extracted = set.extract_and_shrink(element.hash()).unwrap().unwrap();
        assert_eq!(extracted, element);
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_erase_one_out_of_two_elements1() {
        let mut set = make_test_hash_set(2).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.erase(element1.hash()));
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
    }

    #[test]
    fn test_erase_one_out_of_two_elements2() {
        let mut set = make_test_hash_set(2).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.erase(element2.hash()));
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element1);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element1);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    #[test]
    fn test_extract_one_out_of_two_elements2() {
        let mut set = make_test_hash_set(2).unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        let extracted = set.extract(element2.hash()).unwrap();
        assert_eq!(extracted, element2);
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element1);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element1);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
    }

    // TODO
}
