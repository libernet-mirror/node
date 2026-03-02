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
use std::ops::{Index, IndexMut};

/// NOTE: there are several system architectures where the page size is very much not this one. This
/// is merely the most common value as well as a very good one to use for alignment in binary file
/// formats, so this is the memory alignment we optimize for.
const PAGE_SIZE: usize = 0x1000;

/// Indicates that a type is suitable for storage in a memory-mapped region.
pub trait Stored: Sized + Debug + Default + Copy + Clone + 'static {}

/// A `u64` stored in the memory-mapped region, in little endian order.
///
/// Do not store `u64` directly, as its endianness would change based on the CPU and that would make
/// data files non-portable.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct StoredU64(pub [u8; 8]);

impl StoredU64 {
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 8]
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

impl Stored for StoredU64 {}

impl From<u64> for StoredU64 {
    fn from(value: u64) -> Self {
        Self(value.to_le_bytes())
    }
}

impl Ord for StoredU64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_u64().cmp(&other.to_u64())
    }
}

impl PartialOrd for StoredU64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

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

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct StoredCircularBuffer<T: Stored, const N: usize> {
    values: [T; N],
    offset: StoredU64,
}

impl<T: Stored, const N: usize> StoredCircularBuffer<T, N> {
    pub fn top(&self) -> &T {
        let offset = (self.offset.to_u64() as usize + N - 1) % N;
        &self.values[offset]
    }

    pub fn top_mut(&mut self) -> &mut T {
        let offset = (self.offset.to_u64() as usize + N - 1) % N;
        &mut self.values[offset]
    }

    pub fn get(&self, index: usize) -> &T {
        assert!(index < N);
        let offset = self.offset.to_u64() as usize;
        &self.values[(offset + index) % N]
    }

    pub fn get_mut(&mut self, index: usize) -> &mut T {
        assert!(index < N);
        let offset = self.offset.to_u64() as usize;
        &mut self.values[(offset + index) % N]
    }

    pub fn push(&mut self, value: T) {
        let mut offset = self.offset.to_u64() as usize;
        self.values[offset] = value;
        offset = (offset + 1) % N;
        self.offset = (offset as u64).into();
    }

    pub fn pop(&mut self) -> T {
        let offset = (self.offset.to_u64() as usize + N - 1) % N;
        let mut result = T::default();
        std::mem::swap(&mut self.values[offset], &mut result);
        self.offset = (offset as u64).into();
        result
    }
}

impl<T: Stored, const N: usize> Default for StoredCircularBuffer<T, N> {
    fn default() -> Self {
        Self {
            values: std::array::from_fn(|_| T::default()),
            offset: StoredU64::default(),
        }
    }
}

impl<T: Stored, const N: usize> Stored for StoredCircularBuffer<T, N> {}

impl<T: Stored, const N: usize> IntoIterator for StoredCircularBuffer<T, N> {
    type Item = T;

    type IntoIter =
        std::iter::Take<std::iter::Skip<std::iter::Cycle<<[T; N] as IntoIterator>::IntoIter>>>;

    fn into_iter(self) -> Self::IntoIter {
        let offset = self.offset.to_u64() as usize;
        self.values.into_iter().cycle().skip(offset).take(N)
    }
}

impl<T: Stored, const N: usize> Index<usize> for StoredCircularBuffer<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
    }
}

impl<T: Stored, const N: usize> IndexMut<usize> for StoredCircularBuffer<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index)
    }
}

/// Trait for data that is stored in the header of a `MappedHashSet`.
pub trait HeaderData: Stored {}

#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct EmptyHeaderData {}

impl Stored for EmptyHeaderData {}
impl HeaderData for EmptyHeaderData {}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Header<T: HeaderData> {
    signature: [u8; 8],
    flags: [u8; 8],
    node_size: StoredU64,
    capacity: StoredU64,
    size: StoredU64,
    data: T,
}

impl<T: HeaderData> Header<T> {
    fn parse_flags(&self) -> (u32, u32) {
        let mut lo = [0u8; 4];
        lo.copy_from_slice(&self.flags[0..4]);
        let mut hi = [0u8; 4];
        hi.copy_from_slice(&self.flags[4..8]);
        (u32::from_le_bytes(lo), u32::from_le_bytes(hi))
    }

    fn new(flags: u32, node_size: usize, capacity: usize) -> Self {
        let mut header = Self {
            signature: *constants::DATA_FILE_SIGNATURE,
            flags: [0u8; 8],
            node_size: StoredU64::from(node_size as u64),
            capacity: StoredU64::from(capacity as u64),
            size: 0.into(),
            data: T::default(),
        };
        header.flags[0..4].copy_from_slice(&constants::DATA_FILE_VERSION.to_le_bytes());
        header.flags[4..8].copy_from_slice(&flags.to_le_bytes());
        header
    }

    fn file_version(&self) -> u32 {
        let (version, _) = self.parse_flags();
        version
    }

    fn flags(&self) -> u32 {
        let (_, flags) = self.parse_flags();
        flags
    }

    fn node_size(&self) -> usize {
        self.node_size.to_u64() as usize
    }

    fn capacity(&self) -> usize {
        self.capacity.to_u64() as usize
    }

    fn set_capacity(&mut self, capacity: usize) {
        self.capacity = (capacity as u64).into();
    }

    fn size(&self) -> usize {
        self.size.to_u64() as usize
    }

    fn set_size(&mut self, size: usize) {
        self.size = (size as u64).into();
    }

    fn increment_size(&mut self) {
        self.size = (self.size.to_u64() + 1).into();
    }

    fn decrement_size(&mut self) {
        let size = self.size.to_u64();
        assert!(size > 0);
        self.size = (size - 1).into();
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
}

/// Manages access to a node in the mapped memory region.
#[derive(Debug, Default, Copy, Clone)]
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
        self.value = T::default();
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
/// linear probing. For deletions we do not use tombstones: the deletion algorithm removes an
/// element and then simply shifts the local cluster (if any) backwards. It does so while still
/// respecting the natural positions of any elements from intersecting clusters.
///
/// The capacity of `MappedHashSet` (in terms of number of nodes, not bytes) is always a power of 2,
/// and thanks to that we can perform all rehashes in place without copying all data over to a new
/// memory-mapped region.
///
/// Our implementation also features a hysteresis cycle that uses two different thresholds for the
/// load factor to determine when we need to trigger a rehash: grows are triggered when the load
/// exceeds the *upper* threshold and shrinks are triggered when it falls below the *lower*
/// threshold. This way we prevent expensive zig-zagging rehashes in case elements are repeatedly
/// inserted and removed over the load factor threshold. In fact, since we set our lower threshold
/// to 40% and our upper threshold to 60%, it takes a 20% of removals to trigger a shrink after the
/// table has been grown and vice versa.
#[derive(Debug)]
pub struct MappedHashSet<H: HeaderData, T: NodeData> {
    mmap: MmapMut,
    _data: PhantomData<(H, T)>,
}

impl<H: HeaderData, T: NodeData> MappedHashSet<H, T> {
    // `MIN_LOAD_FACTOR_*` constants express the lower threshold on the load factor, while
    // `MAX_LOAD_FACTOR_*` constants express the upper threshold.

    const MIN_LOAD_FACTOR_NUMERATOR: usize = 4;
    const MIN_LOAD_FACTOR_DENOMINATOR: usize = 10;

    const MAX_LOAD_FACTOR_NUMERATOR: usize = 6;
    const MAX_LOAD_FACTOR_DENOMINATOR: usize = 10;

    /// The byte size allocated for the file header.
    pub const PADDED_HEADER_SIZE: usize = PAGE_SIZE;

    /// The maximum allowed size for `HeaderData` implementations.
    ///
    /// This is given by the fact that the total file header size must be 0x1000.
    pub const MAX_HEADER_DATA_SIZE: usize =
        PAGE_SIZE - std::mem::size_of::<Header<EmptyHeaderData>>();

    /// Returns the byte size allocated for every node.
    pub const fn padded_node_size() -> usize {
        std::mem::size_of::<Node<T>>().next_multiple_of(8)
    }

    const fn get_capacity_at_load(
        size: usize,
        load_factor_numerator: usize,
        load_factor_denominator: usize,
    ) -> usize {
        let size = if size < 1 { 1 } else { size };
        let dividend = size * load_factor_denominator;
        let remainder = dividend % load_factor_numerator;
        let quotient = dividend / load_factor_numerator + if remainder != 0 { 1 } else { 0 };
        quotient.next_power_of_two()
    }

    /// Returns the minimum capacity (in terms of number of nodes) required to host `size` nodes.
    ///
    /// When adding elements to the hash table this function is used to assess whether we need to
    /// trigger a grow. If the current capacity is below the minimum required to host the current
    /// elements, we grow the table.
    ///
    /// NOTE: the formula to retrieve the *minimum* capacity for a given size uses the *maximum*
    /// load factor, that's not a mistake. If the table has the minimum capacity required for a
    /// certain load it means it's at maximum load.
    pub const fn get_min_capacity_for(size: usize) -> usize {
        Self::get_capacity_at_load(
            size,
            Self::MAX_LOAD_FACTOR_NUMERATOR,
            Self::MAX_LOAD_FACTOR_DENOMINATOR,
        )
    }

    /// Returns the maximum capacity (in terms of number of nodes) allowed to host `size` nodes.
    ///
    /// When removing elements from the hash table this function is used to assess whether we need
    /// to trigger a shrink. If the current capacity exceeds the maximum allowed to host the current
    /// elements, we shrink the table.
    ///
    /// NOTE: the formula to retrieve the *maximum* capacity for a given size uses the *minimum*
    /// load factor, that's not a mistake. If the table has the maximum capacity allowed for a
    /// certain load (that is, it should have a lower capacity if it had even one less element) it
    /// means it's at minimum load.
    pub const fn get_max_capacity_for(size: usize) -> usize {
        Self::get_capacity_at_load(
            size,
            Self::MIN_LOAD_FACTOR_NUMERATOR,
            Self::MIN_LOAD_FACTOR_DENOMINATOR,
        )
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
        let offset = Self::PADDED_HEADER_SIZE + i * Self::padded_node_size();
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
        let offset = Self::PADDED_HEADER_SIZE + i * Self::padded_node_size();
        unsafe {
            // SAFETY: we're changing neither mutability nor lifetime, just reinterpreting the bytes
            // for the node. The caller is assumed to provide a valid index `i`, in which case
            // `offset` will point to a valid node within the data slice.
            &mut *(data.as_ptr().add(offset) as *mut Node<T>)
        }
    }

    /// TEST ONLY: checks the hash table for consistency.
    #[cfg(test)]
    pub fn check_consistency(&self) -> Result<()> {
        use std::collections::BTreeSet;

        let capacity = self.capacity();
        if !capacity.is_power_of_two() {
            return Err(anyhow!(
                "the capacity is not a power of 2 (got {})",
                capacity
            ));
        }

        let size = self.size();
        if capacity < Self::get_min_capacity_for(size) {
            return Err(anyhow!(
                "the size exceeds the max load factor (size={}, capacity={})",
                size,
                capacity,
            ));
        }

        let mut hashes = BTreeSet::default();
        let mask = capacity - 1;
        for i in 0..capacity {
            let node = self.node(i);
            if !node.is_empty() {
                let hash = node.value.hash();
                if node.hash() != hash {
                    return Err(anyhow!(
                        "wrong hash stored at slot {} (got {}, want {})",
                        i,
                        utils::format_scalar(node.hash()),
                        utils::format_scalar(hash)
                    ));
                }
                if !hashes.insert(hash) {
                    return Err(anyhow!("duplicate hash {}", utils::format_scalar(hash)));
                }
                let j = self.get_natural_position(node.hash()) as usize;
                let mut k = j;
                while k != i {
                    if self.node(k).is_empty() {
                        return Err(anyhow!(
                            "expected cluster [{}, {}] but found a hole at {}",
                            j,
                            i,
                            k
                        ));
                    }
                    k = (k + 1) & mask;
                }
            }
        }

        if hashes.len() != size {
            return Err(anyhow!(
                "incorrect size (got {}, want {})",
                self.size(),
                hashes.len()
            ));
        }

        Ok(())
    }

    /// Constructs a hash set from the provided data.
    ///
    /// Returns an error if the data is invalid, but the checks performed on it are not as extensive
    /// as those performed by `check_consistency`.
    pub fn load(mut mmap: MmapMut, expected_flags: u32) -> Result<Self> {
        let data = &mut mmap[..];
        {
            let address = data.as_ptr() as usize;
            if address % PAGE_SIZE != 0 {
                return Err(anyhow!("the memory-mapped address is not page-aligned"));
            }
        }
        let min_size = Self::PADDED_HEADER_SIZE + Self::min_capacity() * Self::padded_node_size();
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
        let file_version = set.header().file_version();
        if file_version != constants::DATA_FILE_VERSION {
            return Err(anyhow!(
                "unrecognized data file version {} (want {})",
                file_version,
                constants::DATA_FILE_VERSION
            ));
        }
        let flags = set.header().flags();
        if flags & expected_flags != expected_flags {
            return Err(anyhow!("invalid flags for this file type"));
        }
        let node_size = set.header().node_size();
        if node_size != Self::padded_node_size() {
            return Err(anyhow!(
                "incorrect node size (got {}, want {})",
                node_size,
                Self::padded_node_size()
            ));
        }
        let capacity = set.capacity();
        if capacity != capacity.next_power_of_two() {
            return Err(anyhow!(
                "the data capacity must be a power of 2 (was {})",
                capacity
            ));
        }
        let expected_length = Self::PADDED_HEADER_SIZE + capacity * Self::padded_node_size();
        if set.mmap.len() != expected_length {
            return Err(anyhow!(
                "incorrect mmap length (was {} bytes but this capacity requires {})",
                set.mmap.len(),
                expected_length
            ));
        }
        let size = set.size();
        if capacity < Self::get_min_capacity_for(size) {
            return Err(anyhow!(
                "the size exceeds the max load factor (size={}, capacity={})",
                size,
                capacity,
            ));
        }
        Ok(set)
    }

    /// Initializes a new hash set on the provided memory-mapped region.
    ///
    /// The memory-mapped region will be filled with zeros as part of the initialization process.
    /// Any previous contents are discarded.
    pub fn new(mut mmap: MmapMut, flags: u32) -> Result<Self> {
        let data = &mut mmap[..];
        data.fill(0);
        let capacity = (data.len() - Self::PADDED_HEADER_SIZE) / Self::padded_node_size();
        *unsafe { &mut *(std::ptr::from_ref(data) as *mut Header<H>) } =
            Header::<H>::new(flags, Self::padded_node_size(), capacity);
        Self::load(mmap, flags)
    }

    /// Returns the file format version as specified in the file.
    ///
    /// It must be `constants::DATA_FILE_VERSION`.
    pub fn file_version(&self) -> u32 {
        self.header().file_version()
    }

    /// Returns the flags specified in the file.
    ///
    /// Use the `DATA_FILE_TYPE_*` constants to parse this value.
    pub fn flags(&self) -> u32 {
        self.header().flags()
    }

    /// Returns the number of elements in the hash set.
    pub fn size(&self) -> usize {
        self.header().size()
    }

    /// Returns the capacity (in terms of number of nodes) of the hash set.
    ///
    /// NOTE: this will always return a power of 2.
    pub fn capacity(&self) -> usize {
        self.header().capacity()
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

    fn get_natural_position(&self, hash: Scalar) -> u64 {
        let mask = self.capacity() as u64 - 1;
        (utils::scalar_to_u256(hash) & U256::from(mask)).as_u64()
    }

    fn probe(&self, hash: Scalar) -> usize {
        let mask = self.capacity() - 1;
        let mut i = self.get_natural_position(hash) as usize;
        loop {
            let node = self.node(i);
            if node.is_empty() || node.hash() == hash {
                return i;
            }
            i = (i + 1) & mask;
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

    fn extract_wraparound_nodes(&mut self) -> Vec<Node<T>> {
        let mut elements = vec![];
        for i in 0..self.capacity() {
            let node = self.node(i);
            if node.is_empty() {
                break;
            }
            let j = self.get_natural_position(node.hash());
            if j > i as u64 {
                elements.push(*node);
                self.node_mut(i).erase();
            }
        }
        elements
    }

    fn reinsert_wraparound_nodes(&mut self, nodes: Vec<Node<T>>) -> Result<()> {
        for node in nodes {
            let destination = self.node_mut(self.probe(node.hash()));
            assert!(destination.is_empty());
            *destination = node;
        }
        Ok(())
    }

    fn shrink(&mut self) -> Result<()> {
        let old_capacity = self.capacity();
        if old_capacity < 2 {
            return Ok(());
        }
        let new_capacity = old_capacity >> 1;

        // Step 1: extract wraparound elements.
        let wraparound_nodes = self.extract_wraparound_nodes();
        self.header_mut().set_capacity(new_capacity);

        // Step 2: reinsert upper half.
        for i in new_capacity..old_capacity {
            let node = self.node(i);
            if !node.is_empty() {
                let node = *node;
                let destination = self.node_mut(self.probe(node.hash()));
                assert!(destination.is_empty());
                *destination = node;
            }
        }

        // Step 3: reinsert wraparound elements.
        self.reinsert_wraparound_nodes(wraparound_nodes)?;

        unsafe {
            self.mmap.remap(
                Self::PADDED_HEADER_SIZE + new_capacity * Self::padded_node_size(),
                memmap2::RemapOptions::default().may_move(true),
            )
        }?;

        Ok(())
    }

    fn grow(&mut self) -> Result<()> {
        let old_capacity = self.capacity();
        let new_capacity = old_capacity * 2;

        unsafe {
            self.mmap.remap(
                Self::PADDED_HEADER_SIZE + new_capacity * Self::padded_node_size(),
                memmap2::RemapOptions::default().may_move(true),
            )
        }?;
        let data = &mut self.mmap[..];
        data[(Self::PADDED_HEADER_SIZE + old_capacity * Self::padded_node_size())
            ..(Self::PADDED_HEADER_SIZE + new_capacity * Self::padded_node_size())]
            .fill(0);

        // Step 1: extract wraparound elements.
        let wraparound_nodes = self.extract_wraparound_nodes();
        self.header_mut().set_capacity(new_capacity);

        // Step 2: split.
        for i in 0..old_capacity {
            let node = self.node(i);
            if !node.is_empty() {
                let index = self.get_natural_position(node.hash());
                if index & (old_capacity as u64) != 0 {
                    *self.node_mut(i + old_capacity) = *node;
                    self.node_mut(i).erase();
                }
            }
        }

        // Step 3: compact.
        let mask = new_capacity - 1;
        for i in 0..new_capacity {
            let node = self.node(i);
            if !node.is_empty() {
                let j = self.get_natural_position(node.hash()) as usize;
                let mut k = j;
                while k != i {
                    if self.node(k).is_empty() {
                        *self.node_mut(k) = *node;
                        self.node_mut(i).erase();
                        break;
                    }
                    k = (k + 1) & mask;
                }
            }
        }

        // Step 4: reinsert wraparound elements.
        self.reinsert_wraparound_nodes(wraparound_nodes)?;

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
            if Self::get_min_capacity_for(new_size) > self.capacity() {
                self.grow()?;
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
        let mut i = self.get_natural_position(hash);
        let value;
        loop {
            let node = self.node(i as usize);
            if node.is_empty() {
                return None;
            }
            if node.hash() == hash {
                value = node.value;
                self.header_mut().decrement_size();
                break;
            }
            i = (i + 1) & mask;
        }
        let mut j = (i + 1) & mask;
        loop {
            let node = self.node(j as usize);
            if node.is_empty() {
                self.node_mut(i as usize).erase();
                return Some(value);
            }
            let k = self.get_natural_position(node.hash());
            if (i < j && (k <= i || k > j)) || (j < i && (k <= i && k > j)) {
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
    pub fn shrink_to_fit(&mut self) -> Result<bool> {
        if Self::get_max_capacity_for(self.size()) < self.capacity() {
            self.shrink()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Erases an element and shrinks to the minimum required capacity if necessary.
    pub fn erase_and_shrink(&mut self, hash: Scalar) -> Result<bool> {
        if !self.erase(hash) {
            return Ok(false);
        }
        self.shrink_to_fit()?;
        Ok(true)
    }

    /// Removes an element and shrinks to the minimum required capacity if necessary.
    pub fn extract_and_shrink(&mut self, hash: Scalar) -> Result<Option<T>> {
        let value = self.extract(hash);
        self.shrink_to_fit()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::poseidon;

    const TEST_FLAGS: u32 =
        constants::DATA_FILE_TYPE_ACCOUNT_TREE | constants::DATA_FILE_TYPE_TEST_TREE;

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
        fn new(i: usize) -> Self {
            Self(
                Scalar::from(i as u64).into(),
                Scalar::ZERO.into(),
                Scalar::ZERO.into(),
            )
        }

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
    }

    type TestMappedHashSet = MappedHashSet<TestHeaderData, TestNodeData>;

    fn make_test_hash_set() -> Result<TestMappedHashSet> {
        MappedHashSet::new(
            MmapMut::map_anon(
                TestMappedHashSet::PADDED_HEADER_SIZE + 2 * TestMappedHashSet::padded_node_size(),
            )?,
            TEST_FLAGS,
        )
    }

    #[test]
    fn test_default_stored_u64() {
        let value = StoredU64::default();
        assert_eq!(value, 0.into());
        assert!(value.is_zero());
        assert_eq!(value.to_u64(), 0);
    }

    #[test]
    fn test_stored_u64() {
        let value: StoredU64 = 42.into();
        assert!(!value.is_zero());
        assert_eq!(value.to_u64(), 42);
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
    fn test_empty_stored_circular_buffer_1() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 1>::default();
        assert_eq!(*buffer.top(), StoredScalar::default());
        assert_eq!(*buffer.top_mut(), StoredScalar::default());
        assert_eq!(*buffer.get(0), StoredScalar::default());
        assert_eq!(*buffer.get_mut(0), StoredScalar::default());
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![StoredScalar::default()]
        );
    }

    #[test]
    fn test_empty_stored_circular_buffer_2() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 2>::default();
        assert_eq!(*buffer.top(), StoredScalar::default());
        assert_eq!(*buffer.top_mut(), StoredScalar::default());
        assert_eq!(*buffer.get(0), StoredScalar::default());
        assert_eq!(*buffer.get(1), StoredScalar::default());
        assert_eq!(*buffer.get_mut(0), StoredScalar::default());
        assert_eq!(*buffer.get_mut(1), StoredScalar::default());
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![StoredScalar::default(), StoredScalar::default()]
        );
    }

    #[test]
    fn test_empty_stored_circular_buffer_3() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 3>::default();
        assert_eq!(*buffer.top(), StoredScalar::default());
        assert_eq!(*buffer.top_mut(), StoredScalar::default());
        assert_eq!(*buffer.get(0), StoredScalar::default());
        assert_eq!(*buffer.get(1), StoredScalar::default());
        assert_eq!(*buffer.get(2), StoredScalar::default());
        assert_eq!(*buffer.get_mut(0), StoredScalar::default());
        assert_eq!(*buffer.get_mut(1), StoredScalar::default());
        assert_eq!(*buffer.get_mut(2), StoredScalar::default());
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![
                StoredScalar::default(),
                StoredScalar::default(),
                StoredScalar::default(),
            ]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_one_element_1() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 1>::default();
        let value = Scalar::from(42).into();
        buffer.push(value);
        assert_eq!(*buffer.top(), value);
        assert_eq!(*buffer.top_mut(), value);
        assert_eq!(*buffer.get(0), value);
        assert_eq!(*buffer.get_mut(0), value);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![value]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_one_element_2() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 2>::default();
        let value = Scalar::from(42).into();
        buffer.push(value);
        assert_eq!(*buffer.top(), value);
        assert_eq!(*buffer.top_mut(), value);
        assert_eq!(*buffer.get(0), StoredScalar::default());
        assert_eq!(*buffer.get(1), value);
        assert_eq!(*buffer.get_mut(0), StoredScalar::default());
        assert_eq!(*buffer.get_mut(1), value);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![StoredScalar::default(), value]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_one_element_3() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 3>::default();
        let value = Scalar::from(42).into();
        buffer.push(value);
        assert_eq!(*buffer.top(), value);
        assert_eq!(*buffer.top_mut(), value);
        assert_eq!(*buffer.get(0), StoredScalar::default());
        assert_eq!(*buffer.get(1), StoredScalar::default());
        assert_eq!(*buffer.get(2), value);
        assert_eq!(*buffer.get_mut(0), StoredScalar::default());
        assert_eq!(*buffer.get_mut(1), StoredScalar::default());
        assert_eq!(*buffer.get_mut(2), value);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![StoredScalar::default(), StoredScalar::default(), value]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_two_elements_1() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 1>::default();
        let value1 = Scalar::from(12).into();
        let value2 = Scalar::from(34).into();
        buffer.push(value1);
        buffer.push(value2);
        assert_eq!(*buffer.top(), value2);
        assert_eq!(*buffer.top_mut(), value2);
        assert_eq!(*buffer.get(0), value2);
        assert_eq!(*buffer.get_mut(0), value2);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![value2]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_two_elements_2() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 2>::default();
        let value1 = Scalar::from(12).into();
        let value2 = Scalar::from(34).into();
        buffer.push(value1);
        buffer.push(value2);
        assert_eq!(*buffer.top(), value2);
        assert_eq!(*buffer.top_mut(), value2);
        assert_eq!(*buffer.get(0), value1);
        assert_eq!(*buffer.get(1), value2);
        assert_eq!(*buffer.get_mut(0), value1);
        assert_eq!(*buffer.get_mut(1), value2);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![value1, value2]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_two_elements_3() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 3>::default();
        let value1 = Scalar::from(12).into();
        let value2 = Scalar::from(34).into();
        buffer.push(value1);
        buffer.push(value2);
        assert_eq!(*buffer.top(), value2);
        assert_eq!(*buffer.top_mut(), value2);
        assert_eq!(*buffer.get(0), StoredScalar::default());
        assert_eq!(*buffer.get(1), value1);
        assert_eq!(*buffer.get(2), value2);
        assert_eq!(*buffer.get_mut(0), StoredScalar::default());
        assert_eq!(*buffer.get_mut(1), value1);
        assert_eq!(*buffer.get_mut(2), value2);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![StoredScalar::default(), value1, value2]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_three_elements_1() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 1>::default();
        let value1 = Scalar::from(56).into();
        let value2 = Scalar::from(78).into();
        let value3 = Scalar::from(90).into();
        buffer.push(value1);
        buffer.push(value2);
        buffer.push(value3);
        assert_eq!(*buffer.top(), value3);
        assert_eq!(*buffer.top_mut(), value3);
        assert_eq!(*buffer.get(0), value3);
        assert_eq!(*buffer.get_mut(0), value3);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![value3]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_three_elements_2() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 2>::default();
        let value1 = Scalar::from(56).into();
        let value2 = Scalar::from(78).into();
        let value3 = Scalar::from(90).into();
        buffer.push(value1);
        buffer.push(value2);
        buffer.push(value3);
        assert_eq!(*buffer.top(), value3);
        assert_eq!(*buffer.top_mut(), value3);
        assert_eq!(*buffer.get(0), value2);
        assert_eq!(*buffer.get(1), value3);
        assert_eq!(*buffer.get_mut(0), value2);
        assert_eq!(*buffer.get_mut(1), value3);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![value2, value3]
        );
    }

    #[test]
    fn test_stored_circular_buffer_push_three_elements_3() {
        let mut buffer = StoredCircularBuffer::<StoredScalar, 3>::default();
        let value1 = Scalar::from(56).into();
        let value2 = Scalar::from(78).into();
        let value3 = Scalar::from(90).into();
        buffer.push(value1);
        buffer.push(value2);
        buffer.push(value3);
        assert_eq!(*buffer.top(), value3);
        assert_eq!(*buffer.top_mut(), value3);
        assert_eq!(*buffer.get(0), value1);
        assert_eq!(*buffer.get(1), value2);
        assert_eq!(*buffer.get(2), value3);
        assert_eq!(*buffer.get_mut(0), value1);
        assert_eq!(*buffer.get_mut(1), value2);
        assert_eq!(*buffer.get_mut(2), value3);
        assert_eq!(
            buffer.into_iter().collect::<Vec<StoredScalar>>(),
            vec![value1, value2, value3]
        );
    }

    #[test]
    fn test_initial_state() {
        let mut set = make_test_hash_set().unwrap();
        assert_eq!(set.file_version(), constants::DATA_FILE_VERSION);
        assert_eq!(set.flags(), TEST_FLAGS);
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_update_header_data() {
        let mut set = make_test_hash_set().unwrap();
        let header = TestHeaderData::test_data();
        *set.header_data_mut() = header;
        assert_eq!(*set.header_data(), header);
        assert_eq!(*set.header_data_mut(), header);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_insert_one_element1() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_insert_one_element2() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_insert_two_elements() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_insert_three_elements() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_insert_element_twice() {
        let mut set = make_test_hash_set().unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert!(set.insert(element).is_ok());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert_eq!(*set.get(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash1()).unwrap(), element);
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_insert_modified_element() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_from_empty() {
        let mut set = make_test_hash_set().unwrap();
        assert!(!set.erase(TestNodeData::test_hash2()));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_from_empty() {
        let mut set = make_test_hash_set().unwrap();
        assert!(set.extract(TestNodeData::test_hash2()).is_none());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_missing_element() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_missing_element() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_element() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_element() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_element_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_element_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_element_twice() {
        let mut set = make_test_hash_set().unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert!(set.erase(element.hash()));
        assert!(!set.erase(element.hash()));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_element_twice() {
        let mut set = make_test_hash_set().unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        assert_eq!(set.extract(element.hash()).unwrap(), element);
        assert!(set.extract(element.hash()).is_none());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_out_of_two_elements1() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_out_of_two_elements2() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_out_of_two_elements1() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        let extracted = set.extract(element1.hash()).unwrap();
        assert_eq!(extracted, element1);
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_out_of_two_elements2() {
        let mut set = make_test_hash_set().unwrap();
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
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_out_of_two_elements_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.erase_and_shrink(element1.hash()).unwrap());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_out_of_two_elements_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        let extracted = set.extract_and_shrink(element1.hash()).unwrap().unwrap();
        assert_eq!(extracted, element1);
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_one_element_out_of_two_twice() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.erase(element1.hash()));
        assert!(!set.erase(element1.hash()));
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_one_element_out_of_two_twice() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert_eq!(set.extract(element1.hash()).unwrap(), element1);
        assert!(set.extract(element1.hash()).is_none());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert_eq!(*set.get_mut(TestNodeData::test_hash2()).unwrap(), element2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_two_elements() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.erase(element1.hash()));
        assert!(set.erase(element2.hash()));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_two_elements() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert_eq!(set.extract(element1.hash()).unwrap(), element1);
        assert_eq!(set.extract(element2.hash()).unwrap(), element2);
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_two_elements_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.erase_and_shrink(element1.hash()).unwrap());
        assert!(set.erase_and_shrink(element2.hash()).unwrap());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_two_elements_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert_eq!(
            set.extract_and_shrink(element1.hash()).unwrap().unwrap(),
            element1
        );
        assert_eq!(
            set.extract_and_shrink(element2.hash()).unwrap().unwrap(),
            element2
        );
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_three_elements() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        let element3 = TestNodeData::test_data3();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.insert(element3).is_ok());
        assert!(set.erase(element1.hash()));
        assert!(set.erase(element2.hash()));
        assert!(set.erase(element3.hash()));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 8);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get(TestNodeData::test_hash3()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash3()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_three_elements() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        let element3 = TestNodeData::test_data3();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.insert(element3).is_ok());
        assert_eq!(set.extract(element1.hash()).unwrap(), element1);
        assert_eq!(set.extract(element2.hash()).unwrap(), element2);
        assert_eq!(set.extract(element3.hash()).unwrap(), element3);
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 8);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get(TestNodeData::test_hash3()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash3()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_erase_three_elements_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        let element3 = TestNodeData::test_data3();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.insert(element3).is_ok());
        assert!(set.erase_and_shrink(element1.hash()).unwrap());
        assert!(set.erase_and_shrink(element2.hash()).unwrap());
        assert!(set.erase_and_shrink(element3.hash()).unwrap());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get(TestNodeData::test_hash3()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash3()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_extract_three_elements_and_shrink() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        let element3 = TestNodeData::test_data3();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        assert!(set.insert(element3).is_ok());
        assert_eq!(
            set.extract_and_shrink(element1.hash()).unwrap().unwrap(),
            element1
        );
        assert_eq!(
            set.extract_and_shrink(element2.hash()).unwrap().unwrap(),
            element2
        );
        assert_eq!(
            set.extract_and_shrink(element3.hash()).unwrap().unwrap(),
            element3
        );
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.header_data(), TestHeaderData::default());
        assert_eq!(*set.header_data_mut(), TestHeaderData::default());
        assert!(set.get(TestNodeData::test_hash1()).is_none());
        assert!(set.get(TestNodeData::test_hash2()).is_none());
        assert!(set.get(TestNodeData::test_hash3()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash1()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash2()).is_none());
        assert!(set.get_mut(TestNodeData::test_hash3()).is_none());
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_max_load_factor() {
        let mut set = make_test_hash_set().unwrap();
        let elements: [TestNodeData; 10] = std::array::from_fn(|i| TestNodeData::new(i));
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert!(set.insert(elements[0]).is_ok());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert!(set.insert(elements[1]).is_ok());
        assert_eq!(set.size(), 2);
        assert_eq!(set.capacity(), 4);
        assert!(set.insert(elements[2]).is_ok());
        assert_eq!(set.size(), 3);
        assert_eq!(set.capacity(), 8);
        assert!(set.insert(elements[3]).is_ok());
        assert_eq!(set.size(), 4);
        assert_eq!(set.capacity(), 8);
        assert!(set.insert(elements[4]).is_ok());
        assert_eq!(set.size(), 5);
        assert_eq!(set.capacity(), 16);
        assert!(set.insert(elements[5]).is_ok());
        assert_eq!(set.size(), 6);
        assert_eq!(set.capacity(), 16);
        assert!(set.insert(elements[6]).is_ok());
        assert_eq!(set.size(), 7);
        assert_eq!(set.capacity(), 16);
        assert!(set.insert(elements[7]).is_ok());
        assert_eq!(set.size(), 8);
        assert_eq!(set.capacity(), 16);
        assert!(set.insert(elements[8]).is_ok());
        assert_eq!(set.size(), 9);
        assert_eq!(set.capacity(), 16);
        assert!(set.insert(elements[9]).is_ok());
        assert_eq!(set.size(), 10);
        assert_eq!(set.capacity(), 32);
    }

    #[test]
    fn test_min_load_factor() {
        let mut set = make_test_hash_set().unwrap();
        let elements: [TestNodeData; 10] = std::array::from_fn(|i| {
            let element = TestNodeData::new(i);
            assert!(set.insert(element).is_ok());
            element
        });
        assert_eq!(set.size(), 10);
        assert_eq!(set.capacity(), 32);
        assert!(set.erase_and_shrink(elements[0].hash()).unwrap());
        assert_eq!(set.size(), 9);
        assert_eq!(set.capacity(), 32);
        assert!(set.erase_and_shrink(elements[1].hash()).unwrap());
        assert_eq!(set.size(), 8);
        assert_eq!(set.capacity(), 32);
        assert!(set.erase_and_shrink(elements[2].hash()).unwrap());
        assert_eq!(set.size(), 7);
        assert_eq!(set.capacity(), 32);
        assert!(set.erase_and_shrink(elements[3].hash()).unwrap());
        assert_eq!(set.size(), 6);
        assert_eq!(set.capacity(), 16);
        assert!(set.erase_and_shrink(elements[4].hash()).unwrap());
        assert_eq!(set.size(), 5);
        assert_eq!(set.capacity(), 16);
        assert!(set.erase_and_shrink(elements[5].hash()).unwrap());
        assert_eq!(set.size(), 4);
        assert_eq!(set.capacity(), 16);
        assert!(set.erase_and_shrink(elements[6].hash()).unwrap());
        assert_eq!(set.size(), 3);
        assert_eq!(set.capacity(), 8);
        assert!(set.erase_and_shrink(elements[7].hash()).unwrap());
        assert_eq!(set.size(), 2);
        assert_eq!(set.capacity(), 8);
        assert!(set.erase_and_shrink(elements[8].hash()).unwrap());
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 4);
        assert!(set.erase_and_shrink(elements[9].hash()).unwrap());
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 4);
    }

    #[test]
    fn test_reload_empty_set() {
        let mmap = make_test_hash_set().unwrap().take();
        let set = MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_reload_one_element() {
        let mut set = make_test_hash_set().unwrap();
        let element = TestNodeData::test_data1();
        assert!(set.insert(element).is_ok());
        let mmap = set.take();
        let set = MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(set.size(), 1);
        assert_eq!(set.capacity(), 2);
        assert_eq!(*set.get(element.hash()).unwrap(), element);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_reload_two_elements() {
        let mut set = make_test_hash_set().unwrap();
        let element1 = TestNodeData::test_data1();
        let element2 = TestNodeData::test_data2();
        assert!(set.insert(element1).is_ok());
        assert!(set.insert(element2).is_ok());
        let mmap = set.take();
        let set = MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(set.size(), 2);
        assert_eq!(set.capacity(), 4);
        assert_eq!(*set.get(element1.hash()).unwrap(), element1);
        assert_eq!(*set.get(element2.hash()).unwrap(), element2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_validate_header_signature() {
        let mut mmap = make_test_hash_set().unwrap().take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.signature.copy_from_slice(b"loremips");
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }

    #[test]
    fn test_validate_file_version() {
        let mut mmap = make_test_hash_set().unwrap().take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.flags[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }

    #[test]
    fn test_validate_flags() {
        let mut mmap = make_test_hash_set().unwrap().take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.flags[4..8].fill(0);
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }

    #[test]
    fn test_ignore_extra_flags() {
        let mut mmap = make_test_hash_set().unwrap().take();
        let flags = TEST_FLAGS | 0xff000000u32;
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.flags[4..8].copy_from_slice(&flags.to_le_bytes());
        let set = MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).unwrap();
        assert_eq!(set.flags(), flags);
        assert_eq!(set.size(), 0);
        assert_eq!(set.capacity(), 2);
        assert!(set.check_consistency().is_ok());
    }

    #[test]
    fn test_validate_node_size() {
        let mut mmap = make_test_hash_set().unwrap().take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.node_size = 42.into();
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }

    #[test]
    fn test_validate_capacity() {
        let mut set = make_test_hash_set().unwrap();
        assert!(set.insert(TestNodeData::test_data1()).is_ok());
        assert!(set.insert(TestNodeData::test_data2()).is_ok());
        let mut mmap = set.take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.capacity = 2.into();
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }

    #[test]
    fn test_validate_power_of_two_capacity() {
        let mut set = make_test_hash_set().unwrap();
        assert!(set.insert(TestNodeData::test_data1()).is_ok());
        assert!(set.insert(TestNodeData::test_data2()).is_ok());
        let mut mmap = set.take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.capacity = 46.into();
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }

    #[test]
    fn test_validate_size() {
        let mut set = make_test_hash_set().unwrap();
        assert!(set.insert(TestNodeData::test_data1()).is_ok());
        assert!(set.insert(TestNodeData::test_data2()).is_ok());
        let mut mmap = set.take();
        let header =
            unsafe { &mut *(std::ptr::from_ref(&mut *mmap) as *mut Header<TestHeaderData>) };
        header.size = 64.into();
        assert!(MappedHashSet::<TestHeaderData, TestNodeData>::load(mmap, TEST_FLAGS).is_err());
    }
}
