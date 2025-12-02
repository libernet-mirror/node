use crate::libernet;
use crate::proto::{self, DecodeFromAny, EncodeToAny};
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use crypto::{
    merkle::{AsScalar, FromScalar, Proof as LowLevelMerkleProof},
    utils, xits,
};
use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock, Mutex};

trait Node<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
>: Debug + Send + Sync + AsScalar + 'static
{
    fn get(&self, key: K) -> &V;
    fn lookup(&self, key: K) -> (&V, Vec<[Scalar; W]>);
    fn put(self: Arc<Self>, key: K, value: V) -> Arc<dyn Node<K, V, W>>;
}

#[derive(Debug)]
struct PhantomNodes<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> {
    nodes: Vec<Arc<dyn Node<K, V, W>>>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> PhantomNodes<K, V, W, H>
{
    fn get(&self, level: usize) -> Arc<dyn Node<K, V, W>> {
        self.nodes[level].clone()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> Default for PhantomNodes<K, V, 2, H>
{
    fn default() -> Self {
        let mut nodes = vec![];
        let mut node: Arc<dyn Node<K, V, 2>> = Arc::new(Leaf::new(V::default()));
        nodes.push(node.clone());
        for level in 1..=H {
            node = Arc::new(InternalNode::new(level, [node.clone(), node.clone()]));
            nodes.push(node.clone());
        }
        Self { nodes }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> Default for PhantomNodes<K, V, 3, H>
{
    fn default() -> Self {
        let mut nodes = vec![];
        let mut node: Arc<dyn Node<K, V, 3>> = Arc::new(Leaf::new(V::default()));
        nodes.push(node.clone());
        for level in 1..=H {
            node = Arc::new(InternalNode::new(
                level,
                [node.clone(), node.clone(), node.clone()],
            ));
            nodes.push(node.clone());
        }
        Self { nodes }
    }
}

#[derive(Debug, Default)]
struct MonomorphicPhantomNodes {
    map: Mutex<BTreeMap<(TypeId, usize, usize), Arc<dyn Any + Send + Sync>>>,
}

impl MonomorphicPhantomNodes {
    fn get<
        K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
        V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
        const W: usize,
        const H: usize,
    >(
        &self,
        level: usize,
    ) -> Arc<dyn Node<K, V, W>> {
        let id = (TypeId::of::<(K, V)>(), W, H);
        {
            let map = self.map.lock().unwrap();
            if let Some(nodes) = map.get(&id) {
                return nodes
                    .clone()
                    .downcast::<PhantomNodes<K, V, W, H>>()
                    .unwrap()
                    .get(level);
            }
        }
        // The new PhantomNodes instance MUST be constructed outside of the lock because `V` may be
        // a nested Merkle tree whose default construction would again call into here and cause
        // reentrancy.
        //
        // NOTE: we'll be able to simplify this code when Rust provides a reentrant lock
        // implementation (see https://github.com/rust-lang/rust/issues/121440).
        let nodes: Arc<dyn Any + Send + Sync> = match W {
            2 => Arc::new(PhantomNodes::<K, V, 2, H>::default()),
            3 => Arc::new(PhantomNodes::<K, V, 3, H>::default()),
            _ => unimplemented!(),
        };
        {
            let mut map = self.map.lock().unwrap();
            if !map.contains_key(&id) {
                map.insert(id, nodes);
            }
            map.get(&id).unwrap().clone()
        }
        .downcast::<PhantomNodes<K, V, W, H>>()
        .unwrap()
        .get(level)
    }
}

static PHANTOM_NODES: LazyLock<MonomorphicPhantomNodes> =
    LazyLock::new(MonomorphicPhantomNodes::default);

#[derive(Debug, Clone)]
struct Leaf<V: Debug + Default + Clone + Send + Sync + AsScalar + 'static> {
    value: V,
}

impl<V: Debug + Default + Clone + Send + Sync + AsScalar + 'static> Leaf<V> {
    fn new(value: V) -> Self {
        Self { value }
    }
}
impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
> Node<K, V, W> for Leaf<V>
{
    fn get(&self, _key: K) -> &V {
        &self.value
    }

    fn lookup(&self, _key: K) -> (&V, Vec<[Scalar; W]>) {
        (&self.value, vec![])
    }

    fn put(self: Arc<Self>, _key: K, value: V) -> Arc<dyn Node<K, V, W>> {
        if value.as_scalar() != self.value.as_scalar() {
            Arc::new(Self::new(value))
        } else {
            self
        }
    }
}

impl<V: Debug + Default + Clone + Send + Sync + AsScalar + 'static> AsScalar for Leaf<V> {
    fn as_scalar(&self) -> Scalar {
        self.value.as_scalar()
    }
}

#[derive(Debug, Clone)]
struct InternalNode<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
> {
    // TODO: convert `level` to a generic const argument when Rust supports generic const argument
    // expressions. See <https://github.com/rust-lang/rust/issues/76560>.
    level: usize,
    children: [Arc<dyn Node<K, V, W>>; W],
    hash: Scalar,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
> InternalNode<K, V, W>
{
    fn map_nodes<T>(
        array: &[Arc<dyn Node<K, V, W>>; W],
        mut f: impl FnMut(&Arc<dyn Node<K, V, W>>) -> T,
    ) -> [T; W] {
        std::array::from_fn(|i| f(&array[i]))
    }

    fn map_children<T>(&self, f: impl FnMut(&Arc<dyn Node<K, V, W>>) -> T) -> [T; W] {
        Self::map_nodes(&self.children, f)
    }

    fn new(level: usize, children: [Arc<dyn Node<K, V, W>>; W]) -> Self {
        let hash = utils::poseidon_hash(&Self::map_nodes(&children, |child| child.as_scalar()));
        Self {
            level,
            children,
            hash,
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> InternalNode<K, V, 2>
{
    fn get_bit(&self, key: K) -> usize {
        let count = Scalar::from(self.level as u64 - 1);
        let bit = xits::and1(xits::shr(key.as_scalar(), count));
        bit.to_bytes_le()[0] as usize
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Node<K, V, 2> for InternalNode<K, V, 2>
{
    fn get(&self, key: K) -> &V {
        self.children[self.get_bit(key)].get(key)
    }

    fn lookup(&self, key: K) -> (&V, Vec<[Scalar; 2]>) {
        let (value, mut path) = self.children[self.get_bit(key)].lookup(key);
        path.push(self.map_children(|child| child.as_scalar()));
        (value, path)
    }

    fn put(self: Arc<Self>, key: K, value: V) -> Arc<dyn Node<K, V, 2>> {
        let mut children = self.children.clone();
        let bit = self.get_bit(key);
        let child = children[bit].clone().put(key, value);
        if child.as_scalar() != children[bit].as_scalar() {
            children[bit] = child;
            Arc::new(Self::new(self.level, children))
        } else {
            self
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> InternalNode<K, V, 3>
{
    fn get_trit(&self, key: K) -> usize {
        let count = (self.level - 1) as u8;
        let trit = xits::mod3(xits::div_pow3(key.as_scalar(), count));
        trit.to_bytes_le()[0] as usize
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
> Node<K, V, 3> for InternalNode<K, V, 3>
{
    fn get(&self, key: K) -> &V {
        self.children[self.get_trit(key)].get(key)
    }

    fn lookup(&self, key: K) -> (&V, Vec<[Scalar; 3]>) {
        let (value, mut path) = self.children[self.get_trit(key)].lookup(key);
        path.push(self.map_children(|child| child.as_scalar()));
        (value, path)
    }

    fn put(self: Arc<Self>, key: K, value: V) -> Arc<dyn Node<K, V, 3>> {
        let mut children = self.children.clone();
        let trit = self.get_trit(key);
        let child = children[trit].clone().put(key, value);
        if child.as_scalar() != children[trit].as_scalar() {
            children[trit] = child;
            Arc::new(Self::new(self.level, children))
        } else {
            self
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
> AsScalar for InternalNode<K, V, W>
{
    fn as_scalar(&self) -> Scalar {
        self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> {
    inner: LowLevelMerkleProof<K, V, W, H>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> MerkleProof<K, V, W, H>
{
    pub fn new(key: K, value: V, path: [[Scalar; W]; H], root_hash: Scalar) -> Self {
        Self {
            inner: LowLevelMerkleProof::<K, V, W, H>::new(key, value, path, root_hash),
        }
    }

    pub fn key(&self) -> K {
        self.inner.key()
    }

    pub fn value(&self) -> &V {
        self.inner.value()
    }

    pub fn take_value(self) -> V {
        self.inner.take_value()
    }

    pub fn map<U: Debug + Clone + Send + Sync + AsScalar + 'static>(
        self,
        new_value: U,
    ) -> Result<MerkleProof<K, U, W, H>> {
        Ok(MerkleProof {
            inner: self.inner.map(new_value)?,
        })
    }

    pub fn path(&self) -> &[[Scalar; W]; H] {
        self.inner.path()
    }

    pub fn root_hash(&self) -> Scalar {
        self.inner.root_hash()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> MerkleProof<K, V, 2, H>
{
    pub fn compressed_path(&self) -> [Scalar; H] {
        self.inner.compressed_path()
    }

    pub fn verify(&self) -> Result<()> {
        self.inner.verify()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + EncodeToAny + 'static,
    const H: usize,
> MerkleProof<K, V, 2, H>
{
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    pub fn encode(
        &self,
        block_descriptor: libernet::BlockDescriptor,
    ) -> Result<libernet::MerkleProof> {
        Ok(libernet::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(proto::encode_scalar(self.inner.key().as_scalar())),
            value: Some(self.inner.value().encode_to_any()?),
            path: self
                .compressed_path()
                .iter()
                .map(|hash| libernet::merkle_proof::Node {
                    child_hashes: vec![proto::encode_scalar(*hash)],
                })
                .collect(),
        })
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + DecodeFromAny + 'static,
    const H: usize,
> MerkleProof<K, V, 2, H>
{
    /// Decodes a Merkle proof from the provided protobuf. The `block_descriptor` is ignored. The
    /// resulting proof is not verified (use `decode_and_verify` to decode and verify it).
    pub fn decode(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let key = match &proto.key {
            Some(key) => proto::decode_scalar(key),
            None => Err(anyhow!("invalid Merkle proof: the key is missing")),
        }?;
        let key = K::from_scalar(key)?;
        let value = match &proto.value {
            Some(value) => V::decode_from_any(value),
            None => Err(anyhow!("invalid Merkle proof: the value is missing")),
        }?;
        let path: [Scalar; H] = proto
            .path
            .iter()
            .map(|node| {
                let children = node
                    .child_hashes
                    .iter()
                    .map(proto::decode_scalar)
                    .collect::<Result<Vec<Scalar>>>()?;
                if children.len() != 1 {
                    Err(anyhow!(
                        "invalid Merkle proof: found node with {} sister hashes (expected 1)",
                        children.len()
                    ))
                } else {
                    Ok(children[0])
                }
            })
            .collect::<Result<Vec<Scalar>>>()?
            .try_into()
            .map_err(|vec: Vec<Scalar>| {
                anyhow!(
                    "invalid Merkle proof: incorrect lookup path length (got {}, want {})",
                    vec.len(),
                    H
                )
            })?;
        Ok(Self {
            inner: LowLevelMerkleProof::<K, V, 2, H>::from_compressed(
                key, value, root_hash, &path,
            )?,
        })
    }

    /// Like `decode` but also validates the decoded proof against the provided root hash.
    ///
    /// Note that the root hash should be the same as one of the root hashes specified in the block
    /// descriptor, depending on what storage component this proof is relative to. For example, if
    /// the proof was generated from an account lookup the root hash must be the same as the one
    /// encoded in `block_descriptor.accounts_root_hash`.
    ///
    /// WARNING: this method validates the Merkle proof but NOT the block descriptor! The caller is
    /// still responsible for decoding and hashing the latter and checking that the hash corresponds
    /// to the serialized block hash.
    pub fn decode_and_verify(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let proof = Self::decode(proto, root_hash)?;
        if proof.root_hash() != root_hash {
            return Err(anyhow!(
                "root hash mismatch: got {:#x}, want {:#x}",
                utils::scalar_to_u256(proof.root_hash()),
                utils::scalar_to_u256(root_hash)
            ));
        }
        proof.verify()?;
        Ok(proof)
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> MerkleProof<K, V, 3, H>
{
    pub fn compressed_path(&self) -> [[Scalar; 2]; H] {
        self.inner.compressed_path()
    }

    pub fn verify(&self) -> Result<()> {
        self.inner.verify()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + EncodeToAny + 'static,
    const H: usize,
> MerkleProof<K, V, 3, H>
{
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    pub fn encode(
        &self,
        block_descriptor: libernet::BlockDescriptor,
    ) -> Result<libernet::MerkleProof> {
        Ok(libernet::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(proto::encode_scalar(self.inner.key().as_scalar())),
            value: Some(self.inner.value().encode_to_any()?),
            path: self
                .compressed_path()
                .iter()
                .map(|children| libernet::merkle_proof::Node {
                    child_hashes: vec![
                        proto::encode_scalar(children[0]),
                        proto::encode_scalar(children[1]),
                    ],
                })
                .collect(),
        })
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + DecodeFromAny + 'static,
    const H: usize,
> MerkleProof<K, V, 3, H>
{
    /// Decodes a Merkle proof from the provided protobuf. The `block_descriptor` is ignored. The
    /// resulting proof is not verified (use `decode_and_verify` to decode and verify it).
    pub fn decode(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let key = match &proto.key {
            Some(key) => proto::decode_scalar(key),
            None => Err(anyhow!("invalid Merkle proof: the key is missing")),
        }?;
        let key = K::from_scalar(key)?;
        let value = match &proto.value {
            Some(value) => V::decode_from_any(value),
            None => Err(anyhow!("invalid Merkle proof: the value is missing")),
        }?;
        let path: [[Scalar; 2]; H] = proto
            .path
            .iter()
            .map(|node| {
                node.child_hashes
                    .iter()
                    .map(proto::decode_scalar)
                    .collect::<Result<Vec<_>>>()?
                    .try_into()
                    .map_err(|vec: Vec<Scalar>| {
                        anyhow!(
                            "invalid Merkle proof: found node with {} child hashes (expected 2)",
                            vec.len()
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|vec: Vec<[Scalar; 2]>| {
                anyhow!(
                    "invalid Merkle proof: incorrect lookup path length (got {}, want {})",
                    vec.len(),
                    H
                )
            })?;
        Ok(Self {
            inner: LowLevelMerkleProof::<K, V, 3, H>::from_compressed(
                key, value, root_hash, &path,
            )?,
        })
    }

    /// Like `decode` but also validates the decoded proof against the provided root hash.
    ///
    /// Note that the root hash should be the same as one of the root hashes specified in the block
    /// descriptor, depending on what storage component this proof is relative to. For example, if
    /// the proof was generated from an account lookup the root hash must be the same as the one
    /// encoded in `block_descriptor.accounts_root_hash`.
    ///
    /// WARNING: this method validates the Merkle proof but NOT the block descriptor! The caller is
    /// still responsible for decoding and hashing the latter and check that the hash corresponds to
    /// the block hash. For a more comprehensive validation see one of the other
    /// `decode_and_verify_*` methods.
    pub fn decode_and_verify(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let proof = Self::decode(proto, root_hash)?;
        if proof.root_hash() != root_hash {
            return Err(anyhow!(
                "root hash mismatch: got {:#x}, want {:#x}",
                utils::scalar_to_u256(proof.root_hash()),
                utils::scalar_to_u256(root_hash)
            ));
        }
        proof.verify()?;
        Ok(proof)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTreeVersion<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> {
    root: Arc<dyn Node<K, V, W>>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> MerkleTreeVersion<K, V, W, H>
{
    pub fn from<const N: usize>(entries: [(K, V); N]) -> Self {
        let mut tree = Self::default();
        for (key, value) in entries {
            tree = tree.put(key, value);
        }
        tree
    }

    pub fn root_hash(&self) -> Scalar {
        self.root.as_scalar()
    }

    pub fn get(&self, key: K) -> &V {
        self.root.get(key)
    }

    pub fn get_proof(&self, key: K) -> MerkleProof<K, V, W, H> {
        let (value, path) = self.root.lookup(key);
        MerkleProof::new(
            key,
            value.clone(),
            path.try_into().unwrap(),
            self.root.as_scalar(),
        )
    }

    pub fn put(&self, key: K, value: V) -> Self {
        Self {
            root: self.root.clone().put(key, value),
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> Default for MerkleTreeVersion<K, V, W, H>
{
    fn default() -> Self {
        Self {
            root: PHANTOM_NODES.get::<K, V, W, H>(H),
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> AsScalar for MerkleTreeVersion<K, V, W, H>
{
    fn as_scalar(&self) -> Scalar {
        self.root_hash()
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> EncodeToAny for MerkleTreeVersion<K, V, W, H>
{
    fn encode_to_any(&self) -> Result<prost_types::Any> {
        Ok(prost_types::Any::from_msg(&proto::encode_scalar(
            self.root_hash(),
        ))?)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> {
    versions: BTreeMap<u64, MerkleTreeVersion<K, V, W, H>>,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> MerkleTree<K, V, W, H>
{
    pub fn from<const N: usize>(entries: [(K, V); N]) -> Self {
        Self {
            versions: BTreeMap::from([(0, MerkleTreeVersion::from(entries))]),
        }
    }

    pub fn get_version(&self, version: u64) -> &MerkleTreeVersion<K, V, W, H> {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version
    }

    pub fn root_hash(&self, version: u64) -> Scalar {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version.root_hash()
    }

    pub fn get(&self, key: K, version: u64) -> &V {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version.get(key)
    }

    pub fn get_proof(&self, key: K, version: u64) -> MerkleProof<K, V, W, H> {
        let (_, version) = self.versions.range(0..=version).next_back().unwrap();
        version.get_proof(key)
    }

    pub fn put(&mut self, key: K, value: V, version: u64) {
        let (_, root) = self.versions.range_mut(0..=version).next_back().unwrap();
        let new_root = root.put(key, value);
        if new_root.as_scalar() != root.as_scalar() {
            self.versions.insert(version, new_root);
        }
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Default + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> Default for MerkleTree<K, V, W, H>
{
    fn default() -> Self {
        Self {
            versions: BTreeMap::from([(0, MerkleTreeVersion::default())]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;
    use ff::Field;

    type TestTree = MerkleTree<Scalar, Scalar, 3, 161>;
    type TestProof = MerkleProof<Scalar, Scalar, 3, 161>;

    fn test_scalar1() -> Scalar {
        Scalar::from_bytes_le(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .unwrap()
    }

    fn test_scalar2() -> Scalar {
        Scalar::from_bytes_le(&[
            31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ])
        .unwrap()
    }

    fn test_scalar3() -> Scalar {
        Scalar::from_bytes_le(&[
            32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .unwrap()
    }

    #[test]
    fn test_initial_root_hash() {
        let tree = TestTree::default();
        let hash =
            parse_scalar("0x135e8102d60f086dc416d39a754991573b7a85551a0f06098c847a118cdb9cb5");
        assert_eq!(tree.root_hash(0), hash);
        assert_eq!(tree.root_hash(1), hash);
        assert_eq!(tree.root_hash(2), hash);
    }

    fn test_initial_state(key: Scalar, version: u64) {
        let tree = TestTree::default();
        assert_eq!(*tree.get(key, version), Scalar::ZERO);
        let proof = tree.get_proof(key, version);
        assert_eq!(proof.key(), key);
        assert_eq!(*proof.value(), Scalar::ZERO);
        assert_eq!(proof.root_hash(), tree.root_hash(version));
        assert!(proof.verify().is_ok());
        assert_eq!(proof.take_value(), Scalar::ZERO);
    }

    #[test]
    fn test_initial_state1() {
        let key = test_scalar1();
        test_initial_state(key, 0);
        test_initial_state(key, 1);
        test_initial_state(key, 2);
    }

    #[test]
    fn test_initial_state2() {
        let key = test_scalar2();
        test_initial_state(key, 0);
        test_initial_state(key, 1);
        test_initial_state(key, 2);
    }

    fn test_from_empty(key: Scalar, version: u64) {
        let tree = TestTree::from([]);
        assert_eq!(
            tree.root_hash(version),
            TestTree::default().root_hash(version)
        );
        assert_eq!(*tree.get(key, version), Scalar::ZERO);
        let proof = tree.get_proof(key, version);
        assert_eq!(proof.key(), key);
        assert_eq!(*proof.value(), Scalar::ZERO);
        assert_eq!(proof.root_hash(), tree.root_hash(version));
        assert!(proof.verify().is_ok());
        assert_eq!(proof.take_value(), Scalar::ZERO);
    }

    #[test]
    fn test_from_empty1() {
        let key = test_scalar1();
        test_from_empty(key, 0);
        test_from_empty(key, 1);
        test_from_empty(key, 2);
    }

    #[test]
    fn test_from_empty2() {
        let key = test_scalar2();
        test_from_empty(key, 0);
        test_from_empty(key, 1);
        test_from_empty(key, 2);
    }

    #[test]
    fn test_insert_one() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value = test_scalar3();
        tree.put(key1, value, 0);
        assert_eq!(*tree.get(key1, 0), value);
        assert_eq!(*tree.get(key1, 1), value);
        assert_eq!(*tree.get(key1, 2), value);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(*proof1.value(), value);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(proof1.take_value(), value);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(*proof2.value(), Scalar::ZERO);
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
        assert_eq!(proof2.take_value(), Scalar::ZERO);
    }

    #[test]
    fn test_first_root_hash_change() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let value = test_scalar2();
        let hash1 = tree.root_hash(0);
        tree.put(key1, value, 0);
        let hash2 = tree.root_hash(0);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_from_one_element() {
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value = test_scalar2();
        let tree1 = TestTree::from([(key1, value)]);
        let mut tree2 = TestTree::default();
        tree2.put(key1, value, 0);
        assert_eq!(tree1.root_hash(0), tree2.root_hash(0));
        assert_eq!(tree1.root_hash(0), tree2.root_hash(1));
        assert_eq!(*tree1.get(key1, 0), value);
        assert_eq!(*tree1.get(key1, 1), value);
        assert_eq!(*tree1.get(key1, 2), value);
        let proof1 = tree1.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(*proof1.value(), value);
        assert_eq!(proof1.root_hash(), tree1.root_hash(0));
        assert_eq!(proof1.root_hash(), tree1.root_hash(1));
        assert_eq!(proof1.root_hash(), tree1.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree1.get_proof(key1, 1), proof1);
        assert_eq!(tree1.get_proof(key1, 2), proof1);
        assert_eq!(proof1.take_value(), value);
        assert_eq!(*tree1.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree1.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree1.get(key2, 2), Scalar::ZERO);
        let proof2 = tree1.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(*proof2.value(), Scalar::ZERO);
        assert_eq!(proof2.root_hash(), tree1.root_hash(0));
        assert_eq!(proof2.root_hash(), tree1.root_hash(1));
        assert_eq!(proof2.root_hash(), tree1.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree1.get_proof(key2, 1), proof2);
        assert_eq!(tree1.get_proof(key2, 2), proof2);
        assert_eq!(proof2.take_value(), Scalar::ZERO);
    }

    #[test]
    fn test_insert_two() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1, 0);
        tree.put(key2, value2, 0);
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(*proof1.value(), value1);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(proof1.take_value(), value1);
        assert_eq!(*tree.get(key2, 0), value2);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value2);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(*proof2.value(), value2);
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
        assert_eq!(proof2.take_value(), value2);
    }

    #[test]
    fn test_second_root_hash_change() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1, 0);
        let hash1 = tree.root_hash(0);
        tree.put(key2, value2, 0);
        let hash2 = tree.root_hash(0);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_from_two_elements() {
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        let tree1 = TestTree::from([(key1, value1), (key2, value2)]);
        let mut tree2 = TestTree::default();
        tree2.put(key1, value1.clone(), 0);
        tree2.put(key2, value2.clone(), 0);
        assert_eq!(tree1.root_hash(0), tree2.root_hash(0));
        assert_eq!(tree1.root_hash(0), tree2.root_hash(1));
        assert_eq!(*tree1.get(key1, 0), value1);
        assert_eq!(*tree1.get(key1, 1), value1);
        assert_eq!(*tree1.get(key1, 2), value1);
        let proof1 = tree1.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(*proof1.value(), value1);
        assert_eq!(proof1.root_hash(), tree1.root_hash(0));
        assert_eq!(proof1.root_hash(), tree1.root_hash(1));
        assert_eq!(proof1.root_hash(), tree1.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree1.get_proof(key1, 1), proof1);
        assert_eq!(tree1.get_proof(key1, 2), proof1);
        assert_eq!(proof1.take_value(), value1);
        assert_eq!(*tree1.get(key2, 0), value2);
        assert_eq!(*tree1.get(key2, 1), value2);
        assert_eq!(*tree1.get(key2, 2), value2);
        let proof2 = tree1.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(*proof2.value(), value2);
        assert_eq!(proof2.root_hash(), tree1.root_hash(0));
        assert_eq!(proof2.root_hash(), tree1.root_hash(1));
        assert_eq!(proof2.root_hash(), tree1.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree1.get_proof(key2, 1), proof2);
        assert_eq!(tree1.get_proof(key2, 2), proof2);
        assert_eq!(proof2.take_value(), value2);
    }

    #[test]
    fn test_insert_with_shared_prefix() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(*proof1.value(), value1);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(proof1.take_value(), value1);
        assert_eq!(*tree.get(key2, 0), value2);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value2);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(*proof2.value(), value2);
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
        assert_eq!(proof2.take_value(), value2);
    }

    fn test_insert_three(value1: Scalar, value2: Scalar, value3: Scalar) {
        let mut tree = TestTree::default();
        tree.put(value1, value1.clone(), 0);
        tree.put(value2, value2.clone(), 0);
        tree.put(value3, value3.clone(), 0);
        assert_eq!(*tree.get(value1, 0), value1);
        assert_eq!(*tree.get(value1, 1), value1);
        assert_eq!(*tree.get(value1, 2), value1);
        let proof1 = tree.get_proof(value1, 0);
        assert_eq!(proof1.key(), value1);
        assert_eq!(*proof1.value(), value1);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree.get_proof(value1, 1), proof1);
        assert_eq!(tree.get_proof(value1, 2), proof1);
        assert_eq!(proof1.take_value(), value1);
        assert_eq!(*tree.get(value2, 0), value2);
        assert_eq!(*tree.get(value2, 1), value2);
        assert_eq!(*tree.get(value2, 2), value2);
        let proof2 = tree.get_proof(value2, 0);
        assert_eq!(proof2.key(), value2);
        assert_eq!(*proof2.value(), value2);
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree.get_proof(value2, 1), proof2);
        assert_eq!(tree.get_proof(value2, 2), proof2);
        assert_eq!(proof2.take_value(), value2);
        assert_eq!(*tree.get(value3, 0), value3);
        assert_eq!(*tree.get(value3, 1), value3);
        assert_eq!(*tree.get(value3, 2), value3);
        let proof3 = tree.get_proof(value3, 0);
        assert_eq!(proof3.key(), value3);
        assert_eq!(*proof3.value(), value3);
        assert_eq!(proof3.root_hash(), tree.root_hash(0));
        assert_eq!(proof3.root_hash(), tree.root_hash(1));
        assert_eq!(proof3.root_hash(), tree.root_hash(2));
        assert!(proof3.verify().is_ok());
        assert_eq!(tree.get_proof(value3, 1), proof3);
        assert_eq!(tree.get_proof(value3, 2), proof3);
        assert_eq!(proof3.take_value(), value3);
    }

    #[test]
    fn test_insert_three1() {
        test_insert_three(test_scalar1(), test_scalar2(), test_scalar3());
    }

    #[test]
    fn test_insert_three2() {
        test_insert_three(test_scalar1(), test_scalar3(), test_scalar2());
    }

    #[test]
    fn test_insert_three3() {
        test_insert_three(test_scalar2(), test_scalar1(), test_scalar3());
    }

    #[test]
    fn test_insert_three4() {
        test_insert_three(test_scalar2(), test_scalar3(), test_scalar1());
    }

    #[test]
    fn test_insert_three5() {
        test_insert_three(test_scalar3(), test_scalar1(), test_scalar2());
    }

    #[test]
    fn test_insert_three6() {
        test_insert_three(test_scalar3(), test_scalar2(), test_scalar1());
    }

    #[test]
    fn test_update() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1, 0);
        tree.put(key1, value2.clone(), 0);
        assert_eq!(*tree.get(key1, 0), value2);
        assert_eq!(*tree.get(key1, 1), value2);
        assert_eq!(*tree.get(key1, 2), value2);
        let proof1 = tree.get_proof(key1, 0);
        assert_eq!(proof1.key(), key1);
        assert_eq!(*proof1.value(), value2);
        assert_eq!(proof1.root_hash(), tree.root_hash(0));
        assert_eq!(proof1.root_hash(), tree.root_hash(1));
        assert_eq!(proof1.root_hash(), tree.root_hash(2));
        assert!(proof1.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof1);
        assert_eq!(tree.get_proof(key1, 2), proof1);
        assert_eq!(proof1.take_value(), value2);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof2 = tree.get_proof(key2, 0);
        assert_eq!(proof2.key(), key2);
        assert_eq!(*proof2.value(), Scalar::ZERO);
        assert_eq!(proof2.root_hash(), tree.root_hash(0));
        assert_eq!(proof2.root_hash(), tree.root_hash(1));
        assert_eq!(proof2.root_hash(), tree.root_hash(2));
        assert!(proof2.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof2);
        assert_eq!(tree.get_proof(key2, 2), proof2);
        assert_eq!(proof2.take_value(), Scalar::ZERO);
    }

    #[test]
    fn test_new_version() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key1, value2.clone(), 1);
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value2);
        assert_eq!(*tree.get(key1, 2), value2);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(proof11.key(), key1);
        assert_eq!(*proof11.value(), value1);
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_ne!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify().is_ok());
        assert_eq!(proof11.take_value(), value1);
        let proof12 = tree.get_proof(key1, 1);
        assert_eq!(proof12.key(), key1);
        assert_eq!(*proof12.value(), value2);
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_eq!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 2), proof12);
        assert_eq!(proof12.take_value(), value2);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(proof21.key(), key2);
        assert_eq!(*proof21.value(), Scalar::ZERO);
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_ne!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify().is_ok());
        assert_eq!(proof21.take_value(), Scalar::ZERO);
        let proof22 = tree.get_proof(key2, 1);
        assert_eq!(proof22.key(), key2);
        assert_eq!(*proof22.value(), Scalar::ZERO);
        assert_ne!(proof22.root_hash(), tree.root_hash(0));
        assert_eq!(proof22.root_hash(), tree.root_hash(1));
        assert_eq!(proof22.root_hash(), tree.root_hash(2));
        assert!(proof22.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof22);
        assert_eq!(tree.get_proof(key2, 2), proof22);
        assert_eq!(proof22.take_value(), Scalar::ZERO);
    }

    #[test]
    fn test_skip_version() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key1, value2.clone(), 2);
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value2);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(proof11.key(), key1);
        assert_eq!(*proof11.value(), value1);
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_eq!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify().is_ok());
        let proof12 = tree.get_proof(key1, 2);
        assert_eq!(proof12.key(), key1);
        assert_eq!(*proof12.value(), value2);
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_ne!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof11);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 2), Scalar::ZERO);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(proof21.key(), key2);
        assert_eq!(*proof21.value(), Scalar::ZERO);
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_eq!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify().is_ok());
        let proof22 = tree.get_proof(key2, 2);
        assert_eq!(proof22.key(), key2);
        assert_eq!(*proof22.value(), Scalar::ZERO);
        assert_ne!(proof22.root_hash(), tree.root_hash(0));
        assert_ne!(proof22.root_hash(), tree.root_hash(1));
        assert_eq!(proof22.root_hash(), tree.root_hash(2));
        assert!(proof22.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof21);
    }

    #[test]
    fn test_two_values_across_versions() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key2, value3.clone(), 2);
        assert_eq!(*tree.get(key1, 0), value1);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        let proof11 = tree.get_proof(key1, 0);
        assert_eq!(proof11.key(), key1);
        assert_eq!(*proof11.value(), value1.clone());
        assert_eq!(proof11.root_hash(), tree.root_hash(0));
        assert_eq!(proof11.root_hash(), tree.root_hash(1));
        assert_ne!(proof11.root_hash(), tree.root_hash(2));
        assert!(proof11.verify().is_ok());
        let proof12 = tree.get_proof(key1, 2);
        assert_eq!(proof12.key(), key1);
        assert_eq!(*proof12.value(), value1);
        assert_ne!(proof12.root_hash(), tree.root_hash(0));
        assert_ne!(proof12.root_hash(), tree.root_hash(1));
        assert_eq!(proof12.root_hash(), tree.root_hash(2));
        assert!(proof12.verify().is_ok());
        assert_eq!(tree.get_proof(key1, 1), proof11);
        assert_eq!(*tree.get(key2, 0), value2);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value3);
        let proof21 = tree.get_proof(key2, 0);
        assert_eq!(proof21.key(), key2);
        assert_eq!(*proof21.value(), value2);
        assert_eq!(proof21.root_hash(), tree.root_hash(0));
        assert_eq!(proof21.root_hash(), tree.root_hash(1));
        assert_ne!(proof21.root_hash(), tree.root_hash(2));
        assert!(proof21.verify().is_ok());
        let proof22 = tree.get_proof(key2, 2);
        assert_eq!(proof22.key(), key2);
        assert_eq!(*proof22.value(), value3);
        assert_ne!(proof22.root_hash(), tree.root_hash(0));
        assert_ne!(proof22.root_hash(), tree.root_hash(1));
        assert_eq!(proof22.root_hash(), tree.root_hash(2));
        assert!(proof22.verify().is_ok());
        assert_eq!(tree.get_proof(key2, 1), proof21);
    }

    #[test]
    fn test_transcode_proof() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let proto = proof
            .encode(libernet::BlockDescriptor {
                block_hash: None,
                chain_id: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                transactions_root_hash: None,
                accounts_root_hash: Some(proto::encode_scalar(tree.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        assert_eq!(TestProof::decode(&proto, tree.root_hash(0)).unwrap(), proof);
    }

    #[test]
    fn test_decode_and_verify_proof() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let proto = proof
            .encode(libernet::BlockDescriptor {
                block_hash: None,
                chain_id: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                transactions_root_hash: None,
                accounts_root_hash: Some(proto::encode_scalar(tree.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        assert_eq!(
            TestProof::decode_and_verify(&proto, tree.root_hash(0)).unwrap(),
            proof
        );
    }

    #[test]
    fn test_decode_sabotaged_proof() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(libernet::BlockDescriptor {
                block_hash: None,
                chain_id: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                transactions_root_hash: None,
                accounts_root_hash: Some(proto::encode_scalar(tree.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.path[123].child_hashes[0] = proto::encode_scalar(Scalar::ZERO);
        assert!(TestProof::decode_and_verify(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_decode_and_verify_sabotaged_proof() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(libernet::BlockDescriptor {
                block_hash: None,
                chain_id: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                transactions_root_hash: None,
                accounts_root_hash: Some(proto::encode_scalar(tree.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.path[123].child_hashes[0] = proto::encode_scalar(Scalar::ZERO);
        assert!(TestProof::decode_and_verify(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_decode_invalid_proof() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        let proof = tree.get_proof(key2, 0);
        let mut proto = proof
            .encode(libernet::BlockDescriptor {
                block_hash: None,
                chain_id: None,
                block_number: None,
                previous_block_hash: None,
                timestamp: None,
                network_topology_root_hash: None,
                transactions_root_hash: None,
                accounts_root_hash: Some(proto::encode_scalar(tree.root_hash(0))),
                program_storage_root_hash: None,
            })
            .unwrap();
        proto.value = None;
        assert!(TestProof::decode(&proto, tree.root_hash(0)).is_err());
    }

    #[test]
    fn test_past_modification() {
        let mut tree = TestTree::default();
        let key1 = test_scalar1();
        let key2 = test_scalar2();
        let key3 = test_scalar3();
        let value1 = test_scalar2();
        let value2 = test_scalar3();
        let value3 = test_scalar1();
        tree.put(key1, value1.clone(), 0);
        tree.put(key2, value2.clone(), 1);
        tree.put(key1, value3.clone(), 0);
        tree.put(key3, value3.clone(), 0);
        assert_eq!(*tree.get(key1, 0), value3);
        assert_eq!(*tree.get(key1, 1), value1);
        assert_eq!(*tree.get(key1, 2), value1);
        assert_eq!(*tree.get(key2, 0), Scalar::ZERO);
        assert_eq!(*tree.get(key2, 1), value2);
        assert_eq!(*tree.get(key2, 2), value2);
        assert_eq!(*tree.get(key3, 0), value3);
        assert_eq!(*tree.get(key3, 1), Scalar::ZERO);
        assert_eq!(*tree.get(key3, 2), Scalar::ZERO);
    }
}
