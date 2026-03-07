use crate::libernet;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use crypto::{merkle, utils};
use primitive_types::{H256, H384, H768, U256};
use std::fmt::Debug;

const MAX_VARINT_LENGTH: usize = 10;

/// Defines the `prost::Name` impl for the given proto using predefined domain and package names
/// (respectively "type.libernet.org" and "libernet").
///
/// Example:
///
///   // The following results in `type.libernet.org/libernet.Scalar`.
///   liber_proto_name!(libernet::Scalar, "Scalar");
///
macro_rules! liber_proto_name {
    ($type:path, $name:expr) => {
        impl prost::Name for $type {
            const NAME: &str = $name;
            const PACKAGE: &str = "libernet";

            fn full_name() -> String {
                format!("{}.{}", Self::PACKAGE, Self::NAME)
            }

            fn type_url() -> String {
                format!("type.libernet.org/{}", Self::full_name())
            }
        }
    };
}

liber_proto_name!(libernet::AccountInfo, "AccountInfo");
liber_proto_name!(libernet::BlockDescriptor, "BlockDescriptor");
liber_proto_name!(libernet::MerkleProof, "MerkleProof");
liber_proto_name!(libernet::Scalar, "Scalar");
liber_proto_name!(libernet::Transaction, "Transaction");
liber_proto_name!(libernet::node_identity::Payload, "NodeIdentity.Payload");
liber_proto_name!(libernet::transaction::Payload, "Transaction.Payload");

/// Makes a type encodable to `google.protobuf.Any`.
pub trait EncodeToAny: Sized {
    fn encode_to_any(&self) -> Result<prost_types::Any>;
}

impl EncodeToAny for Scalar {
    fn encode_to_any(&self) -> Result<prost_types::Any> {
        Ok(prost_types::Any::from_msg(&encode_scalar(*self))?)
    }
}

impl EncodeToAny for u64 {
    fn encode_to_any(&self) -> Result<prost_types::Any> {
        Ok(prost_types::Any::from_msg(&encode_scalar(Scalar::from(
            *self,
        )))?)
    }
}

/// Makes a type decodable from `google.protobuf.Any`.
pub trait DecodeFromAny: Sized {
    fn decode_from_any(proto: &prost_types::Any) -> Result<Self>;
}

impl DecodeFromAny for Scalar {
    fn decode_from_any(proto: &prost_types::Any) -> Result<Self> {
        decode_scalar(&proto.to_msg()?)
    }
}

impl DecodeFromAny for u64 {
    fn decode_from_any(proto: &prost_types::Any) -> Result<Self> {
        let scalar = decode_scalar(&proto.to_msg()?)?;
        let scalar = utils::scalar_to_u256(scalar);
        Ok(scalar.as_u64())
    }
}

pub fn encode_u256(value: U256) -> libernet::Scalar {
    libernet::Scalar {
        value: Some(value.to_little_endian().to_vec()),
    }
}

pub fn decode_u256(proto: &libernet::Scalar) -> Result<U256> {
    if let Some(bytes) = &proto.value {
        if bytes.len() > 32 {
            Err(anyhow!("invalid U256 encoding"))
        } else if bytes.len() < 32 {
            let mut padded = [0u8; 32];
            padded.copy_from_slice(bytes.as_slice());
            Ok(U256::from_little_endian(&padded))
        } else {
            Ok(U256::from_little_endian(&bytes))
        }
    } else {
        Ok(0.into())
    }
}

pub fn encode_scalar(value: Scalar) -> libernet::Scalar {
    encode_u256(utils::scalar_to_u256(value))
}

pub fn decode_scalar(proto: &libernet::Scalar) -> Result<Scalar> {
    utils::u256_to_scalar(decode_u256(proto)?)
}

pub fn encode_h256(value: H256) -> libernet::Scalar {
    libernet::Scalar {
        value: Some(value.to_fixed_bytes().to_vec()),
    }
}

pub fn decode_h256(proto: &libernet::Scalar) -> Result<H256> {
    if let Some(bytes) = &proto.value {
        if bytes.len() == 32 {
            return Ok(H256::from_slice(&bytes));
        }
    }
    Err(anyhow!("invalid H256 encoding"))
}

pub fn encode_g1(point: G1Affine) -> libernet::PointG1 {
    libernet::PointG1 {
        compressed_bytes: Some(utils::compress_g1(point).to_fixed_bytes().to_vec()),
    }
}

pub fn decode_g1(proto: &libernet::PointG1) -> Result<G1Affine> {
    if let Some(bytes) = &proto.compressed_bytes {
        utils::decompress_g1(H384::from_slice(bytes))
    } else {
        Err(anyhow!("invalid G1 point"))
    }
}

pub fn encode_g2(point: G2Affine) -> libernet::PointG2 {
    libernet::PointG2 {
        compressed_bytes: Some(utils::compress_g2(point).to_fixed_bytes().to_vec()),
    }
}

pub fn decode_g2(proto: &libernet::PointG2) -> Result<G2Affine> {
    if let Some(bytes) = &proto.compressed_bytes {
        utils::decompress_g2(H768::from_slice(bytes))
    } else {
        Err(anyhow!("invalid G2 point"))
    }
}

fn encode_varint(buffer: &mut Vec<u8>, mut value: usize) {
    while value > 0x7F {
        buffer.push(0x80 | (value & 0x7F) as u8);
        value >>= 7;
    }
    buffer.push((value & 0x7F) as u8);
}

pub fn encode_any_canonical(any: &prost_types::Any) -> Vec<u8> {
    let type_url_bytes = any.type_url.as_bytes();
    let value_bytes = any.value.as_slice();
    let mut buffer = Vec::<u8>::with_capacity(
        (1 + MAX_VARINT_LENGTH) * 2 + type_url_bytes.len() + value_bytes.len(),
    );
    buffer.push(10);
    encode_varint(&mut buffer, type_url_bytes.len());
    buffer.extend_from_slice(type_url_bytes);
    buffer.push(18);
    encode_varint(&mut buffer, value_bytes.len());
    buffer.extend_from_slice(value_bytes);
    buffer
}

pub fn encode_message_canonical<M: prost::Message + prost::Name>(
    message: &M,
) -> Result<(prost_types::Any, Vec<u8>)> {
    let any = prost_types::Any::from_msg(message)?;
    let buffer = encode_any_canonical(&any);
    Ok((any, buffer))
}

pub trait EncodeMerkleProof<
    K: Debug + Copy + Send + Sync + merkle::FromScalar + merkle::AsScalar + 'static,
    V: Debug + Clone + Send + Sync + merkle::AsScalar + EncodeToAny + 'static,
    const W: usize,
    const H: usize,
>
{
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    fn encode(&self, block_descriptor: libernet::BlockDescriptor) -> Result<libernet::MerkleProof>;
}

impl<
    K: Debug + Copy + Send + Sync + merkle::FromScalar + merkle::AsScalar + 'static,
    V: Debug + Clone + Send + Sync + merkle::AsScalar + EncodeToAny + 'static,
    const H: usize,
> EncodeMerkleProof<K, V, 2, H> for merkle::Proof<K, V, 2, H>
{
    fn encode(&self, block_descriptor: libernet::BlockDescriptor) -> Result<libernet::MerkleProof> {
        Ok(libernet::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(encode_scalar(self.key().as_scalar())),
            value: Some(self.value().encode_to_any()?),
            path: self
                .compressed_path()
                .into_iter()
                .map(|hash| libernet::merkle_proof::Node {
                    child_hashes: vec![encode_scalar(hash)],
                })
                .collect(),
        })
    }
}

impl<
    K: Debug + Copy + Send + Sync + merkle::FromScalar + merkle::AsScalar + 'static,
    V: Debug + Clone + Send + Sync + merkle::AsScalar + EncodeToAny + 'static,
    const H: usize,
> EncodeMerkleProof<K, V, 3, H> for merkle::Proof<K, V, 3, H>
{
    /// Encodes this proof into a `MerkleProof` protobuf. Note that the block descriptor must be
    /// provided by the caller.
    fn encode(&self, block_descriptor: libernet::BlockDescriptor) -> Result<libernet::MerkleProof> {
        Ok(libernet::MerkleProof {
            block_descriptor: Some(block_descriptor),
            key: Some(encode_scalar(self.key().as_scalar())),
            value: Some(self.value().encode_to_any()?),
            path: self
                .compressed_path()
                .into_iter()
                .map(|children| libernet::merkle_proof::Node {
                    child_hashes: vec![encode_scalar(children[0]), encode_scalar(children[1])],
                })
                .collect(),
        })
    }
}

pub trait DecodeMerkleProof<
    K: Debug + Copy + Send + Sync + merkle::FromScalar + merkle::AsScalar + 'static,
    V: Debug + Clone + Send + Sync + merkle::AsScalar + DecodeFromAny + 'static,
    const W: usize,
    const H: usize,
>: Sized
{
    /// Decodes a Merkle proof from the provided protobuf. The `block_descriptor` is ignored. The
    /// resulting proof is not verified (use `decode_and_verify` to decode and verify it).
    fn decode(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self>;

    /// Like `decode` but also validates the decoded proof against the provided root hash.
    ///
    /// Note that the root hash should be equal to one of the root hashes specified in the block
    /// descriptor, depending on what storage component this proof is relative to. For example, if
    /// the proof was generated from an account lookup the root hash must be equal to
    /// `block_descriptor.accounts_root_hash`.
    ///
    /// WARNING: this method validates the Merkle proof but NOT the block descriptor! The caller is
    /// still responsible for decoding and hashing the latter and checking that the hash corresponds
    /// to the serialized block hash.
    fn decode_and_verify(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self>;
}

impl<
    K: Debug + Copy + Send + Sync + merkle::FromScalar + merkle::AsScalar + 'static,
    V: Debug + Clone + Send + Sync + merkle::AsScalar + DecodeFromAny + 'static,
    const H: usize,
> DecodeMerkleProof<K, V, 2, H> for merkle::Proof<K, V, 2, H>
{
    fn decode(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let key = match &proto.key {
            Some(key) => decode_scalar(key),
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
                    .map(decode_scalar)
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
        Ok(Self::from_compressed(key, value, root_hash, &path)?)
    }

    fn decode_and_verify(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
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
    K: Debug + Copy + Send + Sync + merkle::FromScalar + merkle::AsScalar + 'static,
    V: Debug + Clone + Send + Sync + merkle::AsScalar + DecodeFromAny + 'static,
    const H: usize,
> DecodeMerkleProof<K, V, 3, H> for merkle::Proof<K, V, 3, H>
{
    fn decode(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
        let key = match &proto.key {
            Some(key) => decode_scalar(key),
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
                    .map(decode_scalar)
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
        Ok(Self::from_compressed(key, value, root_hash, &path)?)
    }

    fn decode_and_verify(proto: &libernet::MerkleProof, root_hash: Scalar) -> Result<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;
    use blstrs::{G1Projective, G2Projective};
    use crypto::poseidon;
    use group::Group;
    use prost::Message;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_scalar_encoding_to_any() {
        let value = utils::get_random_scalar();
        let encoded = value.encode_to_any().unwrap();
        assert_eq!(Scalar::decode_from_any(&encoded).unwrap(), value);
    }

    fn test_u64_encoding(value: u64) {
        let encoded = value.encode_to_any().unwrap();
        assert_eq!(u64::decode_from_any(&encoded).unwrap(), value);
    }

    #[test]
    fn test_u64_encoding1() {
        test_u64_encoding(123);
    }

    #[test]
    fn test_u64_encoding2() {
        test_u64_encoding(456);
    }

    #[test]
    fn test_scalar_encoding() {
        let value = utils::get_random_scalar();
        let encoded = encode_scalar(value);
        assert_eq!(decode_scalar(&encoded).unwrap(), value);
    }

    #[test]
    fn test_u256_encoding() {
        let value = utils::scalar_to_u256(utils::get_random_scalar());
        let encoded = encode_u256(value);
        assert_eq!(decode_u256(&encoded).unwrap(), value);
    }

    #[test]
    fn test_h256_encoding() {
        let u256 = utils::scalar_to_u256(utils::get_random_scalar());
        let h256 = H256::from_slice(&u256.to_little_endian());
        let encoded = encode_h256(h256);
        assert_eq!(decode_h256(&encoded).unwrap(), h256);
    }

    #[test]
    fn test_g1_point_encoding() {
        let point = (G1Projective::generator() * utils::get_random_scalar()).into();
        let encoded = encode_g1(point);
        assert_eq!(decode_g1(&encoded).unwrap(), point);
    }

    #[test]
    fn test_g2_point_encoding() {
        let point = (G2Projective::generator() * utils::get_random_scalar()).into();
        let encoded = encode_g2(point);
        assert_eq!(decode_g2(&encoded).unwrap(), point);
    }

    #[test]
    fn test_encode_any_canonical() {
        let chain_id = 42;
        let block_number = 123;
        let previous_block_hash = utils::get_random_scalar();
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(71104);
        let network_topology_root_hash = utils::get_random_scalar();
        let transactions_root_hash = utils::get_random_scalar();
        let accounts_root_hash = utils::get_random_scalar();
        let program_storage_root_hash = utils::get_random_scalar();
        let block_hash = poseidon::hash_t4(&[
            chain_id.into(),
            block_number.into(),
            previous_block_hash,
            timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .into(),
            network_topology_root_hash,
            transactions_root_hash,
            accounts_root_hash,
            program_storage_root_hash,
        ]);
        let block_descriptor = libernet::BlockDescriptor {
            block_hash: Some(encode_scalar(block_hash)),
            chain_id: Some(chain_id),
            block_number: Some(block_number),
            previous_block_hash: Some(encode_scalar(previous_block_hash)),
            timestamp: Some(timestamp.into()),
            network_topology_root_hash: Some(encode_scalar(network_topology_root_hash)),
            transactions_root_hash: Some(encode_scalar(transactions_root_hash)),
            accounts_root_hash: Some(encode_scalar(accounts_root_hash)),
            program_storage_root_hash: Some(encode_scalar(program_storage_root_hash)),
        };
        let (any, bytes) = encode_message_canonical(&block_descriptor).unwrap();
        assert_eq!(prost_types::Any::decode(bytes.as_slice()).unwrap(), any);
        assert_eq!(
            any.to_msg::<libernet::BlockDescriptor>().unwrap(),
            block_descriptor
        );
    }

    fn test_encode_binary_merkle_proof_h1(key: u64) {
        let values = [
            parse_scalar("0x66d4182752f9afc3bbbb5394867e3fe6012794b2eadd1f35906ddae4616c8ca8"),
            parse_scalar("0x6597780566d518710d41667b44e4bf450c4c4d0581a12832d737fbff1505ef8a"),
        ];
        let root_hash =
            parse_scalar("0x4a36f288525ffe7d6cebda4b7c3983acb69c3e52bd24b14dd1a82cc98aea8d14");
        let proof = merkle::Proof::<Scalar, Scalar, 2, 1>::new(
            key.into(),
            values[key as usize],
            [values],
            root_hash,
        );
        let encoded = proof.encode(libernet::BlockDescriptor::default()).unwrap();
        let decoded = merkle::Proof::<Scalar, Scalar, 2, 1>::decode(&encoded, root_hash).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded, proof);
        assert_eq!(
            merkle::Proof::<Scalar, Scalar, 2, 1>::decode_and_verify(&encoded, root_hash).unwrap(),
            proof
        );
    }

    #[test]
    fn test_encode_binary_merkle_proof_h1_0() {
        test_encode_binary_merkle_proof_h1(0);
    }

    #[test]
    fn test_encode_binary_merkle_proof_h1_1() {
        test_encode_binary_merkle_proof_h1(1);
    }

    #[test]
    fn test_encode_binary_merkle_proof_h2() {
        let value3 =
            parse_scalar("0x2df0f079053f216dab8b765c3df683e71ed7364aa4c646907be95fea7ec5f84f");
        let value4 =
            parse_scalar("0x49c5f76f883b58566c86e91ef5ea06d2e7bd7fdf0c528aa1b5d7f90053812453");
        let hash1 =
            parse_scalar("0x52436e08f070cbc8d2146ca7cbbe2a87ac8680a9875e143349131e8aff0f7ee2");
        let hash2 =
            parse_scalar("0x42616745af33a422e572db14a8fe697e30a268e585dd2b7a05933da6475eef3b");
        let root_hash =
            parse_scalar("0x07ba33f3208a37cac1ba578b96959e330fa68e5cba17b1fc2abc8772c39b4c4e");
        let proof = merkle::Proof::<Scalar, Scalar, 2, 2>::new(
            2.into(),
            value3,
            [[value3, value4], [hash1, hash2]],
            root_hash,
        );
        let encoded = proof.encode(libernet::BlockDescriptor::default()).unwrap();
        let decoded = merkle::Proof::<Scalar, Scalar, 2, 2>::decode(&encoded, root_hash).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded, proof);
        assert_eq!(
            merkle::Proof::<Scalar, Scalar, 2, 2>::decode_and_verify(&encoded, root_hash).unwrap(),
            proof
        );
    }

    fn test_encode_ternary_merkle_proof_h1(key: u64) {
        let values = [
            parse_scalar("0x511b2a31257a1b3b593d23472e9c5d117e6a6b738f9bce8502afdbd3ad923d1d"),
            parse_scalar("0x186e3b31996e667b3af1a59cd45e08469a31f2cf98411d0aea1cfe6fdbed1d70"),
            parse_scalar("0x335d220a350a44a1649619c36495eab6e33cf6ee431c8b227961aa5b08c96900"),
        ];
        let root_hash =
            parse_scalar("0x7156ea185fde0156d3d4ad12406c51ca9564ab0a0d46d5a3f3044e3c3457dc57");
        let proof = merkle::Proof::<Scalar, Scalar, 3, 1>::new(
            key.into(),
            values[key as usize],
            [values],
            root_hash,
        );
        let encoded = proof.encode(libernet::BlockDescriptor::default()).unwrap();
        let decoded = merkle::Proof::<Scalar, Scalar, 3, 1>::decode(&encoded, root_hash).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded, proof);
        assert_eq!(
            merkle::Proof::<Scalar, Scalar, 3, 1>::decode_and_verify(&encoded, root_hash).unwrap(),
            proof
        );
    }

    #[test]
    fn test_encode_ternary_merkle_proof_h1_0() {
        test_encode_ternary_merkle_proof_h1(0);
    }

    #[test]
    fn test_encode_ternary_merkle_proof_h1_1() {
        test_encode_ternary_merkle_proof_h1(1);
    }

    #[test]
    fn test_encode_ternary_merkle_proof_h1_2() {
        test_encode_ternary_merkle_proof_h1(2);
    }

    #[test]
    fn test_encode_ternary_merkle_proof_h2() {
        let level0 = [
            parse_scalar("0x335005b5d899cce461a65cd86b83e122afdc62023c934466b9804b1bab75a0b1"),
            parse_scalar("0x0b70eb2412c1b19d933581e1cf5babbdc3497296bdf561157cb0c7a83f68e32e"),
            parse_scalar("0x333ae6f755f4bfe7b165c596b79d80789f70a445235aba84433c127c2bfc7248"),
        ];
        let level1 = [
            parse_scalar("0x41778515eb8aa9d4a137ace6dae03b011b54389e1cdfd9fa1aec7e56c2ce5df6"),
            parse_scalar("0x64f6bd1c599ee76f935ef42debaf58cd05f23da845b54956bac4aa2cc1efba80"),
            parse_scalar("0x317f0d49c77992c3fbfeee6acd5f43300ddb3069fe529df41a7aed02dee09ee1"),
        ];
        let root_hash =
            parse_scalar("0x397ff978b40dec0fe3330380d5a4dbb7ba430fb8cc544bdec77b6a0f2ed0c187");
        let proof = merkle::Proof::<Scalar, Scalar, 3, 2>::new(
            5.into(),
            level0[2],
            [level0, level1],
            root_hash,
        );
        let encoded = proof.encode(libernet::BlockDescriptor::default()).unwrap();
        let decoded = merkle::Proof::<Scalar, Scalar, 3, 2>::decode(&encoded, root_hash).unwrap();
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded, proof);
        assert_eq!(
            merkle::Proof::<Scalar, Scalar, 3, 2>::decode_and_verify(&encoded, root_hash).unwrap(),
            proof
        );
    }
}
