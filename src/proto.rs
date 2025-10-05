use crate::libernet;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use crypto::utils;
use primitive_types::{H256, H384, H768, U256};

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
liber_proto_name!(libernet::Scalar, "Scalar");
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

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
