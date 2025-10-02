use crate::libernet;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use crypto::utils;

#[derive(Debug)]
pub struct Account {
    inner: crypto::account::Account,
}

impl Account {
    pub fn new(inner: crypto::account::Account) -> Self {
        Self { inner }
    }

    pub fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> Result<(prost_types::Any, libernet::Signature)> {
        let (payload, bytes) = proto::encode_message_canonical(message)?;
        let signature = self.inner.bls_sign(bytes.as_slice());
        Ok((
            payload,
            libernet::Signature {
                signer: Some(proto::encode_scalar(self.inner.address())),
                public_key: Some(proto::encode_g1(self.inner.public_key())),
                signature: Some(proto::encode_g2(signature)),
            },
        ))
    }

    pub fn verify_signed_message(
        payload: &prost_types::Any,
        signature: &libernet::Signature,
    ) -> Result<()> {
        let public_key = proto::decode_g1(
            signature
                .public_key
                .as_ref()
                .context("missing public key field")?,
        )?;
        let signer_address =
            proto::decode_scalar(signature.signer.as_ref().context("missing signer field")?)?;
        if utils::hash_g1_to_scalar(public_key) != signer_address {
            return Err(anyhow!("invalid signature: public key mismatch"));
        }
        let signature = proto::decode_g2(
            signature
                .signature
                .as_ref()
                .context("missing signature field")?,
        )?;
        let payload = proto::encode_any_canonical(&payload);
        crypto::account::Account::bls_verify(public_key, payload.as_slice(), signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
