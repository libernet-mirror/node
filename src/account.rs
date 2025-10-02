use crate::libernet;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use crypto::{account::Account as LowLevelAccount, utils};

#[derive(Debug)]
pub struct Account {
    inner: LowLevelAccount,
}

impl Account {
    pub fn new(inner: LowLevelAccount) -> Self {
        Self { inner }
    }

    pub fn from_private_key(private_key: Scalar) -> Self {
        Self {
            inner: LowLevelAccount::new(private_key),
        }
    }

    pub fn public_key(&self) -> G1Affine {
        self.inner.public_key()
    }

    pub fn address(&self) -> Scalar {
        self.inner.address()
    }

    pub fn bls_sign(&self, message: &[u8]) -> G2Affine {
        self.inner.bls_sign(message)
    }

    pub fn bls_verify(public_key: G1Affine, message: &[u8], signature: G2Affine) -> Result<()> {
        LowLevelAccount::bls_verify(public_key, message, signature)
    }

    pub fn bls_verify_own(&self, message: &[u8], signature: G2Affine) -> Result<()> {
        self.inner.bls_verify_own(message, signature)
    }

    pub fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> Result<(prost_types::Any, libernet::Signature)> {
        let (payload, bytes) = proto::encode_message_canonical(message)?;
        let signature = self.bls_sign(bytes.as_slice());
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
        Self::bls_verify(public_key, payload.as_slice(), signature)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub fn account1() -> Account {
        Account::new(LowLevelAccount::new(
            utils::parse_scalar(
                "0x0b0276914bf0f850d27771adb1abb62b2674e041b63c86c8cd0d7520355ae7c0",
            )
            .unwrap(),
        ))
    }

    pub fn account2() -> Account {
        Account::new(LowLevelAccount::new(
            utils::parse_scalar(
                "0x0fc56ce55997c46f1ba0bce9a8a4daead405c29edf4066a2cd7d0419f592392b",
            )
            .unwrap(),
        ))
    }

    pub fn account3() -> Account {
        Account::new(LowLevelAccount::new(
            utils::parse_scalar(
                "0x2417c832ac8f3f2e773d8e01eb9fe12e5349a7bfeff44b15d1b15b06e8c1176f",
            )
            .unwrap(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::H256;

    #[test]
    fn test_account1() {
        let account = testing::account1();
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x971a30a286a15f62f9b93b4444851051ca102dd62a1adf63f16ae1e721934c1adfb611eadd71ebb81f2bbba11e9fa7e6")
                .unwrap()
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x33bae89b460efdef119f92c722a4e7c25003310cdcbdb9aa696e7bf37539882f"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_account2() {
        let account = testing::account2();
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0xb7903cbd05093082918179fbdd250629a86be67ad069c0f0c2b5c7f5f299ba38680de9b60333504434e5acc096d66a58")
                .unwrap()
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x69c22a50555cff3bda736d8a5e7e658a73e59da13173395135a3135883d043c1"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_account3() {
        let account = testing::account3();
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0xa4e3a32b90c771d93ab3f78582e823dbf31e55a7e898223bd1a5cad15b0393574deb1c05131bbe946875a443b3b1f7de")
                .unwrap()
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x50215682c436f03f0bdc903061e2ff3f01ed6452433a2fdfb6d167418a00a398"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_bls_signature() {
        let account = Account::from_private_key(utils::get_random_scalar());
        let message = b"Hello, world!";
        let signature = account.bls_sign(message);
        assert!(Account::bls_verify(account.public_key(), message, signature).is_ok());
        assert!(account.bls_verify_own(message, signature).is_ok());
    }

    #[test]
    fn test_wrong_bls_signature() {
        let account = Account::from_private_key(utils::get_random_scalar());
        let signature = account.bls_sign(b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(Account::bls_verify(account.public_key(), wrong_message, signature).is_err());
        assert!(account.bls_verify_own(wrong_message, signature).is_err());
    }

    fn test_message_signature(account: &Account) {
        let message = proto::encode_h256(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, signature) = account.sign_message(&message).unwrap();
        assert!(Account::verify_signed_message(&any, &signature).is_ok());
    }

    #[test]
    fn test_message_signature1() {
        test_message_signature(&testing::account1());
    }

    #[test]
    fn test_message_signature2() {
        test_message_signature(&testing::account2());
    }

    #[test]
    fn test_message_signature3() {
        test_message_signature(&testing::account3());
    }

    #[test]
    fn test_message_signature_wrong_message() {
        let account = testing::account1();
        let message1 = proto::encode_h256(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (_, signature) = account.sign_message(&message1).unwrap();
        let message2 = proto::encode_h256(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 32, 31, 30,
        ]));
        let any2 = prost_types::Any::from_msg(&message2).unwrap();
        assert!(Account::verify_signed_message(&any2, &signature).is_err());
    }

    #[test]
    fn test_message_signature_wrong_public_key() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let message = proto::encode_h256(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, mut signature) = account1.sign_message(&message).unwrap();
        signature.public_key = Some(proto::encode_g1(account2.public_key()));
        signature.signer = Some(proto::encode_scalar(account2.address()));
        assert!(Account::verify_signed_message(&any, &signature).is_err());
    }

    #[test]
    fn test_message_signature_wrong_signer_address() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let message = proto::encode_h256(H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]));
        let (any, mut signature) = account1.sign_message(&message).unwrap();
        signature.signer = Some(proto::encode_scalar(account2.address()));
        assert!(Account::verify_signed_message(&any, &signature).is_err());
    }
}
