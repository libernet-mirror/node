use crate::libernet;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use crypto::{
    account::Account as LowLevelAccount,
    bls,
    remote::PartialRemoteAccount,
    signer::{BlsVerifier, EcDsaVerifier, Ed25519Verifier, Signer},
    utils,
};
use curve25519_dalek::EdwardsPoint as Point25519;
use p256::AffinePoint as PointP256;
use primitive_types::H512;
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::SystemTime;
use zeroize::Zeroizing;

/// A Libernet account with an associated BLS keypair, account address, and ephemeral
/// ECDSA / Ed25519 keypairs for generating TLS certificates.
#[derive(Debug)]
pub struct Account {
    inner: LowLevelAccount,
    ecdsa_public_key_bytes: Vec<u8>,
    ed25519_public_key_bytes: Vec<u8>,
}

impl Account {
    pub fn new(inner: LowLevelAccount) -> Result<Self> {
        let ecdsa_public_key_bytes = utils::compress_p256(inner.ecdsa_public_key())
            .as_fixed_bytes()
            .to_vec();
        let ed25519_public_key_bytes = utils::compress_point_25519(inner.ed25519_public_key())
            .as_fixed_bytes()
            .to_vec();
        Ok(Self {
            inner,
            ecdsa_public_key_bytes,
            ed25519_public_key_bytes,
        })
    }

    pub fn from_secret_key(secret_key: H512) -> Result<Self> {
        Self::new(LowLevelAccount::new(secret_key)?)
    }

    pub fn address(&self) -> Scalar {
        self.inner.address()
    }

    pub fn public_key(&self) -> G1Affine {
        self.inner.public_key()
    }

    pub fn ecdsa_public_key(&self) -> PointP256 {
        self.inner.ecdsa_public_key()
    }

    pub fn export_ecdsa_private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.inner.export_ecdsa_private_key_der()
    }

    pub fn ed25519_public_key(&self) -> Point25519 {
        self.inner.ed25519_public_key()
    }

    pub fn export_ed25519_private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.inner.export_ed25519_private_key_der()
    }

    pub fn bls_sign(&self, message: &[u8]) -> G2Affine {
        self.inner.bls_sign(message)
    }

    pub fn bls_verify(public_key: G1Affine, message: &[u8], signature: G2Affine) -> Result<()> {
        bls::verify(public_key, message, signature)
    }

    pub fn bls_verify_own(&self, message: &[u8], signature: G2Affine) -> Result<()> {
        self.inner.bls_verify(message, signature)
    }

    pub fn generate_ecdsa_certificate(
        &self,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<Vec<u8>> {
        self.inner.generate_ecdsa_certificate(not_before, not_after)
    }

    pub fn generate_ed25519_certificate(
        &self,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<Vec<u8>> {
        self.inner
            .generate_ed25519_certificate(not_before, not_after)
    }

    pub fn verify_ssl_certificate(der: &[u8], now: SystemTime) -> Result<PartialRemoteAccount> {
        LowLevelAccount::verify_ssl_certificate(der, now)
    }

    pub fn generate_ed25519_certified_key(
        &self,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<Arc<CertifiedKey>> {
        let certificate = self.generate_ed25519_certificate(not_before, not_after)?;
        let private_key = self.export_ed25519_private_key_der()?;
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&private_key.as_slice().into())?;
        Ok(Arc::new(CertifiedKey::new(
            vec![certificate.into()],
            signing_key,
        )))
    }

    pub fn generate_ecdsa_certified_key(
        &self,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<Arc<CertifiedKey>> {
        let certificate = self.generate_ecdsa_certificate(not_before, not_after)?;
        let private_key = self.export_ecdsa_private_key_der()?;
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(private_key.as_slice().into()),
        )?;
        Ok(Arc::new(CertifiedKey::new(
            vec![certificate.into()],
            signing_key,
        )))
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
        bls::verify(public_key, payload.as_slice(), signature)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub fn account1() -> Account {
        Account::new(
            LowLevelAccount::new(
                "0x4191f15fdee5d58d9e829c72da3ff838a707a3e798e0cd67348dbdc628ad1565381456e6acde30debd3054224d3f684a8262550c5abc757d2dd4be979151997d"
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    pub fn account2() -> Account {
        Account::new(
            LowLevelAccount::new(
                "0xac363bfd648af099278f7bc694633713999eb1089c33ef144496d52c9ee41d70b4503dac4448ad234747f3553fb4040c29cdf842f251cf116795dcd72be51ddc"
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    pub fn account3() -> Account {
        Account::new(
            LowLevelAccount::new(
                "0xbee4977e23fd5a077def6fe641ebcf0c876484ff32b62095df046398c77eb93ab22161ccf87f3b9e1915a41578badafdce4f6608fdf6f9aafd02a11d13b4780d"
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::H256;
    use std::time::Duration;

    #[test]
    fn test_account1() {
        let account = testing::account1();
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x28fe947cabf1257baba35b31ba1f1ae837d20c4b0dbcf15b23c5e2afa7d0e369"
            )
            .unwrap()
        );
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0xa0a63b0e43652fe3d2b5d5255df9eaf97ac522b929819db4d8655b29b2745695021dfda5f93a50f33d9fff9c95ab6fdc")
                .unwrap()
        );
    }

    #[test]
    fn test_account2() {
        let account = testing::account2();
        println!("{}", utils::format_g1(account.public_key()));
        println!(
            "{}",
            utils::format_point_25519(account.ed25519_public_key())
        );
        println!("{}", utils::format_scalar(account.address()));
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x3725571def3264422951c9225e5f9c16bb68b15f1c58ccae131b8d13d15213f2"
            )
            .unwrap()
        );
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x90ae9b9e3c07d5eec8b3e4bc60ae7242a06816d0c4eb791b77958cd1f6feab226773bf3d049c5178dc9531271e9b0514")
                .unwrap()
        );
    }

    #[test]
    fn test_account3() {
        let account = testing::account3();
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x5858d1799bf539667a0c48bed0c019ac2da886f85218e902dd147c59a99c397"
            )
            .unwrap()
        );
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x8a73da6df68c26747a0fcda2b311d866dfed5a47c864629073a04b52d4d89e21690507939d73987ce10a2a38ab7177eb")
                .unwrap()
        );
    }

    #[test]
    fn test_bls_signature() {
        let account = Account::from_secret_key(utils::get_random_bytes()).unwrap();
        let message = b"Hello, world!";
        let signature = account.bls_sign(message);
        assert!(Account::bls_verify(account.public_key(), message, signature).is_ok());
        assert!(account.bls_verify_own(message, signature).is_ok());
    }

    #[test]
    fn test_wrong_bls_signature() {
        let account = Account::from_secret_key(utils::get_random_bytes()).unwrap();
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

    #[test]
    fn test_ecdsa_certificate() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certificate = account
            .generate_ecdsa_certificate(not_before, not_after)
            .unwrap();
        let remote = Account::verify_ssl_certificate(certificate.as_slice(), now).unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_ed25519_certificate() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certificate = account
            .generate_ed25519_certificate(not_before, not_after)
            .unwrap();
        let remote = Account::verify_ssl_certificate(certificate.as_slice(), now).unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_ecdsa_certified_key() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certified_key = account
            .generate_ecdsa_certified_key(not_before, not_after)
            .unwrap();
        assert!(certified_key.keys_match().is_ok());
        let certificate = certified_key.end_entity_cert().unwrap();
        let remote = Account::verify_ssl_certificate(&*certificate, now).unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_ed25519_certified_key() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certified_key = account
            .generate_ed25519_certified_key(not_before, not_after)
            .unwrap();
        assert!(certified_key.keys_match().is_ok());
        let certificate = certified_key.end_entity_cert().unwrap();
        let remote = Account::verify_ssl_certificate(&*certificate, now).unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.bls_public_key());
    }
}
