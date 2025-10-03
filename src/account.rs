use crate::libernet;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use crypto::{account::Account as LowLevelAccount, utils};
use curve25519_dalek::EdwardsPoint as Point25519;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey, spki::der::Encode};
use oid_registry::{Oid, asn1_rs::oid};
use primitive_types::{H256, H384, H512, H768};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

const OID_LIBERNET_BLS_PUBLIC_KEY: Oid<'_> = oid!(1.3.6.1.4.1.71104.1);
const OID_LIBERNET_IDENTITY_SIGNATURE_V1: Oid<'_> = oid!(1.3.6.1.4.1.71104.2);

/// A Libernet account with an associated BLS keypair, account address, and Ed25519 keypair for
/// generating TLS certificates.
#[derive(Debug)]
pub struct Account {
    inner: LowLevelAccount,
    ed25519_public_key_bytes: Vec<u8>,
}

impl Account {
    pub fn new(inner: LowLevelAccount) -> Result<Self> {
        let ed25519_public_key_bytes = {
            let bytes = utils::compress_point_25519(inner.ed25519_public_key());
            let bytes = ed25519_dalek::pkcs8::PublicKeyBytes(bytes.to_fixed_bytes());
            bytes.to_public_key_der()?.to_der()?
        };
        Ok(Self {
            inner,
            ed25519_public_key_bytes,
        })
    }

    pub fn from_secret_key(secret_key: H512) -> Result<Self> {
        Self::new(LowLevelAccount::new(secret_key))
    }

    pub fn public_key(&self) -> G1Affine {
        self.inner.public_key()
    }

    pub fn ed25519_public_key(&self) -> Point25519 {
        self.inner.ed25519_public_key()
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

    /// Generates a self-signed TLS certificate for use in all network connections with other
    /// Libernet nodes.
    pub fn generate_tls_certificate(
        &self,
        subject_alt_names: Vec<String>,
    ) -> Result<rcgen::Certificate> {
        let mut params = rcgen::CertificateParams::new(subject_alt_names)?;

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(365);

        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            utils::format_scalar(self.inner.address()),
        );

        params.is_ca = rcgen::IsCa::ExplicitNoCa;

        let public_key_oid: Vec<u64> = OID_LIBERNET_BLS_PUBLIC_KEY.iter().unwrap().collect();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                public_key_oid.as_slice(),
                utils::compress_g1(self.inner.public_key())
                    .to_fixed_bytes()
                    .to_vec(),
            ));

        let ed25519_public_key = utils::compress_point_25519(self.inner.ed25519_public_key());
        let signature = self.inner.bls_sign(ed25519_public_key.as_fixed_bytes());
        let identity_signature_oid: Vec<u64> =
            OID_LIBERNET_IDENTITY_SIGNATURE_V1.iter().unwrap().collect();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                identity_signature_oid.as_slice(),
                utils::compress_g2(signature).as_bytes().to_vec(),
            ));

        Ok(params.self_signed(self)?)
    }

    fn get_cert_not_before(certificate: &X509Certificate) -> u64 {
        certificate.tbs_certificate.validity.not_before.timestamp() as u64
    }

    fn get_cert_not_after(certificate: &X509Certificate) -> u64 {
        certificate.tbs_certificate.validity.not_after.timestamp() as u64
    }

    fn recover_ed25519_public_key(
        certificate: &X509Certificate,
    ) -> Result<Point25519, rustls::Error> {
        let public_key = certificate
            .tbs_certificate
            .subject_pki
            .parsed()
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let bytes = match public_key {
            // NOTE: the x509_parser doesn't handle Ed25519 keys yet, so our Ed25519 keys show up as
            // "unknown".
            x509_parser::public_key::PublicKey::Unknown(bytes) => Ok(bytes),
            _ => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnsupportedSignatureAlgorithmContext {
                    signature_algorithm_id: certificate
                        .tbs_certificate
                        .subject_pki
                        .algorithm
                        .algorithm
                        .as_bytes()
                        .to_vec(),
                    supported_algorithms: vec![rustls::pki_types::alg_id::ED25519],
                },
            )),
        }?;
        let bytes =
            ed25519_dalek::pkcs8::PublicKeyBytes::from_public_key_der(bytes).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(bytes).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        Ok(verifying_key.to_edwards())
    }

    fn recover_bls_public_key(certificate: &X509Certificate) -> Result<G1Affine, rustls::Error> {
        let extensions = certificate.extensions_map().map_err(|_| {
            rustls::Error::General("public BLS key not found in X.509 certificate".into())
        })?;
        let extension = *extensions
            .get(&OID_LIBERNET_BLS_PUBLIC_KEY)
            .context("public BLS key not found in X.509 certificate")
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        utils::decompress_g1(H384::from_slice(extension.value))
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))
    }

    fn recover_identity_signature(
        certificate: &X509Certificate,
    ) -> Result<G2Affine, rustls::Error> {
        let extensions = certificate.extensions_map().map_err(|_| {
            rustls::Error::General("identity signature not found in X.509 certificate".into())
        })?;
        let extension = *extensions
            .get(&OID_LIBERNET_IDENTITY_SIGNATURE_V1)
            .context("identity signature not found in X.509 certificate")
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        utils::decompress_g2(H768::from_slice(extension.value))
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))
    }

    /// Verifies a self-signed TLS certificate from another Libernet node, returning the public BLS
    /// key of the node.
    pub fn verify_tls_certificate(
        certificate: &rustls::pki_types::CertificateDer<'_>,
        now: rustls::pki_types::UnixTime,
    ) -> Result<G1Affine, rustls::Error> {
        let (_, certificate) = parse_x509_certificate(certificate).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        if now.as_secs() < Self::get_cert_not_before(&certificate) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet,
            ));
        }
        if now.as_secs() > Self::get_cert_not_after(&certificate) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        let ed25519_public_key = Self::recover_ed25519_public_key(&certificate)?;
        let ed25519_public_key = utils::compress_point_25519(ed25519_public_key);
        let bls_public_key = Self::recover_bls_public_key(&certificate)?;
        let identity_signature = Self::recover_identity_signature(&certificate)?;
        LowLevelAccount::bls_verify(
            bls_public_key,
            ed25519_public_key.as_fixed_bytes(),
            identity_signature,
        )
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

        Ok(bls_public_key)
    }
}

impl rcgen::PublicKeyData for Account {
    fn der_bytes(&self) -> &[u8] {
        self.ed25519_public_key_bytes.as_slice()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for Account {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        Ok(self.inner.ed25519_sign(message).to_vec())
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub fn account1() -> Account {
        Account::new(LowLevelAccount::new(
            "0x4191f15fdee5d58d9e829c72da3ff838a707a3e798e0cd67348dbdc628ad1565381456e6acde30debd3054224d3f684a8262550c5abc757d2dd4be979151997d"
                .parse()
                .unwrap(),
        ))
        .unwrap()
    }

    pub fn account2() -> Account {
        Account::new(LowLevelAccount::new(
            "0xac363bfd648af099278f7bc694633713999eb1089c33ef144496d52c9ee41d70b4503dac4448ad234747f3553fb4040c29cdf842f251cf116795dcd72be51ddc"
                .parse()
                .unwrap(),
        ))
        .unwrap()
    }

    pub fn account3() -> Account {
        Account::new(LowLevelAccount::new(
            "0xbee4977e23fd5a077def6fe641ebcf0c876484ff32b62095df046398c77eb93ab22161ccf87f3b9e1915a41578badafdce4f6608fdf6f9aafd02a11d13b4780d"
                .parse()
                .unwrap(),
        ))
        .unwrap()
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
            utils::parse_g1("0xa0a63b0e43652fe3d2b5d5255df9eaf97ac522b929819db4d8655b29b2745695021dfda5f93a50f33d9fff9c95ab6fdc")
                .unwrap()
        );
        assert_eq!(
            account.ed25519_public_key(),
            utils::parse_point_25519(
                "0x908ea6fbbb3d4979d185118b94762b127002e06ee43fdb8b62bba20e443dc71f"
            )
            .unwrap()
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x28fe947cabf1257baba35b31ba1f1ae837d20c4b0dbcf15b23c5e2afa7d0e369"
            )
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
            account.public_key(),
            utils::parse_g1("0x90ae9b9e3c07d5eec8b3e4bc60ae7242a06816d0c4eb791b77958cd1f6feab226773bf3d049c5178dc9531271e9b0514")
                .unwrap()
        );
        assert_eq!(
            account.ed25519_public_key(),
            utils::parse_point_25519(
                "0xea9f8969a264ea7ebade38388c90add11ecd517389f94ad230c6e94b58b1bcdd"
            )
            .unwrap()
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x3725571def3264422951c9225e5f9c16bb68b15f1c58ccae131b8d13d15213f2"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_account3() {
        let account = testing::account3();
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x8a73da6df68c26747a0fcda2b311d866dfed5a47c864629073a04b52d4d89e21690507939d73987ce10a2a38ab7177eb")
                .unwrap()
        );
        assert_eq!(
            account.ed25519_public_key(),
            utils::parse_point_25519(
                "0xcafd8587e708bb86514539c252213072660b7ecb4839f5e4bae2b806acabaca2"
            )
            .unwrap()
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x5858d1799bf539667a0c48bed0c019ac2da886f85218e902dd147c59a99c397"
            )
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

    fn test_tls_certificate(account: Account) {
        let certificate = account.generate_tls_certificate(vec![]).unwrap();
        assert!(
            Account::verify_tls_certificate(certificate.der(), rustls::pki_types::UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn test_tls_certificate1() {
        test_tls_certificate(testing::account1());
    }

    #[test]
    fn test_tls_certificate2() {
        test_tls_certificate(testing::account2());
    }

    #[test]
    fn test_tls_certificate3() {
        test_tls_certificate(testing::account3());
    }
}
