use crate::account::Account;
use anyhow::Context;
use blstrs::{G1Affine, G2Affine};
use crypto::utils;
use curve25519_dalek::edwards::EdwardsPoint as Point25519;
use oid_registry::{Oid, asn1_rs::oid};
use primitive_types::{H384, H768};
use rustls::{client::danger::ServerCertVerifier, server::danger::ClientCertVerifier};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

pub const OID_LIBERNET_BLS_PUBLIC_KEY: Oid<'_> = oid!(1.3.6.1.4.1.71104.1);
pub const OID_LIBERNET_IDENTITY_SIGNATURE_V1: Oid<'_> = oid!(1.3.6.1.4.1.71104.2);

/// Generates a self-signed TLS certificate for use in all network connections with other Libernet
/// nodes.
pub fn generate_certificate(
    account: &Account,
    subject_alt_names: Vec<String>,
) -> anyhow::Result<rcgen::Certificate> {
    let mut params = rcgen::CertificateParams::new(subject_alt_names)?;

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        utils::format_scalar(account.address()),
    );

    params.is_ca = rcgen::IsCa::ExplicitNoCa;

    let public_key_oid: Vec<u64> = OID_LIBERNET_BLS_PUBLIC_KEY.iter().unwrap().collect();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            public_key_oid.as_slice(),
            utils::compress_g1(account.public_key())
                .to_fixed_bytes()
                .to_vec(),
        ));

    let ed25519_public_key = utils::compress_point_25519(account.ed25519_public_key());
    let signature = account.bls_sign(ed25519_public_key.as_fixed_bytes());
    let identity_signature_oid: Vec<u64> =
        OID_LIBERNET_IDENTITY_SIGNATURE_V1.iter().unwrap().collect();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            identity_signature_oid.as_slice(),
            utils::compress_g2(signature).as_bytes().to_vec(),
        ));

    Ok(params.self_signed(&account)?)
}

fn get_cert_not_before(certificate: &X509Certificate) -> u64 {
    certificate.tbs_certificate.validity.not_before.timestamp() as u64
}

fn get_cert_not_after(certificate: &X509Certificate) -> u64 {
    certificate.tbs_certificate.validity.not_after.timestamp() as u64
}

pub fn recover_ed25519_public_key(
    certificate: &X509Certificate,
) -> Result<Point25519, rustls::Error> {
    let public_key = certificate
        .tbs_certificate
        .subject_pki
        .parsed()
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
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
    let verifying_key = ed25519_dalek::VerifyingKey::try_from(bytes)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    Ok(verifying_key.to_edwards())
}

pub fn recover_bls_public_key(certificate: &X509Certificate) -> Result<G1Affine, rustls::Error> {
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

pub fn recover_identity_signature(
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

/// Verifies a self-signed TLS certificate from another Libernet node.
pub fn verify_certificate(
    certificate: &rustls::pki_types::CertificateDer<'_>,
    now: rustls::pki_types::UnixTime,
) -> Result<G1Affine, rustls::Error> {
    let (_, certificate) = parse_x509_certificate(certificate)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

    if now.as_secs() < get_cert_not_before(&certificate) {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidYet,
        ));
    }
    if now.as_secs() > get_cert_not_after(&certificate) {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
    }

    let ed25519_public_key = recover_ed25519_public_key(&certificate)?;
    let ed25519_public_key = utils::compress_point_25519(ed25519_public_key);
    let bls_public_key = recover_bls_public_key(&certificate)?;
    let identity_signature = recover_identity_signature(&certificate)?;
    Account::bls_verify(
        bls_public_key,
        ed25519_public_key.as_fixed_bytes(),
        identity_signature,
    )
    .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

    Ok(bls_public_key)
}

fn verify_tls_signature(
    message: &[u8],
    certificate: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    if dss.scheme != rustls::SignatureScheme::ED25519 {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnsupportedSignatureAlgorithmContext {
                // TODO: convert dss.scheme to the corresponding OID.
                signature_algorithm_id: vec![],
                supported_algorithms: vec![rustls::pki_types::alg_id::ED25519],
            },
        ));
    }

    let (_, parsed_certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

    let public_key = utils::compress_point_25519(recover_ed25519_public_key(&parsed_certificate)?);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.to_fixed_bytes())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

    if dss.signature().len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(dss.signature());
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
}

#[derive(Debug, Default, Clone)]
pub struct LibernetClientCertVerifier {
    root_hint_subjects: [rustls::DistinguishedName; 0],
}

impl ClientCertVerifier for LibernetClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        verify_certificate(end_entity, now)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

#[derive(Debug, Default, Clone)]
pub struct LibernetServerCertVerifier {}

impl ServerCertVerifier for LibernetServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        verify_certificate(end_entity, now)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::testing;
    use anyhow::anyhow;
    use std::ops::Deref;
    use std::sync::Arc;
    use time::{Duration, OffsetDateTime};
    use tokio::{io::AsyncReadExt, io::AsyncWriteExt};

    #[test]
    fn test_certificate_generation() {
        let account = testing::account1();
        let ed25519_public_key = utils::compress_point_25519(account.ed25519_public_key());
        let certificate =
            generate_certificate(&account, vec!["110.120.130.140".to_string()]).unwrap();
        let (_, parsed) = parse_x509_certificate(certificate.der()).unwrap();
        let common_names: Vec<&x509_parser::x509::AttributeTypeAndValue> =
            parsed.subject().iter_common_name().collect();
        assert_eq!(common_names.len(), 1);
        assert_eq!(
            common_names[0].attr_value().clone().string().unwrap(),
            utils::format_scalar(utils::hash_g1_to_scalar(account.public_key()))
        );
        assert_eq!(
            parsed.tbs_certificate.signature.algorithm,
            oid_registry::OID_SIG_ED25519
        );
        assert_eq!(
            parsed.signature_algorithm.algorithm,
            oid_registry::OID_SIG_ED25519
        );
        assert_eq!(
            parsed.tbs_certificate.subject_pki.parsed().unwrap(),
            x509_parser::public_key::PublicKey::Unknown(ed25519_public_key.as_fixed_bytes())
        );
        assert_eq!(
            parsed.public_key().parsed().unwrap(),
            x509_parser::public_key::PublicKey::Unknown(ed25519_public_key.as_fixed_bytes())
        );
        assert_eq!(
            parsed
                .get_extension_unique(&OID_LIBERNET_BLS_PUBLIC_KEY)
                .unwrap()
                .unwrap()
                .value,
            utils::compress_g1(account.public_key()).as_fixed_bytes()
        );
        let identity_signature_extension = parsed
            .get_extension_unique(&OID_LIBERNET_IDENTITY_SIGNATURE_V1)
            .unwrap()
            .unwrap();
        let identity_signature =
            utils::decompress_g2(H768::from_slice(identity_signature_extension.value)).unwrap();
        assert!(
            account
                .bls_verify_own(ed25519_public_key.as_bytes(), identity_signature)
                .is_ok()
        );
    }

    fn test_certificate(account: Account) {
        let certificate = generate_certificate(&account, vec![]).unwrap();
        assert!(verify_certificate(certificate.der(), rustls::pki_types::UnixTime::now()).is_ok());
    }

    #[test]
    fn test_certificate1() {
        test_certificate(testing::account1());
    }

    #[test]
    fn test_certificate2() {
        test_certificate(testing::account2());
    }

    #[test]
    fn test_certificate3() {
        test_certificate(testing::account3());
    }

    fn test_recover_public_keys(account: Account) {
        let certificate = generate_certificate(&account, vec![]).unwrap();
        let (_, parsed_certificate) = parse_x509_certificate(certificate.der()).unwrap();
        assert_eq!(
            recover_ed25519_public_key(&parsed_certificate).unwrap(),
            account.ed25519_public_key()
        );
        assert_eq!(
            recover_bls_public_key(&parsed_certificate).unwrap(),
            account.public_key()
        );
    }

    #[test]
    fn test_recover_public_keys1() {
        test_recover_public_keys(testing::account1());
    }

    #[test]
    fn test_recover_public_keys2() {
        test_recover_public_keys(testing::account2());
    }

    #[test]
    fn test_recover_public_keys3() {
        test_recover_public_keys(testing::account3());
    }

    #[test]
    fn test_certificate_validity() {
        let account = testing::account1();
        let certificate = generate_certificate(&account, vec![]).unwrap();
        let (_, parsed) = parse_x509_certificate(certificate.der()).unwrap();

        let now = OffsetDateTime::now_utc();
        let expected_not_before = now - Duration::days(1);
        let expected_not_after = now + Duration::days(365);

        let actual_not_before =
            OffsetDateTime::from_unix_timestamp(get_cert_not_before(&parsed) as i64).unwrap();
        let actual_not_after =
            OffsetDateTime::from_unix_timestamp(get_cert_not_after(&parsed) as i64).unwrap();

        assert!(actual_not_before >= expected_not_before - Duration::hours(1));
        assert!(actual_not_before <= expected_not_before + Duration::hours(1));
        assert!(actual_not_after >= expected_not_after - Duration::hours(1));
        assert!(actual_not_after <= expected_not_after + Duration::hours(1));
    }

    #[test]
    fn test_client_cert_verifier_parameters() {
        let verifier = LibernetClientCertVerifier::default();
        assert_eq!(verifier.root_hint_subjects().len(), 0);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![rustls::SignatureScheme::ED25519]
        );
        assert!(verifier.offer_client_auth());
        assert!(verifier.client_auth_mandatory());
        assert!(!verifier.requires_raw_public_keys());
    }

    #[test]
    fn test_server_cert_verifier_parameters() {
        let verifier = LibernetServerCertVerifier::default();
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![rustls::SignatureScheme::ED25519]
        );
        assert!(!verifier.requires_raw_public_keys());
        assert!(verifier.root_hint_subjects().is_none());
    }

    #[test]
    fn test_client_certificate_verification() {
        let account = testing::account1();
        let certificate = generate_certificate(&account, vec![]).unwrap();
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            verifier
                .verify_client_cert(certificate.der(), &[], rustls::pki_types::UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn test_not_yet_valid_client_certificate_verification() {
        let account = testing::account1();
        let certificate = generate_certificate(&account, vec![]).unwrap();
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            !verifier
                .verify_client_cert(
                    certificate.der(),
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        (OffsetDateTime::now_utc() - Duration::days(2) - OffsetDateTime::UNIX_EPOCH)
                            .whole_seconds() as u64
                    )),
                )
                .is_ok()
        );
    }

    #[test]
    fn test_expired_client_certificate_verification() {
        let account = testing::account1();
        let certificate = generate_certificate(&account, vec![]).unwrap();
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            !verifier
                .verify_client_cert(
                    certificate.der(),
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        (OffsetDateTime::now_utc() + Duration::days(366)
                            - OffsetDateTime::UNIX_EPOCH)
                            .whole_seconds() as u64
                    )),
                )
                .is_ok()
        );
    }

    fn extract_ed25519_private_key_der(account: &Account) -> &'static [u8] {
        &*account
            .export_ed25519_private_key()
            .unwrap()
            .deref()
            .clone()
            .leak()
    }

    fn check_peer(connection: &rustls::CommonState, peer_account: &Account) -> anyhow::Result<()> {
        let certificates = connection
            .peer_certificates()
            .context("certificate not found")?;
        if certificates.len() != 1 {
            return Err(anyhow!(
                "unexpected number of mTLS certificates (expected: 1, got {})",
                certificates.len()
            ));
        }
        let (_, parsed_certificate) = parse_x509_certificate(&certificates[0])?;
        let public_key_ed25519 = recover_ed25519_public_key(&parsed_certificate)?;
        if public_key_ed25519 != peer_account.ed25519_public_key() {
            return Err(anyhow!("the Ed25519 public key doesn't match"));
        }
        let public_key = recover_bls_public_key(&parsed_certificate)?;
        if public_key != peer_account.public_key() {
            return Err(anyhow!("the Pallas public key doesn't match"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_mutual_tls() {
        let server_account = testing::account1();
        let server_certificate =
            generate_certificate(&server_account, vec!["server".to_string()]).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(LibernetClientCertVerifier::default()))
                .with_single_cert(
                    vec![server_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            extract_ed25519_private_key_der(&server_account),
                        ),
                    ),
                )
                .unwrap(),
        ));

        let client_account = testing::account2();
        let client_certificate =
            generate_certificate(&client_account, vec!["client".to_string()]).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LibernetServerCertVerifier::default()))
                .with_client_auth_cert(
                    vec![client_certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            extract_ed25519_private_key_der(&client_account),
                        ),
                    ),
                )
                .unwrap(),
        ));

        let (client_stream, server_stream) = tokio::io::duplex(4096);

        let server_task = tokio::task::spawn(async move {
            let mut stream = acceptor.accept(server_stream).await.unwrap();
            let (_, connection) = stream.get_ref();
            assert!(check_peer(connection, &client_account).is_ok());
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let client_task = tokio::spawn(async move {
            let mut stream = connector
                .connect("localhost".try_into().unwrap(), client_stream)
                .await
                .unwrap();
            let (_, connection) = stream.get_ref();
            assert!(check_peer(connection, &server_account).is_ok());
            stream.write_all(b"ping").await.unwrap();
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"pong");
        });

        let (result1, result2) = tokio::join!(server_task, client_task);
        assert!(result1.is_ok() && result2.is_ok());
    }
}
