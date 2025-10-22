use crate::account::Account;
use crypto::{remote::RemoteAccount, signer::Verifier};
use rustls::{client::danger::ServerCertVerifier, server::danger::ClientCertVerifier};
use std::time::{Duration, UNIX_EPOCH};

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

    let remote_account = RemoteAccount::from_certificate(certificate)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

    if dss.signature().len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    let mut signature_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(dss.signature());
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    remote_account
        .ed25519_verify(message, &signature)
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
        let now = UNIX_EPOCH + Duration::from_secs(now.as_secs());
        Account::verify_ssl_certificate(&end_entity, now).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;
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
        let now = UNIX_EPOCH + Duration::from_secs(now.as_secs());
        Account::verify_ssl_certificate(&end_entity, now).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;
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
    use anyhow::{Context, anyhow};
    use crypto::ssl;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use std::ops::Deref;
    use std::sync::Arc;
    use std::time::SystemTime;
    use tokio::{io::AsyncReadExt, io::AsyncWriteExt};

    fn system_time_to_unix_time(time: SystemTime) -> UnixTime {
        UnixTime::since_unix_epoch(time.duration_since(UNIX_EPOCH).unwrap())
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
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certificate = account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let certificate = CertificateDer::from_slice(certificate.as_slice());
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            verifier
                .verify_client_cert(&certificate, &[], system_time_to_unix_time(now))
                .is_ok()
        );
    }

    #[test]
    fn test_not_yet_valid_client_certificate_verification() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now + Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certificate = account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let certificate = CertificateDer::from_slice(certificate.as_slice());
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            !verifier
                .verify_client_cert(&certificate, &[], system_time_to_unix_time(now))
                .is_ok()
        );
    }

    #[test]
    fn test_expired_client_certificate_verification() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(456);
        let not_after = now - Duration::from_secs(123);
        let certificate = account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let certificate = CertificateDer::from_slice(certificate.as_slice());
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            !verifier
                .verify_client_cert(&certificate, &[], system_time_to_unix_time(now))
                .is_ok()
        );
    }

    fn extract_ed25519_private_key_der(account: &Account) -> &'static [u8] {
        &*account
            .export_ed25519_private_key_der()
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
        let (public_key, ed25519_public_key) = ssl::recover_public_keys(&certificates[0])?;
        if ed25519_public_key != peer_account.ed25519_public_key() {
            return Err(anyhow!("the Ed25519 public key doesn't match"));
        }
        if public_key != peer_account.public_key() {
            return Err(anyhow!("the Pallas public key doesn't match"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_mutual_tls() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = testing::account1();
        let server_certificate = server_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(LibernetClientCertVerifier::default()))
                .with_single_cert(
                    vec![CertificateDer::from_slice(server_certificate.leak())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            extract_ed25519_private_key_der(&server_account),
                        ),
                    ),
                )
                .unwrap(),
        ));

        let client_account = testing::account2();
        let client_certificate = client_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LibernetServerCertVerifier::default()))
                .with_client_auth_cert(
                    vec![CertificateDer::from_slice(client_certificate.leak())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            extract_ed25519_private_key_der(&client_account),
                        ),
                    ),
                )
                .unwrap(),
        ));

        let (client_stream, server_stream) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
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
