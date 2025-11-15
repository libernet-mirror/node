use crate::account::Account;
use crypto::{
    remote::{RemoteEcDsaAccount, RemoteEd25519Account},
    signer::{EcDsaVerifier, Ed25519Verifier},
};
use rustls::{
    SignatureScheme,
    client::{ResolvesClientCert, danger::ServerCertVerifier},
    pki_types::CertificateDer,
    server::{CertificateType, ClientHello, ResolvesServerCert, danger::ClientCertVerifier},
    sign::CertifiedKey,
};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

trait DssVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>;
}

#[derive(Debug)]
struct EcDsaDssVerifier {
    inner: RemoteEcDsaAccount,
}

impl EcDsaDssVerifier {
    fn from_certificate(certificate: &CertificateDer<'_>) -> Result<Self, rustls::Error> {
        Ok(Self {
            inner: RemoteEcDsaAccount::from_certificate(&certificate).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?,
        })
    }
}

impl DssVerifier for EcDsaDssVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let signature = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| rustls::Error::General("invalid DSS format".to_string()))?;
        match self.inner.ecdsa_verify(message, &signature) {
            Ok(_) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            Err(_) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            )),
        }
    }
}

#[derive(Debug)]
struct Ed25519DssVerifier {
    inner: RemoteEd25519Account,
}

impl Ed25519DssVerifier {
    fn from_certificate(certificate: &CertificateDer<'_>) -> Result<Self, rustls::Error> {
        Ok(Self {
            inner: RemoteEd25519Account::from_certificate(&certificate).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?,
        })
    }
}

impl DssVerifier for Ed25519DssVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| rustls::Error::General("invalid DSS format".to_string()))?;
        match self.inner.ed25519_verify(message, &signature) {
            Ok(_) => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            Err(_) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            )),
        }
    }
}

fn verify_tls_signature(
    message: &[u8],
    certificate: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    match dss.scheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => {
            Ok(Box::new(EcDsaDssVerifier::from_certificate(&certificate)?) as Box<dyn DssVerifier>)
        }
        rustls::SignatureScheme::ED25519 => Ok(Box::new(Ed25519DssVerifier::from_certificate(
            &certificate,
        )?) as Box<dyn DssVerifier>),
        _ => Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnsupportedSignatureAlgorithmContext {
                // TODO: convert dss.scheme to the corresponding OID.
                signature_algorithm_id: vec![],
                supported_algorithms: vec![rustls::pki_types::alg_id::ED25519],
            },
        )),
    }?
    .verify(message, dss.signature())
}

fn scan_signature_schemes(signature_schemes: &[SignatureScheme]) -> (bool, bool) {
    let mut has_ed25519 = false;
    let mut has_ecdsa = false;
    for scheme in signature_schemes {
        match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                has_ecdsa = true;
            }
            SignatureScheme::ED25519 => {
                has_ed25519 = true;
            }
            _ => {}
        }
    }
    (has_ed25519, has_ecdsa)
}

#[derive(Debug)]
pub struct ClientCertResolver {
    ed25519_key: Arc<CertifiedKey>,
    ecdsa_key: Arc<CertifiedKey>,
}

impl ClientCertResolver {
    pub fn new(ed25519_key: Arc<CertifiedKey>, ecdsa_key: Arc<CertifiedKey>) -> Self {
        Self {
            ed25519_key,
            ecdsa_key,
        }
    }
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        signature_schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let (has_ed25519, has_ecdsa) = scan_signature_schemes(signature_schemes);
        if has_ed25519 {
            Some(self.ed25519_key.clone())
        } else if has_ecdsa {
            Some(self.ecdsa_key.clone())
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
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
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let now = UNIX_EPOCH + Duration::from_secs(now.as_secs());
        Account::verify_ssl_certificate(&end_entity, now, None).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

#[derive(Debug)]
pub struct ServerCertResolver {
    ed25519_key: Arc<CertifiedKey>,
    ecdsa_key: Arc<CertifiedKey>,
}

impl ServerCertResolver {
    pub fn new(ed25519_key: Arc<CertifiedKey>, ecdsa_key: Arc<CertifiedKey>) -> Self {
        Self {
            ed25519_key,
            ecdsa_key,
        }
    }

    fn check_cert_types(cert_types: Option<&'_ [CertificateType]>) -> Option<()> {
        let Some(cert_types) = cert_types else {
            return Some(());
        };
        for cert_type in cert_types {
            if *cert_type == CertificateType::X509 {
                return Some(());
            }
        }
        None
    }
}

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let (has_ed25519, has_ecdsa) = scan_signature_schemes(&client_hello.signature_schemes());
        Self::check_cert_types(client_hello.server_cert_types())?;
        Self::check_cert_types(client_hello.client_cert_types())?;
        if has_ed25519 {
            Some(self.ed25519_key.clone())
        } else if has_ecdsa {
            Some(self.ecdsa_key.clone())
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LibernetServerCertVerifier {}

impl ServerCertVerifier for LibernetServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let now = UNIX_EPOCH + Duration::from_secs(now.as_secs());
        Account::verify_ssl_certificate(&end_entity, now, Some(&*server_name.to_str())).map_err(
            |_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            },
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::testing;
    use anyhow::{Context, anyhow};
    use crypto::ssl::{self, SslPublicKey};
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
            vec![
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
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
            vec![
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        );
        assert!(!verifier.requires_raw_public_keys());
        assert!(verifier.root_hint_subjects().is_none());
    }

    #[test]
    fn test_ecdsa_client_certificate_verification() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certificate = account
            .generate_ecdsa_certificate(not_before, not_after, None)
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
    fn test_ed25519_client_certificate_verification() {
        let account = testing::account1();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);
        let certificate = account
            .generate_ed25519_certificate(not_before, not_after, None)
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
            .generate_ed25519_certificate(not_before, not_after, None)
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
            .generate_ed25519_certificate(not_before, not_after, None)
            .unwrap();
        let certificate = CertificateDer::from_slice(certificate.as_slice());
        let verifier = LibernetClientCertVerifier::default();
        assert!(
            !verifier
                .verify_client_cert(&certificate, &[], system_time_to_unix_time(now))
                .is_ok()
        );
    }

    fn extract_ecdsa_private_key_der(account: &Account) -> &'static [u8] {
        &*account
            .export_ecdsa_private_key_der()
            .unwrap()
            .deref()
            .clone()
            .leak()
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
        let (public_key, ssl_public_key) = ssl::recover_public_keys(&certificates[0])?;
        match ssl_public_key {
            SslPublicKey::EcDsa(ecdsa_public_key) => {
                if ecdsa_public_key != peer_account.ecdsa_public_key() {
                    return Err(anyhow!("the ECDSA public key doesn't match"));
                }
            }
            SslPublicKey::Ed25519(ed25519_public_key) => {
                if ed25519_public_key != peer_account.ed25519_public_key() {
                    return Err(anyhow!("the Ed25519 public key doesn't match"));
                }
            }
        };
        if public_key != peer_account.public_key() {
            return Err(anyhow!("the Pallas public key doesn't match"));
        }
        Ok(())
    }

    async fn test_mutual_tls(use_ed25519: bool) {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = testing::account1();
        let server_certificate = if use_ed25519 {
            server_account
                .generate_ed25519_certificate(not_before, not_after, Some("localhost"))
                .unwrap()
        } else {
            server_account
                .generate_ecdsa_certificate(not_before, not_after, Some("localhost"))
                .unwrap()
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(LibernetClientCertVerifier::default()))
                .with_single_cert(
                    vec![CertificateDer::from_slice(server_certificate.leak())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(if use_ed25519 {
                            extract_ed25519_private_key_der(&server_account)
                        } else {
                            extract_ecdsa_private_key_der(&server_account)
                        }),
                    ),
                )
                .unwrap(),
        ));

        let client_account = testing::account2();
        let client_certificate = if use_ed25519 {
            client_account
                .generate_ed25519_certificate(not_before, not_after, None)
                .unwrap()
        } else {
            client_account
                .generate_ecdsa_certificate(not_before, not_after, None)
                .unwrap()
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LibernetServerCertVerifier::default()))
                .with_client_auth_cert(
                    vec![CertificateDer::from_slice(client_certificate.leak())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(if use_ed25519 {
                            extract_ed25519_private_key_der(&client_account)
                        } else {
                            extract_ecdsa_private_key_der(&client_account)
                        }),
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

    #[tokio::test]
    async fn test_mutual_tls_with_ecdsa() {
        test_mutual_tls(false).await;
    }

    #[tokio::test]
    async fn test_mutual_tls_with_ed25519() {
        test_mutual_tls(true).await;
    }

    async fn test_mutual_tls_with_dual_server_key(use_ed25519: bool) {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = testing::account1();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(LibernetClientCertVerifier::default()))
                .with_cert_resolver(Arc::new(ServerCertResolver::new(
                    server_account
                        .generate_ed25519_certified_key(not_before, not_after, Some("localhost"))
                        .unwrap(),
                    server_account
                        .generate_ecdsa_certified_key(not_before, not_after, Some("localhost"))
                        .unwrap(),
                ))),
        ));

        let client_account = testing::account2();
        let client_certificate = if use_ed25519 {
            client_account
                .generate_ed25519_certificate(not_before, not_after, None)
                .unwrap()
        } else {
            client_account
                .generate_ecdsa_certificate(not_before, not_after, None)
                .unwrap()
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LibernetServerCertVerifier::default()))
                .with_client_auth_cert(
                    vec![CertificateDer::from_slice(client_certificate.leak())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(if use_ed25519 {
                            extract_ed25519_private_key_der(&client_account)
                        } else {
                            extract_ecdsa_private_key_der(&client_account)
                        }),
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

    #[tokio::test]
    async fn test_mutual_tls_with_dual_server_key1() {
        test_mutual_tls_with_dual_server_key(false).await;
    }

    #[tokio::test]
    async fn test_mutual_tls_with_dual_server_key2() {
        test_mutual_tls_with_dual_server_key(true).await;
    }

    async fn test_mutual_tls_with_dual_client_key(use_ed25519: bool) {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = testing::account1();
        let server_certificate = if use_ed25519 {
            server_account
                .generate_ed25519_certificate(not_before, not_after, Some("localhost"))
                .unwrap()
        } else {
            server_account
                .generate_ecdsa_certificate(not_before, not_after, Some("localhost"))
                .unwrap()
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(LibernetClientCertVerifier::default()))
                .with_single_cert(
                    vec![CertificateDer::from_slice(server_certificate.leak())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(if use_ed25519 {
                            extract_ed25519_private_key_der(&server_account)
                        } else {
                            extract_ecdsa_private_key_der(&server_account)
                        }),
                    ),
                )
                .unwrap(),
        ));

        let client_account = testing::account2();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LibernetServerCertVerifier::default()))
                .with_client_cert_resolver(Arc::new(ClientCertResolver::new(
                    client_account
                        .generate_ed25519_certified_key(not_before, not_after, None)
                        .unwrap(),
                    client_account
                        .generate_ecdsa_certified_key(not_before, not_after, None)
                        .unwrap(),
                ))),
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

    #[tokio::test]
    async fn test_mutual_tls_with_dual_client_key1() {
        test_mutual_tls_with_dual_client_key(false).await;
    }

    #[tokio::test]
    async fn test_mutual_tls_with_dual_client_key2() {
        test_mutual_tls_with_dual_client_key(true).await;
    }

    #[tokio::test]
    async fn test_dual_key_mutual_tls() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = testing::account1();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(LibernetClientCertVerifier::default()))
                .with_cert_resolver(Arc::new(ServerCertResolver::new(
                    server_account
                        .generate_ed25519_certified_key(not_before, not_after, Some("localhost"))
                        .unwrap(),
                    server_account
                        .generate_ecdsa_certified_key(not_before, not_after, Some("localhost"))
                        .unwrap(),
                ))),
        ));

        let client_account = testing::account2();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(LibernetServerCertVerifier::default()))
                .with_client_cert_resolver(Arc::new(ClientCertResolver::new(
                    client_account
                        .generate_ed25519_certified_key(not_before, not_after, None)
                        .unwrap(),
                    client_account
                        .generate_ecdsa_certified_key(not_before, not_after, None)
                        .unwrap(),
                ))),
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
