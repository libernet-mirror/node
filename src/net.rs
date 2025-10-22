use crate::account::Account;
use crate::ssl;
use anyhow::Context;
use blstrs::{G1Affine, Scalar};
use crypto::{remote::RemoteAccount, signer::PartialVerifier};
use hyper::rt::{Read, ReadBufCursor, Write};
use rustls::pki_types::CertificateDer;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use tokio::{
    io::AsyncRead, io::AsyncWrite, io::ReadBuf, net::TcpListener, net::TcpStream,
    net::ToSocketAddrs,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use tonic::transport::{Channel, Uri, server::Connected};

#[derive(Debug, Copy, Clone)]
pub struct ConnectionInfo {
    peer_account: RemoteAccount,
}

impl ConnectionInfo {
    pub fn new<'a>(peer_certificate: CertificateDer<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            peer_account: RemoteAccount::from_certificate(&peer_certificate)?,
        })
    }

    pub fn peer_account(&self) -> &RemoteAccount {
        &self.peer_account
    }

    pub fn peer_address(&self) -> Scalar {
        self.peer_account.address()
    }

    pub fn peer_public_key(&self) -> G1Affine {
        self.peer_account.public_key()
    }
}

pub struct TlsServerStreamAdapter<IO: AsyncRead + AsyncWrite + Unpin> {
    info: ConnectionInfo,
    inner: server::TlsStream<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsServerStreamAdapter<IO> {
    pub fn new(
        inner_stream: server::TlsStream<IO>,
        peer_certificate: CertificateDer<'static>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            info: ConnectionInfo::new(peer_certificate)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))?,
            inner: inner_stream,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsServerStreamAdapter<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsServerStreamAdapter<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Connected for TlsServerStreamAdapter<IO> {
    type ConnectInfo = ConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

pub struct TlsClientStreamAdapter<IO: AsyncRead + AsyncWrite + Unpin> {
    info: ConnectionInfo,
    inner: client::TlsStream<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsClientStreamAdapter<IO> {
    pub fn new(
        inner_stream: client::TlsStream<IO>,
        peer_certificate: CertificateDer<'static>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            info: ConnectionInfo::new(peer_certificate)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))?,
            inner: inner_stream,
        })
    }

    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Read for TlsClientStreamAdapter<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        mut buffer_cursor: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut raw = vec![0u8; buffer_cursor.remaining()];
        let mut buffer = ReadBuf::new(raw.as_mut_slice());
        let poll = Pin::new(&mut self.inner).poll_read(context, &mut buffer);
        if let Poll::Ready(Ok(())) = &poll {
            buffer_cursor.put_slice(buffer.filled());
        }
        poll
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Write for TlsClientStreamAdapter<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn get_peer_certificate(
    connection: &rustls::CommonState,
) -> std::io::Result<CertificateDer<'static>> {
    let certificates = connection
        .peer_certificates()
        .context("certificate missing")
        .map_err(|error| Error::new(ErrorKind::PermissionDenied, error))?;
    if certificates.len() != 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unexpected number of mTLS certificates (expected: 1, got {})",
                certificates.len()
            ),
        ));
    }
    Ok(certificates[0].clone())
}

pub trait Listener<IO: AsyncRead + AsyncWrite + Unpin>: Send + Sync {
    fn accept<'a>(&'a self) -> Pin<Box<dyn Future<Output = std::io::Result<IO>> + Send + 'a>>;
}

pub struct TcpListenerAdapter {
    inner: TcpListener,
}

impl TcpListenerAdapter {
    pub async fn new<A: ToSocketAddrs>(address: A) -> std::io::Result<Self> {
        let inner = TcpListener::bind(address).await?;
        Ok(Self { inner })
    }

    pub fn local_address(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }
}

impl Listener<TcpStream> for TcpListenerAdapter {
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + 'a>> {
        Box::pin(async move {
            let (stream, _) = self.inner.accept().await?;
            Ok(stream)
        })
    }
}

// This is atrocious but seems to be the only way to make the custom rustls configs work. The dang
// rustls won't accept an external signing object.
fn extract_ed25519_private_key_der(account: &Account) -> anyhow::Result<&'static [u8]> {
    Ok(&*account
        .export_ed25519_private_key_der()?
        .deref()
        .clone()
        .leak())
}

type TlsHandshakeFuture<IO> =
    Pin<Box<dyn Future<Output = std::io::Result<TlsServerStreamAdapter<IO>>> + Send>>;

pub struct IncomingWithMTls<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    listener: Arc<dyn Listener<IO>>,
    acceptor: TlsAcceptor,
    pending: TlsHandshakeFuture<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> IncomingWithMTls<IO> {
    fn accept(listener: Arc<dyn Listener<IO>>, acceptor: TlsAcceptor) -> TlsHandshakeFuture<IO> {
        Box::pin(async move {
            let stream = listener.accept().await?;
            let stream = acceptor.accept(stream).await?;
            let (_, connection) = stream.get_ref();
            let certificate = get_peer_certificate(connection)?;
            TlsServerStreamAdapter::new(stream, certificate)
        })
    }

    pub async fn new(
        listener: Arc<dyn Listener<IO>>,
        account: &Account,
        certificate: CertificateDer<'static>,
    ) -> anyhow::Result<Self> {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(ssl::LibernetClientCertVerifier::default()))
                .with_single_cert(
                    vec![certificate],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            extract_ed25519_private_key_der(account)?,
                        ),
                    ),
                )?,
        ));
        let pending = Self::accept(listener.clone(), acceptor.clone());
        Ok(Self {
            listener,
            acceptor,
            pending,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> futures::Stream for IncomingWithMTls<IO> {
    type Item = std::io::Result<TlsServerStreamAdapter<IO>>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.pending.as_mut().poll(context) {
            Poll::Ready(result) => {
                self.pending = Self::accept(self.listener.clone(), self.acceptor.clone());
                Poll::Ready(Some(result))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub trait Connector<IO: AsyncRead + AsyncWrite>: Send + Sync {
    fn connect<'a>(
        &'a self,
        address: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<IO>> + Send + 'a>>;
}

pub struct TcpConnectorAdapter {}

impl TcpConnectorAdapter {
    pub fn new() -> Self {
        Self {}
    }
}

impl Connector<TcpStream> for TcpConnectorAdapter {
    fn connect<'a>(
        &'a self,
        address: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + 'a>> {
        Box::pin(async move {
            let stream = TcpStream::connect(address).await?;
            Ok(stream)
        })
    }
}

struct ConnectorWithMTls<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    tcp_connector: Arc<dyn Connector<IO>>,
    tls_connector: TlsConnector,
    peer_certificate: Arc<Mutex<Option<CertificateDer<'static>>>>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> ConnectorWithMTls<IO> {
    const DEFAULT_PORT: u16 = 443;

    pub fn new(
        tcp_connector: Arc<dyn Connector<IO>>,
        account: &Account,
        certificate: CertificateDer<'static>,
        peer_certificate: Arc<Mutex<Option<CertificateDer<'static>>>>,
    ) -> anyhow::Result<ConnectorWithMTls<IO>> {
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    ssl::LibernetServerCertVerifier::default(),
                ))
                .with_client_auth_cert(
                    vec![certificate],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            extract_ed25519_private_key_der(account)?,
                        ),
                    ),
                )
                .unwrap(),
        ));
        {
            let mut guard = peer_certificate.lock().unwrap();
            *guard = None;
        }
        Ok(Self {
            tcp_connector,
            tls_connector,
            peer_certificate,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> tower::Service<Uri>
    for ConnectorWithMTls<IO>
{
    type Response = TlsClientStreamAdapter<IO>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _context: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Uri) -> Self::Future {
        let tcp_connector = self.tcp_connector.clone();
        let tls_connector = self.tls_connector.clone();
        let peer_certificate = self.peer_certificate.clone();
        Box::pin(async move {
            let host = request
                .host()
                .context("invalid host name")
                .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
            let port = request.port_u16().unwrap_or(Self::DEFAULT_PORT);

            let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid server name"))?;

            let address = format!("{}:{}", host, port);
            let stream = tcp_connector.connect(address).await?;
            let stream = tls_connector.connect(server_name, stream).await?;
            let (_, connection) = stream.get_ref();
            let certificate = get_peer_certificate(connection)?;
            {
                let mut guard = peer_certificate.lock().unwrap();
                *guard = Some(certificate.clone());
            }
            TlsClientStreamAdapter::new(stream, certificate)
        })
    }
}

pub async fn connect_with_mtls(
    account: &Account,
    certificate: CertificateDer<'static>,
    uri: Uri,
) -> anyhow::Result<(Channel, ConnectionInfo)> {
    let peer_certificate = Arc::new(Mutex::new(None::<CertificateDer<'static>>));
    let channel = Channel::builder(uri)
        .connect_with_connector(
            ConnectorWithMTls::new(
                Arc::new(TcpConnectorAdapter::new()),
                account,
                certificate,
                peer_certificate.clone(),
            )
            .unwrap(),
        )
        .await?;
    let peer_certificate = peer_certificate.lock().unwrap().as_mut().unwrap().clone();
    let connection_info = ConnectionInfo::new(peer_certificate)?;
    Ok((channel, connection_info))
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use futures::future;
    use tokio::io::DuplexStream;

    pub struct MockListener {
        stream: Mutex<Option<DuplexStream>>,
    }

    impl MockListener {
        pub fn new(stream: DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
            }
        }
    }

    impl Listener<DuplexStream> for MockListener {
        fn accept<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<DuplexStream>> + Send + 'a>> {
            let mut lock = self.stream.lock().unwrap();
            Box::pin(match lock.take() {
                Some(stream) => future::Either::Left(future::ready(Ok(stream))),
                None => future::Either::Right(future::pending()),
            })
        }
    }

    pub struct MockConnector {
        stream: Mutex<Option<DuplexStream>>,
    }

    impl MockConnector {
        pub fn new(stream: DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
            }
        }
    }

    impl Connector<DuplexStream> for MockConnector {
        fn connect<'a>(
            &'a self,
            _address: String,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<DuplexStream>> + Send + 'a>> {
            let mut lock = self.stream.lock().unwrap();
            Box::pin(match lock.take() {
                Some(stream) => future::Either::Left(future::ready(Ok(stream))),
                None => future::Either::Right(future::pending()),
            })
        }
    }

    pub async fn mock_connect_with_mtls(
        stream: DuplexStream,
        account: &Account,
        certificate: CertificateDer<'static>,
    ) -> anyhow::Result<(Channel, ConnectionInfo)> {
        let peer_certificate = Arc::new(Mutex::new(None::<CertificateDer<'static>>));
        let channel = Channel::builder("http://fake".parse().unwrap())
            .connect_with_connector(
                ConnectorWithMTls::new(
                    Arc::new(MockConnector::new(stream)),
                    account,
                    certificate,
                    peer_certificate.clone(),
                )
                .unwrap(),
            )
            .await?;
        let peer_certificate = peer_certificate.lock().unwrap().as_mut().unwrap().clone();
        let connection_info = ConnectionInfo::new(peer_certificate)?;
        Ok((channel, connection_info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::testing as account_testing;
    use crate::fake::FakeNodeService;
    use crate::libernet::{
        self, node_service_v1_client::NodeServiceV1Client,
        node_service_v1_server::NodeServiceV1Server,
    };
    use std::time::{Duration, SystemTime};
    use tokio::sync::Notify;
    use tonic::{Request, transport::Server};

    #[tokio::test]
    async fn test_tcp_connection() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = Arc::pin(account_testing::account1());
        let server_certificate = server_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let server_certificate = CertificateDer::from_slice(server_certificate.leak());

        let client_account = Arc::pin(account_testing::account2());
        let client_certificate = client_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let client_certificate = CertificateDer::from_slice(client_certificate.leak());

        let client_checked = Arc::new(Mutex::new(false));
        let client_checked2 = client_checked.clone();
        let client_account2 = client_account.clone();
        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert_eq!(
                    client_account2.public_key(),
                    request
                        .extensions()
                        .get::<ConnectionInfo>()
                        .unwrap()
                        .peer_public_key()
                );
                assert_eq!(
                    client_account2.address(),
                    request
                        .extensions()
                        .get::<ConnectionInfo>()
                        .unwrap()
                        .peer_account()
                        .address()
                );
                let mut client_checked = client_checked2.lock().unwrap();
                *client_checked = true;
                Ok(request)
            },
        );

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server_account2 = server_account.clone();
        let server = tokio::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, &*server_account2, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            future.await.unwrap();
        });
        start_client.notified().await;

        let (channel, connection_info) = connect_with_mtls(
            &*client_account,
            client_certificate,
            format!(
                "http://localhost:{}",
                listener.local_address().unwrap().port()
            )
            .parse()
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            server_account.public_key(),
            connection_info.peer_public_key()
        );
        assert_eq!(
            server_account.address(),
            connection_info.peer_account().address()
        );

        let mut client = NodeServiceV1Client::new(channel);
        client
            .get_identity(libernet::GetIdentityRequest::default())
            .await
            .unwrap();

        server.abort();
        assert!(*(client_checked.lock().unwrap()));
    }

    #[tokio::test]
    async fn test_invalid_server_certificate() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let server_not_after = now - Duration::from_secs(100);
        let client_not_after = now + Duration::from_secs(456);

        let server_account = Arc::pin(account_testing::account1());
        let server_certificate = server_account
            .generate_ssl_certificate(not_before, server_not_after)
            .unwrap();
        let server_certificate = CertificateDer::from_slice(server_certificate.leak());

        let client_account = account_testing::account2();
        let client_certificate = client_account
            .generate_ssl_certificate(not_before, client_not_after)
            .unwrap();
        let client_certificate = CertificateDer::from_slice(client_certificate.leak());

        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert!(request.extensions().get::<ConnectionInfo>().is_none());
                Ok(request)
            },
        );

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server_account2 = server_account.clone();
        let server = tokio::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, &*server_account2, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            let _ = future.await;
        });
        start_client.notified().await;

        assert!(
            connect_with_mtls(
                &client_account,
                client_certificate,
                format!(
                    "http://localhost:{}",
                    listener.local_address().unwrap().port()
                )
                .parse()
                .unwrap(),
            )
            .await
            .is_err()
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_invalid_client_certificate() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let server_not_after = now + Duration::from_secs(456);
        let client_not_after = now - Duration::from_secs(100);

        let server_account = Arc::pin(account_testing::account1());
        let server_certificate = server_account
            .generate_ssl_certificate(not_before, server_not_after)
            .unwrap();
        let server_certificate = CertificateDer::from_slice(server_certificate.leak());

        let client_account = account_testing::account2();
        let client_certificate = client_account
            .generate_ssl_certificate(not_before, client_not_after)
            .unwrap();
        let client_certificate = CertificateDer::from_slice(client_certificate.leak());

        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert!(request.extensions().get::<ConnectionInfo>().is_none());
                Ok(request)
            },
        );

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server_account2 = server_account.clone();
        let server = tokio::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, &*server_account2, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            let _ = future.await;
        });
        start_client.notified().await;

        assert!(
            async {
                let (channel, connection_info) = connect_with_mtls(
                    &client_account,
                    client_certificate,
                    format!(
                        "http://localhost:{}",
                        listener.local_address().unwrap().port()
                    )
                    .parse()
                    .unwrap(),
                )
                .await?;
                assert_eq!(
                    server_account.public_key(),
                    connection_info.peer_public_key()
                );
                assert_eq!(
                    server_account.address(),
                    connection_info.peer_account().address()
                );
                let mut client = NodeServiceV1Client::new(channel);
                client
                    .get_identity(libernet::GetIdentityRequest::default())
                    .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await
            .is_err()
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_missing_client_certificate() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = Arc::pin(account_testing::account1());
        let server_certificate = server_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let server_certificate = CertificateDer::from_slice(server_certificate.leak());

        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert!(request.extensions().get::<ConnectionInfo>().is_none());
                Ok(request)
            },
        );

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server_account2 = server_account.clone();
        let server = tokio::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, &*server_account2, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            let _ = future.await;
        });
        start_client.notified().await;

        assert!(
            async {
                let channel = Channel::builder(
                    format!(
                        "http://localhost:{}",
                        listener.local_address().unwrap().port()
                    )
                    .parse()
                    .unwrap(),
                )
                .connect()
                .await?;
                let mut client = NodeServiceV1Client::new(channel);
                client
                    .get_identity(libernet::GetIdentityRequest::default())
                    .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await
            .is_err()
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_mock_connection() {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(123);
        let not_after = now + Duration::from_secs(456);

        let server_account = Arc::pin(account_testing::account1());
        let server_certificate = server_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let server_certificate = CertificateDer::from_slice(server_certificate.leak());

        let client_account = Arc::pin(account_testing::account2());
        let client_certificate = client_account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let client_certificate = CertificateDer::from_slice(client_certificate.leak());

        let client_checked = Arc::new(Mutex::new(false));
        let client_checked_ref = client_checked.clone();
        let client_account2 = client_account.clone();
        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert_eq!(
                    client_account2.public_key(),
                    request
                        .extensions()
                        .get::<ConnectionInfo>()
                        .unwrap()
                        .peer_public_key()
                );
                assert_eq!(
                    client_account2.address(),
                    request
                        .extensions()
                        .get::<ConnectionInfo>()
                        .unwrap()
                        .peer_account()
                        .address()
                );
                let mut client_checked = client_checked_ref.lock().unwrap();
                *client_checked = true;
                Ok(request)
            },
        );

        let (server_stream, client_stream) = tokio::io::duplex(4096);

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server_account2 = server_account.clone();
        let server = tokio::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(
                    Arc::new(testing::MockListener::new(server_stream)),
                    &*server_account2,
                    server_certificate,
                )
                .await
                .unwrap(),
            );
            server_ready.notify_one();
            future.await.unwrap();
        });
        start_client.notified().await;

        let (channel, connection_info) =
            testing::mock_connect_with_mtls(client_stream, &*client_account, client_certificate)
                .await
                .unwrap();
        assert_eq!(
            server_account.public_key(),
            connection_info.peer_public_key()
        );
        assert_eq!(
            server_account.address(),
            connection_info.peer_account().address()
        );

        let mut client = NodeServiceV1Client::new(channel);
        client
            .get_identity(libernet::GetIdentityRequest::default())
            .await
            .unwrap();

        server.abort();
        assert!(*(client_checked.lock().unwrap()));
    }
}
