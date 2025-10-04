use crate::account::Account;
use crate::ssl;
use anyhow::Context;
use blstrs::{G1Affine, Scalar};
use crypto::utils;
use hyper::rt::{Read, ReadBufCursor, Write};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::{
    io::AsyncRead, io::AsyncWrite, io::ReadBuf, net::TcpListener, net::TcpStream,
    net::ToSocketAddrs,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use tonic::transport::server::Connected;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    peer_certificate: rustls::pki_types::CertificateDer<'static>,
    peer_public_key: G1Affine,
}

impl ConnectionInfo {
    fn new(
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> anyhow::Result<ConnectionInfo> {
        let (_, parsed_certificate) =
            x509_parser::parse_x509_certificate(peer_certificate.as_ref())?;
        let peer_public_key = ssl::recover_bls_public_key(&parsed_certificate)?;
        Ok(Self {
            peer_certificate,
            peer_public_key,
        })
    }

    pub fn peer_certificate(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.peer_certificate.clone()
    }

    pub fn peer_public_key(&self) -> G1Affine {
        self.peer_public_key
    }

    pub fn peer_wallet_address(&self) -> Scalar {
        utils::hash_g1_to_scalar(self.peer_public_key)
    }
}

pub struct TlsServerStreamAdapter<IO: AsyncRead + AsyncWrite + Unpin> {
    info: ConnectionInfo,
    inner: server::TlsStream<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsServerStreamAdapter<IO> {
    pub fn new(
        inner_stream: server::TlsStream<IO>,
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
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
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
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
) -> std::io::Result<rustls::pki_types::CertificateDer<'static>> {
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
        account: Arc<Account>,
        certificate: Arc<rcgen::Certificate>,
    ) -> anyhow::Result<Self> {
        // TODO
        todo!()
    }
}

// TODO

#[cfg(test)]
pub mod testing {
    use super::*;
    use futures::future;
    use std::sync::Mutex;
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

    // TODO
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
