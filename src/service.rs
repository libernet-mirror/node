use crate::account::Account;
use crate::clock::Clock;
use crate::db;
use crate::libernet::{self, node_service_v1_server::NodeServiceV1};
use crate::proto;
use crate::tree::AccountInfo;
use crate::version;
use blstrs::Scalar;
use crypto::utils;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::{time::Duration, time::sleep};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

pub struct NodeServiceImpl {
    account: Arc<Account>,
    identity: libernet::node_identity::Payload,
    db: db::Db,
    cancel: CancellationToken,
}

impl NodeServiceImpl {
    fn get_protocol_version() -> libernet::ProtocolVersion {
        libernet::ProtocolVersion {
            major: Some(version::PROTOCOL_VERSION_MAJOR),
            minor: Some(version::PROTOCOL_VERSION_MINOR),
            build: Some(version::PROTOCOL_VERSION_BUILD),
        }
    }

    fn make_node_identity(
        chain_id: u64,
        timestamp: SystemTime,
        account: &Account,
        location: libernet::GeographicalLocation,
        public_address: &str,
        grpc_port: u16,
        http_port: u16,
    ) -> libernet::node_identity::Payload {
        libernet::node_identity::Payload {
            protocol_version: Some(Self::get_protocol_version()),
            chain_id: Some(chain_id),
            account_address: Some(proto::encode_scalar(account.address())),
            location: Some(location),
            network_address: Some(public_address.to_owned()),
            grpc_port: Some(grpc_port.into()),
            http_port: Some(http_port.into()),
            timestamp: Some(timestamp.into()),
        }
    }

    fn new<const N: usize>(
        clock: Arc<dyn Clock>,
        account: Arc<Account>,
        location: libernet::GeographicalLocation,
        chain_id: u64,
        public_address: &str,
        initial_accounts: [(Scalar, AccountInfo); N],
        grpc_port: u16,
        http_port: u16,
    ) -> anyhow::Result<Arc<Self>> {
        println!("Public key: {}", utils::format_g1(account.public_key()));
        println!(
            "Public key (Ed25519): {}",
            utils::format_point_25519(account.ed25519_public_key())
        );
        println!(
            "Wallet address: {}",
            utils::format_scalar(account.address())
        );
        let identity = Self::make_node_identity(
            chain_id,
            clock.now(),
            &*account,
            location,
            public_address,
            grpc_port,
            http_port,
        );
        let (identity_payload, identity_signature) = account.sign_message(&identity)?;
        let service = Arc::new(Self {
            account,
            identity,
            db: db::Db::new(
                clock,
                chain_id,
                libernet::NodeIdentity {
                    payload: Some(identity_payload),
                    signature: Some(identity_signature),
                },
                initial_accounts,
            )?,
            cancel: CancellationToken::new(),
        });
        service.clone().start_block_timer();
        Ok(service)
    }

    fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> anyhow::Result<(prost_types::Any, libernet::Signature)> {
        self.account.sign_message(message)
    }

    fn start_block_timer(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sleep(Duration::from_secs(10)) => {
                        let block = self.db.close_block().await;
                        println!("mined block {}: {}", block.number(), utils::format_scalar(block.hash()));
                    },
                    _ = self.cancel.cancelled() => {
                        break;
                    },
                }
            }
        });
    }
}

impl Drop for NodeServiceImpl {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct NodeService {
    inner: Arc<NodeServiceImpl>,
}

impl NodeService {
    pub fn new<const N: usize>(
        clock: Arc<dyn Clock>,
        account: Arc<Account>,
        location: libernet::GeographicalLocation,
        chain_id: u64,
        public_address: &str,
        initial_accounts: [(Scalar, AccountInfo); N],
        grpc_port: u16,
        http_port: u16,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: NodeServiceImpl::new(
                clock,
                account,
                location,
                chain_id,
                public_address,
                initial_accounts,
                grpc_port,
                http_port,
            )?,
        })
    }

    fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> anyhow::Result<(prost_types::Any, libernet::Signature)> {
        self.inner.sign_message(message)
    }
}

#[tonic::async_trait]
impl NodeServiceV1 for NodeService {
    async fn get_identity(
        &self,
        _request: Request<libernet::GetIdentityRequest>,
    ) -> Result<Response<libernet::NodeIdentity>, Status> {
        let (payload, signature) = self
            .sign_message(&self.inner.identity)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(libernet::NodeIdentity {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn get_block(
        &self,
        request: Request<libernet::GetBlockRequest>,
    ) -> Result<Response<libernet::GetBlockResponse>, Status> {
        // TODO
        todo!()
    }

    async fn get_topology(
        &self,
        _request: Request<libernet::GetTopologyRequest>,
    ) -> Result<Response<libernet::NetworkTopology>, Status> {
        // TODO
        todo!()
    }

    async fn get_account(
        &self,
        request: Request<libernet::GetAccountRequest>,
    ) -> Result<Response<libernet::GetAccountResponse>, Status> {
        // TODO
        todo!()
    }

    async fn get_transaction(
        &self,
        request: Request<libernet::GetTransactionRequest>,
    ) -> Result<Response<libernet::GetTransactionResponse>, Status> {
        // TODO
        todo!()
    }

    async fn broadcast_transaction(
        &self,
        request: Request<libernet::BroadcastTransactionRequest>,
    ) -> Result<Response<libernet::BroadcastTransactionResponse>, Status> {
        // TODO
        todo!()
    }

    async fn broadcast_new_block(
        &self,
        _request: Request<libernet::BroadcastBlockRequest>,
    ) -> Result<Response<libernet::BroadcastBlockResponse>, Status> {
        // TODO
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::testing;
    use crate::clock::testing::MockClock;
    use crate::libernet::{
        node_service_v1_client::NodeServiceV1Client, node_service_v1_server::NodeServiceV1Server,
    };
    use crate::net;
    use crate::ssl;
    use tokio::{sync::Notify, task::JoinHandle};
    use tonic::transport::{Channel, Server};

    const TEST_CHAIN_ID: u64 = 42;

    struct TestFixture {
        clock: Arc<MockClock>,
        server_account: Arc<Account>,
        client_account: Arc<Account>,
        server_handle: JoinHandle<()>,
        client: NodeServiceV1Client<Channel>,
    }

    impl TestFixture {
        async fn new<const N: usize>(
            location: libernet::GeographicalLocation,
            initial_accounts: [(Scalar, AccountInfo); N],
        ) -> anyhow::Result<Self> {
            let server_account = Arc::new(testing::account1());
            let server_certificate = Arc::new(
                ssl::generate_certificate(&*server_account, vec!["server".to_string()]).unwrap(),
            );

            let client_account = Arc::new(testing::account2());
            let client_certificate = Arc::new(
                ssl::generate_certificate(&*client_account, vec!["client".to_string()]).unwrap(),
            );

            let clock: Arc<MockClock> = Arc::new(MockClock::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            ));

            let service = NodeServiceV1Server::new(
                NodeService::new(
                    clock.clone(),
                    server_account.clone(),
                    location,
                    TEST_CHAIN_ID,
                    "localhost",
                    initial_accounts,
                    4443,
                    8080,
                )
                .unwrap(),
            );

            let (server_stream, client_stream) = tokio::io::duplex(4096);

            let server_ready = Arc::new(Notify::new());
            let start_client = server_ready.clone();
            let server_account2 = server_account.clone();
            let server_handle = tokio::task::spawn(async move {
                let future = Server::builder().add_service(service).serve_with_incoming(
                    net::IncomingWithMTls::new(
                        Arc::new(net::testing::MockListener::new(server_stream)),
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

            let (channel, _) = net::testing::mock_connect_with_mtls(
                client_stream,
                &*client_account,
                client_certificate.clone(),
            )
            .await
            .unwrap();
            let client = NodeServiceV1Client::new(channel);

            Ok(Self {
                clock,
                server_account,
                client_account,
                server_handle,
                client,
            })
        }

        async fn with_initial_balances<const N: usize>(
            initial_balances: [(Scalar, Scalar); N],
        ) -> anyhow::Result<Self> {
            Self::new(
                libernet::GeographicalLocation {
                    latitude: Some(71i32),
                    longitude: Some(104u32),
                },
                initial_balances
                    .map(|(address, balance)| (address, AccountInfo::with_balance(balance))),
            )
            .await
        }

        async fn default() -> anyhow::Result<Self> {
            Self::with_initial_balances([]).await
        }

        fn clock(&self) -> &Arc<MockClock> {
            &self.clock
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            self.server_handle.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_identity() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_identity(libernet::GetIdentityRequest::default())
            .await
            .unwrap();
        let identity = response.get_ref();
        let payload = identity.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(payload, identity.signature.as_ref().unwrap()).is_ok()
        );
        let payload = payload
            .to_msg::<libernet::node_identity::Payload>()
            .unwrap();

        let protocol_version = &payload.protocol_version.unwrap();
        assert_eq!(
            protocol_version.major.unwrap(),
            version::PROTOCOL_VERSION_MAJOR
        );
        assert_eq!(
            protocol_version.minor.unwrap(),
            version::PROTOCOL_VERSION_MINOR
        );
        assert_eq!(
            protocol_version.build.unwrap(),
            version::PROTOCOL_VERSION_BUILD
        );

        assert_eq!(
            proto::decode_scalar(&payload.account_address.unwrap()).unwrap(),
            fixture.server_account.address()
        );

        let location = &payload.location.unwrap();
        assert_eq!(location.latitude.unwrap(), 71i32);
        assert_eq!(location.longitude.unwrap(), 104u32);

        assert_eq!(payload.network_address.unwrap(), "localhost");
        assert_eq!(payload.grpc_port.unwrap(), 4443u32);
        assert_eq!(payload.http_port.unwrap(), 8080u32);
    }

    // TODO
}
