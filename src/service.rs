use crate::account::Account;
use crate::clock::Clock;
use crate::db;
use crate::libernet::{self, node_service_v1_server::NodeServiceV1};
use crate::net;
use crate::proto;
use crate::tree::{self, AccountInfo};
use crate::version;
use anyhow::Context;
use blstrs::{G1Affine, Scalar};
use crypto::{signer::PartialVerifier, utils};
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

    fn get_client_public_key<M>(&self, request: &Request<M>) -> anyhow::Result<G1Affine> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_account().public_key())
    }

    fn get_client_account_address<M>(&self, request: &Request<M>) -> anyhow::Result<Scalar> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_account().address())
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

    async fn get_block_impl(
        &self,
        request: &libernet::GetBlockRequest,
    ) -> Result<db::BlockInfo, Status> {
        match &request.block_hash {
            Some(block_hash) => {
                let block_hash = proto::decode_scalar(block_hash)
                    .map_err(|_| Status::invalid_argument("invalid block hash"))?;
                self.db
                    .get_block_by_hash(block_hash)
                    .await
                    .context(format!(
                        "block hash {} not found",
                        utils::format_scalar(block_hash)
                    ))
                    .map_err(|error| Status::not_found(error.to_string()))
            }
            None => Ok(self.db.get_latest_block().await),
        }
    }

    async fn get_account_impl(
        &self,
        request: &libernet::GetAccountRequest,
    ) -> Result<(db::BlockInfo, tree::AccountProof), Status> {
        let account_address = proto::decode_scalar(
            request
                .account_address
                .as_ref()
                .context("missing account address field")
                .map_err(|error| Status::invalid_argument(error.to_string()))?,
        )
        .map_err(|_| Status::invalid_argument("invalid account address"))?;
        match &request.block_hash {
            Some(block_hash) => {
                let block_hash = proto::decode_scalar(&block_hash)
                    .map_err(|_| Status::invalid_argument("invalid block hash"))?;
                self.db
                    .get_account_info(account_address, block_hash)
                    .await
                    .map_err(|_| {
                        Status::not_found(format!(
                            "account address {} not found at block {}",
                            utils::format_scalar(account_address),
                            utils::format_scalar(block_hash)
                        ))
                    })
            }
            None => self
                .db
                .get_latest_account_info(account_address)
                .await
                .map_err(|_| {
                    Status::not_found(format!(
                        "account address {} not found",
                        utils::format_scalar(account_address)
                    ))
                }),
        }
    }

    async fn get_transaction_impl(
        &self,
        request: &libernet::GetTransactionRequest,
    ) -> Result<libernet::BoundTransaction, Status> {
        let transaction_hash = match &request.transaction_hash {
            Some(hash) => proto::decode_scalar(&hash)
                .map_err(|_| Status::invalid_argument("invalid transaction hash"))?,
            None => return Err(Status::invalid_argument("transaction hash field missing")),
        };
        match self.db.get_transaction(transaction_hash).await {
            Some(transaction) => Ok(libernet::BoundTransaction {
                parent_transaction_hash: Some(proto::encode_scalar(transaction.parent_hash())),
                transaction: Some(transaction.diff()),
            }),
            None => Err(Status::not_found(format!(
                "transaction hash {} not found",
                utils::format_scalar(transaction_hash)
            ))),
        }
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
        let block_info = self.inner.get_block_impl(request.get_ref()).await?;
        let descriptor = block_info.encode();
        let (payload, signature) = self
            .sign_message(&descriptor)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(libernet::GetBlockResponse {
            payload: Some(payload),
            signature: Some(signature),
        }))
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
        let (block_info, proof) = self.inner.get_account_impl(request.get_ref()).await?;
        let payload = proof
            .encode(block_info.encode())
            .map_err(|_| Status::internal("internal error"))?;
        let (payload, signature) = self
            .sign_message(&payload)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(libernet::GetAccountResponse {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn get_transaction(
        &self,
        request: Request<libernet::GetTransactionRequest>,
    ) -> Result<Response<libernet::GetTransactionResponse>, Status> {
        let transaction = self.inner.get_transaction_impl(request.get_ref()).await?;
        let (payload, signature) = self
            .sign_message(&transaction)
            .map_err(|_| Status::internal("internal error"))?;
        Ok(Response::new(libernet::GetTransactionResponse {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn broadcast_transaction(
        &self,
        request: Request<libernet::BroadcastTransactionRequest>,
    ) -> Result<Response<libernet::BroadcastTransactionResponse>, Status> {
        let transaction = match &request.get_ref().transaction {
            Some(transaction) => Ok(transaction),
            None => Err(Status::invalid_argument("missing transaction data")),
        }?;
        let payload = match &transaction.payload {
            Some(payload) => Ok(payload),
            None => Err(Status::invalid_argument("missing transaction payload")),
        }?;
        let signature = match &transaction.signature {
            Some(signature) => Ok(signature),
            None => Err(Status::invalid_argument("missing transaction signature")),
        }?;
        Account::verify_signed_message(payload, signature)
            .map_err(|_| Status::invalid_argument("invalid transaction signature"))?;
        self.inner
            .db
            .add_transaction(transaction)
            .await
            .map_err(|_| Status::internal("transaction error"))?;
        Ok(Response::new(libernet::BroadcastTransactionResponse {}))
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
    use primitive_types::H256;
    use rustls::pki_types::CertificateDer;
    use tokio::{sync::Notify, task::JoinHandle, task::yield_now};
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
            let now = SystemTime::now();
            let not_before = now - Duration::from_secs(123);
            let not_after = now + Duration::from_secs(456);

            let server_account = Arc::new(testing::account1());
            let server_certificate = server_account
                .generate_ssl_certificate(not_before, not_after)
                .unwrap();
            let server_certificate = CertificateDer::from_slice(server_certificate.leak());

            let client_account = Arc::new(testing::account2());
            let client_certificate = client_account
                .generate_ssl_certificate(not_before, not_after)
                .unwrap();
            let client_certificate = CertificateDer::from_slice(client_certificate.leak());

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
            let server_handle = tokio::spawn(async move {
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
                client_certificate,
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

    fn default_genesis_block_hash() -> Scalar {
        utils::parse_scalar("0x5eeae7a6b309c8843a8368e7c790df9929a161f2a6240c889877698fef62f4c7")
            .unwrap()
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

    #[tokio::test(start_paused = true)]
    async fn test_get_genesis_block() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_block(libernet::GetBlockRequest {
                block_hash: Some(proto::encode_scalar(default_genesis_block_hash())),
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = payload.to_msg::<libernet::BlockDescriptor>().unwrap();

        assert_eq!(
            proto::decode_scalar(&payload.block_hash.unwrap()).unwrap(),
            default_genesis_block_hash()
        );
        assert_eq!(payload.block_number.unwrap(), 0);
        assert_eq!(
            proto::decode_scalar(&payload.previous_block_hash.unwrap()).unwrap(),
            0.into()
        );
        assert_eq!(
            proto::decode_scalar(&payload.network_topology_root_hash.unwrap()).unwrap(),
            utils::parse_scalar(
                "0x4800c8c37ce52cacc52188a8ee04dec60f9a88ab5e930334a4165861e14656cb"
            )
            .unwrap()
        );
        assert_eq!(
            proto::decode_scalar(&payload.accounts_root_hash.unwrap()).unwrap(),
            utils::parse_scalar(
                "0x09d8fc5eccc46993858b47fb2da64d04118fac5ff0ce6664107550cab923c6a2"
            )
            .unwrap()
        );
        assert_eq!(
            proto::decode_scalar(&payload.program_storage_root_hash.unwrap()).unwrap(),
            utils::parse_scalar(
                "0x3c1316ed223e30eb6b4e6e2d2d2f13039301f08aee3ee06cc0a2318477a439e9"
            )
            .unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_latest_block_at_genesis() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_block(libernet::GetBlockRequest { block_hash: None })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = payload.to_msg::<libernet::BlockDescriptor>().unwrap();

        assert_eq!(
            proto::decode_scalar(&payload.block_hash.unwrap()).unwrap(),
            default_genesis_block_hash()
        );
        assert_eq!(payload.block_number.unwrap(), 0);
        assert_eq!(
            proto::decode_scalar(&payload.previous_block_hash.unwrap()).unwrap(),
            0.into()
        );
        assert_eq!(
            proto::decode_scalar(&payload.network_topology_root_hash.unwrap()).unwrap(),
            utils::parse_scalar(
                "0x4800c8c37ce52cacc52188a8ee04dec60f9a88ab5e930334a4165861e14656cb"
            )
            .unwrap()
        );
        assert_eq!(
            proto::decode_scalar(&payload.accounts_root_hash.unwrap()).unwrap(),
            utils::parse_scalar(
                "0x09d8fc5eccc46993858b47fb2da64d04118fac5ff0ce6664107550cab923c6a2"
            )
            .unwrap()
        );
        assert_eq!(
            proto::decode_scalar(&payload.program_storage_root_hash.unwrap()).unwrap(),
            utils::parse_scalar(
                "0x3c1316ed223e30eb6b4e6e2d2d2f13039301f08aee3ee06cc0a2318477a439e9"
            )
            .unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_unknown_block() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_block(libernet::GetBlockRequest {
                    block_hash: Some(proto::encode_scalar(
                        utils::parse_scalar(
                            "0x375830d6862157562431f637dcb4aa91e2bba7220abfa58b7618a713e9bb8803"
                        )
                        .unwrap()
                    )),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_default_initial_account_balance() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let account = testing::account3();

        let response = client
            .get_account(libernet::GetAccountRequest {
                account_address: Some(proto::encode_scalar(account.address())),
                block_hash: Some(proto::encode_scalar(default_genesis_block_hash())),
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = payload.to_msg::<libernet::MerkleProof>().unwrap();

        let block_info = db::BlockInfo::decode(payload.block_descriptor.as_ref().unwrap()).unwrap();
        assert_eq!(block_info.hash(), default_genesis_block_hash());

        let proof =
            tree::AccountProof::decode_and_verify(&payload, block_info.accounts_root_hash())
                .unwrap();
        assert_eq!(proof.key(), account.address());
        assert_eq!(*proof.value(), AccountInfo::with_balance(0.into()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_latest_account_balance_at_genesis() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let account = testing::account3();

        let response = client
            .get_account(libernet::GetAccountRequest {
                account_address: Some(proto::encode_scalar(account.address())),
                block_hash: None,
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = payload.to_msg::<libernet::MerkleProof>().unwrap();

        let block_info = db::BlockInfo::decode(payload.block_descriptor.as_ref().unwrap()).unwrap();
        assert_eq!(block_info.hash(), default_genesis_block_hash());

        let proof =
            tree::AccountProof::decode_and_verify(&payload, block_info.accounts_root_hash())
                .unwrap();
        assert_eq!(proof.key(), account.address());
        assert_eq!(*proof.value(), AccountInfo::with_balance(0.into()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_initial_account_state() {
        let account = testing::account3();

        let mut fixture = TestFixture::with_initial_balances([(account.address(), 123.into())])
            .await
            .unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_account(libernet::GetAccountRequest {
                account_address: Some(proto::encode_scalar(account.address())),
                block_hash: None,
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = payload.to_msg::<libernet::MerkleProof>().unwrap();

        let block_info = db::BlockInfo::decode(payload.block_descriptor.as_ref().unwrap()).unwrap();
        assert_eq!(
            block_info.hash(),
            utils::parse_scalar(
                "0x1abcdbb5ac82d5e17d8ae4f9b83da68e8b636e1c736be3a4691254911c18c7a1"
            )
            .unwrap()
        );

        let proof =
            tree::AccountProof::decode_and_verify(&payload, block_info.accounts_root_hash())
                .unwrap();
        assert_eq!(proof.key(), account.address());
        assert_eq!(*proof.value(), AccountInfo::with_balance(123.into()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_invalid_account_balance1() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_account(libernet::GetAccountRequest {
                    account_address: None,
                    block_hash: Some(proto::encode_scalar(default_genesis_block_hash())),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_invalid_account_balance2() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_account(libernet::GetAccountRequest {
                    account_address: None,
                    block_hash: None,
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_invalid_transaction_lookup() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_transaction(libernet::GetTransactionRequest {
                    transaction_hash: None,
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_unknown_transaction() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_transaction(libernet::GetTransactionRequest {
                    transaction_hash: Some(proto::encode_h256(H256::zero())),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_closure() {
        let mut fixture = TestFixture::default().await.unwrap();

        let response = fixture
            .client
            .get_block(libernet::GetBlockRequest { block_hash: None })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = &payload.to_msg::<libernet::BlockDescriptor>().unwrap();
        assert_eq!(payload.block_number.unwrap(), 0);
        assert_eq!(
            proto::decode_scalar(payload.block_hash.as_ref().unwrap()).unwrap(),
            default_genesis_block_hash()
        );

        fixture.clock().advance(Duration::from_secs(10)).await;
        yield_now().await;

        let response = fixture
            .client
            .get_block(libernet::GetBlockRequest { block_hash: None })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            Account::verify_signed_message(&payload, response.signature.as_ref().unwrap()).is_ok()
        );
        let payload = &payload.to_msg::<libernet::BlockDescriptor>().unwrap();
        assert_eq!(payload.block_number.unwrap(), 1);
        assert_eq!(
            proto::decode_scalar(payload.block_hash.as_ref().unwrap()).unwrap(),
            utils::parse_scalar(
                "0x170e647bfa7c9d1361c4554ed6ef02bef36033701cea301123d8c405aa05bc95"
            )
            .unwrap()
        );
    }
}
