use crate::account::Account;
use crate::clock::Clock;
use crate::constants::{
    self, BLOCK_REWARD_DENOMINATOR_LOG2, BLOCK_REWARD_NUMERATOR, BLOCK_TIME_MS,
};
use crate::data;
use crate::db;
use crate::libernet::{self, node_service_v1_server::NodeServiceV1};
use crate::net;
use crate::proto;
use anyhow::Context;
use blstrs::{G1Affine, Scalar};
use crypto::{signer::BlsVerifier, utils};
use futures::{Stream, stream::unfold};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::SystemTime;
use tokio::{time::Duration, time::sleep};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

pub struct SubscribeToBlocksStream {
    inner: Pin<
        Box<dyn Stream<Item = Result<libernet::BlockSubscriptionResponse, Status>> + Send + Sync>,
    >,
}

impl SubscribeToBlocksStream {
    pub async fn new(db: Arc<db::Db>) -> Self {
        Self {
            inner: Box::pin(unfold(
                db.listen_to_blocks().await,
                |mut receiver| async move {
                    receiver.recv().await.map(|block| {
                        (
                            Ok(libernet::BlockSubscriptionResponse {
                                block_descriptor: vec![block.encode()],
                            }),
                            receiver,
                        )
                    })
                },
            )),
        }
    }
}

impl Stream for SubscribeToBlocksStream {
    type Item = Result<libernet::BlockSubscriptionResponse, Status>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

pub struct SubscribeToAccountStream {
    inner: Pin<
        Box<dyn Stream<Item = Result<libernet::AccountSubscriptionResponse, Status>> + Send + Sync>,
    >,
}

impl SubscribeToAccountStream {
    fn encode_account(
        account_state: &db::AccountState,
    ) -> Result<libernet::AccountSubscriptionResponse, Status> {
        Ok(libernet::AccountSubscriptionResponse {
            account_proof: vec![
                account_state
                    .encode()
                    .map_err(|_| Status::internal("encoding error"))?,
            ],
        })
    }

    pub async fn new(db: Arc<db::Db>, account_address: Scalar, every_block: bool) -> Self {
        Self {
            inner: Box::pin(unfold(
                if every_block {
                    db.watch_account(account_address).await
                } else {
                    db.listen_for_account_changes(account_address).await
                },
                |mut receiver| async move {
                    receiver
                        .recv()
                        .await
                        .map(|account_state| (Self::encode_account(&account_state), receiver))
                },
            )),
        }
    }
}

impl Stream for SubscribeToAccountStream {
    type Item = Result<libernet::AccountSubscriptionResponse, Status>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

pub struct NodeServiceImpl {
    chain_id: u64,
    account: Arc<Account>,
    identity: libernet::node_identity::Payload,
    db: Arc<db::Db>,
    cancel: CancellationToken,
}

impl NodeServiceImpl {
    fn get_protocol_version() -> libernet::ProtocolVersion {
        libernet::ProtocolVersion {
            major: Some(constants::PROTOCOL_VERSION_MAJOR),
            minor: Some(constants::PROTOCOL_VERSION_MINOR),
            build: Some(constants::PROTOCOL_VERSION_BUILD),
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

    fn new(
        clock: Arc<dyn Clock>,
        account: Arc<Account>,
        location: libernet::GeographicalLocation,
        chain_id: u64,
        public_address: &str,
        initial_accounts: &[(Scalar, data::AccountInfo)],
        grpc_port: u16,
        http_port: u16,
    ) -> anyhow::Result<Arc<Self>> {
        println!("Public key: {}", utils::format_g1(account.public_key()));
        println!(
            "Account address: {}",
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
            chain_id,
            account,
            identity,
            db: Arc::new(db::Db::new(
                clock,
                chain_id,
                libernet::NodeIdentity {
                    payload: Some(identity_payload),
                    signature: Some(identity_signature),
                },
                initial_accounts,
            )?),
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

    async fn add_block_rewards(&self) {
        let account = self
            .db
            .get_latest_account_info(self.account.address())
            .await
            .unwrap();
        let account = account.account_info();
        let reward = (account.staking_balance * Scalar::from(BLOCK_REWARD_NUMERATOR))
            .shr(BLOCK_REWARD_DENOMINATOR_LOG2 as usize)
            - account.staking_balance;
        self.db
            .add_transaction(
                data::Transaction::make_block_reward_proto(
                    &*self.account,
                    self.chain_id,
                    account.last_nonce + 1,
                    self.account.address(),
                    reward,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }

    fn start_block_timer(self: Arc<Self>) {
        tokio::spawn(async move {
            println!(
                "genesis block hash: {}",
                utils::format_scalar(self.db.get_latest_block().await.hash())
            );
            loop {
                self.add_block_rewards().await;
                tokio::select! {
                    _ = sleep(Duration::from_millis(BLOCK_TIME_MS)) => {
                        let block = self.db.close_block().await;
                        println!("added block {}: {}", block.number(), utils::format_scalar(block.hash()));
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
    ) -> Result<data::BlockInfo, Status> {
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

    async fn subscribe_to_blocks_impl(&self) -> SubscribeToBlocksStream {
        SubscribeToBlocksStream::new(self.db.clone()).await
    }

    async fn get_account_impl(
        &self,
        request: &libernet::GetAccountRequest,
    ) -> Result<db::AccountState, Status> {
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
                let block_hash = proto::decode_scalar(block_hash)
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

    async fn subscribe_to_account_impl(
        &self,
        request: &libernet::AccountSubscriptionRequest,
    ) -> Result<SubscribeToAccountStream, Status> {
        let account_address = proto::decode_scalar(
            request
                .account_address
                .as_ref()
                .context("missing account address field")
                .map_err(|error| Status::invalid_argument(error.to_string()))?,
        )
        .map_err(|_| Status::invalid_argument("invalid account address"))?;
        let every_block = request.every_block();
        Ok(SubscribeToAccountStream::new(self.db.clone(), account_address, every_block).await)
    }

    async fn get_transaction_impl(
        &self,
        request: &libernet::GetTransactionRequest,
    ) -> Result<libernet::MerkleProof, Status> {
        let hash = proto::decode_scalar(
            request
                .transaction_hash
                .as_ref()
                .context("transaction hash field missing")
                .map_err(|error| Status::invalid_argument(error.to_string()))?,
        )
        .map_err(|_| Status::invalid_argument("invalid transaction hash"))?;
        let (block_info, proof) = self
            .db
            .get_transaction(hash)
            .await
            .context("transaction not found")
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        proof
            .encode(block_info.encode())
            .map_err(|_| Status::internal("encoding error"))
    }

    async fn get_all_block_transaction_hashes(
        &self,
        block_number: u64,
    ) -> Result<Vec<libernet::Scalar>, Status> {
        Ok(self
            .db
            .get_all_block_transaction_hashes(block_number as usize)
            .await
            .map_err(|_| Status::internal("unable to fetch transaction hashes"))?
            .into_iter()
            .map(proto::encode_scalar)
            .collect())
    }

    async fn query_transactions_impl(
        &self,
        request: libernet::QueryTransactionsRequest,
    ) -> Result<Vec<libernet::MerkleProof>, Status> {
        let signer = request.from_filter.map(|address| {
            proto::decode_scalar(&address)
                .map_err(|_| Status::invalid_argument("invalid `from` filter"))
        });
        let recipient = request.to_filter.map(|address| {
            proto::decode_scalar(&address)
                .map_err(|_| Status::invalid_argument("invalid `to` filter"))
        });
        let sort_order = match request.sort_order.map(|sort_order| {
            libernet::query_transactions_request::SortOrder::try_from(sort_order)
                .map_err(|_| Status::invalid_argument("invalid sort order"))
        }) {
            Some(Ok(
                libernet::query_transactions_request::SortOrder::TransactionSortOrderAscending,
            )) => Ok(db::SortOrder::Ascending),
            Some(Ok(
                libernet::query_transactions_request::SortOrder::TransactionSortOrderDescending,
            )) => Ok(db::SortOrder::Descending),
            Some(Err(status)) => Err(status),
            None => Ok(db::SortOrder::Descending),
        }?;
        let max_count = match request.max_count {
            Some(max_count) => max_count as usize,
            None => usize::MAX,
        };
        let start_block = match request.start_block_filter {
            Some(libernet::query_transactions_request::StartBlockFilter::StartBlockHash(
                block_hash,
            )) => Some(db::BlockFilter::BlockHash(
                proto::decode_scalar(&block_hash).map_err(|_| {
                    Status::invalid_argument("invalid block hash in start block filter")
                })?,
            )),
            Some(libernet::query_transactions_request::StartBlockFilter::StartBlockNumber(
                block_number,
            )) => Some(db::BlockFilter::BlockNumber(block_number as usize)),
            None => None,
        };
        let end_block = match request.end_block_filter {
            Some(libernet::query_transactions_request::EndBlockFilter::EndBlockHash(
                block_hash,
            )) => Some(db::BlockFilter::BlockHash(
                proto::decode_scalar(&block_hash).map_err(|_| {
                    Status::invalid_argument("invalid block hash in end block filter")
                })?,
            )),
            Some(libernet::query_transactions_request::EndBlockFilter::EndBlockNumber(
                block_number,
            )) => Some(db::BlockFilter::BlockNumber(block_number as usize)),
            None => None,
        };
        let results = match (signer, recipient) {
            (None, None) => self
                .db
                .query_transactions(start_block, end_block, sort_order, max_count)
                .await
                .map_err(|_| Status::aborted("query error"))?,
            (Some(signer), None) => self
                .db
                .query_transactions_from(signer?, start_block, end_block, sort_order, max_count)
                .await
                .map_err(|_| Status::aborted("query error"))?,
            (None, Some(recipient)) => self
                .db
                .query_transactions_to(recipient?, start_block, end_block, sort_order, max_count)
                .await
                .map_err(|_| Status::aborted("query error"))?,
            (Some(signer), Some(recipient)) => self
                .db
                .query_transactions_between(
                    signer?,
                    recipient?,
                    start_block,
                    end_block,
                    sort_order,
                    max_count,
                )
                .await
                .map_err(|_| Status::aborted("query error"))?,
        };
        results
            .encode()
            .map_err(|_| Status::internal("internal error"))
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
    pub fn new(
        clock: Arc<dyn Clock>,
        account: Arc<Account>,
        location: libernet::GeographicalLocation,
        chain_id: u64,
        public_address: &str,
        initial_accounts: &[(Scalar, data::AccountInfo)],
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
        let request = request.into_inner();
        let block_info = self.inner.get_block_impl(&request).await?;
        let transaction_hashes = if request.get_all_transaction_hashes() {
            self.inner
                .get_all_block_transaction_hashes(block_info.number())
                .await?
        } else {
            vec![]
        };
        Ok(Response::new(libernet::GetBlockResponse {
            block_descriptor: Some(block_info.encode()),
            transaction_hash: transaction_hashes,
        }))
    }

    type SubscribeToBlocksStream = SubscribeToBlocksStream;

    async fn subscribe_to_blocks(
        &self,
        _request: Request<libernet::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::SubscribeToBlocksStream>, Status> {
        Ok(Response::new(self.inner.subscribe_to_blocks_impl().await))
    }

    async fn get_topology(
        &self,
        _request: Request<libernet::GetTopologyRequest>,
    ) -> Result<Response<libernet::NetworkTopology>, Status> {
        // TODO
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn get_account(
        &self,
        request: Request<libernet::GetAccountRequest>,
    ) -> Result<Response<libernet::GetAccountResponse>, Status> {
        let account = self.inner.get_account_impl(request.get_ref()).await?;
        let proof_proto = account
            .encode()
            .map_err(|_| Status::internal("internal error"))?;
        Ok(Response::new(libernet::GetAccountResponse {
            account_proof: Some(proof_proto),
        }))
    }

    type SubscribeToAccountStream = SubscribeToAccountStream;

    async fn subscribe_to_account(
        &self,
        request: Request<libernet::AccountSubscriptionRequest>,
    ) -> Result<Response<Self::SubscribeToAccountStream>, Status> {
        Ok(Response::new(
            self.inner
                .subscribe_to_account_impl(request.get_ref())
                .await?,
        ))
    }

    async fn get_transaction(
        &self,
        request: Request<libernet::GetTransactionRequest>,
    ) -> Result<Response<libernet::GetTransactionResponse>, Status> {
        Ok(Response::new(libernet::GetTransactionResponse {
            transaction_proof: Some(self.inner.get_transaction_impl(request.get_ref()).await?),
        }))
    }

    async fn query_transactions(
        &self,
        request: Request<libernet::QueryTransactionsRequest>,
    ) -> Result<Response<libernet::QueryTransactionsResponse>, Status> {
        Ok(Response::new(libernet::QueryTransactionsResponse {
            transaction_proofs: Some(
                libernet::query_transactions_response::TransactionProofs::IndividualProofs(
                    libernet::query_transactions_response::IndividualProofs {
                        individual_proof: self
                            .inner
                            .query_transactions_impl(request.into_inner())
                            .await?,
                    },
                ),
            ),
        }))
    }

    async fn broadcast_transaction(
        &self,
        request: Request<libernet::BroadcastTransactionRequest>,
    ) -> Result<Response<libernet::BroadcastTransactionResponse>, Status> {
        let transaction = match request.into_inner().transaction {
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
            .add_transaction_blocking_rewards(transaction)
            .await
            .map_err(|_| Status::internal("transaction error"))?;
        Ok(Response::new(libernet::BroadcastTransactionResponse {}))
    }

    async fn broadcast_new_block(
        &self,
        _request: Request<libernet::BroadcastBlockRequest>,
    ) -> Result<Response<libernet::BroadcastBlockResponse>, Status> {
        // TODO
        Err(Status::unimplemented("not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::testing;
    use crate::clock::testing::MockClock;
    use crate::data::{Transaction, TransactionInclusionProof, TransactionTree};
    use crate::libernet::{
        node_service_v1_client::NodeServiceV1Client, node_service_v1_server::NodeServiceV1Server,
    };
    use crate::net;
    use crate::testing::parse_scalar;
    use anyhow::{Result, anyhow};
    use futures::StreamExt;
    use tokio::{sync::Mutex, sync::Notify, task::JoinHandle, task::yield_now};
    use tonic::transport::{Channel, Server};

    const COIN_UNIT: u64 = 1_000_000_000_000_000_000u64;

    const TEST_CHAIN_ID: u64 = 42;

    fn coins(number: u64) -> Scalar {
        Scalar::from(number) * Scalar::from(COIN_UNIT)
    }

    fn reward_for(stake: Scalar) -> Scalar {
        (stake * Scalar::from(BLOCK_REWARD_NUMERATOR)).shr(BLOCK_REWARD_DENOMINATOR_LOG2 as usize)
            - stake
    }

    struct TestFixture {
        clock: Arc<MockClock>,
        server_account: Arc<Account>,
        client_account: Arc<Account>,
        server_handle: JoinHandle<()>,
        client: Mutex<NodeServiceV1Client<Channel>>,
    }

    impl TestFixture {
        async fn new(
            location: libernet::GeographicalLocation,
            initial_accounts: &[(Scalar, data::AccountInfo)],
        ) -> Result<Self> {
            let now = SystemTime::now();
            let not_before = now - Duration::from_secs(123);
            let not_after = now + Duration::from_secs(456);

            let server_account = Arc::new(testing::account1());
            let client_account = Arc::new(testing::account2());

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
                        server_account2
                            .generate_ed25519_certified_key(not_before, not_after, Some("fake"))
                            .unwrap(),
                        server_account2
                            .generate_ecdsa_certified_key(not_before, not_after, Some("fake"))
                            .unwrap(),
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
                client_account
                    .generate_ed25519_certified_key(not_before, not_after, None)
                    .unwrap(),
                client_account
                    .generate_ecdsa_certified_key(not_before, not_after, None)
                    .unwrap(),
            )
            .await
            .unwrap();
            let client = Mutex::new(NodeServiceV1Client::new(channel));

            Ok(Self {
                clock,
                server_account,
                client_account,
                server_handle,
                client,
            })
        }

        async fn default() -> Result<Self> {
            let address1 = testing::account1().address();
            let address2 = testing::account2().address();
            let address3 = testing::account3().address();
            let address4 = testing::account4().address();
            Self::new(
                libernet::GeographicalLocation {
                    latitude: Some(71i32),
                    longitude: Some(104u32),
                },
                &[
                    (
                        address1,
                        data::AccountInfo {
                            last_nonce: 12,
                            balance: coins(90),
                            staking_balance: coins(78),
                        },
                    ),
                    (
                        address2,
                        data::AccountInfo {
                            last_nonce: 34,
                            balance: coins(56),
                            staking_balance: 0.into(),
                        },
                    ),
                    (
                        address3,
                        data::AccountInfo {
                            last_nonce: 56,
                            balance: coins(34),
                            staking_balance: 0.into(),
                        },
                    ),
                    (
                        address4,
                        data::AccountInfo {
                            last_nonce: 78,
                            balance: coins(12),
                            staking_balance: 0.into(),
                        },
                    ),
                ],
            )
            .await
        }

        fn clock(&self) -> &Arc<MockClock> {
            &self.clock
        }

        async fn advance_to_next_block(&self) {
            self.clock
                .advance(Duration::from_millis(BLOCK_TIME_MS))
                .await;
            yield_now().await;
        }

        async fn get_block(&self, block_hash: Option<Scalar>) -> Result<data::BlockInfo> {
            let response = self
                .client
                .lock()
                .await
                .get_block(libernet::GetBlockRequest {
                    block_hash: block_hash.map(proto::encode_scalar),
                    get_all_transaction_hashes: Some(false),
                })
                .await?;
            let block_descriptor = response
                .get_ref()
                .block_descriptor
                .as_ref()
                .context("missing block descriptor")?;
            Ok(data::BlockInfo::decode(block_descriptor)?)
        }

        async fn get_block_and_transactions(
            &self,
            block_hash: Option<Scalar>,
        ) -> Result<(data::BlockInfo, Vec<data::Transaction>)> {
            let response = self
                .client
                .lock()
                .await
                .get_block(libernet::GetBlockRequest {
                    block_hash: block_hash.map(proto::encode_scalar),
                    get_all_transaction_hashes: Some(true),
                })
                .await?
                .into_inner();
            let block_descriptor = response
                .block_descriptor
                .as_ref()
                .context("missing block descriptor")?;
            let tasks = response
                .transaction_hash
                .iter()
                .map(async |hash| {
                    Ok::<_, anyhow::Error>(self.get_transaction(proto::decode_scalar(hash)?).await?)
                })
                .collect::<Vec<_>>();
            let block_info = data::BlockInfo::decode(block_descriptor)?;
            let transactions = futures::future::try_join_all(tasks).await?;
            let mut transaction_tree = TransactionTree::default();
            for i in 0..transactions.len() {
                transaction_tree =
                    transaction_tree.put(Scalar::from(i as u64), transactions[i].hash());
            }
            if transaction_tree.root_hash() != block_info.transactions_root_hash() {
                return Err(anyhow!(
                    "incorrect transactions root hash (got {}, want {})",
                    transaction_tree.root_hash(),
                    block_info.transactions_root_hash()
                ));
            }
            Ok((block_info, transactions))
        }

        async fn get_account(
            &self,
            address: Scalar,
            block_hash: Option<Scalar>,
        ) -> Result<data::AccountInfo> {
            let response = self
                .client
                .lock()
                .await
                .get_account(libernet::GetAccountRequest {
                    account_address: Some(proto::encode_scalar(address)),
                    block_hash: block_hash.map(proto::encode_scalar),
                })
                .await?;
            let proof_proto = response
                .get_ref()
                .account_proof
                .as_ref()
                .context("missing Merkle proof")?;
            let (_, proof) = data::AccountProof::decode_and_verify_account_proof(proof_proto)?;
            assert_eq!(proof.key(), address);
            Ok(proof.take_value())
        }

        async fn get_transaction(&self, transaction_hash: Scalar) -> Result<data::Transaction> {
            let proof = self
                .client
                .lock()
                .await
                .get_transaction(libernet::GetTransactionRequest {
                    transaction_hash: Some(proto::encode_scalar(transaction_hash)),
                })
                .await?
                .into_inner()
                .transaction_proof
                .context("missing transaction data")?;
            let (_, proof) =
                TransactionInclusionProof::decode_and_verify_transaction_proof(&proof)?;
            Ok(proof.take_value())
        }

        async fn send_coins(
            &self,
            signer: &Account,
            nonce: u64,
            recipient_address: Scalar,
            amount: Scalar,
        ) -> Result<libernet::BroadcastTransactionResponse> {
            Ok(self
                .client
                .lock()
                .await
                .broadcast_transaction(libernet::BroadcastTransactionRequest {
                    transaction: Some(
                        data::Transaction::make_coin_transfer_proto(
                            signer,
                            TEST_CHAIN_ID,
                            nonce,
                            recipient_address,
                            amount,
                        )
                        .unwrap(),
                    ),
                    ttl: Some(1),
                })
                .await?
                .into_inner())
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            self.server_handle.abort();
        }
    }

    fn default_genesis_block_hash() -> Scalar {
        parse_scalar("0x2c9f00c8427e254ab63b3dab55c3cb9cdb57bb4d3e283fc969f2c3cc62642525")
    }

    #[tokio::test(start_paused = true)]
    async fn test_identity() {
        let fixture = TestFixture::default().await.unwrap();

        let response = fixture
            .client
            .lock()
            .await
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
            constants::PROTOCOL_VERSION_MAJOR
        );
        assert_eq!(
            protocol_version.minor.unwrap(),
            constants::PROTOCOL_VERSION_MINOR
        );
        assert_eq!(
            protocol_version.build.unwrap(),
            constants::PROTOCOL_VERSION_BUILD
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
        let fixture = TestFixture::default().await.unwrap();
        let block_info = fixture
            .get_block(Some(default_genesis_block_hash()))
            .await
            .unwrap();
        assert_eq!(block_info.hash(), default_genesis_block_hash());
        assert_eq!(block_info.number(), 0);
        assert_eq!(block_info.previous_block_hash(), 0.into());
        assert_eq!(
            block_info.network_topology_root_hash(),
            parse_scalar("0x26d7bdfa55f037ede2301959d3e4fd36543fae19f774589ee2c99dd12a9874e6")
        );
        assert_eq!(
            block_info.accounts_root_hash(),
            parse_scalar("0x633e9766dbe86a02c8b9ee59fd23020f7f4a6d61bf930c9e29f16751cd486ce9")
        );
        assert_eq!(
            block_info.program_storage_root_hash(),
            parse_scalar("0x3d9016982089280a29c69e2fe04485ef3e4bfc93713b8c34ff168ccc3226298d")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_latest_block_at_genesis() {
        let fixture = TestFixture::default().await.unwrap();
        let block_info = fixture.get_block(None).await.unwrap();
        assert_eq!(block_info.hash(), default_genesis_block_hash());
        assert_eq!(block_info.number(), 0);
        assert_eq!(block_info.previous_block_hash(), 0.into());
        assert_eq!(
            block_info.network_topology_root_hash(),
            parse_scalar("0x26d7bdfa55f037ede2301959d3e4fd36543fae19f774589ee2c99dd12a9874e6")
        );
        assert_eq!(
            block_info.accounts_root_hash(),
            parse_scalar("0x633e9766dbe86a02c8b9ee59fd23020f7f4a6d61bf930c9e29f16751cd486ce9")
        );
        assert_eq!(
            block_info.program_storage_root_hash(),
            parse_scalar("0x3d9016982089280a29c69e2fe04485ef3e4bfc93713b8c34ff168ccc3226298d")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_unknown_block() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .client
                .lock()
                .await
                .get_block(libernet::GetBlockRequest {
                    block_hash: Some(proto::encode_scalar(parse_scalar(
                        "0x375830d6862157562431f637dcb4aa91e2bba7220abfa58b7618a713e9bb8803"
                    ))),
                    get_all_transaction_hashes: Some(false),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_default_initial_account_balance() {
        let fixture = TestFixture::default().await.unwrap();
        let account_info = fixture
            .get_account(
                testing::account3().address(),
                Some(default_genesis_block_hash()),
            )
            .await
            .unwrap();
        assert_eq!(
            account_info,
            data::AccountInfo {
                last_nonce: 56,
                balance: coins(34),
                staking_balance: 0.into(),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_latest_account_balance_at_genesis() {
        let fixture = TestFixture::default().await.unwrap();
        let account_info = fixture
            .get_account(testing::account3().address(), None)
            .await
            .unwrap();
        assert_eq!(
            account_info,
            data::AccountInfo {
                last_nonce: 56,
                balance: coins(34),
                staking_balance: 0.into(),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_invalid_account_balance1() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .client
                .lock()
                .await
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
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .client
                .lock()
                .await
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
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .client
                .lock()
                .await
                .get_transaction(libernet::GetTransactionRequest {
                    transaction_hash: None,
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_unknown_transaction() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .client
                .lock()
                .await
                .get_transaction(libernet::GetTransactionRequest {
                    transaction_hash: Some(proto::encode_scalar(0.into())),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_closure() {
        let fixture = TestFixture::default().await.unwrap();

        let block_info = fixture.get_block(None).await.unwrap();
        assert_eq!(block_info.number(), 0);
        assert_eq!(block_info.hash(), default_genesis_block_hash());

        fixture.advance_to_next_block().await;

        let block_info = fixture.get_block(None).await.unwrap();
        assert_eq!(block_info.number(), 1);
        assert_eq!(
            block_info.hash(),
            parse_scalar("0x32d15c0114e735fd4ea1d8463d42f8b28c83db452ba61b4570adc029df92e21a")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_reward_transaction() {
        let account1 = testing::account1();
        let fixture = TestFixture::default().await.unwrap();

        fixture.advance_to_next_block().await;

        let (_, transactions) = fixture.get_block_and_transactions(None).await.unwrap();
        assert_eq!(transactions.len(), 1);

        let transaction = &transactions[0];
        let payload = transaction.payload();
        assert_eq!(transaction.signer(), account1.address());
        assert_eq!(payload.chain_id(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce(), 13);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::BlockReward(payload) => {
                assert_eq!(
                    proto::decode_scalar(payload.recipient.as_ref().unwrap()).unwrap(),
                    account1.address()
                );
                assert_eq!(
                    proto::decode_scalar(payload.amount.as_ref().unwrap()).unwrap(),
                    reward_for(coins(78))
                );
            }
            _ => panic!(),
        }

        let account1_info = fixture.get_account(account1.address(), None).await.unwrap();
        assert_eq!(
            account1_info,
            data::AccountInfo {
                last_nonce: 13,
                balance: coins(90) + reward_for(coins(78)),
                staking_balance: coins(78),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_pending_transaction() {
        let account1 = testing::account3();
        let account2 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();

        fixture
            .send_coins(&account1, 57, account2.address(), coins(12))
            .await
            .unwrap();

        let (_, transactions) = fixture.get_block_and_transactions(None).await.unwrap();
        assert!(transactions.is_empty());

        let account1_info = fixture.get_account(account1.address(), None).await.unwrap();
        assert_eq!(account1_info.last_nonce, 56);
        assert_eq!(account1_info.balance, coins(34));
        assert_eq!(account1_info.staking_balance, 0.into());

        let account2_info = fixture.get_account(account2.address(), None).await.unwrap();
        assert_eq!(account2_info.last_nonce, 78);
        assert_eq!(account2_info.balance, coins(12));
        assert_eq!(account2_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_coin_transfer_transaction() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();

        fixture
            .send_coins(&account2, 35, account3.address(), coins(12))
            .await
            .unwrap();

        fixture.advance_to_next_block().await;

        let (block_info, transactions) = fixture.get_block_and_transactions(None).await.unwrap();
        assert_eq!(block_info.number(), 1);
        assert_eq!(transactions.len(), 2);

        let transaction = &transactions[0];
        assert_eq!(transaction.signer(), account1.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 13);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::BlockReward(block_reward) => {
                assert_eq!(
                    proto::decode_scalar(block_reward.recipient.as_ref().unwrap()).unwrap(),
                    account1.address(),
                );
                assert_eq!(
                    proto::decode_scalar(block_reward.amount.as_ref().unwrap()).unwrap(),
                    reward_for(coins(78))
                );
            }
            _ => panic!(),
        }

        let transaction = &transactions[1];
        assert_eq!(transaction.signer(), account2.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 35);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::SendCoins(send_coins) => {
                assert_eq!(
                    proto::decode_scalar(send_coins.recipient.as_ref().unwrap()).unwrap(),
                    account3.address(),
                );
                assert_eq!(
                    proto::decode_scalar(send_coins.amount.as_ref().unwrap()).unwrap(),
                    coins(12)
                );
            }
            _ => panic!(),
        }

        let account1_info = fixture.get_account(account1.address(), None).await.unwrap();
        assert_eq!(account1_info.last_nonce, 13);
        assert_eq!(account1_info.balance, coins(90) + reward_for(coins(78)));
        assert_eq!(account1_info.staking_balance, coins(78));

        let account2_info = fixture.get_account(account2.address(), None).await.unwrap();
        assert_eq!(account2_info.last_nonce, 35);
        assert_eq!(account2_info.balance, coins(44));
        assert_eq!(account2_info.staking_balance, 0.into());

        let account3_info = fixture.get_account(account3.address(), None).await.unwrap();
        assert_eq!(account3_info.last_nonce, 56);
        assert_eq!(account3_info.balance, coins(46));
        assert_eq!(account3_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_two_transactions() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();

        fixture
            .client
            .lock()
            .await
            .broadcast_transaction(libernet::BroadcastTransactionRequest {
                transaction: Some(
                    data::Transaction::make_coin_transfer_proto(
                        &account3,
                        TEST_CHAIN_ID,
                        57,
                        account2.address(),
                        coins(12),
                    )
                    .unwrap(),
                ),
                ttl: Some(1),
            })
            .await
            .unwrap();

        fixture
            .client
            .lock()
            .await
            .broadcast_transaction(libernet::BroadcastTransactionRequest {
                transaction: Some(
                    data::Transaction::make_coin_transfer_proto(
                        &account2,
                        TEST_CHAIN_ID,
                        35,
                        account3.address(),
                        coins(21),
                    )
                    .unwrap(),
                ),
                ttl: Some(1),
            })
            .await
            .unwrap();

        fixture.advance_to_next_block().await;

        let (block_info, transactions) = fixture.get_block_and_transactions(None).await.unwrap();
        assert_eq!(block_info.number(), 1);
        assert_eq!(transactions.len(), 3);

        let transaction = &transactions[0];
        assert_eq!(transaction.signer(), account1.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 13);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::BlockReward(block_reward) => {
                assert_eq!(
                    proto::decode_scalar(block_reward.recipient.as_ref().unwrap()).unwrap(),
                    account1.address(),
                );
                assert_eq!(
                    proto::decode_scalar(block_reward.amount.as_ref().unwrap()).unwrap(),
                    reward_for(coins(78))
                );
            }
            _ => panic!(),
        }

        let transaction = &transactions[1];
        assert_eq!(transaction.signer(), account3.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 57);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::SendCoins(send_coins) => {
                assert_eq!(
                    proto::decode_scalar(send_coins.recipient.as_ref().unwrap()).unwrap(),
                    account2.address(),
                );
                assert_eq!(
                    proto::decode_scalar(send_coins.amount.as_ref().unwrap()).unwrap(),
                    coins(12)
                );
            }
            _ => panic!(),
        }

        let transaction = &transactions[2];
        assert_eq!(transaction.signer(), account2.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 35);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::SendCoins(send_coins) => {
                assert_eq!(
                    proto::decode_scalar(send_coins.recipient.as_ref().unwrap()).unwrap(),
                    account3.address(),
                );
                assert_eq!(
                    proto::decode_scalar(send_coins.amount.as_ref().unwrap()).unwrap(),
                    coins(21)
                );
            }
            _ => panic!(),
        }

        let account1_info = fixture.get_account(account1.address(), None).await.unwrap();
        assert_eq!(account1_info.last_nonce, 13);
        assert_eq!(account1_info.balance, coins(90) + reward_for(coins(78)));
        assert_eq!(account1_info.staking_balance, coins(78));

        let account2_info = fixture.get_account(account2.address(), None).await.unwrap();
        assert_eq!(account2_info.last_nonce, 35);
        assert_eq!(account2_info.balance, coins(47));
        assert_eq!(account2_info.staking_balance, 0.into());

        let account3_info = fixture.get_account(account3.address(), None).await.unwrap();
        assert_eq!(account3_info.last_nonce, 57);
        assert_eq!(account3_info.balance, coins(43));
        assert_eq!(account3_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_transaction_in_second_block() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();

        let fixture = TestFixture::default().await.unwrap();

        fixture
            .send_coins(&account3, 57, account2.address(), coins(12))
            .await
            .unwrap();

        fixture.advance_to_next_block().await;

        let (block_info1, transactions1) = fixture.get_block_and_transactions(None).await.unwrap();
        assert_eq!(block_info1.number(), 1);

        fixture
            .send_coins(&account2, 35, account3.address(), coins(21))
            .await
            .unwrap();

        fixture.advance_to_next_block().await;

        let (block_info2, transactions2) = fixture.get_block_and_transactions(None).await.unwrap();
        assert_eq!(block_info2.number(), 2);

        let transaction = &transactions1[0];
        assert_eq!(transaction.signer(), account1.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 13);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::BlockReward(block_reward) => {
                assert_eq!(
                    proto::decode_scalar(block_reward.recipient.as_ref().unwrap()).unwrap(),
                    account1.address(),
                );
                assert_eq!(
                    proto::decode_scalar(block_reward.amount.as_ref().unwrap()).unwrap(),
                    reward_for(coins(78))
                );
            }
            _ => panic!(),
        }

        let transaction = &transactions1[1];
        assert_eq!(transaction.signer(), account3.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 57);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::SendCoins(send_coins) => {
                assert_eq!(
                    proto::decode_scalar(send_coins.recipient.as_ref().unwrap()).unwrap(),
                    account2.address(),
                );
                assert_eq!(
                    proto::decode_scalar(send_coins.amount.as_ref().unwrap()).unwrap(),
                    coins(12)
                );
            }
            _ => panic!(),
        }

        let transaction = &transactions2[0];
        assert_eq!(transaction.signer(), account1.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 14);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::BlockReward(block_reward) => {
                assert_eq!(
                    proto::decode_scalar(block_reward.recipient.as_ref().unwrap()).unwrap(),
                    account1.address(),
                );
                assert_eq!(
                    proto::decode_scalar(block_reward.amount.as_ref().unwrap()).unwrap(),
                    reward_for(coins(78))
                );
            }
            _ => panic!(),
        }

        let transaction = &transactions2[1];
        assert_eq!(transaction.signer(), account2.address());
        let payload = transaction.payload();
        assert_eq!(payload.chain_id.unwrap(), TEST_CHAIN_ID);
        assert_eq!(payload.nonce.unwrap(), 35);
        match payload.transaction.as_ref().unwrap() {
            libernet::transaction::payload::Transaction::SendCoins(send_coins) => {
                assert_eq!(
                    proto::decode_scalar(send_coins.recipient.as_ref().unwrap()).unwrap(),
                    account3.address(),
                );
                assert_eq!(
                    proto::decode_scalar(send_coins.amount.as_ref().unwrap()).unwrap(),
                    coins(21)
                );
            }
            _ => panic!(),
        }

        let account1_info = fixture.get_account(account1.address(), None).await.unwrap();
        assert_eq!(account1_info.last_nonce, 14);
        assert_eq!(
            account1_info.balance,
            coins(90) + reward_for(coins(78)) * Scalar::from(2)
        );
        assert_eq!(account1_info.staking_balance, coins(78));

        let account2_info = fixture.get_account(account2.address(), None).await.unwrap();
        assert_eq!(account2_info.last_nonce, 35);
        assert_eq!(account2_info.balance, coins(47));
        assert_eq!(account2_info.staking_balance, 0.into());

        let account3_info = fixture.get_account(account3.address(), None).await.unwrap();
        assert_eq!(account3_info.last_nonce, 57);
        assert_eq!(account3_info.balance, coins(43));
        assert_eq!(account3_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_subscription1() {
        let fixture = TestFixture::default().await.unwrap();

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_blocks(libernet::BlockSubscriptionRequest {})
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.block_descriptor.len(), 1);
        let block_info =
            data::BlockInfo::decode(response.block_descriptor.first().unwrap()).unwrap();
        assert_eq!(block_info.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info.number(), 1);
        assert_eq!(
            block_info.previous_block_hash(),
            default_genesis_block_hash()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_subscription2() {
        let fixture = TestFixture::default().await.unwrap();

        fixture.advance_to_next_block().await;

        let block_info1 = fixture.get_block(None).await.unwrap();
        assert_eq!(block_info1.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info1.number(), 1);

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_blocks(libernet::BlockSubscriptionRequest {})
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.block_descriptor.len(), 1);
        let block_info2 =
            data::BlockInfo::decode(response.block_descriptor.first().unwrap()).unwrap();
        assert_eq!(block_info2.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info2.number(), 2);
        assert_eq!(block_info2.previous_block_hash(), block_info1.hash());
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_subscription3() {
        let fixture = TestFixture::default().await.unwrap();

        fixture.advance_to_next_block().await;

        let block_info1 = fixture.get_block(None).await.unwrap();
        assert_eq!(block_info1.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info1.number(), 1);

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_blocks(libernet::BlockSubscriptionRequest {})
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.block_descriptor.len(), 1);
        let block_info2 =
            data::BlockInfo::decode(response.block_descriptor.first().unwrap()).unwrap();
        assert_eq!(block_info2.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info2.number(), 2);
        assert_eq!(block_info2.previous_block_hash(), block_info1.hash());

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.block_descriptor.len(), 1);
        let block_info3 =
            data::BlockInfo::decode(response.block_descriptor.first().unwrap()).unwrap();
        assert_eq!(block_info3.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info3.number(), 3);
        assert_eq!(block_info3.previous_block_hash(), block_info2.hash());
    }

    async fn test_account1_subscription(every_block: bool) {
        let account1 = testing::account3();
        let account2 = testing::account4();

        let fixture = TestFixture::default().await.unwrap();

        fixture
            .send_coins(&account1, 57, account2.address(), coins(12))
            .await
            .unwrap();

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_account(libernet::AccountSubscriptionRequest {
                account_address: Some(proto::encode_scalar(account1.address())),
                every_block: Some(every_block),
            })
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.account_proof.len(), 1);
        let proof = response.account_proof.first().unwrap();
        let (block_info, proof) =
            data::AccountProof::decode_and_verify_account_proof(proof).unwrap();

        assert_eq!(block_info.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info.number(), 1);
        assert_eq!(
            block_info.previous_block_hash(),
            default_genesis_block_hash()
        );

        assert_eq!(proof.key(), account1.address());
        let account_info = proof.value();
        assert_eq!(account_info.last_nonce, 57);
        assert_eq!(account_info.balance, coins(22));
        assert_eq!(account_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_account1_subscription1() {
        test_account1_subscription(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_account1_subscription2() {
        test_account1_subscription(true).await;
    }

    async fn test_account2_subscription(every_block: bool) {
        let account1 = testing::account3();
        let account2 = testing::account4();

        let fixture = TestFixture::default().await.unwrap();

        fixture
            .send_coins(&account1, 57, account2.address(), coins(12))
            .await
            .unwrap();

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_account(libernet::AccountSubscriptionRequest {
                account_address: Some(proto::encode_scalar(account2.address())),
                every_block: Some(every_block),
            })
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.account_proof.len(), 1);
        let proof = response.account_proof.first().unwrap();
        let (block_info, proof) =
            data::AccountProof::decode_and_verify_account_proof(proof).unwrap();

        assert_eq!(block_info.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info.number(), 1);
        assert_eq!(
            block_info.previous_block_hash(),
            default_genesis_block_hash()
        );

        assert_eq!(proof.key(), account2.address());
        let account_info = proof.value();
        assert_eq!(account_info.last_nonce, 78);
        assert_eq!(account_info.balance, coins(24));
        assert_eq!(account_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_account2_subscription1() {
        test_account2_subscription(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_account2_subscription2() {
        test_account2_subscription(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_account_subscription_second_block() {
        let account1 = testing::account3();
        let account2 = testing::account4();

        let fixture = TestFixture::default().await.unwrap();

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_account(libernet::AccountSubscriptionRequest {
                account_address: Some(proto::encode_scalar(account1.address())),
                every_block: Some(false),
            })
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        fixture
            .send_coins(&account1, 57, account2.address(), coins(12))
            .await
            .unwrap();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.account_proof.len(), 1);
        let proof = response.account_proof.first().unwrap();
        let (block_info, proof) =
            data::AccountProof::decode_and_verify_account_proof(proof).unwrap();

        assert_eq!(block_info.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info.number(), 2);
        assert_eq!(
            block_info.previous_block_hash(),
            parse_scalar("0x32d15c0114e735fd4ea1d8463d42f8b28c83db452ba61b4570adc029df92e21a")
        );

        assert_eq!(proof.key(), account1.address());
        let account_info = proof.value();
        assert_eq!(account_info.last_nonce, 57);
        assert_eq!(account_info.balance, coins(22));
        assert_eq!(account_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_watch_account_two_blocks() {
        let account1 = testing::account3();
        let account2 = testing::account4();

        let fixture = TestFixture::default().await.unwrap();

        let mut stream = fixture
            .client
            .lock()
            .await
            .subscribe_to_account(libernet::AccountSubscriptionRequest {
                account_address: Some(proto::encode_scalar(account1.address())),
                every_block: Some(true),
            })
            .await
            .unwrap()
            .into_inner();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.account_proof.len(), 1);
        let proof = response.account_proof.first().unwrap();
        let (block_info, proof) =
            data::AccountProof::decode_and_verify_account_proof(proof).unwrap();

        assert_eq!(block_info.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info.number(), 1);
        assert_eq!(
            block_info.previous_block_hash(),
            default_genesis_block_hash()
        );

        assert_eq!(proof.key(), account1.address());
        let account_info = proof.value();
        assert_eq!(account_info.last_nonce, 56);
        assert_eq!(account_info.balance, coins(34));
        assert_eq!(account_info.staking_balance, 0.into());

        fixture
            .send_coins(&account1, 57, account2.address(), coins(12))
            .await
            .unwrap();

        fixture.advance_to_next_block().await;

        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.account_proof.len(), 1);
        let proof = response.account_proof.first().unwrap();
        let (block_info, proof) =
            data::AccountProof::decode_and_verify_account_proof(proof).unwrap();

        assert_eq!(block_info.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block_info.number(), 2);
        assert_eq!(
            block_info.previous_block_hash(),
            parse_scalar("0x32d15c0114e735fd4ea1d8463d42f8b28c83db452ba61b4570adc029df92e21a")
        );

        assert_eq!(proof.key(), account1.address());
        let account_info = proof.value();
        assert_eq!(account_info.last_nonce, 57);
        assert_eq!(account_info.balance, coins(22));
        assert_eq!(account_info.staking_balance, 0.into());
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_no_results() {
        let fixture = TestFixture::default().await.unwrap();
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: None,
                max_count: None,
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        assert!(proofs.individual_proof.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_pending_transactions_not_included_in_queries() {
        let account1 = testing::account3();
        let account2 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();
        fixture
            .send_coins(&account1, 57, account2.address(), 5.into())
            .await
            .unwrap();
        fixture
            .send_coins(&account2, 79, account1.address(), 3.into())
            .await
            .unwrap();
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: None,
                max_count: None,
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        assert!(proofs.individual_proof.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions() {
        let account1 = testing::account1();
        let account3 = testing::account3();
        let account4 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();
        fixture
            .send_coins(&account3, 57, account4.address(), 5.into())
            .await
            .unwrap();
        fixture
            .send_coins(&account4, 79, account3.address(), 3.into())
            .await
            .unwrap();
        fixture.advance_to_next_block().await;
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: None,
                max_count: None,
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        let transactions = proofs
            .individual_proof
            .iter()
            .map(|proto| {
                let (block_info, proof) =
                    TransactionInclusionProof::decode_and_verify_transaction_proof(proto).unwrap();
                assert_eq!(
                    block_info.hash(),
                    parse_scalar(
                        "0x63aa3659c5db5156b52704df8aaf3f16a1c0db51ebc1b1f1aff348961dafe74c",
                    )
                );
                proof.take_value()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            transactions,
            vec![
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account4,
                        TEST_CHAIN_ID,
                        79,
                        account3.address(),
                        3.into()
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account3,
                        TEST_CHAIN_ID,
                        57,
                        account4.address(),
                        5.into()
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_block_reward_proto(
                        &account1,
                        TEST_CHAIN_ID,
                        13,
                        account1.address(),
                        reward_for(coins(78)),
                    )
                    .unwrap()
                )
                .unwrap(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_ascending() {
        let account1 = testing::account1();
        let account3 = testing::account3();
        let account4 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();
        fixture
            .send_coins(&account3, 57, account4.address(), 5.into())
            .await
            .unwrap();
        fixture
            .send_coins(&account4, 79, account3.address(), 3.into())
            .await
            .unwrap();
        fixture.advance_to_next_block().await;
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: Some(
                    libernet::query_transactions_request::SortOrder::TransactionSortOrderAscending
                        as i32,
                ),
                max_count: None,
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        let transactions = proofs
            .individual_proof
            .iter()
            .map(|proto| {
                let (block_info, proof) =
                    TransactionInclusionProof::decode_and_verify_transaction_proof(proto).unwrap();
                assert_eq!(
                    block_info.hash(),
                    parse_scalar(
                        "0x63aa3659c5db5156b52704df8aaf3f16a1c0db51ebc1b1f1aff348961dafe74c",
                    )
                );
                proof.take_value()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            transactions,
            vec![
                Transaction::from_proto(
                    Transaction::make_block_reward_proto(
                        &account1,
                        TEST_CHAIN_ID,
                        13,
                        account1.address(),
                        reward_for(coins(78)),
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account3,
                        TEST_CHAIN_ID,
                        57,
                        account4.address(),
                        5.into()
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account4,
                        TEST_CHAIN_ID,
                        79,
                        account3.address(),
                        3.into()
                    )
                    .unwrap()
                )
                .unwrap(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_ascending_capped() {
        let account1 = testing::account1();
        let account3 = testing::account3();
        let account4 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();
        fixture
            .send_coins(&account3, 57, account4.address(), 5.into())
            .await
            .unwrap();
        fixture
            .send_coins(&account4, 79, account3.address(), 3.into())
            .await
            .unwrap();
        fixture.advance_to_next_block().await;
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: Some(
                    libernet::query_transactions_request::SortOrder::TransactionSortOrderAscending
                        as i32,
                ),
                max_count: Some(2),
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        let transactions = proofs
            .individual_proof
            .iter()
            .map(|proto| {
                let (block_info, proof) =
                    TransactionInclusionProof::decode_and_verify_transaction_proof(proto).unwrap();
                assert_eq!(
                    block_info.hash(),
                    parse_scalar(
                        "0x63aa3659c5db5156b52704df8aaf3f16a1c0db51ebc1b1f1aff348961dafe74c",
                    )
                );
                proof.take_value()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            transactions,
            vec![
                Transaction::from_proto(
                    Transaction::make_block_reward_proto(
                        &account1,
                        TEST_CHAIN_ID,
                        13,
                        account1.address(),
                        reward_for(coins(78)),
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account3,
                        TEST_CHAIN_ID,
                        57,
                        account4.address(),
                        5.into()
                    )
                    .unwrap()
                )
                .unwrap(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_descending() {
        let account1 = testing::account1();
        let account3 = testing::account3();
        let account4 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();
        fixture
            .send_coins(&account3, 57, account4.address(), 5.into())
            .await
            .unwrap();
        fixture
            .send_coins(&account4, 79, account3.address(), 3.into())
            .await
            .unwrap();
        fixture.advance_to_next_block().await;
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: Some(
                    libernet::query_transactions_request::SortOrder::TransactionSortOrderDescending
                        as i32,
                ),
                max_count: None,
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        let transactions = proofs
            .individual_proof
            .iter()
            .map(|proto| {
                let (block_info, proof) =
                    TransactionInclusionProof::decode_and_verify_transaction_proof(proto).unwrap();
                assert_eq!(
                    block_info.hash(),
                    parse_scalar(
                        "0x63aa3659c5db5156b52704df8aaf3f16a1c0db51ebc1b1f1aff348961dafe74c",
                    )
                );
                proof.take_value()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            transactions,
            vec![
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account4,
                        TEST_CHAIN_ID,
                        79,
                        account3.address(),
                        3.into()
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account3,
                        TEST_CHAIN_ID,
                        57,
                        account4.address(),
                        5.into()
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_block_reward_proto(
                        &account1,
                        TEST_CHAIN_ID,
                        13,
                        account1.address(),
                        reward_for(coins(78)),
                    )
                    .unwrap()
                )
                .unwrap(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_descending_capped() {
        let account3 = testing::account3();
        let account4 = testing::account4();
        let fixture = TestFixture::default().await.unwrap();
        fixture
            .send_coins(&account3, 57, account4.address(), 5.into())
            .await
            .unwrap();
        fixture
            .send_coins(&account4, 79, account3.address(), 3.into())
            .await
            .unwrap();
        fixture.advance_to_next_block().await;
        let response = fixture
            .client
            .lock()
            .await
            .query_transactions(libernet::QueryTransactionsRequest {
                from_filter: None,
                to_filter: None,
                sort_order: Some(
                    libernet::query_transactions_request::SortOrder::TransactionSortOrderDescending
                        as i32,
                ),
                max_count: Some(2),
                start_block_filter: None,
                end_block_filter: None,
            })
            .await
            .unwrap()
            .into_inner();
        let libernet::query_transactions_response::TransactionProofs::IndividualProofs(proofs) =
            response.transaction_proofs.unwrap()
        else {
            panic!();
        };
        let transactions = proofs
            .individual_proof
            .iter()
            .map(|proto| {
                let (block_info, proof) =
                    TransactionInclusionProof::decode_and_verify_transaction_proof(proto).unwrap();
                assert_eq!(
                    block_info.hash(),
                    parse_scalar(
                        "0x63aa3659c5db5156b52704df8aaf3f16a1c0db51ebc1b1f1aff348961dafe74c",
                    )
                );
                proof.take_value()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            transactions,
            vec![
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account4,
                        TEST_CHAIN_ID,
                        79,
                        account3.address(),
                        3.into()
                    )
                    .unwrap()
                )
                .unwrap(),
                Transaction::from_proto(
                    Transaction::make_coin_transfer_proto(
                        &account3,
                        TEST_CHAIN_ID,
                        57,
                        account4.address(),
                        5.into()
                    )
                    .unwrap()
                )
                .unwrap(),
            ]
        );
    }

    // TODO
}
