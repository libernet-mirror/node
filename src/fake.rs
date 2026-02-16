use crate::libernet::{self, node_service_v1_server::NodeServiceV1};
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::{Request, Response, Status};

#[derive(Default)]
pub struct SubscribeToBlocksStream {}

impl Stream for SubscribeToBlocksStream {
    type Item = Result<libernet::BlockSubscriptionResponse, Status>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

#[derive(Default)]
pub struct SubscribeToAccountStream {}

impl Stream for SubscribeToAccountStream {
    type Item = Result<libernet::AccountSubscriptionResponse, Status>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

#[cfg(test)]
pub struct FakeNodeService {}

#[cfg(test)]
#[tonic::async_trait]
impl NodeServiceV1 for FakeNodeService {
    async fn get_identity(
        &self,
        _request: Request<libernet::GetIdentityRequest>,
    ) -> Result<Response<libernet::NodeIdentity>, Status> {
        Ok(Response::new(libernet::NodeIdentity {
            payload: None,
            signature: None,
        }))
    }

    async fn get_block(
        &self,
        _request: Request<libernet::GetBlockRequest>,
    ) -> Result<Response<libernet::GetBlockResponse>, Status> {
        Ok(Response::new(libernet::GetBlockResponse {
            block_descriptor: None,
            transaction_hash: vec![],
        }))
    }

    type SubscribeToBlocksStream = SubscribeToBlocksStream;

    async fn subscribe_to_blocks(
        &self,
        _request: Request<libernet::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::SubscribeToBlocksStream>, Status> {
        Ok(Response::new(SubscribeToBlocksStream::default()))
    }

    async fn get_topology(
        &self,
        _request: Request<libernet::GetTopologyRequest>,
    ) -> Result<Response<libernet::NetworkTopology>, Status> {
        Ok(Response::new(libernet::NetworkTopology { cluster: vec![] }))
    }

    async fn get_account(
        &self,
        _request: Request<libernet::GetAccountRequest>,
    ) -> Result<Response<libernet::GetAccountResponse>, Status> {
        Ok(Response::new(libernet::GetAccountResponse {
            account_proof: None,
        }))
    }

    type SubscribeToAccountStream = SubscribeToAccountStream;

    async fn subscribe_to_account(
        &self,
        _request: Request<libernet::AccountSubscriptionRequest>,
    ) -> Result<Response<Self::SubscribeToAccountStream>, Status> {
        Ok(Response::new(SubscribeToAccountStream::default()))
    }

    async fn get_transaction(
        &self,
        _request: Request<libernet::GetTransactionRequest>,
    ) -> Result<Response<libernet::GetTransactionResponse>, Status> {
        Ok(Response::new(libernet::GetTransactionResponse {
            transaction_proof: None,
        }))
    }

    async fn query_transactions(
        &self,
        _request: Request<libernet::QueryTransactionsRequest>,
    ) -> Result<Response<libernet::QueryTransactionsResponse>, Status> {
        Ok(Response::new(libernet::QueryTransactionsResponse {
            transaction_proofs: Some(
                libernet::query_transactions_response::TransactionProofs::IndividualProofs(
                    libernet::query_transactions_response::IndividualProofs {
                        individual_proof: vec![],
                    },
                ),
            ),
        }))
    }

    async fn broadcast_transaction(
        &self,
        _request: Request<libernet::BroadcastTransactionRequest>,
    ) -> Result<Response<libernet::BroadcastTransactionResponse>, Status> {
        Ok(Response::new(libernet::BroadcastTransactionResponse {}))
    }

    async fn broadcast_new_block(
        &self,
        _request: Request<libernet::BroadcastBlockRequest>,
    ) -> Result<Response<libernet::BroadcastBlockResponse>, Status> {
        Ok(Response::new(libernet::BroadcastBlockResponse {}))
    }
}
