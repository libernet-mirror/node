use crate::libernet::{self, node_service_v1_server::NodeServiceV1};
use tonic::{Request, Response, Status};

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
            payload: None,
            signature: None,
        }))
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
            payload: None,
            signature: None,
        }))
    }

    async fn get_transaction(
        &self,
        _request: Request<libernet::GetTransactionRequest>,
    ) -> Result<Response<libernet::GetTransactionResponse>, Status> {
        Ok(Response::new(libernet::GetTransactionResponse {
            payload: None,
            signature: None,
        }))
    }

    async fn broadcast_transaction(
        &self,
        _request: Request<libernet::BroadcastTransactionRequest>,
    ) -> Result<Response<libernet::BroadcastTransactionResponse>, Status> {
        todo!()
    }

    async fn broadcast_new_block(
        &self,
        _request: Request<libernet::BroadcastBlockRequest>,
    ) -> Result<Response<libernet::BroadcastBlockResponse>, Status> {
        todo!()
    }
}
