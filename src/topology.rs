use crate::libernet;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::poseidon;
use std::collections::BTreeSet;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Location {
    pub latitude: i32,
    pub longitude: u32,
}

#[derive(Debug, Clone)]
pub struct Node {
    account_address: Scalar,
    signed_identity: libernet::NodeIdentity,
    location: Location,
    network_address: String,
    grpc_port: u16,
    http_port: u16,
}

impl Node {
    fn sanitize_port_number(port: u32) -> Result<u16> {
        if port > 0xFFFF {
            Err(anyhow!("invalid port number: {}", port))
        } else {
            Ok(port as u16)
        }
    }

    pub fn new(identity: libernet::NodeIdentity) -> Result<Self> {
        let payload = &identity
            .payload
            .as_ref()
            .context("payload missing")?
            .to_msg::<libernet::node_identity::Payload>()?;
        let account_address = proto::decode_scalar(
            payload
                .account_address
                .as_ref()
                .context("account address field missing")?,
        )?;
        let location = payload
            .location
            .context("geographical location field missing")?;
        let latitude = location.latitude.context("latitude field missing")?;
        let longitude = location.longitude.context("longitude field missing")?;
        let network_address = payload
            .network_address
            .as_ref()
            .context("network address field missing")?
            .clone();
        let grpc_port =
            Self::sanitize_port_number(payload.grpc_port.context("gRPC port field missing")?)?;
        let http_port =
            Self::sanitize_port_number(payload.http_port.context("HTTP port field missing")?)?;
        Ok(Self {
            account_address,
            signed_identity: identity,
            location: Location {
                latitude,
                longitude,
            },
            network_address,
            grpc_port,
            http_port,
        })
    }

    pub fn account_address(&self) -> Scalar {
        self.account_address
    }

    pub fn hash(&self) -> Scalar {
        self.account_address
    }

    pub fn signed_identity(&self) -> &libernet::NodeIdentity {
        &self.signed_identity
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn network_address(&self) -> &str {
        self.network_address.as_str()
    }

    pub fn grpc_port(&self) -> u16 {
        self.grpc_port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.account_address == other.account_address
    }
}

impl Eq for Node {}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.account_address.cmp(&other.account_address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Clique {
    nodes: Vec<Node>,
    hash: Scalar,
}

impl Clique {
    fn hash_nodes(nodes: &[Node]) -> Scalar {
        poseidon::hash_t4(
            std::iter::once(Scalar::from(nodes.len() as u64))
                .chain(nodes.iter().map(|node| node.account_address()))
                .collect::<Vec<Scalar>>()
                .as_slice(),
        )
    }

    fn from<const N: usize>(nodes: [Node; N]) -> Result<Self> {
        let node_set =
            BTreeSet::from_iter(nodes.as_ref().iter().map(|node| node.account_address()));
        if node_set.len() < N {
            return Err(anyhow!("two or more nodes have the same account address"));
        }
        let hash = Self::hash_nodes(&nodes);
        Ok(Self {
            nodes: Vec::from(nodes),
            hash,
        })
    }

    pub fn hash(&self) -> Scalar {
        self.hash
    }

    pub fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    cliques: Vec<Clique>,
    own_clique_index: usize,
    own_node_index: usize,
    hash: Scalar,
}

impl Network {
    fn hash_network(cliques: &[Clique]) -> Scalar {
        poseidon::hash_t4(
            std::iter::once(Scalar::from(cliques.len() as u64))
                .chain(cliques.iter().map(|clique| clique.hash()))
                .collect::<Vec<Scalar>>()
                .as_slice(),
        )
    }

    pub fn new(identity: libernet::NodeIdentity) -> Result<Self> {
        let cliques = vec![Clique::from([Node::new(identity)?])?];
        let hash = Self::hash_network(cliques.as_slice());
        Ok(Self {
            cliques,
            own_clique_index: 0,
            own_node_index: 0,
            hash,
        })
    }

    pub fn root_hash(&self) -> Scalar {
        self.hash
    }

    pub fn get_self(&self) -> &Node {
        self.cliques[self.own_clique_index].node(self.own_node_index)
    }

    pub async fn broadcast_transaction(&self, transaction: &libernet::Transaction) -> Result<()> {
        // TODO
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
