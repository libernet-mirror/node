use crate::account::Account;
use crate::libernet::node_service_v1_server::NodeServiceV1Server;
use anyhow::{Result, anyhow};
use clap::Parser;
use crypto::utils;
use primitive_types::H512;
use std::sync::Arc;
use tonic::transport::Server;

mod account;
mod clock;
mod db;
mod net;
mod proto;
mod service;
mod ssl;
mod topology;
mod tree;
mod version;

#[cfg(test)]
mod fake;

pub mod libernet {
    tonic::include_proto!("libernet");
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The private key of the wallet used to stake DOT and receive rewards. If this is left empty
    /// the node will generate a new key securely at startup, but the corresponding Dotakon account
    /// will be empty and so the node won't be able to join an existing network, it will have to
    /// start a new one.
    #[arg(long, default_value = "")]
    secret_key: String,

    /// The canonical address of this node. It may be an IPv4 address, an IPv6 address, or a DNS
    /// address. The gRPC server must be reachable at this address at all times.
    #[arg(long)]
    public_address: String,

    /// The local IP address the gRPC service binds to. If unspecified the service will bind to all
    /// available network interfaces.
    #[arg(long, default_value = "[::]")]
    local_address: String,

    /// The TCP port where the gRPC service is exposed.
    #[arg(long)]
    grpc_port: u16,

    /// The TCP port where the gRPC-web service is exposed.
    #[arg(long)]
    http_port: u16,

    /// The latitude of the self-declared geographical location of the node, expressed in degrees
    /// between -90.0 and +90.0.
    #[arg(long)]
    latitude: f64,

    /// The longitude of the self-declared geographical location of the node, expressed in degrees
    /// between 0.0 and 180.0.
    #[arg(long)]
    longitude: f64,

    /// The globally unique ID of the network this node will join or create.
    #[arg(long)]
    chain_id: u64,

    /// A list of well-known nodes to connect to in order to join an existing network. If the list
    /// is left empty this node will start a new network.
    #[arg(long, default_value = "")]
    bootstrap_list: Vec<String>,
}

fn make_location(latitude: f64, longitude: f64) -> Result<libernet::GeographicalLocation> {
    if !(-90.0..=90.0).contains(&latitude) {
        return Err(anyhow!("the latitude is out of range"));
    }
    if !(0.0..=180.0).contains(&longitude) {
        return Err(anyhow!("the longitude is out of range"));
    }
    Ok(libernet::GeographicalLocation {
        latitude: Some((latitude * 60.0) as i32),
        longitude: Some((longitude * 60.0) as u32),
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let secret_key = if args.secret_key.is_empty() {
        let key = utils::get_random_bytes();
        println!("New secret key: {:#x}", key);
        key
    } else {
        args.secret_key.as_str().parse::<H512>()?
    };

    let account = Arc::new(Account::from_secret_key(secret_key)?);
    let certificate = Arc::new(ssl::generate_certificate(
        &*account,
        vec![args.public_address.clone()],
    )?);

    let location = make_location(args.latitude, args.longitude)?;
    let server =
        Server::builder().add_service(NodeServiceV1Server::new(service::NodeService::new(
            Arc::new(clock::RealClock::default()),
            account.clone(),
            location,
            args.chain_id,
            args.public_address.as_str(),
            [],
            args.grpc_port,
            args.http_port,
        )?));

    let local_address = format!("{}:{}", args.local_address, args.grpc_port);
    println!("listening on {}", local_address);

    server
        .serve_with_incoming(
            net::IncomingWithMTls::new(
                Arc::new(net::TcpListenerAdapter::new(local_address).await.unwrap()),
                &*account,
                certificate,
            )
            .await?,
        )
        .await?;

    Ok(())
}
