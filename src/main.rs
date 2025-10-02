use anyhow::Result;
use clap::Parser;
use crypto::{account::Account, utils};

mod account;
mod clock;
mod db;
mod proto;
mod topology;
mod tree;

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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let secret_key = if args.secret_key.is_empty() {
        let key = utils::get_random_scalar();
        println!("New secret key: {:#x}", utils::scalar_to_u256(key));
        key
    } else {
        utils::parse_scalar(args.secret_key.as_str())?
    };

    let account = Account::new(secret_key);

    // TODO

    println!("Hello, world!");

    Ok(())
}
