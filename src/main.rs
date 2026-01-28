// Copyright 2025 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

use crate::account::Account;
use crate::data::AccountInfo;
use crate::libernet::node_service_v1_server::NodeServiceV1Server;
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use clap::Parser;
use crypto::utils;
use primitive_types::H512;
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tonic::transport::Server;

mod account;
mod clock;
mod constants;
mod data;
mod db;
mod net;
mod proto;
mod service;
mod ssl;
mod topology;
mod tree;

#[cfg(test)]
mod fake;

#[cfg(test)]
mod testing;

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
    #[arg(long)]
    bootstrap_list: Vec<String>,

    /// The block time, in milliseconds. Ignored if --bootstrap_list is provided.
    ///
    /// NOTE: this is currently ignored because the block time is hard-coded in constants.rs. We
    /// need to make it configurable.
    #[arg(long, default_value = "10000")]
    block_time_ms: u32,

    /// Provides a JSON file where the user can specify initial account states at genesis.
    ///
    /// Ignored if --bootstrap_list is specified, as in that case we'll be joining an existing
    /// network.
    #[arg(long)]
    account_file: Option<String>,
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

fn read_accounts(file_path: &str) -> Result<BTreeMap<Scalar, AccountInfo>> {
    let json = fs::read_to_string(file_path)?;
    match serde_json::from_str(json.as_str())? {
        serde_json::Value::Object(accounts) => Ok(accounts
            .iter()
            .map(|(address, account_state)| {
                Ok((
                    utils::parse_scalar(address.as_str())?,
                    match account_state {
                        serde_json::Value::String(balance) => Ok(AccountInfo {
                            last_nonce: 0,
                            balance: utils::parse_scalar(balance.as_str())?,
                            staking_balance: 0.into(),
                        }),
                        serde_json::Value::Object(fields) => Ok(AccountInfo {
                            last_nonce: 0,
                            balance: match fields.get("balance") {
                                Some(serde_json::Value::String(balance)) => {
                                    Ok(utils::parse_scalar(balance.as_str())?)
                                }
                                _ => {
                                    Err(anyhow!("invalid balance format for {}", address.as_str()))
                                }
                            }?,
                            staking_balance: match fields.get("staking_balance") {
                                Some(serde_json::Value::String(balance)) => {
                                    Ok(utils::parse_scalar(balance.as_str())?)
                                }
                                _ => Err(anyhow!(
                                    "invalid staking balance format for {}",
                                    address.as_str()
                                )),
                            }?,
                        }),
                        _ => Err(anyhow!("invalid balance for {}", address)),
                    }?,
                ))
            })
            .collect::<Result<BTreeMap<Scalar, AccountInfo>>>()?),
        _ => Err(anyhow!("invalid account file format")),
    }
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
    let (ed25519_certified_key, ecdsa_certified_key) = {
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(1) * 3600 * 24;
        let not_after = now + Duration::from_secs(1) * 3600 * 24 * 365;
        let server_address = Some(args.public_address.as_str());
        (
            account.generate_ed25519_certified_key(not_before, not_after, server_address)?,
            account.generate_ecdsa_certified_key(not_before, not_after, server_address)?,
        )
    };

    let location = make_location(args.latitude, args.longitude)?;

    let accounts = if let Some(file_path) = args.account_file {
        if args.bootstrap_list.is_empty() {
            println!("reading {}", file_path);
            let accounts = read_accounts(file_path.as_str())?;
            println!("initial accounts: {{");
            for (address, account) in &accounts {
                println!("  {}: {{", utils::format_scalar(*address));
                println!("    balance: {}", utils::format_scalar(account.balance));
                println!(
                    "    staking_balance: {}",
                    utils::format_scalar(account.staking_balance)
                );
                println!("  }}");
            }
            println!("}}");
            accounts
        } else {
            println!(
                "ignoring account file {} because a bootstrap list was specified",
                file_path
            );
            BTreeMap::default()
        }
    } else {
        BTreeMap::default()
    };

    let server =
        Server::builder().add_service(NodeServiceV1Server::new(service::NodeService::new(
            Arc::new(clock::RealClock::default()),
            account.clone(),
            location,
            args.chain_id,
            args.public_address.as_str(),
            accounts.into_iter().collect::<Vec<_>>().as_slice(),
            args.grpc_port,
            args.http_port,
        )?));

    let local_address = format!("{}:{}", args.local_address, args.grpc_port);
    println!("listening on {}", local_address);

    server
        .serve_with_incoming(
            net::IncomingWithMTls::new(
                Arc::new(net::TcpListenerAdapter::new(local_address).await.unwrap()),
                ed25519_certified_key,
                ecdsa_certified_key,
            )
            .await?,
        )
        .await?;

    Ok(())
}
