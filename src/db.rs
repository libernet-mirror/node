use crate::account;
use crate::clock::Clock;
use crate::libernet;
use crate::proto;
use crate::topology;
use crate::tree;
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::{
    merkle::AsScalar,
    utils::{self, PoseidonHash},
};
use ff::Field;
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, atomic::AtomicU64, atomic::Ordering};
use std::time::SystemTime;
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender, channel},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    hash: Scalar,
    chain_id: u64,
    number: u64,
    previous_block_hash: Scalar,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    last_transaction_hash: Scalar,
    accounts_root_hash: Scalar,
    program_storage_root_hash: Scalar,
}

impl BlockInfo {
    fn hash_block(
        chain_id: u64,
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        last_transaction_hash: Scalar,
        accounts_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Scalar {
        utils::poseidon_hash(&[
            Scalar::from(chain_id),
            Scalar::from(block_number),
            previous_block_hash,
            Scalar::from(
                timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            network_topology_root_hash,
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        ])
    }

    fn new(
        chain_id: u64,
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        last_transaction_hash: Scalar,
        accounts_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Self {
        Self {
            hash: Self::hash_block(
                chain_id,
                block_number,
                previous_block_hash,
                timestamp,
                network_topology_root_hash,
                last_transaction_hash,
                accounts_root_hash,
                program_storage_root_hash,
            ),
            chain_id,
            number: block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        }
    }

    pub fn hash(&self) -> Scalar {
        self.hash
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn previous_block_hash(&self) -> Scalar {
        self.previous_block_hash
    }

    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    pub fn network_topology_root_hash(&self) -> Scalar {
        self.network_topology_root_hash
    }

    pub fn last_transaction_hash(&self) -> Scalar {
        self.last_transaction_hash
    }

    pub fn accounts_root_hash(&self) -> Scalar {
        self.accounts_root_hash
    }

    pub fn program_storage_root_hash(&self) -> Scalar {
        self.program_storage_root_hash
    }

    pub fn encode(&self) -> libernet::BlockDescriptor {
        libernet::BlockDescriptor {
            block_hash: Some(proto::encode_scalar(self.hash)),
            chain_id: Some(self.chain_id),
            block_number: Some(self.number),
            previous_block_hash: Some(proto::encode_scalar(self.previous_block_hash)),
            timestamp: Some(self.timestamp.into()),
            network_topology_root_hash: Some(proto::encode_scalar(self.network_topology_root_hash)),
            last_transaction_hash: Some(proto::encode_scalar(self.last_transaction_hash)),
            accounts_root_hash: Some(proto::encode_scalar(self.accounts_root_hash)),
            program_storage_root_hash: Some(proto::encode_scalar(self.program_storage_root_hash)),
        }
    }

    pub fn decode(proto: &libernet::BlockDescriptor) -> Result<BlockInfo> {
        let block_hash = proto::decode_scalar(
            proto
                .block_hash
                .as_ref()
                .context("block hash field is missing")?,
        )?;
        let chain_id = proto.chain_id.context("chain ID field is missing")?;
        let block_number = proto
            .block_number
            .context("block number field is missing")?;
        let previous_block_hash = proto::decode_scalar(
            proto
                .previous_block_hash
                .as_ref()
                .context("previous block hash field is missing")?,
        )?;
        let timestamp: SystemTime = proto
            .timestamp
            .context("timestamp field is missing")?
            .try_into()?;
        let network_topology_root_hash = proto::decode_scalar(
            proto
                .network_topology_root_hash
                .as_ref()
                .context("network topology root hash field is missing")?,
        )?;
        let last_transaction_hash = proto::decode_scalar(
            proto
                .last_transaction_hash
                .as_ref()
                .context("last transaction hash field is missing")?,
        )?;
        let accounts_root_hash = proto::decode_scalar(
            proto
                .accounts_root_hash
                .as_ref()
                .context("account balance root hash field is missing")?,
        )?;
        let program_storage_root_hash = proto::decode_scalar(
            proto
                .program_storage_root_hash
                .as_ref()
                .context("program storage root hash field is missing")?,
        )?;
        let block_info = Self::new(
            chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        );
        if block_hash != block_info.hash {
            Err(anyhow!("block hash mismatch"))
        } else {
            Ok(block_info)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    parent_hash: Scalar,
    payload: prost_types::Any,
    signature: libernet::Signature,
    hash: Scalar,
}

impl Transaction {
    fn hash_block_reward_transaction(
        parent_hash: Scalar,
        chain_id: u64,
        nonce: u64,
        sender_address: Scalar,
        transaction: &libernet::transaction::BlockReward,
    ) -> Result<Scalar> {
        Ok(utils::poseidon_hash(&[
            parent_hash,
            sender_address,
            chain_id.into(),
            nonce.into(),
            proto::decode_scalar(
                transaction
                    .recipient
                    .as_ref()
                    .context("invalid block reward transaction: recipient field is missing")?,
            )?,
            proto::decode_scalar(
                transaction
                    .amount
                    .as_ref()
                    .context("invalid block reward transaction: amount field is missing")?,
            )?,
        ]))
    }

    fn hash_send_coins_transaction(
        parent_hash: Scalar,
        chain_id: u64,
        nonce: u64,
        sender_address: Scalar,
        transaction: &libernet::transaction::SendCoins,
    ) -> Result<Scalar> {
        Ok(utils::poseidon_hash(&[
            parent_hash,
            sender_address,
            chain_id.into(),
            nonce.into(),
            proto::decode_scalar(
                transaction
                    .recipient
                    .as_ref()
                    .context("invalid coin transfer transaction: recipient field is missing")?,
            )?,
            proto::decode_scalar(
                transaction
                    .amount
                    .as_ref()
                    .context("invalid coin transfer transaction: amount field is missing")?,
            )?,
        ]))
    }

    fn from_proto_impl(
        parent_hash: Scalar,
        payload: prost_types::Any,
        signature: libernet::Signature,
    ) -> Result<Self> {
        let decoded = payload.to_msg::<libernet::transaction::Payload>()?;
        let chain_id = decoded
            .chain_id
            .context("invalid transaction: network ID field is missing")?;
        let nonce = decoded
            .nonce
            .context("invalid transaction: nonce field is missing")?;
        let signer = proto::decode_scalar(
            signature
                .signer
                .as_ref()
                .context("invalid transaction signature")?,
        )?;
        let hash = match &decoded.transaction.context("invalid transaction")? {
            libernet::transaction::payload::Transaction::BlockReward(transaction) => {
                Self::hash_block_reward_transaction(
                    parent_hash,
                    chain_id,
                    nonce,
                    signer,
                    transaction,
                )
            }
            libernet::transaction::payload::Transaction::SendCoins(transaction) => {
                Self::hash_send_coins_transaction(parent_hash, chain_id, nonce, signer, transaction)
            }
            _ => Err(anyhow!("unknown transaction type")),
        }?;
        Ok(Self {
            parent_hash,
            payload,
            signature,
            hash,
        })
    }

    pub fn from_proto(parent_hash: Scalar, proto: libernet::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        Self::from_proto_impl(parent_hash, payload, signature)
    }

    pub fn from_proto_verify(parent_hash: Scalar, proto: libernet::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        account::Account::verify_signed_message(&payload, &signature)?;
        Self::from_proto_impl(parent_hash, payload, signature)
    }

    pub fn make_block_reward_proto(
        signer: &account::Account,
        chain_id: u64,
        nonce: u64,
        recipient_address: Scalar,
        amount: Scalar,
    ) -> Result<libernet::Transaction> {
        let (payload, signature) = signer.sign_message(&libernet::transaction::Payload {
            chain_id: Some(chain_id),
            nonce: Some(nonce),
            transaction: Some(libernet::transaction::payload::Transaction::BlockReward(
                libernet::transaction::BlockReward {
                    recipient: Some(proto::encode_scalar(recipient_address)),
                    amount: Some(proto::encode_scalar(amount)),
                },
            )),
        })?;
        Ok(libernet::Transaction {
            payload: Some(payload),
            signature: Some(signature),
        })
    }

    pub fn make_coin_transfer_proto(
        signer: &account::Account,
        chain_id: u64,
        nonce: u64,
        recipient_address: Scalar,
        amount: Scalar,
    ) -> Result<libernet::Transaction> {
        let (payload, signature) = signer.sign_message(&libernet::transaction::Payload {
            chain_id: Some(chain_id),
            nonce: Some(nonce),
            transaction: Some(libernet::transaction::payload::Transaction::SendCoins(
                libernet::transaction::SendCoins {
                    recipient: Some(proto::encode_scalar(recipient_address)),
                    amount: Some(proto::encode_scalar(amount)),
                },
            )),
        })?;
        Ok(libernet::Transaction {
            payload: Some(payload),
            signature: Some(signature),
        })
    }

    pub fn parent_hash(&self) -> Scalar {
        self.parent_hash
    }

    pub fn hash(&self) -> Scalar {
        self.hash
    }

    pub fn diff(&self) -> libernet::Transaction {
        libernet::Transaction {
            payload: Some(self.payload.clone()),
            signature: Some(self.signature.clone()),
        }
    }

    pub fn signer(&self) -> Scalar {
        proto::decode_scalar(self.signature.signer.as_ref().unwrap()).unwrap()
    }

    pub fn payload(&self) -> libernet::transaction::Payload {
        self.payload
            .to_msg::<libernet::transaction::Payload>()
            .unwrap()
    }
}

impl PoseidonHash for Transaction {
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

fn make_genesis_block(
    chain_id: u64,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    accounts_root_hash: Scalar,
) -> BlockInfo {
    let block_number = 0;
    let program_storage_root_hash = tree::ProgramStorageTree::default().root_hash(block_number);
    BlockInfo::new(
        chain_id,
        block_number,
        Scalar::ZERO,
        timestamp,
        network_topology_root_hash,
        Scalar::ZERO,
        accounts_root_hash,
        program_storage_root_hash,
    )
}

struct BlockListener {
    id: u64,
    sender: Sender<BlockInfo>,
}

impl BlockListener {
    fn new(sender: Sender<BlockInfo>) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            sender,
        }
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn notify(&self, block_info: BlockInfo) -> Result<()> {
        Ok(self.sender.try_send(block_info)?)
    }
}

impl PartialEq for BlockListener {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for BlockListener {}

impl PartialOrd for BlockListener {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.id.partial_cmp(&other.id)
    }
}

impl Ord for BlockListener {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl Borrow<u64> for BlockListener {
    fn borrow(&self) -> &u64 {
        &self.id
    }
}

#[derive(Clone)]
pub struct AccountState {
    block_info: BlockInfo,
    proof: tree::AccountProof,
}

impl AccountState {
    pub fn block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    pub fn account_info(&self) -> &tree::AccountInfo {
        self.proof.value()
    }

    pub fn encode(&self) -> Result<libernet::MerkleProof> {
        self.proof.encode(self.block_info.encode())
    }
}

struct AccountListener {
    id: u64,
    sender: Sender<AccountState>,
}

impl AccountListener {
    fn new(sender: Sender<AccountState>) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            sender,
        }
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn notify(&self, account_state: AccountState) -> Result<()> {
        Ok(self.sender.try_send(account_state)?)
    }
}

impl PartialEq for AccountListener {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AccountListener {}

impl PartialOrd for AccountListener {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.id.partial_cmp(&other.id)
    }
}

impl Ord for AccountListener {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl Borrow<u64> for AccountListener {
    fn borrow(&self) -> &u64 {
        &self.id
    }
}

struct Repr {
    chain_id: u64,
    blocks: Vec<BlockInfo>,
    block_numbers_by_hash: BTreeMap<Scalar, usize>,
    network_topologies: BTreeMap<u64, topology::Network>,
    transactions: Vec<Transaction>,
    transactions_by_hash: BTreeMap<Scalar, usize>,
    accounts: tree::AccountTree,
    program_storage: tree::ProgramStorageTree,

    block_listeners: BTreeSet<BlockListener>,
    account_watchers: BTreeMap<Scalar, BTreeSet<AccountListener>>,
    account_listeners: BTreeMap<Scalar, BTreeSet<AccountListener>>,
}

impl Repr {
    fn new<const N: usize>(
        clock: &Arc<dyn Clock>,
        chain_id: u64,
        identity: libernet::NodeIdentity,
        initial_accounts: [(Scalar, tree::AccountInfo); N],
    ) -> Result<Self> {
        let network = topology::Network::new(identity)?;
        let accounts = tree::AccountTree::from(initial_accounts);
        let genesis_block = make_genesis_block(
            chain_id,
            clock.now(),
            network.root_hash(),
            accounts.root_hash(0),
        );
        Ok(Self {
            chain_id,
            blocks: vec![genesis_block],
            block_numbers_by_hash: BTreeMap::from([(genesis_block.hash(), 0)]),
            network_topologies: BTreeMap::from([(0, network)]),
            transactions: vec![],
            transactions_by_hash: BTreeMap::new(),
            accounts,
            program_storage: tree::ProgramStorageTree::default(),
            block_listeners: BTreeSet::default(),
            account_watchers: BTreeMap::default(),
            account_listeners: BTreeMap::default(),
        })
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn current_version(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn get_block_by_number(&self, block_number: usize) -> Option<BlockInfo> {
        if block_number < self.blocks.len() {
            Some(self.blocks[block_number])
        } else {
            None
        }
    }

    fn get_block_by_hash(&self, block_hash: Scalar) -> Option<BlockInfo> {
        if let Some(block_number) = self.block_numbers_by_hash.get(&block_hash) {
            self.get_block_by_number(*block_number)
        } else {
            None
        }
    }

    fn get_latest_block(&self) -> BlockInfo {
        self.blocks[self.blocks.len() - 1]
    }

    fn listen_to_blocks(&mut self) -> Receiver<BlockInfo> {
        let (sender, receiver) = channel(6);
        self.block_listeners.insert(BlockListener::new(sender));
        receiver
    }

    fn get_account_info(
        &self,
        account_address: Scalar,
        block_hash: Scalar,
    ) -> Result<AccountState> {
        match self.get_block_by_hash(block_hash) {
            Some(block) => Ok(AccountState {
                block_info: block,
                proof: self.accounts.get_proof(account_address, block.number()),
            }),
            None => Err(anyhow!(
                "block {} not found",
                utils::format_scalar(block_hash)
            )),
        }
    }

    fn get_latest_account_info(&self, account_address: Scalar) -> Result<AccountState> {
        let block = self.get_latest_block();
        Ok(AccountState {
            block_info: block,
            proof: self.accounts.get_proof(account_address, block.number()),
        })
    }

    fn watch_account(&mut self, account_address: Scalar) -> Receiver<AccountState> {
        let (sender, receiver) = channel(6);
        let watcher = AccountListener::new(sender);
        match self.account_watchers.get_mut(&account_address) {
            Some(watchers) => {
                watchers.insert(watcher);
            }
            None => {
                self.account_watchers
                    .insert(account_address, BTreeSet::from([watcher]));
            }
        };
        receiver
    }

    fn listen_for_account_changes(&mut self, account_address: Scalar) -> Receiver<AccountState> {
        let (sender, receiver) = channel(6);
        let listener = AccountListener::new(sender);
        match self.account_listeners.get_mut(&account_address) {
            Some(listeners) => {
                listeners.insert(listener);
            }
            None => {
                self.account_listeners
                    .insert(account_address, BTreeSet::from([listener]));
            }
        };
        receiver
    }

    fn get_transaction(&self, hash: Scalar) -> Option<Transaction> {
        let index = *(self.transactions_by_hash.get(&hash)?);
        Some(self.transactions[index].clone())
    }

    fn get_all_block_transaction_hashes(&self, block_number: usize) -> Result<Vec<Scalar>> {
        if block_number >= self.blocks.len() {
            return Err(anyhow!("block #{} not found", block_number));
        }
        let block_info = self.blocks[block_number];
        let previous_transaction_hash = if block_number > 0 {
            self.blocks[block_number - 1].last_transaction_hash()
        } else {
            0.into()
        };
        let mut transaction_hashes = vec![];
        let mut hash = block_info.last_transaction_hash();
        while hash != previous_transaction_hash {
            transaction_hashes.push(hash);
            let index = *self.transactions_by_hash.get(&hash).unwrap();
            hash = self.transactions[index].parent_hash();
        }
        transaction_hashes.reverse();
        Ok(transaction_hashes)
    }

    fn apply_block_reward_transaction(
        &mut self,
        payload: &libernet::transaction::BlockReward,
    ) -> Result<()> {
        let version = self.current_version();
        let recipient = proto::decode_scalar(
            payload
                .recipient
                .as_ref()
                .context("invalid block reward transaction payload: missing recipient")?,
        )?;
        let amount = proto::decode_scalar(
            payload
                .amount
                .as_ref()
                .context("invalid block reward transaction payload: missing amount")?,
        )?;
        let mut recipient_account = *self.accounts.get(recipient, version);
        recipient_account.balance += amount;
        self.accounts.put(recipient, recipient_account, version);
        Ok(())
    }

    fn apply_send_coins_transaction(
        &mut self,
        signer: Scalar,
        payload: &libernet::transaction::SendCoins,
    ) -> Result<()> {
        let version = self.current_version();
        let recipient = proto::decode_scalar(
            payload
                .recipient
                .as_ref()
                .context("invalid coin transfer transaction payload: missing recipient")?,
        )?;
        let amount = proto::decode_scalar(
            payload
                .amount
                .as_ref()
                .context("invalid coin transfer transaction payload: missing amount")?,
        )?;
        let mut signer_account = *self.accounts.get(signer, version);
        let sender_balance = signer_account.balance;
        if sender_balance < amount {
            return Err(anyhow!(
                "insufficient balance for {:#x}: {} available, cannot transfer {}",
                utils::scalar_to_u256(signer),
                utils::scalar_to_u256(sender_balance),
                utils::scalar_to_u256(amount),
            ));
        }
        signer_account.balance -= amount;
        self.accounts.put(signer, signer_account, version);
        let mut recipient_account = *self.accounts.get(recipient, version);
        recipient_account.balance += amount;
        self.accounts.put(recipient, recipient_account, version);
        Ok(())
    }

    fn apply_transaction(
        &mut self,
        transaction: &Transaction,
        fail_on_block_reward: bool,
    ) -> Result<()> {
        let signer = transaction.signer();
        let payload = &transaction.payload();
        if payload.chain_id() != self.chain_id {
            return Err(anyhow!(
                "invalid chain ID {} (this is network {})",
                payload.chain_id(),
                self.chain_id
            ));
        }
        let block_number = self.current_version();
        let nonce = payload.nonce();
        let signer_account = *self.accounts.get(signer, block_number);
        if nonce <= signer_account.last_nonce {
            return Err(anyhow!(
                "invalid nonce {} (latest for {:#x} is {})",
                nonce,
                utils::scalar_to_u256(signer),
                signer_account.last_nonce,
            ));
        }
        match &payload.transaction {
            Some(libernet::transaction::payload::Transaction::BlockReward(payload)) => {
                if fail_on_block_reward {
                    Err(anyhow!("block reward transactions may not be broadcast"))
                } else {
                    self.apply_block_reward_transaction(payload)
                }
            }
            Some(libernet::transaction::payload::Transaction::SendCoins(payload)) => {
                self.apply_send_coins_transaction(signer, payload)
            }
            Some(libernet::transaction::payload::Transaction::CreateProgram(_)) => {
                todo!()
            }
            None => Err(anyhow!("invalid transaction payload")),
        }?;
        let mut signer_account = *self.accounts.get(signer, block_number);
        signer_account.last_nonce = nonce;
        self.accounts.put(signer, signer_account, block_number);
        Ok(())
    }

    fn add_transaction(
        &mut self,
        transaction: &libernet::Transaction,
        fail_on_block_reward: bool,
    ) -> Result<Scalar> {
        let parent_hash = match self.transactions.last() {
            Some(last_transaction) => last_transaction.hash(),
            None => Scalar::ZERO,
        };
        let transaction = Transaction::from_proto(parent_hash, transaction.clone())?;
        let hash = transaction.hash();
        self.apply_transaction(&transaction, fail_on_block_reward)?;
        let index = self.transactions.len();
        self.transactions.push(transaction);
        self.transactions_by_hash.insert(hash, index);
        Ok(hash)
    }

    fn close_block(&mut self, timestamp: SystemTime) -> BlockInfo {
        let block_number = self.current_version();
        let previous_block_hash = self.blocks.last().unwrap().hash();
        let (_, network_topology) = self
            .network_topologies
            .range(0..=block_number)
            .next_back()
            .unwrap();
        let last_transaction_hash = match self.transactions.last() {
            Some(transaction) => transaction.hash(),
            None => Scalar::ZERO,
        };
        let accounts_root_hash = self.accounts.root_hash(block_number);
        let program_storage_root_hash = self.program_storage.root_hash(block_number);
        let block = BlockInfo::new(
            self.chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology.root_hash(),
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        );
        let block_hash = block.hash();
        self.blocks.push(block);
        self.block_numbers_by_hash
            .insert(block_hash, block_number as usize);
        block
    }

    fn notify_block(&mut self, block_info: &BlockInfo) {
        let mut closed = vec![];
        for listener in &self.block_listeners {
            if listener.notify(*block_info).is_err() {
                closed.push(listener.id());
            }
        }
        for id in closed {
            self.block_listeners.remove(&id);
        }
    }

    fn notify_accounts(&mut self, block_info: &BlockInfo) {
        let current_version = self.accounts.get_version((self.blocks.len() - 1) as u64);
        let mut empty_accounts = vec![];
        for (account_address, listeners) in &mut self.account_watchers {
            let message = AccountState {
                block_info: *block_info,
                proof: current_version.get_proof(*account_address),
            };
            let mut closed = vec![];
            for listener in &*listeners {
                if listener.notify(message.clone()).is_err() {
                    closed.push(listener.id());
                }
            }
            for id in closed {
                listeners.remove(&id);
            }
            if listeners.is_empty() {
                empty_accounts.push(*account_address);
            }
        }
        for address in &empty_accounts {
            self.account_watchers.remove(address);
        }
    }

    fn notify_account_changes(&mut self, block_info: &BlockInfo) {
        let previous_version = self.accounts.get_version((self.blocks.len() - 2) as u64);
        let current_version = self.accounts.get_version((self.blocks.len() - 1) as u64);
        let mut empty_accounts = vec![];
        for (account_address, listeners) in &mut self.account_listeners {
            let previous_hash = previous_version.get(*account_address).as_scalar();
            let account = current_version.get(*account_address);
            if account.as_scalar() != previous_hash {
                let message = AccountState {
                    block_info: *block_info,
                    proof: current_version.get_proof(*account_address),
                };
                let mut closed = vec![];
                for listener in &*listeners {
                    if listener.notify(message.clone()).is_err() {
                        closed.push(listener.id());
                    }
                }
                for id in closed {
                    listeners.remove(&id);
                }
                if listeners.is_empty() {
                    empty_accounts.push(*account_address);
                }
            }
        }
        for address in &empty_accounts {
            self.account_listeners.remove(address);
        }
    }
}

pub struct Db {
    clock: Arc<dyn Clock>,
    repr: Mutex<Repr>,
}

impl Db {
    pub fn new<const N: usize>(
        clock: Arc<dyn Clock>,
        chain_id: u64,
        identity: libernet::NodeIdentity,
        initial_accounts: [(Scalar, tree::AccountInfo); N],
    ) -> Result<Self> {
        let repr = Repr::new(&clock, chain_id, identity, initial_accounts)?;
        Ok(Self {
            clock,
            repr: Mutex::new(repr),
        })
    }

    pub async fn chain_id(&self) -> u64 {
        self.repr.lock().await.chain_id()
    }

    pub async fn current_version(&self) -> u64 {
        self.repr.lock().await.current_version()
    }

    pub async fn get_block_by_number(&self, block_number: usize) -> Option<BlockInfo> {
        self.repr.lock().await.get_block_by_number(block_number)
    }

    pub async fn get_block_by_hash(&self, block_hash: Scalar) -> Option<BlockInfo> {
        self.repr.lock().await.get_block_by_hash(block_hash)
    }

    pub async fn get_latest_block(&self) -> BlockInfo {
        self.repr.lock().await.get_latest_block()
    }

    pub async fn listen_to_blocks(&self) -> Receiver<BlockInfo> {
        self.repr.lock().await.listen_to_blocks()
    }

    pub async fn get_account_info(
        &self,
        account_address: Scalar,
        block_hash: Scalar,
    ) -> Result<AccountState> {
        self.repr
            .lock()
            .await
            .get_account_info(account_address, block_hash)
    }

    pub async fn get_latest_account_info(&self, account_address: Scalar) -> Result<AccountState> {
        self.repr
            .lock()
            .await
            .get_latest_account_info(account_address)
    }

    pub async fn watch_account(&self, account_address: Scalar) -> Receiver<AccountState> {
        self.repr.lock().await.watch_account(account_address)
    }

    pub async fn listen_for_account_changes(
        &self,
        account_address: Scalar,
    ) -> Receiver<AccountState> {
        self.repr
            .lock()
            .await
            .listen_for_account_changes(account_address)
    }

    pub async fn get_transaction(&self, hash: Scalar) -> Option<Transaction> {
        self.repr.lock().await.get_transaction(hash)
    }

    pub async fn get_all_block_transaction_hashes(
        &self,
        block_number: usize,
    ) -> Result<Vec<Scalar>> {
        self.repr
            .lock()
            .await
            .get_all_block_transaction_hashes(block_number)
    }

    pub async fn add_transaction(&self, transaction: &libernet::Transaction) -> Result<Scalar> {
        self.repr.lock().await.add_transaction(transaction, false)
    }

    /// This method is the same as `add_transaction` except that it fails if the payload is a block
    /// reward transaction. The `BroadcastTransaction` RPC must be served using this method because
    /// block reward transactions may not be broadcast.
    pub async fn add_transaction_blocking_rewards(
        &self,
        transaction: &libernet::Transaction,
    ) -> Result<Scalar> {
        self.repr.lock().await.add_transaction(transaction, true)
    }

    pub async fn close_block(&self) -> BlockInfo {
        let mut repr = self.repr.lock().await;
        let block_info = repr.close_block(self.clock.now());
        repr.notify_block(&block_info);
        repr.notify_accounts(&block_info);
        repr.notify_account_changes(&block_info);
        block_info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::parse_scalar;
    use std::time::Duration;

    #[test]
    fn test_block_info1() {
        let block_info = BlockInfo::new(
            123,
            12,
            parse_scalar("0x387d4e5f500fb33a27eb820239e845aaef7a84f852be4033a7d3c23d64571ea7"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            parse_scalar("0x351e6822f39868e620d10995eb2c58513ccce8e55d0998e78bce97703c15df68"),
            parse_scalar("0x25cec4238bfaa905f2c97075aade1b266fc1120ccca08634e5adf1572d4d03ce"),
            parse_scalar("0x277b1387699dc9fe9636af621c72872278d290344266612ce6e79555664361c8"),
            parse_scalar("0x2b346f1eeac6cd03a43c826d72a102e78d82dcf249c01fc9f185a4b957daf060"),
        );
        assert_eq!(
            block_info.hash(),
            parse_scalar("0x233ad3460c6a12bae72dbf6056ffdd08ef5a52016b345857153d0cb4ee8c6c9b")
        );
        assert_eq!(block_info.chain_id(), 123);
        assert_eq!(block_info.number(), 12);
        assert_eq!(
            block_info.previous_block_hash(),
            parse_scalar("0x387d4e5f500fb33a27eb820239e845aaef7a84f852be4033a7d3c23d64571ea7")
        );
        assert_eq!(
            block_info.timestamp(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(71104)
        );
        assert_eq!(
            block_info.network_topology_root_hash(),
            parse_scalar("0x351e6822f39868e620d10995eb2c58513ccce8e55d0998e78bce97703c15df68")
        );
        assert_eq!(
            block_info.last_transaction_hash(),
            parse_scalar("0x25cec4238bfaa905f2c97075aade1b266fc1120ccca08634e5adf1572d4d03ce")
        );
        assert_eq!(
            block_info.accounts_root_hash(),
            parse_scalar("0x277b1387699dc9fe9636af621c72872278d290344266612ce6e79555664361c8")
        );
        assert_eq!(
            block_info.program_storage_root_hash(),
            parse_scalar("0x2b346f1eeac6cd03a43c826d72a102e78d82dcf249c01fc9f185a4b957daf060")
        );
    }

    #[test]
    fn test_block_info2() {
        let block_info = BlockInfo::new(
            456,
            34,
            parse_scalar("0x3b2fc7f32a00e220e6d6792714bfa01679c7a176e2be92cae1d3fab56a28610b"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(40117),
            parse_scalar("0x6850d697616cd6f003c99cc13840251db4c9e5bbf2a0daf24fdf371ed0fa0eb1"),
            parse_scalar("0x5159768a2180cf64008a38917360b7811b1ca488390e76c71ed3c6602f48a51d"),
            parse_scalar("0x367a546a703795bc1c3965eb037297dfe4956e4866b67e22d0b12995b9f4fbff"),
            parse_scalar("0x5f2fd026dfc233c1e1adfbcd7c6b20280db9b33e12f493802a72b9a7f55f0a2"),
        );
        assert_eq!(
            block_info.hash(),
            parse_scalar("0x5cc2eaa017792482d14d6fbf56a432a28c4a390e0169e58892fae279c23ad022")
        );
        assert_eq!(block_info.chain_id(), 456);
        assert_eq!(block_info.number(), 34);
        assert_eq!(
            block_info.previous_block_hash(),
            parse_scalar("0x3b2fc7f32a00e220e6d6792714bfa01679c7a176e2be92cae1d3fab56a28610b")
        );
        assert_eq!(
            block_info.timestamp(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(40117)
        );
        assert_eq!(
            block_info.network_topology_root_hash(),
            parse_scalar("0x6850d697616cd6f003c99cc13840251db4c9e5bbf2a0daf24fdf371ed0fa0eb1")
        );
        assert_eq!(
            block_info.last_transaction_hash(),
            parse_scalar("0x5159768a2180cf64008a38917360b7811b1ca488390e76c71ed3c6602f48a51d")
        );
        assert_eq!(
            block_info.accounts_root_hash(),
            parse_scalar("0x367a546a703795bc1c3965eb037297dfe4956e4866b67e22d0b12995b9f4fbff")
        );
        assert_eq!(
            block_info.program_storage_root_hash(),
            parse_scalar("0x5f2fd026dfc233c1e1adfbcd7c6b20280db9b33e12f493802a72b9a7f55f0a2")
        );
    }

    #[test]
    fn test_encode_block_info1() {
        let block_info = BlockInfo::new(
            123,
            12,
            parse_scalar("0x387d4e5f500fb33a27eb820239e845aaef7a84f852be4033a7d3c23d64571ea7"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            parse_scalar("0x351e6822f39868e620d10995eb2c58513ccce8e55d0998e78bce97703c15df68"),
            parse_scalar("0x25cec4238bfaa905f2c97075aade1b266fc1120ccca08634e5adf1572d4d03ce"),
            parse_scalar("0x277b1387699dc9fe9636af621c72872278d290344266612ce6e79555664361c8"),
            parse_scalar("0x2b346f1eeac6cd03a43c826d72a102e78d82dcf249c01fc9f185a4b957daf060"),
        );
        let block_descriptor = block_info.encode();
        assert_eq!(block_info, BlockInfo::decode(&block_descriptor).unwrap());
        assert_eq!(
            proto::decode_scalar(&block_descriptor.block_hash.unwrap()).unwrap(),
            parse_scalar("0x233ad3460c6a12bae72dbf6056ffdd08ef5a52016b345857153d0cb4ee8c6c9b")
        );
        assert_eq!(block_descriptor.chain_id, Some(123));
        assert_eq!(block_descriptor.block_number, Some(12));
        assert_eq!(
            proto::decode_scalar(&block_descriptor.previous_block_hash.unwrap()).unwrap(),
            parse_scalar("0x387d4e5f500fb33a27eb820239e845aaef7a84f852be4033a7d3c23d64571ea7")
        );
        assert_eq!(
            TryInto::<SystemTime>::try_into(block_descriptor.timestamp.unwrap()).unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(71104)
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.network_topology_root_hash.unwrap()).unwrap(),
            parse_scalar("0x351e6822f39868e620d10995eb2c58513ccce8e55d0998e78bce97703c15df68")
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.last_transaction_hash.unwrap()).unwrap(),
            parse_scalar("0x25cec4238bfaa905f2c97075aade1b266fc1120ccca08634e5adf1572d4d03ce")
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.accounts_root_hash.unwrap()).unwrap(),
            parse_scalar("0x277b1387699dc9fe9636af621c72872278d290344266612ce6e79555664361c8")
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.program_storage_root_hash.unwrap()).unwrap(),
            parse_scalar("0x2b346f1eeac6cd03a43c826d72a102e78d82dcf249c01fc9f185a4b957daf060")
        );
    }

    #[test]
    fn test_encode_block_info2() {
        let block_info = BlockInfo::new(
            456,
            34,
            parse_scalar("0x3b2fc7f32a00e220e6d6792714bfa01679c7a176e2be92cae1d3fab56a28610b"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(40117),
            parse_scalar("0x6850d697616cd6f003c99cc13840251db4c9e5bbf2a0daf24fdf371ed0fa0eb1"),
            parse_scalar("0x5159768a2180cf64008a38917360b7811b1ca488390e76c71ed3c6602f48a51d"),
            parse_scalar("0x367a546a703795bc1c3965eb037297dfe4956e4866b67e22d0b12995b9f4fbff"),
            parse_scalar("0x5f2fd026dfc233c1e1adfbcd7c6b20280db9b33e12f493802a72b9a7f55f0a2"),
        );
        let block_descriptor = block_info.encode();
        assert_eq!(block_info, BlockInfo::decode(&block_descriptor).unwrap());
        assert_eq!(
            proto::decode_scalar(&block_descriptor.block_hash.unwrap()).unwrap(),
            parse_scalar("0x5cc2eaa017792482d14d6fbf56a432a28c4a390e0169e58892fae279c23ad022")
        );
        assert_eq!(block_descriptor.chain_id, Some(456));
        assert_eq!(block_descriptor.block_number, Some(34));
        assert_eq!(
            proto::decode_scalar(&block_descriptor.previous_block_hash.unwrap()).unwrap(),
            parse_scalar("0x3b2fc7f32a00e220e6d6792714bfa01679c7a176e2be92cae1d3fab56a28610b")
        );
        assert_eq!(
            TryInto::<SystemTime>::try_into(block_descriptor.timestamp.unwrap()).unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(40117)
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.network_topology_root_hash.unwrap()).unwrap(),
            parse_scalar("0x6850d697616cd6f003c99cc13840251db4c9e5bbf2a0daf24fdf371ed0fa0eb1")
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.last_transaction_hash.unwrap()).unwrap(),
            parse_scalar("0x5159768a2180cf64008a38917360b7811b1ca488390e76c71ed3c6602f48a51d")
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.accounts_root_hash.unwrap()).unwrap(),
            parse_scalar("0x367a546a703795bc1c3965eb037297dfe4956e4866b67e22d0b12995b9f4fbff")
        );
        assert_eq!(
            proto::decode_scalar(&block_descriptor.program_storage_root_hash.unwrap()).unwrap(),
            parse_scalar("0x5f2fd026dfc233c1e1adfbcd7c6b20280db9b33e12f493802a72b9a7f55f0a2")
        );
    }

    // TODO
}
