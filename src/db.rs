use crate::accounts::AccountStore;
use crate::clock::Clock;
use crate::constants;
use crate::data::{
    AccountInfo, AccountProof, BlockHeader, BlockInfo, BlockList, ProgramStorageTree, Transaction,
    TransactionInclusionProof,
};
use crate::libernet;
use crate::proto::{self, EncodeMerkleProof};
use crate::store::NodeData;
use crate::topology;
use crate::transactions::TransactionStore;
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::{
    merkle::{self, AsScalar, FromScalar},
    utils,
};
use ff::Field;
use memmap2::MmapMut;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::ops::RangeInclusive;
use std::sync::{Arc, atomic::AtomicU64};
use std::time::SystemTime;
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender, channel},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockFilter {
    BlockHash(Scalar),
    BlockNumber(usize),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone)]
pub struct QueryResults<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
>(Vec<(BlockInfo, Vec<merkle::Proof<K, V, W, H>>)>);

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + proto::EncodeToAny + 'static,
    const W: usize,
    const H: usize,
> QueryResults<K, V, W, H>
{
    fn add_block(&mut self, block_info: BlockInfo, block_results: Vec<merkle::Proof<K, V, W, H>>) {
        self.0.push((block_info, block_results));
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + proto::EncodeToAny + 'static,
    const H: usize,
> QueryResults<K, V, 2, H>
{
    pub fn encode(&self) -> Result<Vec<libernet::MerkleProof>> {
        let mut results = Vec::with_capacity(self.0.len());
        for (block_info, proofs) in &self.0 {
            let block_descriptor = block_info.encode();
            for proof in proofs {
                results.push(proof.encode(block_descriptor.clone())?);
            }
        }
        Ok(results)
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + proto::EncodeToAny + 'static,
    const H: usize,
> QueryResults<K, V, 3, H>
{
    pub fn encode(&self) -> Result<Vec<libernet::MerkleProof>> {
        let mut results = Vec::with_capacity(self.0.len());
        for (block_info, proofs) in &self.0 {
            let block_descriptor = block_info.encode();
            for proof in proofs {
                results.push(proof.encode(block_descriptor.clone())?);
            }
        }
        Ok(results)
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> Default for QueryResults<K, V, 2, H>
{
    fn default() -> Self {
        Self(vec![])
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> Default for QueryResults<K, V, 3, H>
{
    fn default() -> Self {
        Self(vec![])
    }
}

pub type TransactionQueryResults = QueryResults<Scalar, Transaction, 2, 32>;

fn make_genesis_block(
    chain_id: u64,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    accounts_root_hash: Scalar,
) -> Result<BlockInfo> {
    let block_number = 0;
    let transactions_root_hash = TransactionStore::default()?.current_root_hash();
    let program_storage_root_hash = ProgramStorageTree::default().root_hash(block_number);
    Ok(BlockInfo::new(
        chain_id,
        block_number,
        Scalar::ZERO,
        timestamp,
        network_topology_root_hash,
        transactions_root_hash,
        accounts_root_hash,
        program_storage_root_hash,
    ))
}

/// Allows locating a specific transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TransactionLocator {
    /// The number of the block where the transaction is included.
    block_number: usize,

    /// The number of the transaction within the block, i.e. 0 for the first, 1 for the second, etc.
    transaction_number: usize,
}

struct BlockListener {
    id: u64,
    sender: Sender<BlockInfo>,
}

impl BlockListener {
    fn new(sender: Sender<BlockInfo>) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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
    proof: AccountProof,
}

impl AccountState {
    pub fn block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    pub fn account_info(&self) -> &AccountInfo {
        self.proof.value()
    }

    pub fn take(self) -> AccountInfo {
        self.proof.take_value()
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
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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

    blocks: BlockList,
    block_hashes_by_number: Vec<Scalar>,

    network_topologies: BTreeMap<u64, topology::Network>,

    transactions: TransactionStore,
    transaction_locators_by_hash: BTreeMap<Scalar, TransactionLocator>,
    transactions_by_signer: BTreeMap<Scalar, Vec<Scalar>>,
    transactions_by_recipient: BTreeMap<Scalar, Vec<Scalar>>,

    accounts: AccountStore,
    program_storage: ProgramStorageTree,

    block_listeners: BTreeSet<BlockListener>,
    account_watchers: BTreeMap<Scalar, BTreeSet<AccountListener>>,
    account_listeners: BTreeMap<Scalar, BTreeSet<AccountListener>>,
}

impl Repr {
    fn new(
        clock: &Arc<dyn Clock>,
        chain_id: u64,
        identity: libernet::NodeIdentity,
        initial_accounts: &[(Scalar, AccountInfo)],
    ) -> Result<Self> {
        let network = topology::Network::new(identity)?;
        let accounts = AccountStore::from(initial_accounts)?;
        let genesis_block = make_genesis_block(
            chain_id,
            clock.now(),
            network.root_hash(),
            accounts.root_hash(0),
        )?;
        let mut blocks = BlockList::new(
            MmapMut::map_anon(
                BlockList::PADDED_HEADER_SIZE
                    + BlockList::min_capacity() * BlockList::padded_node_size(),
            )?,
            constants::DATA_FILE_TYPE_BLOCK_DESCRIPTORS,
        )?;
        blocks.insert_hashed(*genesis_block.header(), genesis_block.hash())?;
        let mut transactions = TransactionStore::default()?;
        transactions.commit();
        Ok(Self {
            chain_id,
            blocks,
            block_hashes_by_number: vec![genesis_block.hash()],
            network_topologies: BTreeMap::from([(0, network)]),
            transactions,
            transaction_locators_by_hash: BTreeMap::default(),
            transactions_by_signer: BTreeMap::default(),
            transactions_by_recipient: BTreeMap::default(),
            accounts,
            program_storage: ProgramStorageTree::default(),
            block_listeners: BTreeSet::default(),
            account_watchers: BTreeMap::default(),
            account_listeners: BTreeMap::default(),
        })
    }

    fn current_version(&self) -> u64 {
        self.block_hashes_by_number.len() as u64
    }

    fn get_block_by_number(&self, block_number: usize) -> Option<BlockInfo> {
        if block_number >= self.block_hashes_by_number.len() {
            return None;
        }
        let block_hash = self.block_hashes_by_number[block_number];
        let header = self.blocks.get(block_hash).unwrap();
        Some(BlockInfo::from_parts(block_hash, *header))
    }

    fn get_block_by_hash(&self, block_hash: Scalar) -> Option<BlockInfo> {
        if let Some(header) = self.blocks.get(block_hash) {
            Some(BlockInfo::from_parts(block_hash, *header))
        } else {
            None
        }
    }

    fn get_latest_block(&self) -> BlockInfo {
        let block_hash = *self.block_hashes_by_number.last().unwrap();
        let header = *self.blocks.get(block_hash).unwrap();
        BlockInfo::from_parts(block_hash, header)
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
                proof: self
                    .accounts
                    .get_proof(account_address, block.number() as usize),
            }),
            None => Err(anyhow!(
                "block {} not found",
                utils::format_scalar(block_hash)
            )),
        }
    }

    fn get_latest_account_info(&self, account_address: Scalar) -> AccountState {
        let block = self.get_latest_block();
        AccountState {
            block_info: block,
            proof: self
                .accounts
                .get_proof(account_address, block.number() as usize),
        }
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

    fn check_block_number(&self, block_number: usize) -> Option<usize> {
        // NOTE: we're checking `block_number` against the length of `self.blocks` rather than
        // `self.transactions_per_block` because `block_number` must refer to a closed block, not to
        // the one that's being built.
        //
        // TODO: maybe store pending transactions in a separate data structure that works as the
        // mempool and merge the `self.blocks` and `self.transactions_per_block` vectors into one.
        if block_number < self.block_hashes_by_number.len() {
            Some(block_number)
        } else {
            None
        }
    }

    fn get_transaction(&self, hash: Scalar) -> Result<(BlockInfo, TransactionInclusionProof)> {
        let locator = *(self
            .transaction_locators_by_hash
            .get(&hash)
            .context(format!(
                "transaction {} not found",
                utils::format_scalar(hash)
            ))?);
        let block_number = self.check_block_number(locator.block_number).unwrap();
        let block_info = self.get_block_by_number(block_number).unwrap();
        let proof = self
            .transactions
            .get_proof(block_number, locator.transaction_number)?;
        Ok((block_info, proof))
    }

    fn get_all_block_transaction_hashes(&self, block_number: usize) -> Result<Vec<Scalar>> {
        let block_number = self
            .check_block_number(block_number)
            .context(format!("block #{} not found", block_number))?;
        self.transactions.get_hashes(block_number)
    }

    fn apply_block_reward_transaction(
        &mut self,
        payload: &libernet::transaction::BlockReward,
    ) -> Result<()> {
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
        let recipient_account = self.accounts.get_latest(recipient).add_to_balance(amount)?;
        self.accounts.put(recipient, recipient_account)?;
        Ok(())
    }

    fn apply_send_coins_transaction(
        &mut self,
        signer: Scalar,
        payload: &libernet::transaction::SendCoins,
    ) -> Result<()> {
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
        let mut signer_account = self.accounts.get_latest(signer);
        let sender_balance = signer_account.balance();
        if sender_balance < amount {
            return Err(anyhow!(
                "insufficient balance for {}: {} available, cannot transfer {}",
                utils::format_scalar(signer),
                utils::scalar_to_u256(sender_balance),
                utils::scalar_to_u256(amount),
            ));
        }
        signer_account = signer_account.sub_from_balance(amount)?;
        self.accounts.put(signer, signer_account)?;
        let mut recipient_account = self.accounts.get_latest(recipient);
        recipient_account = recipient_account.add_to_balance(amount)?;
        self.accounts.put(recipient, recipient_account)?;
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
        let nonce = payload.nonce();
        let signer_account = self.accounts.get_latest(signer);
        if nonce <= signer_account.last_nonce() {
            return Err(anyhow!(
                "invalid nonce {} (latest for {} is {})",
                nonce,
                utils::format_scalar(signer),
                signer_account.last_nonce(),
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
                // TODO
                return Err(anyhow!("not yet implemented"));
            }
            None => Err(anyhow!("invalid transaction payload")),
        }?;
        let mut signer_account = self.accounts.get_latest(signer);
        signer_account = signer_account.set_last_nonce(nonce);
        self.accounts.put(signer, signer_account)?;
        Ok(())
    }

    fn get_transaction_params(
        transaction: &Transaction,
    ) -> Result<(Scalar, Scalar, Option<Scalar>)> {
        let hash = transaction.hash();
        let signer = transaction.signer();
        let inner = transaction.payload().transaction.unwrap();
        let recipient = match &inner {
            libernet::transaction::payload::Transaction::BlockReward(payload) => {
                Some(proto::decode_scalar(payload.recipient.as_ref().unwrap())?)
            }
            libernet::transaction::payload::Transaction::SendCoins(payload) => {
                Some(proto::decode_scalar(payload.recipient.as_ref().unwrap())?)
            }
            _ => None,
        };
        Ok((hash, signer, recipient))
    }

    fn add_transaction(
        &mut self,
        transaction: libernet::Transaction,
        fail_on_block_reward: bool,
    ) -> Result<Scalar> {
        let transaction = Transaction::from_proto(transaction)?;
        let (hash, signer, recipient) = Self::get_transaction_params(&transaction)?;
        self.apply_transaction(&transaction, fail_on_block_reward)?;
        let transaction_number = self.transactions.push(&transaction)?;
        self.transaction_locators_by_hash.insert(
            hash,
            TransactionLocator {
                block_number: self.current_version() as usize,
                transaction_number,
            },
        );
        if let Some(transaction_hashes) = self.transactions_by_signer.get_mut(&signer) {
            transaction_hashes.push(hash);
        } else {
            self.transactions_by_signer.insert(signer, vec![hash]);
        }
        if let Some(recipient) = recipient {
            if let Some(transaction_hashes) = self.transactions_by_recipient.get_mut(&recipient) {
                transaction_hashes.push(hash);
            } else {
                self.transactions_by_recipient.insert(recipient, vec![hash]);
            }
        }
        Ok(hash)
    }

    /// Parses and validates `start_block` / `end_block` query parameters and returns the indices of
    /// the first (inclusive) and last (exclusive) blocks to process. For internal use by the query
    /// methods.
    fn get_block_range(
        &self,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
    ) -> Result<RangeInclusive<usize>> {
        let start_index = match start_block {
            Some(BlockFilter::BlockHash(block_hash)) => self
                .get_block_by_hash(block_hash)
                .context(format!("invalid block hash {}", block_hash))?
                .number() as usize,
            Some(BlockFilter::BlockNumber(block_number)) => block_number,
            None => 0,
        };
        let last_block = self.block_hashes_by_number.len() - 1;
        let end_index = match end_block {
            Some(BlockFilter::BlockHash(block_hash)) => self
                .get_block_by_hash(block_hash)
                .context(format!("invalid block hash {}", block_hash))?
                .number() as usize,
            Some(BlockFilter::BlockNumber(block_number)) => block_number,
            None => last_block,
        };
        if end_index > last_block {
            return Err(anyhow!(
                "invalid block #{}: the latest is #{}",
                end_index,
                last_block
            ));
        }
        if start_index > end_index {
            return Err(anyhow!(
                "invalid block range [#{}, #{}]",
                start_index,
                end_index
            ));
        }
        Ok(start_index..=end_index)
    }

    fn query_transactions(
        &self,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        mut max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let mut results = TransactionQueryResults::default();
        let block_range = self.get_block_range(start_block, end_block)?;
        match sort_order {
            SortOrder::Ascending => {
                for block_number in block_range {
                    if max_count == 0 {
                        return Ok(results);
                    }
                    let mut block_results = vec![];
                    for proof in self.transactions.iter(block_number) {
                        let proof = proof?;
                        if max_count > 0 {
                            max_count -= 1;
                        } else {
                            break;
                        }
                        block_results.push(proof);
                    }
                    if !block_results.is_empty() {
                        let block_info = self.get_block_by_number(block_number).unwrap();
                        results.add_block(block_info, block_results);
                    }
                }
            }
            SortOrder::Descending => {
                for block_number in block_range.rev() {
                    if max_count == 0 {
                        return Ok(results);
                    }
                    let mut block_results = vec![];
                    for proof in self.transactions.iter(block_number).rev() {
                        let proof = proof?;
                        if max_count > 0 {
                            max_count -= 1;
                        } else {
                            break;
                        }
                        block_results.push(proof);
                    }
                    if !block_results.is_empty() {
                        let block_info = self.get_block_by_number(block_number).unwrap();
                        results.add_block(block_info, block_results);
                    }
                }
            }
        };
        Ok(results)
    }

    fn get_transaction_inclusion_proof(
        &self,
        transaction_hash: Scalar,
    ) -> Result<(usize, TransactionInclusionProof)> {
        let transaction_locator = self
            .transaction_locators_by_hash
            .get(&transaction_hash)
            .context(format!(
                "transaction {} not found",
                utils::format_scalar(transaction_hash)
            ))?;
        let proof = self.transactions.get_proof(
            transaction_locator.block_number,
            transaction_locator.transaction_number,
        )?;
        Ok((transaction_locator.block_number, proof))
    }

    fn query_transactions_from_list(
        &self,
        transaction_hashes: &[Scalar],
        block_range: RangeInclusive<usize>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let mut results = TransactionQueryResults::default();
        let start_index = transaction_hashes
            .binary_search_by(|transaction_hash| {
                let transaction_locator = self
                    .transaction_locators_by_hash
                    .get(transaction_hash)
                    .unwrap();
                match transaction_locator.block_number.cmp(block_range.start()) {
                    Ordering::Equal => Ordering::Greater,
                    ordering => ordering,
                }
            })
            .unwrap_err();
        let end_index = transaction_hashes
            .binary_search_by(|transaction_hash| {
                let transaction_locator = self
                    .transaction_locators_by_hash
                    .get(transaction_hash)
                    .unwrap();
                match transaction_locator.block_number.cmp(block_range.end()) {
                    Ordering::Equal => Ordering::Greater,
                    ordering => ordering,
                }
            })
            .unwrap_err();
        let transaction_hashes = match sort_order {
            SortOrder::Ascending => (start_index..end_index)
                .take(max_count)
                .map(|i| transaction_hashes[i])
                .collect::<Vec<Scalar>>(),
            SortOrder::Descending => (start_index..end_index)
                .rev()
                .take(max_count)
                .map(|i| transaction_hashes[i])
                .collect::<Vec<Scalar>>(),
        };
        let mut last_block_number = 0;
        let mut block_results = vec![];
        for hash in transaction_hashes {
            match self.get_transaction_inclusion_proof(hash) {
                Ok((block_number, proof)) => {
                    if block_number != last_block_number {
                        if !block_results.is_empty() {
                            let block_info = self.get_block_by_number(block_number).unwrap();
                            results.add_block(block_info, block_results);
                        }
                        last_block_number = block_number;
                        block_results = vec![proof];
                    } else {
                        block_results.push(proof);
                    }
                }
                Err(_) => {
                    // TODO: don't silently skip errors, log them.
                }
            };
        }
        if !block_results.is_empty() {
            let block_info = self.get_block_by_number(last_block_number).unwrap();
            results.add_block(block_info, block_results);
        }
        Ok(results)
    }

    fn query_transactions_from(
        &self,
        signer: Scalar,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let block_range = self.get_block_range(start_block, end_block)?;
        match self.transactions_by_signer.get(&signer) {
            Some(signer_transactions) => self.query_transactions_from_list(
                signer_transactions,
                block_range,
                sort_order,
                max_count,
            ),
            None => Ok(TransactionQueryResults::default()),
        }
    }

    fn query_transactions_to(
        &self,
        recipient: Scalar,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let block_range = self.get_block_range(start_block, end_block)?;
        match self.transactions_by_recipient.get(&recipient) {
            Some(recipient_transactions) => self.query_transactions_from_list(
                recipient_transactions.as_slice(),
                block_range,
                sort_order,
                max_count,
            ),
            None => Ok(TransactionQueryResults::default()),
        }
    }

    fn query_transactions_between_asc(
        &self,
        signer_transactions: &[Scalar],
        recipient_transactions: &[Scalar],
        block_range: RangeInclusive<usize>,
        mut max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let mut results = TransactionQueryResults::default();
        if max_count == 0 {
            return Ok(results);
        }
        let mut last_block_number = 0;
        let mut block_results = vec![];
        let cmp = |transaction_hash| {
            let transaction_locator = self
                .transaction_locators_by_hash
                .get(transaction_hash)
                .unwrap();
            match transaction_locator.block_number.cmp(block_range.start()) {
                Ordering::Equal => Ordering::Greater,
                ordering => ordering,
            }
        };
        let mut i = signer_transactions.binary_search_by(cmp).unwrap_err();
        let mut j = recipient_transactions.binary_search_by(cmp).unwrap_err();
        while max_count > 0 && i < signer_transactions.len() && j < recipient_transactions.len() {
            let lhs = &signer_transactions[i];
            let rhs = &recipient_transactions[j];
            let lhs_locator = self.transaction_locators_by_hash.get(lhs).unwrap();
            let rhs_locator = self.transaction_locators_by_hash.get(rhs).unwrap();
            if lhs_locator < rhs_locator {
                i += 1;
            } else if lhs_locator > rhs_locator {
                j += 1;
            } else {
                match self.get_transaction_inclusion_proof(*lhs) {
                    Ok((block_number, proof)) => {
                        if block_number != last_block_number {
                            if !block_results.is_empty() {
                                let block_info =
                                    self.get_block_by_number(last_block_number).unwrap();
                                results.add_block(block_info, block_results);
                            }
                            last_block_number = block_number;
                            block_results = vec![proof];
                        } else {
                            block_results.push(proof);
                        }
                    }
                    Err(_) => {
                        // TODO: don't silently skip errors, log them.
                    }
                };
                i += 1;
                j += 1;
                max_count -= 1;
            }
        }
        if !block_results.is_empty() {
            let block_info = self.get_block_by_number(last_block_number).unwrap();
            results.add_block(block_info, block_results);
        }
        Ok(results)
    }

    fn query_transactions_between_desc(
        &self,
        signer_transactions: &[Scalar],
        recipient_transactions: &[Scalar],
        block_range: RangeInclusive<usize>,
        mut max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let mut results = TransactionQueryResults::default();
        if max_count == 0 {
            return Ok(results);
        }
        let mut last_block_number = 0;
        let mut block_results = vec![];
        let cmp = |transaction_hash| {
            let transaction_locator = self
                .transaction_locators_by_hash
                .get(transaction_hash)
                .unwrap();
            match transaction_locator.block_number.cmp(block_range.end()) {
                Ordering::Equal => Ordering::Less,
                ordering => ordering,
            }
        };
        let mut i = signer_transactions.binary_search_by(cmp).unwrap_err();
        let mut j = recipient_transactions.binary_search_by(cmp).unwrap_err();
        while max_count > 0 && i > 0 && j > 0 {
            let lhs = &signer_transactions[i - 1];
            let rhs = &recipient_transactions[j - 1];
            let lhs_locator = self.transaction_locators_by_hash.get(lhs).unwrap();
            let rhs_locator = self.transaction_locators_by_hash.get(rhs).unwrap();
            if lhs_locator < rhs_locator {
                j -= 1;
            } else if lhs_locator > rhs_locator {
                i -= 1;
            } else {
                match self.get_transaction_inclusion_proof(*lhs) {
                    Ok((block_number, proof)) => {
                        if block_number != last_block_number {
                            if !block_results.is_empty() {
                                let block_info =
                                    self.get_block_by_number(last_block_number).unwrap();
                                results.add_block(block_info, block_results);
                            }
                            last_block_number = block_number;
                            block_results = vec![proof];
                        } else {
                            block_results.push(proof);
                        }
                    }
                    Err(_) => {
                        // TODO: don't silently skip errors, log them.
                    }
                };
                i -= 1;
                j -= 1;
                max_count -= 1;
            }
        }
        if !block_results.is_empty() {
            let block_info = self.get_block_by_number(last_block_number).unwrap();
            results.add_block(block_info, block_results);
        }
        Ok(results)
    }

    fn query_transactions_between(
        &self,
        signer: Scalar,
        recipient: Scalar,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        let block_range = self.get_block_range(start_block, end_block)?;
        if let (Some(signer_transactions), Some(recipient_transactions)) = (
            self.transactions_by_signer.get(&signer),
            self.transactions_by_recipient.get(&recipient),
        ) {
            match sort_order {
                SortOrder::Ascending => self.query_transactions_between_asc(
                    signer_transactions.as_slice(),
                    recipient_transactions.as_slice(),
                    block_range,
                    max_count,
                ),
                SortOrder::Descending => self.query_transactions_between_desc(
                    signer_transactions.as_slice(),
                    recipient_transactions.as_slice(),
                    block_range,
                    max_count,
                ),
            }
        } else {
            Ok(TransactionQueryResults::default())
        }
    }

    fn close_block(&mut self, timestamp: SystemTime) -> Result<BlockInfo> {
        let block_number = self.current_version();
        assert_eq!(block_number as usize, self.accounts.current_version());
        let previous_block_hash = *self.block_hashes_by_number.last().unwrap();
        let (_, network_topology) = self
            .network_topologies
            .range(0..=block_number)
            .next_back()
            .unwrap();
        let transactions_root_hash = self.transactions.commit();
        let accounts_root_hash = self.accounts.commit();
        let program_storage_root_hash = self.program_storage.root_hash(block_number);
        let block_header = BlockHeader::new(
            self.chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology.root_hash(),
            transactions_root_hash,
            accounts_root_hash,
            program_storage_root_hash,
        );
        let block_hash = block_header.hash();
        self.blocks.insert_hashed(block_header, block_hash)?;
        self.block_hashes_by_number.push(block_hash);
        Ok(BlockInfo::from_parts(block_hash, block_header))
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
        let version = (self.current_version() - 1) as usize;
        let mut empty_accounts = vec![];
        for (account_address, listeners) in &mut self.account_watchers {
            let message = AccountState {
                block_info: *block_info,
                proof: self.accounts.get_proof(*account_address, version),
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
        let current_version = (self.current_version() - 1) as usize;
        let previous_version = current_version - 1;
        let mut empty_accounts = vec![];
        for (account_address, listeners) in &mut self.account_listeners {
            let previous_hash = self
                .accounts
                .get(*account_address, previous_version)
                .as_scalar();
            let account = self.accounts.get(*account_address, current_version);
            if account.as_scalar() != previous_hash {
                let message = AccountState {
                    block_info: *block_info,
                    proof: self.accounts.get_proof(*account_address, current_version),
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
    chain_id: u64,
    repr: Mutex<Repr>,
}

impl Db {
    pub fn new(
        clock: Arc<dyn Clock>,
        chain_id: u64,
        identity: libernet::NodeIdentity,
        initial_accounts: &[(Scalar, AccountInfo)],
    ) -> Result<Self> {
        let repr = Repr::new(&clock, chain_id, identity, initial_accounts)?;
        Ok(Self {
            clock,
            chain_id,
            repr: Mutex::new(repr),
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
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

    pub async fn get_latest_account_info(&self, account_address: Scalar) -> AccountState {
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

    pub async fn get_transaction(
        &self,
        hash: Scalar,
    ) -> Result<(BlockInfo, TransactionInclusionProof)> {
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

    pub async fn add_transaction(&self, transaction: libernet::Transaction) -> Result<Scalar> {
        self.repr.lock().await.add_transaction(transaction, false)
    }

    /// This method is the same as `add_transaction` except that it fails if the payload is a block
    /// reward transaction. The `BroadcastTransaction` RPC must be served using this method because
    /// block reward transactions may not be broadcast.
    pub async fn add_transaction_blocking_rewards(
        &self,
        transaction: libernet::Transaction,
    ) -> Result<Scalar> {
        self.repr.lock().await.add_transaction(transaction, true)
    }

    pub async fn query_transactions(
        &self,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        self.repr
            .lock()
            .await
            .query_transactions(start_block, end_block, sort_order, max_count)
    }

    pub async fn query_transactions_from(
        &self,
        signer: Scalar,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        self.repr.lock().await.query_transactions_from(
            signer,
            start_block,
            end_block,
            sort_order,
            max_count,
        )
    }

    pub async fn query_transactions_to(
        &self,
        recipient: Scalar,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        self.repr.lock().await.query_transactions_to(
            recipient,
            start_block,
            end_block,
            sort_order,
            max_count,
        )
    }

    pub async fn query_transactions_between(
        &self,
        signer: Scalar,
        recipient: Scalar,
        start_block: Option<BlockFilter>,
        end_block: Option<BlockFilter>,
        sort_order: SortOrder,
        max_count: usize,
    ) -> Result<TransactionQueryResults> {
        self.repr.lock().await.query_transactions_between(
            signer,
            recipient,
            start_block,
            end_block,
            sort_order,
            max_count,
        )
    }

    pub async fn close_block(&self) -> Result<BlockInfo> {
        let mut repr = self.repr.lock().await;
        let block_info = repr.close_block(self.clock.now())?;
        repr.notify_block(&block_info);
        repr.notify_accounts(&block_info);
        repr.notify_account_changes(&block_info);
        Ok(block_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::testing;
    use crate::clock::testing::MockClock;
    use crate::constants;
    use crate::data::{self, AccountFields};
    use crate::testing::parse_scalar;
    use std::time::Duration;

    const COIN_UNIT: u64 = 1_000_000_000_000_000_000u64;

    const TEST_CHAIN_ID: u64 = 42;

    fn coins(number: u64) -> Scalar {
        Scalar::from(number) * Scalar::from(COIN_UNIT)
    }

    fn reward_for(stake: Scalar) -> Scalar {
        data::reward_for(stake).unwrap()
    }

    fn account_info1() -> AccountInfo {
        AccountFields {
            last_nonce: 12,
            balance: coins(90),
            staking_balance: coins(78),
        }
        .into()
    }

    fn account_info2() -> AccountInfo {
        AccountFields {
            last_nonce: 34,
            balance: coins(56),
            staking_balance: 0.into(),
        }
        .into()
    }

    fn account_info3() -> AccountInfo {
        AccountFields {
            last_nonce: 56,
            balance: coins(34),
            staking_balance: 0.into(),
        }
        .into()
    }

    fn account_info4() -> AccountInfo {
        AccountFields {
            last_nonce: 78,
            balance: coins(12),
            staking_balance: 0.into(),
        }
        .into()
    }

    struct TestFixture {
        clock: Arc<MockClock>,
        db: Db,
    }

    impl TestFixture {
        async fn new(initial_accounts: &[(Scalar, AccountInfo)]) -> Result<Self> {
            let clock = Arc::new(MockClock::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            ));
            let account = testing::account1();
            let identity = libernet::node_identity::Payload {
                protocol_version: Some(libernet::ProtocolVersion {
                    major: Some(constants::PROTOCOL_VERSION_MAJOR),
                    minor: Some(constants::PROTOCOL_VERSION_MINOR),
                    build: Some(constants::PROTOCOL_VERSION_BUILD),
                }),
                chain_id: Some(TEST_CHAIN_ID),
                account_address: Some(proto::encode_scalar(account.address())),
                location: Some(libernet::GeographicalLocation {
                    latitude: Some(71i32),
                    longitude: Some(104u32),
                }),
                network_address: Some("localhost".into()),
                grpc_port: Some(4443u32),
                http_port: Some(8080u32),
                timestamp: Some(clock.now().into()),
            };
            let (identity_payload, identity_signature) = account.sign_message(&identity)?;
            let identity = libernet::NodeIdentity {
                payload: Some(identity_payload),
                signature: Some(identity_signature),
            };
            let db = Db::new(clock.clone(), TEST_CHAIN_ID, identity, initial_accounts)?;
            Ok(Self { clock, db })
        }

        async fn default() -> Result<Self> {
            Self::new(&[
                (testing::account1().address(), account_info1()),
                (testing::account2().address(), account_info2()),
                (testing::account3().address(), account_info3()),
                (testing::account4().address(), account_info4()),
            ])
            .await
        }

        async fn advance_to_next_block(&self) -> BlockInfo {
            self.clock
                .advance(Duration::from_millis(constants::BLOCK_TIME_MS))
                .await;
            self.db.close_block().await.unwrap()
        }

        async fn get_account_info(
            &self,
            account_address: Scalar,
            block_hash: Scalar,
        ) -> Result<AccountInfo> {
            let account_state = self
                .db
                .get_account_info(account_address, block_hash)
                .await?;
            if account_state.block_info.hash() != block_hash {
                return Err(anyhow!(
                    "incorrect block hash (got {}, want {})",
                    utils::format_scalar(account_state.block_info.hash()),
                    utils::format_scalar(block_hash)
                ));
            }
            if account_state.proof.root_hash() != account_state.block_info.accounts_root_hash() {
                return Err(anyhow!(
                    "incorrect account root hash (got {}, want {})",
                    utils::format_scalar(account_state.proof.root_hash()),
                    utils::format_scalar(account_state.block_info.accounts_root_hash())
                ));
            }
            account_state.proof.verify()?;
            Ok(account_state.take())
        }

        async fn get_latest_account_info(&self, account_address: Scalar) -> Result<AccountInfo> {
            let account_state = self.db.get_latest_account_info(account_address).await;
            if account_state.proof.root_hash() != account_state.block_info.accounts_root_hash() {
                return Err(anyhow!(
                    "incorrect account root hash (got {}, want {})",
                    account_state.proof.root_hash(),
                    account_state.block_info.accounts_root_hash()
                ));
            }
            account_state.proof.verify()?;
            Ok(account_state.take())
        }

        fn verify_transaction_proof(
            block_info: &BlockInfo,
            proof: TransactionInclusionProof,
        ) -> Result<Transaction> {
            if proof.root_hash() != block_info.transactions_root_hash() {
                return Err(anyhow!(
                    "incorrect transaction root hash (got {}, want {})",
                    utils::format_scalar(proof.root_hash()),
                    utils::format_scalar(block_info.transactions_root_hash())
                ));
            }
            proof.verify()?;
            Ok(proof.take_value())
        }

        async fn get_transaction(&self, hash: Scalar) -> Result<(BlockInfo, Transaction)> {
            let (block_info, proof) = self.db.get_transaction(hash).await.context(format!(
                "transaction {} not found",
                utils::format_scalar(hash)
            ))?;
            Ok((
                block_info,
                Self::verify_transaction_proof(&block_info, proof)?,
            ))
        }

        async fn query_transactions(
            &self,
            start_block: Option<BlockFilter>,
            end_block: Option<BlockFilter>,
            sort_order: SortOrder,
            max_count: Option<usize>,
        ) -> Result<Vec<(BlockInfo, Transaction)>> {
            Ok(self
                .db
                .query_transactions(
                    start_block,
                    end_block,
                    sort_order,
                    match max_count {
                        Some(max_count) => max_count,
                        None => usize::MAX,
                    },
                )
                .await?
                .0
                .into_iter()
                .map(|(block_info, block_proofs)| {
                    Ok(block_proofs
                        .into_iter()
                        .map(|proof| {
                            Ok((
                                block_info,
                                Self::verify_transaction_proof(&block_info, proof)?,
                            ))
                        })
                        .collect::<Result<Vec<(BlockInfo, Transaction)>>>()?)
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_empty() {
        let address1 = testing::account1().address();
        let address2 = testing::account2().address();
        let address3 = testing::account3().address();
        let fixture = TestFixture::new(&[]).await.unwrap();
        let db = &fixture.db;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 1);
        let block = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block.number(), 0);
        let block_hash =
            parse_scalar("0x5a902562063f0bb372c6a4bd03a15b203bb81ef72d0ff27e639391ec47390249");
        assert_eq!(block.hash(), block_hash);
        let transactions_root_hash =
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634");
        assert_eq!(block.transactions_root_hash(), transactions_root_hash);
        assert_eq!(db.get_block_by_hash(block_hash).await.unwrap(), block);
        assert!(db.get_block_by_number(1).await.is_none());
        assert_eq!(db.get_latest_block().await, block);
        let empty_account = AccountInfo::default();
        assert_eq!(
            fixture
                .get_account_info(address1, block_hash)
                .await
                .unwrap(),
            empty_account
        );
        assert_eq!(
            fixture.get_latest_account_info(address1).await.unwrap(),
            empty_account
        );
        assert_eq!(
            fixture
                .get_account_info(address2, block_hash)
                .await
                .unwrap(),
            empty_account
        );
        assert_eq!(
            fixture.get_latest_account_info(address2).await.unwrap(),
            empty_account
        );
        assert_eq!(
            fixture
                .get_account_info(address3, block_hash)
                .await
                .unwrap(),
            empty_account
        );
        assert_eq!(
            fixture.get_latest_account_info(address3).await.unwrap(),
            empty_account
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_initial_state() {
        let address1 = testing::account1().address();
        let address2 = testing::account2().address();
        let address3 = testing::account3().address();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 1);
        let block = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block.number(), 0);
        let block_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block.hash(), block_hash);
        let transactions_root_hash =
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634");
        assert_eq!(block.transactions_root_hash(), transactions_root_hash);
        assert_eq!(db.get_block_by_hash(block_hash).await.unwrap(), block);
        assert!(db.get_block_by_number(1).await.is_none());
        assert_eq!(db.get_latest_block().await, block);
        assert_eq!(
            fixture
                .get_account_info(address1, block_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture.get_latest_account_info(address1).await.unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(address2, block_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture.get_latest_account_info(address2).await.unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(address3, block_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture.get_latest_account_info(address3).await.unwrap(),
            account_info3()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_close_empty_block() {
        let address1 = testing::account1().address();
        let address2 = testing::account2().address();
        let address3 = testing::account3().address();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        let transactions_root_hash =
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634");
        assert_eq!(block1.transactions_root_hash(), transactions_root_hash);
        let block2_hash =
            parse_scalar("0x480b99256bae40c26875ea0f478057d838232f3e0ccba7af2931ac04b5e033ad");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(block2.transactions_root_hash(), transactions_root_hash);
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        assert_eq!(
            fixture
                .get_account_info(address1, block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(address1, block2_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture.get_latest_account_info(address1).await.unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(address2, block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(address2, block2_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture.get_latest_account_info(address2).await.unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(address3, block1_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture
                .get_account_info(address3, block2_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture.get_latest_account_info(address3).await.unwrap(),
            account_info3()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_reward_transaction() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction.diff()).await.is_ok());
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x32796b7a07b4ca7aba35de5abb9184e36002c3fdac07927e682ed84994e050cd");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x3b1c6defdd39ed7608a0826d9fedba7125d145e00a56cd6c3b65ee6b1bfaa043")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountFields {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block1_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block2_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account3.address())
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![transaction.hash()]
        );
        assert_eq!(
            fixture.get_transaction(transaction.hash()).await.unwrap(),
            (block2, transaction)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_two_transactions() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                35,
                account3.address(),
                coins(12),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_ok());
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x299d394eee457abd9ebfbcbaf8a043e2463eedc5bfc2fadb1740896d01a3f59f");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x3c1329bbe29e166369609ac31c556d739a1749a037c36cde594de3c50cbc8d3a")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountFields {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            updated_account_info1
        );
        let updated_account_info2 = AccountFields {
            last_nonce: 35,
            balance: coins(44),
            staking_balance: 0.into(),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info2
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            updated_account_info2
        );
        let updated_account_info3 = AccountFields {
            last_nonce: 56,
            balance: coins(46),
            staking_balance: 0.into(),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block1_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info3
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account3.address())
                .await
                .unwrap(),
            updated_account_info3
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![transaction1.hash(), transaction2.hash()]
        );
        assert_eq!(
            fixture.get_transaction(transaction1.hash()).await.unwrap(),
            (block2, transaction1)
        );
        assert_eq!(
            fixture.get_transaction(transaction2.hash()).await.unwrap(),
            (block2, transaction2)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_bad_nonce1() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account2.address(),
                coins(12),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_err());
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x32796b7a07b4ca7aba35de5abb9184e36002c3fdac07927e682ed84994e050cd");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x3b1c6defdd39ed7608a0826d9fedba7125d145e00a56cd6c3b65ee6b1bfaa043")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountFields {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![transaction1.hash()]
        );
        assert_eq!(
            fixture.get_transaction(transaction1.hash()).await.unwrap(),
            (block2, transaction1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_bad_nonce2() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                12,
                account2.address(),
                coins(12),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_err());
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x32796b7a07b4ca7aba35de5abb9184e36002c3fdac07927e682ed84994e050cd");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x3b1c6defdd39ed7608a0826d9fedba7125d145e00a56cd6c3b65ee6b1bfaa043")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountFields {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![transaction1.hash()]
        );
        assert_eq!(
            fixture.get_transaction(transaction1.hash()).await.unwrap(),
            (block2, transaction1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_bad_chain_id() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                1337,
                14,
                account2.address(),
                coins(12),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_err());
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x32796b7a07b4ca7aba35de5abb9184e36002c3fdac07927e682ed84994e050cd");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x3b1c6defdd39ed7608a0826d9fedba7125d145e00a56cd6c3b65ee6b1bfaa043")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountFields {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![transaction1.hash()]
        );
        assert_eq!(
            fixture.get_transaction(transaction1.hash()).await.unwrap(),
            (block2, transaction1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_three_transactions() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account3,
                TEST_CHAIN_ID,
                57,
                account2.address(),
                coins(12),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_ok());
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                35,
                account3.address(),
                coins(34),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction3.diff()).await.is_ok());
        let block2 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 2);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x20ab2f3d7961dddfd2bbd697f5c43027834a21a19b73b35c2542f55e5d700786");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x32eaa7c316d37151dc368499bd8bfb4c12587a8e91ffee68f1206c2f0bccee06")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountFields {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info1
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            updated_account_info1
        );
        let updated_account_info2 = AccountFields {
            last_nonce: 35,
            balance: coins(34),
            staking_balance: 0.into(),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info2
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            updated_account_info2
        );
        let updated_account_info3 = AccountFields {
            last_nonce: 57,
            balance: coins(56),
            staking_balance: 0.into(),
        }
        .into();
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block1_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block2_hash)
                .await
                .unwrap(),
            updated_account_info3
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account3.address())
                .await
                .unwrap(),
            updated_account_info3
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![
                transaction1.hash(),
                transaction2.hash(),
                transaction3.hash()
            ]
        );
        assert_eq!(
            fixture.get_transaction(transaction1.hash()).await.unwrap(),
            (block2, transaction1)
        );
        assert_eq!(
            fixture.get_transaction(transaction2.hash()).await.unwrap(),
            (block2, transaction2)
        );
        assert_eq!(
            fixture.get_transaction(transaction3.hash()).await.unwrap(),
            (block2, transaction3)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_two_blocks() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account3,
                TEST_CHAIN_ID,
                57,
                account2.address(),
                coins(12),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_ok());
        let block2 = fixture.advance_to_next_block().await;
        let transaction3 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                14,
                account1.address(),
                reward_for(coins(78)),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction3.diff()).await.is_ok());
        let transaction4 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                35,
                account3.address(),
                coins(34),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction4.diff()).await.is_ok());
        let block3 = fixture.advance_to_next_block().await;
        assert_eq!(db.chain_id(), TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 3);
        let block1 = db.get_block_by_number(0).await.unwrap();
        assert_eq!(block1.number(), 0);
        assert_eq!(block2.number(), 1);
        assert_eq!(block3.number(), 2);
        let block1_hash =
            parse_scalar("0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x6d95ae588d6c75947417a6509c159b787eedc227eeb3d478a18ed7cabfd0f634")
        );
        let block2_hash =
            parse_scalar("0x0f1053d4e64a1865dbb8d49fcd96e28685faaf72f9e7a30d770d8c60144b39ee");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x57995d248885eb11b95574af8771390e08f9490dcdec66b15f1010588df7eaa7")
        );
        let block3_hash =
            parse_scalar("0x008d1dde20f41f94538268a361bb745a59c8ed2504b9896fe44dea0485aa42c4");
        assert_eq!(block3.hash(), block3_hash);
        assert_eq!(
            block3.transactions_root_hash(),
            parse_scalar("0x71f85b3398a2979132abddda7fde3f718ad63a95cd1d7797fae8fc8217e346ee")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_hash(block3_hash).await.unwrap(), block3);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(2).await.unwrap(), block3);
        assert!(db.get_block_by_number(3).await.is_none());
        assert_eq!(db.get_latest_block().await, block3);
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block1_hash)
                .await
                .unwrap(),
            account_info1()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block2_hash)
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 13,
                balance: coins(90) + reward_for(coins(78)),
                staking_balance: coins(78),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block3_hash)
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 14,
                balance: coins(90) + reward_for(coins(78)).double(),
                staking_balance: coins(78),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 14,
                balance: coins(90) + reward_for(coins(78)).double(),
                staking_balance: coins(78),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block1_hash)
                .await
                .unwrap(),
            account_info2()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block2_hash)
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 34,
                balance: coins(68),
                staking_balance: 0.into(),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block3_hash)
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 35,
                balance: coins(34),
                staking_balance: 0.into(),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 35,
                balance: coins(34),
                staking_balance: 0.into(),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block1_hash)
                .await
                .unwrap(),
            account_info3()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block2_hash)
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 57,
                balance: coins(22),
                staking_balance: 0.into(),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block3_hash)
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 57,
                balance: coins(56),
                staking_balance: 0.into(),
            }
            .into()
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account3.address())
                .await
                .unwrap(),
            AccountFields {
                last_nonce: 57,
                balance: coins(56),
                staking_balance: 0.into(),
            }
            .into()
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(1).await.unwrap(),
            vec![transaction1.hash(), transaction2.hash()]
        );
        assert_eq!(
            db.get_all_block_transaction_hashes(2).await.unwrap(),
            vec![transaction3.hash(), transaction4.hash()]
        );
        assert_eq!(
            fixture.get_transaction(transaction1.hash()).await.unwrap(),
            (block2, transaction1)
        );
        assert_eq!(
            fixture.get_transaction(transaction2.hash()).await.unwrap(),
            (block2, transaction2)
        );
        assert_eq!(
            fixture.get_transaction(transaction3.hash()).await.unwrap(),
            (block3, transaction3)
        );
        assert_eq!(
            fixture.get_transaction(transaction4.hash()).await.unwrap(),
            (block3, transaction4)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_descending() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_capped() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, Some(10))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_lower_bound_number() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    None,
                    SortOrder::Ascending,
                    None,
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_lower_bound_hash() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869",
                    ))),
                    None,
                    SortOrder::Ascending,
                    None,
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_upper_bound_number() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockNumber(0)),
                    SortOrder::Ascending,
                    None,
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_upper_bound_hash() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869",
                    ))),
                    SortOrder::Ascending,
                    None,
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_bounded_with_numbers() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    Some(BlockFilter::BlockNumber(0)),
                    SortOrder::Ascending,
                    None,
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_genesis_block_bounded_with_hashes() {
        let fixture = TestFixture::default().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869",
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869",
                    ))),
                    SortOrder::Ascending,
                    None,
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    async fn make_test_fixture_with_one_block()
    -> Result<(TestFixture, Vec<(BlockInfo, Transaction)>)> {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account1.address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                14,
                account2.address(),
                100.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_ok());
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                35,
                account1.address(),
                50.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction3.diff()).await.is_ok());
        let block = fixture.advance_to_next_block().await;
        Ok((
            fixture,
            vec![
                (block, transaction1),
                (block, transaction2),
                (block, transaction3),
            ],
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, None)
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_descending() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, None)
                .await
                .unwrap(),
            transactions.into_iter().rev().collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_capped1() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, Some(1))
                .await
                .unwrap(),
            transactions.into_iter().take(1).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_capped1_descending() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, Some(1))
                .await
                .unwrap(),
            transactions.into_iter().rev().take(1).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_capped2() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, Some(2))
                .await
                .unwrap(),
            transactions.into_iter().take(2).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_capped2_descending() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, Some(2))
                .await
                .unwrap(),
            transactions.into_iter().rev().take(2).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_two_blocks_lower_bound_number() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_two_blocks_lower_bound_hash() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_lower_bound_number() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(1)),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_lower_bound_hash() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x3d8b2999b142583263541dfa42fcfe57d7b2e5c1e069d31da870024725c65008"
                    ))),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_before_first_block_upper_bound_number() {
        let (fixture, _) = make_test_fixture_with_one_block().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockNumber(0)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_before_first_block_upper_bound_hash() {
        let (fixture, _) = make_test_fixture_with_one_block().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_upper_bound_number() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockNumber(1)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_upper_bound_hash() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x3d8b2999b142583263541dfa42fcfe57d7b2e5c1e069d31da870024725c65008"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_bounded_with_numbers() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(1)),
                    Some(BlockFilter::BlockNumber(1)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_block_bounded_with_hashes() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x3d8b2999b142583263541dfa42fcfe57d7b2e5c1e069d31da870024725c65008"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x3d8b2999b142583263541dfa42fcfe57d7b2e5c1e069d31da870024725c65008"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_two_blocks_bounded_with_numbers() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    Some(BlockFilter::BlockNumber(1)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_two_blocks_bounded_with_hashes() {
        let (fixture, transactions) = make_test_fixture_with_one_block().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x3d8b2999b142583263541dfa42fcfe57d7b2e5c1e069d31da870024725c65008"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    async fn make_test_fixture_with_two_blocks()
    -> Result<(TestFixture, Vec<(BlockInfo, Transaction)>)> {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let account3 = testing::account3();
        let fixture = TestFixture::default().await.unwrap();
        let db = &fixture.db;
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account2,
                TEST_CHAIN_ID,
                35,
                account2.address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction1.diff()).await.is_ok());
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                36,
                account1.address(),
                12.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction2.diff()).await.is_ok());
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                37,
                account3.address(),
                34.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction3.diff()).await.is_ok());
        let transaction4 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account2.address(),
                56.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction4.diff()).await.is_ok());
        let block1 = fixture.advance_to_next_block().await;
        let transaction5 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                14,
                account1.address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction5.diff()).await.is_ok());
        let transaction6 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                15,
                account3.address(),
                78.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction6.diff()).await.is_ok());
        let transaction7 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account3,
                TEST_CHAIN_ID,
                57,
                account2.address(),
                90.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction7.diff()).await.is_ok());
        let transaction8 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account3,
                TEST_CHAIN_ID,
                58,
                account1.address(),
                12.into(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(db.add_transaction(transaction8.diff()).await.is_ok());
        let block2 = fixture.advance_to_next_block().await;
        Ok((
            fixture,
            vec![
                (block1, transaction1),
                (block1, transaction2),
                (block1, transaction3),
                (block1, transaction4),
                (block2, transaction5),
                (block2, transaction6),
                (block2, transaction7),
                (block2, transaction8),
            ],
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, None)
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_descending() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, None)
                .await
                .unwrap(),
            transactions.into_iter().rev().collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_capped1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, Some(7))
                .await
                .unwrap(),
            transactions.into_iter().take(7).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_capped1_descending() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, Some(7))
                .await
                .unwrap(),
            transactions.into_iter().rev().take(7).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_capped2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, Some(8))
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_capped2_descending() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, Some(8))
                .await
                .unwrap(),
            transactions.into_iter().rev().collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_capped3() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Ascending, Some(9))
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_capped3_descending() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(None, None, SortOrder::Descending, Some(9))
                .await
                .unwrap(),
            transactions.into_iter().rev().collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_lower_bound_number_0() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_lower_bound_hash_0() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_lower_bound_number_1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(1)),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_lower_bound_hash_1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x733cb8a024f38a3099ee032d75c005df79f99b335bab2b84883d2fdcc6e4da31"
                    ))),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_lower_bound_number_2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(2)),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().skip(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_lower_bound_hash_2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x0ee1b5501b46e177d2466855934aba224d4f0fba3652c241e49cc0fa8b14dfbc"
                    ))),
                    None,
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().skip(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_upper_bound_number_0() {
        let (fixture, _) = make_test_fixture_with_two_blocks().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockNumber(0)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_upper_bound_hash_0() {
        let (fixture, _) = make_test_fixture_with_two_blocks().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_upper_bound_number_1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockNumber(1)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().take(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_upper_bound_hash_1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x733cb8a024f38a3099ee032d75c005df79f99b335bab2b84883d2fdcc6e4da31"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().take(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_upper_bound_number_2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockNumber(2)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_upper_bound_hash_2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    None,
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x0ee1b5501b46e177d2466855934aba224d4f0fba3652c241e49cc0fa8b14dfbc"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_numbers_0() {
        let (fixture, _) = make_test_fixture_with_two_blocks().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    Some(BlockFilter::BlockNumber(0)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_hashes_0() {
        let (fixture, _) = make_test_fixture_with_two_blocks().await.unwrap();
        assert!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_numbers_1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    Some(BlockFilter::BlockNumber(1)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().take(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_hashes_1() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x733cb8a024f38a3099ee032d75c005df79f99b335bab2b84883d2fdcc6e4da31"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().take(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_numbers_2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(0)),
                    Some(BlockFilter::BlockNumber(2)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_hashes_2() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x638f6cb70d73032c0d6510faff8db4a7047b9e4e98a943898abb6cd6f900f869"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x0ee1b5501b46e177d2466855934aba224d4f0fba3652c241e49cc0fa8b14dfbc"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_numbers_3() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(1)),
                    Some(BlockFilter::BlockNumber(1)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().take(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_hashes_3() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x733cb8a024f38a3099ee032d75c005df79f99b335bab2b84883d2fdcc6e4da31"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x733cb8a024f38a3099ee032d75c005df79f99b335bab2b84883d2fdcc6e4da31"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().take(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_numbers_4() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(1)),
                    Some(BlockFilter::BlockNumber(2)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_hashes_4() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x733cb8a024f38a3099ee032d75c005df79f99b335bab2b84883d2fdcc6e4da31"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x0ee1b5501b46e177d2466855934aba224d4f0fba3652c241e49cc0fa8b14dfbc"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_numbers_5() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockNumber(2)),
                    Some(BlockFilter::BlockNumber(2)),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().skip(4).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_query_transactions_from_first_three_blocks_bounded_with_hashes_5() {
        let (fixture, transactions) = make_test_fixture_with_two_blocks().await.unwrap();
        assert_eq!(
            fixture
                .query_transactions(
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x0ee1b5501b46e177d2466855934aba224d4f0fba3652c241e49cc0fa8b14dfbc"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x0ee1b5501b46e177d2466855934aba224d4f0fba3652c241e49cc0fa8b14dfbc"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions.into_iter().skip(4).collect::<Vec<_>>()
        );
    }

    // TODO
}
