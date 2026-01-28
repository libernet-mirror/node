use crate::clock::Clock;
use crate::data::{
    AccountInfo, AccountProof, AccountTree, BlockInfo, ProgramStorageTree, Transaction,
    TransactionInclusionProof, TransactionTree,
};
use crate::libernet;
use crate::proto;
use crate::topology;
use crate::tree;
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::{
    merkle::{AsScalar, FromScalar},
    utils,
};
use ff::Field;
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
>(Vec<(BlockInfo, Vec<tree::MerkleProof<K, V, W, H>>)>);

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + proto::EncodeToAny + 'static,
    const W: usize,
    const H: usize,
> QueryResults<K, V, W, H>
{
    fn add_block(
        &mut self,
        block_info: BlockInfo,
        block_results: Vec<tree::MerkleProof<K, V, W, H>>,
    ) {
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
) -> BlockInfo {
    let block_number = 0;
    let transactions_root_hash = TransactionTree::default().root_hash();
    let program_storage_root_hash = ProgramStorageTree::default().root_hash(block_number);
    BlockInfo::new(
        chain_id,
        block_number,
        Scalar::ZERO,
        timestamp,
        network_topology_root_hash,
        transactions_root_hash,
        accounts_root_hash,
        program_storage_root_hash,
    )
}

/// Stores and indexes the transactions of a block.
#[derive(Debug, Default, Clone)]
struct BlockTransactions {
    /// Indexes the transactions by their hash.
    ///
    /// The keys of this map are transaction hashes. The first component of the value pairs is the
    /// transaction number within the block (0 for the first, 1 for the second, etc.), while the
    /// second component is the transaction object.
    by_hash: BTreeMap<Scalar, (usize, Transaction)>,

    /// The transaction SMT. The `transactions_root_hash` of the block will be set to the root hash
    /// of this tree when the block is closed.
    tree: TransactionTree,
}

impl BlockTransactions {
    /// Returns the root hash of the transaction SMT.
    fn root_hash(&self) -> Scalar {
        self.tree.root_hash()
    }

    /// Returns the number of transactions.
    fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Adds a transaction and returns the transaction number.
    fn add(&mut self, transaction: Transaction) -> usize {
        let transaction_number = self.by_hash.len();
        let key = Scalar::from(transaction_number as u64);
        let hash = transaction.hash();
        self.by_hash.insert(hash, (transaction_number, transaction));
        self.tree = self.tree.put(key, hash);
        transaction_number
    }

    /// Returns all transaction hashes in chronological order, i.e. first the hash of the first
    /// transaction, then the hash of the second one, etc.
    fn get_all_hashes(&self) -> Vec<Scalar> {
        let mut results = self
            .by_hash
            .iter()
            .map(|(hash, (transaction_number, _))| (*transaction_number, *hash))
            .collect::<Vec<_>>();
        results.sort_unstable();
        results.into_iter().map(|(_, hash)| hash).collect()
    }

    /// Returns proof of inclusion of a transaction in the block, or None if `transaction_index` is
    /// out of bounds.
    ///
    /// The transaction index is zero-based, so None is returned when `transaction_index` is greater
    /// than or equal to the number of transactions.
    fn get_inclusion_proof(&self, transaction_index: usize) -> Option<TransactionInclusionProof> {
        let proof = self.tree.get_proof(Scalar::from(transaction_index as u64));
        let (_, transaction) = self.by_hash.get(proof.value())?.clone();
        Some(proof.map(transaction).unwrap())
    }

    /// Constructs an iterator that iterates over the transactions in chronological order, returning
    /// an inclusion proof of each.
    ///
    /// NOTE: this iteration is relatively expensive because a brand new inclusion proof is
    /// constructed for every element, including a clone of the transaction object.
    fn iter(&self) -> impl DoubleEndedIterator<Item = TransactionInclusionProof> {
        BlockTransactionIterator::new(self)
    }
}

#[derive(Copy, Clone)]
struct BlockTransactionIterator<'a> {
    parent: &'a BlockTransactions,
    index: usize,
}

impl<'a> BlockTransactionIterator<'a> {
    fn new(parent: &'a BlockTransactions) -> Self {
        Self { parent, index: 0 }
    }
}

impl<'a> Iterator for BlockTransactionIterator<'a> {
    type Item = TransactionInclusionProof;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.parent.len() {
            let proof = self.parent.get_inclusion_proof(self.index).unwrap();
            self.index += 1;
            Some(proof)
        } else {
            None
        }
    }
}

impl<'a> DoubleEndedIterator for BlockTransactionIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index < self.parent.len() {
            let proof = self
                .parent
                .get_inclusion_proof(self.parent.len() - 1 - self.index)
                .unwrap();
            self.index += 1;
            Some(proof)
        } else {
            None
        }
    }
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

    blocks: Vec<BlockInfo>,
    block_numbers_by_hash: BTreeMap<Scalar, usize>,

    network_topologies: BTreeMap<u64, topology::Network>,

    transactions_per_block: Vec<BlockTransactions>,
    transaction_locators_by_hash: BTreeMap<Scalar, TransactionLocator>,
    transactions_by_signer: BTreeMap<Scalar, Vec<Scalar>>,
    transactions_by_recipient: BTreeMap<Scalar, Vec<Scalar>>,

    accounts: AccountTree,
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
        let accounts = AccountTree::from(initial_accounts);
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
            transactions_per_block: vec![
                BlockTransactions::default(), // transactions of the genesis block (always empty)
                BlockTransactions::default(), // transactions of the first (pending) block
            ],
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

    fn check_block_number(&self, block_number: usize) -> Option<usize> {
        // NOTE: we're checking `block_number` against the length of `self.blocks` rather than
        // `self.transactions_per_block` because `block_number` must refer to a closed block, not to
        // the one that's being built.
        //
        // TODO: maybe store pending transactions in a separate data structure that works as the
        // mempool and merge the `self.blocks` and `self.transactions_per_block` vectors into one.
        if block_number < self.blocks.len() {
            Some(block_number)
        } else {
            None
        }
    }

    fn get_transaction(&self, hash: Scalar) -> Option<(BlockInfo, TransactionInclusionProof)> {
        let locator = *(self.transaction_locators_by_hash.get(&hash)?);
        let block_number = self.check_block_number(locator.block_number)?;
        let block_info = self.blocks[block_number].clone();
        let transactions = &self.transactions_per_block[block_number];
        let proof = transactions
            .get_inclusion_proof(locator.transaction_number)
            .unwrap();
        Some((block_info, proof))
    }

    fn get_all_block_transaction_hashes(&self, block_number: usize) -> Result<Vec<Scalar>> {
        Ok(self.transactions_per_block[self
            .check_block_number(block_number)
            .context(format!("block #{} not found", block_number))?]
        .get_all_hashes())
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
        let block_transactions = self.transactions_per_block.last_mut().unwrap();
        let transaction_number = block_transactions.add(transaction);
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
            Some(BlockFilter::BlockHash(block_hash)) => *self
                .block_numbers_by_hash
                .get(&block_hash)
                .context(format!("invalid block hash {}", block_hash))?,
            Some(BlockFilter::BlockNumber(block_number)) => block_number,
            None => 0,
        };
        let last_block = self.blocks.len() - 1;
        let end_index = match end_block {
            Some(BlockFilter::BlockHash(block_hash)) => *self
                .block_numbers_by_hash
                .get(&block_hash)
                .context(format!("invalid block hash {}", block_hash))?,
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
                    let transactions = &self.transactions_per_block[block_number];
                    for proof in transactions.iter() {
                        if max_count > 0 {
                            max_count -= 1;
                        } else {
                            break;
                        }
                        block_results.push(proof);
                    }
                    if !block_results.is_empty() {
                        results.add_block(self.blocks[block_number], block_results);
                    }
                }
            }
            SortOrder::Descending => {
                for block_number in block_range.rev() {
                    if max_count == 0 {
                        return Ok(results);
                    }
                    let mut block_results = vec![];
                    let transactions = &self.transactions_per_block[block_number];
                    for proof in transactions.iter().rev() {
                        if max_count > 0 {
                            max_count -= 1;
                        } else {
                            break;
                        }
                        block_results.push(proof);
                    }
                    if !block_results.is_empty() {
                        results.add_block(self.blocks[block_number], block_results);
                    }
                }
            }
        };
        Ok(results)
    }

    fn get_transaction_inclusion_proof(
        &self,
        transaction_hash: &Scalar,
    ) -> Option<(usize, TransactionInclusionProof)> {
        let transaction_locator = self.transaction_locators_by_hash.get(transaction_hash)?;
        let block_transactions = self
            .transactions_per_block
            .get(transaction_locator.block_number)?;
        let proof =
            block_transactions.get_inclusion_proof(transaction_locator.transaction_number)?;
        Some((transaction_locator.block_number, proof))
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
            // TODO: don't silently skip errors, log them.
            if let Some((block_number, proof)) = self.get_transaction_inclusion_proof(&hash) {
                if block_number != last_block_number {
                    if !block_results.is_empty() {
                        results.add_block(self.blocks[last_block_number], block_results);
                    }
                    last_block_number = block_number;
                    block_results = vec![proof];
                } else {
                    block_results.push(proof);
                }
            }
        }
        if !block_results.is_empty() {
            results.add_block(self.blocks[last_block_number], block_results);
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
                // TODO: don't silently skip errors, log them.
                if let Some((block_number, proof)) = self.get_transaction_inclusion_proof(lhs) {
                    if block_number != last_block_number {
                        if !block_results.is_empty() {
                            results.add_block(self.blocks[last_block_number], block_results);
                        }
                        last_block_number = block_number;
                        block_results = vec![proof];
                    } else {
                        block_results.push(proof);
                    }
                }
                i += 1;
                j += 1;
                max_count -= 1;
            }
        }
        if !block_results.is_empty() {
            results.add_block(self.blocks[last_block_number], block_results);
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
                // TODO: don't silently skip errors, log them.
                if let Some((block_number, proof)) = self.get_transaction_inclusion_proof(lhs) {
                    if block_number != last_block_number {
                        if !block_results.is_empty() {
                            results.add_block(self.blocks[last_block_number], block_results);
                        }
                        last_block_number = block_number;
                        block_results = vec![proof];
                    } else {
                        block_results.push(proof);
                    }
                }
                i -= 1;
                j -= 1;
                max_count -= 1;
            }
        }
        if !block_results.is_empty() {
            results.add_block(self.blocks[last_block_number], block_results);
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

    fn close_block(&mut self, timestamp: SystemTime) -> BlockInfo {
        let block_number = self.current_version();
        let previous_block_hash = self.blocks.last().unwrap().hash();
        let (_, network_topology) = self
            .network_topologies
            .range(0..=block_number)
            .next_back()
            .unwrap();
        let transactions_root_hash = self.transactions_per_block.last().unwrap().root_hash();
        let accounts_root_hash = self.accounts.root_hash(block_number);
        let program_storage_root_hash = self.program_storage.root_hash(block_number);
        let block = BlockInfo::new(
            self.chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology.root_hash(),
            transactions_root_hash,
            accounts_root_hash,
            program_storage_root_hash,
        );
        let block_hash = block.hash();
        self.blocks.push(block);
        self.block_numbers_by_hash
            .insert(block_hash, block_number as usize);
        self.transactions_per_block
            .push(BlockTransactions::default());
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

    pub async fn get_transaction(
        &self,
        hash: Scalar,
    ) -> Option<(BlockInfo, TransactionInclusionProof)> {
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
    use crate::account::testing;
    use crate::clock::testing::MockClock;
    use crate::constants;
    use crate::testing::parse_scalar;
    use std::time::Duration;

    const COIN_UNIT: u64 = 1_000_000_000_000_000_000u64;

    const TEST_CHAIN_ID: u64 = 42;

    fn coins(number: u64) -> Scalar {
        Scalar::from(number) * Scalar::from(COIN_UNIT)
    }

    fn reward_for(stake: Scalar) -> Scalar {
        (stake * Scalar::from(constants::BLOCK_REWARD_NUMERATOR))
            .shr(constants::BLOCK_REWARD_DENOMINATOR_LOG2 as usize)
            - stake
    }

    fn account_info1() -> AccountInfo {
        AccountInfo {
            last_nonce: 12,
            balance: coins(90),
            staking_balance: coins(78),
        }
    }

    fn account_info2() -> AccountInfo {
        AccountInfo {
            last_nonce: 34,
            balance: coins(56),
            staking_balance: 0.into(),
        }
    }

    fn account_info3() -> AccountInfo {
        AccountInfo {
            last_nonce: 56,
            balance: coins(34),
            staking_balance: 0.into(),
        }
    }

    fn account_info4() -> AccountInfo {
        AccountInfo {
            last_nonce: 78,
            balance: coins(12),
            staking_balance: 0.into(),
        }
    }

    #[test]
    fn test_empty_block_transactions() {
        let transactions = BlockTransactions::default();
        assert_eq!(
            transactions.root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        assert_eq!(transactions.len(), 0);
        assert!(transactions.get_all_hashes().is_empty());
        assert!(transactions.get_inclusion_proof(0).is_none());
        assert!(transactions.get_inclusion_proof(1).is_none());
        assert!(transactions.iter().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn test_block_transactions_with_reward_transaction() {
        let account = testing::account1();
        let transaction = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account,
                TEST_CHAIN_ID,
                12,
                account.address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transactions = {
            let mut transactions = BlockTransactions::default();
            let index = transactions.add(transaction.clone());
            assert_eq!(index, 0);
            transactions
        };
        assert_eq!(
            transactions.root_hash(),
            parse_scalar("0x409025ae97968b756848983e04d5bcf0b636917134f13026d8f1203c91674e1a")
        );
        assert_eq!(transactions.len(), 1);
        assert_eq!(
            transactions.get_all_hashes(),
            vec![parse_scalar(
                "0x3ee056e5982b58d5156d04c1b7d17e0c0948172e24403f2f79a6b8400be6dbf8"
            )]
        );
        let proof = transactions.get_inclusion_proof(0).unwrap();
        assert_eq!(proof.root_hash(), transactions.root_hash());
        assert_eq!(proof.key(), 0.into());
        assert_eq!(proof.value(), &transaction);
        assert!(proof.verify().is_ok());
        assert!(transactions.get_inclusion_proof(1).is_none());
        let proofs = transactions.iter().collect::<Vec<_>>();
        assert_eq!(proofs, vec![proof.clone()]);
        let proofs = transactions.iter().rev().collect::<Vec<_>>();
        assert_eq!(proofs, vec![proof]);
    }

    #[test]
    fn test_block_transactions_with_two_transactions() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                12,
                account1.address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account2.address(),
                100.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transactions = {
            let mut transactions = BlockTransactions::default();
            assert_eq!(transactions.add(transaction1.clone()), 0);
            assert_eq!(transactions.add(transaction2.clone()), 1);
            transactions
        };
        assert_eq!(
            transactions.root_hash(),
            parse_scalar("0x49589c2263e9ec866602aaf5341bdf7301e323bb0621b61413b7796dda48fa2b")
        );
        assert_eq!(transactions.len(), 2);
        assert_eq!(
            transactions.get_all_hashes(),
            vec![
                parse_scalar("0x3ee056e5982b58d5156d04c1b7d17e0c0948172e24403f2f79a6b8400be6dbf8"),
                parse_scalar("0x4fb70b3d66f4689fefc98959e1a9aa98a47b5184ea69eac5e4c0f77ba796c863"),
            ]
        );
        let proof1 = transactions.get_inclusion_proof(0).unwrap();
        assert_eq!(proof1.root_hash(), transactions.root_hash());
        assert_eq!(proof1.key(), 0.into());
        assert_eq!(proof1.value(), &transaction1);
        assert!(proof1.verify().is_ok());
        let proof2 = transactions.get_inclusion_proof(1).unwrap();
        assert_eq!(proof2.root_hash(), transactions.root_hash());
        assert_eq!(proof2.key(), 1.into());
        assert_eq!(proof2.value(), &transaction2);
        assert!(proof2.verify().is_ok());
        assert!(transactions.get_inclusion_proof(2).is_none());
        let proofs = transactions.iter().collect::<Vec<_>>();
        assert_eq!(proofs, vec![proof1.clone(), proof2.clone()]);
        let proofs = transactions.iter().rev().collect::<Vec<_>>();
        assert_eq!(proofs, vec![proof2, proof1]);
    }

    #[test]
    fn test_block_transactions_with_three_transactions() {
        let account1 = testing::account1();
        let account2 = testing::account2();
        let transaction1 = Transaction::from_proto(
            Transaction::make_block_reward_proto(
                &account1,
                TEST_CHAIN_ID,
                12,
                account1.address(),
                123.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction2 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                13,
                account2.address(),
                100.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transaction3 = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account2,
                TEST_CHAIN_ID,
                1,
                account1.address(),
                50.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let transactions = {
            let mut transactions = BlockTransactions::default();
            assert_eq!(transactions.add(transaction1.clone()), 0);
            assert_eq!(transactions.add(transaction2.clone()), 1);
            assert_eq!(transactions.add(transaction3.clone()), 2);
            transactions
        };
        assert_eq!(
            transactions.root_hash(),
            parse_scalar("0x7118340ff7271a0836506cbafc082c2dec8959cdb8027ec58dc6fd7a14aad4d7")
        );
        assert_eq!(transactions.len(), 3);
        assert_eq!(
            transactions.get_all_hashes(),
            vec![
                parse_scalar("0x3ee056e5982b58d5156d04c1b7d17e0c0948172e24403f2f79a6b8400be6dbf8"),
                parse_scalar("0x4fb70b3d66f4689fefc98959e1a9aa98a47b5184ea69eac5e4c0f77ba796c863"),
                parse_scalar("0x05fc556b2f96f7cfe60fe7cc19696080d07ab9f63efcb722f6f4ff8f5434a477"),
            ]
        );
        let proof1 = transactions.get_inclusion_proof(0).unwrap();
        assert_eq!(proof1.root_hash(), transactions.root_hash());
        assert_eq!(proof1.key(), 0.into());
        assert_eq!(proof1.value(), &transaction1);
        assert!(proof1.verify().is_ok());
        let proof2 = transactions.get_inclusion_proof(1).unwrap();
        assert_eq!(proof2.root_hash(), transactions.root_hash());
        assert_eq!(proof2.key(), 1.into());
        assert_eq!(proof2.value(), &transaction2);
        assert!(proof2.verify().is_ok());
        let proof3 = transactions.get_inclusion_proof(2).unwrap();
        assert_eq!(proof3.root_hash(), transactions.root_hash());
        assert_eq!(proof3.key(), 2.into());
        assert_eq!(proof3.value(), &transaction3);
        assert!(proof3.verify().is_ok());
        assert!(transactions.get_inclusion_proof(3).is_none());
        let proofs = transactions.iter().collect::<Vec<_>>();
        assert_eq!(proofs, vec![proof1.clone(), proof2.clone(), proof3.clone()]);
        let proofs = transactions.iter().rev().collect::<Vec<_>>();
        assert_eq!(proofs, vec![proof3, proof2, proof1]);
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
            self.db.close_block().await
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
            let account_state = self.db.get_latest_account_info(account_address).await?;
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
            parse_scalar("0x0c82d3129412419aaedd519dc1bff1f6833b8ef242c7e61e3d40cbf216ec0335");
        assert_eq!(block.hash(), block_hash);
        let transactions_root_hash =
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3");
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block.hash(), block_hash);
        let transactions_root_hash =
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3");
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        let transactions_root_hash =
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3");
        assert_eq!(block1.transactions_root_hash(), transactions_root_hash);
        let block2_hash =
            parse_scalar("0x012280d6c021dd104fdef2276f9bba2de523fb32a94d621c0635e5a1e6b13794");
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x19fc6e9517f053243ea7660897f9b2e6def915d74baf46f254e9b667e14b27d5");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x458bedbde3994bc17658554661b69a865f02656ecb0345b2a02f76f29638f4c3")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountInfo {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        };
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x326c32a9ebf758afdf602f35afedb25273f9904fb4f03aadbc343e4917b0e7ce");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x48ece9417b7949566daf094af4990952685665aef0c47b74a689a34db8c7842f")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountInfo {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        };
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
        let updated_account_info2 = AccountInfo {
            last_nonce: 35,
            balance: coins(44),
            staking_balance: 0.into(),
        };
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
        let updated_account_info3 = AccountInfo {
            last_nonce: 56,
            balance: coins(46),
            staking_balance: 0.into(),
        };
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x19fc6e9517f053243ea7660897f9b2e6def915d74baf46f254e9b667e14b27d5");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x458bedbde3994bc17658554661b69a865f02656ecb0345b2a02f76f29638f4c3")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountInfo {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        };
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x19fc6e9517f053243ea7660897f9b2e6def915d74baf46f254e9b667e14b27d5");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x458bedbde3994bc17658554661b69a865f02656ecb0345b2a02f76f29638f4c3")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountInfo {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        };
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x19fc6e9517f053243ea7660897f9b2e6def915d74baf46f254e9b667e14b27d5");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x458bedbde3994bc17658554661b69a865f02656ecb0345b2a02f76f29638f4c3")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountInfo {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        };
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x5f43d012dd4d4aef5e4b49aabd382bfc38c707093fdaf81e430bf5fe1e3b8e15");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x57c8acd9ac5e276e64a292d408cf817a4043ff0912f65c9aaa22b098989bc2f1")
        );
        assert_eq!(db.get_block_by_hash(block1_hash).await.unwrap(), block1);
        assert_eq!(db.get_block_by_hash(block2_hash).await.unwrap(), block2);
        assert_eq!(db.get_block_by_number(1).await.unwrap(), block2);
        assert!(db.get_block_by_number(2).await.is_none());
        assert_eq!(db.get_latest_block().await, block2);
        let updated_account_info1 = AccountInfo {
            last_nonce: 13,
            balance: coins(90) + reward_for(coins(78)),
            staking_balance: coins(78),
        };
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
        let updated_account_info2 = AccountInfo {
            last_nonce: 35,
            balance: coins(34),
            staking_balance: 0.into(),
        };
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
        let updated_account_info3 = AccountInfo {
            last_nonce: 57,
            balance: coins(56),
            staking_balance: 0.into(),
        };
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
            parse_scalar("0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d");
        assert_eq!(block1.hash(), block1_hash);
        assert_eq!(
            block1.transactions_root_hash(),
            parse_scalar("0x18946455643c580076fa4d0b296a9bca801685e125b5ac65fb987e01fb2466b3")
        );
        let block2_hash =
            parse_scalar("0x6eabea08d8e0f12e77945dad9b15240f0c1a835393e0a8ec78a7cce907982999");
        assert_eq!(block2.hash(), block2_hash);
        assert_eq!(
            block2.transactions_root_hash(),
            parse_scalar("0x0ec2e845d77342dc33ba79b40935a195ec578a39c3c4fab5ae3a1cf7580886b0")
        );
        let block3_hash =
            parse_scalar("0x012fcee1811edd4b2d04470bea9419359c153648abd6aa5ba9f1d2cb51dccd55");
        assert_eq!(block3.hash(), block3_hash);
        assert_eq!(
            block3.transactions_root_hash(),
            parse_scalar("0x10487a6336d088dde8431afac6962b2cade255520021544215da794e2e8ac1d1")
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
            AccountInfo {
                last_nonce: 13,
                balance: coins(90) + reward_for(coins(78)),
                staking_balance: coins(78),
            }
        );
        assert_eq!(
            fixture
                .get_account_info(account1.address(), block3_hash)
                .await
                .unwrap(),
            AccountInfo {
                last_nonce: 14,
                balance: coins(90) + reward_for(coins(78)).double(),
                staking_balance: coins(78),
            }
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account1.address())
                .await
                .unwrap(),
            AccountInfo {
                last_nonce: 14,
                balance: coins(90) + reward_for(coins(78)).double(),
                staking_balance: coins(78),
            }
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
            AccountInfo {
                last_nonce: 34,
                balance: coins(68),
                staking_balance: 0.into(),
            }
        );
        assert_eq!(
            fixture
                .get_account_info(account2.address(), block3_hash)
                .await
                .unwrap(),
            AccountInfo {
                last_nonce: 35,
                balance: coins(34),
                staking_balance: 0.into(),
            }
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account2.address())
                .await
                .unwrap(),
            AccountInfo {
                last_nonce: 35,
                balance: coins(34),
                staking_balance: 0.into(),
            }
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
            AccountInfo {
                last_nonce: 57,
                balance: coins(22),
                staking_balance: 0.into(),
            }
        );
        assert_eq!(
            fixture
                .get_account_info(account3.address(), block3_hash)
                .await
                .unwrap(),
            AccountInfo {
                last_nonce: 57,
                balance: coins(56),
                staking_balance: 0.into(),
            }
        );
        assert_eq!(
            fixture
                .get_latest_account_info(account3.address())
                .await
                .unwrap(),
            AccountInfo {
                last_nonce: 57,
                balance: coins(56),
                staking_balance: 0.into(),
            }
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
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d",
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
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d",
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
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d",
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d",
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
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d"
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
                        "0x588fbc7bd8ddafc5b78421ca6b7ad357d9d95182c4fad8b34eefd7238cb92ce5"
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
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d"
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
                        "0x588fbc7bd8ddafc5b78421ca6b7ad357d9d95182c4fad8b34eefd7238cb92ce5"
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
                        "0x588fbc7bd8ddafc5b78421ca6b7ad357d9d95182c4fad8b34eefd7238cb92ce5"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x588fbc7bd8ddafc5b78421ca6b7ad357d9d95182c4fad8b34eefd7238cb92ce5"
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
                        "0x2976c1f3ec8eb4c6e1e289138dda4e8029823e08c3866d08f7f200bfcfe28a6d"
                    ))),
                    Some(BlockFilter::BlockHash(parse_scalar(
                        "0x588fbc7bd8ddafc5b78421ca6b7ad357d9d95182c4fad8b34eefd7238cb92ce5"
                    ))),
                    SortOrder::Ascending,
                    None
                )
                .await
                .unwrap(),
            transactions
        );
    }

    // TODO
}
