use crate::account;
use crate::libernet;
use crate::proto;
use crate::tree;
use anyhow::{Context, Result, anyhow};
use blstrs::Scalar;
use crypto::{merkle::AsScalar, poseidon};
use ff::Field;
use std::time::SystemTime;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    hash: Scalar,
    chain_id: u64,
    number: u64,
    previous_block_hash: Scalar,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    transactions_root_hash: Scalar,
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
        transactions_root_hash: Scalar,
        accounts_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Scalar {
        poseidon::hash_t4(&[
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
            transactions_root_hash,
            accounts_root_hash,
            program_storage_root_hash,
        ])
    }

    pub fn new(
        chain_id: u64,
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        transactions_root_hash: Scalar,
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
                transactions_root_hash,
                accounts_root_hash,
                program_storage_root_hash,
            ),
            chain_id,
            number: block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            transactions_root_hash,
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

    pub fn transactions_root_hash(&self) -> Scalar {
        self.transactions_root_hash
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
            transactions_root_hash: Some(proto::encode_scalar(self.transactions_root_hash)),
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
        let transactions_root_hash = proto::decode_scalar(
            proto
                .transactions_root_hash
                .as_ref()
                .context("transaction tree root hash field is missing")?,
        )?;
        let accounts_root_hash = proto::decode_scalar(
            proto
                .accounts_root_hash
                .as_ref()
                .context("account balance tree root hash field is missing")?,
        )?;
        let program_storage_root_hash = proto::decode_scalar(
            proto
                .program_storage_root_hash
                .as_ref()
                .context("program storage tree root hash field is missing")?,
        )?;
        let block_info = Self::new(
            chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            transactions_root_hash,
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

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub last_nonce: u64,
    pub balance: Scalar,
    pub staking_balance: Scalar,
}

impl AsScalar for AccountInfo {
    fn as_scalar(&self) -> Scalar {
        poseidon::hash_t4(&[self.last_nonce.into(), self.balance, self.staking_balance])
    }
}

impl proto::EncodeToAny for AccountInfo {
    fn encode_to_any(&self) -> Result<prost_types::Any> {
        Ok(prost_types::Any::from_msg(&libernet::AccountInfo {
            last_nonce: Some(self.last_nonce),
            balance: Some(proto::encode_scalar(self.balance)),
            staking_balance: Some(proto::encode_scalar(self.staking_balance)),
        })?)
    }
}

impl proto::DecodeFromAny for AccountInfo {
    fn decode_from_any(proto: &prost_types::Any) -> Result<Self> {
        let proto = proto.to_msg::<libernet::AccountInfo>()?;
        Ok(Self {
            last_nonce: proto.last_nonce(),
            balance: proto
                .balance
                .map_or(Ok(Scalar::ZERO), |balance| proto::decode_scalar(&balance))?,
            staking_balance: proto
                .staking_balance
                .map_or(Ok(Scalar::ZERO), |balance| proto::decode_scalar(&balance))?,
        })
    }
}

pub type AccountTree = tree::MerkleTree<Scalar, AccountInfo, 3, 161>;
pub type AccountProof = tree::MerkleProof<Scalar, AccountInfo, 3, 161>;

impl AccountProof {
    /// Decodes a Merkle proof protobuf for an account, including the block descriptor, and
    /// validates it up to the block hash. Returns the decoded `BlockInfo` and high-level
    /// `MerkleProof` object containing the proven `AccountInfo`.
    pub fn decode_and_verify_account_proof(
        proto: &libernet::MerkleProof,
    ) -> Result<(BlockInfo, Self)> {
        let block_descriptor = proto
            .block_descriptor
            .as_ref()
            .context("missing block descriptor")?;
        let block_info = BlockInfo::decode(block_descriptor)?;
        let proof = Self::decode(proto, block_info.accounts_root_hash())?;
        proof.verify()?;
        Ok((block_info, proof))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    payload: prost_types::Any,
    signature: libernet::Signature,
    hash: Scalar,
}

impl Transaction {
    fn hash_block_reward_transaction(
        chain_id: u64,
        nonce: u64,
        sender_address: Scalar,
        transaction: &libernet::transaction::BlockReward,
    ) -> Result<Scalar> {
        Ok(poseidon::hash_t3(&[
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
        chain_id: u64,
        nonce: u64,
        sender_address: Scalar,
        transaction: &libernet::transaction::SendCoins,
    ) -> Result<Scalar> {
        Ok(poseidon::hash_t3(&[
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

    fn from_proto_impl(payload: prost_types::Any, signature: libernet::Signature) -> Result<Self> {
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
                Self::hash_block_reward_transaction(chain_id, nonce, signer, transaction)
            }
            libernet::transaction::payload::Transaction::SendCoins(transaction) => {
                Self::hash_send_coins_transaction(chain_id, nonce, signer, transaction)
            }
            _ => Err(anyhow!("unknown transaction type")),
        }?;
        Ok(Self {
            payload,
            signature,
            hash,
        })
    }

    pub fn from_proto(proto: libernet::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        Self::from_proto_impl(payload, signature)
    }

    pub fn from_proto_verify(proto: libernet::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        account::Account::verify_signed_message(&payload, &signature)?;
        Self::from_proto_impl(payload, signature)
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

impl AsScalar for Transaction {
    fn as_scalar(&self) -> Scalar {
        self.hash
    }
}

impl proto::EncodeToAny for Transaction {
    fn encode_to_any(&self) -> Result<prost_types::Any> {
        Ok(prost_types::Any::from_msg(&self.diff())?)
    }
}

impl proto::DecodeFromAny for Transaction {
    fn decode_from_any(proto: &prost_types::Any) -> Result<Self> {
        let proto = proto.to_msg::<libernet::Transaction>()?;
        Self::from_proto_verify(proto)
    }
}

/// NOTE: we cannot store `Transaction` objects directly in this tree because transactions don't
/// have default constructions or the `Default` trait. For empty leaves of this SMT we want to store
/// the zero scalar, so we store transaction hashes (which default to zero).
pub type TransactionTree = tree::MerkleTreeVersion<Scalar, Scalar, 2, 32>;

/// NOTE: unlike `TransactionTree` we can safely store `Transaction` objects here because
/// `MerkleProof` doesn't require the `Default` trait. `TransactionTree.get_proof` won't return
/// `TransactionInclusionProof` objects but rather `MerkleProof<Scalar, Scalar, 2, 32>`, so the
/// caller will have to convert manually.
pub type TransactionInclusionProof = tree::MerkleProof<Scalar, Transaction, 2, 32>;

impl TransactionInclusionProof {
    /// Decodes a Merkle proof protobuf for a transaction, including the block descriptor, and
    /// validates it up to the block hash. Returns the decoded `BlockInfo` and high-level
    /// `MerkleProof` object containing the proven `Transaction`.
    pub fn decode_and_verify_transaction_proof(
        proto: &libernet::MerkleProof,
    ) -> Result<(BlockInfo, Self)> {
        let block_descriptor = proto
            .block_descriptor
            .as_ref()
            .context("missing block descriptor")?;
        let block_info = BlockInfo::decode(block_descriptor)?;
        let proof = Self::decode(proto, block_info.transactions_root_hash())?;
        proof.verify()?;
        Ok((block_info, proof))
    }
}

#[derive(Debug, Default, Clone)]
pub struct ProgramStorage {
    tree: tree::MerkleTreeVersion<u32, u128, 2, 28>,
}

impl ProgramStorage {
    pub fn get_u8(&self, address: u32) -> u8 {
        let bytes = self.tree.get(address >> 4).to_le_bytes();
        bytes[(address & 0xF) as usize]
    }

    pub fn set_u8(&self, address: u32, value: u8) -> Self {
        let mut bytes = self.tree.get(address >> 4).to_le_bytes();
        bytes[(address & 0xF) as usize] = value;
        Self {
            tree: self.tree.put(address >> 4, u128::from_le_bytes(bytes)),
        }
    }
}

pub type ProgramStorageTree =
    tree::MerkleTree<Scalar, tree::MerkleTreeVersion<u32, u128, 2, 28>, 3, 161>;
pub type ProgramStorageProof = tree::MerkleProof<u32, u128, 2, 28>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{DecodeFromAny, EncodeToAny};
    use crate::testing::parse_scalar;
    use crypto::utils;
    use std::time::Duration;

    const TEST_CHAIN_ID: u64 = 42;

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
            parse_scalar("0x705a1cee832b5c00ce866716c5dcc78c9655bcfd329487d801b896fe330ad7ee")
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
            block_info.transactions_root_hash(),
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
            parse_scalar("0x1e5faa7a7eac17bb5e804eb81ba914eafebf58c42e579d636d53c07cefc0d1fb")
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
            block_info.transactions_root_hash(),
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
            parse_scalar("0x705a1cee832b5c00ce866716c5dcc78c9655bcfd329487d801b896fe330ad7ee")
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
            proto::decode_scalar(&block_descriptor.transactions_root_hash.unwrap()).unwrap(),
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
            parse_scalar("0x1e5faa7a7eac17bb5e804eb81ba914eafebf58c42e579d636d53c07cefc0d1fb")
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
            proto::decode_scalar(&block_descriptor.transactions_root_hash.unwrap()).unwrap(),
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

    #[test]
    fn test_bad_block_hash() {
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
        let mut block_descriptor = block_info.encode();
        block_descriptor.block_hash = block_descriptor.accounts_root_hash.clone();
        assert!(BlockInfo::decode(&block_descriptor).is_err());
    }

    #[test]
    fn test_default_account() {
        let account = AccountInfo::default();
        assert_eq!(
            account.as_scalar(),
            parse_scalar("0x447e7f6236dfaf8f3ddf7f0cd38eae309b9bff95f4ea6ecf2a46d106abd0623c")
        );
    }

    #[test]
    fn test_account_hash() {
        let account = AccountInfo {
            last_nonce: 42,
            balance: 123.into(),
            staking_balance: 456.into(),
        };
        assert_eq!(
            account.as_scalar(),
            parse_scalar("0x076bac30cc799b5d4ad51aefe54de1ecb11d57456ed46167d8003500c58c2f5f")
        );
    }

    #[test]
    fn test_encode_account1() {
        let account = AccountInfo {
            last_nonce: 42,
            balance: 123.into(),
            staking_balance: 456.into(),
        };
        let proto = account.encode_to_any().unwrap();
        assert_eq!(account, AccountInfo::decode_from_any(&proto).unwrap());
        let proto = proto.to_msg::<libernet::AccountInfo>().unwrap();
        assert_eq!(proto.last_nonce, Some(42));
        assert_eq!(
            proto::decode_scalar(&proto.balance.unwrap()).unwrap(),
            123.into()
        );
        assert_eq!(
            proto::decode_scalar(&proto.staking_balance.unwrap()).unwrap(),
            456.into()
        );
    }

    #[test]
    fn test_encode_account2() {
        let account = AccountInfo {
            last_nonce: 24,
            balance: 321.into(),
            staking_balance: 654.into(),
        };
        let proto = account.encode_to_any().unwrap();
        assert_eq!(account, AccountInfo::decode_from_any(&proto).unwrap());
        let proto = proto.to_msg::<libernet::AccountInfo>().unwrap();
        assert_eq!(proto.last_nonce, Some(24));
        assert_eq!(
            proto::decode_scalar(&proto.balance.unwrap()).unwrap(),
            321.into()
        );
        assert_eq!(
            proto::decode_scalar(&proto.staking_balance.unwrap()).unwrap(),
            654.into()
        );
    }

    #[test]
    fn test_decode_and_verify_account_proof() {
        let account = AccountInfo {
            last_nonce: 42,
            balance: 123.into(),
            staking_balance: 456.into(),
        };
        let address = utils::get_random_scalar();
        let version = 42;
        let mut tree = AccountTree::default();
        tree.put(address, account, version);
        let block_info = BlockInfo::new(
            TEST_CHAIN_ID,
            version,
            parse_scalar("0x387d4e5f500fb33a27eb820239e845aaef7a84f852be4033a7d3c23d64571ea7"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            parse_scalar("0x351e6822f39868e620d10995eb2c58513ccce8e55d0998e78bce97703c15df68"),
            parse_scalar("0x25cec4238bfaa905f2c97075aade1b266fc1120ccca08634e5adf1572d4d03ce"),
            tree.root_hash(version),
            parse_scalar("0x2b346f1eeac6cd03a43c826d72a102e78d82dcf249c01fc9f185a4b957daf060"),
        );
        let proof = tree.get_proof(address, version);
        let proto = proof.encode(block_info.encode()).unwrap();
        let (decoded_block_info, decoded_proof) =
            AccountProof::decode_and_verify_account_proof(&proto).unwrap();
        assert_eq!(decoded_block_info, block_info);
        assert_eq!(decoded_proof.take_value(), account);
    }

    #[test]
    fn test_decode_and_verify_transaction_proof() {
        let account1 = account::testing::account1();
        let account2 = account::testing::account2();
        let transaction = Transaction::from_proto(
            Transaction::make_coin_transfer_proto(
                &account1,
                TEST_CHAIN_ID,
                123,
                account2.address(),
                456.into(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut tree = TransactionTree::default();
        let index = 789.into();
        tree = tree.put(index, transaction.hash());
        let block_info = BlockInfo::new(
            TEST_CHAIN_ID,
            42,
            parse_scalar("0x387d4e5f500fb33a27eb820239e845aaef7a84f852be4033a7d3c23d64571ea7"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            parse_scalar("0x351e6822f39868e620d10995eb2c58513ccce8e55d0998e78bce97703c15df68"),
            tree.root_hash(),
            parse_scalar("0x277b1387699dc9fe9636af621c72872278d290344266612ce6e79555664361c8"),
            parse_scalar("0x2b346f1eeac6cd03a43c826d72a102e78d82dcf249c01fc9f185a4b957daf060"),
        );
        let proof = tree.get_proof(index).map(transaction.clone()).unwrap();
        let proto = proof.encode(block_info.encode()).unwrap();
        let (decoded_block_info, decoded_proof) =
            TransactionInclusionProof::decode_and_verify_transaction_proof(&proto).unwrap();
        assert_eq!(decoded_block_info, block_info);
        assert_eq!(decoded_proof.take_value(), transaction);
    }

    #[test]
    fn test_program_storage_initial_state() {
        let storage = ProgramStorage::default();
        assert_eq!(storage.get_u8(0x12345670u32), 0);
        assert_eq!(storage.get_u8(0x12345671u32), 0);
        assert_eq!(storage.get_u8(0x12345672u32), 0);
        assert_eq!(storage.get_u8(0x12345673u32), 0);
        assert_eq!(storage.get_u8(0x12345674u32), 0);
        assert_eq!(storage.get_u8(0x12345675u32), 0);
        assert_eq!(storage.get_u8(0x12345676u32), 0);
        assert_eq!(storage.get_u8(0x12345677u32), 0);
        assert_eq!(storage.get_u8(0x12345678u32), 0);
        assert_eq!(storage.get_u8(0x12345679u32), 0);
        assert_eq!(storage.get_u8(0x1234567au32), 0);
        assert_eq!(storage.get_u8(0x1234567bu32), 0);
        assert_eq!(storage.get_u8(0x1234567cu32), 0);
        assert_eq!(storage.get_u8(0x1234567du32), 0);
        assert_eq!(storage.get_u8(0x1234567eu32), 0);
        assert_eq!(storage.get_u8(0x1234567fu32), 0);
    }

    #[test]
    fn test_program_storage_update() {
        let mut storage = ProgramStorage::default();
        storage = storage.set_u8(0x12345674u32, 12u8);
        storage = storage.set_u8(0x12345672u32, 34u8);
        assert_eq!(storage.get_u8(0x12345670u32), 0);
        assert_eq!(storage.get_u8(0x12345671u32), 0);
        assert_eq!(storage.get_u8(0x12345672u32), 34);
        assert_eq!(storage.get_u8(0x12345673u32), 0);
        assert_eq!(storage.get_u8(0x12345674u32), 12);
        assert_eq!(storage.get_u8(0x12345675u32), 0);
        assert_eq!(storage.get_u8(0x12345676u32), 0);
        assert_eq!(storage.get_u8(0x12345677u32), 0);
        assert_eq!(storage.get_u8(0x12345678u32), 0);
        assert_eq!(storage.get_u8(0x12345679u32), 0);
        assert_eq!(storage.get_u8(0x1234567au32), 0);
        assert_eq!(storage.get_u8(0x1234567bu32), 0);
        assert_eq!(storage.get_u8(0x1234567cu32), 0);
        assert_eq!(storage.get_u8(0x1234567du32), 0);
        assert_eq!(storage.get_u8(0x1234567eu32), 0);
        assert_eq!(storage.get_u8(0x1234567fu32), 0);
    }
}
