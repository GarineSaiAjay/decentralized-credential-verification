//! Everything done on the chain: reading the two contracts, and sending transactions to them.
//!
//! `Client` holds the connection and the rules for sending (fee limit, nonce, confirmations). `Ledger` and
//! `Registry` are the two contracts. The worker uses a client with the anchorer key; the admin commands use
//! one with the issuer admin key; `sync-keys` uses one with no key at all.

use std::time::{Duration, Instant};

use alloy::{
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder},
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{BlockNumberOrTag, Filter, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};

use crate::{
    config::{Net, R},
    ledger::Block,
};

// The parts of contracts/src/*.sol used here. scripts/chain-test.sh runs every command against the real
// contracts, so a difference between these and the Solidity shows up there.
sol! {
    #[sol(rpc)]
    contract LedgerAnchor {
        struct Anchor {
            bytes32 blockHash;
            bytes32 merkleRoot;
            uint32 leafCount;
            uint64 anchoredAt;
            uint64 blockNumber;
        }
        struct AnchorInput {
            bytes32 blockHash;
            bytes32 merkleRoot;
            uint32 leafCount;
        }
        struct Position {
            uint64 epoch;
            uint64 height;
            uint32 leafIndex;
        }
        event Anchored(uint64 indexed epoch, uint64 indexed height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount);
        event Revoked(uint64 indexed epoch, uint64 indexed height, uint32 leafIndex);

        function owner() external view returns (address);
        function pendingOwner() external view returns (address);
        function anchorer() external view returns (address);
        function epoch() external view returns (uint64);
        function nextHeight() external view returns (uint64);
        function anchor(uint64 height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount) external;
        function anchorBatch(uint64 firstHeight, AnchorInput[] calldata blocks) external;
        function anchorOf(uint64 epoch_, uint64 height) external view returns (Anchor memory);
        function currentAnchor(uint64 height) external view returns (uint64 epoch_, Anchor memory a);
        function isRevoked(uint64 epoch_, uint64 height, uint32 leafIndex) external view returns (bool);
        function revoke(uint64 epoch_, uint64 height, uint32 leafIndex) external;
        function revokeBatch(Position[] calldata positions) external;
        function setAnchorer(address anchorer_) external;
        function startEpoch(uint64 fromHeight, string calldata reason) external;
        function transferOwnership(address newOwner) external;
        function acceptOwnership() external;
    }

    #[sol(rpc)]
    contract IssuerRegistry {
        struct Issuer {
            address admin;
            address pendingAdmin;
            address ledger;
            bool suspended;
            uint64 registeredAt;
            string name;
            string did;
        }
        struct Key {
            uint8 status;
            uint8 stage;
            uint64 addedAt;
            uint64 retiredAt;
            uint64 revokedAt;
        }
        function owner() external view returns (address);
        function pendingOwner() external view returns (address);
        function acceptOwnership() external;
        function issuer(uint64 issuerId) external view returns (Issuer memory);
        function keyInfo(uint64 issuerId, bytes32 publicKey) external view returns (Key memory);
        function activeKey(uint64 issuerId, uint8 stage) external view returns (bytes32);
        function addKey(uint64 issuerId, bytes32 publicKey, uint8 stage) external;
        function retireKey(uint64 issuerId, bytes32 publicKey) external;
        function revokeKey(uint64 issuerId, bytes32 publicKey, string calldata reason) external;
        function setLedger(uint64 issuerId, address ledger) external;
        function transferIssuerAdmin(uint64 issuerId, address proposed) external;
        function acceptIssuerAdmin(uint64 issuerId) external;
    }
}

pub(crate) fn rpc<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> String + '_ {
    move |err| format!("{what}: {err}")
}

pub fn b256(hash_hex: &str) -> R<B256> {
    hash_hex
        .trim_start_matches("0x")
        .parse::<B256>()
        .map_err(|_| format!("'{hash_hex}' is not a 32-byte hash"))
}

pub enum Sent {
    /// The transaction was accepted by the node; it is not confirmed yet.
    Tx(B256),
    /// The network's fee is above CHAIN_MAX_FEE_GWEI; nothing was sent.
    FeeTooHigh { wanted_wei: u128 },
}

type Http = alloy::transports::http::reqwest::Client;
type Url = alloy::transports::http::reqwest::Url;

/// A connection to the chain, with or without a key to sign with.
#[derive(Clone)]
pub struct Client {
    pub provider: DynProvider,
    /// The address transactions are sent from (zero for a read-only client).
    pub signer: Address,
    net: Net,
}

impl Client {
    fn http(net: &Net) -> R<(Http, Url)> {
        let url = net
            .rpc_url
            .parse()
            .map_err(|_| "CHAIN_RPC_URL is not a valid URL".to_string())?;
        // Without a time limit, a node that stops answering would hang the program instead of failing the round.
        let http = Http::builder()
            .timeout(net.rpc_timeout)
            .build()
            .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
        Ok((http, url))
    }

    pub fn new(net: &Net, signer: PrivateKeySigner) -> R<Self> {
        let (http, url) = Self::http(net)?;
        let address = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect_reqwest(http, url)
            .erased();
        Ok(Self {
            provider,
            signer: address,
            net: net.clone(),
        })
    }

    /// A client that can read but has no key, so it cannot send anything.
    pub fn read_only(net: &Net) -> R<Self> {
        let (http, url) = Self::http(net)?;
        let provider = ProviderBuilder::new().connect_reqwest(http, url).erased();
        Ok(Self {
            provider,
            signer: Address::ZERO,
            net: net.clone(),
        })
    }

    /// Refuses to work against a different network than the one configured.
    pub async fn check_network(&self) -> R<()> {
        let id = self
            .provider
            .get_chain_id()
            .await
            .map_err(rpc("the RPC node did not answer"))?;
        if id != self.net.chain_id {
            return Err(format!(
                "the RPC node is chain {id}, but CHAIN_ID is {}",
                self.net.chain_id
            ));
        }
        Ok(())
    }

    pub async fn has_code(&self, at: Address) -> R<bool> {
        let code = self
            .provider
            .get_code_at(at)
            .await
            .map_err(rpc("reading the contract"))?;
        Ok(!code.is_empty())
    }

    pub async fn balance_wei(&self) -> R<U256> {
        self.provider
            .get_balance(self.signer)
            .await
            .map_err(rpc("reading the balance"))
    }

    /// Sends one transaction, unless the network fee is above the limit.
    pub async fn submit(&self, tx: TransactionRequest) -> R<Sent> {
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(rpc("estimating the fee"))?;
        if fees.max_fee_per_gas > self.net.max_fee_wei {
            return Ok(Sent::FeeTooHigh {
                wanted_wei: fees.max_fee_per_gas,
            });
        }
        // The confirmed nonce, not the pending one: a transaction stuck from an earlier attempt is replaced
        // instead of being queued behind.
        let nonce = self
            .provider
            .get_transaction_count(self.signer)
            .await
            .map_err(rpc("reading the nonce"))?;
        let tx = tx
            .with_from(self.signer)
            .with_nonce(nonce)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
        let pending = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(rpc("the transaction was refused"))?;
        Ok(Sent::Tx(*pending.tx_hash()))
    }

    /// Waits until the transaction has the required number of confirmations. `Ok(None)` means it did not
    /// get there in time (dropped, replaced, or removed by a chain reorganisation); the caller sends nothing
    /// more and simply looks at the contract again later. `Ok(Some(n))` is the chain block that holds it.
    pub async fn confirmed(&self, tx: B256) -> R<Option<u64>> {
        let deadline = Instant::now() + self.net.tx_timeout;
        loop {
            let receipt = self
                .provider
                .get_transaction_receipt(tx)
                .await
                .map_err(rpc("reading the receipt"))?;
            if let Some(r) = receipt {
                if !r.status() {
                    return Err(format!("transaction {tx:#x} was mined but reverted"));
                }
                if let Some(mined) = r.block_number() {
                    let head = self
                        .provider
                        .get_block_number()
                        .await
                        .map_err(rpc("reading the chain head"))?;
                    if head + 1 >= mined + self.net.confirmations {
                        return Ok(Some(mined));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(self.net.poll).await;
        }
    }

    /// The time (seconds) of a chain block.
    pub async fn block_time(&self, number: u64) -> R<u64> {
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(number))
            .await
            .map_err(rpc("reading a chain block"))?
            .ok_or_else(|| format!("the node does not have chain block {number}"))?;
        Ok(block.header.timestamp)
    }

    pub fn log_window(&self) -> u64 {
        self.net.log_window
    }

    pub fn timeout(&self) -> Duration {
        self.net.tx_timeout
    }
}

/// What the ledger contract holds for one height.
#[derive(Clone, Debug, PartialEq)]
pub struct OnChain {
    pub epoch: u64,
    pub block_hash: String,
    pub merkle_root: String,
    pub leaf_count: u32,
    pub anchored_at: u64,
    pub block_number: u64,
}

impl OnChain {
    fn from(epoch: u64, a: LedgerAnchor::Anchor) -> Option<Self> {
        (a.anchoredAt != 0).then(|| Self {
            epoch,
            block_hash: hex::encode(a.blockHash),
            merkle_root: hex::encode(a.merkleRoot),
            leaf_count: a.leafCount,
            anchored_at: a.anchoredAt,
            block_number: a.blockNumber,
        })
    }

    /// True if this anchor is exactly the given database block.
    pub fn is(&self, b: &Block) -> bool {
        self.block_hash == b.block_hash
            && self.merkle_root == b.merkle_root
            && self.leaf_count as usize == b.leaves.len()
    }
}

/// A credential's place in the anchored ledger: what the revocation bit is keyed by.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Position {
    pub epoch: u64,
    pub height: u64,
    pub leaf_index: u32,
}

/// One university's LedgerAnchor contract.
pub struct Ledger {
    pub client: Client,
    contract: LedgerAnchor::LedgerAnchorInstance<DynProvider>,
    pub address: Address,
}

impl Ledger {
    pub fn new(client: Client, address: Address) -> Self {
        Self {
            contract: LedgerAnchor::new(address, client.provider.clone()),
            client,
            address,
        }
    }

    /// There must be a LedgerAnchor at the address. Returns its anchorer.
    pub async fn anchorer(&self) -> R<Address> {
        if !self.client.has_code(self.address).await? {
            return Err(format!(
                "there is no contract at CHAIN_ANCHOR_CONTRACT {:#x} on this chain",
                self.address
            ));
        }
        self.contract
            .anchorer()
            .call()
            .await
            .map_err(|_| format!("the contract at {:#x} is not a LedgerAnchor", self.address))
    }

    pub async fn owner(&self) -> R<Address> {
        self.contract
            .owner()
            .call()
            .await
            .map_err(rpc("reading the ledger's owner"))
    }

    pub async fn pending_owner(&self) -> R<Address> {
        self.contract
            .pendingOwner()
            .call()
            .await
            .map_err(rpc("reading the ledger's pending owner"))
    }

    /// (current epoch, the only height the next anchor may use)
    pub async fn state(&self) -> R<(u64, u64)> {
        let epoch = self
            .contract
            .epoch()
            .call()
            .await
            .map_err(rpc("reading the epoch"))?;
        let next = self
            .contract
            .nextHeight()
            .call()
            .await
            .map_err(rpc("reading the next height"))?;
        Ok((epoch, next))
    }

    /// The anchor that currently stands for a height, if any.
    pub async fn current(&self, height: i64) -> R<Option<OnChain>> {
        let r = self
            .contract
            .currentAnchor(height as u64)
            .call()
            .await
            .map_err(rpc("reading an anchor"))?;
        Ok(OnChain::from(r.epoch_, r.a))
    }

    /// The anchor stored for a height in one particular epoch, if any.
    pub async fn at(&self, epoch: u64, height: i64) -> R<Option<OnChain>> {
        let a = self
            .contract
            .anchorOf(epoch, height as u64)
            .call()
            .await
            .map_err(rpc("reading an anchor"))?;
        Ok(OnChain::from(epoch, a))
    }

    /// The transaction that anchored a height, found through its event in the block the contract recorded.
    pub async fn anchoring_tx(&self, a: &OnChain, height: i64) -> R<B256> {
        let filter = Filter::new()
            .address(self.address)
            .event_signature(LedgerAnchor::Anchored::SIGNATURE_HASH)
            .topic1(B256::from(U256::from(a.epoch)))
            .topic2(B256::from(U256::from(height as u64)))
            .from_block(a.block_number)
            .to_block(a.block_number);
        let logs = self
            .client
            .provider
            .get_logs(&filter)
            .await
            .map_err(rpc("reading the anchoring event"))?;
        logs.iter().find_map(|l| l.transaction_hash).ok_or_else(|| {
            format!(
                "no anchoring event for block {height} in chain block {}",
                a.block_number
            )
        })
    }

    /// The transaction request that anchors consecutive blocks.
    pub fn anchor_request(&self, blocks: &[Block]) -> R<TransactionRequest> {
        let first = blocks[0].height as u64;
        if let [b] = blocks {
            return Ok(self
                .contract
                .anchor(
                    first,
                    b256(&b.block_hash)?,
                    b256(&b.merkle_root)?,
                    b.leaves.len() as u32,
                )
                .into_transaction_request());
        }
        let inputs = blocks
            .iter()
            .map(|b| {
                Ok(LedgerAnchor::AnchorInput {
                    blockHash: b256(&b.block_hash)?,
                    merkleRoot: b256(&b.merkle_root)?,
                    leafCount: b.leaves.len() as u32,
                })
            })
            .collect::<R<Vec<_>>>()?;
        Ok(self
            .contract
            .anchorBatch(first, inputs)
            .into_transaction_request())
    }

    pub async fn is_revoked(&self, p: Position) -> R<bool> {
        self.contract
            .isRevoked(p.epoch, p.height, p.leaf_index)
            .call()
            .await
            .map_err(rpc("reading a revocation bit"))
    }

    /// The transaction request that sets the revocation bit of each position.
    pub fn revoke_request(&self, positions: &[Position]) -> TransactionRequest {
        if let [p] = positions {
            return self
                .contract
                .revoke(p.epoch, p.height, p.leaf_index)
                .into_transaction_request();
        }
        let list = positions
            .iter()
            .map(|p| LedgerAnchor::Position {
                epoch: p.epoch,
                height: p.height,
                leafIndex: p.leaf_index,
            })
            .collect();
        self.contract.revokeBatch(list).into_transaction_request()
    }

    /// Finds the transaction that set a revocation bit: (transaction, chain block). The contract does not
    /// record where that happened, so its events are searched backwards from the chain head, a window at a
    /// time, no further back than the block that anchored the credential.
    pub async fn revocation_tx(&self, p: Position, not_before: u64) -> R<Option<(B256, u64)>> {
        let window = self.client.log_window();
        let head = self
            .client
            .provider
            .get_block_number()
            .await
            .map_err(rpc("reading the chain head"))?;
        let mut to = head;
        for _ in 0..500 {
            let from = to.saturating_sub(window - 1).max(not_before);
            let filter = Filter::new()
                .address(self.address)
                .event_signature(LedgerAnchor::Revoked::SIGNATURE_HASH)
                .topic1(B256::from(U256::from(p.epoch)))
                .topic2(B256::from(U256::from(p.height)))
                .from_block(from)
                .to_block(to);
            let logs = self
                .client
                .provider
                .get_logs(&filter)
                .await
                .map_err(rpc("reading revocation events"))?;
            for log in logs {
                let Ok(event) = LedgerAnchor::Revoked::decode_log(&log.inner) else {
                    continue;
                };
                if event.leafIndex == p.leaf_index {
                    if let (Some(tx), Some(block)) = (log.transaction_hash, log.block_number) {
                        return Ok(Some((tx, block)));
                    }
                }
            }
            if from <= not_before || from == 0 {
                break;
            }
            to = from - 1;
        }
        Ok(None)
    }

    pub fn set_anchorer_request(&self, anchorer: Address) -> TransactionRequest {
        self.contract
            .setAnchorer(anchorer)
            .into_transaction_request()
    }

    pub fn start_epoch_request(&self, from_height: u64, reason: &str) -> TransactionRequest {
        self.contract
            .startEpoch(from_height, reason.to_string())
            .into_transaction_request()
    }

    pub fn transfer_ownership_request(&self, to: Address) -> TransactionRequest {
        self.contract
            .transferOwnership(to)
            .into_transaction_request()
    }

    pub fn accept_ownership_request(&self) -> TransactionRequest {
        self.contract.acceptOwnership().into_transaction_request()
    }
}

/// What the registry says about this issuer.
#[derive(Clone, Debug)]
pub struct IssuerInfo {
    pub admin: Address,
    pub pending_admin: Address,
    pub ledger: Address,
    pub suspended: bool,
    pub name: String,
}

/// One issuer's entry in the IssuerRegistry contract.
pub struct Registry {
    pub client: Client,
    contract: IssuerRegistry::IssuerRegistryInstance<DynProvider>,
    pub address: Address,
    pub issuer_id: u64,
}

impl Registry {
    pub fn new(client: Client, address: Address, issuer_id: u64) -> Self {
        Self {
            contract: IssuerRegistry::new(address, client.provider.clone()),
            client,
            address,
            issuer_id,
        }
    }

    pub async fn issuer(&self) -> R<IssuerInfo> {
        if !self.client.has_code(self.address).await? {
            return Err(format!(
                "there is no contract at CHAIN_REGISTRY_CONTRACT {:#x} on this chain",
                self.address
            ));
        }
        let i = self
            .contract
            .issuer(self.issuer_id)
            .call()
            .await
            .map_err(|_| {
                format!(
                    "the registry at {:#x} does not list issuer {}",
                    self.address, self.issuer_id
                )
            })?;
        Ok(IssuerInfo {
            admin: i.admin,
            pending_admin: i.pendingAdmin,
            ledger: i.ledger,
            suspended: i.suspended,
            name: i.name,
        })
    }

    pub async fn owner(&self) -> R<Address> {
        self.contract
            .owner()
            .call()
            .await
            .map_err(rpc("reading the registry's owner"))
    }

    pub async fn pending_owner(&self) -> R<Address> {
        self.contract
            .pendingOwner()
            .call()
            .await
            .map_err(rpc("reading the registry's pending owner"))
    }

    /// (status, stage) of a key: status 0 = never registered, 1 = active, 2 = retired, 3 = revoked.
    pub async fn key(&self, public_hex: &str) -> R<(u8, u8)> {
        let k = self
            .contract
            .keyInfo(self.issuer_id, b256(public_hex)?)
            .call()
            .await
            .map_err(rpc("reading a key from the registry"))?;
        Ok((k.status, k.stage))
    }

    /// The registry's one active key for a stage, if it has one.
    pub async fn active_key(&self, stage: u8) -> R<Option<String>> {
        let k = self
            .contract
            .activeKey(self.issuer_id, stage)
            .call()
            .await
            .map_err(rpc("reading the active key from the registry"))?;
        Ok((k != B256::ZERO).then(|| hex::encode(k)))
    }

    pub fn add_key_request(&self, public_hex: &str, stage: u8) -> R<TransactionRequest> {
        Ok(self
            .contract
            .addKey(self.issuer_id, b256(public_hex)?, stage)
            .into_transaction_request())
    }

    pub fn retire_key_request(&self, public_hex: &str) -> R<TransactionRequest> {
        Ok(self
            .contract
            .retireKey(self.issuer_id, b256(public_hex)?)
            .into_transaction_request())
    }

    pub fn revoke_key_request(&self, public_hex: &str, reason: &str) -> R<TransactionRequest> {
        Ok(self
            .contract
            .revokeKey(self.issuer_id, b256(public_hex)?, reason.to_string())
            .into_transaction_request())
    }

    pub fn set_ledger_request(&self, ledger: Address) -> TransactionRequest {
        self.contract
            .setLedger(self.issuer_id, ledger)
            .into_transaction_request()
    }

    pub fn transfer_admin_request(&self, to: Address) -> TransactionRequest {
        self.contract
            .transferIssuerAdmin(self.issuer_id, to)
            .into_transaction_request()
    }

    pub fn accept_admin_request(&self) -> TransactionRequest {
        self.contract
            .acceptIssuerAdmin(self.issuer_id)
            .into_transaction_request()
    }

    pub fn accept_ownership_request(&self) -> TransactionRequest {
        self.contract.acceptOwnership().into_transaction_request()
    }
}

/// Opens an encrypted keystore file. The key exists only in this process's memory.
pub fn open_keystore(file: &std::path::Path, passphrase: &str) -> R<PrivateKeySigner> {
    PrivateKeySigner::decrypt_keystore(file, passphrase).map_err(|err| {
        format!(
            "cannot open the keystore {} (wrong passphrase, or not a keystore file): {err}",
            file.display()
        )
    })
}
