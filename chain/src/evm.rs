//! Everything the worker does on the chain: read the anchor contract, and send `anchor` transactions.

use std::time::{Duration, Instant};

use alloy::{
    network::{EthereumWallet, ReceiptResponse},
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};

use crate::{
    config::{Config, R},
    ledger::Block,
};

// The part of contracts/src/LedgerAnchor.sol the worker uses. scripts/chain-test.sh runs the worker against
// the real contract, so a difference between the two shows up there.
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
        event Anchored(uint64 indexed epoch, uint64 indexed height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount);

        function anchorer() external view returns (address);
        function epoch() external view returns (uint64);
        function nextHeight() external view returns (uint64);
        function anchor(uint64 height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount) external;
        function anchorBatch(uint64 firstHeight, AnchorInput[] calldata blocks) external;
        function anchorOf(uint64 epoch_, uint64 height) external view returns (Anchor memory);
        function currentAnchor(uint64 height) external view returns (uint64 epoch_, Anchor memory a);
    }
}

/// What the contract holds for one height.
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

pub enum Sent {
    /// The transaction was accepted by the node; it is not confirmed yet.
    Tx(B256),
    /// The network's fee is above CHAIN_MAX_FEE_GWEI; nothing was sent.
    FeeTooHigh { wanted_wei: u128 },
}

pub struct Chain {
    provider: DynProvider,
    contract: LedgerAnchor::LedgerAnchorInstance<DynProvider>,
    pub address: Address,
    pub signer: Address,
    chain_id: u64,
    confirmations: u64,
    max_fee_wei: u128,
    tx_timeout: Duration,
    poll: Duration,
}

fn rpc<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> String + '_ {
    move |err| format!("{what}: {err}")
}

fn b256(hash_hex: &str) -> R<B256> {
    hash_hex
        .parse::<B256>()
        .map_err(|_| format!("'{hash_hex}' is not a 32-byte hash"))
}

/// Opens the anchorer's encrypted keystore file. The key exists only in this process's memory.
pub fn load_signer(cfg: &Config) -> R<PrivateKeySigner> {
    PrivateKeySigner::decrypt_keystore(&cfg.keystore_file, &cfg.keystore_passphrase).map_err(|err| {
        format!(
            "cannot open the keystore {} (wrong CHAIN_KEYSTORE_PASSPHRASE, or not a keystore file): {err}",
            cfg.keystore_file.display()
        )
    })
}

impl Chain {
    pub fn new(cfg: &Config, signer: PrivateKeySigner) -> R<Self> {
        let url = cfg
            .rpc_url
            .parse()
            .map_err(|_| "CHAIN_RPC_URL is not a valid URL".to_string())?;
        let address = signer.address();
        // Without a time limit, a node that stops answering would hang the worker instead of failing the round.
        let http = alloy::transports::http::reqwest::Client::builder()
            .timeout(cfg.rpc_timeout)
            .build()
            .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect_reqwest(http, url)
            .erased();
        Ok(Self {
            contract: LedgerAnchor::new(cfg.anchor_contract, provider.clone()),
            provider,
            address: cfg.anchor_contract,
            signer: address,
            chain_id: cfg.chain_id,
            confirmations: cfg.confirmations,
            max_fee_wei: cfg.max_fee_wei,
            tx_timeout: cfg.tx_timeout,
            poll: cfg.poll,
        })
    }

    /// Refuses to run against the wrong network, a missing contract, or with a key that is not the anchorer.
    pub async fn preflight(&self) -> R<()> {
        let id = self
            .provider
            .get_chain_id()
            .await
            .map_err(rpc("the RPC node did not answer"))?;
        if id != self.chain_id {
            return Err(format!(
                "the RPC node is chain {id}, but CHAIN_ID is {}",
                self.chain_id
            ));
        }
        let code = self
            .provider
            .get_code_at(self.address)
            .await
            .map_err(rpc("reading the contract"))?;
        if code.is_empty() {
            return Err(format!(
                "there is no contract at CHAIN_ANCHOR_CONTRACT {:#x} on chain {id}",
                self.address
            ));
        }
        let anchorer =
            self.contract.anchorer().call().await.map_err(|_| {
                format!("the contract at {:#x} is not a LedgerAnchor", self.address)
            })?;
        if anchorer != self.signer {
            return Err(format!(
                "this worker's key is {:#x}, but the contract's anchorer is {anchorer:#x}; the issuer admin must call setAnchorer",
                self.signer
            ));
        }
        Ok(())
    }

    pub async fn balance_wei(&self) -> R<U256> {
        self.provider
            .get_balance(self.signer)
            .await
            .map_err(rpc("reading the balance"))
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

    /// Sends one transaction anchoring consecutive blocks. Sends nothing if the fee is above the cap.
    pub async fn send(&self, blocks: &[Block]) -> R<Sent> {
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(rpc("estimating the fee"))?;
        if fees.max_fee_per_gas > self.max_fee_wei {
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
        let first = blocks[0].height as u64;
        let pending = if blocks.len() == 1 {
            let b = &blocks[0];
            self.contract
                .anchor(
                    first,
                    b256(&b.block_hash)?,
                    b256(&b.merkle_root)?,
                    b.leaves.len() as u32,
                )
                .nonce(nonce)
                .max_fee_per_gas(fees.max_fee_per_gas)
                .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
                .send()
                .await
        } else {
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
            self.contract
                .anchorBatch(first, inputs)
                .nonce(nonce)
                .max_fee_per_gas(fees.max_fee_per_gas)
                .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
                .send()
                .await
        };
        let pending = pending.map_err(rpc("the anchoring transaction was refused"))?;
        Ok(Sent::Tx(*pending.tx_hash()))
    }

    /// Waits until the transaction has the required number of confirmations. `Ok(false)` means it did not
    /// get there in time (dropped, replaced, or removed by a chain reorganisation); the caller sends nothing
    /// more and simply looks at the contract again on its next round.
    pub async fn confirmed(&self, tx: B256) -> R<bool> {
        let deadline = Instant::now() + self.tx_timeout;
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
                    if head + 1 >= mined + self.confirmations {
                        return Ok(true);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(self.poll).await;
        }
    }
}
