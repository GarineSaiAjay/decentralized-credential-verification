//! One round of work: find sealed blocks with no receipt, lowest first, and for each either record that the
//! contract already holds it, or anchor it and record that. The contract is the source of truth and a
//! database row is only a receipt, so there is no "in progress" state: if the worker dies at any point, the
//! next round reads the contract and carries on.
//!
//! The worker never changes a block, never overwrites an anchor (the contract would refuse) and never tries
//! to repair a disagreement. It records the finding and stops until a person has looked.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::{
    config::{Config, R},
    db,
    evm::{Chain, OnChain, Sent},
    ledger::{self, Block},
};

#[derive(Serialize, Default, Debug)]
pub struct Report {
    /// Heights anchored by a transaction sent in this round.
    pub anchored: Vec<i64>,
    /// Heights the contract already held, for which only the receipt was written.
    pub recorded: Vec<i64>,
    /// Findings that need a person. The worker stops at the first one.
    pub incidents: Vec<Value>,
    /// Why the round ended without finishing, when that is not an incident (fee too high, not confirmed yet).
    pub waiting: Option<String>,
    /// Blocks still without a receipt at the end of the round.
    pub pending: i64,
}

impl Report {
    pub fn clean(&self) -> bool {
        self.incidents.is_empty()
    }
}

struct Ctx<'a> {
    cfg: &'a Config,
    db: &'a PgPool,
    chain: &'a Chain,
    contract: String,
}

impl Ctx<'_> {
    async fn incident(&self, report: &mut Report, kind: &str, height: i64, detail: Value) -> R<()> {
        let new = db::incident(
            self.db,
            self.cfg.chain_id,
            &self.contract,
            kind,
            Some(height),
            &detail,
        )
        .await?;
        if new {
            tracing::error!(kind, height, %detail, "ON-CHAIN INCIDENT: anchoring has stopped until this is resolved");
        } else {
            tracing::warn!(
                kind,
                height,
                "unresolved on-chain incident (already recorded); anchoring is stopped"
            );
        }
        report
            .incidents
            .push(json!({ "kind": kind, "height": height, "detail": detail }));
        Ok(())
    }

    async fn record(&self, b: &Block, a: &OnChain, tx_hash: String) -> R<bool> {
        let anchored_at = DateTime::<Utc>::from_timestamp(a.anchored_at as i64, 0)
            .ok_or("the contract returned an impossible anchoring time")?;
        db::insert_receipt(
            self.db,
            &db::Receipt {
                chain_id: self.cfg.chain_id,
                contract: &self.contract,
                height: b.height,
                block_hash: &a.block_hash,
                merkle_root: &a.merkle_root,
                leaf_count: a.leaf_count,
                epoch: a.epoch,
                tx_hash,
                chain_block: a.block_number,
                anchored_at,
            },
        )
        .await
    }
}

fn mismatch_detail(b: &Block, a: &OnChain) -> Value {
    json!({
        "database": { "block_hash": b.block_hash, "merkle_root": b.merkle_root, "leaf_count": b.leaves.len() },
        "on_chain": { "block_hash": a.block_hash, "merkle_root": a.merkle_root, "leaf_count": a.leaf_count,
                      "epoch": a.epoch, "chain_block": a.block_number },
        "note": "the ledger in the database is not the one that was anchored (for example after restoring an older backup). Nothing was changed. See 'Restoring from a backup' in the README.",
    })
}

pub async fn tick(cfg: &Config, pool: &PgPool, chain: &Chain) -> R<Report> {
    let cx = Ctx {
        cfg,
        db: pool,
        chain,
        contract: cfg.contract_text(),
    };
    let mut report = Report::default();
    let done = run(&cx, &mut report).await;
    report.pending = db::pending_count(pool, cfg.chain_id, &cx.contract)
        .await
        .unwrap_or(-1);
    done.map(|()| report)
}

async fn run(cx: &Ctx<'_>, report: &mut Report) -> R<()> {
    // The newest receipt must still be on the contract. If it is not, this is a different or reset chain,
    // and anchoring on top of it would only add confusion.
    if let Some((height, epoch, block_hash)) =
        db::latest_receipt(cx.db, cx.cfg.chain_id, &cx.contract).await?
    {
        let on_chain = cx.chain.at(epoch as u64, height).await?;
        if on_chain.as_ref().map(|a| a.block_hash.as_str()) != Some(block_hash.as_str()) {
            let detail = json!({
                "receipt": { "epoch": epoch, "block_hash": block_hash },
                "on_chain": on_chain.map(|a| a.block_hash),
                "note": "a stored receipt names an anchor the contract does not hold: wrong CHAIN_ANCHOR_CONTRACT or CHAIN_RPC_URL, or the chain was reset",
            });
            return cx
                .incident(report, "receipt_not_on_chain", height, detail)
                .await;
        }
    }

    loop {
        let batch = db::pending_blocks(cx.db, cx.cfg.chain_id, &cx.contract, cx.cfg.batch).await?;
        if batch.is_empty() {
            return Ok(());
        }

        // 1. Check each block as the backend would. Nothing that fails is ever sent.
        let key_ids: Vec<_> = batch.iter().map(|b| b.key_id).collect();
        let keys = db::keys(cx.db, &key_ids).await?;
        let mut prev = match batch[0].height {
            1 => Some(ledger::GENESIS.to_string()),
            h => db::block_hash_at(cx.db, h - 1).await?,
        };
        let mut expected_height = batch[0].height;
        let mut good: Vec<&Block> = vec![];
        let mut invalid: Option<(&Block, String)> = None;
        for b in &batch {
            let link = if b.height == expected_height {
                prev.as_deref()
            } else {
                None
            };
            match ledger::check(b, link, keys.get(&b.key_id)) {
                Ok(()) => good.push(b),
                Err(why) => {
                    invalid = Some((b, why));
                    break;
                }
            }
            prev = Some(b.block_hash.clone());
            expected_height = b.height + 1;
        }

        // 2. Blocks the contract already holds only need their receipt.
        let mut to_send: Vec<Block> = vec![];
        for (i, b) in good.iter().enumerate() {
            match cx.chain.current(b.height).await? {
                Some(a) if a.is(b) => {
                    let tx = cx.chain.anchoring_tx(&a, b.height).await?;
                    if cx.record(b, &a, format!("{tx:#x}")).await? {
                        tracing::info!(
                            height = b.height,
                            epoch = a.epoch,
                            "block was already anchored; receipt written"
                        );
                        report.recorded.push(b.height);
                    }
                }
                Some(a) => {
                    return cx
                        .incident(report, "anchor_mismatch", b.height, mismatch_detail(b, &a))
                        .await;
                }
                None => {
                    to_send = good[i..].iter().map(|b| (*b).clone()).collect();
                    break;
                }
            }
        }

        // 3. Anchor the rest in one transaction.
        if !to_send.is_empty() {
            let (_, next) = cx.chain.state().await?;
            let first = to_send[0].height;
            if first as u64 != next {
                let detail = json!({
                    "contract_next_height": next,
                    "first_unanchored_block": first,
                    "note": "the contract expects a different height than the first block without a receipt; the database and the contract do not describe the same ledger",
                });
                return cx.incident(report, "height_gap", first, detail).await;
            }
            let tx = match cx.chain.send(&to_send).await? {
                Sent::Tx(tx) => tx,
                Sent::FeeTooHigh { wanted_wei } => {
                    let msg = format!(
                        "the network fee ({} gwei) is above CHAIN_MAX_FEE_GWEI; nothing was sent, will retry",
                        wanted_wei / 1_000_000_000
                    );
                    tracing::warn!("{msg}");
                    report.waiting = Some(msg);
                    return Ok(());
                }
            };
            tracing::info!(first, count = to_send.len(), tx = %format!("{tx:#x}"), "anchoring transaction sent");
            if !cx.chain.confirmed(tx).await? {
                let msg = format!("transaction {tx:#x} is not confirmed yet; will look again");
                tracing::warn!("{msg}");
                report.waiting = Some(msg);
                return Ok(());
            }
            // Read the contract again and write receipts only for what it really holds now.
            for b in &to_send {
                match cx.chain.current(b.height).await? {
                    Some(a) if a.is(b) => {
                        cx.record(b, &a, format!("{tx:#x}")).await?;
                        tracing::info!(
                            height = b.height,
                            epoch = a.epoch,
                            chain_block = a.block_number,
                            "block anchored"
                        );
                        report.anchored.push(b.height);
                    }
                    Some(a) => {
                        return cx
                            .incident(report, "anchor_mismatch", b.height, mismatch_detail(b, &a))
                            .await;
                    }
                    None => {
                        let msg = format!(
                            "block {} is not on the contract after confirmation; will look again",
                            b.height
                        );
                        tracing::warn!("{msg}");
                        report.waiting = Some(msg);
                        return Ok(());
                    }
                }
            }
        }

        if let Some((b, why)) = invalid {
            let detail = json!({ "reason": why, "block_hash": b.block_hash, "note": "the block does not pass the ledger's own checks, so it was not anchored" });
            return cx.incident(report, "block_invalid", b.height, detail).await;
        }
    }
}
