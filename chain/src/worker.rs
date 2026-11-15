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
    evm::{Ledger, OnChain, Position, Registry, Sent},
    ledger::{self, Block},
    plan::{self, Action},
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
    /// Credentials whose revocation was published (or found already published) in this round.
    pub revoked: Vec<String>,
    /// Revoked credentials whose revocation is still not recorded as published.
    pub pending_revocations: i64,
    /// Signing-key changes that wait for the issuer admin's signature (when a registry is configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_changes_pending: Option<usize>,
}

impl Report {
    pub fn clean(&self) -> bool {
        self.incidents.is_empty()
    }
}

struct Ctx<'a> {
    cfg: &'a Config,
    db: &'a PgPool,
    chain: &'a Ledger,
    contract: String,
}

impl Ctx<'_> {
    async fn incident(&self, report: &mut Report, kind: &str, height: i64, detail: Value) -> R<()> {
        let new = db::incident(
            self.db,
            self.cfg.net.chain_id,
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
                chain_id: self.cfg.net.chain_id,
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

pub async fn tick(
    cfg: &Config,
    pool: &PgPool,
    chain: &Ledger,
    registry: Option<&Registry>,
) -> R<Report> {
    let cx = Ctx {
        cfg,
        db: pool,
        chain,
        contract: cfg.contract_text(),
    };
    let mut report = Report::default();
    let mut done = run(&cx, &mut report).await;
    // Revocations are published only while anchoring is in order: an incident means the database and the
    // contract may not describe the same ledger, and a revocation bit can never be taken back.
    if done.is_ok() && report.incidents.is_empty() {
        done = revocations(&cx, &mut report).await;
    }
    report.pending = db::pending_count(pool, cfg.net.chain_id, &cx.contract)
        .await
        .unwrap_or(-1);
    report.pending_revocations = db::pending_revocation_count(pool, cfg.net.chain_id, &cx.contract)
        .await
        .unwrap_or(-1);
    if let Some(registry) = registry {
        // Failing to read the registry must not fail the round: anchoring does not depend on it.
        match key_sync(&cx, registry).await {
            Ok(n) => report.key_changes_pending = Some(n),
            Err(error) => {
                tracing::warn!(%error, "could not compare the signing keys with the registry")
            }
        }
    }
    done.map(|()| report)
}

/// Reads the registry and works out which signing-key changes it still lacks. Nothing is sent: only the
/// issuer admin can make them. The result is written to chain_sync_state for the backend to show.
pub async fn key_plan(cfg: &Config, pool: &PgPool, registry: &Registry) -> R<plan::Plan> {
    let issuer = registry.issuer().await?;
    let keys = db::all_keys(pool).await?;
    let mut reg = plan::RegistryKeys::default();
    for k in &keys {
        reg.keys
            .insert(k.public_key.clone(), registry.key(&k.public_key).await?);
    }
    for stage in 0..4u8 {
        reg.active[stage as usize] = registry.active_key(stage).await?;
    }
    let (mut actions, mut warnings) = plan::key_actions(&keys, &reg);
    if issuer.ledger != cfg.anchor_contract {
        actions.insert(
            0,
            Action::SetLedger {
                ledger: format!("{:#x}", cfg.anchor_contract),
            },
        );
    }
    if issuer.suspended {
        warnings.push("the registry owner has suspended this issuer: verifiers will not accept its credentials".into());
    }
    Ok(plan::Plan {
        chain_id: cfg.net.chain_id,
        ledger: format!("{:#x}", cfg.anchor_contract),
        registry: Some(format!("{:#x}", registry.address)),
        issuer_id: Some(registry.issuer_id),
        actions,
        warnings,
    })
}

async fn key_sync(cx: &Ctx<'_>, registry: &Registry) -> R<usize> {
    let plan = key_plan(cx.cfg, cx.db, registry).await?;
    let detail = json!({
        "changes": plan.actions.iter().map(Action::describe).collect::<Vec<_>>(),
        "warnings": plan.warnings,
    });
    db::save_sync_state(
        cx.db,
        cx.cfg.net.chain_id,
        &cx.contract,
        plan.actions.len(),
        &detail,
    )
    .await?;
    if !plan.actions.is_empty() {
        tracing::warn!(
            pending = plan.actions.len(),
            "signing-key changes wait for the issuer admin (acvs-chain sync-keys)"
        );
    }
    Ok(plan.actions.len())
}

/// True if the signed revocation event verifies exactly as the backend requires: signed by the university
/// key, which has not itself been revoked, over this credential, reason and time.
fn revocation_is_genuine(r: &db::PendingRevocation) -> Result<(), String> {
    if r.stage != "university" {
        return Err(format!(
            "it is signed by the {} key, not the university key",
            r.stage
        ));
    }
    if r.key_status == "revoked" {
        return Err("the key that signed it has been revoked".into());
    }
    let message = crate::crypto::event_message(
        r.id,
        "revoked",
        &r.stage,
        &r.credential_hash,
        &r.reason,
        r.ts,
        r.legacy,
    );
    if !crate::crypto::verify(&r.public_key, &r.signature, &message) {
        return Err("its signature does not verify".into());
    }
    Ok(())
}

/// Publishes revocations: for each revoked credential in an anchored block, checks its signed event, then
/// either records that the bit is already set or sets it. One transaction covers all that are new.
async fn revocations(cx: &Ctx<'_>, report: &mut Report) -> R<()> {
    let chain_id = cx.cfg.net.chain_id;
    let rows = db::pending_revocations(cx.db, chain_id, &cx.contract, 50).await?;
    let mut to_send: Vec<(db::PendingRevocation, Position)> = vec![];
    for r in rows {
        if let Err(why) = revocation_is_genuine(&r) {
            let detail = json!({ "credential": r.id, "reason": why, "note": "the revocation recorded in the database does not verify, so it was not published. The credential shows as INVALID on the verification page until this is resolved." });
            let new = db::incident(
                cx.db,
                chain_id,
                &cx.contract,
                "revocation_invalid",
                Some(r.height),
                &detail,
            )
            .await?;
            if new {
                tracing::error!(credential = %r.id, why, "ON-CHAIN INCIDENT: a revocation was not published");
            }
            report.incidents.push(
                json!({ "kind": "revocation_invalid", "height": r.height, "detail": detail }),
            );
            continue;
        }
        let p = Position {
            epoch: r.epoch as u64,
            height: r.height as u64,
            leaf_index: r.leaf_index as u32,
        };
        if cx.chain.is_revoked(p).await? {
            // Set earlier (for example the worker stopped before writing the receipt): find where.
            let Some((tx, block)) = cx.chain.revocation_tx(p, r.anchor_block as u64).await? else {
                tracing::warn!(credential = %r.id, "the revocation bit is set but its event was not found; will look again");
                continue;
            };
            record_revocation(cx, &r, p, format!("{tx:#x}"), block).await?;
            tracing::info!(credential = %r.id, "revocation was already published; receipt written");
            report.revoked.push(r.id.to_string());
        } else {
            to_send.push((r, p));
        }
    }
    if to_send.is_empty() {
        return Ok(());
    }
    let positions: Vec<Position> = to_send.iter().map(|(_, p)| *p).collect();
    let tx = match cx
        .chain
        .client
        .submit(cx.chain.revoke_request(&positions))
        .await?
    {
        Sent::Tx(tx) => tx,
        Sent::FeeTooHigh { wanted_wei } => {
            let msg = format!(
                "the network fee ({} gwei) is above CHAIN_MAX_FEE_GWEI; no revocation was sent, will retry",
                wanted_wei / 1_000_000_000
            );
            tracing::warn!("{msg}");
            report.waiting = Some(msg);
            return Ok(());
        }
    };
    tracing::info!(count = to_send.len(), tx = %format!("{tx:#x}"), "revocation transaction sent");
    let Some(block) = cx.chain.client.confirmed(tx).await? else {
        let msg = format!("transaction {tx:#x} is not confirmed yet; will look again");
        tracing::warn!("{msg}");
        report.waiting = Some(msg);
        return Ok(());
    };
    for (r, p) in &to_send {
        if cx.chain.is_revoked(*p).await? {
            record_revocation(cx, r, *p, format!("{tx:#x}"), block).await?;
            tracing::info!(credential = %r.id, height = r.height, leaf = r.leaf_index, "revocation published");
            report.revoked.push(r.id.to_string());
        }
    }
    Ok(())
}

async fn record_revocation(
    cx: &Ctx<'_>,
    r: &db::PendingRevocation,
    p: Position,
    tx_hash: String,
    block: u64,
) -> R<()> {
    let at = cx.chain.client.block_time(block).await?;
    let revoked_at = DateTime::<Utc>::from_timestamp(at as i64, 0)
        .ok_or("the chain block has an impossible time")?;
    db::insert_revocation(
        cx.db,
        &db::RevocationReceipt {
            chain_id: cx.cfg.net.chain_id,
            contract: &cx.contract,
            credential_id: r.id,
            epoch: p.epoch,
            height: r.height,
            leaf_index: r.leaf_index,
            tx_hash,
            chain_block: block,
            revoked_at,
        },
    )
    .await?;
    Ok(())
}

async fn run(cx: &Ctx<'_>, report: &mut Report) -> R<()> {
    // The newest receipt must still be on the contract. If it is not, this is a different or reset chain,
    // and anchoring on top of it would only add confusion.
    if let Some((height, epoch, block_hash)) =
        db::latest_receipt(cx.db, cx.cfg.net.chain_id, &cx.contract).await?
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
        let batch =
            db::pending_blocks(cx.db, cx.cfg.net.chain_id, &cx.contract, cx.cfg.batch).await?;
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
            let tx = match cx
                .chain
                .client
                .submit(cx.chain.anchor_request(&to_send)?)
                .await?
            {
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
            if cx.chain.client.confirmed(tx).await?.is_none() {
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
