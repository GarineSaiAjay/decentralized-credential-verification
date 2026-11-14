//! Read-only view of the optional on-chain anchoring.
//!
//! A separate worker (`acvs-chain`, in `chain/`) writes each sealed block's hash to a public smart contract
//! and leaves a receipt in `chain_anchors`. This module only reads those receipts and shows them next to the
//! ledger. The backend never talks to a chain, holds no chain key and never writes these tables.
//!
//! Everything here is off unless `CHAIN_ID` and `CHAIN_ANCHOR_CONTRACT` are set; responses then carry no
//! on-chain fields at all, exactly as before this module existed. A receipt never changes a credential's
//! verdict. A receipt that names a different hash than the block it belongs to is reported as a mismatch
//! and fails the public ledger check, as a mismatching outside timestamp does.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool};

use crate::{
    config::OnchainConfig,
    error::{AppError, Res},
    AppState,
};

#[derive(FromRow, Clone)]
pub struct Receipt {
    pub block_height: i64,
    pub block_hash: String,
    pub merkle_root: String,
    pub leaf_count: i32,
    pub epoch: i64,
    pub tx_hash: String,
    pub chain_block: i64,
    pub anchored_at: DateTime<Utc>,
}

/// An open finding of the worker: kind, block height, when it was recorded, and its explanation.
type Incident = (String, Option<i64>, DateTime<Utc>, Option<String>);

const COLS: &str =
    "block_height, block_hash, merkle_root, leaf_count, epoch, tx_hash, chain_block, anchored_at";

/// `none`: no receipt yet. `ok`: the receipt is about this very block. `mismatch`: it names something else.
pub fn status(receipt: Option<&Receipt>, block_hash: &str, merkle_root: &str) -> &'static str {
    match receipt {
        None => "none",
        Some(r) if r.block_hash == block_hash && r.merkle_root == merkle_root => "ok",
        Some(_) => "mismatch",
    }
}

/// Receipts for the given heights on the configured chain and contract.
pub async fn receipts(
    db: &PgPool,
    cfg: &OnchainConfig,
    heights: &[i64],
) -> Res<HashMap<i64, Receipt>> {
    let rows: Vec<Receipt> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM chain_anchors WHERE chain_id = $1 AND contract = $2 AND block_height = ANY($3)"
    ))
    .bind(cfg.chain_id)
    .bind(&cfg.contract)
    .bind(heights)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.block_height, r)).collect())
}

/// What is shown for one block: the status and, if there is a receipt, where to find the anchor.
pub fn view(
    cfg: &OnchainConfig,
    receipt: Option<&Receipt>,
    block_hash: &str,
    merkle_root: &str,
) -> Value {
    let status = status(receipt, block_hash, merkle_root);
    match receipt {
        None => json!({ "status": status }),
        Some(r) => json!({
            "status": status,
            "chain_id": cfg.chain_id,
            "contract": cfg.contract,
            "epoch": r.epoch,
            "tx_hash": r.tx_hash,
            "chain_block": r.chain_block,
            "anchored_at": r.anchored_at,
            "explorer_url": cfg.explorer.as_ref().map(|e| format!("{e}/tx/{}", r.tx_hash)),
        }),
    }
}

/// For the ledger page: which chain and contract, how many blocks still wait, and what the worker has
/// refused to act on. An incident counts as open until a receipt is written after it, because the worker
/// anchors nothing while one stands.
pub async fn overview(db: &PgPool, cfg: &OnchainConfig) -> Res<Value> {
    let (unanchored,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM blocks b WHERE NOT EXISTS
           (SELECT 1 FROM chain_anchors a WHERE a.block_height = b.height AND a.chain_id = $1 AND a.contract = $2)",
    )
    .bind(cfg.chain_id)
    .bind(&cfg.contract)
    .fetch_one(db)
    .await?;
    let incidents: Vec<Incident> = sqlx::query_as(
        "SELECT i.kind, i.block_height, i.created_at, i.detail->>'note' FROM chain_incidents i
         WHERE i.chain_id = $1 AND i.contract = $2 AND NOT EXISTS
           (SELECT 1 FROM chain_anchors a
            WHERE a.chain_id = i.chain_id AND a.contract = i.contract AND a.created_at > i.created_at)
         ORDER BY i.id DESC LIMIT 20",
    )
    .bind(cfg.chain_id)
    .bind(&cfg.contract)
    .fetch_all(db)
    .await?;
    Ok(json!({
        "chain_id": cfg.chain_id,
        "contract": cfg.contract,
        "explorer_url": cfg.explorer.as_ref().map(|e| format!("{e}/address/{}", cfg.contract)),
        "unanchored": unanchored,
        "open_incidents": incidents.into_iter().map(|(kind, height, at, note)|
            json!({ "kind": kind, "height": height, "at": at, "note": note })).collect::<Vec<_>>(),
    }))
}

/// Numbers for the metrics endpoint: (blocks without a receipt, receipts that do not match their block,
/// open incidents).
pub async fn gauges(db: &PgPool, cfg: &OnchainConfig) -> Result<(i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM blocks b WHERE NOT EXISTS
              (SELECT 1 FROM chain_anchors a WHERE a.block_height = b.height AND a.chain_id = $1 AND a.contract = $2)),
           (SELECT count(*) FROM chain_anchors a JOIN blocks b ON b.height = a.block_height
              WHERE a.chain_id = $1 AND a.contract = $2
                AND (a.block_hash <> b.block_hash OR a.merkle_root <> b.merkle_root)),
           (SELECT count(*) FROM chain_incidents i WHERE i.chain_id = $1 AND i.contract = $2 AND NOT EXISTS
              (SELECT 1 FROM chain_anchors a
               WHERE a.chain_id = i.chain_id AND a.contract = i.contract AND a.created_at > i.created_at))",
    )
    .bind(cfg.chain_id)
    .bind(&cfg.contract)
    .fetch_one(db)
    .await
}

/// Public: the on-chain receipt of one block, with everything needed to look the anchor up independently
/// (chain, contract, epoch, transaction) and the values the contract must hold for it.
pub async fn show(State(st): State<AppState>, Path(height): Path<i64>) -> Res<Json<Value>> {
    let Some(cfg) = &st.cfg.onchain else {
        return Err(AppError::NotFound(
            "on-chain anchoring is not configured".into(),
        ));
    };
    let block: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT block_hash, merkle_root, jsonb_array_length(leaves)::bigint FROM blocks WHERE height = $1",
    )
    .bind(height)
    .fetch_optional(&st.db)
    .await?;
    let Some((block_hash, merkle_root, leaves)) = block else {
        return Err(AppError::NotFound("no such block".into()));
    };
    let found = receipts(&st.db, cfg, &[height]).await?;
    let Some(r) = found.get(&height) else {
        return Err(AppError::NotFound(
            "this block has not been anchored on-chain yet".into(),
        ));
    };
    let mut out = view(cfg, Some(r), &block_hash, &merkle_root);
    out["height"] = height.into();
    out["block"] =
        json!({ "block_hash": block_hash, "merkle_root": merkle_root, "leaf_count": leaves });
    out["anchored"] = json!({ "block_hash": r.block_hash, "merkle_root": r.merkle_root, "leaf_count": r.leaf_count });
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(hash: &str, root: &str) -> Receipt {
        Receipt {
            block_height: 1,
            block_hash: hash.into(),
            merkle_root: root.into(),
            leaf_count: 1,
            epoch: 1,
            tx_hash: "0xabc".into(),
            chain_block: 7,
            anchored_at: Utc::now(),
        }
    }

    #[test]
    fn status_compares_both_hash_and_root() {
        assert_eq!(status(None, "h", "r"), "none");
        assert_eq!(status(Some(&receipt("h", "r")), "h", "r"), "ok");
        assert_eq!(status(Some(&receipt("x", "r")), "h", "r"), "mismatch");
        assert_eq!(status(Some(&receipt("h", "x")), "h", "r"), "mismatch");
    }

    #[test]
    fn view_links_to_the_explorer_only_when_one_is_set() {
        let mut cfg = OnchainConfig {
            chain_id: 11155111,
            contract: "0xabc".into(),
            explorer: None,
        };
        let r = receipt("h", "r");
        assert_eq!(view(&cfg, None, "h", "r"), json!({ "status": "none" }));
        assert!(view(&cfg, Some(&r), "h", "r")["explorer_url"].is_null());
        cfg.explorer = Some("https://sepolia.etherscan.io".into());
        let v = view(&cfg, Some(&r), "h", "r");
        assert_eq!(v["explorer_url"], "https://sepolia.etherscan.io/tx/0xabc");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["chain_id"], 11155111);
    }
}
