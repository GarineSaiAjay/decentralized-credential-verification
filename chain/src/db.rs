//! Everything the worker does in PostgreSQL. It reads the ledger and inserts into its own three tables;
//! its database role is not granted anything else (scripts/chain-db-role.sh).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{pool::PoolConnection, postgres::PgPoolOptions, FromRow, PgPool, Postgres};
use uuid::Uuid;

use crate::{
    config::R,
    crypto,
    ledger::{Block, Key},
};

/// Advisory-lock key ("ACVSchn1"). Only one worker may hold it, which also keeps transaction nonces in order.
const LOCK_KEY: i64 = 0x4143_5653_6368_6e31;

fn e(err: sqlx::Error) -> String {
    format!("database: {err}")
}

pub async fn connect(url: &str) -> R<PgPool> {
    let db = PgPoolOptions::new()
        .max_connections(3)
        .connect(url)
        .await
        .map_err(e)?;
    let missing: Vec<String> = sqlx::query_scalar(
        "SELECT t FROM unnest(ARRAY['chain_anchors','chain_revocations','chain_incidents','blocks']) t
         WHERE to_regclass('public.' || t) IS NULL",
    )
    .fetch_all(&db)
    .await
    .map_err(e)?;
    if !missing.is_empty() {
        return Err(format!(
            "table(s) {} not found: start the backend once so it applies migration 0010, then run scripts/chain-db-role.sh",
            missing.join(", ")
        ));
    }
    Ok(db)
}

/// Holds the single-worker lock for as long as it lives (the lock belongs to this one connection).
pub struct WorkerLock(#[allow(dead_code)] PoolConnection<Postgres>);

pub async fn lock(db: &PgPool) -> R<WorkerLock> {
    let mut conn = db.acquire().await.map_err(e)?;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(LOCK_KEY)
        .fetch_one(&mut *conn)
        .await
        .map_err(e)?;
    if !got {
        return Err("another acvs-chain worker is already running against this database".into());
    }
    Ok(WorkerLock(conn))
}

#[derive(FromRow)]
struct BlockRow {
    height: i64,
    prev_hash: String,
    merkle_root: String,
    leaves: Value,
    ts: i64,
    block_hash: String,
    signature: String,
    key_id: Uuid,
}

/// Sealed blocks with no receipt for this chain and contract, lowest first.
pub async fn pending_blocks(
    db: &PgPool,
    chain_id: u64,
    contract: &str,
    limit: i64,
) -> R<Vec<Block>> {
    let rows: Vec<BlockRow> = sqlx::query_as(
        "SELECT b.height, b.prev_hash, b.merkle_root, b.leaves, b.ts, b.block_hash, b.signature, b.key_id
         FROM blocks b
         WHERE NOT EXISTS (SELECT 1 FROM chain_anchors a
                           WHERE a.block_height = b.height AND a.chain_id = $1 AND a.contract = $2)
         ORDER BY b.height LIMIT $3",
    )
    .bind(chain_id as i64)
    .bind(contract)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(e)?;
    Ok(rows
        .into_iter()
        .map(|r| Block {
            height: r.height,
            prev_hash: r.prev_hash,
            merkle_root: r.merkle_root,
            // A value that is not a list of strings becomes an empty block, which never verifies.
            leaves: serde_json::from_value(r.leaves).unwrap_or_default(),
            ts: r.ts,
            block_hash: r.block_hash,
            signature: r.signature,
            key_id: r.key_id,
        })
        .collect())
}

pub async fn pending_count(db: &PgPool, chain_id: u64, contract: &str) -> R<i64> {
    sqlx::query_scalar(
        "SELECT count(*) FROM blocks b
         WHERE NOT EXISTS (SELECT 1 FROM chain_anchors a
                           WHERE a.block_height = b.height AND a.chain_id = $1 AND a.contract = $2)",
    )
    .bind(chain_id as i64)
    .bind(contract)
    .fetch_one(db)
    .await
    .map_err(e)
}

pub async fn block_hash_at(db: &PgPool, height: i64) -> R<Option<String>> {
    sqlx::query_scalar("SELECT block_hash FROM blocks WHERE height = $1")
        .bind(height)
        .fetch_optional(db)
        .await
        .map_err(e)
}

/// Public halves and status only; the worker's role cannot read the encrypted private keys.
pub async fn keys(db: &PgPool, ids: &[Uuid]) -> R<HashMap<Uuid, Key>> {
    let rows: Vec<(Uuid, String, String, String)> =
        sqlx::query_as("SELECT id, role, public_key, status FROM signing_keys WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(db)
            .await
            .map_err(e)?;
    Ok(rows
        .into_iter()
        .map(|(id, role, public_key, status)| {
            (
                id,
                Key {
                    role,
                    public_key,
                    status,
                },
            )
        })
        .collect())
}

pub struct Receipt<'a> {
    pub chain_id: u64,
    pub contract: &'a str,
    pub height: i64,
    pub block_hash: &'a str,
    pub merkle_root: &'a str,
    pub leaf_count: u32,
    pub epoch: u64,
    pub tx_hash: String,
    pub chain_block: u64,
    pub anchored_at: DateTime<Utc>,
}

/// Returns true if the row was new.
pub async fn insert_receipt(db: &PgPool, r: &Receipt<'_>) -> R<bool> {
    let n = sqlx::query(
        "INSERT INTO chain_anchors
           (chain_id, contract, block_height, block_hash, merkle_root, leaf_count, epoch, tx_hash, chain_block, anchored_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
    )
    .bind(r.chain_id as i64)
    .bind(r.contract)
    .bind(r.height)
    .bind(r.block_hash)
    .bind(r.merkle_root)
    .bind(r.leaf_count as i32)
    .bind(r.epoch as i64)
    .bind(&r.tx_hash)
    .bind(r.chain_block as i64)
    .bind(r.anchored_at)
    .execute(db)
    .await
    .map_err(e)?
    .rows_affected();
    Ok(n == 1)
}

/// The newest receipt for this chain and contract: (height, epoch, block hash).
pub async fn latest_receipt(
    db: &PgPool,
    chain_id: u64,
    contract: &str,
) -> R<Option<(i64, i64, String)>> {
    sqlx::query_as(
        "SELECT block_height, epoch, block_hash FROM chain_anchors
         WHERE chain_id = $1 AND contract = $2 ORDER BY block_height DESC LIMIT 1",
    )
    .bind(chain_id as i64)
    .bind(contract)
    .fetch_optional(db)
    .await
    .map_err(e)
}

/// Records a finding once. Returns true the first time it is seen.
pub async fn incident(
    db: &PgPool,
    chain_id: u64,
    contract: &str,
    kind: &str,
    height: Option<i64>,
    detail: &Value,
) -> R<bool> {
    let fingerprint = crypto::canonical_hash(&serde_json::json!({
        "chain_id": chain_id, "contract": contract, "kind": kind, "height": height, "detail": detail,
    }));
    let n = sqlx::query(
        "INSERT INTO chain_incidents (chain_id, contract, kind, block_height, detail, fingerprint)
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (fingerprint) DO NOTHING",
    )
    .bind(chain_id as i64)
    .bind(contract)
    .bind(kind)
    .bind(height)
    .bind(detail)
    .bind(fingerprint)
    .execute(db)
    .await
    .map_err(e)?
    .rows_affected();
    Ok(n == 1)
}
