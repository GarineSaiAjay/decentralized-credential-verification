//! Checks a sealed block exactly as the backend does, before anything about it is sent to the chain.
//! An anchor can never be taken back, so a block that does not verify is never anchored.

use uuid::Uuid;

use crate::crypto::{self, merkle};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug)]
pub struct Block {
    pub height: i64,
    pub prev_hash: String,
    pub merkle_root: String,
    pub leaves: Vec<String>,
    pub ts: i64,
    pub block_hash: String,
    pub signature: String,
    pub key_id: Uuid,
}

/// The key a block names as its signer, as stored in `signing_keys`.
#[derive(Clone, Debug)]
pub struct Key {
    pub role: String,
    pub public_key: String,
    pub status: String,
}

/// Must stay identical to `ledger::block_hash` in the backend (a test below guards the format string).
pub fn block_hash(height: i64, prev: &str, root: &str, ts: i64, n: usize) -> String {
    crypto::sha256_hex(format!("ACVS-BLOCK-v1|{height}|{prev}|{root}|{ts}|{n}").as_bytes())
}

fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Everything the backend's chain check verifies about one block: its leaves, Merkle root, hash, link to the
/// previous block, and the university's signature by a key that has not been revoked.
/// `expected_prev` is the hash of the block below it (`GENESIS` for height 1), or `None` if that block is missing.
pub fn check(b: &Block, expected_prev: Option<&str>, key: Option<&Key>) -> Result<(), String> {
    if b.height < 1 {
        return Err(format!("height {} is not a valid block height", b.height));
    }
    if b.leaves.is_empty() {
        return Err("the block has no credentials".into());
    }
    if b.leaves.len() > u32::MAX as usize {
        return Err("the block has too many credentials".into());
    }
    if !b.leaves.iter().all(|l| is_hash(l)) {
        return Err("a leaf is not a SHA-256 hash".into());
    }
    if !is_hash(&b.block_hash) || !is_hash(&b.merkle_root) {
        return Err("the block hash or Merkle root is malformed".into());
    }
    if merkle::root(&b.leaves).as_deref() != Some(b.merkle_root.as_str()) {
        return Err("the Merkle root does not match the block's credentials".into());
    }
    if block_hash(b.height, &b.prev_hash, &b.merkle_root, b.ts, b.leaves.len()) != b.block_hash {
        return Err("the block hash does not match the block's contents".into());
    }
    match expected_prev {
        None => {
            return Err(format!(
                "block {} is missing, so the link cannot be checked",
                b.height - 1
            ))
        }
        Some(p) if p != b.prev_hash => {
            return Err("the block does not link to the block below it".into())
        }
        Some(_) => {}
    }
    let Some(key) = key else {
        return Err("the block's signing key is not in the database".into());
    };
    if key.role != "university" {
        return Err(format!(
            "the block is signed by a {} key, not the university key",
            key.role
        ));
    }
    if key.status == "revoked" {
        return Err("the block's signing key has been revoked".into());
    }
    if !crypto::verify(&key.public_key, &b.signature, b.block_hash.as_bytes()) {
        return Err("the university signature on the block is not valid".into());
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn leaves(n: usize, seed: &str) -> Vec<String> {
        (0..n)
            .map(|i| crypto::sha256_hex(format!("{seed}-{i}").as_bytes()))
            .collect()
    }

    /// A correctly sealed block and its key, built the way the backend seals one.
    pub fn sealed(height: i64, prev: &str, n: usize) -> (Block, Key) {
        let (seed, public_key) = crypto::new_keypair();
        let leaves = leaves(n, &format!("block-{height}"));
        let merkle_root = merkle::root(&leaves).unwrap();
        let ts = 1_800_000_000 + height;
        let hash = block_hash(height, prev, &merkle_root, ts, leaves.len());
        let block = Block {
            height,
            prev_hash: prev.into(),
            merkle_root,
            leaves,
            ts,
            signature: crypto::sign(&seed, hash.as_bytes()),
            block_hash: hash,
            key_id: Uuid::new_v4(),
        };
        (
            block,
            Key {
                role: "university".into(),
                public_key,
                status: "active".into(),
            },
        )
    }

    #[test]
    fn a_sealed_block_passes() {
        let (b, k) = sealed(1, GENESIS, 5);
        assert_eq!(check(&b, Some(GENESIS), Some(&k)), Ok(()));
        let (b2, k2) = sealed(2, &b.block_hash, 1);
        assert_eq!(check(&b2, Some(&b.block_hash), Some(&k2)), Ok(()));
        // A retired key is fine: it signed while it was the university key.
        let retired = Key {
            status: "retired".into(),
            ..k2.clone()
        };
        assert_eq!(check(&b2, Some(&b.block_hash), Some(&retired)), Ok(()));
    }

    #[test]
    fn every_kind_of_tampering_is_refused() {
        let (good, key) = sealed(3, &"ab".repeat(32), 4);
        let prev = "ab".repeat(32);
        let fails = |b: &Block, k: Option<&Key>, p: Option<&str>, what: &str| {
            let r = check(b, p, k);
            assert!(r.is_err(), "{what} was accepted");
        };

        let mut b = good.clone();
        b.leaves[2] = crypto::sha256_hex(b"swapped");
        fails(&b, Some(&key), Some(&prev), "a changed leaf");

        let mut b = good.clone();
        b.leaves.pop();
        fails(&b, Some(&key), Some(&prev), "a removed leaf");

        let mut b = good.clone();
        b.ts += 1;
        fails(&b, Some(&key), Some(&prev), "a changed time");

        let mut b = good.clone();
        b.height = 4;
        fails(&b, Some(&key), Some(&prev), "a changed height");

        let mut b = good.clone();
        b.merkle_root = crypto::sha256_hex(b"other");
        fails(&b, Some(&key), Some(&prev), "a changed root");

        let mut b = good.clone();
        b.signature = crypto::sign(&[7u8; 32], b.block_hash.as_bytes());
        fails(&b, Some(&key), Some(&prev), "a signature by another key");

        let mut b = good.clone();
        b.leaves.clear();
        fails(&b, Some(&key), Some(&prev), "an empty block");

        let mut b = good.clone();
        b.leaves[0] = "not-a-hash".into();
        fails(&b, Some(&key), Some(&prev), "a malformed leaf");

        fails(&good, Some(&key), Some(GENESIS), "a wrong link");
        fails(&good, Some(&key), None, "a missing previous block");
        fails(&good, None, Some(&prev), "an unknown key");
        let revoked = Key {
            status: "revoked".into(),
            ..key.clone()
        };
        fails(&good, Some(&revoked), Some(&prev), "a revoked key");
        let stage = Key {
            role: "registrar".into(),
            ..key.clone()
        };
        fails(&good, Some(&stage), Some(&prev), "a stage key");
    }

    /// A rewritten-and-re-signed block (new hash, valid signature) still fails if it no longer links.
    #[test]
    fn a_consistent_forgery_still_needs_the_link() {
        let (b1, _) = sealed(1, GENESIS, 2);
        let (forged, key) = sealed(2, &crypto::sha256_hex(b"some other history"), 2);
        assert!(check(&forged, Some(&b1.block_hash), Some(&key)).is_err());
    }

    /// The backend's own source must still contain the block-hash format this file copies.
    #[test]
    fn block_hash_format_matches_the_backend_source() {
        let backend = include_str!("../../backend/src/ledger.rs");
        assert!(
            backend.contains(r#"format!("ACVS-BLOCK-v1|{height}|{prev}|{root}|{ts}|{n}")"#),
            "backend/src/ledger.rs changed how a block is hashed; chain/src/ledger.rs must follow"
        );
        assert!(backend.contains(&format!("const GENESIS: &str = \"{GENESIS}\"")));
    }
}
