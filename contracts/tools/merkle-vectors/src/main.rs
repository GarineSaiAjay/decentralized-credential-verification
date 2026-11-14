//! Prints Merkle test vectors as JSON, computed by the backend's `crypto::merkle`.
//! Usage (from contracts/): cargo run --manifest-path tools/merkle-vectors/Cargo.toml > test/vectors/merkle.json

// Only the Merkle functions of crypto.rs are used here.
#[allow(dead_code)]
#[path = "../../../../backend/src/crypto.rs"]
mod crypto;

use crypto::merkle;
use serde_json::{json, Value};

/// Tree sizes that cover every shape: a single leaf, full trees, and odd sizes at one or several levels.
const SIZES: [usize; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 16, 17, 31, 33];

fn hex0x(h: &str) -> String {
    format!("0x{h}")
}

fn main() {
    let mut cases: Vec<Value> = vec![];
    for n in SIZES {
        let leaves: Vec<String> = (0..n)
            .map(|i| crypto::sha256_hex(format!("acvs-vector-{n}-{i}").as_bytes()))
            .collect();
        let root = merkle::root(&leaves).expect("non-empty tree");
        let proofs: Vec<Value> = (0..n)
            .map(|i| {
                let steps = merkle::proof(&leaves, i).expect("index in range");
                assert!(merkle::verify(&leaves[i], &steps, &root));
                json!({
                    "depth": steps.len(),
                    "siblings": steps.iter().map(|s| hex0x(&s.hash)).collect::<Vec<_>>(),
                    "left": steps.iter().map(|s| s.left).collect::<Vec<_>>(),
                })
            })
            .collect();
        cases.push(json!({
            "n": n,
            "leaves": leaves.iter().map(|l| hex0x(l)).collect::<Vec<_>>(),
            "root": hex0x(&root),
            "proofs": proofs,
        }));
    }
    let doc = json!({
        "source": "backend/src/crypto.rs (crypto::merkle), via contracts/tools/merkle-vectors",
        "count": cases.len(),
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
}
