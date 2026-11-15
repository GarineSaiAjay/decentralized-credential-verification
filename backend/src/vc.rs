//! Export of an issued credential as a W3C Verifiable Credentials Data Model 2.0 document.
//!
//! The document has the shape other systems expect (`@context`, `type`, `issuer`, `validFrom`,
//! `credentialSubject`, `credentialStatus`, `proof`). The proofs are NOT W3C Data Integrity proofs: they are
//! this system's own Ed25519 stage signatures, carried with the exact message each one signed, so anyone can
//! check them with any Ed25519 library. A generic VC verifier will not understand them; the `credentialStatus`
//! URL gives the live verdict, including revocation.
//!
//! When on-chain anchoring is configured (see `onchain.rs`) and the credential's block has been anchored, the
//! document also carries an `evidence` entry: where the anchor is and the Merkle proof that leads to it. With
//! that, a verifier needs only the file and a public chain node, not this server.

use axum::{
    extract::{Path, State},
    http::header,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    audit,
    auth::AuthUser,
    config::OnchainConfig,
    credentials::{assess, fetch_approvals, ApprovalRow, CredRow},
    crypto,
    error::{AppError, Res},
    ledger::Anchor,
    AppState,
};

const PROOF_TYPE: &str = "AcvsEd25519Approval2026";

/// Builds the document. The student's own identifier is left out, as it is from the public verify page.
pub fn document(base: &str, c: &CredRow, approvals: &[ApprovalRow]) -> Value {
    let proofs: Vec<Value> = approvals
        .iter()
        .map(|a| {
            json!({
                "type": PROOF_TYPE,
                "created": a.signed_at,
                "proofPurpose": "assertionMethod",
                "verificationMethod": format!("urn:acvs:ed25519:{}", a.public_key),
                "stage": a.role,
                "signedMessage": String::from_utf8_lossy(&crypto::approval_message(c.id, &a.role, &c.credential_hash)),
                "proofValue": a.signature,
            })
        })
        .collect();
    let mut subject = json!({
        "type": "AcvsGraduate",
        "studentName": c.student_name,
        "program": c.program,
        "graduationDate": c.graduation_date,
    });
    if let Some(g) = &c.gpa {
        subject["gpa"] = g.clone().into();
    }
    if let Some(h) = &c.honors {
        subject["honors"] = h.clone().into();
    }
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", format!("{base}/api/v1/vc/context")],
        "id": format!("urn:uuid:{}", c.id),
        "type": ["VerifiableCredential", "AcvsAcademicCredential"],
        "issuer": base,
        "validFrom": approvals.last().map(|a| a.signed_at),
        "credentialSubject": subject,
        "credentialStatus": {
            "id": format!("{base}/api/v1/verify/{}", c.id),
            "type": "AcvsVerifyEndpoint",
        },
        "credentialHash": c.credential_hash,
        "proof": proofs,
    });
    if let Some(old) = c.supersedes {
        doc["supersedes"] = format!("urn:uuid:{old}").into();
    }
    doc
}

/// Where the credential's block is anchored on a public chain, and the Merkle proof from the credential's
/// hash to the anchored root. `None` unless the block has a receipt that matches it.
pub fn evidence(cfg: &OnchainConfig, anchor: &Anchor) -> Option<Value> {
    let receipt = anchor.onchain.as_ref()?;
    if !anchor.ok || receipt["status"] != "ok" {
        return None;
    }
    let mut e = json!({
        "type": "AcvsLedgerAnchor",
        "chainId": cfg.chain_id,
        "ledger": cfg.contract,
        "epoch": receipt["epoch"],
        "blockHeight": anchor.height,
        "leafIndex": anchor.leaf_index,
        "blockHash": anchor.block_hash,
        "merkleRoot": anchor.merkle_root,
        // Bottom-up sibling hashes. Which side each one is on follows from the leaf index and the block's
        // size, which is how the contract checks them.
        "merkleProof": anchor.proof.iter().map(|s| s.hash.clone()).collect::<Vec<_>>(),
        "transaction": receipt["tx_hash"],
        "anchoredAt": receipt["anchored_at"],
    });
    if let Some(i) = &cfg.issuer {
        e["registry"] = i.registry.clone().into();
        e["issuerId"] = i.issuer_id.into();
    }
    Some(e)
}

/// The document for a credential that verifies as VALID right now, with its on-chain evidence if there is any.
/// Anything else is refused: the file would otherwise present something pending, revoked or tampered with as
/// if it were an award.
async fn valid_document(st: &AppState, id: Uuid) -> Res<(CredRow, Value)> {
    let (c, a) = assess(st, id).await?;
    if a.verdict != "VALID" {
        return Err(AppError::Conflict(format!(
            "credential is {}; only a VALID credential can be exported",
            a.verdict
        )));
    }
    let approvals = fetch_approvals(&st.db, id).await?;
    let mut doc = document(&st.cfg.public_base_url, &c, &approvals);
    if let (Some(cfg), Some(anchor)) = (&st.cfg.onchain, &a.anchor) {
        if let Some(e) = evidence(cfg, anchor) {
            doc["evidence"] = json!([e]);
        }
    }
    Ok((c, doc))
}

fn download(doc: Value, filename: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/vc+ld+json"),
            (header::CONTENT_DISPOSITION, filename),
        ],
        Json(doc),
    )
}

pub async fn export(State(st): State<AppState>, Path(id): Path<Uuid>) -> Res<impl IntoResponse> {
    let (_, doc) = valid_document(&st, id).await?;
    Ok(download(doc, "attachment; filename=\"credential.json\""))
}

/// Signed-in staff only: the same document plus the student's identifier and the exact text the content hash
/// covers. With it, a verifier can recompute the hash and so prove every displayed field, not only that some
/// hash was signed. It is handed to the graduate, who decides whether to pass it on; it is never public,
/// and each download is written to the audit log.
pub async fn export_full(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Res<impl IntoResponse> {
    if st.cfg.onchain.is_none() {
        return Err(AppError::NotFound(
            "on-chain anchoring is not configured".into(),
        ));
    }
    // The same rule as the credential's own page: faculty only reach the credentials they created.
    crate::credentials::load(&st, &user, id).await?;
    let (c, mut doc) = valid_document(&st, id).await?;
    doc["credentialSubject"]["studentId"] = c.student_id.clone().into();
    doc["hashedContent"] = c.content().canonical().into();
    audit::actor_log(
        &st.db,
        &user,
        "CREDENTIAL_EXPORTED_FULL",
        "credential",
        &id.to_string(),
        json!({ "anchored": doc.get("evidence").is_some() }),
    )
    .await;
    Ok(download(
        doc,
        "attachment; filename=\"credential-full.json\"",
    ))
}

/// The JSON-LD context that defines the terms above.
pub async fn context(State(st): State<AppState>) -> impl IntoResponse {
    let ns = format!("{}/api/v1/vc/context#", st.cfg.public_base_url);
    let mut terms = json!({
        "@version": 1.1,
        "@protected": true,
        "acvs": ns,
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "AcvsAcademicCredential": "acvs:AcademicCredential",
        "AcvsGraduate": "acvs:Graduate",
        "AcvsVerifyEndpoint": "acvs:VerifyEndpoint",
        "AcvsEd25519Approval2026": "acvs:Ed25519Approval2026",
        "studentName": "acvs:studentName",
        "program": "acvs:program",
        "graduationDate": {"@id": "acvs:graduationDate", "@type": "xsd:date"},
        "gpa": "acvs:gpa",
        "honors": "acvs:honors",
        "credentialHash": "acvs:credentialHash",
        "supersedes": {"@id": "acvs:supersedes", "@type": "@id"},
        "stage": "acvs:stage",
        "signedMessage": "acvs:signedMessage"
    });
    // The terms of the on-chain evidence and the full export exist only where those do.
    if st.cfg.onchain.is_some() {
        for term in [
            "AcvsLedgerAnchor",
            "chainId",
            "ledger",
            "registry",
            "issuerId",
            "epoch",
            "blockHeight",
            "leafIndex",
            "blockHash",
            "merkleRoot",
            "merkleProof",
            "transaction",
            "anchoredAt",
            "studentId",
            "hashedContent",
        ] {
            terms[term] = format!("acvs:{term}").into();
        }
    }
    (
        [
            (header::CONTENT_TYPE, "application/ld+json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Json(json!({ "@context": terms })),
    )
}

/// `did:web` identifier for the site at `base`: the host, with a port's colon percent-encoded.
pub fn did_web(base: &str) -> String {
    let host = base
        .split_once("://")
        .map_or(base, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default();
    format!("did:web:{}", host.replace(':', "%3A"))
}

/// Bitcoin-alphabet base58, as multibase `z...` values use.
fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = vec![];
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in &mut digits {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|d| ALPHABET[*d as usize] as char));
    out
}

/// An Ed25519 public key as a Multikey value: multicodec prefix 0xed01, then the key, in base58btc.
pub fn multikey(public_hex: &str) -> Option<String> {
    let key = hex::decode(public_hex).ok().filter(|k| k.len() == 32)?;
    let mut bytes = vec![0xed, 0x01];
    bytes.extend(key);
    Some(format!("z{}", base58(&bytes)))
}

/// Public: this university's DID document (`did:web`), listing the signing keys whose signatures are still
/// trusted (active and retired; a revoked key is left out). It publishes the same keys an on-chain registry
/// entry does, so the two can be checked against each other.
pub async fn did_document(State(st): State<AppState>) -> Res<impl IntoResponse> {
    let did = did_web(&st.cfg.public_base_url);
    let keys: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT role, public_key, status FROM signing_keys WHERE status <> 'revoked' ORDER BY created_at, id",
    )
    .fetch_all(&st.db)
    .await?;
    let mut methods = vec![];
    let mut ids = vec![];
    for (role, public_key, status) in &keys {
        let Some(multibase) = multikey(public_key) else {
            continue;
        };
        let id = format!("{did}#{role}-{}", &public_key[..16]);
        methods.push(json!({
            "id": id, "type": "Multikey", "controller": did, "publicKeyMultibase": multibase,
            "acvsStage": role, "acvsStatus": status, "acvsPublicKeyHex": public_key,
        }));
        ids.push(id);
    }
    let mut services = vec![json!({
        "id": format!("{did}#verify"),
        "type": "AcvsVerification",
        "serviceEndpoint": format!("{}/api/v1/verify", st.cfg.public_base_url),
    })];
    if let Some(c) = &st.cfg.onchain {
        services.push(json!({
            "id": format!("{did}#ledger-anchor"),
            "type": "AcvsLedgerAnchor",
            // CAIP-10: the chain and the contract that holds this university's block anchors.
            "serviceEndpoint": format!("eip155:{}:{}", c.chain_id, c.contract),
        }));
        if let Some(i) = &c.issuer {
            services.push(json!({
                "id": format!("{did}#issuer-registry"),
                "type": "AcvsIssuerRegistry",
                "serviceEndpoint": format!("eip155:{}:{}#{}", c.chain_id, i.registry, i.issuer_id),
            }));
        }
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/did+json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        Json(json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": methods,
            "assertionMethod": ids,
            "service": services,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_follows_the_site_address() {
        assert_eq!(
            did_web("https://credentials.example.edu"),
            "did:web:credentials.example.edu"
        );
        assert_eq!(did_web("http://localhost:3000"), "did:web:localhost%3A3000");
        assert_eq!(did_web("https://a.test/some/path"), "did:web:a.test");
    }

    #[test]
    fn base58_matches_known_values() {
        assert_eq!(base58(b""), "");
        assert_eq!(base58(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58(&[0, 0, 1]), "112");
        assert_eq!(base58(&[0xff; 4]), "7YXq9G");
    }

    /// A widely published pair: the RFC 8032 test key and its did:key form.
    #[test]
    fn multikey_matches_the_published_example() {
        let hex = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
        assert_eq!(
            multikey(hex).as_deref(),
            Some("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        );
        assert_eq!(multikey("abcd"), None);
        assert_eq!(multikey("not hex"), None);
    }
}
