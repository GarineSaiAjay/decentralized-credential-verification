//! Plans: lists of changes that only the issuer admin key may make, written down so that the admin can
//! read them in plain words before signing.
//!
//! A plan is made without any key (`sync-keys`, `plan ...`), carried to wherever the admin's pen drive is
//! plugged in, and carried out there by `admin-sign`. Nothing in a plan is secret.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const STAGES: [&str; 4] = ["faculty", "exam_cell", "registrar", "university"];

pub fn stage_index(role: &str) -> Option<u8> {
    STAGES.iter().position(|s| *s == role).map(|i| i as u8)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Action {
    /// List a signing key in the registry as the active key of its stage.
    AddKey { key: String, stage: String },
    /// Mark a listed key as replaced. What it signed stays trusted.
    RetireKey { key: String },
    /// Mark a listed key as compromised. Nothing it signed is trusted any more. Cannot be undone.
    RevokeKey { key: String, reason: String },
    /// Point the registry entry at this university's ledger contract.
    SetLedger { ledger: String },
    /// Replace the worker's key on the ledger contract.
    SetAnchorer { anchorer: String },
    /// Continue anchoring from a height in a new epoch (after restoring an older backup).
    StartEpoch { from_height: u64, reason: String },
    /// Offer the admin role (ledger ownership and registry entry) to another key.
    TransferAdmin { to: String },
    /// Take up an admin role that was offered to this key.
    AcceptAdmin,
    /// Take up ownership of the registry itself, offered at deployment.
    AcceptRegistryOwnership,
}

fn short(key: &str) -> String {
    format!("{}…", &key[..key.len().min(16)])
}

impl Action {
    /// What the admin is about to sign, in plain words.
    pub fn describe(&self) -> String {
        match self {
            Action::AddKey { key, stage } => format!(
                "List signing key {} in the registry as the active {} key",
                short(key),
                stage.replace('_', " ")
            ),
            Action::RetireKey { key } => format!(
                "Mark signing key {} as replaced (what it signed stays trusted)",
                short(key)
            ),
            Action::RevokeKey { key, reason } => format!(
                "REVOKE signing key {} as compromised: nothing it signed will be trusted. This cannot be undone. Reason: {reason}",
                short(key)
            ),
            Action::SetLedger { ledger } => {
                format!("Point the registry entry at the ledger contract {ledger}")
            }
            Action::SetAnchorer { anchorer } => {
                format!("Make {anchorer} the worker's key (the previous one stops working at once)")
            }
            Action::StartEpoch { from_height, reason } => format!(
                "Start a new ledger epoch that anchors again from block {from_height}. Earlier anchors stay readable. Reason: {reason}"
            ),
            Action::TransferAdmin { to } => format!(
                "Offer the issuer admin role to {to} (it takes effect when that key accepts)"
            ),
            Action::AcceptAdmin => "Take up the issuer admin role offered to this key".into(),
            Action::AcceptRegistryOwnership => {
                "Take up ownership of the issuer registry offered to this key".into()
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Plan {
    pub chain_id: u64,
    pub ledger: String,
    pub registry: Option<String>,
    pub issuer_id: Option<u64>,
    pub actions: Vec<Action>,
    /// Things the planner noticed but cannot fix with a transaction. For a person to read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A signing key as ACVS has it.
#[derive(Clone, Debug)]
pub struct DbKey {
    pub public_key: String,
    pub role: String,
    pub status: String,
}

/// The registry's view, read before planning.
#[derive(Default, Debug)]
pub struct RegistryKeys {
    /// Status of each ACVS key in the registry: 0 never registered, 1 active, 2 retired, 3 revoked; and its stage.
    pub keys: HashMap<String, (u8, u8)>,
    /// The registry's active key per stage.
    pub active: [Option<String>; 4],
}

/// Works out which registry changes bring it in step with ACVS's signing keys.
///
/// `db` must be oldest first. The registry allows one active key per stage and a status only moves forward
/// (active, retired, revoked), so the order matters: an old key is retired before its successor is added.
pub fn key_actions(db: &[DbKey], reg: &RegistryKeys) -> (Vec<Action>, Vec<String>) {
    let (mut actions, mut warnings) = (vec![], vec![]);
    for (s, stage) in STAGES.iter().enumerate() {
        let mut active = reg.active[s].clone();
        let known: Vec<&str> = db.iter().map(|k| k.public_key.as_str()).collect();
        if let Some(a) = &active {
            if !known.contains(&a.as_str()) {
                warnings.push(format!(
                    "the registry's active {stage} key {} is not a key ACVS knows; it was left alone",
                    short(a)
                ));
            }
        }
        for k in db.iter().filter(|k| k.role == *stage) {
            let key = k.public_key.clone();
            let (status, on_stage) = reg.keys.get(&key).copied().unwrap_or((0, s as u8));
            if status != 0 && on_stage as usize != s {
                warnings.push(format!(
                    "key {} is a {stage} key in ACVS but listed for another stage in the registry",
                    short(&key)
                ));
                continue;
            }
            match (k.status.as_str(), status) {
                ("active", 1) | ("retired", 2) | ("revoked", 3) | ("revoked", 0) => {}
                ("revoked", 1 | 2) => {
                    if active.as_deref() == Some(&key) {
                        active = None;
                    }
                    actions.push(Action::RevokeKey { key, reason: "revoked by the issuer in ACVS".into() });
                }
                ("retired", 1) => {
                    active = None;
                    actions.push(Action::RetireKey { key });
                }
                ("retired", 0) => {
                    if active.is_some() {
                        warnings.push(format!(
                            "the replaced {stage} key {} was never listed and a later key already is; credentials it signed cannot be checked on-chain",
                            short(&key)
                        ));
                    } else {
                        actions.push(Action::AddKey { key: key.clone(), stage: stage.to_string() });
                        actions.push(Action::RetireKey { key });
                    }
                }
                ("active", 0) => {
                    if let Some(other) = &active {
                        warnings.push(format!(
                            "the {stage} key {} cannot be listed while the registry still has {} active for that stage",
                            short(&key),
                            short(other)
                        ));
                    } else {
                        active = Some(key.clone());
                        actions.push(Action::AddKey { key, stage: stage.to_string() });
                    }
                }
                ("active", 2 | 3) => warnings.push(format!(
                    "ACVS signs with the {stage} key {}, but the registry says it is {}; rotate that key in ACVS",
                    short(&key),
                    if status == 2 { "retired" } else { "revoked" }
                )),
                ("retired", 3) => warnings.push(format!(
                    "the registry says the {stage} key {} is revoked, ACVS only replaced it; revoke it in ACVS too if it was compromised",
                    short(&key)
                )),
                _ => {}
            }
        }
    }
    (actions, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8, role: &str, status: &str) -> DbKey {
        DbKey {
            public_key: format!("{n:02x}").repeat(32),
            role: role.into(),
            status: status.into(),
        }
    }
    fn k(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }
    fn reg(keys: &[(u8, u8, u8)], active: &[(usize, u8)]) -> RegistryKeys {
        let mut r = RegistryKeys::default();
        for (n, status, stage) in keys {
            r.keys.insert(k(*n), (*status, *stage));
        }
        for (stage, n) in active {
            r.active[*stage] = Some(k(*n));
        }
        r
    }
    fn add(n: u8, stage: &str) -> Action {
        Action::AddKey {
            key: k(n),
            stage: stage.into(),
        }
    }
    fn retire(n: u8) -> Action {
        Action::RetireKey { key: k(n) }
    }

    #[test]
    fn a_new_registry_gets_the_four_active_keys() {
        let db: Vec<DbKey> = STAGES
            .iter()
            .enumerate()
            .map(|(i, s)| key(i as u8 + 1, s, "active"))
            .collect();
        let (actions, warnings) = key_actions(&db, &RegistryKeys::default());
        assert_eq!(
            actions,
            vec![
                add(1, "faculty"),
                add(2, "exam_cell"),
                add(3, "registrar"),
                add(4, "university")
            ]
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn nothing_to_do_when_in_step() {
        let db = vec![
            key(1, "faculty", "retired"),
            key(2, "faculty", "active"),
            key(3, "registrar", "revoked"),
        ];
        let r = reg(&[(1, 2, 0), (2, 1, 0), (3, 3, 2)], &[(0, 2)]);
        assert_eq!(key_actions(&db, &r), (vec![], vec![]));
    }

    #[test]
    fn a_rotation_retires_the_old_key_before_adding_the_new_one() {
        let db = vec![
            key(1, "registrar", "retired"),
            key(2, "registrar", "active"),
        ];
        let r = reg(&[(1, 1, 2)], &[(2, 1)]);
        assert_eq!(key_actions(&db, &r).0, vec![retire(1), add(2, "registrar")]);
    }

    #[test]
    fn history_is_listed_in_order_on_a_first_sync() {
        // Two rotations happened before the registry existed.
        let db = vec![
            key(1, "university", "retired"),
            key(2, "university", "retired"),
            key(3, "university", "active"),
        ];
        let (actions, warnings) = key_actions(&db, &RegistryKeys::default());
        assert_eq!(
            actions,
            vec![
                add(1, "university"),
                retire(1),
                add(2, "university"),
                retire(2),
                add(3, "university")
            ]
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_compromised_key_is_revoked_whether_active_or_retired() {
        let db = vec![
            key(1, "exam_cell", "revoked"),
            key(2, "exam_cell", "revoked"),
            key(3, "exam_cell", "active"),
        ];
        let r = reg(&[(1, 2, 1), (2, 1, 1)], &[(1, 2)]);
        let (actions, _) = key_actions(&db, &r);
        assert!(matches!(&actions[0], Action::RevokeKey { key, .. } if *key == k(1)));
        assert!(matches!(&actions[1], Action::RevokeKey { key, .. } if *key == k(2)));
        // Revoking the active key frees the stage for its successor.
        assert_eq!(actions[2], add(3, "exam_cell"));
        assert_eq!(actions.len(), 3);
    }

    #[test]
    fn a_key_revoked_before_it_was_ever_listed_is_never_listed() {
        let db = vec![key(1, "faculty", "revoked"), key(2, "faculty", "active")];
        assert_eq!(
            key_actions(&db, &RegistryKeys::default()).0,
            vec![add(2, "faculty")]
        );
    }

    #[test]
    fn what_cannot_be_fixed_is_reported_not_forced() {
        // An old key was never listed and its successor already is.
        let db = vec![key(1, "faculty", "retired"), key(2, "faculty", "active")];
        let (actions, warnings) = key_actions(&db, &reg(&[(2, 1, 0)], &[(0, 2)]));
        assert!(actions.is_empty());
        assert!(warnings[0].contains("never listed"));

        // The registry has an active key ACVS does not know.
        let (actions, warnings) = key_actions(&[key(1, "faculty", "active")], &reg(&[], &[(0, 9)]));
        assert!(actions.is_empty());
        assert_eq!(warnings.len(), 2);

        // ACVS still signs with a key the registry has revoked or retired.
        for status in [2, 3] {
            let (actions, warnings) = key_actions(
                &[key(1, "registrar", "active")],
                &reg(&[(1, status, 2)], &[]),
            );
            assert!(actions.is_empty());
            assert!(warnings[0].contains("rotate that key"));
        }

        // A key listed under another stage is never touched.
        let (actions, warnings) = key_actions(
            &[key(1, "registrar", "active")],
            &reg(&[(1, 1, 0)], &[(0, 1)]),
        );
        assert!(actions.is_empty());
        assert!(warnings[0].contains("another stage"));
    }

    #[test]
    fn stages_do_not_affect_each_other() {
        let db = vec![
            key(1, "faculty", "active"),
            key(2, "university", "retired"),
            key(3, "university", "active"),
        ];
        let r = reg(&[(1, 1, 0), (2, 1, 3)], &[(0, 1), (3, 2)]);
        assert_eq!(
            key_actions(&db, &r).0,
            vec![retire(2), add(3, "university")]
        );
    }

    #[test]
    fn a_plan_survives_being_written_down() {
        let plan = Plan {
            chain_id: 11155111,
            ledger: "0xabc".into(),
            registry: Some("0xdef".into()),
            issuer_id: Some(1),
            actions: vec![
                add(1, "faculty"),
                retire(2),
                Action::RevokeKey {
                    key: k(3),
                    reason: "laptop stolen".into(),
                },
                Action::StartEpoch {
                    from_height: 8,
                    reason: "restored backup".into(),
                },
                Action::AcceptAdmin,
            ],
            warnings: vec![],
        };
        let text = serde_json::to_string(&plan).unwrap();
        assert!(
            text.contains(r#""action":"add-key""#) && text.contains(r#""action":"accept-admin""#)
        );
        assert_eq!(serde_json::from_str::<Plan>(&text).unwrap(), plan);
        for a in &plan.actions {
            assert!(!a.describe().is_empty());
        }
        assert!(plan.actions[2].describe().contains("cannot be undone"));
    }
}
