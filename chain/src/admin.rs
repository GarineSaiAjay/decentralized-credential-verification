//! Commands for the issuer admin key, which is kept offline (for example on a pen drive) and plugged in
//! only for the few minutes these take. The worker never runs any of this and never sees that key.
//!
//!   admin-init FILE                     create the admin key straight into an encrypted keystore file
//!   admin-check FILE [FILE...]          open each copy and confirm they hold the same key
//!   admin-sign --keystore FILE --plan FILE [--yes]
//!                                       show a plan in plain words, then sign and send it
//!
//! The passphrase is typed at a prompt (or read from standard input when that is not a terminal). It is
//! never taken from the command line or the environment, so it does not end up in a shell history or a
//! process list.

use std::{
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

use alloy::{primitives::Address, signers::local::PrivateKeySigner};

use crate::{
    config::{Net, R},
    evm::{self, Client, Ledger, Registry, Sent},
    plan::{stage_index, Action, Plan},
};

const MIN_PASSPHRASE: usize = 20;

fn read_line() -> R<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read standard input: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Asks for the passphrase without showing it. From a pipe, reads one line instead.
fn passphrase(prompt: &str) -> R<String> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).map_err(|e| format!("cannot read the passphrase: {e}"))
    } else {
        read_line()
    }
}

fn confirm(question: &str) -> R<bool> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    Ok(matches!(read_line()?.trim(), "y" | "Y" | "yes"))
}

/// True if the path lies inside a git repository. A key must never be created where it could be committed.
fn inside_repository(path: &Path) -> bool {
    let start = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Ok(start) = start.canonicalize() else {
        return false;
    };
    start.ancestors().any(|dir| dir.join(".git").exists())
}

pub fn init(file: &str) -> R<()> {
    let path = Path::new(file);
    if path.exists() {
        return Err(format!(
            "{file} already exists; refusing to overwrite a key"
        ));
    }
    let (dir, name) = match (path.parent(), path.file_name().and_then(|n| n.to_str())) {
        (Some(d), Some(n)) => (
            if d.as_os_str().is_empty() {
                Path::new(".")
            } else {
                d
            },
            n,
        ),
        _ => return Err(format!("{file} is not a usable file path")),
    };
    if !dir.is_dir() {
        return Err(format!(
            "{} is not a folder (is the drive plugged in?)",
            dir.display()
        ));
    }
    if inside_repository(path) {
        return Err(format!(
            "{file} is inside a git repository. Create the admin key on the pen drive, never in a project folder"
        ));
    }
    let first = passphrase("New passphrase for the admin key (at least six random words): ")?;
    if first.chars().count() < MIN_PASSPHRASE {
        return Err(format!("the passphrase must be at least {MIN_PASSPHRASE} characters; six random words are easy to type and hard to guess"));
    }
    if std::io::stdin().is_terminal() && passphrase("The same passphrase again: ")? != first {
        return Err("the two passphrases differ; nothing was written".into());
    }
    let (signer, _) =
        PrivateKeySigner::new_keystore(dir, &mut rand::rngs::OsRng, &first, Some(name))
            .map_err(|e| format!("cannot write the keystore: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    println!("{:#x}", signer.address());
    eprintln!("wrote {file}. This address is the ISSUER ADMIN.");
    eprintln!("Next: copy the file to a second drive kept somewhere else (or print it), then run");
    eprintln!("  acvs-chain admin-check {file} <the copy>");
    eprintln!("A lost admin key cannot be recovered, and the passphrase is not stored anywhere.");
    Ok(())
}

pub fn check(files: &[String]) -> R<()> {
    if files.is_empty() {
        return Err("name at least one keystore file".into());
    }
    let pass = passphrase("Passphrase of the admin key: ")?;
    let mut first: Option<Address> = None;
    for f in files {
        let address = evm::open_keystore(Path::new(f), &pass)?.address();
        println!("{address:#x}  {f}");
        match first {
            None => first = Some(address),
            Some(a) if a != address => {
                return Err(format!("{f} holds a different key than {}", files[0]));
            }
            Some(_) => {}
        }
    }
    eprintln!(
        "{}",
        if files.len() > 1 {
            "every copy opens and holds the same key"
        } else {
            "the keystore opens"
        }
    );
    Ok(())
}

pub struct SignArgs {
    pub keystore: PathBuf,
    pub plan: PathBuf,
    pub yes: bool,
}

pub fn parse_sign_args(args: &[String]) -> R<SignArgs> {
    let (mut keystore, mut plan, mut yes) = (None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--keystore" => keystore = it.next().map(PathBuf::from),
            "--plan" => plan = it.next().map(PathBuf::from),
            "--yes" => yes = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    match (keystore, plan) {
        (Some(keystore), Some(plan)) => Ok(SignArgs {
            keystore,
            plan,
            yes,
        }),
        _ => Err("usage: acvs-chain admin-sign --keystore FILE --plan FILE [--yes]".into()),
    }
}

fn address(text: &str, what: &str) -> R<Address> {
    text.parse::<Address>()
        .ok()
        .filter(|a| *a != Address::ZERO)
        .ok_or_else(|| format!("the plan's {what} '{text}' is not an address"))
}

/// What one action needs from the contracts, given what they hold now: `Ok(None)` means it is already done.
async fn requests(
    action: &Action,
    ledger: &Ledger,
    registry: Option<&Registry>,
) -> R<Option<Vec<alloy::rpc::types::TransactionRequest>>> {
    let need_registry = || {
        registry.ok_or_else(|| "this plan names no registry, but the action needs one".to_string())
    };
    Ok(Some(match action {
        Action::AddKey { key, stage } => {
            let r = need_registry()?;
            let stage = stage_index(stage).ok_or_else(|| format!("unknown stage '{stage}'"))?;
            match r.key(key).await?.0 {
                0 => vec![r.add_key_request(key, stage)?],
                _ => return Ok(None),
            }
        }
        Action::RetireKey { key } => {
            let r = need_registry()?;
            match r.key(key).await?.0 {
                1 => vec![r.retire_key_request(key)?],
                0 => {
                    return Err(format!(
                        "key {key} is not in the registry, so it cannot be retired"
                    ))
                }
                _ => return Ok(None),
            }
        }
        Action::RevokeKey { key, reason } => {
            let r = need_registry()?;
            match r.key(key).await?.0 {
                1 | 2 => vec![r.revoke_key_request(key, reason)?],
                0 => {
                    return Err(format!(
                        "key {key} is not in the registry, so it cannot be revoked"
                    ))
                }
                _ => return Ok(None),
            }
        }
        Action::SetLedger { ledger: to } => {
            let r = need_registry()?;
            let to = address(to, "ledger")?;
            if r.issuer().await?.ledger == to {
                return Ok(None);
            }
            vec![r.set_ledger_request(to)]
        }
        Action::SetAnchorer { anchorer } => {
            let to = address(anchorer, "anchorer")?;
            if ledger.anchorer().await? == to {
                return Ok(None);
            }
            vec![ledger.set_anchorer_request(to)]
        }
        Action::StartEpoch {
            from_height,
            reason,
        } => vec![ledger.start_epoch_request(*from_height, reason)],
        Action::TransferAdmin { to } => {
            let to = address(to, "new admin")?;
            let mut txs = vec![];
            if ledger.pending_owner().await? != to {
                txs.push(ledger.transfer_ownership_request(to));
            }
            if let Some(r) = registry {
                if r.issuer().await?.pending_admin != to {
                    txs.push(r.transfer_admin_request(to));
                }
            }
            if txs.is_empty() {
                return Ok(None);
            }
            txs
        }
        Action::AcceptAdmin => {
            let me = ledger.client.signer;
            let mut txs = vec![];
            if ledger.pending_owner().await? == me {
                txs.push(ledger.accept_ownership_request());
            }
            if let Some(r) = registry {
                if r.issuer().await?.pending_admin == me {
                    txs.push(r.accept_admin_request());
                }
            }
            if txs.is_empty() {
                // "Already done" only if this key holds the role and no offer to anyone is open. Otherwise
                // the role is on its way to a different key, and this one has nothing to accept.
                if ledger.owner().await? == me && ledger.pending_owner().await? == Address::ZERO {
                    return Ok(None);
                }
                return Err("no admin role has been offered to this key".into());
            }
            txs
        }
        Action::AcceptRegistryOwnership => {
            let r = need_registry()?;
            let me = r.client.signer;
            if r.owner().await? == me {
                return Ok(None);
            }
            if r.pending_owner().await? != me {
                return Err("ownership of the registry has not been offered to this key".into());
            }
            vec![r.accept_ownership_request()]
        }
    }))
}

pub async fn sign(args: SignArgs) -> R<()> {
    let text = std::fs::read_to_string(&args.plan)
        .map_err(|e| format!("cannot read the plan {}: {e}", args.plan.display()))?;
    let plan: Plan = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a plan: {e}", args.plan.display()))?;
    let net = Net::from_env()?;
    if plan.chain_id != net.chain_id {
        return Err(format!(
            "the plan is for chain {}, but CHAIN_ID is {}",
            plan.chain_id, net.chain_id
        ));
    }
    if plan.actions.is_empty() {
        eprintln!("the plan holds nothing to sign");
        return Ok(());
    }

    eprintln!(
        "Plan for chain {} (node {}):",
        plan.chain_id,
        net.rpc_host()
    );
    eprintln!("  ledger contract   {}", plan.ledger);
    if let (Some(r), Some(i)) = (&plan.registry, plan.issuer_id) {
        eprintln!("  issuer registry   {r} (issuer {i})");
    }
    for (n, a) in plan.actions.iter().enumerate() {
        eprintln!("  {}. {}", n + 1, a.describe());
    }
    for w in &plan.warnings {
        eprintln!("  note: {w}");
    }

    let pass = passphrase("Passphrase of the admin key: ")?;
    let signer = evm::open_keystore(&args.keystore, &pass)?;
    drop(pass);
    eprintln!("Signing as {:#x}", signer.address());

    let client = Client::new(&net, signer)?;
    client.check_network().await?;
    let ledger = Ledger::new(client.clone(), address(&plan.ledger, "ledger")?);
    ledger.anchorer().await?; // there must be a LedgerAnchor there
    let registry = match (&plan.registry, plan.issuer_id) {
        (Some(r), Some(i)) => {
            let r = Registry::new(client.clone(), address(r, "registry")?, i);
            // The issuer must be listed; say who it is, so a plan for the wrong entry is noticed.
            let info = r.issuer().await?;
            eprintln!(
                "Registry entry: {} (its admin is {:#x})",
                info.name, info.admin
            );
            Some(r)
        }
        _ => None,
    };

    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err("not run from a terminal: add --yes to sign without the question".into());
        }
        if !confirm(&format!(
            "Sign and send these {} change(s)?",
            plan.actions.len()
        ))? {
            eprintln!("nothing was signed");
            return Ok(());
        }
    }

    for (n, action) in plan.actions.iter().enumerate() {
        let label = format!("{}. {}", n + 1, action.describe());
        let Some(txs) = requests(action, &ledger, registry.as_ref()).await? else {
            eprintln!("{label}\n   already done");
            continue;
        };
        for tx in txs {
            let hash = match client
                .submit(tx)
                .await
                .map_err(|e| format!("{label}\n   {}", explain(&e)))?
            {
                Sent::Tx(hash) => hash,
                Sent::FeeTooHigh { wanted_wei } => {
                    return Err(format!(
                        "the network fee ({} gwei) is above CHAIN_MAX_FEE_GWEI; stopped before: {label}",
                        wanted_wei / 1_000_000_000
                    ));
                }
            };
            if client.confirmed(hash).await?.is_none() {
                return Err(format!(
                    "transaction {hash:#x} was not confirmed within {}s; run the same command again later (finished steps are skipped)",
                    client.timeout().as_secs()
                ));
            }
            eprintln!("{label}\n   done in transaction {hash:#x}");
        }
    }
    eprintln!("All done. Unplug the drive.");
    Ok(())
}

/// Turns the commonest refusals into something a person can act on.
fn explain(error: &str) -> String {
    // Selectors of OwnableUnauthorizedAccount(address) and NotIssuerAdmin(uint64).
    if error.contains("0x118cdaa7")
        || error.contains("OwnableUnauthorizedAccount")
        || error.contains("0x108800bd")
    {
        return format!("this key is not the issuer admin for that contract ({error})");
    }
    if error.contains("insufficient funds") {
        return "the admin address has no funds to pay for the transaction; send it a little of the network's currency".into();
    }
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_arguments_are_read() {
        let a: Vec<String> = [
            "--plan",
            "p.json",
            "--keystore",
            "/Volumes/X/k.json",
            "--yes",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let s = parse_sign_args(&a).unwrap();
        assert_eq!(
            (s.plan.to_str(), s.keystore.to_str(), s.yes),
            (Some("p.json"), Some("/Volumes/X/k.json"), true)
        );
        assert!(parse_sign_args(&a[..2]).is_err());
        assert!(
            parse_sign_args(&["--passphrase".to_string(), "x".to_string()]).is_err(),
            "a passphrase is never an argument"
        );
    }

    #[test]
    fn a_key_is_never_created_inside_a_repository() {
        // This crate's own folder is inside the project's repository.
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(inside_repository(&here.join("admin-keystore.json")));
        assert!(inside_repository(&here.join("src").join("k.json")));
        assert!(!inside_repository(&std::env::temp_dir().join("k.json")));
    }
}
