//! acvs-chain: the optional program that links the ACVS ledger to a public smart contract.
//!
//! It is separate from the backend on purpose. The backend never talks to a chain and never holds a chain
//! key; this program never signs a credential and cannot write the backend's tables.
//!
//! The worker (uses the anchorer key, a hot key that can only anchor and set revocation bits):
//!   acvs-chain run            anchor pending blocks and publish revocations, now and every CHAIN_INTERVAL_SECS
//!   acvs-chain once           one round, print a JSON report; exit 1 on an incident
//!   acvs-chain check          check the settings, key, network and contract, then exit
//!   acvs-chain keystore-new FILE   create the anchorer key as an encrypted keystore file, print its address
//!   acvs-chain address        print the address of the key in CHAIN_KEYSTORE_FILE
//!
//! Plans (need no key; they write down what only the issuer admin may do):
//!   acvs-chain sync-keys      compare ACVS's signing keys with the registry; print the changes as a plan
//!   acvs-chain plan start-epoch HEIGHT REASON | set-anchorer ADDRESS | transfer-admin ADDRESS
//!                           | accept-admin | accept-registry-ownership
//!
//! The issuer admin (an offline key, for example on a pen drive; see admin.rs):
//!   acvs-chain admin-init FILE
//!   acvs-chain admin-check FILE [FILE...]
//!   acvs-chain admin-sign --keystore FILE --plan FILE [--yes]

// The backend's own hashing, Merkle and signature code, compiled here unchanged.
#[allow(dead_code)]
#[path = "../../backend/src/crypto.rs"]
mod crypto;

mod admin;
mod config;
mod db;
mod evm;
mod ledger;
mod plan;
mod worker;

use std::{env, path::Path, process::ExitCode};

use alloy::signers::local::PrivateKeySigner;
use config::{Config, R};
use evm::{Client, Ledger, Registry};
use plan::{Action, Plan};

const USAGE: &str = "usage: acvs-chain [run | once | check | address | keystore-new FILE | sync-keys
                   | plan start-epoch HEIGHT REASON | plan set-anchorer ADDRESS | plan transfer-admin ADDRESS
                   | plan accept-admin | plan accept-registry-ownership
                   | admin-init FILE | admin-check FILE... | admin-sign --keystore FILE --plan FILE [--yes]]";

fn init_logging() {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if env::var("LOG_FORMAT").is_ok_and(|v| v == "json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Creates a new key straight into an encrypted keystore file. The key itself is never printed.
fn keystore_new(file: &str) -> R<()> {
    let passphrase = env::var("CHAIN_KEYSTORE_PASSPHRASE").unwrap_or_default();
    if passphrase.chars().count() < 16 {
        return Err("CHAIN_KEYSTORE_PASSPHRASE must be set and at least 16 characters".into());
    }
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
    let (signer, _) =
        PrivateKeySigner::new_keystore(dir, &mut rand::rngs::OsRng, &passphrase, Some(name))
            .map_err(|e| format!("cannot write the keystore: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    println!("{:#x}", signer.address());
    eprintln!("wrote {file}. This address is the ANCHORER: give it to the deployment, and send it a little gas money.");
    Ok(())
}

fn anchorer_key(cfg: &Config) -> R<PrivateKeySigner> {
    evm::open_keystore(&cfg.keystore_file, &cfg.keystore_passphrase)
        .map_err(|e| format!("{e} (the passphrase is CHAIN_KEYSTORE_PASSPHRASE)"))
}

/// A plan for something other than keys. Uses only the settings; nothing is read from the chain.
fn make_plan(args: &[String]) -> R<Plan> {
    let address = |text: &str| -> R<String> {
        config::parse_address("the address", text).map(|a| format!("{a:#x}"))
    };
    let action = match args {
        [kind, height, reason] if kind == "start-epoch" => Action::StartEpoch {
            from_height: height
                .parse::<u64>()
                .ok()
                .filter(|h| *h > 0)
                .ok_or("HEIGHT must be a block height (1 or more)")?,
            reason: Some(reason.trim().to_string())
                .filter(|r| !r.is_empty())
                .ok_or("a reason is required: it is recorded publicly")?,
        },
        [kind, to] if kind == "set-anchorer" => Action::SetAnchorer {
            anchorer: address(to)?,
        },
        [kind, to] if kind == "transfer-admin" => Action::TransferAdmin { to: address(to)? },
        [kind] if kind == "accept-admin" => Action::AcceptAdmin,
        [kind] if kind == "accept-registry-ownership" => Action::AcceptRegistryOwnership,
        _ => return Err(USAGE.into()),
    };
    let issuer = config::issuer_from_env()?;
    let chain_id = env::var("CHAIN_ID")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or("CHAIN_ID must be set")?;
    Ok(Plan {
        chain_id,
        ledger: format!("{:#x}", config::anchor_contract_from_env()?),
        registry: issuer.map(|i| format!("{:#x}", i.registry)),
        issuer_id: issuer.map(|i| i.issuer_id),
        actions: vec![action],
        warnings: vec![],
    })
}

fn print_plan(plan: &Plan) -> R<()> {
    if plan.actions.is_empty() {
        eprintln!("nothing waits for the issuer admin");
    } else {
        eprintln!(
            "{} change(s) for the issuer admin to sign (acvs-chain admin-sign):",
            plan.actions.len()
        );
        for (n, a) in plan.actions.iter().enumerate() {
            eprintln!("  {}. {}", n + 1, a.describe());
        }
    }
    for w in &plan.warnings {
        eprintln!("  note: {w}");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(plan).map_err(|e| e.to_string())?
    );
    Ok(())
}

async fn real_main() -> R<ExitCode> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map_or("run", String::as_str);
    let done = |r: R<()>| r.map(|()| ExitCode::SUCCESS);
    match (cmd, args.len()) {
        ("keystore-new", 2) => return done(keystore_new(&args[1])),
        ("admin-init", 2) => return done(admin::init(&args[1])),
        ("admin-check", n) if n >= 2 => return done(admin::check(&args[1..])),
        ("admin-sign", _) => return done(admin::sign(admin::parse_sign_args(&args[1..])?).await),
        ("plan", _) => return done(print_plan(&make_plan(&args[1..])?)),
        ("run" | "once" | "check" | "address" | "sync-keys", 0 | 1) => {}
        _ => return Err(USAGE.into()),
    }

    let cfg = Config::from_env()?;
    if cmd == "address" {
        println!("{:#x}", anchorer_key(&cfg)?.address());
        return Ok(ExitCode::SUCCESS);
    }
    if cmd == "sync-keys" {
        let issuer = cfg
            .issuer
            .ok_or("CHAIN_REGISTRY_CONTRACT and CHAIN_ISSUER_ID must be set to compare keys with the registry")?;
        let client = Client::read_only(&cfg.net)?;
        client.check_network().await?;
        let registry = Registry::new(client, issuer.registry, issuer.issuer_id);
        let pool = db::connect(&cfg.database_url).await?;
        return done(print_plan(&worker::key_plan(&cfg, &pool, &registry).await?));
    }

    // Refuse to run against the wrong network, a missing contract, or with a key that is not the anchorer.
    let client = Client::new(&cfg.net, anchorer_key(&cfg)?)?;
    client.check_network().await?;
    let ledger = Ledger::new(client.clone(), cfg.anchor_contract);
    let anchorer = ledger.anchorer().await?;
    if anchorer != client.signer {
        return Err(format!(
            "this worker's key is {:#x}, but the contract's anchorer is {anchorer:#x}; the issuer admin must call setAnchorer",
            client.signer
        ));
    }
    let registry = cfg
        .issuer
        .map(|i| Registry::new(client.clone(), i.registry, i.issuer_id));
    let pool = db::connect(&cfg.database_url).await?;
    let balance = client.balance_wei().await?;
    tracing::info!(
        chain_id = cfg.net.chain_id,
        rpc = %cfg.net.rpc_host(),
        contract = %cfg.contract_text(),
        anchorer = %format!("{:#x}", client.signer),
        balance_wei = %balance,
        confirmations = cfg.net.confirmations,
        registry = registry.is_some(),
        "on-chain anchoring is configured"
    );
    if balance.is_zero() {
        tracing::warn!("the anchorer address holds no funds, so it cannot pay for transactions");
    }
    if cmd == "check" {
        println!("ok");
        return Ok(ExitCode::SUCCESS);
    }

    let _lock = db::lock(&pool).await?;
    if cmd == "once" {
        let report = worker::tick(&cfg, &pool, &ledger, registry.as_ref()).await?;
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
        return Ok(if report.clean() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }

    let mut stop = shutdown_signal();
    loop {
        match worker::tick(&cfg, &pool, &ledger, registry.as_ref()).await {
            Ok(r) if !r.anchored.is_empty() || !r.recorded.is_empty() || !r.revoked.is_empty() => {
                tracing::info!(
                    anchored = r.anchored.len(),
                    recorded = r.recorded.len(),
                    revoked = r.revoked.len(),
                    pending = r.pending,
                    "round finished"
                )
            }
            Ok(_) => {}
            // The node or the database is unreachable: nothing is lost, the next round starts from the contract.
            Err(error) => tracing::warn!(%error, "round failed; will retry"),
        }
        tokio::select! {
            () = tokio::time::sleep(cfg.interval) => {}
            () = &mut stop => {
                tracing::info!("stopping");
                return Ok(ExitCode::SUCCESS);
            }
        }
    }
}

fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut term) = signal(SignalKind::terminate()) {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
                return;
            }
        }
        let _ = tokio::signal::ctrl_c().await;
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    match real_main().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("acvs-chain: {error}");
            ExitCode::from(2)
        }
    }
}
