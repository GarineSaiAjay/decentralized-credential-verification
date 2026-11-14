//! acvs-chain: the optional worker that anchors sealed ledger blocks to a public smart contract.
//!
//! It is a separate program from the backend on purpose. The backend never talks to a chain and never
//! holds a chain key; this worker never signs a credential and cannot write the backend's tables.
//!
//!   acvs-chain run            anchor pending blocks now and every CHAIN_INTERVAL_SECS (default)
//!   acvs-chain once           one round, print a JSON report; exit 1 on an incident
//!   acvs-chain check          check the settings, key, network and contract, then exit
//!   acvs-chain keystore-new FILE   create the anchorer key as an encrypted keystore file, print its address
//!   acvs-chain address        print the address of the key in CHAIN_KEYSTORE_FILE

// The backend's own hashing, Merkle and signature code, compiled here unchanged.
#[allow(dead_code)]
#[path = "../../backend/src/crypto.rs"]
mod crypto;

mod config;
mod db;
mod evm;
mod ledger;
mod worker;

use std::{env, path::Path, process::ExitCode};

use alloy::signers::local::PrivateKeySigner;
use config::{Config, R};

const USAGE: &str = "usage: acvs-chain [run | once | check | address | keystore-new FILE]";

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

async fn start(cfg: &Config) -> R<(sqlx::PgPool, evm::Chain)> {
    let signer = evm::load_signer(cfg)?;
    let chain = evm::Chain::new(cfg, signer)?;
    chain.preflight().await?;
    let pool = db::connect(&cfg.database_url).await?;
    Ok((pool, chain))
}

async fn real_main() -> R<ExitCode> {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map_or("run", String::as_str);
    match (cmd, args.len()) {
        ("keystore-new", 2) => return keystore_new(&args[1]).map(|()| ExitCode::SUCCESS),
        ("run" | "once" | "check" | "address", 0 | 1) => {}
        _ => return Err(USAGE.into()),
    }

    let cfg = Config::from_env()?;
    if cmd == "address" {
        println!("{:#x}", evm::load_signer(&cfg)?.address());
        return Ok(ExitCode::SUCCESS);
    }

    let (pool, chain) = start(&cfg).await?;
    let balance = chain.balance_wei().await?;
    tracing::info!(
        chain_id = cfg.chain_id,
        rpc = %cfg.rpc_host(),
        contract = %cfg.contract_text(),
        anchorer = %format!("{:#x}", chain.signer),
        balance_wei = %balance,
        confirmations = cfg.confirmations,
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
        let report = worker::tick(&cfg, &pool, &chain).await?;
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
        match worker::tick(&cfg, &pool, &chain).await {
            Ok(r) if !r.anchored.is_empty() || !r.recorded.is_empty() => {
                tracing::info!(
                    anchored = r.anchored.len(),
                    recorded = r.recorded.len(),
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
