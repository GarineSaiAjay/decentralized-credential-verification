//! Settings, all from the environment. Nothing here is read by the backend.

use std::{env, path::PathBuf, time::Duration};

use alloy::primitives::Address;

pub type R<T> = Result<T, String>;

pub struct Config {
    /// Connection for the worker's own database role (see scripts/chain-db-role.sh), not the backend's.
    pub database_url: String,
    pub rpc_url: String,
    pub chain_id: u64,
    pub anchor_contract: Address,
    pub keystore_file: PathBuf,
    pub keystore_passphrase: String,
    /// Blocks that must follow a transaction's block before its receipt is written.
    pub confirmations: u64,
    pub interval: Duration,
    /// The worker sends nothing while the network asks for more than this per unit of gas.
    pub max_fee_wei: u128,
    pub tx_timeout: Duration,
    /// Longest wait for one answer from the RPC node.
    pub rpc_timeout: Duration,
    pub poll: Duration,
    /// Most blocks anchored by one transaction when catching up.
    pub batch: i64,
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn required(name: &str) -> R<String> {
    optional(name).ok_or_else(|| format!("{name} must be set"))
}

fn bounded(name: &str, default: u64, min: u64, max: u64) -> R<u64> {
    match optional(name) {
        None => Ok(default),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| format!("{name} must be a whole number from {min} to {max}")),
    }
}

/// Reads a fee in gwei, with up to nine decimals, as wei. No floating point is involved.
pub fn gwei_to_wei(text: &str) -> Option<u128> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 9 {
        return None;
    }
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if !digits(whole) || !digits(frac) || whole.len() > 12 {
        return None;
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac: u128 = format!("{frac:0<9}").parse().ok()?;
    Some(whole * 1_000_000_000 + frac)
}

pub fn parse_address(name: &str, value: &str) -> R<Address> {
    value
        .parse::<Address>()
        .ok()
        .filter(|a| *a != Address::ZERO)
        .ok_or_else(|| format!("{name} must be a contract address (0x followed by 40 hex digits)"))
}

impl Config {
    pub fn from_env() -> R<Self> {
        let rpc_url = required("CHAIN_RPC_URL")?;
        if !(rpc_url.starts_with("https://") || rpc_url.starts_with("http://")) {
            return Err("CHAIN_RPC_URL must start with https:// or http://".into());
        }
        let chain_id = required("CHAIN_ID")?
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or(
                "CHAIN_ID must be a positive whole number (for example 31337 for a local node)",
            )?;
        let keystore_passphrase = required("CHAIN_KEYSTORE_PASSPHRASE")?;
        let max_fee = optional("CHAIN_MAX_FEE_GWEI").unwrap_or_else(|| "50".into());
        let max_fee_wei = gwei_to_wei(&max_fee)
            .filter(|w| *w > 0)
            .ok_or("CHAIN_MAX_FEE_GWEI must be a positive number of gwei, for example 50 or 0.5")?;
        Ok(Self {
            database_url: required("CHAIN_DATABASE_URL")?,
            rpc_url,
            chain_id,
            anchor_contract: parse_address(
                "CHAIN_ANCHOR_CONTRACT",
                &required("CHAIN_ANCHOR_CONTRACT")?,
            )?,
            keystore_file: PathBuf::from(required("CHAIN_KEYSTORE_FILE")?),
            keystore_passphrase,
            confirmations: bounded("CHAIN_CONFIRMATIONS", 2, 1, 64)?,
            interval: Duration::from_secs(bounded("CHAIN_INTERVAL_SECS", 60, 2, 86_400)?),
            max_fee_wei,
            tx_timeout: Duration::from_secs(bounded("CHAIN_TX_TIMEOUT_SECS", 180, 5, 3_600)?),
            rpc_timeout: Duration::from_secs(bounded("CHAIN_RPC_TIMEOUT_SECS", 20, 1, 300)?),
            poll: Duration::from_millis(bounded("CHAIN_POLL_MS", 1_500, 100, 60_000)?),
            batch: bounded("CHAIN_BATCH_SIZE", 25, 1, 100)? as i64,
        })
    }

    /// The contract address as stored in the database: lower-case, 0x-prefixed.
    pub fn contract_text(&self) -> String {
        format!("{:#x}", self.anchor_contract)
    }

    /// The RPC endpoint without its path or query, which often carry an API key and must not reach a log.
    pub fn rpc_host(&self) -> String {
        let rest = self
            .rpc_url
            .split_once("://")
            .map_or(self.rpc_url.as_str(), |(_, r)| r);
        let host = rest.split(['/', '?']).next().unwrap_or("");
        host.rsplit_once('@').map_or(host, |(_, h)| h).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gwei_is_read_exactly() {
        assert_eq!(gwei_to_wei("50"), Some(50_000_000_000));
        assert_eq!(gwei_to_wei("0.5"), Some(500_000_000));
        assert_eq!(gwei_to_wei(".25"), Some(250_000_000));
        assert_eq!(gwei_to_wei("1.000000001"), Some(1_000_000_001));
        assert_eq!(gwei_to_wei("0"), Some(0));
        for bad in ["", ".", "1.0000000001", "-1", "1e9", "abc", "1,5", " 5"] {
            assert_eq!(gwei_to_wei(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn addresses_are_validated() {
        assert!(parse_address("X", "0x5FbDB2315678afecb367f032d93F642f64180aa3").is_ok());
        assert!(parse_address("X", "0x0000000000000000000000000000000000000000").is_err());
        assert!(parse_address("X", "5FbDB2").is_err());
        assert!(parse_address("X", "").is_err());
    }

    #[test]
    fn rpc_host_hides_keys() {
        let mut c = sample();
        c.rpc_url = "https://sepolia.example.io/v3/SECRETKEY?x=1".into();
        assert_eq!(c.rpc_host(), "sepolia.example.io");
        c.rpc_url = "https://user:pass@node.example:8545/".into();
        assert_eq!(c.rpc_host(), "node.example:8545");
        c.rpc_url = "http://anvil:8545".into();
        assert_eq!(c.rpc_host(), "anvil:8545");
    }

    #[test]
    fn contract_text_is_lower_case() {
        let mut c = sample();
        c.anchor_contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();
        assert_eq!(
            c.contract_text(),
            "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        );
    }

    fn sample() -> Config {
        Config {
            database_url: String::new(),
            rpc_url: String::new(),
            chain_id: 1,
            anchor_contract: Address::ZERO,
            keystore_file: PathBuf::new(),
            keystore_passphrase: String::new(),
            confirmations: 1,
            interval: Duration::from_secs(1),
            max_fee_wei: 1,
            tx_timeout: Duration::from_secs(1),
            rpc_timeout: Duration::from_secs(1),
            poll: Duration::from_secs(1),
            batch: 1,
        }
    }
}
