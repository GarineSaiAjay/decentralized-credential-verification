use std::{env, net::IpAddr, path::PathBuf, time::Duration};

use crate::{auth::Role, crypto::KeyRing};

/// External RFC 3161 time-stamping authority that every sealed block is anchored to.
#[derive(Clone)]
pub struct TsaConfig {
    pub url: String,
    /// PEM file with the root certificate(s) the TSA's signing certificate must chain to.
    pub ca_file: PathBuf,
    pub interval: Duration,
    pub timeout: Duration,
}

/// Where the optional on-chain worker anchors sealed blocks. Used for display only: the backend never talks
/// to a chain. `contract` is lower-case, as the worker stores it.
#[derive(Clone, Debug, PartialEq)]
pub struct OnchainConfig {
    pub chain_id: i64,
    pub contract: String,
    /// Base address of a block explorer for links, e.g. `https://sepolia.etherscan.io` (optional).
    pub explorer: Option<String>,
    /// Where this university is listed, so an exported credential can say so (optional).
    pub issuer: Option<IssuerRef>,
}

/// This university's entry in the on-chain issuer registry: the registry contract and the issuer's id in it.
#[derive(Clone, Debug, PartialEq)]
pub struct IssuerRef {
    pub registry: String,
    pub issuer_id: i64,
}

fn contract_address(name: &str, value: &str) -> Result<String, String> {
    value
        .strip_prefix("0x")
        .filter(|h| h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|h| format!("0x{}", h.to_ascii_lowercase()))
        .ok_or_else(|| format!("{name} must be 0x followed by 40 hex digits"))
}

/// Reads CHAIN_REGISTRY_CONTRACT and CHAIN_ISSUER_ID, which belong together.
pub fn issuer_ref(
    registry: Option<String>,
    issuer_id: Option<String>,
) -> Result<Option<IssuerRef>, String> {
    match (registry, issuer_id) {
        (None, None) => Ok(None),
        (Some(r), Some(i)) => Ok(Some(IssuerRef {
            registry: contract_address("CHAIN_REGISTRY_CONTRACT", &r)?,
            issuer_id: i
                .parse::<i64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or("CHAIN_ISSUER_ID must be a positive whole number")?,
        })),
        _ => Err("CHAIN_REGISTRY_CONTRACT and CHAIN_ISSUER_ID must be set together".into()),
    }
}

/// Reads the on-chain display settings. `Err` says why they are unusable; the caller then runs with the
/// display off instead of refusing to start, so a half-finished worker setup can never stop the backend.
pub fn onchain_config(
    chain_id: Option<String>,
    contract: Option<String>,
    explorer: Option<String>,
) -> Result<Option<OnchainConfig>, String> {
    let (chain_id, contract) = match (chain_id, contract) {
        (None, None) => return Ok(None),
        (Some(i), Some(c)) => (i, c),
        _ => return Err("CHAIN_ID and CHAIN_ANCHOR_CONTRACT must be set together".into()),
    };
    let chain_id = chain_id
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or("CHAIN_ID must be a positive whole number")?;
    let contract = contract_address("CHAIN_ANCHOR_CONTRACT", &contract)?;
    let explorer = match explorer {
        None => None,
        Some(e) if e.starts_with("https://") || e.starts_with("http://") => {
            Some(e.trim_end_matches('/').to_string())
        }
        Some(_) => return Err("CHAIN_EXPLORER_URL must start with https:// or http://".into()),
    };
    Ok(Some(OnchainConfig {
        chain_id,
        contract,
        explorer,
        issuer: None,
    }))
}

/// Request limits. `*_per_min` are per minute; the login-failure limit is per account per window.
#[derive(Clone)]
pub struct RateConfig {
    /// Anonymous requests per client address (the public verification page shares this).
    pub ip_per_min: u32,
    /// Signed-in requests per user, so people behind one office address do not share a budget.
    pub user_per_min: u32,
    /// Login attempts per client address.
    pub login_ip_per_min: u32,
    /// Failed logins per account (whatever the address) before that account is throttled.
    pub login_account_failures: u32,
    pub login_account_window_secs: u64,
}

/// How browsers identify this site to authenticators (WebAuthn relying party).
#[derive(Clone)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub origin: String,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    /// ENCRYPTION_KEY (current) plus ENCRYPTION_KEY_PREVIOUS (still readable during a rotation).
    pub enc_key: KeyRing,
    pub bind: String,
    pub public_base_url: String,
    /// Addresses of the reverse proxies whose `X-Forwarded-For` is believed. Empty: the header is ignored.
    pub trusted_proxies: Vec<Cidr>,
    pub seed_password: Option<String>,
    pub bootstrap_admin: Option<(String, String)>,
    pub tsa: Option<TsaConfig>,
    pub webauthn: WebAuthnConfig,
    pub rate: RateConfig,
    /// Every approval must carry the approver's personal (WebAuthn) countersignature.
    pub require_personal: bool,
    /// Even a person's first key needs an administrator to open the enrolment window.
    pub require_admin_enrollment: bool,
    /// Roles that must sign in with a second factor; without one set up they can do nothing but set it up.
    pub require_mfa_roles: Vec<Role>,
    /// Where the Prometheus endpoint listens (METRICS_BIND). Unset: no metrics endpoint.
    pub metrics_bind: Option<String>,
    /// How long the public whole-chain check may be served from memory (CHAIN_VERIFY_CACHE_SECS; 0 = never).
    pub chain_cache_secs: u64,
    /// Set when sealed blocks are also anchored on a public chain (CHAIN_ID + CHAIN_ANCHOR_CONTRACT).
    pub onchain: Option<OnchainConfig>,
}

/// An address range such as `172.29.250.0/24`; a bare address is a range of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("'{s}' is not an IP address or range"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            Some(b) => b
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| format!("'{s}': the prefix length must be 0-{max}"))?,
            None => max,
        };
        Ok(Self { net, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is that IPv4 address.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.bits))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

fn mfa_roles() -> Result<Vec<Role>, String> {
    optional("REQUIRE_MFA_ROLES")
        .map(|l| {
            l.split(',')
                .map(|r| {
                    Role::parse(r.trim()).ok_or_else(|| {
                        format!("REQUIRE_MFA_ROLES: '{}' is not a role (faculty, exam_cell, registrar, university_admin, auditor)", r.trim())
                    })
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn trusted_proxies() -> Result<Vec<Cidr>, String> {
    let list = optional("TRUSTED_PROXIES");
    if list.is_none() && optional("TRUST_PROXY").is_some_and(|v| v == "true") {
        return Err("TRUST_PROXY is no longer used: it trusted whatever the connecting host sent. \
            List the address(es) of your reverse proxy in TRUSTED_PROXIES (comma-separated addresses or ranges, \
            e.g. 172.29.250.12), or leave it unset to ignore X-Forwarded-For"
            .into());
    }
    list.map(|l| {
        l.split(',')
            .map(|c| Cidr::parse(c).map_err(|e| format!("TRUSTED_PROXIES: {e}")))
            .collect()
    })
    .unwrap_or_else(|| Ok(Vec::new()))
}

fn metrics_bind() -> Result<Option<String>, String> {
    match optional("METRICS_BIND") {
        None => Ok(None),
        Some(v) => v
            .parse::<std::net::SocketAddr>()
            .map(|_| Some(v.clone()))
            .map_err(|_| format!("METRICS_BIND '{v}' must look like 0.0.0.0:9090")),
    }
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn bounded(name: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    match optional(name) {
        None => Ok(default),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| format!("{name} must be a whole number between {min} and {max}")),
    }
}

/// Origin and relying-party id from the public URL; WEBAUTHN_RP_ID may widen the id to a parent domain.
fn webauthn_config(
    public_base_url: &str,
    rp_override: Option<String>,
) -> Result<WebAuthnConfig, String> {
    let (scheme, rest) = public_base_url
        .split_once("://")
        .filter(|(s, _)| matches!(*s, "http" | "https"))
        .ok_or("PUBLIC_BASE_URL must start with http:// or https://")?;
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    if host.is_empty() {
        return Err("PUBLIC_BASE_URL has no host".into());
    }
    let rp_id = rp_override.unwrap_or_else(|| host.to_string());
    if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        return Err(
            "WEBAUTHN_RP_ID must be the host of PUBLIC_BASE_URL or a parent domain of it".into(),
        );
    }
    Ok(WebAuthnConfig {
        rp_id,
        origin: format!("{scheme}://{host_port}"),
    })
}

fn parse_key(name: &str, hex_key: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_key)
        .map_err(|_| format!("{name} must be hex"))?
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes (64 hex chars)"))
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be set"))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = required("JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters".into());
        }
        let current = parse_key("ENCRYPTION_KEY", &required("ENCRYPTION_KEY")?)?;
        let mut previous = vec![];
        for (i, part) in optional("ENCRYPTION_KEY_PREVIOUS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .enumerate()
        {
            let key = parse_key("ENCRYPTION_KEY_PREVIOUS", part)?;
            if key == current || previous.contains(&key) {
                return Err(format!(
                    "ENCRYPTION_KEY_PREVIOUS entry {} repeats another key",
                    i + 1
                ));
            }
            previous.push(key);
        }
        if previous.len() > 4 {
            return Err("ENCRYPTION_KEY_PREVIOUS may list at most 4 keys".into());
        }
        let enc_key = KeyRing::new(current, previous);
        let bootstrap_admin = match (
            optional("BOOTSTRAP_ADMIN_EMAIL"),
            optional("BOOTSTRAP_ADMIN_PASSWORD"),
        ) {
            (Some(email), Some(password)) => Some((email, password)),
            (None, None) => None,
            _ => {
                return Err(
                    "BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together"
                        .into(),
                )
            }
        };
        let tsa = match (optional("TSA_URL"), optional("TSA_CA_FILE")) {
            (Some(url), Some(ca_file)) => {
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err("TSA_URL must start with https:// or http://".into());
                }
                Some(TsaConfig {
                    url,
                    ca_file: PathBuf::from(ca_file),
                    interval: Duration::from_secs(bounded("TSA_INTERVAL_SECS", 300, 10, 86_400)?),
                    timeout: Duration::from_secs(bounded("TSA_TIMEOUT_SECS", 15, 1, 120)?),
                })
            }
            (None, None) => None,
            _ => return Err("TSA_URL and TSA_CA_FILE must be set together".into()),
        };
        let public_base_url = env::var("PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".into())
            .trim_end_matches('/')
            .to_string();
        let rate = RateConfig {
            ip_per_min: bounded("RATE_LIMIT_IP_PER_MIN", 240, 1, 1_000_000)? as u32,
            user_per_min: bounded("RATE_LIMIT_USER_PER_MIN", 600, 1, 1_000_000)? as u32,
            login_ip_per_min: bounded("LOGIN_IP_PER_MIN", 10, 1, 10_000)? as u32,
            login_account_failures: bounded("LOGIN_ACCOUNT_FAILURES", 20, 1, 10_000)? as u32,
            login_account_window_secs: bounded("LOGIN_ACCOUNT_WINDOW_SECS", 900, 10, 86_400)?,
        };
        let trusted_proxies = trusted_proxies()?;
        let require_mfa_roles = mfa_roles()?;
        let webauthn = webauthn_config(&public_base_url, optional("WEBAUTHN_RP_ID"))?;
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            jwt_secret,
            enc_key,
            bind: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".into()),
            public_base_url,
            trusted_proxies,
            seed_password: optional("SEED_DEMO_PASSWORD"),
            bootstrap_admin,
            tsa,
            webauthn,
            rate,
            require_personal: optional("REQUIRE_PERSONAL_SIGNATURES").is_some_and(|v| v == "true"),
            require_admin_enrollment: optional("REQUIRE_ADMIN_ENROLLMENT")
                .is_some_and(|v| v == "true"),
            require_mfa_roles,
            metrics_bind: metrics_bind()?,
            chain_cache_secs: bounded("CHAIN_VERIFY_CACHE_SECS", 30, 0, 3600)?,
            onchain: onchain_config(
                optional("CHAIN_ID"),
                optional("CHAIN_ANCHOR_CONTRACT"),
                optional("CHAIN_EXPLORER_URL"),
            )
            .and_then(|c| match c {
                Some(mut c) => {
                    c.issuer = issuer_ref(
                        optional("CHAIN_REGISTRY_CONTRACT"),
                        optional("CHAIN_ISSUER_ID"),
                    )?;
                    Ok(Some(c))
                }
                None => Ok(None),
            })
            .unwrap_or_else(|why| {
                tracing::warn!("on-chain anchoring is not shown: {why}");
                None
            }),
        })
    }
}

#[cfg(test)]
impl Config {
    /// A configuration for tests that talk to the router in-process: generous limits, no proxies, no extras.
    pub fn for_tests() -> Self {
        Self {
            database_url: String::new(),
            jwt_secret: "test-secret-test-secret-test-secret!".into(),
            enc_key: KeyRing::new([7; 32], vec![]),
            bind: "127.0.0.1:0".into(),
            public_base_url: "http://localhost:3000".into(),
            trusted_proxies: vec![],
            seed_password: None,
            bootstrap_admin: None,
            tsa: None,
            webauthn: WebAuthnConfig {
                rp_id: "localhost".into(),
                origin: "http://localhost:3000".into(),
            },
            rate: RateConfig {
                ip_per_min: 100_000,
                user_per_min: 100_000,
                login_ip_per_min: 100_000,
                login_account_failures: 5,
                login_account_window_secs: 900,
            },
            require_personal: false,
            require_admin_enrollment: false,
            require_mfa_roles: vec![],
            metrics_bind: None,
            chain_cache_secs: 0,
            onchain: None,
        }
    }
}

#[cfg(test)]
mod onchain_tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn unset_means_off() {
        assert_eq!(onchain_config(None, None, None), Ok(None));
        // An explorer address alone switches nothing on.
        assert_eq!(onchain_config(None, None, s("https://x.test")), Ok(None));
    }

    #[test]
    fn a_complete_setting_is_normalised() {
        let c = onchain_config(
            s("11155111"),
            s("0x5FbDB2315678afecb367f032d93F642f64180aa3"),
            s("https://sepolia.etherscan.io/"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.chain_id, 11155111);
        // Lower-case, as the worker stores it, so the two always compare equal.
        assert_eq!(c.contract, "0x5fbdb2315678afecb367f032d93f642f64180aa3");
        assert_eq!(c.explorer.as_deref(), Some("https://sepolia.etherscan.io"));
    }

    #[test]
    fn the_registry_entry_needs_both_values() {
        let addr = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
        assert_eq!(issuer_ref(None, None), Ok(None));
        assert_eq!(
            issuer_ref(s(addr), s("1")),
            Ok(Some(IssuerRef {
                registry: "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512".into(),
                issuer_id: 1
            }))
        );
        for (r, i) in [
            (s(addr), None),
            (None, s("1")),
            (s(addr), s("0")),
            (s(addr), s("one")),
            (s("0x12"), s("1")),
        ] {
            assert!(issuer_ref(r.clone(), i.clone()).is_err(), "{r:?} {i:?}");
        }
    }

    #[test]
    fn unusable_settings_are_reported_not_guessed() {
        let addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
        for (id, contract, explorer) in [
            (s("31337"), None, None),
            (None, s(addr), None),
            (s("0"), s(addr), None),
            (s("-1"), s(addr), None),
            (s("sepolia"), s(addr), None),
            (
                s("31337"),
                s("5FbDB2315678afecb367f032d93F642f64180aa3"),
                None,
            ),
            (s("31337"), s("0x5FbDB2"), None),
            (
                s("31337"),
                s("0xZZbDB2315678afecb367f032d93F642f64180aa3"),
                None,
            ),
            (s("31337"), s(addr), s("javascript:alert(1)")),
        ] {
            assert!(
                onchain_config(id.clone(), contract.clone(), explorer.clone()).is_err(),
                "{id:?} {contract:?} {explorer:?}"
            );
        }
    }
}
