//! Operator configuration loaded from TOML file.

use layer_tree_core::Params;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub operator: OperatorConfig,
    pub network: NetworkConfig,
    pub listen: ListenConfig,
    #[serde(default)]
    pub peers: PeersConfig,
    pub bitcoind: Option<BitcoindConfig>,
    pub database: DatabaseConfig,
    #[serde(default)]
    pub params: ParamsConfig,
    #[serde(default)]
    pub admin: AdminConfig,
}

#[derive(Debug, Deserialize)]
pub struct OperatorConfig {
    /// Path to the operator secret key file (32-byte raw key).
    pub key_file: String,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    /// "regtest" or "signet"
    #[serde(default = "default_chain")]
    pub chain: String,
}

fn default_chain() -> String {
    "regtest".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    /// Address for user-facing REST + WebSocket + static files.
    #[serde(default = "default_user_addr")]
    pub user_addr: String,
    /// Address for operator-to-operator gRPC.
    #[serde(default = "default_peer_addr")]
    pub peer_addr: String,
}

fn default_user_addr() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_peer_addr() -> String {
    "0.0.0.0:50051".to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct PeersConfig {
    /// gRPC URLs of other operators.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Public keys of all operators (including self), in signer order.
    /// 33-byte hex-encoded compressed public keys.
    #[serde(default)]
    pub pubkeys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BitcoindConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
}

fn default_db_path() -> String {
    "./layer_tree.db".to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct AdminConfig {
    /// Bearer token for admin endpoints. If empty, admin endpoints are disabled.
    #[serde(default)]
    pub token: String,
}

/// Protocol params from config, falling back to defaults.
#[derive(Debug, Deserialize)]
pub struct ParamsConfig {
    pub fanout: Option<usize>,
    pub kickoff_delay: Option<u16>,
    pub nseq_start: Option<u16>,
    pub step_size: Option<u16>,
    pub kickoff_fee: Option<u64>,
    pub root_fee: Option<u64>,
    pub split_fee: Option<u64>,
    pub refresh_fee: Option<u64>,
}

impl Default for ParamsConfig {
    fn default() -> Self {
        Self {
            fanout: None,
            kickoff_delay: None,
            nseq_start: None,
            step_size: None,
            kickoff_fee: None,
            root_fee: None,
            split_fee: None,
            refresh_fee: None,
        }
    }
}

impl ParamsConfig {
    /// Merge with base params, overriding only fields set in config.
    pub fn to_params(&self, base: &Params) -> Params {
        Params {
            fanout: self.fanout.unwrap_or(base.fanout),
            kickoff_delay: self.kickoff_delay.unwrap_or(base.kickoff_delay),
            nseq_start: self.nseq_start.unwrap_or(base.nseq_start),
            step_size: self.step_size.unwrap_or(base.step_size),
            kickoff_fee: self.kickoff_fee.unwrap_or(base.kickoff_fee),
            root_fee: self.root_fee.unwrap_or(base.root_fee),
            split_fee: self.split_fee.unwrap_or(base.split_fee),
            refresh_fee: self.refresh_fee.unwrap_or(base.refresh_fee),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Resolve protocol params based on chain and config overrides.
    pub fn protocol_params(&self) -> Params {
        let base = match self.network.chain.as_str() {
            "signet" => &layer_tree_core::SIGNET_PARAMS,
            _ => &layer_tree_core::REGTEST_PARAMS,
        };
        self.params.to_params(base)
    }

    /// Number of operators (including self).
    pub fn n_operators(&self) -> usize {
        self.peers.pubkeys.len()
    }
}
