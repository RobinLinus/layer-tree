pub mod blockchain;
pub mod keys;
pub mod signing;
pub mod state;
pub mod transactions;
pub mod tree;

use bitcoin::Amount;
use serde::{Deserialize, Serialize};

/// Runtime-configurable protocol parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub fanout: usize,
    pub kickoff_delay: u16,
    pub nseq_start: u16,
    pub step_size: u16,
    pub kickoff_fee: u64,
    pub root_fee: u64,
    pub split_fee: u64,
    pub refresh_fee: u64,
}

impl Params {
    pub fn split_fee(&self) -> Amount {
        Amount::from_sat(self.split_fee)
    }
    pub fn root_fee(&self) -> Amount {
        Amount::from_sat(self.root_fee)
    }
    pub fn kickoff_fee(&self) -> Amount {
        Amount::from_sat(self.kickoff_fee)
    }
    pub fn refresh_fee(&self) -> Amount {
        Amount::from_sat(self.refresh_fee)
    }
}

impl Default for Params {
    fn default() -> Self {
        REGTEST_PARAMS
    }
}

/// Regtest parameters (small values for fast testing).
pub const REGTEST_PARAMS: Params = Params {
    fanout: 4,
    kickoff_delay: 10,
    nseq_start: 20,
    step_size: 2,
    kickoff_fee: 200,
    root_fee: 200,
    split_fee: 300,
    refresh_fee: 200,
};

/// Signet parameters (realistic values).
pub const SIGNET_PARAMS: Params = Params {
    fanout: 4,
    kickoff_delay: 144,   // ~1 day
    nseq_start: 4320,     // ~30 days
    step_size: 4,          // ~1008 states per epoch
    kickoff_fee: 200,
    root_fee: 200,
    split_fee: 300,
    refresh_fee: 200,
};

// Keep old constants for backward compatibility with demos
pub const FANOUT: usize = 4;
pub const SPLIT_FEE: u64 = 300;
pub const KICKOFF_FEE: u64 = 200;
pub const ROOT_FEE: u64 = 200;
pub const REFRESH_FEE: u64 = 200;

pub mod regtest {
    pub const KICKOFF_DELAY: u16 = 10;
    pub const NSEQ_START: u16 = 20;
    pub const STEP_SIZE: u16 = 2;
}
