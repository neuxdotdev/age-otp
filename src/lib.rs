mod engine;
mod error;
pub mod ffi;
mod types;
pub use age_setup::{build_keypair, KeyPair, PublicKey, SecretKey};
pub use engine::OtpEngine;
pub use error::{Error, Result};
pub use types::{Charset, OtpCode, OtpSeed};
pub mod constants {
    pub const MIN_CODE_LEN: usize = 4;
    pub const MAX_CODE_LEN: usize = 64;
    pub const MIN_STEP_SECS: u64 = 1;
    pub const MAX_STEP_SECS: u64 = 3600;
    pub const MAX_SKEW_STEPS: u64 = 10;
    pub const SEED_LEN: usize = 32;
}
