use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Generation error: {0}")]
    Generation(#[from] GenerationError),
    #[error("Verification error: {0}")]
    Verification(#[from] VerificationError),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Key is empty")]
    Empty,
    #[error("Invalid prefix: expected 'age1', got '{0}'")]
    InvalidPrefix(String),
    #[error("Bech32 decode failed: {0}")]
    Bech32Decode(String),
    #[error("Invalid decoded length: expected 32 bytes, got {0}")]
    InvalidDecodedLength(usize),
}
#[derive(Debug, Error)]
pub enum GenerationError {
    #[error("HMAC failed")]
    HmacFailed,
    #[error("Truncation failed: {0}")]
    TruncateFailed(String),
    #[error("Invalid length: {0}")]
    InvalidLength(String),
    #[error("Overflow computing born time")]
    Overflow,
}
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Code mismatch")]
    Mismatch,
    #[error("Expired at {0}, current {1}")]
    Expired(u64, u64),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}
