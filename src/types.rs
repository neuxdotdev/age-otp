use crate::PublicKey;
use crate::error::{Error, GenerationError, KeyError, Result};
use std::fmt;
pub const SEED_LEN: usize = 32;
pub const MIN_CODE_LEN: usize = 4;
pub const MAX_CODE_LEN: usize = 64;
pub const MIN_STEP_SECS: u64 = 1;
pub const MAX_STEP_SECS: u64 = 3600;
pub const MAX_SKEW_STEPS: u64 = 10;
const DIGITS: &[u8] = b"0123456789";
const ALPHANUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HEX: &[u8] = b"0123456789abcdef";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Numeric,
    AlphanumericUpper,
    HexLower,
}
impl Charset {
    fn chars(&self) -> &'static [u8] {
        match self {
            Self::Numeric => DIGITS,
            Self::AlphanumericUpper => ALPHANUM,
            Self::HexLower => HEX,
        }
    }
    pub fn len(&self) -> usize {
        self.chars().len()
    }
    pub fn validate(&self, s: &str) -> bool {
        let chars = self.chars();
        !s.is_empty() && s.bytes().all(|b| chars.contains(&b))
    }
}
impl Default for Charset {
    fn default() -> Self {
        Self::Numeric
    }
}
use bech32::Bech32;
use bech32::primitives::decode::CheckedHrpstring;
pub(crate) fn decode_age_public_key(raw: &str) -> Result<[u8; SEED_LEN]> {
    if raw.is_empty() {
        return Err(KeyError::Empty.into());
    }
    if !raw.starts_with("age1") {
        return Err(KeyError::InvalidPrefix(raw[..raw.len().min(10)].into()).into());
    }
    let parsed = CheckedHrpstring::new::<Bech32>(raw)
        .map_err(|e| KeyError::Bech32Decode(format!("Bech32 parse error: {}", e)))?;
    let bytes: Vec<u8> = parsed.byte_iter().collect();
    if bytes.len() != SEED_LEN {
        return Err(KeyError::InvalidDecodedLength(bytes.len()).into());
    }
    let mut result = [0u8; SEED_LEN];
    result.copy_from_slice(&bytes);
    Ok(result)
}
#[derive(Clone)]
pub struct OtpSeed {
    bytes: [u8; SEED_LEN],
}
impl OtpSeed {
    pub fn from_public_key(pk: &PublicKey) -> Result<Self> {
        let raw = pk.expose();
        let decoded_key = decode_age_public_key(raw)?;
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, &decoded_key);
        let mut seed = [0u8; SEED_LEN];
        hk.expand(b"age-otp-v1", &mut seed)
            .map_err(|_| GenerationError::HmacFailed)?;
        Ok(Self { bytes: seed })
    }
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Self {
        Self { bytes }
    }
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.bytes
    }
    pub fn to_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
impl fmt::Debug for OtpSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpSeed")
            .field("hex_prefix", &&self.to_hex()[..8])
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct OtpCode {
    value: String,
    born: u64,
}
impl OtpCode {
    pub(crate) fn new(value: String, time_step: u64, step_secs: u64) -> Result<Self> {
        let born = time_step
            .checked_mul(step_secs)
            .ok_or(GenerationError::Overflow)?;
        Ok(Self { value, born })
    }
    pub fn as_str(&self) -> &str {
        &self.value
    }
    pub fn born_at(&self) -> u64 {
        self.born
    }
    pub fn len(&self) -> usize {
        self.value.len()
    }
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
    pub fn is_valid_at(&self, ts: u64, ttl: u64) -> bool {
        let expires = self.born.saturating_add(ttl);
        ts >= self.born && ts < expires
    }
}
impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let masked = if self.value.len() >= 2 {
            format!("{}***", &self.value[..2])
        } else {
            "***".into()
        };
        f.debug_struct("OtpCode")
            .field("code", &masked)
            .field("born", &self.born)
            .finish()
    }
}
impl fmt::Display for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}
impl AsRef<str> for OtpCode {
    fn as_ref(&self) -> &str {
        &self.value
    }
}
pub(crate) fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
pub(crate) fn compute_hmac(seed: &[u8; SEED_LEN], step: u64) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(seed).map_err(|_| GenerationError::HmacFailed)?;
    mac.update(&step.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}
pub(crate) fn truncate(hash: &[u8; 32], charset: Charset, len: usize) -> Result<String> {
    if len < MIN_CODE_LEN || len > MAX_CODE_LEN {
        return Err(GenerationError::InvalidLength(format!(
            "code length must be {}-{}, got {}",
            MIN_CODE_LEN, MAX_CODE_LEN, len
        ))
        .into());
    }
    let offset = (hash[31] & 0x0f) as usize;
    let binary = ((hash[offset] as u32) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    let base = charset.len() as u64;
    let code_val = match base.checked_pow(len as u32) {
        Some(max_val) => (binary as u64) % max_val,
        None => binary as u64,
    };
    let chars = charset.chars();
    let mut s = String::with_capacity(len);
    let mut rem = code_val;
    for _ in 0..len {
        let idx = (rem % base) as usize;
        s.push(chars[idx] as char);
        rem /= base;
    }
    let s: String = s.chars().rev().collect();
    debug_assert_eq!(s.len(), len, "truncation produced wrong length");
    Ok(s)
}
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
pub(crate) fn validate_code_len(len: usize) -> Result<()> {
    if len < MIN_CODE_LEN || len > MAX_CODE_LEN {
        return Err(Error::Generation(GenerationError::InvalidLength(format!(
            "code length must be {}-{}, got {}",
            MIN_CODE_LEN, MAX_CODE_LEN, len
        ))));
    }
    Ok(())
}
pub(crate) fn validate_step_secs(secs: u64) -> Result<()> {
    if secs < MIN_STEP_SECS || secs > MAX_STEP_SECS {
        return Err(Error::Generation(GenerationError::TruncateFailed(format!(
            "step_secs must be {}-{}, got {}",
            MIN_STEP_SECS, MAX_STEP_SECS, secs
        ))));
    }
    Ok(())
}
pub(crate) fn validate_skew_steps(skew: u64) -> Result<()> {
    if skew > MAX_SKEW_STEPS {
        return Err(Error::Verification(
            crate::error::VerificationError::InvalidFormat(format!(
                "skew_steps must be <= {}, got {}",
                MAX_SKEW_STEPS, skew
            )),
        ));
    }
    Ok(())
}
