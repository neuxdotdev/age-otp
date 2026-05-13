use crate::error::{Error, GenerationError, KeyError, Result};
use crate::PublicKey;
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
use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32;
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn charset_numeric() {
        let cs = Charset::Numeric;
        assert!(cs.validate("123456"));
        assert!(!cs.validate("12345a"));
        assert!(!cs.validate(""));
        assert_eq!(cs.len(), 10);
    }
    #[test]
    fn charset_alphanumeric() {
        let cs = Charset::AlphanumericUpper;
        assert!(cs.validate("ABC123"));
        assert!(!cs.validate("abc123"));
        assert!(!cs.validate("ABC!23"));
    }
    #[test]
    fn charset_hex() {
        let cs = Charset::HexLower;
        assert!(cs.validate("0123456789abcdef"));
        assert!(!cs.validate("ABCDEF"));
        assert!(!cs.validate("ghij"));
    }
    #[test]
    fn decode_age_public_key_valid() {
        let pk = "age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe";
        let result = decode_age_public_key(pk);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.len(), 32);
    }
    #[test]
    fn decode_age_public_key_empty() {
        assert!(decode_age_public_key("").is_err());
    }
    #[test]
    fn decode_age_public_key_invalid_prefix() {
        assert!(decode_age_public_key("ssh-rsa AAAA").is_err());
    }
    #[test]
    fn decode_age_public_key_invalid_bech32() {
        assert!(decode_age_public_key("age1!!!!invalid!!!").is_err());
    }
    #[test]
    fn seed_from_public_key() {
        let pk =
            PublicKey::new("age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe".into())
                .unwrap();
        let seed = OtpSeed::from_public_key(&pk);
        assert!(seed.is_ok());
        let seed = seed.unwrap();
        assert_eq!(seed.to_hex().len(), 64);
    }
    #[test]
    fn seed_from_invalid_key() {
        let pk = PublicKey::new("age1invalidbech32!!!".into()).unwrap();
        let seed = OtpSeed::from_public_key(&pk);
        assert!(seed.is_err());
    }
    #[test]
    fn seed_debug_no_leak() {
        let pk =
            PublicKey::new("age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe".into())
                .unwrap();
        let seed = OtpSeed::from_public_key(&pk).unwrap();
        let debug = format!("{:?}", seed);
        assert!(!debug.contains(&seed.to_hex()[8..]));
        assert!(debug.contains("hex_prefix"));
    }
    #[test]
    fn otp_code_validity() {
        let code = OtpCode::new("123456".into(), 100, 30).unwrap();
        assert!(code.is_valid_at(3000, 30));
        assert!(code.is_valid_at(3029, 30));
        assert!(!code.is_valid_at(3030, 30));
        assert!(!code.is_valid_at(2999, 30));
    }
    #[test]
    fn otp_code_zero_ttl() {
        let code = OtpCode::new("123456".into(), 100, 30).unwrap();
        assert!(!code.is_valid_at(3000, 0));
    }
    #[test]
    fn otp_code_overflow_returns_error() {
        let result = OtpCode::new("123456".into(), u64::MAX, 2);
        assert!(result.is_err());
    }
    #[test]
    fn code_debug_masked() {
        let code = OtpCode::new("123456".into(), 100, 30).unwrap();
        let debug = format!("{:?}", code);
        assert!(!debug.contains("123456"));
        assert!(debug.contains("12***"));
    }
    #[test]
    fn truncate_basic() {
        let mut hash = [0u8; 32];
        hash[31] = 0x00;
        hash[0] = 0x00;
        hash[1] = 0x00;
        hash[2] = 0x00;
        hash[3] = 0x01;
        let code = truncate(&hash, Charset::Numeric, 6).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
    #[test]
    fn truncate_too_short() {
        let hash = [0u8; 32];
        assert!(truncate(&hash, Charset::Numeric, 3).is_err());
    }
    #[test]
    fn truncate_too_long() {
        let hash = [0u8; 32];
        assert!(truncate(&hash, Charset::Numeric, 100).is_err());
    }
    #[test]
    fn truncate_hex_16_chars() {
        let hash = [0xABu8; 32];
        let code = truncate(&hash, Charset::HexLower, 16).unwrap();
        assert_eq!(code.len(), 16);
        assert!(Charset::HexLower.validate(&code));
    }
    #[test]
    fn truncate_numeric_64_chars() {
        let hash = [0x42u8; 32];
        let code = truncate(&hash, Charset::Numeric, 64).unwrap();
        assert_eq!(code.len(), 64);
        assert!(Charset::Numeric.validate(&code));
    }
    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hi", b"hello"));
    }
    #[test]
    fn ct_eq_empty() {
        assert!(ct_eq(b"", b""));
    }
    #[test]
    fn validate_code_len_ok() {
        assert!(validate_code_len(4).is_ok());
        assert!(validate_code_len(6).is_ok());
        assert!(validate_code_len(64).is_ok());
    }
    #[test]
    fn validate_code_len_err() {
        assert!(validate_code_len(3).is_err());
        assert!(validate_code_len(0).is_err());
        assert!(validate_code_len(65).is_err());
    }
    #[test]
    fn validate_step_secs_ok() {
        assert!(validate_step_secs(1).is_ok());
        assert!(validate_step_secs(30).is_ok());
        assert!(validate_step_secs(3600).is_ok());
    }
    #[test]
    fn validate_step_secs_err() {
        assert!(validate_step_secs(0).is_err());
        assert!(validate_step_secs(3601).is_err());
        assert!(validate_step_secs(u64::MAX).is_err());
    }
    #[test]
    fn validate_skew_steps_ok() {
        assert!(validate_skew_steps(0).is_ok());
        assert!(validate_skew_steps(1).is_ok());
        assert!(validate_skew_steps(10).is_ok());
    }
    #[test]
    fn validate_skew_steps_err() {
        assert!(validate_skew_steps(11).is_err());
        assert!(validate_skew_steps(100).is_err());
        assert!(validate_skew_steps(u64::MAX).is_err());
    }
    #[test]
    fn now_ts_returns_reasonable() {
        let now = now_ts();
        assert!(now > 1577836800);
        assert!(now < 4102444800);
    }
    #[test]
    fn compute_hmac_deterministic() {
        let seed = [1u8; SEED_LEN];
        let h1 = compute_hmac(&seed, 100).unwrap();
        let h2 = compute_hmac(&seed, 100).unwrap();
        assert_eq!(h1, h2);
    }
    #[test]
    fn compute_hmac_different_steps() {
        let seed = [1u8; SEED_LEN];
        let h1 = compute_hmac(&seed, 100).unwrap();
        let h2 = compute_hmac(&seed, 101).unwrap();
        assert_ne!(h1, h2);
    }
    #[test]
    fn seed_from_bytes() {
        let bytes = [42u8; SEED_LEN];
        let seed = OtpSeed::from_bytes(bytes);
        assert_eq!(seed.as_bytes(), &bytes);
    }
    #[test]
    fn different_keys_different_seeds() {
        use crate::build_keypair;
        let kp1 = build_keypair().unwrap();
        let kp2 = build_keypair().unwrap();
        let seed1 = OtpSeed::from_public_key(&kp1.public).unwrap();
        let seed2 = OtpSeed::from_public_key(&kp2.public).unwrap();
        assert_ne!(seed1.to_hex(), seed2.to_hex());
    }
}
