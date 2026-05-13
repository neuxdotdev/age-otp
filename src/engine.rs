use crate::error::{Error, Result, VerificationError};
use crate::types::{
    compute_hmac, ct_eq, now_ts, truncate, validate_code_len, validate_skew_steps,
    validate_step_secs, Charset, OtpCode, OtpSeed,
};
use crate::PublicKey;
use std::fmt;
#[derive(Clone)]
pub struct OtpEngine {
    seed: OtpSeed,
}
impl fmt::Debug for OtpEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpEngine")
            .field("seed", &self.seed)
            .finish()
    }
}
impl OtpEngine {
    pub fn from_public_key(pk: &PublicKey) -> Result<Self> {
        let seed = OtpSeed::from_public_key(pk)?;
        Ok(Self { seed })
    }
    pub fn from_seed(seed: OtpSeed) -> Self {
        Self { seed }
    }
    pub fn seed(&self) -> &OtpSeed {
        &self.seed
    }
    pub fn generate(
        &self,
        len: usize,
        time_step: u64,
        step_secs: u64,
        charset: Charset,
    ) -> Result<OtpCode> {
        validate_code_len(len)?;
        validate_step_secs(step_secs)?;
        let hash = compute_hmac(self.seed.as_bytes(), time_step)?;
        let value = truncate(&hash, charset, len)?;
        OtpCode::new(value, time_step, step_secs)
    }
    pub fn generate_default(&self, len: usize, time_step: u64) -> Result<OtpCode> {
        self.generate(len, time_step, 30, Charset::default())
    }
    pub fn generate_now(&self, len: usize) -> Result<OtpCode> {
        let step = now_ts() / 30;
        self.generate_default(len, step)
    }
    pub fn verify(
        &self,
        code: &OtpCode,
        time_step: u64,
        ttl: u64,
        step_secs: u64,
        charset: Charset,
    ) -> Result<()> {
        validate_step_secs(step_secs)?;
        let expected = self.generate(code.len(), time_step, step_secs, charset)?;
        if !ct_eq(code.as_str().as_bytes(), expected.as_str().as_bytes()) {
            return Err(VerificationError::Mismatch.into());
        }
        let now = now_ts();
        if !code.is_valid_at(now, ttl) {
            return Err(VerificationError::Expired(code.born_at().saturating_add(ttl), now).into());
        }
        Ok(())
    }
    pub fn verify_default(&self, code: &OtpCode, time_step: u64, ttl: u64) -> Result<()> {
        self.verify(code, time_step, ttl, 30, Charset::default())
    }
    pub fn verify_raw(
        &self,
        raw: &str,
        len: usize,
        time_step: u64,
        ttl: u64,
        step_secs: u64,
        charset: Charset,
    ) -> Result<()> {
        let expected = self.validate_and_generate(raw, len, time_step, step_secs, charset)?;
        if !ct_eq(raw.as_bytes(), expected.as_str().as_bytes()) {
            return Err(VerificationError::Mismatch.into());
        }
        let now = now_ts();
        let born = time_step.checked_mul(step_secs).ok_or_else(|| {
            Error::Verification(VerificationError::InvalidFormat("overflow".into()))
        })?;
        if now < born || now >= born.saturating_add(ttl) {
            return Err(VerificationError::Expired(born.saturating_add(ttl), now).into());
        }
        Ok(())
    }
    pub fn verify_with_skew(
        &self,
        raw: &str,
        len: usize,
        time_step: u64,
        ttl: u64,
        step_secs: u64,
        charset: Charset,
        skew_steps: u64,
    ) -> Result<()> {
        validate_skew_steps(skew_steps)?;
        validate_code_len(len)?;
        validate_step_secs(step_secs)?;
        if raw.len() != len {
            return Err(VerificationError::InvalidFormat(format!(
                "expected length {}, got {}",
                len,
                raw.len()
            ))
            .into());
        }
        if !charset.validate(raw) {
            return Err(VerificationError::InvalidFormat("invalid charset".into()).into());
        }
        let start = time_step.saturating_sub(skew_steps);
        let end = time_step.saturating_add(skew_steps);
        for step in start..=end {
            let expected = self.generate(len, step, step_secs, charset)?;
            if ct_eq(raw.as_bytes(), expected.as_str().as_bytes()) {
                let now = now_ts();
                let born = step.checked_mul(step_secs).ok_or_else(|| {
                    Error::Verification(VerificationError::InvalidFormat("overflow".into()))
                })?;
                if now >= born && now < born.saturating_add(ttl) {
                    return Ok(());
                }
                return Err(VerificationError::Expired(born.saturating_add(ttl), now).into());
            }
        }
        Err(VerificationError::Mismatch.into())
    }
    fn validate_and_generate(
        &self,
        raw: &str,
        len: usize,
        time_step: u64,
        step_secs: u64,
        charset: Charset,
    ) -> Result<OtpCode> {
        validate_code_len(len)?;
        validate_step_secs(step_secs)?;
        if raw.len() != len {
            return Err(VerificationError::InvalidFormat(format!(
                "expected length {}, got {}",
                len,
                raw.len()
            ))
            .into());
        }
        if !charset.validate(raw) {
            return Err(VerificationError::InvalidFormat("invalid charset".into()).into());
        }
        self.generate(len, time_step, step_secs, charset)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn test_pk() -> PublicKey {
        PublicKey::new("age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe".into())
            .unwrap()
    }
    #[test]
    fn create_engine() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk);
        assert!(engine.is_ok());
    }
    #[test]
    fn create_engine_debug() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let debug = format!("{:?}", engine);
        assert!(debug.contains("OtpEngine"));
        assert!(debug.contains("seed"));
    }
    #[test]
    fn deterministic() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let c1 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let c2 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        assert_eq!(c1.as_str(), c2.as_str());
    }
    #[test]
    fn different_steps() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let c1 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let c2 = engine.generate(6, 1001, 30, Charset::Numeric).unwrap();
        assert_ne!(c1.as_str(), c2.as_str());
    }
    #[test]
    fn different_keys_different_codes() {
        use age_setup::build_keypair;
        let kp = build_keypair().unwrap();
        let kp2 = build_keypair().unwrap();
        let e1 = OtpEngine::from_public_key(&kp.public).unwrap();
        let e2 = OtpEngine::from_public_key(&kp2.public).unwrap();
        let c1 = e1.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let c2 = e2.generate(6, 1000, 30, Charset::Numeric).unwrap();
        assert_ne!(c1.as_str(), c2.as_str());
    }
    #[test]
    fn code_format_numeric() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        assert_eq!(code.len(), 6);
        assert!(Charset::Numeric.validate(code.as_str()));
    }
    #[test]
    fn code_format_alphanumeric() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine
            .generate(8, 1000, 30, Charset::AlphanumericUpper)
            .unwrap();
        assert_eq!(code.len(), 8);
        assert!(Charset::AlphanumericUpper.validate(code.as_str()));
    }
    #[test]
    fn code_format_hex() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(16, 1000, 30, Charset::HexLower).unwrap();
        assert_eq!(code.len(), 16);
        assert!(Charset::HexLower.validate(code.as_str()));
    }
    #[test]
    fn generate_default() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let c1 = engine.generate_default(6, 1000).unwrap();
        let c2 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        assert_eq!(c1.as_str(), c2.as_str());
    }
    #[test]
    fn generate_now() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate_now(6);
        assert!(code.is_ok());
        let code = code.unwrap();
        assert_eq!(code.len(), 6);
    }
    #[test]
    fn invalid_len_too_short() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        assert!(engine.generate(3, 1000, 30, Charset::Numeric).is_err());
        assert!(engine.generate(0, 1000, 30, Charset::Numeric).is_err());
    }
    #[test]
    fn invalid_len_too_long() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        assert!(engine.generate(65, 1000, 30, Charset::Numeric).is_err());
        assert!(engine.generate(100, 1000, 30, Charset::Numeric).is_err());
    }
    #[test]
    fn invalid_step_secs_zero() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        assert!(engine.generate(6, 1000, 0, Charset::Numeric).is_err());
    }
    #[test]
    fn invalid_step_secs_too_large() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        assert!(engine.generate(6, 1000, 3601, Charset::Numeric).is_err());
        assert!(engine
            .generate(6, 1000, u64::MAX, Charset::Numeric)
            .is_err());
    }
    #[test]
    fn from_seed() {
        let pk = test_pk();
        let seed = OtpSeed::from_public_key(&pk).unwrap();
        let e1 = OtpEngine::from_public_key(&pk).unwrap();
        let e2 = OtpEngine::from_seed(seed);
        let c1 = e1.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let c2 = e2.generate(6, 1000, 30, Charset::Numeric).unwrap();
        assert_eq!(c1.as_str(), c2.as_str());
    }
    #[test]
    fn verify_raw_wrong_length() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let result = engine.verify_raw("12345", 6, 1000, 30, 30, Charset::Numeric);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expected length"));
    }
    #[test]
    fn verify_raw_wrong_charset() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let result = engine.verify_raw("abcdef", 6, 1000, 30, 30, Charset::Numeric);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid charset"));
    }
    #[test]
    fn verify_raw_mismatch() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let wrong_code = engine.generate(6, 9999, 30, Charset::Numeric).unwrap();
        let result = engine.verify_raw(wrong_code.as_str(), 6, 1000, 30, 30, Charset::Numeric);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mismatch"));
    }
    #[test]
    fn verify_raw_invalid_step_secs() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let result = engine.verify_raw("123456", 6, 1000, 30, 0, Charset::Numeric);
        assert!(result.is_err());
    }
    #[test]
    fn verify_with_skew_valid_at_same_step() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let result = engine.verify_with_skew(code.as_str(), 6, 1000, 3600, 30, Charset::Numeric, 0);
        if let Err(e) = result {
            let err_str = e.to_string();
            assert!(!err_str.contains("invalid charset"));
            assert!(!err_str.contains("expected length"));
        }
    }
    #[test]
    fn verify_with_skew_valid_at_adjacent_step() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let result = engine.verify_with_skew(code.as_str(), 6, 1001, 3600, 30, Charset::Numeric, 1);
        if let Err(e) = result {
            let err_str = e.to_string();
            if err_str.contains("mismatch") {
                panic!("Should have found the code at step 1000 with skew=1");
            }
        }
    }
    #[test]
    fn verify_with_skew_too_large() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let result = engine.verify_with_skew("123456", 6, 1000, 30, 30, Charset::Numeric, 11);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("skew_steps"));
    }
    #[test]
    fn verify_with_skew_wrong_length() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let result = engine.verify_with_skew("123", 6, 1000, 30, 30, Charset::Numeric, 1);
        assert!(result.is_err());
    }
    #[test]
    fn verify_with_skew_wrong_charset() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let result = engine.verify_with_skew("abcdef", 6, 1000, 30, 30, Charset::Numeric, 1);
        assert!(result.is_err());
    }
    #[test]
    fn verify_with_skew_no_match() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let far_code = engine.generate(6, 9000, 30, Charset::Numeric).unwrap();
        let result =
            engine.verify_with_skew(far_code.as_str(), 6, 1000, 3600, 30, Charset::Numeric, 1);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mismatch"));
    }
    #[test]
    fn seed_hex() {
        let pk = test_pk();
        let seed = OtpSeed::from_public_key(&pk).unwrap();
        let hex = seed.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
    #[test]
    fn code_display() {
        let code = OtpCode::new("123456".into(), 100, 30).unwrap();
        assert_eq!(format!("{}", code), "123456");
    }
    #[test]
    fn code_as_ref() {
        let code = OtpCode::new("123456".into(), 100, 30).unwrap();
        assert_eq!(code.as_ref(), "123456");
    }
    #[test]
    fn edge_case_min_length() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(4, 1000, 30, Charset::Numeric).unwrap();
        assert_eq!(code.len(), 4);
    }
    #[test]
    fn edge_case_max_length() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(64, 1000, 30, Charset::Numeric).unwrap();
        assert_eq!(code.len(), 64);
        assert!(Charset::Numeric.validate(code.as_str()));
    }
    #[test]
    fn edge_case_step_zero() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(6, 0, 30, Charset::Numeric).unwrap();
        assert_eq!(code.born_at(), 0);
    }
    #[test]
    fn edge_case_max_step_secs() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(6, 1000, 3600, Charset::Numeric);
        assert!(code.is_ok());
    }
    #[test]
    fn edge_case_max_skew_steps() {
        let pk = test_pk();
        let engine = OtpEngine::from_public_key(&pk).unwrap();
        let code = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
        let result =
            engine.verify_with_skew(code.as_str(), 6, 1000, 3600, 30, Charset::Numeric, 10);
        if let Err(e) = result {
            let err_str = e.to_string();
            assert!(!err_str.contains("skew_steps"));
        }
    }
}
