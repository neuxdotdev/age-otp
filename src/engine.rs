use crate::PublicKey;
use crate::error::{Error, Result, VerificationError};
use crate::types::{
    Charset, OtpCode, OtpSeed, compute_hmac, ct_eq, now_ts, truncate, validate_code_len,
    validate_skew_steps, validate_step_secs,
};
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
