use crate::error::Error;
use crate::types::{Charset, OtpCode, OtpSeed};
use crate::{OtpEngine, PublicKey};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
#[repr(C)]
pub struct COtpEngine { _private: *mut () }
#[repr(C)]
pub struct COtpCode {
    _private: [u8; 0],
}
#[repr(C)]
pub struct COtpSeed {
    _private: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CCharset {
    Numeric = 0,
    AlphanumericUpper = 1,
    HexLower = 2,
}
impl Default for CCharset {
    fn default() -> Self {
        Self::Numeric
    }
}
impl From<CCharset> for Charset {
    fn from(c: CCharset) -> Self {
        match c {
            CCharset::Numeric => Charset::Numeric,
            CCharset::AlphanumericUpper => Charset::AlphanumericUpper,
            CCharset::HexLower => Charset::HexLower,
        }
    }
}
impl From<Charset> for CCharset {
    fn from(c: Charset) -> Self {
        match c {
            Charset::Numeric => CCharset::Numeric,
            Charset::AlphanumericUpper => CCharset::AlphanumericUpper,
            Charset::HexLower => CCharset::HexLower,
        }
    }
}
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpErrorCode {
    Ok = 0,
    NullPointer = -1,
    InvalidString = -2,
    InvalidPublicKey = -3,
    EngineCreationFailed = -4,
    GenerationFailed = -5,
    VerificationFailed = -6,
    Expired = -7,
    InvalidParameter = -8,
    HexDecodeFailed = -9,
    LengthMismatch = -10,
    Unknown = -99,
}
pub const OTP_SEED_LEN: usize = 32;
pub const OTP_MIN_CODE_LEN: usize = 4;
pub const OTP_MAX_CODE_LEN: usize = 64;
pub const OTP_MIN_STEP_SECS: u64 = 1;
pub const OTP_MAX_STEP_SECS: u64 = 3600;
pub const OTP_MAX_SKEW_STEPS: u64 = 10;
pub const OTP_DEFAULT_STEP_SECS: u64 = 30;
#[inline]
fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}
#[inline]
fn _to_c_error(err: &Error) -> *mut c_char {
    to_c_string(&err.to_string())
}
#[inline]
unsafe fn from_c_str(s: *const c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    CStr::from_ptr(s).to_str().ok().map(|s| s.to_string())
}
unsafe fn _copy_to_array<const N: usize>(src: *const u8, dst: &mut [u8; N]) -> bool {
    if src.is_null() {
        return false;
    }
    ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), N);
    true
}
#[inline]
unsafe fn set_error(error: *mut *mut c_char, msg: &str) {
    if !error.is_null() {
        *error = to_c_string(msg);
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_from_public_key(
    pk: *const c_char,
    out: *mut *mut COtpEngine,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if pk.is_null() || out.is_null() {
        unsafe { set_error(error, "public key or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let pk_str = match unsafe { from_c_str(pk) } {
        Some(s) => s,
        None => {
            unsafe { set_error(error, "invalid public key string (not valid UTF-8)") };
            return OtpErrorCode::InvalidString;
        }
    };
    let public_key = match PublicKey::new(pk_str) {
        Ok(pk) => pk,
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            return OtpErrorCode::InvalidPublicKey;
        }
    };
    match OtpEngine::from_public_key(&public_key) {
        Ok(engine) => {
            unsafe {
                *out = Box::into_raw(Box::new(engine)) as *mut COtpEngine;
            }
            OtpErrorCode::Ok
        }
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            OtpErrorCode::EngineCreationFailed
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_from_seed_bytes(
    seed_bytes: *const u8,
    seed_len: usize,
    out: *mut *mut COtpEngine,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if seed_bytes.is_null() || out.is_null() {
        unsafe { set_error(error, "seed_bytes or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    if seed_len != OTP_SEED_LEN {
        unsafe {
            set_error(
                error,
                &format!("seed_len must be {}, got {}", OTP_SEED_LEN, seed_len),
            )
        };
        return OtpErrorCode::LengthMismatch;
    }
    let mut bytes = [0u8; OTP_SEED_LEN];
    unsafe {
        ptr::copy_nonoverlapping(seed_bytes, bytes.as_mut_ptr(), OTP_SEED_LEN);
    }
    let seed = OtpSeed::from_bytes(bytes);
    let engine = OtpEngine::from_seed(seed);
    unsafe {
        *out = Box::into_raw(Box::new(engine)) as *mut COtpEngine;
    }
    OtpErrorCode::Ok
}
#[no_mangle]
pub extern "C" fn otp_engine_from_seed_hex(
    hex: *const c_char,
    out: *mut *mut COtpEngine,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if hex.is_null() || out.is_null() {
        unsafe { set_error(error, "hex or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let hex_str = match unsafe { from_c_str(hex) } {
        Some(s) => s,
        None => {
            unsafe { set_error(error, "invalid hex string") };
            return OtpErrorCode::InvalidString;
        }
    };
    let bytes = match hex::decode(&hex_str) {
        Ok(b) => b,
        Err(e) => {
            unsafe {
                set_error(error, &format!("hex decode error: {}", e));
            }
            return OtpErrorCode::HexDecodeFailed;
        }
    };
    if bytes.len() != OTP_SEED_LEN {
        unsafe {
            set_error(
                error,
                &format!(
                    "decoded hex must be {} bytes, got {}",
                    OTP_SEED_LEN,
                    bytes.len()
                ),
            )
        };
        return OtpErrorCode::LengthMismatch;
    }
    let mut seed_bytes = [0u8; OTP_SEED_LEN];
    seed_bytes.copy_from_slice(&bytes);
    let seed = OtpSeed::from_bytes(seed_bytes);
    let engine = OtpEngine::from_seed(seed);
    unsafe {
        *out = Box::into_raw(Box::new(engine)) as *mut COtpEngine;
    }
    OtpErrorCode::Ok
}
#[no_mangle]
pub extern "C" fn otp_engine_free(engine: *mut COtpEngine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine as *mut OtpEngine));
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_generate(
    engine: *const COtpEngine,
    len: usize,
    time_step: u64,
    step_secs: u64,
    charset: CCharset,
    out: *mut *mut COtpCode,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || out.is_null() {
        unsafe { set_error(error, "engine or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    let charset = Charset::from(charset);
    match engine.generate(len, time_step, step_secs, charset) {
        Ok(code) => {
            unsafe {
                *out = Box::into_raw(Box::new(code)) as *mut COtpCode;
            }
            OtpErrorCode::Ok
        }
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            OtpErrorCode::GenerationFailed
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_generate_default(
    engine: *const COtpEngine,
    len: usize,
    time_step: u64,
    out: *mut *mut COtpCode,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || out.is_null() {
        unsafe { set_error(error, "engine or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    match engine.generate_default(len, time_step) {
        Ok(code) => {
            unsafe {
                *out = Box::into_raw(Box::new(code)) as *mut COtpCode;
            }
            OtpErrorCode::Ok
        }
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            OtpErrorCode::GenerationFailed
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_generate_now(
    engine: *const COtpEngine,
    len: usize,
    out: *mut *mut COtpCode,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || out.is_null() {
        unsafe { set_error(error, "engine or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    match engine.generate_now(len) {
        Ok(code) => {
            unsafe {
                *out = Box::into_raw(Box::new(code)) as *mut COtpCode;
            }
            OtpErrorCode::Ok
        }
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            OtpErrorCode::GenerationFailed
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_verify(
    engine: *const COtpEngine,
    code: *const COtpCode,
    time_step: u64,
    ttl: u64,
    step_secs: u64,
    charset: CCharset,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || code.is_null() {
        unsafe { set_error(error, "engine or code is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    let code = unsafe { &*(code as *const OtpCode) };
    let charset = Charset::from(charset);
    match engine.verify(code, time_step, ttl, step_secs, charset) {
        Ok(()) => OtpErrorCode::Ok,
        Err(e) => {
            let err_str = e.to_string();
            unsafe { set_error(error, &err_str) };
            if err_str.contains("mismatch") {
                OtpErrorCode::VerificationFailed
            } else if err_str.contains("Expired") {
                OtpErrorCode::Expired
            } else {
                OtpErrorCode::VerificationFailed
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_verify_default(
    engine: *const COtpEngine,
    code: *const COtpCode,
    time_step: u64,
    ttl: u64,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || code.is_null() {
        unsafe { set_error(error, "engine or code is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    let code = unsafe { &*(code as *const OtpCode) };
    match engine.verify_default(code, time_step, ttl) {
        Ok(()) => OtpErrorCode::Ok,
        Err(e) => {
            let err_str = e.to_string();
            unsafe { set_error(error, &err_str) };
            if err_str.contains("mismatch") {
                OtpErrorCode::VerificationFailed
            } else if err_str.contains("Expired") {
                OtpErrorCode::Expired
            } else {
                OtpErrorCode::VerificationFailed
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_verify_raw(
    engine: *const COtpEngine,
    raw: *const c_char,
    len: usize,
    time_step: u64,
    ttl: u64,
    step_secs: u64,
    charset: CCharset,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || raw.is_null() {
        unsafe { set_error(error, "engine or raw code is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    let raw_str = match unsafe { from_c_str(raw) } {
        Some(s) => s,
        None => {
            unsafe { set_error(error, "invalid raw code string") };
            return OtpErrorCode::InvalidString;
        }
    };
    let charset = Charset::from(charset);
    match engine.verify_raw(&raw_str, len, time_step, ttl, step_secs, charset) {
        Ok(()) => OtpErrorCode::Ok,
        Err(e) => {
            let err_str = e.to_string();
            unsafe { set_error(error, &err_str) };
            if err_str.contains("mismatch") {
                OtpErrorCode::VerificationFailed
            } else if err_str.contains("Expired") {
                OtpErrorCode::Expired
            } else {
                OtpErrorCode::VerificationFailed
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_verify_with_skew(
    engine: *const COtpEngine,
    raw: *const c_char,
    len: usize,
    time_step: u64,
    ttl: u64,
    step_secs: u64,
    charset: CCharset,
    skew_steps: u64,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if engine.is_null() || raw.is_null() {
        unsafe { set_error(error, "engine or raw code is null") };
        return OtpErrorCode::NullPointer;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    let raw_str = match unsafe { from_c_str(raw) } {
        Some(s) => s,
        None => {
            unsafe { set_error(error, "invalid raw code string") };
            return OtpErrorCode::InvalidString;
        }
    };
    let charset = Charset::from(charset);
    match engine.verify_with_skew(
        &raw_str, len, time_step, ttl, step_secs, charset, skew_steps,
    ) {
        Ok(()) => OtpErrorCode::Ok,
        Err(e) => {
            let err_str = e.to_string();
            unsafe { set_error(error, &err_str) };
            if err_str.contains("mismatch") {
                OtpErrorCode::VerificationFailed
            } else if err_str.contains("Expired") {
                OtpErrorCode::Expired
            } else {
                OtpErrorCode::VerificationFailed
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_engine_seed_hex(engine: *const COtpEngine) -> *mut c_char {
    if engine.is_null() {
        return ptr::null_mut();
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    to_c_string(&engine.seed().to_hex())
}
#[no_mangle]
pub extern "C" fn otp_engine_seed_bytes(
    engine: *const COtpEngine,
    out_bytes: *mut u8,
    out_len: usize,
) -> i32 {
    if engine.is_null() || out_bytes.is_null() {
        return -1;
    }
    if out_len < OTP_SEED_LEN {
        return -2;
    }
    let engine = unsafe { &*(engine as *const OtpEngine) };
    unsafe {
        ptr::copy_nonoverlapping(engine.seed().as_bytes().as_ptr(), out_bytes, OTP_SEED_LEN);
    }
    0
}
#[no_mangle]
pub extern "C" fn otp_code_as_str(code: *const COtpCode) -> *mut c_char {
    if code.is_null() {
        return ptr::null_mut();
    }
    let code = unsafe { &*(code as *const OtpCode) };
    to_c_string(code.as_str())
}
#[no_mangle]
pub extern "C" fn otp_code_born_at(code: *const COtpCode) -> u64 {
    if code.is_null() {
        return 0;
    }
    let code = unsafe { &*(code as *const OtpCode) };
    code.born_at()
}
#[no_mangle]
pub extern "C" fn otp_code_len(code: *const COtpCode) -> usize {
    if code.is_null() {
        return 0;
    }
    let code = unsafe { &*(code as *const OtpCode) };
    code.len()
}
#[no_mangle]
pub extern "C" fn otp_code_is_valid_at(code: *const COtpCode, ts: u64, ttl: u64) -> i32 {
    if code.is_null() {
        return 0;
    }
    let code = unsafe { &*(code as *const OtpCode) };
    if code.is_valid_at(ts, ttl) {
        1
    } else {
        0
    }
}
#[no_mangle]
pub extern "C" fn otp_code_clone(code: *const COtpCode) -> *mut COtpCode {
    if code.is_null() {
        return ptr::null_mut();
    }
    let code = unsafe { &*(code as *const OtpCode) };
    Box::into_raw(Box::new(code.clone())) as *mut COtpCode
}
#[no_mangle]
pub extern "C" fn otp_code_free(code: *mut COtpCode) {
    if !code.is_null() {
        unsafe {
            drop(Box::from_raw(code as *mut OtpCode));
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_seed_from_public_key(
    pk: *const c_char,
    out: *mut *mut COtpSeed,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if pk.is_null() || out.is_null() {
        unsafe { set_error(error, "public key or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let pk_str = match unsafe { from_c_str(pk) } {
        Some(s) => s,
        None => {
            unsafe { set_error(error, "invalid public key string") };
            return OtpErrorCode::InvalidString;
        }
    };
    let public_key = match PublicKey::new(pk_str) {
        Ok(pk) => pk,
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            return OtpErrorCode::InvalidPublicKey;
        }
    };
    match OtpSeed::from_public_key(&public_key) {
        Ok(seed) => {
            unsafe {
                *out = Box::into_raw(Box::new(seed)) as *mut COtpSeed;
            }
            OtpErrorCode::Ok
        }
        Err(e) => {
            unsafe { set_error(error, &e.to_string()) };
            OtpErrorCode::GenerationFailed
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_seed_from_bytes(
    bytes: *const u8,
    len: usize,
    out: *mut *mut COtpSeed,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if bytes.is_null() || out.is_null() {
        unsafe { set_error(error, "bytes or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    if len != OTP_SEED_LEN {
        unsafe { set_error(error, &format!("len must be {}, got {}", OTP_SEED_LEN, len)) };
        return OtpErrorCode::LengthMismatch;
    }
    let mut seed_bytes = [0u8; OTP_SEED_LEN];
    unsafe {
        ptr::copy_nonoverlapping(bytes, seed_bytes.as_mut_ptr(), OTP_SEED_LEN);
    }
    let seed = OtpSeed::from_bytes(seed_bytes);
    unsafe {
        *out = Box::into_raw(Box::new(seed)) as *mut COtpSeed;
    }
    OtpErrorCode::Ok
}
#[no_mangle]
pub extern "C" fn otp_seed_from_hex(
    hex: *const c_char,
    out: *mut *mut COtpSeed,
    error: *mut *mut c_char,
) -> OtpErrorCode {
    if hex.is_null() || out.is_null() {
        unsafe { set_error(error, "hex or output pointer is null") };
        return OtpErrorCode::NullPointer;
    }
    let hex_str = match unsafe { from_c_str(hex) } {
        Some(s) => s,
        None => {
            unsafe { set_error(error, "invalid hex string") };
            return OtpErrorCode::InvalidString;
        }
    };
    let bytes = match hex::decode(&hex_str) {
        Ok(b) => b,
        Err(e) => {
            unsafe {
                set_error(error, &format!("hex decode error: {}", e));
            }
            return OtpErrorCode::HexDecodeFailed;
        }
    };
    if bytes.len() != OTP_SEED_LEN {
        unsafe {
            set_error(
                error,
                &format!(
                    "decoded hex must be {} bytes, got {}",
                    OTP_SEED_LEN,
                    bytes.len()
                ),
            )
        };
        return OtpErrorCode::LengthMismatch;
    }
    let mut seed_bytes = [0u8; OTP_SEED_LEN];
    seed_bytes.copy_from_slice(&bytes);
    let seed = OtpSeed::from_bytes(seed_bytes);
    unsafe {
        *out = Box::into_raw(Box::new(seed)) as *mut COtpSeed;
    }
    OtpErrorCode::Ok
}
#[no_mangle]
pub extern "C" fn otp_seed_to_hex(seed: *const COtpSeed) -> *mut c_char {
    if seed.is_null() {
        return ptr::null_mut();
    }
    let seed = unsafe { &*(seed as *const OtpSeed) };
    to_c_string(&seed.to_hex())
}
#[no_mangle]
pub extern "C" fn otp_seed_to_bytes(
    seed: *const COtpSeed,
    out_bytes: *mut u8,
    out_len: usize,
) -> i32 {
    if seed.is_null() || out_bytes.is_null() {
        return -1;
    }
    if out_len < OTP_SEED_LEN {
        return -2;
    }
    let seed = unsafe { &*(seed as *const OtpSeed) };
    unsafe {
        ptr::copy_nonoverlapping(seed.as_bytes().as_ptr(), out_bytes, OTP_SEED_LEN);
    }
    0
}
#[no_mangle]
pub extern "C" fn otp_seed_clone(seed: *const COtpSeed) -> *mut COtpSeed {
    if seed.is_null() {
        return ptr::null_mut();
    }
    let seed = unsafe { &*(seed as *const OtpSeed) };
    Box::into_raw(Box::new(seed.clone())) as *mut COtpSeed
}
#[no_mangle]
pub extern "C" fn otp_seed_free(seed: *mut COtpSeed) {
    if !seed.is_null() {
        unsafe {
            drop(Box::from_raw(seed as *mut OtpSeed));
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}
#[no_mangle]
pub extern "C" fn otp_now_ts() -> u64 {
    crate::types::now_ts()
}
#[no_mangle]
pub extern "C" fn otp_calculate_time_step(ts: u64, step_secs: u64) -> u64 {
    if step_secs == 0 {
        return 0;
    }
    ts / step_secs
}
#[no_mangle]
pub extern "C" fn otp_validate_code(
    code: *const c_char,
    expected_len: usize,
    charset: CCharset,
) -> i32 {
    if code.is_null() {
        return 0;
    }
    let code_str = match unsafe { from_c_str(code) } {
        Some(s) => s,
        None => return 0,
    };
    let charset = Charset::from(charset);
    if code_str.len() != expected_len {
        return 0;
    }
    if charset.validate(&code_str) {
        1
    } else {
        0
    }
}
#[no_mangle]
pub extern "C" fn otp_charset_len(charset: CCharset) -> usize {
    Charset::from(charset).len()
}
#[no_mangle]
pub extern "C" fn otp_version() -> *mut c_char {
    to_c_string(env!("CARGO_PKG_VERSION"))
}
#[cfg(test)]
mod tests {
    use super::*;
    const TEST_PK: &str = "age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe";
    fn create_test_engine() -> *mut COtpEngine {
        let pk = CString::new(TEST_PK).unwrap();
        let mut engine: *mut COtpEngine = ptr::null_mut();
        let result = otp_engine_from_public_key(pk.as_ptr(), &mut engine, ptr::null_mut());
        assert_eq!(result, OtpErrorCode::Ok);
        assert!(!engine.is_null());
        engine
    }
    #[test]
    fn test_engine_from_public_key() {
        let engine = create_test_engine();
        otp_engine_free(engine);
    }
    #[test]
    fn test_engine_from_public_key_null() {
        let mut engine: *mut COtpEngine = ptr::null_mut();
        let mut error: *mut c_char = ptr::null_mut();
        let result = otp_engine_from_public_key(ptr::null(), &mut engine, &mut error);
        assert_eq!(result, OtpErrorCode::NullPointer);
        assert!(!error.is_null());
        otp_string_free(error);
    }
    #[test]
    fn test_engine_from_public_key_invalid() {
        let pk = CString::new("invalid-key").unwrap();
        let mut engine: *mut COtpEngine = ptr::null_mut();
        let mut error: *mut c_char = ptr::null_mut();
        let result = otp_engine_from_public_key(pk.as_ptr(), &mut engine, &mut error);
        assert_eq!(result, OtpErrorCode::InvalidPublicKey);
        assert!(!error.is_null());
        otp_string_free(error);
    }
    #[test]
    fn test_engine_from_seed_bytes() {
        let engine1 = create_test_engine();
        let mut seed_bytes = [0u8; 32];
        let result = otp_engine_seed_bytes(engine1, seed_bytes.as_mut_ptr(), 32);
        assert_eq!(result, 0);
        let mut engine2: *mut COtpEngine = ptr::null_mut();
        let result =
            otp_engine_from_seed_bytes(seed_bytes.as_ptr(), 32, &mut engine2, ptr::null_mut());
        assert_eq!(result, OtpErrorCode::Ok);
        let mut code1: *mut COtpCode = ptr::null_mut();
        let mut code2: *mut COtpCode = ptr::null_mut();
        otp_engine_generate(
            engine1,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code1,
            ptr::null_mut(),
        );
        otp_engine_generate(
            engine2,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code2,
            ptr::null_mut(),
        );
        let s1 = otp_code_as_str(code1);
        let s2 = otp_code_as_str(code2);
        let s1_str = unsafe { CStr::from_ptr(s1).to_str().unwrap() };
        let s2_str = unsafe { CStr::from_ptr(s2).to_str().unwrap() };
        assert_eq!(s1_str, s2_str);
        otp_string_free(s1);
        otp_string_free(s2);
        otp_code_free(code1);
        otp_code_free(code2);
        otp_engine_free(engine1);
        otp_engine_free(engine2);
    }
    #[test]
    fn test_engine_from_seed_hex() {
        let engine1 = create_test_engine();
        let hex = otp_engine_seed_hex(engine1);
        let mut engine2: *mut COtpEngine = ptr::null_mut();
        let result = otp_engine_from_seed_hex(hex, &mut engine2, ptr::null_mut());
        assert_eq!(result, OtpErrorCode::Ok);
        let mut code1: *mut COtpCode = ptr::null_mut();
        let mut code2: *mut COtpCode = ptr::null_mut();
        otp_engine_generate(
            engine1,
            8,
            2000,
            30,
            CCharset::AlphanumericUpper,
            &mut code1,
            ptr::null_mut(),
        );
        otp_engine_generate(
            engine2,
            8,
            2000,
            30,
            CCharset::AlphanumericUpper,
            &mut code2,
            ptr::null_mut(),
        );
        let s1 = otp_code_as_str(code1);
        let s2 = otp_code_as_str(code2);
        let s1_str = unsafe { CStr::from_ptr(s1).to_str().unwrap() };
        let s2_str = unsafe { CStr::from_ptr(s2).to_str().unwrap() };
        assert_eq!(s1_str, s2_str);
        otp_string_free(s1);
        otp_string_free(s2);
        otp_string_free(hex);
        otp_code_free(code1);
        otp_code_free(code2);
        otp_engine_free(engine1);
        otp_engine_free(engine2);
    }
    #[test]
    fn test_generate_numeric() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        let result = otp_engine_generate(
            engine,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        let s = otp_code_as_str(code);
        let s_str = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        assert_eq!(s_str.len(), 6);
        assert!(s_str.chars().all(|c| c.is_ascii_digit()));
        otp_string_free(s);
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_generate_alphanumeric() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        let result = otp_engine_generate(
            engine,
            8,
            1000,
            30,
            CCharset::AlphanumericUpper,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        let s = otp_code_as_str(code);
        let s_str = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        assert_eq!(s_str.len(), 8);
        assert!(s_str
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        otp_string_free(s);
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_generate_hex() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        let result = otp_engine_generate(
            engine,
            16,
            1000,
            30,
            CCharset::HexLower,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        let s = otp_code_as_str(code);
        let s_str = unsafe { CStr::from_ptr(s).to_str().unwrap() };
        assert_eq!(s_str.len(), 16);
        assert!(s_str
            .chars()
            .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase()));
        otp_string_free(s);
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_generate_invalid_length() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        let mut error: *mut c_char = ptr::null_mut();
        let result = otp_engine_generate(
            engine,
            3,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            &mut error,
        );
        assert_ne!(result, OtpErrorCode::Ok);
        assert!(!error.is_null());
        otp_string_free(error);
        let result = otp_engine_generate(
            engine,
            100,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            &mut error,
        );
        assert_ne!(result, OtpErrorCode::Ok);
        assert!(!error.is_null());
        otp_string_free(error);
        otp_engine_free(engine);
    }
    #[test]
    fn test_generate_default() {
        let engine = create_test_engine();
        let mut code1: *mut COtpCode = ptr::null_mut();
        let mut code2: *mut COtpCode = ptr::null_mut();
        otp_engine_generate_default(engine, 6, 1000, &mut code1, ptr::null_mut());
        otp_engine_generate(
            engine,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code2,
            ptr::null_mut(),
        );
        let s1 = otp_code_as_str(code1);
        let s2 = otp_code_as_str(code2);
        let s1_str = unsafe { CStr::from_ptr(s1).to_str().unwrap() };
        let s2_str = unsafe { CStr::from_ptr(s2).to_str().unwrap() };
        assert_eq!(s1_str, s2_str);
        otp_string_free(s1);
        otp_string_free(s2);
        otp_code_free(code1);
        otp_code_free(code2);
        otp_engine_free(engine);
    }
    #[test]
    fn test_generate_now() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        let result = otp_engine_generate_now(engine, 6, &mut code, ptr::null_mut());
        assert_eq!(result, OtpErrorCode::Ok);
        assert!(!code.is_null());
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_code_properties() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        otp_engine_generate(
            engine,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(otp_code_len(code), 6);
        assert_eq!(otp_code_born_at(code), 30000);
        assert_eq!(otp_code_is_valid_at(code, 30000, 30), 1);
        assert_eq!(otp_code_is_valid_at(code, 30029, 30), 1);
        assert_eq!(otp_code_is_valid_at(code, 30030, 30), 0);
        assert_eq!(otp_code_is_valid_at(code, 29999, 30), 0);
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_verify_raw_success() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        otp_engine_generate(
            engine,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        let code_str = otp_code_as_str(code);
        let result = otp_engine_verify_raw(
            engine,
            code_str,
            6,
            1000,
            3600,
            30,
            CCharset::Numeric,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        otp_string_free(code_str);
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_verify_raw_mismatch() {
        let engine = create_test_engine();
        let wrong_code = CString::new("000000").unwrap();
        let mut error: *mut c_char = ptr::null_mut();
        let result = otp_engine_verify_raw(
            engine,
            wrong_code.as_ptr(),
            6,
            1000,
            3600,
            30,
            CCharset::Numeric,
            &mut error,
        );
        assert_eq!(result, OtpErrorCode::VerificationFailed);
        assert!(!error.is_null());
        otp_string_free(error);
        otp_engine_free(engine);
    }
    #[test]
    fn test_verify_with_skew() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        otp_engine_generate(
            engine,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        let code_str = otp_code_as_str(code);
        let result = otp_engine_verify_with_skew(
            engine,
            code_str,
            6,
            1001,
            3600,
            30,
            CCharset::Numeric,
            1,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        otp_string_free(code_str);
        otp_code_free(code);
        otp_engine_free(engine);
    }
    #[test]
    fn test_verify_with_skew_too_large() {
        let engine = create_test_engine();
        let mut error: *mut c_char = ptr::null_mut();
        let code = CString::new("123456").unwrap();
        let result = otp_engine_verify_with_skew(
            engine,
            code.as_ptr(),
            6,
            1000,
            3600,
            30,
            CCharset::Numeric,
            11,
            &mut error,
        );
        assert_ne!(result, OtpErrorCode::Ok);
        assert!(!error.is_null());
        otp_string_free(error);
        otp_engine_free(engine);
    }
    #[test]
    fn test_code_clone() {
        let engine = create_test_engine();
        let mut code1: *mut COtpCode = ptr::null_mut();
        otp_engine_generate(
            engine,
            6,
            1000,
            30,
            CCharset::Numeric,
            &mut code1,
            ptr::null_mut(),
        );
        let code2 = otp_code_clone(code1);
        let s1 = otp_code_as_str(code1);
        let s2 = otp_code_as_str(code2);
        let s1_str = unsafe { CStr::from_ptr(s1).to_str().unwrap() };
        let s2_str = unsafe { CStr::from_ptr(s2).to_str().unwrap() };
        assert_eq!(s1_str, s2_str);
        otp_string_free(s1);
        otp_string_free(s2);
        otp_code_free(code1);
        otp_code_free(code2);
        otp_engine_free(engine);
    }
    #[test]
    fn test_seed_from_public_key() {
        let pk = CString::new(TEST_PK).unwrap();
        let mut seed: *mut COtpSeed = ptr::null_mut();
        let result = otp_seed_from_public_key(pk.as_ptr(), &mut seed, ptr::null_mut());
        assert_eq!(result, OtpErrorCode::Ok);
        let hex = otp_seed_to_hex(seed);
        let hex_str = unsafe { CStr::from_ptr(hex).to_str().unwrap() };
        assert_eq!(hex_str.len(), 64);
        otp_string_free(hex);
        otp_seed_free(seed);
    }
    #[test]
    fn test_seed_from_hex() {
        let pk = CString::new(TEST_PK).unwrap();
        let mut seed1: *mut COtpSeed = ptr::null_mut();
        otp_seed_from_public_key(pk.as_ptr(), &mut seed1, ptr::null_mut());
        let hex = otp_seed_to_hex(seed1);
        let mut seed2: *mut COtpSeed = ptr::null_mut();
        let result = otp_seed_from_hex(hex, &mut seed2, ptr::null_mut());
        assert_eq!(result, OtpErrorCode::Ok);
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        otp_seed_to_bytes(seed1, bytes1.as_mut_ptr(), 32);
        otp_seed_to_bytes(seed2, bytes2.as_mut_ptr(), 32);
        assert_eq!(bytes1, bytes2);
        otp_string_free(hex);
        otp_seed_free(seed1);
        otp_seed_free(seed2);
    }
    #[test]
    fn test_validate_code() {
        let valid_numeric = CString::new("123456").unwrap();
        let invalid_numeric = CString::new("12345a").unwrap();
        let valid_hex = CString::new("0123456789abcdef").unwrap();
        assert_eq!(
            otp_validate_code(valid_numeric.as_ptr(), 6, CCharset::Numeric),
            1
        );
        assert_eq!(
            otp_validate_code(invalid_numeric.as_ptr(), 6, CCharset::Numeric),
            0
        );
        assert_eq!(
            otp_validate_code(valid_hex.as_ptr(), 16, CCharset::HexLower),
            1
        );
        assert_eq!(
            otp_validate_code(valid_numeric.as_ptr(), 5, CCharset::Numeric),
            0
        );
    }
    #[test]
    fn test_charset_len() {
        assert_eq!(otp_charset_len(CCharset::Numeric), 10);
        assert_eq!(otp_charset_len(CCharset::AlphanumericUpper), 36);
        assert_eq!(otp_charset_len(CCharset::HexLower), 16);
    }
    #[test]
    fn test_now_ts() {
        let now = otp_now_ts();
        assert!(now > 1577836800);
        assert!(now < 4102444800);
    }
    #[test]
    fn test_calculate_time_step() {
        assert_eq!(otp_calculate_time_step(30000, 30), 1000);
        assert_eq!(otp_calculate_time_step(29999, 30), 999);
        assert_eq!(otp_calculate_time_step(0, 30), 0);
        assert_eq!(otp_calculate_time_step(100, 0), 0);
    }
    #[test]
    fn test_version() {
        let version = otp_version();
        assert!(!version.is_null());
        let version_str = unsafe { CStr::from_ptr(version).to_str().unwrap() };
        assert!(!version_str.is_empty());
        otp_string_free(version);
    }
    #[test]
    fn test_null_safety() {
        assert_eq!(otp_code_as_str(ptr::null()), ptr::null_mut());
        assert_eq!(otp_code_born_at(ptr::null()), 0);
        assert_eq!(otp_code_len(ptr::null()), 0);
        assert_eq!(otp_code_is_valid_at(ptr::null(), 0, 0), 0);
        assert_eq!(otp_code_clone(ptr::null()), ptr::null_mut());
        assert_eq!(otp_seed_to_hex(ptr::null()), ptr::null_mut());
        assert_eq!(otp_seed_to_bytes(ptr::null(), ptr::null_mut(), 0), -1);
        assert_eq!(otp_seed_clone(ptr::null()), ptr::null_mut());
        assert_eq!(otp_engine_seed_hex(ptr::null()), ptr::null_mut());
        assert_eq!(otp_engine_seed_bytes(ptr::null(), ptr::null_mut(), 0), -1);
        assert_eq!(otp_validate_code(ptr::null(), 0, CCharset::Numeric), 0);
    }
    #[test]
    fn test_double_free_safety() {
        let engine = create_test_engine();
        otp_engine_free(engine);
        otp_engine_free(engine);
    }
    #[test]
    fn test_edge_cases() {
        let engine = create_test_engine();
        let mut code: *mut COtpCode = ptr::null_mut();
        let result = otp_engine_generate(
            engine,
            OTP_MIN_CODE_LEN,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        assert_eq!(otp_code_len(code), OTP_MIN_CODE_LEN);
        otp_code_free(code);
        let result = otp_engine_generate(
            engine,
            OTP_MAX_CODE_LEN,
            1000,
            30,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        assert_eq!(otp_code_len(code), OTP_MAX_CODE_LEN);
        otp_code_free(code);
        let result = otp_engine_generate(
            engine,
            6,
            1000,
            OTP_MIN_STEP_SECS,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        otp_code_free(code);
        let result = otp_engine_generate(
            engine,
            6,
            1000,
            OTP_MAX_STEP_SECS,
            CCharset::Numeric,
            &mut code,
            ptr::null_mut(),
        );
        assert_eq!(result, OtpErrorCode::Ok);
        otp_code_free(code);
        let mut error: *mut c_char = ptr::null_mut();
        let result =
            otp_engine_generate(engine, 6, 1000, 0, CCharset::Numeric, &mut code, &mut error);
        assert_ne!(result, OtpErrorCode::Ok);
        otp_string_free(error);
        otp_engine_free(engine);
    }
    #[test]
    fn test_engine_seed_bytes_buffer_too_small() {
        let engine = create_test_engine();
        let mut buffer = [0u8; 16];
        let result = otp_engine_seed_bytes(engine, buffer.as_mut_ptr(), 16);
        assert_eq!(result, -2);
        otp_engine_free(engine);
    }
}
