use age_otp::engine::OtpEngine;
use age_otp::types::{Charset, OtpCode, OtpSeed};
use age_otp::{Error, PublicKey, VerificationError};
const TEST_PK: &str = "age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe";
fn test_pk() -> PublicKey {
    PublicKey::new(TEST_PK.into()).unwrap()
}
fn test_engine() -> OtpEngine {
    OtpEngine::from_public_key(&test_pk()).unwrap()
}
fn now_step(step_secs: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now / step_secs
}
#[test]
fn create_engine_from_public_key() {
    let engine = OtpEngine::from_public_key(&test_pk());
    assert!(engine.is_ok());
}
#[test]
fn create_engine_from_seed() {
    let engine1 = test_engine();
    let seed = OtpSeed::from_public_key(&test_pk()).unwrap();
    let engine2 = OtpEngine::from_seed(seed);
    let c1 = engine1.generate(6, 1000, 30, Charset::Numeric).unwrap();
    let c2 = engine2.generate(6, 1000, 30, Charset::Numeric).unwrap();
    assert_eq!(c1.as_str(), c2.as_str());
}
#[test]
fn create_engine_invalid_key() {
    let bad_pk = PublicKey::new("invalid".into()).unwrap();
    let result = OtpEngine::from_public_key(&bad_pk);
    assert!(result.is_err());
}
#[test]
fn engine_debug_does_not_leak_seed() {
    let engine = test_engine();
    let debug = format!("{:?}", engine);
    assert!(!debug.contains(&engine.seed().to_hex()[8..]));
    assert!(debug.contains("hex_prefix"));
}
#[test]
fn different_keys_different_seeds() {
    let kp1 = age_otp::build_keypair().unwrap();
    let kp2 = age_otp::build_keypair().unwrap();
    let seed1 = OtpSeed::from_public_key(&kp1.public).unwrap();
    let seed2 = OtpSeed::from_public_key(&kp2.public).unwrap();
    assert_ne!(seed1.to_hex(), seed2.to_hex());
}
#[test]
fn generate_deterministic() {
    let engine = test_engine();
    let c1 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
    let c2 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
    assert_eq!(c1.as_str(), c2.as_str());
}
#[test]
fn generate_different_steps_produce_different_codes() {
    let engine = test_engine();
    let c1 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
    let c2 = engine.generate(6, 1001, 30, Charset::Numeric).unwrap();
    assert_ne!(c1.as_str(), c2.as_str());
}
#[test]
fn generate_different_keys_produce_different_codes() {
    let kp1 = age_otp::build_keypair().unwrap();
    let kp2 = age_otp::build_keypair().unwrap();
    let e1 = OtpEngine::from_public_key(&kp1.public).unwrap();
    let e2 = OtpEngine::from_public_key(&kp2.public).unwrap();
    let c1 = e1.generate(6, 1000, 30, Charset::Numeric).unwrap();
    let c2 = e2.generate(6, 1000, 30, Charset::Numeric).unwrap();
    assert_ne!(c1.as_str(), c2.as_str());
}
#[test]
fn generate_numeric_format() {
    let engine = test_engine();
    let code = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
    assert_eq!(code.len(), 6);
    assert!(Charset::Numeric.validate(code.as_str()));
}
#[test]
fn generate_alphanumeric_format() {
    let engine = test_engine();
    let code = engine
        .generate(8, 1000, 30, Charset::AlphanumericUpper)
        .unwrap();
    assert_eq!(code.len(), 8);
    assert!(Charset::AlphanumericUpper.validate(code.as_str()));
}
#[test]
fn generate_hex_format() {
    let engine = test_engine();
    let code = engine.generate(16, 1000, 30, Charset::HexLower).unwrap();
    assert_eq!(code.len(), 16);
    assert!(Charset::HexLower.validate(code.as_str()));
}
#[test]
fn generate_default_matches_explicit() {
    let engine = test_engine();
    let c1 = engine.generate_default(6, 1000).unwrap();
    let c2 = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
    assert_eq!(c1.as_str(), c2.as_str());
}
#[test]
fn generate_now_succeeds() {
    let engine = test_engine();
    let code = engine.generate_now(6);
    assert!(code.is_ok());
    assert_eq!(code.unwrap().len(), 6);
}
#[test]
fn code_born_at_is_correct() {
    let engine = test_engine();
    let code = engine.generate(6, 1000, 30, Charset::Numeric).unwrap();
    assert_eq!(code.born_at(), 30000);
}
#[test]
fn code_born_at_zero_step() {
    let engine = test_engine();
    let code = engine.generate(6, 0, 30, Charset::Numeric).unwrap();
    assert_eq!(code.born_at(), 0);
}
#[test]
fn code_validity_window() {
    let code = OtpCode::new("123456".into(), 100, 30).unwrap();
    assert!(code.is_valid_at(3000, 30));
    assert!(code.is_valid_at(3029, 30));
    assert!(!code.is_valid_at(3030, 30));
    assert!(!code.is_valid_at(2999, 30));
}
#[test]
fn code_zero_ttl_never_valid() {
    let code = OtpCode::new("123456".into(), 100, 30).unwrap();
    assert!(!code.is_valid_at(3000, 0));
}
#[test]
fn code_overflow_returns_error() {
    let result = OtpCode::new("123456".into(), u64::MAX, 2);
    assert!(matches!(
        result,
        Err(Error::Generation(age_otp::GenerationError::Overflow))
    ));
}
#[test]
fn code_debug_masks_value() {
    let code = OtpCode::new("123456".into(), 100, 30).unwrap();
    let debug = format!("{:?}", code);
    assert!(!debug.contains("123456"));
    assert!(debug.contains("12***"));
}
#[test]
fn code_display_shows_value() {
    let code = OtpCode::new("123456".into(), 100, 30).unwrap();
    assert_eq!(format!("{code}"), "123456");
}
#[test]
fn code_as_ref_works() {
    let code = OtpCode::new("123456".into(), 100, 30).unwrap();
    assert_eq!(code.as_ref(), "123456");
}
#[test]
fn seed_from_bytes_roundtrip() {
    let bytes = [42u8; 32];
    let seed = OtpSeed::from_bytes(bytes);
    assert_eq!(seed.as_bytes(), &bytes);
}
#[test]
fn seed_to_hex_length() {
    let seed = OtpSeed::from_public_key(&test_pk()).unwrap();
    assert_eq!(seed.to_hex().len(), 64);
}
#[test]
fn seed_to_hex_valid_chars() {
    let seed = OtpSeed::from_public_key(&test_pk()).unwrap();
    assert!(seed.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
}
#[test]
fn seed_debug_no_leak() {
    let seed = OtpSeed::from_public_key(&test_pk()).unwrap();
    let debug = format!("{:?}", seed);
    assert!(!debug.contains(&seed.to_hex()[8..]));
    assert!(debug.contains("hex_prefix"));
}
#[test]
fn reject_code_len_zero() {
    let engine = test_engine();
    let err = engine.generate(0, 1000, 30, Charset::Numeric).unwrap_err();
    assert!(err.to_string().contains("code length must be"));
}
#[test]
fn reject_code_len_too_short() {
    let engine = test_engine();
    let err = engine.generate(3, 1000, 30, Charset::Numeric).unwrap_err();
    assert!(err.to_string().contains("code length must be"));
}
#[test]
fn reject_code_len_too_long() {
    let engine = test_engine();
    let err = engine.generate(65, 1000, 30, Charset::Numeric).unwrap_err();
    assert!(err.to_string().contains("code length must be"));
}
#[test]
fn accept_code_len_min() {
    let engine = test_engine();
    assert!(engine.generate(4, 1000, 30, Charset::Numeric).is_ok());
}
#[test]
fn accept_code_len_max() {
    let engine = test_engine();
    let code = engine.generate(64, 1000, 30, Charset::Numeric).unwrap();
    assert_eq!(code.len(), 64);
    assert!(Charset::Numeric.validate(code.as_str()));
}
#[test]
fn reject_step_secs_zero() {
    let engine = test_engine();
    let err = engine.generate(6, 1000, 0, Charset::Numeric).unwrap_err();
    assert!(err.to_string().contains("step_secs must be"));
}
#[test]
fn reject_step_secs_too_large() {
    let engine = test_engine();
    let err = engine
        .generate(6, 1000, 3601, Charset::Numeric)
        .unwrap_err();
    assert!(err.to_string().contains("step_secs must be"));
}
#[test]
fn reject_step_secs_u64_max() {
    let engine = test_engine();
    assert!(
        engine
            .generate(6, 1000, u64::MAX, Charset::Numeric)
            .is_err()
    );
}
#[test]
fn accept_step_secs_min() {
    let engine = test_engine();
    assert!(engine.generate(6, 1000, 1, Charset::Numeric).is_ok());
}
#[test]
fn accept_step_secs_max() {
    let engine = test_engine();
    assert!(engine.generate(6, 1000, 3600, Charset::Numeric).is_ok());
}
#[test]
fn verify_raw_valid_code() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let result = engine.verify_raw(code.as_str(), 6, step, 60, 30, Charset::Numeric);
    assert!(result.is_ok());
}
#[test]
fn verify_raw_wrong_code_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let err = engine
        .verify_raw("000000", 6, step, 60, 30, Charset::Numeric)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Verification(VerificationError::Mismatch)
    ));
}
#[test]
fn verify_raw_wrong_length_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let err = engine
        .verify_raw("12345", 6, step, 60, 30, Charset::Numeric)
        .unwrap_err();
    assert!(err.to_string().contains("expected length"));
}
#[test]
fn verify_raw_wrong_charset_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let err = engine
        .verify_raw("abcdef", 6, step, 60, 30, Charset::Numeric)
        .unwrap_err();
    assert!(err.to_string().contains("invalid charset"));
}
#[test]
fn verify_raw_invalid_step_secs_rejects() {
    let engine = test_engine();
    assert!(
        engine
            .verify_raw("123456", 6, 1000, 60, 0, Charset::Numeric)
            .is_err()
    );
}
#[test]
fn verify_with_skew_exact_match() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let result = engine.verify_with_skew(code.as_str(), 6, step, 60, 30, Charset::Numeric, 0);
    assert!(result.is_ok());
}
#[test]
fn verify_with_skew_adjacent_step_plus_one() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let result = engine.verify_with_skew(code.as_str(), 6, step + 1, 60, 30, Charset::Numeric, 1);
    assert!(result.is_ok());
}
#[test]
fn verify_with_skew_adjacent_step_minus_one() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let result = engine.verify_with_skew(code.as_str(), 6, step - 1, 60, 30, Charset::Numeric, 1);
    assert!(result.is_ok());
}
#[test]
fn verify_with_skew_beyond_range_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let err = engine
        .verify_with_skew(code.as_str(), 6, step + 5, 60, 30, Charset::Numeric, 1)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Verification(VerificationError::Mismatch)
    ));
}
#[test]
fn verify_with_skew_too_large_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let err = engine
        .verify_with_skew("123456", 6, step, 60, 30, Charset::Numeric, 11)
        .unwrap_err();
    assert!(err.to_string().contains("skew_steps must be"));
}
#[test]
fn verify_with_skew_wrong_length_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let err = engine
        .verify_with_skew("123", 6, step, 60, 30, Charset::Numeric, 1)
        .unwrap_err();
    assert!(err.to_string().contains("expected length"));
}
#[test]
fn verify_with_skew_wrong_charset_rejects() {
    let engine = test_engine();
    let step = now_step(30);
    let err = engine
        .verify_with_skew("abcdef", 6, step, 60, 30, Charset::Numeric, 1)
        .unwrap_err();
    assert!(err.to_string().contains("invalid charset"));
}
#[test]
fn verify_with_skew_max_allowed() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let result = engine.verify_with_skew(code.as_str(), 6, step, 1200, 30, Charset::Numeric, 10);
    assert!(result.is_ok());
}
#[test]
fn verify_handle_valid() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate(6, step, 30, Charset::Numeric).unwrap();
    let result = engine.verify(&code, step, 60, 30, Charset::Numeric);
    assert!(result.is_ok());
}
#[test]
fn verify_handle_default_valid() {
    let engine = test_engine();
    let step = now_step(30);
    let code = engine.generate_default(6, step).unwrap();
    let result = engine.verify_default(&code, step, 60);
    assert!(result.is_ok());
}
#[test]
fn charset_numeric_validate() {
    let cs = Charset::Numeric;
    assert!(cs.validate("123456"));
    assert!(!cs.validate("12345a"));
    assert!(!cs.validate(""));
    assert_eq!(cs.len(), 10);
}
#[test]
fn charset_alphanumeric_validate() {
    let cs = Charset::AlphanumericUpper;
    assert!(cs.validate("ABC123"));
    assert!(!cs.validate("abc123"));
    assert!(!cs.validate("ABC!23"));
    assert_eq!(cs.len(), 36);
}
#[test]
fn charset_hex_validate() {
    let cs = Charset::HexLower;
    assert!(cs.validate("0123456789abcdef"));
    assert!(!cs.validate("ABCDEF"));
    assert!(!cs.validate("ghij"));
    assert_eq!(cs.len(), 16);
}
#[test]
fn decode_valid_public_key() {
    let seed = OtpSeed::from_public_key(&test_pk());
    assert!(seed.is_ok());
    assert_eq!(seed.unwrap().to_hex().len(), 64);
}
#[test]
fn decode_empty_key_rejects() {
    let bad_pk = PublicKey::new("".into()).unwrap();
    assert!(OtpSeed::from_public_key(&bad_pk).is_err());
}
#[test]
fn decode_invalid_prefix_rejects() {
    let bad_pk = PublicKey::new("ssh-rsa AAAA".into()).unwrap();
    assert!(OtpSeed::from_public_key(&bad_pk).is_err());
}
#[test]
fn decode_invalid_bech32_rejects() {
    let bad_pk = PublicKey::new("age1!!!!invalid!!!".into()).unwrap();
    assert!(OtpSeed::from_public_key(&bad_pk).is_err());
}
#[test]
fn hmac_deterministic() {
    let seed = [1u8; 32];
    let h1 = age_otp::types::compute_hmac(&seed, 100).unwrap();
    let h2 = age_otp::types::compute_hmac(&seed, 100).unwrap();
    assert_eq!(h1, h2);
}
#[test]
fn hmac_different_steps_differ() {
    let seed = [1u8; 32];
    let h1 = age_otp::types::compute_hmac(&seed, 100).unwrap();
    let h2 = age_otp::types::compute_hmac(&seed, 101).unwrap();
    assert_ne!(h1, h2);
}
#[test]
fn ct_eq_equal() {
    assert!(age_otp::types::ct_eq(b"hello", b"hello"));
}
#[test]
fn ct_eq_not_equal() {
    assert!(!age_otp::types::ct_eq(b"hello", b"world"));
}
#[test]
fn ct_eq_different_lengths() {
    assert!(!age_otp::types::ct_eq(b"hi", b"hello"));
}
#[test]
fn ct_eq_empty() {
    assert!(age_otp::types::ct_eq(b"", b""));
}
#[test]
fn truncate_produces_correct_length() {
    let hash = [0xABu8; 32];
    for len in [4, 6, 8, 16, 32, 64] {
        let code = age_otp::types::truncate(&hash, Charset::Numeric, len).unwrap();
        assert_eq!(code.len(), len);
    }
}
#[test]
fn truncate_respects_charset() {
    let hash = [0x42u8; 32];
    let numeric = age_otp::types::truncate(&hash, Charset::Numeric, 8).unwrap();
    let hex = age_otp::types::truncate(&hash, Charset::HexLower, 16).unwrap();
    assert!(Charset::Numeric.validate(&numeric));
    assert!(Charset::HexLower.validate(&hex));
}
#[test]
fn truncate_rejects_too_short() {
    let hash = [0u8; 32];
    assert!(age_otp::types::truncate(&hash, Charset::Numeric, 3).is_err());
}
#[test]
fn truncate_rejects_too_long() {
    let hash = [0u8; 32];
    assert!(age_otp::types::truncate(&hash, Charset::Numeric, 100).is_err());
}
#[test]
fn now_ts_reasonable() {
    let now = age_otp::types::now_ts();
    assert!(now > 1577836800);
    assert!(now < 4102444800);
}
