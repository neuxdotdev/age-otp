# age-otp

Generate OTP codes from age public keys.

## Overview

`age-otp` is a Rust library that derives time-based one-time password (OTP) codes from [age](https://age-encryption.org/) public keys. Unlike TOTP which requires shared secrets, this library derives OTP codes **entirely from the public key** — no shared secret needed.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                     User generates age keypair                          │
│                     (using rage or age-setup)                      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│              User shares public key (age1...) with admin         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Admin registers public key with AdminSession          │
│              → Gets API key for database storage                  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Your auth service (age-authenticator)               │
│                  uses OtpEngine to:                                 │
│                  1. Generate OTP code                              │
│                  2. Verify user's OTP code                        │
└─────────────────────────────────────────────────────────────────────┘

Internally:

```

age1ysxuae... ──Bech32 decode──► [32-byte X25519]
│
▼
HKDF-SHA256
│
▼
[32-byte seed]
│
▼
HMAC-SHA256(step)
│
▼
Dynamic truncation
│
▼
"123456"

````

### Key Difference from TOTP

| Aspect | TOTP | age-otp |
|--------|------|---------|
| Shared secret required | Yes | **No** |
| Key derivation | Shared secret | **Public key only** |
| Standard | RFC 6238 | Custom |
| Integration | Authenticator app | Admin generates API key from user's public key |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
age-otp = "0.2"
````

## Quick Start

```rust
use age_otp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Admin: Register user's public key
    let admin = AdminSession::new();
    let user_public_key = "age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe"
        .parse::<PublicKey>()?;

    let registration = admin.register(&user_public_key)?;
    let api_key = registration.api_key();

    // Store in database:
    // - api_key.key() → "aotp..."
    // - api_key.public_key() → for OTP generation later

    // 2. Generate OTP code
    let engine = OtpEngine::from_public_key(&user_public_key)?;

    let config = OtpConfig::builder()
        .code_length(6)
        .ttl_secs(30)
        .build()?;

    let time_step = now_ts() / config.time_step_secs();
    let otp = engine.generate(6, time_step, 30, Charset::Numeric)?;

    println!("OTP: {}", otp); // e.g., "847291"

    // 3. Verify user's OTP code
    let verifier = OtpVerifier::new(&engine);

    match verifier.verify_with_skew(
        "847291",
        6,
        time_step,
        30,
        30,
        Charset::Numeric,
        1, // allow 1 step skew
    )? {
        Ok(()) => println!("✓ Authenticated"),
        Err(Error::Verification(VerificationError::Mismatch)) => println!("✗ Wrong code"),
        Err(Error::Verification(VerificationError::Expired { .. })) => println!("⏰ Expired"),
        Err(e) => println!("✗ Error: {}", e),
    }

    Ok(())
}
```

## API Reference

### Constants

```rust
use age_otp::constants;

assert_eq!(constants::MIN_CODE_LEN, 4);
assert_eq!(constants::MAX_CODE_LEN, 64);
assert_eq!(constants::MIN_STEP_SECS, 1);
assert_eq!(constants::MAX_STEP_SECS, 3600);
assert_eq!(constants::MAX_SKEW_STEPS, 10);
assert_eq!(constants::SEED_LEN, 32);
```

### Charset

```rust
use age_otp::Charset;

let cs = Charset::Numeric;           // "0123456789"
let cs = Charset::AlphanumericUpper;  // "0-9, A-Z"
let cs = Charset::HexLower;           // "0-9, a-f"

assert_eq!(cs.len(), 10);
assert!(cs.validate("123456"));
assert!(!cs.validate("12345a")); // wrong charset
```

### OtpSeed

Derived 32-byte seed from public key using HKDF-SHA256.

```rust
use age_otp::OtpSeed;
use age_otp::PublicKey;

let pk: PublicKey = "age1...".parse()?;
let seed = OtpSeed::from_public_key(&pk)?;

// Get raw bytes (for caching if needed)
let bytes: &[u8; 32] = seed.as_bytes();

// Get hex representation (for debugging)
let hex: String = seed.to_hex();

// Create from cached bytes (skip HKDF derivation)
let seed = OtpSeed::from_bytes(bytes);
```

### OtpCode

Generated OTP code with metadata.

```rust
use age_otp::OtpCode;

let code = OtpCode::new("123456".into(), 1000, 30, 30).unwrap();

code.as_str();       // "123456"
code.len();         // 6
code.born_at();      // 30000 (time_step * step_secs)
code.expires_at();    // 30030
code.is_valid_at(30015, 30);  // true
code.is_valid_now();         // depends on current time
code.remaining_secs();    // Some(...) or None
```

### OtpEngine

Main engine for OTP generation and verification.

#### Creation

```rust
use age_otp::OtpEngine;
use age_otp::PublicKey;

// From public key (derives seed internally)
let engine = OtpEngine::from_public_key(&public_key)?;

// From pre-derived seed (skip HKDF)
let seed = OtpSeed::from_public_key(&public_key)?;
let engine = OtpEngine::from_seed(seed);
```

#### Generation

```rust
use age_otp::Charset;

// Full control
let code = engine.generate(
    6,      // length
    1000,   // time step
    30,     // step seconds
    Charset::Numeric,
)?;

// With defaults (numeric, 30s step)
let code = engine.generate_default(6, 1000)?;

// For current time
let code = engine.generate_now(6)?;
```

#### Verification

```rust
// Verify OtpCode object
engine.verify(&code, 1000, 30, 30, Charset::Numeric)?;

// With defaults
engine.verify_default(&code, 1000, 30)?;

// Verify raw string
engine.verify_raw("123456", 6, 1000, 30, 30, Charset::Numeric)?;

// With clock skew tolerance (checks ±N steps)
engine.verify_with_skew(
    "123456",
    6,        // length
    1000,     // expected time step
    30,       // TTL in seconds
    30,       // step seconds
    Charset::Numeric,
    1,        // skew steps (0-10)
)?;
```

### OtpConfig

Configuration builder with validation.

```rust
use age_otp::OtpConfig;

// Builder pattern
let config = OtpConfig::builder()
    .code_length(8)
    .charset(Charset::AlphanumericUpper)
    .ttl_secs(60)
    .time_step_secs(60)
    .skew_steps(2)
    .build()?;

// Accessors
config.code_length();      // 8
config.charset();         // AlphanumericUpper
config.ttl_secs();         // 60
config.time_step_secs();   // 60
config.skew_steps();       // 2

// Time step calculation
let step = config.time_step_for(16094567890);  // 53648593
let ts = config.timestamp_for(53648593);        // 1609457790

// Security metrics
let bits = config.security_bits(); // ~38 bits for 8-char alphanumeric
```

#### Presets

```rust
use age_otp::config::presets;

let standard = presets::standard_numeric();    // 6 digits, 30s TTL
let extended = presets::extended_numeric();    // 8 digits, 60s TTL
let alpha = presets::alphanumeric();        // 6 chars, 30s TTL, A-Z
let hex = presets::api_hex();                // 16 chars hex, 60s TTL
let base32 = presets::base32();            // 8 chars Base32, 30s TTL
let high_sec = presets::high_security();     // 10 chars, 30s TTL, 0 skew
```

### OtpVerificationResult

```rust
use age_otp::OtpVerificationResult;

match result {
    OtpVerificationResult::Valid => println!("✓"),
    OtpVerificationResult::Expired => println!("⏰"),
    OtpVerificationResult::InvalidCode => println!("✗"),
    OtpVerificationResult::InvalidFormat => println!("❌"),
}

result.is_valid();    // true/false
result.is_expired();   // true/false
result.is_error();     // true/false
```

### Re-exports from age-setup

```rust
use age_setup::{build_keypair, KeyPair, PublicKey, SecretKey};

let kp: KeyPair = build_keypair()?;
println!("Public: {}", kp.public);
// Secret: [REDACTED] (Display/Debug are redacted)

let pk: PublicKey = "age1...".parse()?;
let sk: SecretKey = "AGE-SECRET-KEY-1...".parse()?;
```

## Error Handling

```rust
use age_otp::{Error, Result};

match error {
    Error::Key(e) => {
        match e {
            KeyError::Empty => "Key is empty",
            KeyError::InvalidPrefix { expected, got } => {
                format!("Invalid prefix: expected '{}', got '{}'", expected, got)
            }
            KeyError::Bech32Decode(msg) => format!("Bech32 decode failed: {}", msg),
            KeyError::InvalidDecodedLength(len) => {
                format!("Invalid decoded length: expected 32 bytes, got {}", len)
            }
        }
    }
    Error::Generation(e) => {
        match e {
            GenerationError::HmacFailed => "HMAC computation failed",
            GenerationError::TruncateFailed(msg) => format!("Truncation failed: {}", msg),
            GenerationError::InvalidLength(msg) => format!("Invalid length: {}", msg),
            GenerationError::Overflow => "Overflow computing born time",
        }
    }
    Error::Verification(e) => {
        match e {
            VerificationError::Mismatch => "Code does not match",
            VerificationError::Expired { expired_at, current } => {
                format!("Code expired at {}, current {}", expired_at, current)
            }
            VerificationError::InvalidFormat(msg) => format!("Invalid format: {}", msg),
        }
    }
}
```

## Security Considerations

### ✅ What This Library Does Right

1. **No shared secrets required** — OTP codes derived entirely from public key
2. **Proper IKM for HKDF** — Uses decoded 32-byte X25519 key, not Bech32 string
3. **Constant-time verification** — Uses `subtle` crate to prevent timing attacks
4. **No panic on overflow** — All arithmetic uses checked operations
5. **DoS prevention** — Skew steps limited to max 10
6. **Memory safety** — Secret keys use zeroize (via age-setup)
7. **Debug safety** — OtpCode masks code, OtpSeed shows only hex prefix
8. **Input validation** — Strict bounds on all parameters

### ⚠️ What You Must Ensure

1. **Store API key securely** — It identifies the user, treat it as sensitive
2. **Use HTTPS** — Transmit OTP codes only over encrypted channels
3. **Short TTL** — Use 30-60 second TTL to limit exposure window
4. **Rate limiting** — Implement server-side rate limits on OTP verification
5. **Don't log OTP codes** — Even in debug mode, use masked output

### 🚫 Known Limitations

1. **Not TOTP compatible** — This is custom OTP, won't work with Google Authenticator
2. **No replay protection** — Same code valid for entire TTL window by design
3. **No brute-force protection** — Implement rate limiting on your server
4. **Single charset per code** — Can't mix character sets

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          lib.rs                                │
│  Re-exports: age-setup types + age-otp core types               │
└──────────────────────────────────────────────────────────────────────┘
        │
        ├── engine.rs ───────────────────────────────────────────┐
        │  OtpEngine struct                               │
        │  - from_public_key(pk) → Result<Self>        │
        │  - from_seed(seed) → Self                   │
        │  - generate(len, step, secs, charset) → OtpCode   │
        │  - verify variants                           │
        └──────────────────────────────────────────────────────┘
        │
        ├── types.rs ───────────────────────────────────────────────┐
        │  OtpSeed, OtpCode, Charset, constants           │
        │  decode_age_public_key()                       │
        │  compute_hmac(), truncate(), ct_eq()             │
        │  validate_code_len(), validate_step_secs()        │
        └──────────────────────────────────────────────────────┘
        │
        ├── config.rs ────────────────────────────────────────────┐
        │  OtpConfig, OtpConfigBuilder, presets           │
        └──────────────────────────────────────────────────────┘
        │
        └── error.rs ────────────────────────────────────────────┐
             Error, Result, KeyError,                    │
             GenerationError, VerificationError               │
             ConfigError                                │
        └──────────────────────────────────────────────────────┘
```

### Dependencies

| Crate                                           | Version | Purpose                         |
| ----------------------------------------------- | ------- | ------------------------------- |
| [age-setup](https://crates.io/crates/age-setup) | 0.1     | Key pair generation, key types  |
| [bech32](https://crates.io/crates/bech32)       | 0.11    | Bech32 decoding with checksum   |
| [hkdf](https://crates.io/crates/hkdf)           | 0.12    | HKDF-SHA256 key derivation      |
| [hmac](https://crates.io/crates/hmac)           | 0.12    | HMAC-SHA256 for code generation |
| [sha2](https://crates.io/crates/sha2)           | 0.10    | SHA-256 hash function           |
| [thiserror](https://crates.io/crates/thiserror) | 1.0     | Error derive macros             |
| [subtle](https://crates.io/crates/subtle)       | 2.5     | Constant-time comparison        |

### Minimal Dependencies

```toml
[dependencies]
age-otp = "0.2"

# Only pulls in:
# - age-setup (which depends on age, zeroize)
# - bech32, hkdf, hmac, sha2
# - thiserror, subtle
```

## Migration Guide

### From 0.1 to 0.2

```rust
// OLD (0.1) - Removed features
use age_otp::{AdminSession, ApiKey};

// NEW (0.2) - Core only
use age_otp::{OtpEngine, OtpSeed, Charset, OtpConfig};

// Admin logic now lives in your application
// API key generation is your responsibility
```

### Key Breaking Changes

| Change                    | Description                                   |
| ------------------------- | --------------------------------------------- |
| `AdminSession` removed    | Build your own admin logic                    |
| `ApiKey` removed          | Generate your own API keys                    |
| `OtpConfig.presets` moved | Use `age_otp::config::presets`                |
| Bech32 decoding fixed     | Now uses `Bech32` checksum (was `NoChecksum`) |

## Examples

### Basic Auth Flow

```rust
use age_otp::*;

fn authenticate(
    user_public_key: &str,
    user_otp_code: &str,
) -> Result<bool, Error> {
    let pk: PublicKey = user_public_key.parse()?;
    let engine = OtpEngine::from_public_key(&pk)?;
    let config = OtpConfig::default();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let step = now / config.time_step_secs();

    engine.verify_with_skew(
        user_otp_code,
        config.code_length(),
        step,
        config.ttl_secs(),
        config.time_step_secs(),
        config.charset(),
        config.skew_steps(),
    ).map(|_| true)
}

fn main() {
    let valid = authenticate(
        "age1...",
        "123456",
    ).unwrap();
}
```

### API Key Generation

```rust
use age_otp::{OtpEngine, OtpSeed, PublicKey};
use sha2::{Sha256, Digest};

fn generate_api_key(user_public_key: &PublicKey) -> String {
    let seed = OtpSeed::from_public_key(user_public_key).unwrap();

    // Custom derivation for API key (don't use OTP engine)
    let mut hasher = Sha256::new();
    hasher.update(b"age-otp-apikey-v2");
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();

    // Encode as base62 for URL-safe API keys
    let mut num = u128::from_be_bytes(hash);
    let mut result = String::with_capacity(32);
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while num > 0 {
        result.push(CHARS[(num % 62) as usize] as char);
        num /= 62;
    }

    format!("aotp{}", result)
}
```

### High Security Config

```rust
use age_otp::{OtpConfig, Charset};

let config = OtpConfig::builder()
    .code_length(10)
    .charset(Charset::AlphanumericUpper)
    .ttl_secs(30)
    .time_step_secs(30)
    .skew_steps(0)  // No tolerance for high-security
    .build()?;
```

### Custom Charset

```rust
use age_otp::Charset;

// Define your own charset
fn custom_generate(engine: &OtpEngine, step: u64) -> Result<String, Error> {
    let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let len = 8;

    let hash = engine.compute_hmac(engine.seed().as_bytes(), step)?;

    // Your custom truncation logic here
    let code = (u64::from_be_bytes(hash) % (chars.len() as u64).pow(len as u32))
        .to_string();

    Ok(code)
}
```

## Testing

```bash
# Run all tests
cargo test

# Run specific module
cargo test --lib types::tests::charset_numeric

# Run with output
cargo test -- --nocapture

# Run with coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin tarpaulin.toml
```

## License

MIT OR Apache-2.0

## References

- [age encryption specification](https://github.com/FiloSottile/age/blob/main/doc/age.1.md)
- [RFC 5869 - HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [BIP-173 - Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- [subtle crate - Constant-time operations](https://docs.rs/subtle/)