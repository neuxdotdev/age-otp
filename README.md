# age-otp

Generate time-based OTP codes from [age](https://age-encryption.org) public keys – no shared secret required.

[![Crates.io](https://img.shields.io/crates/v/age-otp)](https://crates.io/crates/age-otp)
[![Docs](https://img.shields.io/docsrs/age-otp)](https://docs.rs/age-otp)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)

## Overview

`age-otp` derives deterministic one‑time passwords **solely from an age public key** (format `age1...`).  
Unlike standard TOTP (RFC 6238), there is **no shared secret** – the verifier only needs the user’s public key.

```
age1ysxuae... ──Bech32 decode──► [32‑byte X25519 key]
                                      │
                                      ▼
                              HKDF‑SHA256 ("age-otp-v1")
                                      │
                                      ▼
                              [32‑byte seed]
                                      │
                                      ▼
                              HMAC‑SHA256(time_step)
                                      │
                                      ▼
                              Dynamic truncation
                                      │
                                      ▼
                                  "123456"
```

### Why this matters

| Standard TOTP | age‑otp |
|---------------|---------|
| Requires shared secret | **Uses only public key** |
| Both parties must protect the secret | Verifier never sees a secret |
| Key rotation is painful | Just rotate the age keypair |
| Works with authenticator apps | Custom – integrate into your own auth service |

## Installation

```toml
[dependencies]
age-otp = "0.2"
```

## Quick Start

```rust
use age_otp::prelude::*;

fn main() -> Result<()> {
    // 1. Create a keypair (or load an existing one)
    let keypair = build_keypair()?;
    let public_key = &keypair.public;

    // 2. Build the OTP engine from the public key
    let engine = OtpEngine::from_public_key(public_key)?;

    // 3. Generate a 6‑digit numeric code for the current 30‑second window
    let now = now_ts();
    let step = now / 30;
    let code = engine.generate(6, step, 30, Charset::Numeric)?;
    println!("Your OTP: {}", code); // e.g. 847291

    // 4. Verify a user‑supplied code (with ±1 step clock skew)
    let user_input = "847291";
    let result = engine.verify_with_skew(
        user_input, 6, step, 30, 30, Charset::Numeric, 1,
    )?;
    assert!(result.is_ok());

    Ok(())
}
```

## API Reference

### Public re‑exports

The crate root (`age_otp`) re‑exports the most important items:

```rust
use age_otp::{
    // Key management (from age‑setup)
    PublicKey, build_keypair,
    // Core engine
    OtpEngine,
    // Data types
    OtpSeed, OtpCode, Charset,
    // Utility functions
    now_ts, compute_hmac, truncate, ct_eq,
    // Constants
    SEED_LEN, MIN_CODE_LEN, MAX_CODE_LEN,
    MIN_STEP_SECS, MAX_STEP_SECS, MAX_SKEW_STEPS,
    // Error types
    Error, KeyError, GenerationError, VerificationError, Result,
};
// Convenience prelude
use age_otp::prelude::*;
```

### `OtpEngine`

The main entry point.

#### Construction

| Method | Description |
|--------|-------------|
| `OtpEngine::from_public_key(pk: &PublicKey) -> Result<Self>` | Derives a seed from an age public key using HKDF‑SHA256. |
| `OtpEngine::from_seed(seed: OtpSeed) -> Self` | Builds the engine directly from a pre‑derived seed (skips HKDF). |
| `engine.seed()` | Returns a reference to the internal `OtpSeed`. |

#### Generation

| Method | Description |
|--------|-------------|
| `engine.generate(len, time_step, step_secs, charset) -> Result<OtpCode>` | Generates an OTP code of given length for a specific time window. |
| `engine.generate_default(len, time_step) -> Result<OtpCode>` | Shortcut for numeric, 30‑second step. |
| `engine.generate_now(len) -> Result<OtpCode>` | Generates a code for the **current** 30‑second window. |

#### Verification

| Method | Description |
|--------|-------------|
| `engine.verify(code: &OtpCode, time_step, ttl, step_secs, charset) -> Result<()>` | Verifies an `OtpCode` object. |
| `engine.verify_default(code: &OtpCode, time_step, ttl) -> Result<()>` | Shortcut for numeric, 30‑second step. |
| `engine.verify_raw(raw: &str, len, time_step, ttl, step_secs, charset) -> Result<()>` | Verifies a raw string. |
| `engine.verify_with_skew(raw: &str, len, time_step, ttl, step_secs, charset, skew_steps) -> Result<()>` | Verifies a raw string with clock skew tolerance (±`skew_steps` steps). |

### `OtpSeed`

A 32‑byte seed derived from a public key.

```rust
let pk: PublicKey = "age1...".parse()?;
let seed = OtpSeed::from_public_key(&pk)?;

seed.as_bytes();           // &[u8; 32]
seed.to_hex();             // 64‑character hex string (for debugging)

let seed2 = OtpSeed::from_bytes([0u8; 32]);   // create from raw bytes
```

> **Debug safety** – `Debug` only prints the first 8 hex characters.

### `OtpCode`

An OTP code together with its birth timestamp.

```rust
let code = OtpCode::new("123456".into(), time_step, step_secs)?;

code.as_str();              // "123456"
code.len();                 // 6
code.born_at();             // time_step * step_secs (UNIX seconds)

code.is_valid_at(current_ts, ttl); // true if current_ts is within [born, born+ttl)
```

> **Debug safety** – `Debug` masks the code (e.g. `12***`), `Display` shows the full code.

### `Charset`

Supported character sets for OTP codes.

| Variant | Characters | Base |
|---------|------------|------|
| `Charset::Numeric` | `0-9` | 10 |
| `Charset::AlphanumericUpper` | `0-9A-Z` | 36 |
| `Charset::HexLower` | `0-9a-f` | 16 |

```rust
let cs = Charset::Numeric;
assert_eq!(cs.len(), 10);
assert!(cs.validate("123456"));
assert!(!cs.validate("abc")); // wrong charset
```

### Constants

```rust
use age_otp::{SEED_LEN, MIN_CODE_LEN, MAX_CODE_LEN, MIN_STEP_SECS, MAX_STEP_SECS, MAX_SKEW_STEPS};
// SEED_LEN = 32
// MIN_CODE_LEN = 4, MAX_CODE_LEN = 64
// MIN_STEP_SECS = 1, MAX_STEP_SECS = 3600
// MAX_SKEW_STEPS = 10
```

### Utility functions

These are re‑exported at the crate root, but are also available under `age_otp::types`.

| Function | Signature | Purpose |
|----------|-----------|---------|
| `now_ts()` | `-> u64` | Current UNIX timestamp in seconds. |
| `compute_hmac` | `(seed: &[u8;32], step: u64) -> Result<[u8;32]>` | HMAC‑SHA256 of the step value. |
| `truncate` | `(hash: &[u8;32], charset: Charset, len: usize) -> Result<String>` | Dynamic truncation (HOTP‑style). |
| `ct_eq` | `(a: &[u8], b: &[u8]) -> bool` | Constant‑time slice comparison. |
| `validate_code_len` | `(len: usize) -> Result<()>` | Checks `len` is within `MIN_CODE_LEN..=MAX_CODE_LEN`. |
| `validate_step_secs` | `(secs: u64) -> Result<()>` | Checks step seconds are within bounds. |
| `validate_skew_steps` | `(skew: u64) -> Result<()>` | Checks skew steps ≤ `MAX_SKEW_STEPS`. |

## Error handling

All fallible operations return `Result<T, Error>`.  
`Error` is an enum:

```rust
pub enum Error {
    Key(KeyError),                // invalid public key
    Generation(GenerationError),  // HMAC failure, invalid parameters, overflow
    Verification(VerificationError), // mismatch, expired, invalid format
}
```

Sub‑errors:
- `KeyError` – `Empty`, `InvalidPrefix`, `Bech32Decode`, `InvalidDecodedLength`
- `GenerationError` – `HmacFailed`, `TruncateFailed`, `InvalidLength`, `Overflow`
- `VerificationError` – `Mismatch`, `Expired { expired_at, current }`, `InvalidFormat`

Example:

```rust
match engine.verify_raw("123456", 6, step, 30, 30, Charset::Numeric) {
    Ok(()) => println!("✓"),
    Err(Error::Verification(VerificationError::Mismatch)) => println!("✗ Wrong code"),
    Err(Error::Verification(VerificationError::Expired { .. })) => println!("⏰ Expired"),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Security

### ✅ What this library provides

- **No shared secrets** – OTP codes are derived from the **public** key only.
- **Proper key derivation** – The age public key is Bech32‑decoded first, then fed into HKDF‑SHA256. The original Bech32 string is **never** used as the HMAC key directly.
- **Constant‑time comparison** – All code comparisons use the `subtle` crate to prevent timing attacks.
- **Overflow safety** – All arithmetic uses checked operations (`checked_mul`, `saturating_add`).
- **Bounded parameters** – Code length, step seconds, and skew steps have hard limits to prevent abuse.
- **Debug protection** – `OtpSeed` shows only a short hex prefix; `OtpCode` masks the code.
- **Zeroization** – Secret keys (via `age‑setup`) are zeroized on drop.

### ⚠️ Deployment checklist

- **Use HTTPS** – OTP codes must be transmitted over encrypted channels.
- **Short TTL** – 30–60 seconds is recommended.
- **Rate limiting** – Throttle verification attempts to prevent brute force (library does **not** implement rate limiting).
- **Store the seed securely** – If you cache `OtpSeed`, treat it as sensitive (it can generate valid codes).
- **Do not log full OTP codes** – Use the `Debug` representation (masked) for logging.

### 🚫 Known limitations

- **Not TOTP compatible** – Does not follow RFC 6238; cannot be used with standard authenticator apps.
- **No replay protection** – A code remains valid for the entire TTL window. The application must enforce one‑time use if desired.
- **Single charset per code** – Characters cannot be mixed.

## Architecture

```
src/
├── lib.rs          # Crate root, re‑exports
├── engine.rs       # OtpEngine (generation & verification)
├── types.rs        # OtpSeed, OtpCode, Charset, constants, utility functions
└── error.rs        # Error and Result types
```

### Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| [age‑setup](https://crates.io/crates/age-setup) | 0.1 | Key pair generation, `PublicKey` type |
| [bech32](https://crates.io/crates/bech32) | 0.11 | Bech32 decoding with checksum |
| [hkdf](https://crates.io/crates/hkdf) | 0.12 | HKDF‑SHA256 key derivation |
| [hmac](https://crates.io/crates/hmac) | 0.12 | HMAC‑SHA256 for code generation |
| [sha2](https://crates.io/crates/sha2) | 0.10 | SHA‑256 hash function |
| [thiserror](https://crates.io/crates/thiserror) | 1.0 | Ergonomic error types |
| [subtle](https://crates.io/crates/subtle) | 2.5 | Constant‑time comparison |

## Examples

More runnable examples are in the [`examples/`](examples/) directory.  
Run them with:

```bash
cargo run --example main
```

## Testing

```bash
cargo test                  # run all unit & integration tests
cargo test --lib            # run only unit tests (inside src/)
cargo test --test engine_tests  # run integration tests only
```

## License

Licensed under either of

 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## References

- [age encryption spec](https://github.com/FiloSottile/age/blob/main/doc/age.1.md)
- [RFC 5869 – HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [BIP‑173 – Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
- [subtle crate](https://docs.rs/subtle/) – constant‑time operations