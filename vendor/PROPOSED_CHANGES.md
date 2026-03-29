# PROPOSED CHANGES — Exercise 2.4: Hashing Utilities

> **Scope:** Add `hash160` and `hash256` as standalone utility modules under `src/utils/`.  
> **Constraint:** No existing files are modified except `src/lib.rs` (one block added).  
> **Dependencies:** Both `sha2 = "0.10"` and `ripemd = "0.1"` are **already present** in `Cargo.toml` — no new entries needed.

---

## 1. Current State

```
bitcoin_dojo/
├── Cargo.toml          ← sha2, ripemd already declared ✅
├── src/
│   ├── lib.rs          ← needs one new `pub mod utils { … }` block
│   ├── ecc/
│   │   └── util.rs     ← already has a sha256() helper (for reference only)
│   └── utils/          ← exists but EMPTY ← target for new files
└── tests/
    └── utils/
        ├── mod.rs               ← already wires hash160_tests + hash256_tests
        ├── hash160_tests.rs     ← tests already written, waiting on impl
        └── hash256_tests.rs     ← tests already written, waiting on impl
```

**The tests are already wired.** Nothing in `tests/` needs to change. The only work is:

1. Create `src/utils/hash160.rs`
2. Create `src/utils/hash256.rs`
3. Register the `utils` module in `src/lib.rs`

---

## 2. Dependency Audit

| Crate   | Version | Already in Cargo.toml? | Purpose                    |
|---------|---------|------------------------|----------------------------|
| `sha2`  | `0.10`  | ✅ Yes (line 9)         | SHA-256 digest             |
| `ripemd`| `0.1`   | ✅ Yes (line 13)        | RIPEMD-160 digest          |

**No `cargo add` commands are needed.** Both crates follow the `digest` trait from the `RustCrypto` ecosystem, so their APIs are identical — `new()`, `update()`, `finalize()`.

---

## 3. File: `src/utils/hash160.rs` (NEW)

### What it does
`hash160(input)` = **RIPEMD160( SHA256( input ) )**

This is the standard Bitcoin public-key → address hash:
1. Run SHA-256 over the raw bytes → 32-byte intermediate digest.
2. Feed that 32-byte array into RIPEMD-160 → 20-byte final digest.
3. Return the 20 bytes as a fixed-size `[u8; 20]` array.

### Exact implementation logic

```rust
/// src/utils/hash160.rs

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

/// Performs HASH160: RIPEMD160(SHA256(input))
/// Commonly used in Bitcoin for deriving P2PKH addresses from public keys.
///
/// # Returns
/// A 20-byte array containing the HASH160 result.
pub fn hash160(input: &[u8]) -> [u8; 20] {
    // Step 1: SHA-256 over the input
    let sha256_digest: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    };

    // Step 2: RIPEMD-160 over the SHA-256 output
    let mut hasher = Ripemd160::new();
    hasher.update(&sha256_digest);
    hasher.finalize().into()
}
```

### Key design notes
- Both hashers are created fresh per call → **no shared mutable state**, function is **pure**.
- The intermediate `[u8; 32]` is stack-allocated → no heap allocation.
- `.finalize().into()` works because `GenericArray<u8, N>` implements `Into<[u8; N]>` in both `sha2` and `ripemd` 0.x crates.
- Return type `[u8; 20]` matches the test file's `Vec<[u8; 20]>` usage and the `assert_eq!(result.len(), 20)` assertions.

---

## 4. File: `src/utils/hash256.rs` (NEW)

### What it does
`hash256(data)` = **SHA256( SHA256( data ) )**

This is Bitcoin's "double hash", used in:
- Block header PoW target computation
- Transaction IDs (txid / wtxid)
- Base58Check checksums

### Exact implementation logic

```rust
/// src/utils/hash256.rs

use sha2::{Sha256, Digest};

/// Performs a double SHA-256 hash: SHA256(SHA256(data))
/// Used in Bitcoin for block headers, transaction IDs, and checksums.
///
/// # Returns
/// A 32-byte array containing the double SHA-256 hash.
pub fn hash256(data: &[u8]) -> [u8; 32] {
    // Step 1: First SHA-256 pass
    let first: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    };

    // Step 2: Second SHA-256 pass over the first digest
    let mut hasher = Sha256::new();
    hasher.update(&first);
    hasher.finalize().into()
}
```

### Key design notes
- Two **independent** hasher instances are used intentionally — reusing one hasher by calling `.reset()` would also work but is less readable. Fresh instances are idiomatic in RustCrypto.
- The test `test_hash256_is_double_sha256` verifies this against the existing `ecc::util::sha256` helper:

  ```rust
  let first_hash  = sha256(input);         // from ecc::util
  let manual      = sha256(&first_hash);   // second pass
  assert_eq!(hash256(input), manual);      // must match
  ```

  Your implementation must produce identical output to chaining `ecc::util::sha256` twice.
- The known-vector test for empty input expects:
  ```
  0x5d f6 e0 e2 76 13 59 d3 0a 82 75 05 8e 29 9f cc
  0x03 81 53 45 45 f5 5c f4 3e 41 98 3f 5d 4c 94 56
  ```
  This is the canonical `sha256(sha256(""))` value.

---

## 5. Edit: `src/lib.rs` (MODIFY — append one block)

The `utils` module must be declared so the compiler knows it exists and tests can import from it.

### Change to make

Add the following block **after the existing `pub mod ecc { … }` block**, before the `#[cfg(test)]` section:

```rust
pub mod utils {
    pub mod hash160;
    pub mod hash256;
}
```

### Before / After

```diff
  pub mod ecc {
      pub mod constants;
      pub mod util;
      pub mod field;
      pub mod scalar;
      pub mod curve;
      pub mod keys;
      pub mod ecdsa;
  }
+ pub mod utils {
+     pub mod hash160;
+     pub mod hash256;
+ }
  #[cfg(test)]
  mod tests {
```

---

## 6. File Tree After Changes

```
src/
├── lib.rs              ← MODIFIED (utils block added)
├── ecc/
│   └── …               ← unchanged
└── utils/
    ├── hash160.rs      ← NEW
    └── hash256.rs      ← NEW
```

---

## 7. Verification

Once implemented, run the full test suite with:

```bash
cargo test
```

Expected outcome — all tests in these modules pass:

| Test file                         | Tests                                          |
|-----------------------------------|------------------------------------------------|
| `tests/utils/hash160_tests.rs`    | `test_hash160_empty_input`                     |
|                                   | `test_hash160_known_vector`                    |
|                                   | `test_hash160_different_inputs`                |
|                                   | `test_hash160_bitcoin_example`                 |
|                                   | `test_hash160_deterministic`                   |
|                                   | `test_hash160_various_lengths`                 |
|                                   | `test_hash160_known_bitcoin_vectors`           |
| `tests/utils/hash256_tests.rs`    | `test_hash256_empty_input`                     |
|                                   | `test_hash256_known_values`                    |
|                                   | `test_hash256_different_inputs`                |
|                                   | `test_hash256_avalanche_effect`                |
|                                   | `test_hash256_consistency`                     |
|                                   | `test_hash256_various_lengths`                 |
|                                   | `test_hash256_is_double_sha256`                |
|                                   | `test_hash256_bitcoin_genesis_block`           |
|                                   | `test_hash256_zero_bytes`                      |
|                                   | `test_hash256_max_bytes`                       |
|                                   | `test_hash256_incremental_pattern`             |

Then submit with:

```bash
dojo-cli submit --exercise 2.4-hash-utilities
```

---

## 8. Summary of All Changes

| Action   | File                        | Why                                              |
|----------|-----------------------------|--------------------------------------------------|
| **NEW**  | `src/utils/hash160.rs`      | Core implementation of RIPEMD160(SHA256(data))   |
| **NEW**  | `src/utils/hash256.rs`      | Core implementation of SHA256(SHA256(data))      |
| **EDIT** | `src/lib.rs`                | Expose `pub mod utils` so tests can import it    |
| —        | `Cargo.toml`                | No changes — `sha2` + `ripemd` already present  |
| —        | `tests/utils/*`             | No changes — tests already fully written         |
