# Bitcoin Dojo — Cryptography Fundamentals Track

> A hands-on implementation of elliptic curve cryptography from first principles, written in Rust.

---

## Overview

<!-- Add a short description of what this project is and what motivated you to build it -->

---

## What I Built

This project walks through the full cryptographic stack that powers Bitcoin — built from scratch, layer by layer.

| Module | Topic | What It Does |
|--------|-------|--------------|
| `1.1` | Hashing & Randomness | SHA-256 hashing and cryptographically secure random number generation |
| `1.2` | Field Element | Arithmetic over a finite field — numbers mod a prime `p` |
| `1.3` | Scalar | Arithmetic mod the curve order `n` — the space where private keys live |
| `1.4` | Curve Point | Elliptic curve point addition and the double-and-add scalar multiplication algorithm |
| `1.5` | Secp256k1 | The specific curve parameters used by Bitcoin (`p`, `n`, `G`) |
| `1.6` | Keys | Private key and public key generation (`Q = d * G`) |
| `1.7` | ECDSA | Elliptic Curve Digital Signature Algorithm — sign and verify messages |

---

## Key Concepts Covered

<!-- Add your own notes or explanations for each concept -->

### Modular Arithmetic
<!-- What is the modulo operation? What did you learn? -->

### Finite Fields
<!-- What makes a set of integers form a field? Why must the modulus be prime? -->

### Fermat's Little Theorem
<!-- How does it help compute modular inverses? -->

### Mathematical Groups
<!-- What are the four group axioms? What is an Abelian group? -->

### Elliptic Curves
<!-- What is an elliptic curve? How do points form a group? -->

### Point Addition
<!-- Explain the three cases: secant line, tangent/doubling, vertical line -->

### Double-and-Add Algorithm
<!-- How does scalar multiplication work efficiently? -->

### Public Key Cryptography
<!-- What one-way function does scalar multiplication enable? -->

### ECDSA
<!-- How does signing work? How does verification work? What is RFC 6979? -->

---

## Project Structure

```
bitcoin_dojo/
├── src/
│   ├── lib.rs
│   └── ecc/
│       ├── constants.rs    # secp256k1 curve parameters (p, n, G)
│       ├── field.rs        # FieldElement — arithmetic mod p
│       ├── scalar.rs       # Scalar — arithmetic mod n
│       ├── curve.rs        # Point — elliptic curve point operations
│       ├── keys.rs         # PrivateKey / PublicKey
│       ├── ecdsa.rs        # sign() / verify() with RFC 6979
│       └── util.rs         # SHA-256, secure random
└── tests/
    └── ecc/
        ├── field_tests.rs
        ├── scalar_tests.rs
        ├── curve_tests.rs
        ├── keys_tests.rs
        ├── ecdsa_tests.rs
        └── util_tests.rs
```

---

## Running the Tests

```bash
# Run all tests
cargo test

# Run tests for a specific module
cargo test field
cargo test scalar
cargo test curve
cargo test ecdsa

# Run with output visible
cargo test -- --nocapture
```

---

## The Cryptographic Stack

```
┌─────────────────────────────────────────┐
│  1.7  ECDSA — sign() / verify()         │
├─────────────────────────────────────────┤
│  1.6  Keys — PrivateKey / PublicKey     │
├─────────────────────────────────────────┤
│  1.5  Secp256k1 — p, n, G constants     │
├─────────────────────────────────────────┤
│  1.4  Curve Point — add, double-and-add │
├─────────────────────────────────────────┤
│  1.3  Scalar — arithmetic mod n         │
├─────────────────────────────────────────┤
│  1.2  Field Element — arithmetic mod p  │
├─────────────────────────────────────────┤
│  1.1  Hashing & Randomness              │
└─────────────────────────────────────────┘
```

---

## Dependencies

```toml
[dependencies]
num-bigint = "0.4"
lazy_static = "1.4"
sha2 = "0.10"
hmac = "0.12"
rand = "0.9"
hex = "0.4"
```

---

## Key Takeaways

<!-- Add your personal reflections — what surprised you, what clicked, what was hard -->

---

## Real-World Applications

<!-- Where can you apply what you learned? Some ideas: -->

- Bitcoin / Ethereum transaction signing
- TLS/HTTPS certificate authentication
- SSH key-based authentication
- JWT token signing (ES256)
- Code signing and software verification
- Hardware wallet key management
- Zero-knowledge proof systems

---

## References

<!-- Add any books, articles, or resources that helped you -->

- [Programming Bitcoin — Jimmy Song](https://programmingbitcoin.com)
- [Bitcoin Whitepaper — Satoshi Nakamoto](https://bitcoin.org/bitcoin.pdf)
- [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)
- [RFC 6979 — Deterministic ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)

---

## Author

<!-- Your name / GitHub / links -->

---

## License

<!-- Add your chosen license -->
