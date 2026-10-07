# Bitcoin Wallet Lab

An interactive, educational Bitcoin wallet built on **testnet4**. Work through a live, step-by-step workflow — generate a wallet, receive coins from a faucet, build and broadcast a real transaction, then watch it confirm on-chain.

The cryptography (secp256k1 elliptic curve, ECDSA, RFC 6979) is implemented from scratch in the vendored `bitcoin_dojo` crate so you can read exactly what is happening at every layer.

---

## What You Can Do

- Generate a testnet wallet with all three address types from a single key
  - **P2PKH** (Legacy) — `m…` / `n…`
  - **P2SH-P2WPKH** (Nested SegWit) — `2…`
  - **P2WPKH** (Native SegWit) — `tb1q…`
- Receive free testnet coins from a faucet, with a QR code for every address type
- Pick which UTXOs to spend (coin control) and build a multi-input transaction (legacy or SegWit)
- Set the fee with **live mempool fee rates** or a custom sat/vByte rate. The tx size is estimated from the real number of inputs and output types, and a live breakdown shows inputs = amount + fee + change
- Change below the dust limit is never created — it is added to the fee, and the UI explains why
- Broadcast the transaction and follow it on a timeline: broadcast → mempool → 1 → 6 confirmations
- Explore a signature malleability demo (flipping `s → n − s`) — legacy TXIDs change, SegWit TXIDs don't (only the WTXID does)
- Light and dark themes, keyboard- and screen-reader-friendly UI

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust, [Axum](https://github.com/tokio-rs/axum), Tokio |
| Blockchain API | [mempool.space](https://mempool.space/testnet4) (Blockstream-compatible REST) |
| Cryptography | Custom `bitcoin_dojo` crate (vendored) |
| Frontend | Vanilla HTML / CSS / JavaScript |
| Deployment | Docker (multi-stage) |

---

## Project Structure

```
wallet_lab/
├── src/
│   ├── main.rs                  # Server startup, graceful shutdown
│   ├── app.rs                   # Router, security headers, CORS, body limit
│   ├── security.rs              # Rate limiting, client IP, param validation
│   ├── config.rs                # Env-var configuration
│   ├── error.rs                 # AppError → HTTP status mapping
│   ├── state.rs                 # Shared state (config + HTTP client)
│   ├── wallet/
│   │   ├── keygen.rs            # Wallet generation, WIF decode
│   │   └── signing.rs           # TX building, sighash, signing
│   ├── script/
│   │   ├── p2pkh.rs             # OP_DUP OP_HASH160 … OP_CHECKSIG
│   │   ├── p2sh.rs              # OP_HASH160 … OP_EQUAL
│   │   └── p2wpkh.rs            # OP_0 <20-byte-hash>
│   ├── blockstream/
│   │   └── client.rs            # fetch_utxos(), broadcast_tx()
│   ├── api/
│   │   ├── wallet_handlers.rs   # POST /api/wallet/create
│   │   ├── utxo_handlers.rs     # GET  /api/utxo/:address
│   │   ├── tx_handlers.rs       # POST /api/tx/build-and-send
│   │   ├── status_handlers.rs   # GET  /api/tx/:txid/status
│   │   ├── malleability_handlers.rs
│   │   └── lab_handler.rs       # GET  /api/lab/info
│   └── static/
│       ├── index.html
│       ├── app.js
│       └── style.css
└── vendor/bitcoin_dojo/         # From-scratch ECC + transaction library
    └── src/
        ├── ecc/
        │   ├── constants.rs     # secp256k1 p, n, G
        │   ├── field.rs         # FieldElement (mod p)
        │   ├── scalar.rs        # Scalar (mod n)
        │   ├── curve.rs         # EC point addition / doubling
        │   ├── keys.rs          # PrivateKey, PublicKey
        │   └── ecdsa.rs         # sign() / verify(), RFC 6979, low-S
        └── transaction/
            ├── tx.rs            # Tx struct, serialize, parse
            ├── tx_input.rs
            └── tx_output.rs
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/wallet/create` | Generate a new testnet wallet |
| `GET` | `/api/utxo/:address` | List UTXOs for an address |
| `POST` | `/api/tx/build-and-send` | Build, sign, and broadcast a transaction (one or more `inputs`) |
| `GET` | `/api/tx/:txid/status` | Confirmation status, tip height and confirmation count |
| `GET` | `/api/fees` | Recommended fee rates (sat/vB) from the mempool |
| `GET` | `/api/address/:address/validate` | Decode an address: type, network, dust limit |
| `POST` | `/api/demo/malleability` | Signature malleability demo |
| `GET` | `/api/lab/info` | Return the lab wallet address |
| `GET` | `/healthz` | Health check for the host (not rate limited) |

---

## Running Locally

**Requirements:** Rust 1.85+

```bash
git clone https://github.com/mwihoti/wallet_lab.git
cd wallet_lab
cargo run
```

Open `http://localhost:8080`.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `BLOCKSTREAM_URL` | `https://mempool.space/testnet4/api` | Blockchain API base URL |
| `LAB_WALLET_ADDRESS` | *(from `lab_wallet/wallet.json`)* | Shared lab wallet address |
| `RUST_LOG` | `wallet_lab=debug,info` | Log filter |
| `TRUST_PROXY` | auto (`true` on Render/Fly) | Read the client IP from `X-Forwarded-For`. Turn on behind any reverse proxy, or every visitor shares one rate-limit bucket |
| `ALLOWED_ORIGINS` | *(empty — same-origin only)* | Comma-separated origins allowed to call the API from another site |
| `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | `5` / `120` | General API limit per client IP |
| `RATE_LIMIT_TX_PER_MIN` / `RATE_LIMIT_TX_BURST` | `12` / `30` | Wallet creation + broadcast limit per client IP |

### Tests

```bash
cargo test
```

Covers address decoding, coin selection and dust handling, the BIP-143 sighash test vector, multi-input legacy and SegWit signing (every signature is verified), the malleability demo for both transaction formats, and the public-hosting protections (rate limits, headers, CORS, body limit, path validation) through the real router.

---

## Running with Docker

```bash
docker build -t wallet_lab .
docker run -p 8080:8080 \
  -e LAB_WALLET_ADDRESS="<testnet_address>" \
  wallet_lab
```

---

## Deploying Publicly

The app is built to be opened by anyone on the internet:

- **Rate limiting per client IP**: a general API limit, plus a stricter one for wallet creation and broadcasting. Clients over the limit get `429` with a `Retry-After` header. IPv6 clients are limited per /64.
- **Upstream caching**: fee rates (30 s) and block height (15 s) are cached, so many visitors don't multiply calls to mempool.space.
- **Security headers**: Content-Security-Policy, HSTS, `X-Frame-Options`, `nosniff`, and `Cache-Control: no-store` on API responses (they can contain a private key).
- **Same-origin API** by default (see `ALLOWED_ORIGINS`), a 64 KB request body limit, and validation of path parameters forwarded upstream.
- **`/healthz`** for the host's health check, and graceful shutdown on `SIGTERM`.

Always serve it over **HTTPS** — the browser sends the testnet private key to the server when signing.

### Render / Fly.io

Deploy from the `Dockerfile` and set the health check path to `/healthz`. Both platforms put the app behind their own proxy, which the app detects (`RENDER` / `FLY_APP_NAME`) and trusts for the client IP. HTTPS is automatic.

### Your own server (VPS)

Needs Docker with the Compose plugin and a domain whose DNS `A` record points at the server.

```bash
git clone https://github.com/mwihoti/wallet_lab.git && cd wallet_lab
cp .env.example .env        # set DOMAIN (and LAB_WALLET_ADDRESS if you have one)
```

**A. Nothing else uses ports 80/443** — use the bundled Caddy, which gets the HTTPS certificate automatically:

```bash
sudo ufw allow 80,443/tcp   # if you use ufw
docker compose --profile caddy up -d --build
```

**B. You already run a reverse proxy** (Nginx, Traefik, the one in front of n8n…) — start only the app and add a site to your proxy:

```bash
docker compose up -d --build   # app listens on 127.0.0.1:8080 only
```

```nginx
server {
    server_name lab.example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    # then: sudo certbot --nginx -d lab.example.com
}
```

The app trusts `X-Forwarded-For` (`TRUST_PROXY=1` in the compose file) and is bound to loopback, so only your proxy can reach it.

**Updating:** `git pull && docker compose up -d --build` (add `--profile caddy` for setup A).

**Small servers:** the Rust release build needs roughly 2 GB of memory. On a 1 GB VPS add swap first (`sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`).

> The rate limiter keeps its state in memory, so it is per instance. Run one instance, or put a shared limiter (e.g. at your proxy or CDN) in front if you scale out.

---

## How Fees Are Calculated

Fee inputs use a **sat/vByte rate** (presets come from mempool.space's recommended rates). The transaction size is estimated from its weight:

```
weight   = overhead + Σ input weight + Σ output size × 4
vbytes   = ceil(weight / 4)
fee      = ceil(fee_rate × vbytes)
```

| Spending from | Weight per input | ≈ vBytes |
|---------------|------------------|----------|
| P2PKH (Legacy) | 592 WU | 148 |
| P2SH-P2WPKH (Nested SegWit) | 364 WU | 91 |
| P2WPKH (Native SegWit) | 272 WU | 68 |

Outputs are 34 (P2PKH), 32 (P2SH) or 31 (P2WPKH) bytes. A 1-input, 2-output native SegWit payment is about 141 vB versus 226 vB for legacy. SegWit inputs are cheaper because witness data is discounted — only 1 weight unit per byte versus 4 for non-witness data.

### Dust

An output worth less than it costs to spend is **dust** and nodes refuse to relay it (546 sat for P2PKH, 540 for P2SH, 294 for P2WPKH). If the change would be below that, no change output is created and the leftover goes to the miner.

---

## Key Concepts Covered

### scriptPubKey vs scriptSig
`scriptPubKey` is the **lock** placed on an output by the sender. `scriptSig` is the **key** provided by the spender. The Bitcoin Script VM concatenates them (`scriptSig || scriptPubKey`) and executes the combined script. Every full node independently verifies the result.

### SegWit and Transaction Malleability
Legacy transactions include the signature inside the txid hash. Because valid alternative signatures exist (e.g. `s → n − s`), the txid could be changed by a third party without invalidating the payment. SegWit moves witness data outside the txid commitment, eliminating this vector.

### RFC 6979 Deterministic k
The signing nonce `k` is derived deterministically from the private key and message hash using HMAC-SHA256. This prevents catastrophic nonce reuse while remaining fully reproducible.

### Low-S Normalization (BIP-62)
After computing `s`, if `s > n/2` the value is replaced with `n − s`. Bitcoin's mempool enforces this rule; signatures with high-S values are rejected.

---

## Testnet Faucets

| Faucet | URL |
|--------|-----|
| mempool.space | https://mempool.space/testnet4/faucet |
| testnetbtc.com | https://testnetbtc.com |
| coinfaucet.eu | https://coinfaucet.eu/en/btc-testnet/ |

Testnet4 blocks arrive approximately every **10 minutes**. A transaction broadcast with 1 sat/vByte is typically confirmed within 1–3 blocks (10–30 minutes).

---

## License

MIT
