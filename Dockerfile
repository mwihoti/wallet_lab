# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN CARGO_BUILD_JOBS=1 RUSTFLAGS="-C codegen-units=1" cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/wallet_lab .
COPY src/static ./src/static

EXPOSE 8080
ENV PORT=8080

CMD ["./wallet_lab"]
