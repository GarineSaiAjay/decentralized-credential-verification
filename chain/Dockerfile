# The optional on-chain worker (acvs-chain). Build from the repository root, because it compiles the
# backend's crypto.rs unchanged:   docker build -f chain/Dockerfile -t acvs-chain .
FROM rust:1-alpine@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS builder
# build-base, cmake and perl are needed by the TLS library's C code (aws-lc).
RUN apk add --no-cache musl-dev pkgconfig build-base cmake perl linux-headers
WORKDIR /usr/src/app
COPY chain/Cargo.toml chain/Cargo.lock chain/
RUN mkdir -p chain/src backend/src && echo "fn main() {}" > chain/src/main.rs \
    && cd chain && cargo build --release --locked && rm -rf src
COPY backend/src/crypto.rs backend/src/crypto.rs
COPY chain/src chain/src
RUN cd chain && touch src/main.rs && cargo build --release --locked

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 acvs \
    && adduser -S -u 10001 -G acvs -H -h /app -s /sbin/nologin acvs
WORKDIR /app
# Owned by root and not writable by the app user: the process can run the binary but never change it.
COPY --from=builder /usr/src/app/chain/target/release/acvs-chain /app/acvs-chain
USER 10001:10001
ENTRYPOINT ["./acvs-chain"]
CMD ["run"]
