# -------- Build stage --------
FROM rust:1.93-slim-bookworm AS builder

WORKDIR /libernet

RUN apt-get update && apt-get install -y \
    clang \
    build-essential \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release

# -------- Runtime stage --------
FROM debian:bookworm-slim

WORKDIR /libernet

COPY --from=builder /libernet/target/release/node /usr/local/bin/node

RUN useradd -r -u 1001 libernet
USER libernet

EXPOSE 4443

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/node \
    --secret-key=$LIBERNET_SECRET_KEY \
    --public-address=$LIBERNET_PUBLIC_ADDRESS \
    --grpc-port=$LIBERNET_GRPC_PORT \
    --http-port=$LIBERNET_HTTP_PORT \
    --chain-id=$LIBERNET_NETWORK_ID \
    --latitude=$LIBERNET_LATITUDE \
    --longitude=$LIBERNET_LONGITUDE"]
