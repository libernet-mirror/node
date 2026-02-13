# Libernet Node

## Prerequisites

To build & run the node you need [Rust](https://www.rust-lang.org/) and
[clang](https://clang.llvm.org/) installed.

You may optionally run it with [Docker](https://docker.com).

## Building & Running

Example command line for development and testing:

```sh
node/$ cargo run --release -- \
    --public-address=localhost \
    --grpc-port=4443 \
    --http-port=8080 \
    --chain-id=1337 \
    --latitude=0 \
    --longitude=0
```

Or, if you want to provide a specific secret key for the staking wallet:

```sh
node/$ cargo run --release -- \
    --secret-key=0x8744f79b0093d78d50363caf7a58274467218dced3dd68074d1d4e292ba3de9facf25f5d460aeb5bf772710a86b2a4c879f46a796f145f45f9f470b25d905f8d \
    --public-address=localhost \
    --grpc-port=4443 \
    --http-port=8080 \
    --chain-id=1337 \
    --latitude=0 \
    --longitude=0
```

> [!WARNING]
> do **NOT** use the above key
> `0x8744f79b0093d78d50363caf7a58274467218dced3dd68074d1d4e292ba3de9facf25f5d460aeb5bf772710a86b2a4c879f46a796f145f45f9f470b25d905f8d`
> for any purpose. It's obviously leaked. Any assets transferred to any accounts derived from that
> key will be **permanently lost**.

## Building & Running with Docker

The `Dockerfile` uses the following environment variables:

- `LIBERNET_SECRET_KEY`
- `LIBERNET_PUBLIC_ADDRESS`
- `LIBERNET_GRPC_PORT`
- `LIBERNET_HTTP_PORT`
- `LIBERNET_NETWORK_ID`
- `LIBERNET_LATITUDE`
- `LIBERNET_LONGITUDE`

Example commands:

```sh
node/$ sudo docker build . --tag libernet
node/$ sudo docker run \
    -e LIBERNET_SECRET_KEY=0x8744f79b0093d78d50363caf7a58274467218dced3dd68074d1d4e292ba3de9facf25f5d460aeb5bf772710a86b2a4c879f46a796f145f45f9f470b25d905f8d \
    -e LIBERNET_PUBLIC_ADDRESS=localhost \
    -e LIBERNET_GRPC_PORT=4443 \
    -e LIBERNET_HTTP_PORT=8080 \
    -e LIBERNET_NETWORK_ID=1337 \
    -e LIBERNET_LATITUDE=0 \
    -e LIBERNET_LONGITUDE=0 \
    -p 4443:4443 \
    libernet:latest
```
