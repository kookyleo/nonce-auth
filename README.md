# Nonce Auth

[![CI](https://github.com/kookyleo/nonce-auth/workflows/CI/badge.svg)](https://github.com/kookyleo/nonce-auth/actions)
[![Crates.io](https://img.shields.io/crates/v/nonce-auth.svg)](https://crates.io/crates/nonce-auth)
[![Documentation](https://docs.rs/nonce-auth/badge.svg)](https://docs.rs/nonce-auth)
[![License](https://img.shields.io/crates/l/nonce-auth.svg)](https://github.com/kookyleo/nonce-auth#license)

A lightweight, secure nonce-based authentication library for Rust, designed to prevent replay attacks in APIs and other services.

## Core Features

- **Replay Protection**: Employs nonces, timestamps, and HMAC-SHA256 signatures to ensure each request is unique and authentic.
- **Safe & Ergonomic API**: Uses a builder pattern (`credential_builder`) to guide developers towards safe usage, preventing common security pitfalls.
- **Async & Pluggable Storage**: Fully asynchronous design with a trait-based storage system, allowing for easy integration with backends like in-memory, SQLite, or Redis.

## Quick Start

```rust
use nonce_auth::{NonceClient, NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Shared secret and a payload to protect.
    let secret = b"my-super-secret-key";
    let payload = b"important_api_request_data";

    // 2. Create the server with a storage backend.
    let storage = Arc::new(MemoryStorage::new());
    let server = NonceServer::builder(secret, storage)
        .build_and_init()
        .await?;

    // 3. Create the client and generate a credential for the payload.
    let client = NonceClient::new(secret);
    let credential = client.credential_builder().sign(payload)?;
    println!("Generated credential: {:?}", credential);

    // 4. The server verifies the credential using the standard, symmetric method.
    let verification_result = server
        .credential_verifier(&credential)
        .verify(payload)
        .await;

    assert!(verification_result.is_ok());
    println!("✅ First verification successful!");

    // 5. Attempting to use the same credential again will fail.
    let replay_result = server
        .credential_verifier(&credential)
        .verify(payload)
        .await;

    assert!(replay_result.is_err());
    println!("✅ Replay attack correctly rejected!");

    Ok(())
}
```

## Configuration & Examples

- For detailed configuration of TTL, time windows, and storage backends, see [CONFIGURATION.md](CONFIGURATION.md).
- For more advanced usage, including a full web server implementation, see the [examples](examples/) directory.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.