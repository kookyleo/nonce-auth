# Nonce Auth

![Nonce Auth Banner](docs/banner.png)

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
use nonce_auth::{NonceClient, NonceServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Shared secret between client and server
    let secret = b"my-super-secret-key";
    let payload = b"important_api_request_data";

    // Create server (defaults to in-memory storage)
    let server = NonceServer::builder(secret)
        .build_and_init()
        .await?;

    // Create client and generate a credential
    let client = NonceClient::new(secret);
    let credential = client.credential_builder().sign(payload)?;

    // Server verifies the credential
    let result = server
        .credential_verifier(&credential)
        .verify(payload)
        .await;
    
    assert!(result.is_ok());
    println!("✅ First verification successful!");

    // Replay attack is automatically rejected
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