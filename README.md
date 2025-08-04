# Nonce Auth

![Nonce Auth Banner](docs/banner.png)

[![CI](https://github.com/kookyleo/nonce-auth/workflows/CI/badge.svg)](https://github.com/kookyleo/nonce-auth/actions)
[![Crates.io](https://img.shields.io/crates/v/nonce-auth.svg)](https://crates.io/crates/nonce-auth)
[![Documentation](https://docs.rs/nonce-auth/badge.svg)](https://docs.rs/nonce-auth)
[![License](https://img.shields.io/crates/l/nonce-auth.svg)](https://github.com/kookyleo/nonce-auth#license)

A lightweight, secure nonce-based authentication library for Rust, designed to prevent replay attacks in APIs and other services.

## Core Features

- **🛡️ Replay Protection**: Combines nonces, timestamps, and HMAC-SHA256 signatures to ensure each request is unique and authentic
- **🚀 Simple & Ergonomic**: Clean builder pattern API that guides developers towards secure usage
- **⚡ Async & Pluggable**: Fully asynchronous with pluggable storage backends (Memory, Redis, SQLite, etc.)
- **🔧 Flexible Configuration**: Customizable TTL, time windows, nonce generation, and secret management

## Quick Start

```bash
cargo add nonce-auth tokio
```

### Quick Start

```rust
use nonce_auth::{CredentialBuilder, CredentialVerifier, storage::MemoryStorage, storage::NonceStorage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Shared secret between credential creator and verifier
    let secret = b"my-super-secret-key";
    let payload = b"important_api_request_data";

    // Create storage backend (in-memory for this example)
    let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());

    // 1. Create a credential
    let credential = CredentialBuilder::new(secret)
        .sign(payload)?;

    println!("✅ Generated credential with nonce: {}", credential.nonce);

    // 2. Verify the credential
    CredentialVerifier::new(Arc::clone(&storage))
        .with_secret(secret)
        .verify(&credential, payload)
        .await?;

    println!("✅ First verification successful!");

    // 3. Replay attack is automatically rejected
    let replay_result = CredentialVerifier::new(storage)
        .with_secret(secret)
        .verify(&credential, payload)
        .await;

    assert!(replay_result.is_err());
    println!("✅ Replay attack correctly rejected!");

    Ok(())
}
```

For more advanced usage, see [`examples`](examples/) and [User Guide](docs/USERGUIDE.md).

## Storage Backends

- **Memory** (`MemoryStorage`): Fast, built-in, perfect for single-instance applications
- **Redis** (`RedisStorage`): Distributed, production-ready, with connection pooling (feature: `redis-storage`)
- **SQLite** (`SQLiteStorage`): Supports WAL mode, with connection pooling (feature: `sqlite-storage`)
- **Custom**: Implement `NonceStorage` trait for your own backend

## Configuration

The library provides several configuration approaches:

- **Presets**: `ConfigPreset::Production`, `ConfigPreset::Development`, `ConfigPreset::HighSecurity`
- **Environment Variables**: `NONCE_AUTH_STORAGE_TTL`, `NONCE_AUTH_DEFAULT_TIME_WINDOW`
- **Custom Configuration**: Fine-grained control via builder methods

For detailed configuration options, see [User Guide](docs/USERGUIDE.md).

## Examples

- [`simple.rs`](examples/simple.rs) - Basic credential creation and verification
- [`web.rs`](examples/web.rs) - Web demo
- [`sqlite_storage.rs`](examples/sqlite_storage.rs) - SQLite storage backend
- [`redis_example.rs`](examples/redis_example.rs) - Redis with connection pooling
- [`performance_test.rs`](examples/performance_test.rs) - Performance benchmarking

## Documentation

- [Complete User Guide](docs/USERGUIDE.md) - Comprehensive API documentation
- [API Documentation](https://docs.rs/nonce-auth) - Generated API docs

## Security Features

- **HMAC-SHA256** signatures for tamper detection
- **Timestamp validation** with configurable time windows
- **Nonce uniqueness** enforcement to prevent replay attacks
- **Context isolation** for multi-tenant applications
- **Constant-time comparisons** to prevent timing attacks

## Performance

- **Zero-copy verification** where possible
- **Async-first design** for high concurrency
- **Connection pooling** for Redis backend
- **Batch operations** for improved throughput
- **Configurable cleanup strategies** for optimal memory usage

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.