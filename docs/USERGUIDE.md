# Nonce Auth - User Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Concepts](#core-concepts)
3. [API Reference](#api-reference)
4. [Storage System](#storage-system)
5. [Configuration Options](#configuration-options)
6. [Error Handling](#error-handling)
7. [Usage Patterns](#usage-patterns)
8. [Performance Guide](#performance-guide)
9. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Usage

```rust
use nonce_auth::{CredentialBuilder, CredentialVerifier, MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"your-secret-key";
    let payload = b"hello world";
    
    // Create storage
    let storage = Arc::new(MemoryStorage::new());
    
    // Generate credential
    let credential = CredentialBuilder::new(secret)
        .sign(payload)?;
    
    // Verify credential
    CredentialVerifier::new(storage)
        .with_secret(secret)
        .verify(&credential, payload)
        .await?;
    
    println!("Verification successful!");
    Ok(())
}
```

### Adding Dependencies

#### Basic Configuration (Memory storage only)

```toml
[dependencies]
nonce-auth = "0.5"
tokio = { version = "1.0", features = ["full"] }
```

#### Full Feature Configuration

```toml
[dependencies]
nonce-auth = { 
    version = "0.5", 
    features = [
        "redis-storage",
        "sqlite-storage", 
        "metrics"
    ] 
}
tokio = { version = "1.0", features = ["full"] }
```

## Core Concepts

### NonceCredential Structure

```rust
pub struct NonceCredential {
    pub timestamp: u64,     // Unix timestamp (seconds)
    pub nonce: String,      // Unique random identifier
    pub signature: String,  // Base64 encoded signature
}
```

### Workflow

1. **Generate Credential**: Use `CredentialBuilder` to create a credential containing timestamp, nonce, and signature
2. **Transmit Credential**: Send the credential along with request data
3. **Verify Credential**: Use `CredentialVerifier` to verify signature and check nonce uniqueness
4. **Prevent Replay**: Used nonces are stored to prevent reuse

## API Reference

### CredentialBuilder

Builder for creating signed credentials.

#### Constructor Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `new(secret: &[u8]) -> Self` | Create builder with secret key |
| `with_nonce_generator` | `with_nonce_generator<F>(self, generator: F) -> Self` | Set custom nonce generator |
| `with_time_provider` | `with_time_provider<F>(self, provider: F) -> Self` | Set custom time provider |

#### Signing Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `sign` | `sign(self, payload: &[u8]) -> Result<NonceCredential, NonceError>` | Sign single payload |
| `sign_structured` | `sign_structured(self, components: &[&[u8]]) -> Result<NonceCredential, NonceError>` | Sign multiple components |
| `sign_with` | `sign_with<F>(self, mac_fn: F) -> Result<NonceCredential, NonceError>` | Sign with custom MAC function |

### CredentialVerifier

Verifier for validating credentials.

#### Constructor Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `new(storage: Arc<dyn NonceStorage>) -> Self` | Create verifier with storage backend |
| `with_secret` | `with_secret(mut self, secret: &[u8]) -> Self` | Set verification key |
| `with_context` | `with_context(mut self, context: Option<&str>) -> Self` | Set context identifier |
| `with_storage_ttl` | `with_storage_ttl(mut self, ttl: Duration) -> Self` | Set storage TTL |
| `with_time_window` | `with_time_window(mut self, window: Duration) -> Self` | Set time window |

#### Verification Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `verify` | `verify(mut self, credential: &NonceCredential, payload: &[u8]) -> Result<(), NonceError>` | Verify single payload |
| `verify_structured` | `verify_structured(mut self, credential: &NonceCredential, components: &[&[u8]]) -> Result<(), NonceError>` | Verify multiple components |
| `verify_with` | `verify_with<F>(mut self, credential: &NonceCredential, mac_fn: F) -> Result<(), NonceError>` | Verify with custom MAC function |

### Function Types

```rust
// Nonce generation function
pub type NonceGeneratorFn = Box<dyn Fn() -> String + Send + Sync>;

// Time provider function
pub type TimeProviderFn = Box<dyn Fn() -> Result<u64, NonceError> + Send + Sync>;
```

## Storage System

### NonceStorage Trait

Core trait that all storage backends must implement:

```rust
#[async_trait]
pub trait NonceStorage: Send + Sync {
    // Initialize storage (optional)
    async fn init(&self) -> Result<(), NonceError>;
    
    // Get nonce entry
    async fn get(&self, nonce: &str, context: Option<&str>) 
        -> Result<Option<NonceEntry>, NonceError>;
    
    // Store nonce
    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) 
        -> Result<(), NonceError>;
    
    // Check if nonce exists
    async fn exists(&self, nonce: &str, context: Option<&str>) 
        -> Result<bool, NonceError>;
    
    // Clean up expired entries
    async fn cleanup_expired(&self, cutoff_time: i64) 
        -> Result<usize, NonceError>;
    
    // Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats, NonceError>;
}
```

### NonceEntry

Stored nonce entry:

```rust
pub struct NonceEntry {
    pub nonce: String,              // Nonce value
    pub created_at: i64,            // Creation timestamp
    pub context: Option<String>,    // Optional context
}
```

### StorageStats

Storage statistics:

```rust
pub struct StorageStats {
    pub total_records: usize,   // Total record count
    pub backend_info: String,   // Backend information description
}
```

### Built-in Storage Backends

#### MemoryStorage

Memory storage implementation, suitable for development and testing:

```rust
use nonce_auth::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
```

#### RedisStorage (requires `redis-storage` feature)

```rust
#[cfg(feature = "redis-storage")]
use nonce_auth::RedisStorage;

let storage = RedisStorage::new("redis://localhost:6379", "myapp")?;
```

#### SQLiteStorage (requires `sqlite-storage` feature)

```rust
#[cfg(feature = "sqlite-storage")]
use nonce_auth::SQLiteStorage;

let storage = SQLiteStorage::new("nonces.db").await?;
```

## Configuration Options

### NonceConfig

Core configuration structure:

```rust
pub struct NonceConfig {
    pub storage_ttl: Duration,    // Storage TTL
    pub time_window: Duration,    // Time window tolerance
}
```

### ConfigPreset

Preset configuration options:

```rust
pub enum ConfigPreset {
    Production,     // Production environment configuration
    Development,    // Development environment configuration
    HighSecurity,   // High security configuration
    FromEnv,        // Read from environment variables
}
```

#### Preset Configuration Comparison

| Preset | Storage TTL | Time Window | Use Case |
|--------|-------------|-------------|----------|
| `Production` | 300s | 30s | Production environment |
| `Development` | 600s | 60s | Development testing |
| `HighSecurity` | 60s | 10s | High security requirements |

### Using Configuration

```rust
use nonce_auth::{NonceConfig, ConfigPreset};
use std::time::Duration;

// Use preset
let config = NonceConfig::from_preset(ConfigPreset::Production);

// Custom configuration
let config = NonceConfig {
    storage_ttl: Duration::from_secs(300),
    time_window: Duration::from_secs(30),
};
```

## Error Handling

### NonceError

All possible error types:

```rust
pub enum NonceError {
    DuplicateNonce,                 // Nonce already exists
    InvalidSignature,               // Invalid signature
    TimestampOutOfWindow,           // Timestamp out of window
    StorageError(Box<dyn Error>),   // Storage error
    CryptoError(String),            // Cryptographic error
}
```

### Error Classification

| Error Type | Description | Severity | Handling Advice |
|------------|-------------|----------|-----------------|
| `DuplicateNonce` | Nonce reuse | High | Regenerate credential |
| `InvalidSignature` | Signature verification failed | High | Check key configuration |
| `TimestampOutOfWindow` | Timestamp out of allowed range | Medium | Check system time |
| `StorageError` | Storage system error | High | Check storage connection |
| `CryptoError` | Cryptographic operation failed | High | Check algorithm configuration |

### Error Handling Best Practices

```rust
use nonce_auth::NonceError;

match verifier.verify(&credential, payload).await {
    Ok(()) => println!("Verification successful"),
    Err(NonceError::DuplicateNonce) => {
        println!("Replay attack detected");
    },
    Err(NonceError::InvalidSignature) => {
        println!("Signature verification failed, possible key mismatch");
    },
    Err(NonceError::TimestampOutOfWindow) => {
        println!("Timestamp out of allowed range");
    },
    Err(NonceError::StorageError(e)) => {
        println!("Storage error: {}", e);
    },
    Err(e) => println!("Other error: {}", e),
}
```

## Usage Patterns

### Web API Integration

```rust
use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::Json as ResponseJson,
};
use nonce_auth::{CredentialVerifier, NonceCredential};

#[derive(serde::Deserialize)]
struct AuthenticatedRequest {
    auth: NonceCredential,
    data: serde_json::Value,
}

async fn authenticate_request(
    State(verifier): State<Arc<CredentialVerifier>>,
    Json(request): Json<AuthenticatedRequest>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    let payload = serde_json::to_vec(&request.data)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    verifier.clone()
        .verify(&request.auth, &payload)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    Ok(ResponseJson(serde_json::json!({
        "status": "success",
        "data": request.data
    })))
}
```

### Custom Nonce Generation

```rust
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

let custom_generator = Box::new(|| {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("nonce_{:016x}", id)
});

let credential = CredentialBuilder::new(secret)
    .with_nonce_generator(custom_generator)
    .sign(payload)?;
```

### Multi-tenant Support

```rust
use std::collections::HashMap;

struct MultiTenantAuth {
    verifiers: HashMap<String, Arc<CredentialVerifier>>,
}

impl MultiTenantAuth {
    pub async fn authenticate(
        &self,
        tenant_id: &str,
        credential: &NonceCredential,
        payload: &[u8],
    ) -> Result<(), NonceError> {
        let verifier = self.verifiers.get(tenant_id)
            .ok_or_else(|| NonceError::CryptoError("Unknown tenant".to_string()))?;
        
        verifier.clone()
            .with_context(Some(tenant_id))
            .verify(credential, payload)
            .await
    }
}
```

## Performance Guide

### Performance Benchmarks

| Operation | Average Latency | Throughput | Memory Usage |
|-----------|-----------------|------------|--------------|
| Credential generation | 50μs | 20,000 ops/s | 1KB/op |
| Memory storage verification | 80μs | 12,500 ops/s | 2KB/op |
| Redis storage verification | 2ms | 500 ops/s | 1KB/op |

### Optimization Recommendations

1. **Use connection pooling**: For Redis/SQLite storage
2. **Batch operations**: For high throughput scenarios
3. **Set reasonable TTL**: Balance security and performance
4. **Regular cleanup**: Prevent memory leaks

### Monitoring Metrics

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    pub total_verifications: AtomicU64,
    pub successful_verifications: AtomicU64,
    pub failed_verifications: AtomicU64,
}
```

## Troubleshooting

### Common Issues

#### Signature Verification Failure

**Symptoms**: Receiving `InvalidSignature` error

**Causes**:
- Key mismatch
- Inconsistent payload data
- Incorrect timestamp or nonce

**Solutions**:
```rust
// Verify key consistency
use sha2::{Sha256, Digest};

fn verify_key_consistency(key1: &[u8], key2: &[u8]) -> bool {
    let hash1 = Sha256::digest(key1);
    let hash2 = Sha256::digest(key2);
    hash1 == hash2
}
```

#### Time Synchronization Issues

**Symptoms**: Receiving `TimestampOutOfWindow` error

**Solutions**:
- Synchronize system clocks
- Increase time window tolerance
- Use NTP service

#### Storage Connection Issues

**Symptoms**: Receiving `StorageError`

**Solutions**:
- Check storage service status
- Verify connection configuration
- Implement retry mechanism

### Debugging Tools

#### Enable Debug Logging

```rust
use tracing::{info, warn, error, debug};
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

#### Diagnostic Helper Functions

```rust
pub fn check_time_sync(credential: &NonceCredential) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let diff = (now as i64 - credential.timestamp as i64).abs();
    diff <= 300 // 5-minute tolerance
}
```

---
