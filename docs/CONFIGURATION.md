# Configuration Guide

This document provides a comprehensive reference for all configuration options available in `nonce-auth`.

## Server Configuration

### Server Builder Pattern

The `NonceServer` is configured using the builder pattern with the following methods:

```rust
use nonce_auth::{NonceServer, NonceConfig};
use std::time::Duration;
use std::sync::Arc;

// Complete server configuration example
let server = NonceServer::builder()
    .with_ttl(Duration::from_secs(600))         // Custom TTL (default: 300s)
    .with_time_window(Duration::from_secs(120)) // Custom time window (default: 60s)
    .with_storage(Arc::new(custom_storage))     // Custom storage backend
    .build_and_init()                           // Initialize storage and return server
    .await?;
```

#### Available Builder Methods

| Method | Description | Default |
|--------|-------------|---------|
| `with_ttl(Duration)` | Set nonce time-to-live duration | 5 minutes |
| `with_time_window(Duration)` | Set timestamp validation window | 1 minute |
| `with_storage(Arc<T>)` | Set custom storage backend | `MemoryStorage` |
| `build_and_init()` | Build and initialize server | - |

### Configuration Presets

Built-in configuration presets for common scenarios:

```rust
use nonce_auth::NonceConfig;

// Production: Balanced security and usability
let config = NonceConfig::production();
assert_eq!(config.default_ttl, Duration::from_secs(300));  // 5 minutes
assert_eq!(config.time_window, Duration::from_secs(60));   // 1 minute

// Development: Developer-friendly settings
let config = NonceConfig::development();
assert_eq!(config.default_ttl, Duration::from_secs(600));  // 10 minutes
assert_eq!(config.time_window, Duration::from_secs(120));  // 2 minutes

// High Security: Maximum security with shorter windows
let config = NonceConfig::high_security();
assert_eq!(config.default_ttl, Duration::from_secs(120));  // 2 minutes
assert_eq!(config.time_window, Duration::from_secs(30));   // 30 seconds

// Apply preset to server
let server = NonceServer::builder()
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### Configuration Validation and Monitoring

```rust
use nonce_auth::NonceConfig;

let config = NonceConfig::production();

// Get human-readable summary
println!("{}", config.summary());
// Output: "NonceConfig { TTL: 300s, Time Window: 60s }"

// Validate configuration and get warnings
let issues = config.validate();
if issues.is_empty() {
    println!("✓ Configuration is valid");
} else {
    println!("⚠ Configuration issues:");
    for issue in issues {
        println!("  - {}", issue);
    }
}
```

### Environment Variables

Configure defaults via environment variables:

```bash
# Set default TTL (in seconds)
export NONCE_AUTH_DEFAULT_TTL=600

# Set default time window (in seconds)  
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

```rust
// Use environment variables as defaults
let config = NonceConfig::from_env();
let server = NonceServer::builder()
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### Server Inspection and Management

Once created, the server provides methods for inspection and management:

```rust
// Inspect server configuration
println!("Server TTL: {:?}", server.ttl());
println!("Server time window: {:?}", server.time_window());

// Access storage backend for statistics
let stats = server.storage().get_stats().await?;
println!("Total nonce records: {}", stats.total_records);
println!("Storage backend: {}", stats.backend_info);

// Manual cleanup of expired nonces
let deleted_count = server.cleanup_expired_nonces(Duration::from_secs(300)).await?;
println!("Cleaned up {} expired nonces", deleted_count);
```

## Storage Backend Configuration

### Built-in Storage Backends

#### Memory Storage (Default)

```rust
use nonce_auth::NonceServer;

// Uses MemoryStorage by default - ideal for testing and single-instance apps
let server = NonceServer::builder()
    .build_and_init()
    .await?;
```

#### Custom Storage Implementation

Implement the `NonceStorage` trait for custom backends:

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage {
    // Your storage implementation details
}

#[async_trait]
impl NonceStorage for MyCustomStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Initialize storage (create tables, connections, etc.)
        Ok(())
    }

    async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
        // Retrieve nonce entry
        todo!()
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        // Store nonce with TTL
        todo!()
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        // Check if nonce exists (optimized version of get)
        todo!()
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        // Remove expired nonces, return count of deleted records
        todo!()
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        // Return storage statistics
        Ok(StorageStats {
            total_records: 0,
            backend_info: "Custom storage backend".to_string(),
        })
    }
}

// Use custom storage
let custom_storage = Arc::new(MyCustomStorage {});
let server = NonceServer::builder()
    .with_storage(custom_storage)
    .build_and_init()
    .await?;
```

See [SQLite example](../examples/sqlite_storage.rs) for a complete implementation.

## Client Configuration

### Basic Client Usage

```rust
use nonce_auth::NonceClient;

// Simple client with defaults (UUID v4 nonces, system time)
let client = NonceClient::new(b"my_secret");
let credential = client.credential_builder().sign(b"payload")?;
```

### Advanced Client Configuration

Use the builder pattern for full customization:

```rust
use nonce_auth::NonceClient;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

let client = NonceClient::builder()
    .with_secret(b"my_secret")
    .with_nonce_generator(|| {
        // Custom nonce generation strategy
        format!("api-req-{}", uuid::Uuid::new_v4())
    })
    .with_time_provider(|| {
        // Custom time source (e.g., NTP-synchronized)
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
    })
    .build();
```

#### Available Client Builder Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `with_secret(&[u8])` | Secret key bytes | Set shared secret (required) |
| `with_nonce_generator(F)` | `F: Fn() -> String` | Custom nonce generation function |
| `with_time_provider(F)` | `F: Fn() -> Result<u64, NonceError>` | Custom timestamp provider |
| `build()` | - | Build client (panics if no secret) |

### Client Configuration Examples

#### Testing with Fixed Values

```rust
// Deterministic values for testing
let test_client = NonceClient::builder()
    .with_secret(b"test_secret")
    .with_nonce_generator(|| "fixed-test-nonce".to_string())
    .with_time_provider(|| Ok(1234567890))
    .build();

let credential = test_client.credential_builder().sign(b"test")?;
assert_eq!(credential.nonce, "fixed-test-nonce");
assert_eq!(credential.timestamp, 1234567890);
```

#### Sequential Nonces

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

let counter = Arc::new(AtomicU64::new(0));
let counter_clone = counter.clone();

let client = NonceClient::builder()
    .with_secret(b"secret")
    .with_nonce_generator(move || {
        let id = counter_clone.fetch_add(1, Ordering::SeqCst);
        format!("seq-{:010}", id)
    })
    .build();

// Generates: seq-0000000000, seq-0000000001, seq-0000000002, ...
```

#### Custom Time Sources

```rust
// NTP-synchronized time or custom time source
let client = NonceClient::builder()
    .with_secret(b"secret")
    .with_time_provider(|| {
        // Your custom time implementation
        get_ntp_synchronized_time()
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("NTP error: {}", e)))
    })
    .build();
```

### Custom Signature Logic

#### Client-Side Custom Signing

```rust
let client = NonceClient::new(b"secret");

// Standard signing (recommended)
let credential = client.credential_builder().sign(b"payload")?;

// Custom signing with additional data
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(b"payload");
        mac.update(b"extra_context_data");  // Additional authenticated data
    })?;
```

## Credential Verification

### Basic Verification

```rust
// Standard verification
let result = server
    .credential_verifier(&credential)
    .with_secret(b"shared_secret")
    .verify(b"payload")
    .await;

match result {
    Ok(()) => println!("✓ Credential verified"),
    Err(e) => println!("✗ Verification failed: {}", e),
}
```

### Advanced Verification Options

```rust
// Verification with context isolation
let result = server
    .credential_verifier(&credential)
    .with_secret(user_secret)
    .with_context(Some("api_v1"))  // Context-specific nonce isolation
    .verify(payload)
    .await;

// Custom verification logic matching custom signing
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .with_context(Some("special_context"))
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(payload);
        mac.update(b"extra_context_data");  // Must match client-side logic
    })
    .await;
```

#### Available Verification Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `with_secret(&[u8])` | Secret key bytes | Set verification secret (required) |
| `with_context(Option<&str>)` | Context string | Set nonce isolation context |
| `verify(&[u8])` | Payload bytes | Standard verification |
| `verify_with<F>(F)` | MAC builder closure | Custom verification logic |

## Multi-Secret and Context Support

### Multi-User Authentication

```rust
let server = NonceServer::builder().build_and_init().await?;

// Different users with different secrets
let user1_secret = b"user1_key_12345";
let user2_secret = b"user2_key_67890";

// User 1 verification
server.credential_verifier(&user1_credential)
    .with_secret(user1_secret)
    .verify(payload)
    .await?;

// User 2 verification with same server instance
server.credential_verifier(&user2_credential)
    .with_secret(user2_secret)
    .verify(payload)
    .await?;
```

### Context Isolation

```rust
// Same nonce can be used across different contexts
let credential = client.credential_builder().sign(b"data")?;

// API v1 context
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v1"))
    .verify(b"data")
    .await?;  // ✓ Success

// API v2 context (same nonce, different context)
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v2"))
    .verify(b"data")
    .await?;  // ✓ Success

// Reuse in same context fails
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v1"))
    .verify(b"data")
    .await?;  // ✗ DuplicateNonce error
```

## Error Handling

### Error Types and Handling

```rust
use nonce_auth::NonceError;

match server.credential_verifier(&credential)
    .with_secret(secret)
    .verify(payload)
    .await
{
    Ok(()) => println!("✓ Verification successful"),
    
    Err(NonceError::DuplicateNonce) => {
        // Nonce already used - replay attack prevention
        println!("⚠ Nonce reuse detected - possible replay attack");
    },
    
    Err(NonceError::ExpiredNonce) => {
        // Nonce exceeded TTL
        println!("⚠ Nonce expired - client should generate new request");
    },
    
    Err(NonceError::InvalidSignature) => {
        // Signature verification failed
        println!("⚠ Invalid signature - check shared secret or request integrity");
    },
    
    Err(NonceError::TimestampOutOfWindow) => {
        // Timestamp outside allowed window
        println!("⚠ Request timestamp out of range - check clock synchronization");
    },
    
    Err(NonceError::DatabaseError(msg)) => {
        // Storage backend error
        println!("⚠ Storage error: {}", msg);
    },
    
    Err(NonceError::CryptoError(msg)) => {
        // Cryptographic operation error
        println!("⚠ Crypto error: {}", msg);
    },
}
```

## Performance and Security Considerations

### TTL Configuration Guidelines

| Use Case | Recommended TTL | Trade-offs |
|----------|----------------|------------|
| High-security APIs | 2-5 minutes | Better security, may impact UX |
| Standard web APIs | 5-10 minutes | Balanced security/usability |
| Development/testing | 10-30 minutes | Developer-friendly |
| Batch processing | 30-60 minutes | Accommodates longer processing |

### Time Window Guidelines

| Network Conditions | Recommended Window | Notes |
|-------------------|------------------|-------|
| Local/LAN | 30-60 seconds | Tight synchronization |
| Internet/WAN | 60-120 seconds | Account for network latency |
| Mobile/unstable | 120-300 seconds | Higher tolerance needed |

### Storage Backend Selection

| Backend | Use Case | Pros | Cons |
|---------|----------|------|------|
| MemoryStorage | Testing, single instance | Fast, simple | No persistence, no scaling |
| SQLite | Single instance, persistence needed | Persistent, reliable | No horizontal scaling |
| Redis | Multi-instance, high scale | Distributed, fast | Additional infrastructure |

### Security Best Practices

```rust
// Production-ready server configuration
let server = NonceServer::builder()
    .with_ttl(Duration::from_secs(300))     // 5-minute TTL
    .with_time_window(Duration::from_secs(60))  // 1-minute window
    .with_storage(Arc::new(persistent_storage)) // Use persistent storage
    .build_and_init()
    .await?;

// Regular cleanup to prevent storage bloat
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
    loop {
        interval.tick().await;
        if let Err(e) = server.cleanup_expired_nonces(Duration::from_secs(300)).await {
            eprintln!("Cleanup failed: {}", e);
        }
    }
});
```

## Complete Example: Production Setup

```rust
use nonce_auth::{NonceServer, NonceClient, NonceConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure server with production settings
    let config = NonceConfig::production();
    let server = NonceServer::builder()
        .with_ttl(config.default_ttl)
        .with_time_window(config.time_window)
        .with_storage(Arc::new(setup_persistent_storage().await?))
        .build_and_init()
        .await?;

    // 2. Configure client with custom nonce strategy
    let client = NonceClient::builder()
        .with_secret(b"production_secret_key")
        .with_nonce_generator(|| {
            format!("prod-{}-{}", 
                std::process::id(), 
                uuid::Uuid::new_v4())
        })
        .build();

    // 3. Regular maintenance
    let server_clone = server.clone();
    tokio::spawn(async move {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            cleanup_interval.tick().await;
            match server_clone.cleanup_expired_nonces(config.default_ttl).await {
                Ok(count) => println!("Cleaned up {} expired nonces", count),
                Err(e) => eprintln!("Cleanup error: {}", e),
            }
        }
    });

    // 4. Handle requests
    let payload = b"important_request_data";
    let credential = client.credential_builder().sign(payload)?;

    match server
        .credential_verifier(&credential)
        .with_secret(b"production_secret_key")
        .with_context(Some("api_v1"))
        .verify(payload)
        .await
    {
        Ok(()) => println!("✅ Request authenticated successfully"),
        Err(e) => eprintln!("❌ Authentication failed: {}", e),
    }

    Ok(())
}
```

This comprehensive configuration guide covers all available options in the nonce-auth library. For more examples, see the [examples directory](../examples/).