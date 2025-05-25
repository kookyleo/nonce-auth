//! # Nonce Auth
//!
//! A Rust library for secure nonce-based authentication that prevents replay attacks.
//!
//! This library provides a complete solution for implementing nonce-based authentication
//! in client-server applications. It uses HMAC-SHA256 signatures and SQLite for persistent
//! nonce storage to ensure that each request can only be used once.
//!
//! ## Features
//!
//! - **HMAC-SHA256 Signing**: Cryptographic signing of requests using shared secrets
//! - **Replay Attack Prevention**: Each nonce can only be used once
//! - **Time Window Validation**: Requests outside the time window are rejected
//! - **Context Isolation**: Nonces can be scoped to different business contexts
//! - **SQLite Persistence**: Automatic nonce storage and cleanup
//! - **Async Support**: Fully asynchronous API design
//! - **Client-Server Separation**: Clean separation of client and server responsibilities
//!
//! ## Quick Start
//!
//! ### Basic Usage
//!
//! ```rust
//! use nonce_auth::{NonceClient, NonceServer};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize the database
//! NonceServer::init().await?;
//!
//! // Create client and server with shared secret
//! let secret = b"shared_secret_key";
//! let client = NonceClient::new(secret);
//! let server = NonceServer::new(secret, None, None);
//!
//! // Client generates a signed request
//! let request = client.create_signed_request()?;
//!
//! // Server verifies the request
//! match server.verify_signed_request(&request, None).await {
//!     Ok(()) => println!("Request verified successfully"),
//!     Err(e) => println!("Verification failed: {}", e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### With Context Isolation
//!
//! ```rust
//! use nonce_auth::{NonceClient, NonceServer};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # NonceServer::init().await?;
//! let client = NonceClient::new(b"secret");
//! let server = NonceServer::new(b"secret", None, None);
//!
//! let request = client.create_signed_request()?;
//!
//! // Same nonce can be used in different contexts
//! server.verify_signed_request(&request, Some("api_v1")).await?;
//! server.verify_signed_request(&request, Some("api_v2")).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Database Configuration
//!
//! The SQLite database location can be configured using the `TURBOSQL_DB_PATH` environment variable:
//!
//! ```bash
//! # Use a specific file
//! export TURBOSQL_DB_PATH="/path/to/nonce_auth.db"
//!
//! # Use in-memory database (for testing)
//! export TURBOSQL_DB_PATH=":memory:"
//! ```
//!
//! If not set, it defaults to `nonce_auth.db` in the current directory.
//!
//! ## Architecture
//!
//! The library is designed with clear separation between client and server responsibilities:
//!
//! - **[`NonceClient`]**: Lightweight client for generating signed requests
//! - **[`NonceServer`]**: Server-side verification and nonce management
//! - **[`SignedRequest`]**: The data structure exchanged between client and server
//! - **[`NonceError`]**: Comprehensive error handling for all failure modes

use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod nonce;

// Re-export commonly used types
pub use nonce::{NonceClient, NonceError, NonceServer};

/// Internal type alias for HMAC-SHA256 operations.
type HmacSha256 = Hmac<Sha256>;

/// A signed request containing timestamp, nonce, and cryptographic signature.
///
/// This structure represents a complete authenticated request that can be
/// verified by a server to prevent replay attacks. It contains all the
/// necessary information for cryptographic verification.
///
/// # Fields
///
/// - `timestamp`: Unix timestamp (seconds since epoch) when the request was created
/// - `nonce`: A unique identifier (typically UUID) that prevents request reuse
/// - `signature`: HMAC-SHA256 signature of the timestamp and nonce
///
/// # Serialization
///
/// This struct implements `Serialize` and `Deserialize` for easy JSON/binary
/// serialization when sending requests over the network.
///
/// # Example
///
/// ```rust
/// use nonce_auth::{NonceClient, SignedRequest};
///
/// let client = NonceClient::new(b"secret");
/// let request: SignedRequest = client.create_signed_request().unwrap();
///
/// // Serialize to JSON for network transmission
/// let json = serde_json::to_string(&request).unwrap();
/// println!("Request JSON: {}", json);
///
/// // Deserialize from JSON
/// let parsed: SignedRequest = serde_json::from_str(&json).unwrap();
/// assert_eq!(request.nonce, parsed.nonce);
/// ```
///
/// # Security Notes
///
/// - The timestamp prevents very old requests from being replayed
/// - The nonce ensures each request is unique and can only be used once
/// - The signature proves the request hasn't been tampered with
/// - All three fields together provide comprehensive replay attack protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    /// Unix timestamp (seconds since epoch) when this request was created.
    ///
    /// Used by the server to validate that the request is within the
    /// acceptable time window and not too old.
    pub timestamp: u64,

    /// A unique nonce value, typically a UUID string.
    ///
    /// This value must be unique and is used to prevent the same
    /// request from being processed multiple times.
    pub nonce: String,

    /// HMAC-SHA256 signature of the timestamp and nonce.
    ///
    /// This signature proves that the request was created by someone
    /// who knows the shared secret and that the request hasn't been
    /// tampered with in transit.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use crate::nonce::{NonceClient, NonceError, NonceServer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const TEST_SECRET: &[u8] = b"test_secret_key_123";

    #[tokio::test]
    async fn test_client_server_separation() {
        // Initialize database
        unsafe {
            std::env::set_var("TURBOSQL_DB_PATH", ":memory:");
        }
        NonceServer::init().await.unwrap();

        let client = NonceClient::new(TEST_SECRET);
        let server = NonceServer::new(
            TEST_SECRET,
            Some(Duration::from_secs(300)), // 5 min TTL
            Some(Duration::from_secs(300)), // 5 min time window
        );

        // Client creates a signed request
        let request = client.create_signed_request().unwrap();

        // Server verifies the request
        assert!(server.verify_signed_request(&request, None).await.is_ok());

        // Test duplicate request detection
        assert!(matches!(
            server.verify_signed_request(&request, None).await,
            Err(NonceError::DuplicateNonce)
        ));

        // Test invalid signature
        let mut bad_request = client.create_signed_request().unwrap();
        bad_request.signature = "invalid_signature".to_string();

        assert!(matches!(
            server.verify_signed_request(&bad_request, None).await,
            Err(NonceError::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn test_context_isolation() {
        unsafe {
            std::env::set_var("TURBOSQL_DB_PATH", ":memory:");
        }
        NonceServer::init().await.unwrap();

        let client = NonceClient::new(TEST_SECRET);
        let server = NonceServer::new(TEST_SECRET, None, None);

        // Create one request to test context isolation
        let request = client.create_signed_request().unwrap();

        // Same nonce can be used in different contexts
        assert!(
            server
                .verify_signed_request(&request, Some("context1"))
                .await
                .is_ok()
        );
        assert!(
            server
                .verify_signed_request(&request, Some("context2"))
                .await
                .is_ok()
        );
        assert!(
            server
                .verify_signed_request(&request, Some("context3"))
                .await
                .is_ok()
        );

        // But cannot be reused in the same context
        let request_copy = request.clone();
        assert!(matches!(
            server
                .verify_signed_request(&request_copy, Some("context1"))
                .await,
            Err(NonceError::DuplicateNonce)
        ));

        // Test with no context (NULL context)
        assert!(server.verify_signed_request(&request, None).await.is_ok());

        // Cannot reuse with no context
        let request_copy2 = request.clone();
        assert!(matches!(
            server.verify_signed_request(&request_copy2, None).await,
            Err(NonceError::DuplicateNonce)
        ));
    }

    #[tokio::test]
    async fn test_timestamp_validation() {
        unsafe {
            std::env::set_var("TURBOSQL_DB_PATH", ":memory:");
        }
        NonceServer::init().await.unwrap();

        let client = NonceClient::new(TEST_SECRET);
        let server = NonceServer::new(
            TEST_SECRET,
            Some(Duration::from_secs(300)),
            Some(Duration::from_secs(60)), // 1 minute window
        );

        // Create a request with old timestamp
        let mut old_request = client.create_signed_request().unwrap();
        old_request.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(3600); // 1 hour ago

        // Re-sign with old timestamp
        old_request.signature = client
            .sign(&old_request.timestamp.to_string(), &old_request.nonce)
            .unwrap();

        assert!(matches!(
            server.verify_signed_request(&old_request, None).await,
            Err(NonceError::TimestampOutOfWindow)
        ));
    }

    #[tokio::test]
    async fn test_server_default_values() {
        let server = NonceServer::new(TEST_SECRET, None, None);

        // Test default values
        assert_eq!(server.default_ttl(), Duration::from_secs(300)); // 5 minutes
        assert_eq!(server.time_window(), Duration::from_secs(60)); // 1 minute
    }

    #[tokio::test]
    async fn test_server_custom_values() {
        let custom_ttl = Duration::from_secs(600);
        let custom_window = Duration::from_secs(120);

        let server = NonceServer::new(TEST_SECRET, Some(custom_ttl), Some(custom_window));

        assert_eq!(server.default_ttl(), custom_ttl);
        assert_eq!(server.time_window(), custom_window);
    }

    #[tokio::test]
    async fn test_nonce_expiration() {
        unsafe {
            std::env::set_var("TURBOSQL_DB_PATH", ":memory:");
        }
        NonceServer::init().await.unwrap();

        let client = NonceClient::new(TEST_SECRET);
        let server = NonceServer::new(
            TEST_SECRET,
            Some(Duration::from_millis(100)), // Very short TTL
            Some(Duration::from_secs(300)),
        );

        let request = client.create_signed_request().unwrap();

        // First verification should succeed
        assert!(server.verify_signed_request(&request, None).await.is_ok());

        // Second verification with same nonce should fail (already consumed)
        let duplicate_request = request.clone();
        assert!(matches!(
            server.verify_signed_request(&duplicate_request, None).await,
            Err(NonceError::DuplicateNonce)
        ));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        unsafe {
            std::env::set_var("TURBOSQL_DB_PATH", ":memory:");
        }
        NonceServer::init().await.unwrap();

        // Test cleanup function
        let result = NonceServer::cleanup_expired(Duration::from_secs(300)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_signature_verification() {
        let client = NonceClient::new(TEST_SECRET);

        // Test direct signature creation and verification
        let timestamp = "1234567890";
        let nonce = "test-nonce";

        let signature = client.sign(timestamp, nonce).unwrap();
        assert!(!signature.is_empty());

        // Test with different secret should produce different signature
        let client2 = NonceClient::new(b"different_secret");
        let signature2 = client2.sign(timestamp, nonce).unwrap();
        assert_ne!(signature, signature2);
    }

    #[tokio::test]
    async fn test_serialization() {
        let client = NonceClient::new(TEST_SECRET);
        let request = client.create_signed_request().unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.is_empty());

        // Test deserialization
        let deserialized: crate::SignedRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.timestamp, deserialized.timestamp);
        assert_eq!(request.nonce, deserialized.nonce);
        assert_eq!(request.signature, deserialized.signature);
    }
}
