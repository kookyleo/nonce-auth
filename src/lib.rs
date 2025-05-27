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
//! use hmac::Mac;
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
//! // Client generates authentication data with custom signature
//! let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
//!     mac.update(timestamp.as_bytes());
//!     mac.update(nonce.as_bytes());
//! })?;
//!
//! // Server verifies the authentication data with matching signature algorithm
//! match server.verify_auth_data(&auth_data, None, |mac| {
//!     mac.update(auth_data.timestamp.to_string().as_bytes());
//!     mac.update(auth_data.nonce.as_bytes());
//! }).await {
//!     Ok(()) => println!("Authentication verified successfully"),
//!     Err(e) => println!("Verification failed: {e}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### With Context Isolation
//!
//! ```rust
//! use nonce_auth::{NonceClient, NonceServer};
//! use hmac::Mac;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # NonceServer::init().await?;
//! let client = NonceClient::new(b"secret");
//! let server = NonceServer::new(b"secret", None, None);
//!
//! let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
//!     mac.update(timestamp.as_bytes());
//!     mac.update(nonce.as_bytes());
//! })?;
//!
//! // Same nonce can be used in different contexts
//! server.verify_auth_data(&auth_data, Some("api_v1"), |mac| {
//!     mac.update(auth_data.timestamp.to_string().as_bytes());
//!     mac.update(auth_data.nonce.as_bytes());
//! }).await?;
//! server.verify_auth_data(&auth_data, Some("api_v2"), |mac| {
//!     mac.update(auth_data.timestamp.to_string().as_bytes());
//!     mac.update(auth_data.nonce.as_bytes());
//! }).await?;
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
//! - **[`AuthData`]**: The data structure exchanged between client and server
//! - **[`NonceError`]**: Comprehensive error handling for all failure modes

use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod nonce;

// Re-export commonly used types
pub use nonce::{NonceClient, NonceError, NonceServer};

/// Internal type alias for HMAC-SHA256 operations.
type HmacSha256 = Hmac<Sha256>;

/// Authentication data for nonce-based request verification.
///
/// This structure contains the cryptographic authentication information
/// that is embedded within or sent alongside application requests. It is
/// specifically designed for nonce-based authentication and replay attack
/// prevention, not as a complete request structure.
///
/// # Purpose
///
/// `AuthData` represents only the authentication portion of a request:
/// - It does not contain application payload or business logic data
/// - It focuses solely on cryptographic verification and replay prevention
/// - It can be embedded in larger request structures or sent as headers
///
/// # Fields
///
/// - `timestamp`: Unix timestamp (seconds since epoch) when the auth data was created
/// - `nonce`: A unique identifier (typically UUID) that prevents request reuse
/// - `signature`: HMAC-SHA256 signature that can include various data fields
///
/// # Serialization
///
/// This struct implements `Serialize` and `Deserialize` for easy JSON/binary
/// serialization when sending authentication data over the network.
///
/// # Example
///
/// ```rust
/// use nonce_auth::{NonceClient, AuthData};
/// use hmac::Mac;
///
/// let client = NonceClient::new(b"secret");
/// let auth_data: AuthData = client.create_auth_data(|mac, timestamp, nonce| {
///     mac.update(timestamp.as_bytes());
///     mac.update(nonce.as_bytes());
/// }).unwrap();
///
/// // Embed in a larger request structure
/// #[derive(serde::Serialize)]
/// struct ApiRequest {
///     payload: String,
///     auth: AuthData,
/// }
///
/// let request = ApiRequest {
///     payload: "application data".to_string(),
///     auth: auth_data,
/// };
/// ```
///
/// # Security Notes
///
/// - The timestamp prevents very old authentication attempts from being replayed
/// - The nonce ensures each authentication attempt is unique and can only be used once
/// - The signature proves the authentication data hasn't been tampered with
/// - The signature algorithm is flexible and can include additional request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthData {
    /// Unix timestamp (seconds since epoch) when this authentication data was created.
    ///
    /// Used by the server to validate that the authentication attempt is within the
    /// acceptable time window and not too old.
    pub timestamp: u64,

    /// A unique nonce value, typically a UUID string.
    ///
    /// This value must be unique and is used to prevent the same
    /// authentication data from being processed multiple times.
    pub nonce: String,

    /// HMAC-SHA256 signature that can include various data fields.
    ///
    /// The signature algorithm is flexible and can be customized to include
    /// timestamp, nonce, payload, HTTP method, path, or any other relevant data.
    /// This proves that the authentication data was created by someone who knows
    /// the shared secret and that the included data hasn't been tampered with.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use crate::nonce::{NonceClient, NonceError, NonceServer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use hmac::Mac;

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

        // Client creates auth data with custom signature
        let request = client.create_auth_data(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();

        // Server verifies the request with matching signature algorithm
        assert!(server.verify_auth_data(&request, None, |mac| {
            mac.update(request.timestamp.to_string().as_bytes());
            mac.update(request.nonce.as_bytes());
        }).await.is_ok());

        // Test duplicate request detection
        assert!(matches!(
            server.verify_auth_data(&request, None, |mac| {
                mac.update(request.timestamp.to_string().as_bytes());
                mac.update(request.nonce.as_bytes());
            }).await,
            Err(NonceError::DuplicateNonce)
        ));

        // Test invalid signature
        let mut bad_request = client.create_auth_data(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();
        bad_request.signature = "invalid_signature".to_string();

        assert!(matches!(
            server.verify_auth_data(&bad_request, None, |mac| {
                mac.update(bad_request.timestamp.to_string().as_bytes());
                mac.update(bad_request.nonce.as_bytes());
            }).await,
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

        // Create one auth data to test context isolation
        let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();

        // Same nonce can be used in different contexts
        assert!(
            server
                .verify_auth_data(&auth_data, Some("context1"), |mac| {
                    mac.update(auth_data.timestamp.to_string().as_bytes());
                    mac.update(auth_data.nonce.as_bytes());
                })
                .await
                .is_ok()
        );
        assert!(
            server
                .verify_auth_data(&auth_data, Some("context2"), |mac| {
                    mac.update(auth_data.timestamp.to_string().as_bytes());
                    mac.update(auth_data.nonce.as_bytes());
                })
                .await
                .is_ok()
        );
        assert!(
            server
                .verify_auth_data(&auth_data, Some("context3"), |mac| {
                    mac.update(auth_data.timestamp.to_string().as_bytes());
                    mac.update(auth_data.nonce.as_bytes());
                })
                .await
                .is_ok()
        );

        // But cannot be reused in the same context
        let auth_data_copy = auth_data.clone();
        assert!(matches!(
            server
                .verify_auth_data(&auth_data_copy, Some("context1"), |mac| {
                    mac.update(auth_data_copy.timestamp.to_string().as_bytes());
                    mac.update(auth_data_copy.nonce.as_bytes());
                })
                .await,
            Err(NonceError::DuplicateNonce)
        ));

        // Test with no context (NULL context)
        assert!(server.verify_auth_data(&auth_data, None, |mac| {
            mac.update(auth_data.timestamp.to_string().as_bytes());
            mac.update(auth_data.nonce.as_bytes());
        }).await.is_ok());

        // Cannot reuse with no context
        let auth_data_copy2 = auth_data.clone();
        assert!(matches!(
            server.verify_auth_data(&auth_data_copy2, None, |mac| {
                mac.update(auth_data_copy2.timestamp.to_string().as_bytes());
                mac.update(auth_data_copy2.nonce.as_bytes());
            }).await,
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

        // Create auth data with old timestamp
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(3600); // 1 hour ago

        let nonce = uuid::Uuid::new_v4().to_string();
        
        // Create signature with old timestamp
        let signature = client.generate_signature(|mac| {
            mac.update(old_timestamp.to_string().as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();

        let old_auth_data = crate::AuthData {
            timestamp: old_timestamp,
            nonce,
            signature,
        };

        assert!(matches!(
            server.verify_auth_data(&old_auth_data, None, |mac| {
                mac.update(old_auth_data.timestamp.to_string().as_bytes());
                mac.update(old_auth_data.nonce.as_bytes());
            }).await,
            Err(NonceError::TimestampOutOfWindow)
        ));
    }

    #[tokio::test]
    async fn test_server_default_values() {
        let server = NonceServer::new(TEST_SECRET, None, None);

        // Test default values
        assert_eq!(server.ttl(), Duration::from_secs(300)); // 5 minutes
        assert_eq!(server.time_window(), Duration::from_secs(60)); // 1 minute
    }

    #[tokio::test]
    async fn test_server_custom_values() {
        let custom_ttl = Duration::from_secs(600);
        let custom_window = Duration::from_secs(120);

        let server = NonceServer::new(TEST_SECRET, Some(custom_ttl), Some(custom_window));

        assert_eq!(server.ttl(), custom_ttl);
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

        let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();

        // First verification should succeed
        assert!(server.verify_auth_data(&auth_data, None, |mac| {
            mac.update(auth_data.timestamp.to_string().as_bytes());
            mac.update(auth_data.nonce.as_bytes());
        }).await.is_ok());

        // Second verification with same nonce should fail (already consumed)
        let duplicate_auth_data = auth_data.clone();
        assert!(matches!(
            server.verify_auth_data(&duplicate_auth_data, None, |mac| {
                mac.update(duplicate_auth_data.timestamp.to_string().as_bytes());
                mac.update(duplicate_auth_data.nonce.as_bytes());
            }).await,
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
        let result = NonceServer::cleanup_expired_nonces(Duration::from_secs(300)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_signature_verification() {
        let client = NonceClient::new(TEST_SECRET);

        // Test direct signature creation and verification
        let timestamp = "1234567890";
        let nonce = "test-nonce";

        let signature = client.generate_signature(|mac| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();
        assert!(!signature.is_empty());

        // Test with different secret should produce different signature
        let client2 = NonceClient::new(b"different_secret");
        let signature2 = client2.generate_signature(|mac| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();
        assert_ne!(signature, signature2);
    }

    #[tokio::test]
    async fn test_serialization() {
        let client = NonceClient::new(TEST_SECRET);
        let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
        }).unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&auth_data).unwrap();
        assert!(!json.is_empty());

        // Test deserialization
        let deserialized: crate::AuthData = serde_json::from_str(&json).unwrap();
        assert_eq!(auth_data.timestamp, deserialized.timestamp);
        assert_eq!(auth_data.nonce, deserialized.nonce);
        assert_eq!(auth_data.signature, deserialized.signature);
    }
}
