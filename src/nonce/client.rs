use hmac::Mac;
use std::time::{SystemTime, UNIX_EPOCH};

use super::NonceError;
use crate::HmacSha256;
use crate::SignedRequest;

/// Client-side nonce manager for generating signed requests.
///
/// The `NonceClient` is responsible for creating cryptographically signed
/// requests that can be verified by a `NonceServer`. It provides a lightweight,
/// stateless interface for generating nonces and signatures without requiring
/// any database or persistent storage.
///
/// # Security Features
///
/// - **HMAC-SHA256 Signing**: Uses industry-standard HMAC with SHA256 for signatures
/// - **UUID Nonces**: Generates cryptographically random UUIDs for nonces
/// - **Timestamp Inclusion**: Includes current timestamp to prevent old request replay
/// - **Stateless Design**: No local state or storage required
///
/// # Usage Pattern
///
/// The typical usage pattern is:
/// 1. Create a client with a shared secret
/// 2. Generate signed requests as needed
/// 3. Send the signed request to the server for verification
///
/// # Example
///
/// ```rust
/// use nonce_auth::NonceClient;
///
/// // Create a client with a shared secret
/// let client = NonceClient::new(b"my_shared_secret");
///
/// // Generate a signed request
/// let request = client.create_signed_request().unwrap();
///
/// // The request contains timestamp, nonce, and signature
/// println!("Timestamp: {}", request.timestamp);
/// println!("Nonce: {}", request.nonce);
/// println!("Signature: {}", request.signature);
/// ```
///
/// # Thread Safety
///
/// `NonceClient` is thread-safe and can be shared across multiple threads
/// or used concurrently to generate multiple signed requests.
pub struct NonceClient {
    /// The secret key used for HMAC signature generation.
    /// This should be the same secret used by the corresponding `NonceServer`.
    secret: Vec<u8>,
}

impl NonceClient {
    /// Creates a new `NonceClient` with the specified secret key.
    ///
    /// The secret key should be shared between the client and server
    /// and kept confidential. It's used to generate HMAC signatures
    /// that prove the authenticity of requests.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key for HMAC signature generation.
    ///   This should match the secret used by the server.
    ///
    /// # Returns
    ///
    /// A new `NonceClient` instance ready to generate signed requests.
    ///
    /// # Security Considerations
    ///
    /// - Use a cryptographically strong secret key (at least 32 bytes recommended)
    /// - Keep the secret key confidential and secure
    /// - Use the same secret key on both client and server
    /// - Consider rotating secret keys periodically
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceClient;
    ///
    /// // Create with a strong secret key
    /// let secret = b"my_very_secure_secret_key_32_bytes";
    /// let client = NonceClient::new(secret);
    ///
    /// // Or use a dynamically generated secret
    /// let dynamic_secret = "generated_secret_from_key_exchange".as_bytes();
    /// let client = NonceClient::new(dynamic_secret);
    /// ```
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    /// Generates a complete signed request with timestamp, nonce, and signature.
    ///
    /// This method creates a new signed request that includes:
    /// - Current Unix timestamp (seconds since epoch)
    /// - A randomly generated UUID as the nonce
    /// - An HMAC-SHA256 signature of the timestamp and nonce
    ///
    /// Each call to this method generates a unique request with a different
    /// nonce and timestamp, ensuring that requests cannot be replayed.
    ///
    /// # Returns
    ///
    /// * `Ok(SignedRequest)` - A complete signed request ready to send to the server
    /// * `Err(NonceError::CryptoError)` - If there's an error in the cryptographic operations
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceClient;
    ///
    /// let client = NonceClient::new(b"shared_secret");
    ///
    /// // Generate a signed request
    /// let request = client.create_signed_request().unwrap();
    ///
    /// // Send to server (example using reqwest)
    /// // let response = reqwest::Client::new()
    /// //     .post("https://api.example.com/protected")
    /// //     .json(&request)
    /// //     .send()
    /// //     .await?;
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from
    /// multiple threads to generate different signed requests.
    pub fn create_signed_request(&self) -> Result<SignedRequest, NonceError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = uuid::Uuid::new_v4().to_string();
        let signature = self.sign(&timestamp.to_string(), &nonce)?;

        Ok(SignedRequest {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Generates an HMAC-SHA256 signature for the given timestamp and nonce.
    ///
    /// This method creates a cryptographic signature that proves the authenticity
    /// of the request. The signature is generated by:
    /// 1. Creating an HMAC-SHA256 instance with the secret key
    /// 2. Updating it with the timestamp bytes
    /// 3. Updating it with the nonce bytes
    /// 4. Finalizing and hex-encoding the result
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp string to include in the signature
    /// * `nonce` - The nonce string to include in the signature
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The hex-encoded HMAC signature
    /// * `Err(NonceError::CryptoError)` - If there's an error in the cryptographic operations
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceClient;
    ///
    /// let client = NonceClient::new(b"shared_secret");
    ///
    /// // Generate signature for specific timestamp and nonce
    /// let signature = client.sign("1640995200", "550e8400-e29b-41d4-a716-446655440000").unwrap();
    ///
    /// // The signature is a 64-character hex string
    /// assert_eq!(signature.len(), 64);
    /// ```
    ///
    /// # Security Notes
    ///
    /// - The same timestamp and nonce will always produce the same signature
    /// - Different secrets will produce different signatures for the same inputs
    /// - The signature is deterministic and reproducible
    pub fn sign(&self, timestamp: &str, nonce: &str) -> Result<String, NonceError> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;

        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());

        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test_secret_key_123";

    #[test]
    fn test_client_creation() {
        let client = NonceClient::new(TEST_SECRET);
        assert_eq!(client.secret, TEST_SECRET);
    }

    #[test]
    fn test_signature_generation() {
        let client = NonceClient::new(TEST_SECRET);
        let timestamp = "1234567890";
        let nonce = "test-nonce-123";

        let signature = client.sign(timestamp, nonce).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64); // SHA256 hex string length

        // Same inputs should produce same signature
        let signature2 = client.sign(timestamp, nonce).unwrap();
        assert_eq!(signature, signature2);
    }

    #[test]
    fn test_different_inputs_different_signatures() {
        let client = NonceClient::new(TEST_SECRET);

        let sig1 = client.sign("123", "nonce1").unwrap();
        let sig2 = client.sign("124", "nonce1").unwrap(); // Different timestamp
        let sig3 = client.sign("123", "nonce2").unwrap(); // Different nonce

        assert_ne!(sig1, sig2);
        assert_ne!(sig1, sig3);
        assert_ne!(sig2, sig3);
    }

    #[test]
    fn test_different_secrets_different_signatures() {
        let client1 = NonceClient::new(b"secret1");
        let client2 = NonceClient::new(b"secret2");

        let timestamp = "1234567890";
        let nonce = "test-nonce";

        let sig1 = client1.sign(timestamp, nonce).unwrap();
        let sig2 = client2.sign(timestamp, nonce).unwrap();

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_create_signed_request() {
        let client = NonceClient::new(TEST_SECRET);
        let request = client.create_signed_request().unwrap();

        assert!(request.timestamp > 0);
        assert!(!request.nonce.is_empty());
        assert!(!request.signature.is_empty());
        assert_eq!(request.signature.len(), 64);

        // Verify the signature is correct
        let expected_signature = client
            .sign(&request.timestamp.to_string(), &request.nonce)
            .unwrap();
        assert_eq!(request.signature, expected_signature);
    }

    #[test]
    fn test_multiple_requests_different_nonces() {
        let client = NonceClient::new(TEST_SECRET);

        let request1 = client.create_signed_request().unwrap();
        let request2 = client.create_signed_request().unwrap();

        assert_ne!(request1.nonce, request2.nonce);
        assert_ne!(request1.signature, request2.signature);
    }

    #[test]
    fn test_empty_secret() {
        let client = NonceClient::new(&[]);
        let result = client.sign("123", "nonce");
        assert!(result.is_ok()); // Empty secret should still work
    }
}
