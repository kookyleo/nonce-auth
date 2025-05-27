use hmac::Mac;
use std::time::{SystemTime, UNIX_EPOCH};

use super::NonceError;
use crate::AuthData;
use crate::HmacSha256;

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
/// - **Fully Customizable**: All signature algorithms are defined by the application
///
/// # Usage Pattern
///
/// The typical usage pattern is:
/// 1. Create a client with a shared secret
/// 2. Generate signed requests with custom signature algorithms
/// 3. Send the signed request to the server for verification
///
/// # Example
///
/// ```rust
/// use nonce_auth::NonceClient;
/// use hmac::Mac;
///
/// // Create a client with a shared secret
/// let client = NonceClient::new(b"my_shared_secret");
///
/// // Generate a signed request with custom signature
/// let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
///     mac.update(timestamp.as_bytes());
///     mac.update(nonce.as_bytes());
///     mac.update(b"custom_payload");
/// }).unwrap();
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

    /// Generates authentication data with custom signature algorithm.
    ///
    /// This method provides complete flexibility to create authentication data with
    /// any signature algorithm. The signature algorithm is defined by the closure
    /// which receives the MAC instance, timestamp, and nonce.
    ///
    /// # Arguments
    ///
    /// * `signature_builder` - A closure that defines how to build the signature data
    ///
    /// # Returns
    ///
    /// * `Ok(AuthData)` - Authentication data with custom signature
    /// * `Err(NonceError)` - If there's an error in the cryptographic operations
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceClient;
    /// use hmac::Mac;
    ///
    /// let client = NonceClient::new(b"shared_secret");
    /// let payload = "request body";
    ///
    /// // Create auth data with payload included in signature
    /// let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
    ///     mac.update(timestamp.as_bytes());
    ///     mac.update(nonce.as_bytes());
    ///     mac.update(payload.as_bytes());
    /// }).unwrap();
    /// ```
    pub fn create_auth_data<F>(&self, signature_builder: F) -> Result<AuthData, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>, &str, &str),
    {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = uuid::Uuid::new_v4().to_string();

        let signature = self.generate_signature(|mac| {
            signature_builder(mac, &timestamp.to_string(), &nonce);
        })?;

        Ok(AuthData {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Generates an HMAC-SHA256 signature with custom data builder.
    ///
    /// This method provides maximum flexibility for signature generation by
    /// allowing applications to define exactly what data should be included
    /// in the signature through a closure.
    ///
    /// # Arguments
    ///
    /// * `data_builder` - A closure that adds data to the HMAC instance
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The hex-encoded HMAC signature
    /// * `Err(NonceError)` - If there's an error in the cryptographic operations
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceClient;
    /// use hmac::Mac;
    ///
    /// let client = NonceClient::new(b"shared_secret");
    ///
    /// // Generate signature with custom data
    /// let signature = client.generate_signature(|mac| {
    ///     mac.update(b"timestamp");
    ///     mac.update(b"nonce");
    ///     mac.update(b"payload");
    ///     mac.update(b"method");
    /// }).unwrap();
    /// ```
    pub fn generate_signature<F>(&self, data_builder: F) -> Result<String, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;

        data_builder(&mut mac);

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
    fn test_create_auth_data_with_custom_signature() {
        let client = NonceClient::new(TEST_SECRET);
        let payload = "test payload";

        let auth_data = client
            .create_auth_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
                mac.update(payload.as_bytes());
            })
            .unwrap();

        assert!(auth_data.timestamp > 0);
        assert!(!auth_data.nonce.is_empty());
        assert!(!auth_data.signature.is_empty());
        assert_eq!(auth_data.signature.len(), 64);

        // Verify the signature includes the payload
        let expected_signature = client
            .generate_signature(|mac| {
                mac.update(auth_data.timestamp.to_string().as_bytes());
                mac.update(auth_data.nonce.as_bytes());
                mac.update(payload.as_bytes());
            })
            .unwrap();
        assert_eq!(auth_data.signature, expected_signature);
    }

    #[test]
    fn test_multiple_auth_data_different_nonces() {
        let client = NonceClient::new(TEST_SECRET);

        let auth_data1 = client
            .create_auth_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        let auth_data2 = client
            .create_auth_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        assert_ne!(auth_data1.nonce, auth_data2.nonce);
        assert_ne!(auth_data1.signature, auth_data2.signature);
    }

    #[test]
    fn test_sign_with_builder() {
        let client = NonceClient::new(TEST_SECRET);

        let signature1 = client
            .generate_signature(|mac| {
                mac.update(b"data1");
                mac.update(b"data2");
            })
            .unwrap();

        let signature2 = client
            .generate_signature(|mac| {
                mac.update(b"data1");
                mac.update(b"data3");
            })
            .unwrap();

        assert_eq!(signature1.len(), 64);
        assert_eq!(signature2.len(), 64);
        assert_ne!(signature1, signature2);
    }

    #[test]
    fn test_different_secrets_different_signatures() {
        let client1 = NonceClient::new(b"secret1");
        let client2 = NonceClient::new(b"secret2");

        let sig1 = client1
            .generate_signature(|mac| {
                mac.update(b"data");
            })
            .unwrap();

        let sig2 = client2
            .generate_signature(|mac| {
                mac.update(b"data");
            })
            .unwrap();

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_empty_secret() {
        let client = NonceClient::new(&[]);
        let result = client.generate_signature(|mac| {
            mac.update(b"data");
        });
        assert!(result.is_ok()); // Empty secret should still work
    }
}
