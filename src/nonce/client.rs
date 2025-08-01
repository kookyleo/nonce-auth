use hmac::Mac;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

use super::NonceError;
use crate::{HmacSha256, NonceCredential};

/// A client for generating cryptographically signed `NonceCredential`s.
///
/// This client is stateless and responsible for creating credentials that can be
/// verified by a `NonceServer`.
///
/// # Example
///
/// ```rust
/// use nonce_auth::NonceClient;
/// use hmac::Mac; // Trait for `mac.update()`
///
/// let client = NonceClient::new(b"my_secret");
/// let payload = b"some_data_to_protect";
///
/// // Standard usage:
/// let credential = client.credential_builder().sign(payload).unwrap();
///
/// // Advanced usage:
/// let custom_credential = client.credential_builder().sign_with(|mac, ts, nonce| {
///     mac.update(ts.as_bytes());
///     mac.update(nonce.as_bytes());
///     mac.update(payload);
/// }).unwrap();
/// ```
pub struct NonceClient {
    secret: Vec<u8>,
}

impl NonceClient {
    /// Creates a new `NonceClient` with the specified shared secret.
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    /// Returns a builder to construct and sign a `NonceCredential`.
    ///
    /// This is the recommended entry point for creating credentials.
    pub fn credential_builder(&self) -> NonceCredentialBuilder {
        NonceCredentialBuilder::new(self)
    }

    /// Low-level function to generate a signature. Used internally by the builder.
    fn generate_signature<F>(&self, data_builder: F) -> Result<String, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;
        data_builder(&mut mac);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
}

/// A builder for creating a `NonceCredential`.
///
/// This builder provides a safe and ergonomic API for signing data.
pub struct NonceCredentialBuilder<'a> {
    client: &'a NonceClient,
    _phantom: PhantomData<()>,
}

impl<'a> NonceCredentialBuilder<'a> {
    fn new(client: &'a NonceClient) -> Self {
        Self {
            client,
            _phantom: PhantomData,
        }
    }

    /// Signs the standard components (`timestamp`, `nonce`) plus a payload.
    ///
    /// This is the recommended method for most use cases, as it ensures the payload
    /// is always included in the signature.
    ///
    /// # Arguments
    ///
    /// * `payload`: The business data to include in the signature.
    pub fn sign(self, payload: &[u8]) -> Result<NonceCredential, NonceError> {
        self.sign_with(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
            mac.update(payload);
        })
    }

    /// Signs the credential using custom logic defined in a closure for advanced use cases.
    ///
    /// # Warning
    ///
    /// You are responsible for including all relevant data in the signature
    /// within the closure. Forgetting to include the payload can lead to security vulnerabilities.
    ///
    /// # Arguments
    ///
    /// * `signature_builder`: A closure that defines the exact data to be signed.
    pub fn sign_with<F>(self, signature_builder: F) -> Result<NonceCredential, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>, &str, &str),
    {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = uuid::Uuid::new_v4().to_string();

        let signature = self.client.generate_signature(|mac| {
            signature_builder(mac, &timestamp.to_string(), &nonce);
        })?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
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
    fn test_builder_sign_standard() {
        let client = NonceClient::new(TEST_SECRET);
        let payload = b"test payload";

        let credential = client.credential_builder().sign(payload).unwrap();

        assert!(credential.timestamp > 0);
        assert!(!credential.nonce.is_empty());
        assert!(!credential.signature.is_empty());
        assert_eq!(credential.signature.len(), 64);

        // Verify the signature matches the expected components
        let expected_signature = client
            .generate_signature(|mac| {
                mac.update(credential.timestamp.to_string().as_bytes());
                mac.update(credential.nonce.as_bytes());
                mac.update(payload);
            })
            .unwrap();
        assert_eq!(credential.signature, expected_signature);
    }

    #[test]
    fn test_builder_sign_with_custom_logic() {
        let client = NonceClient::new(TEST_SECRET);
        let payload = "test payload";
        let extra = "extra_context";

        let credential = client
            .credential_builder()
            .sign_with(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
                mac.update(payload.as_bytes());
                mac.update(extra.as_bytes());
            })
            .unwrap();

        // Verify the signature includes all custom parts
        let expected_signature = client
            .generate_signature(|mac| {
                mac.update(credential.timestamp.to_string().as_bytes());
                mac.update(credential.nonce.as_bytes());
                mac.update(payload.as_bytes());
                mac.update(extra.as_bytes());
            })
            .unwrap();
        assert_eq!(credential.signature, expected_signature);
    }

    #[test]
    fn test_multiple_credentials_different_nonces() {
        let client = NonceClient::new(TEST_SECRET);

        let credential1 = client.credential_builder().sign(b"payload1").unwrap();
        let credential2 = client.credential_builder().sign(b"payload2").unwrap();

        assert_ne!(credential1.nonce, credential2.nonce);
        assert_ne!(credential1.signature, credential2.signature);
    }
}
