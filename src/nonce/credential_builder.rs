use crate::NonceCredential;
use crate::nonce::error::NonceError;
use crate::nonce::time_utils::current_timestamp;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A function that generates unique nonce values.
pub type NonceGeneratorFn = Box<dyn Fn() -> String + Send + Sync>;

/// A function that provides timestamps.
pub type TimeProviderFn = Box<dyn Fn() -> Result<u64, NonceError> + Send + Sync>;

/// Builder for creating cryptographic credentials.
///
/// `CredentialBuilder` provides a fluent interface for configuring and creating
/// `NonceCredential` instances. It supports custom nonce generation, time providers,
/// and various signing methods.
///
/// # Example: Basic Usage
///
/// ```rust
/// use nonce_auth::CredentialBuilder;
///
/// let credential = CredentialBuilder::new(b"my_secret")
///     .sign(b"payload")?;
/// # Ok::<(), nonce_auth::NonceError>(())
/// ```
///
/// # Example: Custom Configuration
///
/// ```rust
/// use nonce_auth::CredentialBuilder;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// # fn example() -> Result<(), nonce_auth::NonceError> {
/// let credential = CredentialBuilder::new(b"my_secret")
///     .with_nonce_generator(|| format!("custom-{}", uuid::Uuid::new_v4()))
///     .with_time_provider(|| {
///         SystemTime::now()
///             .duration_since(UNIX_EPOCH)
///             .map(|d| d.as_secs())
///             .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
///     })
///     .sign(b"payload")?;
/// # Ok(())
/// # }
/// ```
pub struct CredentialBuilder {
    secret: Vec<u8>,
    nonce_generator: NonceGeneratorFn,
    time_provider: TimeProviderFn,
}

impl CredentialBuilder {
    /// Creates a new `CredentialBuilder` with the provided secret.
    ///
    /// The secret is required for all signing operations. Other settings
    /// can be configured using the chainable `with_*` methods.
    ///
    /// # Arguments
    ///
    /// * `secret` - The shared secret key for HMAC operations
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::CredentialBuilder;
    ///
    /// // Simple usage
    /// let credential1 = CredentialBuilder::new(b"key")
    ///     .sign(b"data")?;
    ///     
    /// // With additional configuration in any order
    /// let credential2 = CredentialBuilder::new(b"key")
    ///     .with_time_provider(|| Ok(1234567890))
    ///     .with_nonce_generator(|| "custom".to_string())
    ///     .sign(b"data")?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            nonce_generator: Box::new(|| uuid::Uuid::new_v4().to_string()),
            time_provider: Box::new(|| Ok(current_timestamp()? as u64)),
        }
    }

    /// Sets a custom nonce generator function.
    ///
    /// The nonce generator should produce unique values for each call.
    /// The default generator uses UUID v4.
    ///
    /// # Arguments
    ///
    /// * `generator` - A function that returns unique nonce strings
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::CredentialBuilder;
    /// use std::sync::atomic::{AtomicU64, Ordering};
    /// use std::sync::Arc;
    ///
    /// let counter = Arc::new(AtomicU64::new(0));
    /// let counter_clone = counter.clone();
    ///
    /// let credential = CredentialBuilder::new(b"key")
    ///     .with_nonce_generator(move || {
    ///         let id = counter_clone.fetch_add(1, Ordering::SeqCst);
    ///         format!("nonce-{:010}", id)
    ///     })
    ///     .sign(b"data")?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub fn with_nonce_generator<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.nonce_generator = Box::new(generator);
        self
    }

    /// Sets a custom time provider function.
    ///
    /// The time provider should return the current Unix timestamp.
    /// The default provider uses system time.
    ///
    /// # Arguments
    ///
    /// * `provider` - A function that returns the current timestamp
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::CredentialBuilder;
    ///
    /// let credential = CredentialBuilder::new(b"key")
    ///     .with_time_provider(|| {
    ///         // Custom time source (e.g., NTP-synchronized)
    ///         Ok(1234567890)
    ///     })
    ///     .sign(b"data")?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub fn with_time_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> Result<u64, NonceError> + Send + Sync + 'static,
    {
        self.time_provider = Box::new(provider);
        self
    }

    /// Signs a payload and creates a `NonceCredential`.
    ///
    /// This method generates a nonce, gets the current timestamp, and creates
    /// an HMAC signature over the timestamp, nonce, and payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to be signed
    ///
    /// # Returns
    ///
    /// A `NonceCredential` containing the timestamp, nonce, and signature.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Time provider fails
    /// - Signature generation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::CredentialBuilder;
    ///
    /// let credential = CredentialBuilder::new(b"secret")
    ///     .sign(b"important_data")?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub fn sign(self, payload: &[u8]) -> Result<NonceCredential, NonceError> {
        let timestamp = (self.time_provider)()?;
        let nonce = (self.nonce_generator)();

        let signature = self.create_signature(&self.secret, timestamp, &nonce, payload)?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Signs multiple data components as a structured payload.
    ///
    /// This method concatenates all components in order and signs them as a single payload.
    /// The order of components is significant for verification.
    ///
    /// # Arguments
    ///
    /// * `components` - Array of data components to sign in order
    ///
    /// # Returns
    ///
    /// A `NonceCredential` containing the timestamp, nonce, and signature.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::CredentialBuilder;
    ///
    /// let credential = CredentialBuilder::new(b"secret")
    ///     .sign_structured(&[b"user123", b"action", b"data"])?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub fn sign_structured(self, components: &[&[u8]]) -> Result<NonceCredential, NonceError> {
        let timestamp = (self.time_provider)()?;
        let nonce = (self.nonce_generator)();

        let signature =
            self.create_structured_signature(&self.secret, timestamp, &nonce, components)?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Signs using a custom MAC construction function.
    ///
    /// This method provides maximum flexibility by allowing custom MAC construction.
    /// The provided function receives a MAC instance and the generated timestamp and nonce.
    ///
    /// # Arguments
    ///
    /// * `mac_fn` - Function that constructs the MAC using timestamp, nonce, and custom data
    ///
    /// # Returns
    ///
    /// A `NonceCredential` containing the timestamp, nonce, and signature.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::CredentialBuilder;
    /// use hmac::Mac;
    ///
    /// # fn example() -> Result<(), nonce_auth::NonceError> {
    /// let credential = CredentialBuilder::new(b"secret")
    ///     .sign_with(|mac, timestamp, nonce| {
    ///         mac.update(b"prefix:");
    ///         mac.update(timestamp.as_bytes());
    ///         mac.update(b":nonce:");
    ///         mac.update(nonce.as_bytes());
    ///         mac.update(b":custom_data");
    ///     })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign_with<F>(self, mac_fn: F) -> Result<NonceCredential, NonceError>
    where
        F: FnOnce(&mut HmacSha256, &str, &str),
    {
        let timestamp = (self.time_provider)()?;
        let nonce = (self.nonce_generator)();

        let signature = self.create_custom_signature(&self.secret, timestamp, &nonce, mac_fn)?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Creates a standard HMAC signature for timestamp, nonce, and payload.
    fn create_signature(
        &self,
        secret: &[u8],
        timestamp: u64,
        nonce: &str,
        payload: &[u8],
    ) -> Result<String, NonceError> {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(format!("Invalid secret key: {e}")))?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(payload);

        let result = mac.finalize();
        Ok(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
    }

    /// Creates a structured signature for multiple data components.
    fn create_structured_signature(
        &self,
        secret: &[u8],
        timestamp: u64,
        nonce: &str,
        components: &[&[u8]],
    ) -> Result<String, NonceError> {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(format!("Invalid secret key: {e}")))?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(nonce.as_bytes());
        for component in components {
            mac.update(component);
        }

        let result = mac.finalize();
        Ok(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
    }

    /// Creates a custom signature using a user-provided MAC construction function.
    fn create_custom_signature<F>(
        &self,
        secret: &[u8],
        timestamp: u64,
        nonce: &str,
        mac_fn: F,
    ) -> Result<String, NonceError>
    where
        F: FnOnce(&mut HmacSha256, &str, &str),
    {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(format!("Invalid secret key: {e}")))?;

        mac_fn(&mut mac, &timestamp.to_string(), nonce);

        let result = mac.finalize();
        Ok(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_credential_builder_new() {
        let builder = CredentialBuilder::new(b"test_secret");
        assert_eq!(builder.secret, b"test_secret".to_vec());
    }

    #[test]
    fn test_basic_signing() {
        let credential = CredentialBuilder::new(b"secret").sign(b"payload").unwrap();

        assert!(!credential.nonce.is_empty());
        assert!(credential.timestamp > 0);
        assert!(!credential.signature.is_empty());
    }

    #[test]
    fn test_structured_signing() {
        let credential = CredentialBuilder::new(b"secret")
            .sign_structured(&[b"part1", b"part2", b"part3"])
            .unwrap();

        assert!(!credential.nonce.is_empty());
        assert!(credential.timestamp > 0);
        assert!(!credential.signature.is_empty());
    }

    #[test]
    fn test_custom_nonce_generator() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        let credential = CredentialBuilder::new(b"secret")
            .with_nonce_generator(move || {
                let id = counter_clone.fetch_add(1, Ordering::SeqCst);
                format!("custom-{id:010}")
            })
            .sign(b"payload")
            .unwrap();

        assert_eq!(credential.nonce, "custom-0000000000");
    }

    #[test]
    fn test_custom_time_provider() {
        let fixed_time = 1234567890u64;
        let credential = CredentialBuilder::new(b"secret")
            .with_time_provider(move || Ok(fixed_time))
            .sign(b"payload")
            .unwrap();

        assert_eq!(credential.timestamp, fixed_time);
    }

    #[test]
    fn test_time_provider_error() {
        let result = CredentialBuilder::new(b"secret")
            .with_time_provider(|| Err(NonceError::CryptoError("Time error".to_string())))
            .sign(b"payload");

        assert!(matches!(result, Err(NonceError::CryptoError(_))));
    }

    #[test]
    fn test_sign_with_custom_mac() {
        let credential = CredentialBuilder::new(b"secret")
            .sign_with(|mac, timestamp, nonce| {
                mac.update(b"prefix:");
                mac.update(timestamp.as_bytes());
                mac.update(b":nonce:");
                mac.update(nonce.as_bytes());
                mac.update(b":custom");
            })
            .unwrap();

        assert!(!credential.nonce.is_empty());
        assert!(credential.timestamp > 0);
        assert!(!credential.signature.is_empty());
    }

    #[test]
    fn test_multiple_credentials_different_nonces() {
        let builder = || CredentialBuilder::new(b"secret");

        let cred1 = builder().sign(b"payload").unwrap();
        let cred2 = builder().sign(b"payload").unwrap();

        // Different nonces should be generated
        assert_ne!(cred1.nonce, cred2.nonce);

        // But signatures should be different due to different nonces
        assert_ne!(cred1.signature, cred2.signature);
    }

    #[test]
    fn test_structured_vs_regular_signing() {
        let secret = b"secret";

        // Sign components individually
        let mut combined = Vec::new();
        combined.extend_from_slice(b"part1");
        combined.extend_from_slice(b"part2");

        let cred1 = CredentialBuilder::new(secret)
            .with_nonce_generator(|| "fixed_nonce".to_string())
            .with_time_provider(|| Ok(1234567890))
            .sign(&combined)
            .unwrap();

        // Sign as structured components
        let cred2 = CredentialBuilder::new(secret)
            .with_nonce_generator(|| "fixed_nonce".to_string())
            .with_time_provider(|| Ok(1234567890))
            .sign_structured(&[b"part1", b"part2"])
            .unwrap();

        // Should produce the same result
        assert_eq!(cred1.signature, cred2.signature);
    }

    #[test]
    fn test_builder_method_chaining() {
        let secret = b"test_secret";
        let payload = b"test_payload";

        // Test different building orders produce same result
        let cred1 = CredentialBuilder::new(secret)
            .with_nonce_generator(|| "custom".to_string())
            .with_time_provider(|| Ok(1234567890))
            .sign(payload)
            .unwrap();

        let cred2 = CredentialBuilder::new(secret)
            .with_time_provider(|| Ok(1234567890))
            .with_nonce_generator(|| "custom".to_string())
            .sign(payload)
            .unwrap();

        assert_eq!(cred1.nonce, "custom");
        assert_eq!(cred1.timestamp, 1234567890);
        assert_eq!(cred1.signature, cred2.signature);
    }
}
