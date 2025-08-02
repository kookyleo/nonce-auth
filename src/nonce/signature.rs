//! Pluggable signature algorithm system for nonce-auth.
//!
//! This module provides a trait-based system for supporting different
//! cryptographic signature algorithms. The library ships with HMAC-SHA256
//! as the default algorithm, but users can implement custom algorithms
//! or use alternative implementations.

use crate::NonceError;

/// A trait for signature algorithms used in nonce authentication.
///
/// This trait abstracts the cryptographic operations needed for generating
/// and verifying signatures in the nonce authentication system.
///
/// # Implementation Notes
///
/// - Implementations should be secure against timing attacks
/// - The `sign` method should include timestamp and nonce in the signature
/// - The `verify` method should perform constant-time comparison
/// - All implementations should be `Send + Sync` for async usage
///
/// # Example
///
/// ```rust
/// # use nonce_auth::signature::SignatureAlgorithm;
/// # use nonce_auth::NonceError;
/// # use std::sync::Arc;
/// #
/// struct MyCustomAlgorithm {
///     key: Vec<u8>,
/// }
///
/// impl SignatureAlgorithm for MyCustomAlgorithm {
///     fn name(&self) -> &'static str {
///         "custom-hmac"
///     }
///
///     fn sign(&self, timestamp: u64, nonce: &str, data: &[u8]) -> Result<String, NonceError> {
///         // Custom signature implementation
///         Ok("custom_signature".to_string())
///     }
///
///     fn verify(&self, timestamp: u64, nonce: &str, data: &[u8], signature: &str) -> Result<(), NonceError> {
///         // Custom verification implementation
///         if signature == "custom_signature" {
///             Ok(())
///         } else {
///             Err(NonceError::InvalidSignature)
///         }
///     }
/// }
/// ```
pub trait SignatureAlgorithm: Send + Sync {
    /// Returns the name/identifier of this signature algorithm.
    ///
    /// This is used for debugging and algorithm identification.
    /// Should be a short, unique identifier like "hmac-sha256" or "ed25519".
    fn name(&self) -> &'static str;

    /// Generate a signature for the given data.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp to include in the signature
    /// * `nonce` - The nonce value to include in the signature  
    /// * `data` - The payload data to sign
    ///
    /// # Returns
    ///
    /// A base64-encoded signature string, or an error if signing fails.
    ///
    /// # Implementation Requirements
    ///
    /// The signature MUST include the timestamp and nonce to prevent
    /// replay attacks and ensure uniqueness. The typical pattern is:
    ///
    /// ```text
    /// signature = algorithm(key, timestamp || nonce || data)
    /// ```
    fn sign(&self, timestamp: u64, nonce: &str, data: &[u8]) -> Result<String, NonceError>;

    /// Verify a signature against the given data.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp from the credential
    /// * `nonce` - The nonce from the credential
    /// * `data` - The payload data that was signed
    /// * `signature` - The signature to verify (base64-encoded)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(NonceError::InvalidSignature)` otherwise.
    ///
    /// # Security Requirements
    ///
    /// - Must use constant-time comparison to prevent timing attacks
    /// - Must validate the signature covers timestamp, nonce, and data
    /// - Should handle malformed signatures gracefully
    fn verify(
        &self,
        timestamp: u64,
        nonce: &str,
        data: &[u8],
        signature: &str,
    ) -> Result<(), NonceError>;

    /// Create a signature using a custom MAC builder function.
    ///
    /// This method provides maximum flexibility for applications that need
    /// to include additional data in their signatures or use custom signing logic.
    ///
    /// # Arguments
    ///
    /// * `builder` - A closure that receives a MAC instance and builds the signature data
    ///
    /// # Returns
    ///
    /// A base64-encoded signature string, or an error if signing fails.
    ///
    /// # Default Implementation
    ///
    /// The default implementation calls `sign()` with empty data, which may not
    /// be appropriate for all algorithms. Custom algorithms should override this
    /// method if they support flexible signing.
    fn sign_with<F>(&self, timestamp: u64, nonce: &str, builder: F) -> Result<String, NonceError>
    where
        F: FnOnce(&mut dyn MacLike),
    {
        // Default implementation - algorithms should override if they support custom signing
        let _ = (timestamp, nonce, builder);
        Err(NonceError::CryptoError(
            "Custom signing not supported by this algorithm".to_string(),
        ))
    }

    /// Verify a signature using a custom MAC builder function.
    ///
    /// This method provides maximum flexibility for applications that need
    /// to verify signatures with additional data or custom verification logic.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify (base64-encoded)
    /// * `builder` - A closure that receives a MAC instance and builds the expected signature data
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(NonceError::InvalidSignature)` otherwise.
    ///
    /// # Default Implementation
    ///
    /// The default implementation returns an error, indicating custom verification
    /// is not supported. Custom algorithms should override this method if they
    /// support flexible verification.
    fn verify_with<F>(
        &self,
        timestamp: u64,
        nonce: &str,
        signature: &str,
        builder: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut dyn MacLike),
    {
        // Default implementation - algorithms should override if they support custom verification
        let _ = (timestamp, nonce, signature, builder);
        Err(NonceError::CryptoError(
            "Custom verification not supported by this algorithm".to_string(),
        ))
    }
}

/// A trait for MAC-like operations that can be used in custom signing.
///
/// This trait abstracts over different MAC implementations to allow
/// flexible signature construction in the `sign_with` and `verify_with` methods.
pub trait MacLike {
    /// Update the MAC with the given data.
    fn update(&mut self, data: &[u8]);
}

#[cfg(feature = "algo-hmac-sha256")]
pub mod hmac_sha256 {
    //! HMAC-SHA256 signature algorithm implementation.

    use super::{MacLike, SignatureAlgorithm};
    use crate::NonceError;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    /// HMAC-SHA256 signature algorithm.
    ///
    /// This is the default signature algorithm used by nonce-auth.
    /// It provides strong security guarantees and is widely supported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::signature::hmac_sha256::HmacSha256Algorithm;
    /// use nonce_auth::signature::SignatureAlgorithm;
    ///
    /// let algorithm = HmacSha256Algorithm::new(b"my_secret_key");
    /// let signature = algorithm.sign(1234567890, "unique_nonce", b"payload")?;
    ///
    /// // Verify the signature
    /// algorithm.verify(1234567890, "unique_nonce", b"payload", &signature)?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub struct HmacSha256Algorithm {
        key: Vec<u8>,
    }

    impl HmacSha256Algorithm {
        /// Create a new HMAC-SHA256 algorithm with the given key.
        ///
        /// # Arguments
        ///
        /// * `key` - The secret key to use for HMAC operations
        ///
        /// # Example
        ///
        /// ```rust
        /// use nonce_auth::signature::hmac_sha256::HmacSha256Algorithm;
        ///
        /// let algorithm = HmacSha256Algorithm::new(b"secret_key");
        /// ```
        pub fn new(key: &[u8]) -> Self {
            Self { key: key.to_vec() }
        }

        /// Create an HMAC instance for internal use.
        fn create_hmac(&self) -> Result<Hmac<Sha256>, NonceError> {
            Hmac::<Sha256>::new_from_slice(&self.key)
                .map_err(|e| NonceError::CryptoError(format!("Invalid HMAC key: {}", e)))
        }
    }

    impl SignatureAlgorithm for HmacSha256Algorithm {
        fn name(&self) -> &'static str {
            "hmac-sha256"
        }

        fn sign(&self, timestamp: u64, nonce: &str, data: &[u8]) -> Result<String, NonceError> {
            let mut mac = self.create_hmac()?;

            // Standard signature format: timestamp || nonce || data
            mac.update(timestamp.to_string().as_bytes());
            mac.update(nonce.as_bytes());
            mac.update(data);

            let signature = mac.finalize().into_bytes();
            Ok(base64::engine::general_purpose::STANDARD.encode(signature))
        }

        fn verify(
            &self,
            timestamp: u64,
            nonce: &str,
            data: &[u8],
            signature: &str,
        ) -> Result<(), NonceError> {
            // Decode the provided signature
            let expected_signature = base64::engine::general_purpose::STANDARD
                .decode(signature)
                .map_err(|e| NonceError::CryptoError(format!("Invalid base64 signature: {}", e)))?;

            // Compute the expected signature
            let mut mac = self.create_hmac()?;
            mac.update(timestamp.to_string().as_bytes());
            mac.update(nonce.as_bytes());
            mac.update(data);

            // Use constant-time comparison
            mac.verify_slice(&expected_signature)
                .map_err(|_| NonceError::InvalidSignature)
        }

        fn sign_with<F>(
            &self,
            timestamp: u64,
            nonce: &str,
            builder: F,
        ) -> Result<String, NonceError>
        where
            F: FnOnce(&mut dyn MacLike),
        {
            let mut mac = self.create_hmac()?;
            let mut mac_wrapper = HmacWrapper(&mut mac);

            // Always include timestamp and nonce first
            mac_wrapper.update(timestamp.to_string().as_bytes());
            mac_wrapper.update(nonce.as_bytes());

            // Let the builder add additional data
            builder(&mut mac_wrapper);

            let signature = mac.finalize().into_bytes();
            Ok(base64::engine::general_purpose::STANDARD.encode(signature))
        }

        fn verify_with<F>(
            &self,
            timestamp: u64,
            nonce: &str,
            signature: &str,
            builder: F,
        ) -> Result<(), NonceError>
        where
            F: FnOnce(&mut dyn MacLike),
        {
            // Decode the provided signature
            let expected_signature = base64::engine::general_purpose::STANDARD
                .decode(signature)
                .map_err(|e| NonceError::CryptoError(format!("Invalid base64 signature: {}", e)))?;

            // Compute the expected signature using the same process as signing
            let mut mac = self.create_hmac()?;
            let mut mac_wrapper = HmacWrapper(&mut mac);

            // Always include timestamp and nonce first (matching sign_with)
            mac_wrapper.update(timestamp.to_string().as_bytes());
            mac_wrapper.update(nonce.as_bytes());

            // Let the builder add the same additional data as during signing
            builder(&mut mac_wrapper);

            // Use constant-time comparison
            mac.verify_slice(&expected_signature)
                .map_err(|_| NonceError::InvalidSignature)
        }
    }

    /// Wrapper to make HMAC implement MacLike.
    struct HmacWrapper<'a>(&'a mut Hmac<Sha256>);

    impl<'a> MacLike for HmacWrapper<'a> {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_hmac_sha256_basic_sign_verify() {
            let algorithm = HmacSha256Algorithm::new(b"test_key");
            let timestamp = 1234567890;
            let nonce = "test_nonce";
            let data = b"test_payload";

            // Sign the data
            let signature = algorithm.sign(timestamp, nonce, data).unwrap();
            assert!(!signature.is_empty());

            // Verify the signature
            algorithm
                .verify(timestamp, nonce, data, &signature)
                .unwrap();
        }

        #[test]
        fn test_hmac_sha256_invalid_signature() {
            let algorithm = HmacSha256Algorithm::new(b"test_key");
            let timestamp = 1234567890;
            let nonce = "test_nonce";
            let data = b"test_payload";

            // Try to verify with wrong signature
            let result = algorithm.verify(timestamp, nonce, data, "invalid_signature");
            assert!(matches!(result, Err(NonceError::CryptoError(_))));

            // Try to verify with wrong data
            let signature = algorithm.sign(timestamp, nonce, data).unwrap();
            let result = algorithm.verify(timestamp, nonce, b"wrong_data", &signature);
            assert!(matches!(result, Err(NonceError::InvalidSignature)));
        }

        #[test]
        fn test_hmac_sha256_sign_with() {
            let algorithm = HmacSha256Algorithm::new(b"test_key");
            let timestamp = 1234567890;
            let nonce = "test_nonce";

            // Sign with custom data
            let signature = algorithm
                .sign_with(timestamp, nonce, |mac| {
                    mac.update(b"custom_data");
                    mac.update(b"more_data");
                })
                .unwrap();

            // Verify with the same custom data
            algorithm
                .verify_with(timestamp, nonce, &signature, |mac| {
                    mac.update(b"custom_data");
                    mac.update(b"more_data");
                })
                .unwrap();

            // Verify should fail with different data
            let result = algorithm.verify_with(timestamp, nonce, &signature, |mac| {
                mac.update(b"different_data");
            });
            assert!(matches!(result, Err(NonceError::InvalidSignature)));
        }

        #[test]
        fn test_hmac_sha256_different_keys_different_signatures() {
            let algorithm1 = HmacSha256Algorithm::new(b"key1");
            let algorithm2 = HmacSha256Algorithm::new(b"key2");
            let timestamp = 1234567890;
            let nonce = "test_nonce";
            let data = b"test_payload";

            let signature1 = algorithm1.sign(timestamp, nonce, data).unwrap();
            let signature2 = algorithm2.sign(timestamp, nonce, data).unwrap();

            // Different keys should produce different signatures
            assert_ne!(signature1, signature2);

            // Cross-verification should fail
            let result = algorithm1.verify(timestamp, nonce, data, &signature2);
            assert!(matches!(result, Err(NonceError::InvalidSignature)));
        }
    }
}

/// Type alias for the default signature algorithm.
#[cfg(feature = "algo-hmac-sha256")]
pub type DefaultSignatureAlgorithm = hmac_sha256::HmacSha256Algorithm;

/// Create the default signature algorithm with the given key.
#[cfg(feature = "algo-hmac-sha256")]
pub fn create_default_algorithm(key: &[u8]) -> DefaultSignatureAlgorithm {
    hmac_sha256::HmacSha256Algorithm::new(key)
}

/// Create the default signature algorithm with the given key.
#[cfg(not(feature = "algo-hmac-sha256"))]
pub fn create_default_algorithm(_key: &[u8]) -> ! {
    compile_error!("No signature algorithm available. Enable at least one algorithm feature.");
}
