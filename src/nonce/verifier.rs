use hmac::Mac;

use crate::NonceCredential;
use crate::nonce::{NonceError, NonceServer};
use crate::storage::NonceStorage;

/// A verifier for `NonceCredential`s, created by `NonceServer::credential_verifier`.
///
/// This builder-like struct provides a safe and ergonomic API for verifying credentials.
#[must_use = "The verifier does nothing unless one of the `verify` methods is called."]
pub struct CredentialVerifier<'a, S: NonceStorage> {
    server: &'a NonceServer<S>,
    credential: &'a NonceCredential,
    context: Option<&'a str>,
}

impl<'a, S: NonceStorage> CredentialVerifier<'a, S> {
    /// Creates a new verifier.
    pub(crate) fn new(server: &'a NonceServer<S>, credential: &'a NonceCredential) -> Self {
        Self {
            server,
            credential,
            context: None,
        }
    }

    /// Sets the context for this verification operation.
    ///
    /// The context provides an additional layer of isolation for nonces.
    pub fn with_context(mut self, context: Option<&'a str>) -> Self {
        self.context = context;
        self
    }

    /// Verifies the credential against a standard payload.
    ///
    /// This is the recommended verification method for most use cases. It assumes the
    /// signature was created on the client using `sign(payload)`.
    ///
    /// # Arguments
    ///
    /// * `payload`: The payload that was signed on the client side.
    pub async fn verify(self, payload: &[u8]) -> Result<(), NonceError> {
        let timestamp_str = self.credential.timestamp.to_string();
        let nonce_str = &self.credential.nonce;

        self.verify_with(|mac| {
            mac.update(timestamp_str.as_bytes());
            mac.update(nonce_str.as_bytes());
            mac.update(payload);
        })
        .await
    }

    /// Verifies the credential using custom signature-reconstruction logic.
    ///
    /// This method is for advanced scenarios where the signature includes more than
    /// just the standard payload.
    ///
    /// # Warning
    ///
    /// The logic in the `signature_builder` closure must exactly match the logic
    /// used on the client side in `sign_with`, otherwise verification will fail.
    ///
    /// # Arguments
    ///
    /// * `signature_builder`: A closure to reconstruct the signed data.
    pub async fn verify_with<F>(self, signature_builder: F) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        self.server.verify_timestamp(self.credential.timestamp)?;
        self.server
            .verify_signature(&self.credential.signature, signature_builder)?;
        self.server
            .verify_and_consume_nonce(&self.credential.nonce, self.context)
            .await
    }
}
