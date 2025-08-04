use nonce_auth::{
    CredentialBuilder, CredentialVerifier, storage::MemoryStorage, storage::NonceStorage,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pre-shared key for authentication
    let psk = b"my-secret-key";

    // Initialize storage backend
    let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());

    // Generate a credential for a given payload
    let payload = b"my_important_request_payload";
    let credential = CredentialBuilder::new(psk).sign(payload)?;
    println!("Generated credential: {credential:?}");

    // Verify the credential
    match CredentialVerifier::new(Arc::clone(&storage))
        .with_secret(psk)
        .verify(&credential, payload)
        .await
    {
        Ok(()) => println!("✅ Authentication verified successfully"),
        Err(e) => println!("❌ Authentication verification failed: {e:?}"),
    }

    // Try to use the same credential again (should fail - replay attack)
    match CredentialVerifier::new(storage)
        .with_secret(psk)
        .verify(&credential, payload)
        .await
    {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✅ Correctly rejected duplicate nonce: {e:?}"),
    }

    Ok(())
}
