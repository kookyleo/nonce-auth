use nonce_auth::{NonceClient, NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pre-shared key between client and server
    let psk = b"my-secret-key";

    // Create storage backend
    let storage = Arc::new(MemoryStorage::new());

    // Initialize server
    let server = NonceServer::new(
        psk,
        storage,                        // Storage backend
        Some(Duration::from_secs(300)), // 5 minutes TTL for nonce storage
        Some(Duration::from_secs(60)),  // 1 minute time window for timestamp validation
    );

    // Initialize the storage backend
    server.init().await?;

    // Initialize client
    let client = NonceClient::new(psk);

    // Client generates a credential for a given payload
    let payload = b"my_important_request_payload";
    let credential = client.credential_builder().sign(payload)?;
    println!("Generated credential: {credential:?}");

    // Server verifies the credential using the standard method
    match server
        .credential_verifier(&credential)
        .verify(payload)
        .await
    {
        Ok(()) => println!("✅ Authentication verified successfully"),
        Err(e) => println!("❌ Authentication verification failed: {e:?}"),
    }

    // Try to use the same credential again (should fail)
    match server
        .credential_verifier(&credential)
        .verify(payload)
        .await
    {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✅ Correctly rejected duplicate nonce: {e:?}"),
    }

    Ok(())
}
