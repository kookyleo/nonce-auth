use hmac::Mac;
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

    // Client generates authentication data with custom signature (timestamp + nonce)
    let protection_data = client.create_protection_data(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
    })?;
    println!("Generated authentication data: {protection_data:?}");

    // Server verifies the authentication data with matching signature algorithm
    match server
        .verify_protection_data(&protection_data, None, |mac| {
            mac.update(protection_data.timestamp.to_string().as_bytes());
            mac.update(protection_data.nonce.as_bytes());
        })
        .await
    {
        Ok(()) => println!("✅ Authentication verified successfully"),
        Err(e) => println!("❌ Authentication verification failed: {e:?}"),
    }

    // Try to use the same nonce again (should fail)
    match server
        .verify_protection_data(&protection_data, None, |mac| {
            mac.update(protection_data.timestamp.to_string().as_bytes());
            mac.update(protection_data.nonce.as_bytes());
        })
        .await
    {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✅ Correctly rejected duplicate nonce: {e:?}"),
    }

    Ok(())
}
