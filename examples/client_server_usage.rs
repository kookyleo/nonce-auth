use nonce_auth::{NonceClient, NonceServer};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Shared secret between client and server
    let secret = b"my-secret-key";

    // Initialize server
    NonceServer::init().await?;
    let server = NonceServer::new(
        secret,
        Some(Duration::from_secs(300)), // 5 minutes TTL for nonce storage
        Some(Duration::from_secs(60)),  // 1 minute time window for timestamp validation
    );

    // Initialize client
    let client = NonceClient::new(secret);

    // Client generates a signed request
    let signed_request = client.create_signed_request()?;
    println!("Generated signed request: {signed_request:?}");

    // Server verifies the signed request
    match server.verify_signed_request(&signed_request, None).await {
        Ok(()) => println!("✅ Request verified successfully"),
        Err(e) => println!("❌ Request verification failed: {e:?}"),
    }

    // Try to use the same nonce again (should fail)
    match server.verify_signed_request(&signed_request, None).await {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✅ Correctly rejected duplicate nonce: {e:?}"),
    }

    Ok(())
}
