use hmac::Mac;
use nonce_auth::{NonceClient, NonceServer};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pre-shared key between client and server
    let psk = b"my-secret-key";

    // Initialize server
    NonceServer::init().await?;
    let server = NonceServer::new(
        psk,
        Some(Duration::from_secs(300)), // 5 minutes TTL for nonce storage
        Some(Duration::from_secs(60)),  // 1 minute time window for timestamp validation
    );

    // Initialize client
    let client = NonceClient::new(psk);

    // Client generates authentication data with custom signature (timestamp + nonce)
    let auth_data = client.create_auth_data(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
    })?;
    println!("Generated authentication data: {auth_data:?}");

    // Server verifies the authentication data with matching signature algorithm
    match server
        .verify_auth_data(&auth_data, None, |mac| {
            mac.update(auth_data.timestamp.to_string().as_bytes());
            mac.update(auth_data.nonce.as_bytes());
        })
        .await
    {
        Ok(()) => println!("✅ Authentication verified successfully"),
        Err(e) => println!("❌ Authentication verification failed: {e:?}"),
    }

    // Try to use the same nonce again (should fail)
    match server
        .verify_auth_data(&auth_data, None, |mac| {
            mac.update(auth_data.timestamp.to_string().as_bytes());
            mac.update(auth_data.nonce.as_bytes());
        })
        .await
    {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✅ Correctly rejected duplicate nonce: {e:?}"),
    }

    Ok(())
}
