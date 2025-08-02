use nonce_auth::{NonceClient, NonceServer};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pre-shared key between client and server
    let psk = b"my-secret-key";

    // Initialize server. By default, it uses `MemoryStorage`.
    let server = NonceServer::builder()
        .with_ttl(Duration::from_secs(300))
        .with_time_window(Duration::from_secs(60))
        .build_and_init()
        .await?;

    // To use a different storage backend, like SQLite:
    // let storage = Arc::new(SqliteStorage::new("my_app.db")?);
    // let server = NonceServer::builder()
    //     .with_storage(storage)
    //     .build_and_init()
    //     .await?;

    // Initialize client
    let client = NonceClient::new(psk);

    // Client generates a credential for a given payload
    let payload = b"my_important_request_payload";
    let credential = client.credential_builder().sign(payload)?;
    println!("Generated credential: {credential:?}");

    // Server verifies the credential using the standard method
    match server
        .credential_verifier(&credential)
        .with_secret(psk)
        .verify(payload)
        .await
    {
        Ok(()) => println!("✅ Authentication verified successfully"),
        Err(e) => println!("❌ Authentication verification failed: {e:?}"),
    }

    // Try to use the same credential again (should fail)
    match server
        .credential_verifier(&credential)
        .with_secret(psk)
        .verify(payload)
        .await
    {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✅ Correctly rejected duplicate nonce: {e:?}"),
    }

    Ok(())
}
