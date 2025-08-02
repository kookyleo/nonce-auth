//! Demonstrates the improved AsyncNonceClient API with ergonomic helper functions.
//!
//! This example shows how the new helper functions make it much easier to create
//! async clients without the complex Box::new(|| Box::pin(async ..)) patterns.

use nonce_auth::{
    AsyncNonceClient, NonceServer, static_secret_provider, sync_nonce_generator, sync_time_provider,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("🚀 Improved AsyncNonceClient API Examples");
    println!("==========================================\n");

    // Example 1: Simple static secret (most common use case)
    println!("📝 Example 1: Static Secret");
    let simple_client = AsyncNonceClient::builder()
        .with_static_secret(b"my_static_secret".to_vec())
        .build();

    let payload = b"test_payload_1";
    let credential1 = simple_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with static secret: {}",
        credential1.nonce
    );

    // Example 2: Async secret fetching (database/vault)
    println!("\n📝 Example 2: Async Secret Provider");
    let db_client = AsyncNonceClient::builder()
        .with_secret_provider(|| async {
            // Simulate fetching from database
            sleep(Duration::from_millis(10)).await;
            Ok(b"database_secret".to_vec())
        })
        .build();

    let credential2 = db_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with async secret: {}",
        credential2.nonce
    );

    // Example 3: Sync nonce generator (UUID is sync)
    println!("\n📝 Example 3: Sync Nonce Generator");
    let uuid_client = AsyncNonceClient::builder()
        .with_static_secret(b"secret".to_vec())
        .with_sync_nonce_generator(|| {
            format!(
                "custom-{}-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
                rand::random::<u32>()
            )
        })
        .build();

    let credential3 = uuid_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with sync nonce generator: {}",
        credential3.nonce
    );

    // Example 4: Async nonce generator (network call)
    println!("\n📝 Example 4: Async Nonce Generator");
    let network_client = AsyncNonceClient::builder()
        .with_static_secret(b"secret".to_vec())
        .with_nonce_generator(|| async {
            // Simulate network call to get distributed nonce
            sleep(Duration::from_millis(5)).await;
            Ok(format!("network-nonce-{}", rand::random::<u64>()))
        })
        .build();

    let credential4 = network_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with async nonce generator: {}",
        credential4.nonce
    );

    // Example 5: Sync time provider (system time)
    println!("\n📝 Example 5: Sync Time Provider");
    let sync_time_client = AsyncNonceClient::builder()
        .with_static_secret(b"secret".to_vec())
        .with_sync_time_provider(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
        })
        .build();

    let credential5 = sync_time_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with sync time provider: {}",
        credential5.nonce
    );

    // Example 6: Async time provider (NTP)
    println!("\n📝 Example 6: Async Time Provider");
    let ntp_client = AsyncNonceClient::builder()
        .with_static_secret(b"secret".to_vec())
        .with_time_provider(|| async {
            // Simulate NTP time synchronization
            sleep(Duration::from_millis(20)).await;
            Ok(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs())
        })
        .build();

    let credential6 = ntp_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with async time provider: {}",
        credential6.nonce
    );

    // Example 7: Using helper functions directly
    println!("\n📝 Example 7: Using Helper Functions Directly");

    // These helper functions are available for reuse if needed
    let _secret_provider = static_secret_provider(b"reusable_secret".to_vec());
    let _nonce_gen = sync_nonce_generator(|| uuid::Uuid::new_v4().to_string());
    let _time_prov = sync_time_provider(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time: {}", e)))
    });

    let modular_client = AsyncNonceClient::builder()
        .with_secret_provider(|| async {
            // You can still use the old API if needed for complex logic
            Ok(b"complex_secret".to_vec())
        })
        .build();

    let credential7 = modular_client.credential_builder().sign(payload).await?;
    println!(
        "✅ Generated credential with modular approach: {}",
        credential7.nonce
    );

    // Example 8: Performance comparison
    println!("\n📝 Example 8: Performance Test");
    let start = std::time::Instant::now();

    let perf_client = AsyncNonceClient::builder()
        .with_static_secret(b"perf_secret".to_vec())
        .with_sync_nonce_generator(|| uuid::Uuid::new_v4().to_string())
        .build();

    // Generate multiple credentials
    for i in 0..100 {
        let payload = format!("payload_{}", i);
        let _credential = perf_client
            .credential_builder()
            .sign(payload.as_bytes())
            .await?;
    }

    let elapsed = start.elapsed();
    println!(
        "✅ Generated 100 credentials in {:?} (avg: {:?}/credential)",
        elapsed,
        elapsed / 100
    );

    // Test with server
    println!("\n📝 Example 9: Server Integration Test");
    let server = NonceServer::builder().build_and_init().await?;

    let test_client = AsyncNonceClient::builder()
        .with_static_secret(b"server_test_secret".to_vec())
        .build();

    let test_payload = b"server_test_payload";
    let test_credential = test_client.credential_builder().sign(test_payload).await?;

    let verification_result = server
        .credential_verifier(&test_credential)
        .with_secret(b"server_test_secret")
        .verify(test_payload)
        .await;

    match verification_result {
        Ok(()) => println!("✅ Server verification successful!"),
        Err(e) => println!("❌ Server verification failed: {}", e),
    }

    println!("\n🎉 All examples completed successfully!");
    println!("\n💡 Key improvements:");
    println!("   • No more Box::new(|| Box::pin(async ..)) patterns");
    println!("   • Cleaner API with helper functions");
    println!("   • Better ergonomics for common use cases");
    println!("   • Separate sync/async variants for better performance");
    println!("   • Reusable provider functions");

    Ok(())
}
