//! Example demonstrating the metrics collection functionality.
//!
//! This example shows how to:
//! - Enable basic metrics collection
//! - Perform some authentication operations
//! - Retrieve and display metrics
//!
//! Run with: cargo run --example metrics_example --features metrics

#[cfg(feature = "metrics")]
use nonce_auth::nonce::{InMemoryMetricsCollector, MetricsCollector};
#[cfg(feature = "metrics")]
use nonce_auth::{NonceClient, NonceServer};
#[cfg(feature = "metrics")]
use std::sync::Arc;
#[cfg(feature = "metrics")]
use tokio::time::{Duration, sleep};

#[cfg(not(feature = "metrics"))]
fn main() {
    println!("This example requires the 'metrics' feature to be enabled.");
    println!("Run with: cargo run --example metrics_example --features metrics");
}

#[cfg(feature = "metrics")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::fmt::init();

    println!("🚀 Metrics Example - Nonce Authentication Library");
    println!("================================================\n");

    // Method 1: Enable basic metrics collection using the convenience method
    println!("📊 Setting up metrics collection...");
    let (server_builder, metrics_collector) = NonceServer::builder().enable_basic_metrics();

    let server = server_builder.build_and_init().await?;
    println!("✅ Server initialized with metrics collection enabled\n");

    // Create a client for testing
    let client = NonceClient::new(b"test_secret_key");
    println!("🔑 Client created with shared secret\n");

    // Perform some authentication operations to generate metrics
    println!("🧪 Performing authentication operations...");

    // Successful operations
    for i in 1..=5 {
        let payload = format!("test_payload_{}", i);
        let credential = client.credential_builder().sign(payload.as_bytes())?;

        let result = server
            .credential_verifier(&credential)
            .with_secret(b"test_secret_key")
            .verify(payload.as_bytes())
            .await;

        match result {
            Ok(_) => println!("  ✅ Authentication {} succeeded", i),
            Err(e) => println!("  ❌ Authentication {} failed: {}", i, e),
        }
    }

    // Failed operations (wrong secret)
    println!("\n🔒 Testing failed authentications...");
    for i in 1..=3 {
        let payload = format!("test_payload_fail_{}", i);
        let credential = client.credential_builder().sign(payload.as_bytes())?;

        let result = server
            .credential_verifier(&credential)
            .with_secret(b"wrong_secret_key") // Wrong secret
            .verify(payload.as_bytes())
            .await;

        match result {
            Ok(_) => println!("  ✅ Authentication {} succeeded (unexpected)", i),
            Err(e) => println!("  ❌ Authentication {} failed as expected: {}", i, e),
        }
    }

    // Test duplicate nonce (should fail)
    println!("\n🔄 Testing duplicate nonce...");
    let payload = b"duplicate_test";
    let credential = client.credential_builder().sign(payload)?;

    // First attempt should succeed
    let first_result = server
        .credential_verifier(&credential)
        .with_secret(b"test_secret_key")
        .verify(payload)
        .await;
    println!("  First attempt: {:?}", first_result);

    // Second attempt should fail with duplicate nonce
    let second_result = server
        .credential_verifier(&credential)
        .with_secret(b"test_secret_key")
        .verify(payload)
        .await;
    println!("  Second attempt: {:?}", second_result);

    // Wait a moment for async metrics recording
    sleep(Duration::from_millis(100)).await;

    // Retrieve and display metrics
    println!("\n📈 Current Metrics:");
    println!("==================");
    let metrics = metrics_collector.get_metrics().await?;

    println!("🎯 Verification Statistics:");
    println!("  • Total attempts: {}", metrics.verification_attempts);
    println!(
        "  • Successful: {} ({:.1}%)",
        metrics.verification_successes,
        percentage(
            metrics.verification_successes,
            metrics.verification_attempts
        )
    );
    println!(
        "  • Failed: {} ({:.1}%)",
        metrics.verification_failures,
        percentage(metrics.verification_failures, metrics.verification_attempts)
    );

    println!("\n⚡ Performance Metrics:");
    println!(
        "  • Average verification time: {} μs",
        metrics.performance.avg_verification_time_us
    );
    println!(
        "  • Average storage operation time: {} μs",
        metrics.performance.avg_storage_time_us
    );
    println!(
        "  • Total performance samples: {}",
        metrics.performance.sample_count
    );

    println!("\n🗃️ Storage Operations:");
    println!("  • Total operations: {}", metrics.storage_operations);

    println!("\n🧹 Cleanup Operations:");
    println!("  • Total cleanup runs: {}", metrics.cleanup_operations);

    println!("\n❌ Error Breakdown:");
    println!(
        "  • Duplicate nonce: {}",
        metrics.error_counts.duplicate_nonce
    );
    println!("  • Expired nonce: {}", metrics.error_counts.expired_nonce);
    println!(
        "  • Invalid signature: {}",
        metrics.error_counts.invalid_signature
    );
    println!(
        "  • Database errors: {}",
        metrics.error_counts.database_errors
    );
    println!("  • Crypto errors: {}", metrics.error_counts.crypto_errors);
    println!("  • Other errors: {}", metrics.error_counts.other_errors);

    // Demonstrate metrics reset functionality
    println!("\n🔄 Resetting metrics...");
    metrics_collector.reset_metrics().await?;
    let reset_metrics = metrics_collector.get_metrics().await?;
    println!(
        "✅ Metrics after reset - Total attempts: {}",
        reset_metrics.verification_attempts
    );

    // Example of using a custom metrics collector
    println!("\n🛠️ Custom Metrics Collector Example:");
    let custom_collector = Arc::new(InMemoryMetricsCollector::new());

    let server_with_custom_metrics = NonceServer::builder()
        .with_metrics_collector(Arc::clone(&custom_collector) as Arc<dyn MetricsCollector>)
        .build_and_init()
        .await?;

    // Perform one operation with custom collector
    let credential = client.credential_builder().sign(b"custom_test")?;
    let _ = server_with_custom_metrics
        .credential_verifier(&credential)
        .with_secret(b"test_secret_key")
        .verify(b"custom_test")
        .await;

    sleep(Duration::from_millis(50)).await;
    let custom_metrics = custom_collector.get_metrics().await?;
    println!(
        "  Custom collector recorded {} verification attempts",
        custom_metrics.verification_attempts
    );

    println!("\n🎉 Metrics example completed successfully!");
    Ok(())
}

#[cfg(feature = "metrics")]
fn percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}
