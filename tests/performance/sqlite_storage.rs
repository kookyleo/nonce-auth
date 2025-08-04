//! Performance tests for SQLite storage backend
//!
//! These tests measure the performance characteristics of the optimized SQLite storage
//! implementation and verify that optimizations provide expected improvements.
//!
//! Run with: cargo test --test performance --features sqlite-storage -- sqlite

use nonce_auth::NonceStorage;
#[cfg(feature = "sqlite-storage")]
use nonce_auth::storage::SqliteStorage;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const LARGE_DATASET_SIZE: usize = 10_000;
const MEDIUM_DATASET_SIZE: usize = 5_000;
const SMALL_DATASET_SIZE: usize = 1_000;

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_wal_mode_vs_memory() {
    let temp_file = format!("/tmp/perf_test_wal_{}.db", std::process::id());
    let dataset_size = MEDIUM_DATASET_SIZE;
    
    // Test in-memory SQLite
    let memory_storage = Arc::new(SqliteStorage::new(":memory:").unwrap());
    memory_storage.init().await.unwrap();
    
    let start = Instant::now();
    for i in 0..dataset_size {
        memory_storage.set(&format!("mem-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let memory_time = start.elapsed();
    
    // Test file-based SQLite with WAL mode
    let file_storage = Arc::new(SqliteStorage::new(&temp_file).unwrap());
    file_storage.init().await.unwrap();
    
    let start = Instant::now();
    for i in 0..dataset_size {
        file_storage.set(&format!("file-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let file_time = start.elapsed();
    
    println!("WAL mode vs Memory test:");
    println!("  In-memory SQLite: {:?} ({:.0} ops/sec)", 
        memory_time, dataset_size as f64 / memory_time.as_secs_f64());
    println!("  File-based WAL: {:?} ({:.0} ops/sec)", 
        file_time, dataset_size as f64 / file_time.as_secs_f64());
    
    let memory_stats = memory_storage.get_stats().await.unwrap();
    let file_stats = file_storage.get_stats().await.unwrap();
    
    println!("  Memory storage: {}", memory_stats.backend_info);
    println!("  File storage: {}", file_stats.backend_info);
    
    // Both should have the same number of records
    assert_eq!(memory_stats.total_records, dataset_size);
    assert_eq!(file_stats.total_records, dataset_size);
    
    // Memory should be faster, but file-based should still be reasonable
    let memory_ops_per_sec = dataset_size as f64 / memory_time.as_secs_f64();
    let file_ops_per_sec = dataset_size as f64 / file_time.as_secs_f64();
    
    assert!(memory_ops_per_sec > 20_000.0, "Memory SQLite should exceed 20k ops/sec");
    assert!(file_ops_per_sec > 5_000.0, "File SQLite should exceed 5k ops/sec");
    
    // Cleanup
    std::fs::remove_file(&temp_file).ok();
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_prepared_statement_caching() {
    let storage = Arc::new(SqliteStorage::new(":memory:").unwrap());
    storage.init().await.unwrap();
    
    let dataset_size = LARGE_DATASET_SIZE;
    
    // Multiple operations of the same type should benefit from statement caching
    let start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("cache-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let write_time = start.elapsed();
    
    let start = Instant::now();
    for i in 0..dataset_size {
        let nonce = format!("cache-test-{}", i);
        let _ = storage.get(&nonce, None).await.unwrap();
    }
    let read_time = start.elapsed();
    
    let start = Instant::now();
    for i in 0..dataset_size {
        let nonce = format!("cache-test-{}", i);
        let _ = storage.exists(&nonce, None).await.unwrap();
    }
    let exists_time = start.elapsed();
    
    println!("Prepared statement caching test:");
    println!("  Writes: {:?} ({:.0} ops/sec)", 
        write_time, dataset_size as f64 / write_time.as_secs_f64());
    println!("  Reads: {:?} ({:.0} ops/sec)", 
        read_time, dataset_size as f64 / read_time.as_secs_f64());
    println!("  Exists: {:?} ({:.0} ops/sec)", 
        exists_time, dataset_size as f64 / exists_time.as_secs_f64());
    
    // Should achieve reasonable performance with statement caching
    let write_ops_per_sec = dataset_size as f64 / write_time.as_secs_f64();
    let read_ops_per_sec = dataset_size as f64 / read_time.as_secs_f64();
    let exists_ops_per_sec = dataset_size as f64 / exists_time.as_secs_f64();
    
    assert!(write_ops_per_sec > 30_000.0, "Cached writes should exceed 30k ops/sec");
    assert!(read_ops_per_sec > 100_000.0, "Cached reads should exceed 100k ops/sec");
    assert!(exists_ops_per_sec > 100_000.0, "Cached exists should exceed 100k ops/sec");
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_batch_operations() {
    let storage = Arc::new(SqliteStorage::new(":memory:").unwrap());
    storage.init().await.unwrap();
    
    let dataset_size = MEDIUM_DATASET_SIZE;
    
    // Individual operations
    let start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("individual-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let individual_time = start.elapsed();
    
    // Batch operations
    let batch_nonces: Vec<(&str, Option<&str>)> = (0..dataset_size)
        .map(|i| (Box::leak(format!("batch-{}", i).into_boxed_str()) as &str, None))
        .collect();
    
    let start = Instant::now();
    let inserted = storage.batch_set(batch_nonces, Duration::from_secs(60)).await.unwrap();
    let batch_time = start.elapsed();
    
    println!("SQLite batch operations test:");
    println!("  Individual operations: {:?} ({:.0} ops/sec)", 
        individual_time, dataset_size as f64 / individual_time.as_secs_f64());
    println!("  Batch operations: {:?} ({:.0} ops/sec)", 
        batch_time, inserted as f64 / batch_time.as_secs_f64());
    
    let improvement = individual_time.as_secs_f64() / batch_time.as_secs_f64();
    println!("  Improvement: {:.1}x faster", improvement);
    
    assert_eq!(inserted, dataset_size);
    // Batch operations should be faster due to single transaction
    assert!(improvement > 1.5, "Batch operations should provide at least 50% improvement");
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_concurrent_wal_performance() {
    let temp_file = format!("/tmp/perf_test_concurrent_{}.db", std::process::id());
    let storage = Arc::new(SqliteStorage::new(&temp_file).unwrap());
    storage.init().await.unwrap();
    
    let tasks = 5; // SQLite has limited concurrent write support
    let ops_per_task = SMALL_DATASET_SIZE;
    let total_ops = tasks * ops_per_task;
    
    // Concurrent writes (WAL mode should help)
    let start = Instant::now();
    let mut write_tasks = JoinSet::new();
    
    for task_id in 0..tasks {
        let storage_clone = storage.clone();
        write_tasks.spawn(async move {
            for i in 0..ops_per_task {
                let nonce = format!("concurrent-{}-{}", task_id, i);
                storage_clone.set(&nonce, None, Duration::from_secs(60)).await.unwrap();
            }
        });
    }
    
    while let Some(_) = write_tasks.join_next().await {}
    let write_time = start.elapsed();
    
    // Concurrent reads (should benefit significantly from WAL mode)
    let start = Instant::now();
    let mut read_tasks = JoinSet::new();
    
    for task_id in 0..tasks {
        let storage_clone = storage.clone();
        read_tasks.spawn(async move {
            for i in 0..ops_per_task {
                let nonce = format!("concurrent-{}-{}", task_id, i);
                let _ = storage_clone.get(&nonce, None).await.unwrap();
            }
        });
    }
    
    while let Some(_) = read_tasks.join_next().await {}
    let read_time = start.elapsed();
    
    println!("SQLite concurrent WAL test:");
    println!("  Concurrent writes ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, write_time, total_ops as f64 / write_time.as_secs_f64());
    println!("  Concurrent reads ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, read_time, total_ops as f64 / read_time.as_secs_f64());
    
    let stats = storage.get_stats().await.unwrap();
    assert_eq!(stats.total_records, total_ops);
    
    // WAL mode should enable reasonable concurrent performance
    let write_ops_per_sec = total_ops as f64 / write_time.as_secs_f64();
    let read_ops_per_sec = total_ops as f64 / read_time.as_secs_f64();
    
    assert!(write_ops_per_sec > 1_000.0, "Concurrent writes should exceed 1k ops/sec");
    assert!(read_ops_per_sec > 10_000.0, "Concurrent reads should exceed 10k ops/sec");
    
    // Cleanup
    std::fs::remove_file(&temp_file).ok();
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_transaction_cleanup_performance() {
    let storage = Arc::new(SqliteStorage::new(":memory:").unwrap());
    storage.init().await.unwrap();
    
    let dataset_size = 20_000;
    
    // Populate with test data
    println!("Populating {} entries for cleanup test...", dataset_size);
    let populate_start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("cleanup-{}", i), None, Duration::from_secs(300)).await.unwrap();
    }
    let populate_time = populate_start.elapsed();
    
    println!("Population completed in {:?}", populate_time);
    
    let stats_before = storage.get_stats().await.unwrap();
    println!("Storage before cleanup: {}", stats_before.backend_info);
    
    // Test cleanup performance (uses transaction)
    let cleanup_start = Instant::now();
    let deleted = storage.cleanup_expired(9999999999).await.unwrap();
    let cleanup_time = cleanup_start.elapsed();
    
    println!("SQLite cleanup performance test:");
    println!("  Cleaned up {} entries in {:?}", deleted, cleanup_time);
    println!("  Cleanup rate: {:.0} entries/sec", deleted as f64 / cleanup_time.as_secs_f64());
    
    assert_eq!(deleted, dataset_size);
    
    let stats_after = storage.get_stats().await.unwrap();
    assert_eq!(stats_after.total_records, 0);
    
    // Transaction-based cleanup should be efficient
    let cleanup_rate = deleted as f64 / cleanup_time.as_secs_f64();
    assert!(cleanup_rate > 100_000.0, "Transaction cleanup should exceed 100k entries/sec");
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_pragma_optimizations() {
    let temp_file = format!("/tmp/perf_test_pragma_{}.db", std::process::id());
    let storage = Arc::new(SqliteStorage::new(&temp_file).unwrap());
    storage.init().await.unwrap();
    
    let dataset_size = MEDIUM_DATASET_SIZE;
    
    // Test write performance with PRAGMA optimizations
    let start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("pragma-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let write_time = start.elapsed();
    
    // Test read performance
    let start = Instant::now();
    for i in 0..dataset_size {
        let nonce = format!("pragma-test-{}", i);
        let _ = storage.get(&nonce, None).await.unwrap();
    }
    let read_time = start.elapsed();
    
    println!("PRAGMA optimizations test:");
    println!("  Writes with optimizations: {:?} ({:.0} ops/sec)", 
        write_time, dataset_size as f64 / write_time.as_secs_f64());
    println!("  Reads with optimizations: {:?} ({:.0} ops/sec)", 
        read_time, dataset_size as f64 / read_time.as_secs_f64());
    
    let stats = storage.get_stats().await.unwrap();
    println!("  Final stats: {}", stats.backend_info);
    
    // Should achieve good performance with PRAGMA optimizations
    let write_ops_per_sec = dataset_size as f64 / write_time.as_secs_f64();
    let read_ops_per_sec = dataset_size as f64 / read_time.as_secs_f64();
    
    assert!(write_ops_per_sec > 10_000.0, "Optimized writes should exceed 10k ops/sec");
    assert!(read_ops_per_sec > 50_000.0, "Optimized reads should exceed 50k ops/sec");
    
    // Check that stats include WAL mode info
    assert!(stats.backend_info.contains("WAL mode"));
    
    // Cleanup
    std::fs::remove_file(&temp_file).ok();
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn test_batch_exists_performance() {
    let storage = Arc::new(SqliteStorage::new(":memory:").unwrap());
    storage.init().await.unwrap();
    
    let dataset_size = MEDIUM_DATASET_SIZE;
    
    // Populate with test data
    for i in 0..dataset_size {
        storage.set(&format!("exists-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    
    // Individual exists checks
    let start = Instant::now();
    for i in 0..dataset_size {
        let nonce = format!("exists-test-{}", i);
        let _ = storage.exists(&nonce, None).await.unwrap();
    }
    let individual_time = start.elapsed();
    
    // Batch exists checks
    let exists_nonces: Vec<(&str, Option<&str>)> = (0..dataset_size)
        .map(|i| (Box::leak(format!("exists-test-{}", i).into_boxed_str()) as &str, None))
        .collect();
    
    let start = Instant::now();
    let exists_results = storage.batch_exists(exists_nonces).await.unwrap();
    let batch_time = start.elapsed();
    
    println!("SQLite batch exists test:");
    println!("  Individual exists: {:?} ({:.0} ops/sec)", 
        individual_time, dataset_size as f64 / individual_time.as_secs_f64());
    println!("  Batch exists: {:?} ({:.0} ops/sec)", 
        batch_time, dataset_size as f64 / batch_time.as_secs_f64());
    
    let improvement = individual_time.as_secs_f64() / batch_time.as_secs_f64();
    println!("  Improvement: {:.1}x faster", improvement);
    
    let existing_count = exists_results.iter().filter(|&&r| r).count();
    assert_eq!(existing_count, dataset_size);
    
    // Batch exists should be faster due to single lock acquisition
    assert!(improvement > 1.2, "Batch exists should provide at least 20% improvement");
}

#[cfg(not(feature = "sqlite-storage"))]
#[tokio::test]
async fn test_sqlite_feature_disabled() {
    println!("SQLite storage tests skipped - sqlite-storage feature not enabled");
    println!("Run with: cargo test --features sqlite-storage");
}