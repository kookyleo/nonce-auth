//! Performance tests for memory storage backend
//!
//! These tests measure the performance characteristics of the optimized memory storage
//! implementation and verify that optimizations provide expected improvements.
//!
//! Run with: cargo test --test performance --features default -- memory

use nonce_auth::NonceStorage;
use nonce_auth::storage::MemoryStorage;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const LARGE_DATASET_SIZE: usize = 10_000;
const MEDIUM_DATASET_SIZE: usize = 5_000;
const SMALL_DATASET_SIZE: usize = 1_000;

#[tokio::test]
async fn test_capacity_pre_allocation_performance() {
    let dataset_size = LARGE_DATASET_SIZE;
    
    // Without pre-allocation
    let storage_default = Arc::new(MemoryStorage::new());
    let start = Instant::now();
    for i in 0..dataset_size {
        storage_default.set(&format!("test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let time_default = start.elapsed();
    
    // With pre-allocation
    let storage_capacity = Arc::new(MemoryStorage::with_capacity(dataset_size));
    let start = Instant::now();
    for i in 0..dataset_size {
        storage_capacity.set(&format!("test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let time_capacity = start.elapsed();
    
    println!("Capacity pre-allocation test:");
    println!("  Without pre-allocation: {:?} ({:.0} ops/sec)", 
        time_default, dataset_size as f64 / time_default.as_secs_f64());
    println!("  With pre-allocation: {:?} ({:.0} ops/sec)", 
        time_capacity, dataset_size as f64 / time_capacity.as_secs_f64());
    
    let improvement = time_default.as_secs_f64() / time_capacity.as_secs_f64();
    println!("  Improvement: {:.1}x faster", improvement);
    
    // Should be at least 10% faster with pre-allocation
    assert!(improvement > 1.1, "Pre-allocation should provide at least 10% improvement");
}

#[tokio::test]
async fn test_batch_operations_performance() {
    let dataset_size = MEDIUM_DATASET_SIZE;
    let storage = Arc::new(MemoryStorage::with_capacity(dataset_size * 2));
    
    // Individual set operations
    let start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("individual-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let time_individual = start.elapsed();
    
    // Batch set operations
    let batch_nonces: Vec<(&str, Option<&str>)> = (0..dataset_size)
        .map(|i| (Box::leak(format!("batch-{}", i).into_boxed_str()) as &str, None))
        .collect();
    
    let start = Instant::now();
    let inserted = storage.batch_set(batch_nonces, Duration::from_secs(60)).await.unwrap();
    let time_batch = start.elapsed();
    
    println!("Batch operations test:");
    println!("  Individual operations: {:?} ({:.0} ops/sec)", 
        time_individual, dataset_size as f64 / time_individual.as_secs_f64());
    println!("  Batch operations: {:?} ({:.0} ops/sec)", 
        time_batch, inserted as f64 / time_batch.as_secs_f64());
    
    let improvement = time_individual.as_secs_f64() / time_batch.as_secs_f64();
    println!("  Improvement: {:.1}x faster", improvement);
    
    assert_eq!(inserted, dataset_size);
    // Batch operations should be at least 50% faster
    assert!(improvement > 1.5, "Batch operations should provide at least 50% improvement");
}

#[tokio::test]
async fn test_batch_read_performance() {
    let dataset_size = MEDIUM_DATASET_SIZE;
    let storage = Arc::new(MemoryStorage::with_capacity(dataset_size));
    
    // Populate with test data
    for i in 0..dataset_size {
        storage.set(&format!("read-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    
    // Individual reads
    let start = Instant::now();
    for i in 0..dataset_size {
        let nonce = format!("read-test-{}", i);
        let _ = storage.get(&nonce, None).await.unwrap();
    }
    let time_individual = start.elapsed();
    
    // Batch reads
    let read_nonces: Vec<(&str, Option<&str>)> = (0..dataset_size)
        .map(|i| (Box::leak(format!("read-test-{}", i).into_boxed_str()) as &str, None))
        .collect();
    
    let start = Instant::now();
    let read_results = storage.batch_get(read_nonces).await.unwrap();
    let time_batch = start.elapsed();
    
    println!("Batch read test:");
    println!("  Individual reads: {:?} ({:.0} ops/sec)", 
        time_individual, dataset_size as f64 / time_individual.as_secs_f64());
    println!("  Batch reads: {:?} ({:.0} ops/sec)", 
        time_batch, dataset_size as f64 / time_batch.as_secs_f64());
    
    let improvement = time_individual.as_secs_f64() / time_batch.as_secs_f64();
    println!("  Improvement: {:.1}x faster", improvement);
    
    let found_count = read_results.iter().filter(|r| r.is_some()).count();
    assert_eq!(found_count, dataset_size);
    // Batch reads should be significantly faster
    assert!(improvement > 2.0, "Batch reads should provide at least 2x improvement");
}

#[tokio::test]
async fn test_concurrent_performance() {
    let tasks = 10;
    let ops_per_task = SMALL_DATASET_SIZE;
    let total_ops = tasks * ops_per_task;
    
    let storage = Arc::new(MemoryStorage::with_capacity(total_ops));
    
    // Concurrent writes
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
    
    // Concurrent reads
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
    
    println!("Concurrent performance test:");
    println!("  Concurrent writes ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, write_time, total_ops as f64 / write_time.as_secs_f64());
    println!("  Concurrent reads ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, read_time, total_ops as f64 / read_time.as_secs_f64());
    
    let stats = storage.get_stats().await.unwrap();
    assert_eq!(stats.total_records, total_ops);
    
    // Should achieve reasonable concurrent performance
    let write_ops_per_sec = total_ops as f64 / write_time.as_secs_f64();
    let read_ops_per_sec = total_ops as f64 / read_time.as_secs_f64();
    
    assert!(write_ops_per_sec > 100_000.0, "Concurrent writes should exceed 100k ops/sec");
    assert!(read_ops_per_sec > 500_000.0, "Concurrent reads should exceed 500k ops/sec");
}

#[tokio::test]
async fn test_cleanup_performance() {
    let dataset_size = 50_000;
    let storage = Arc::new(MemoryStorage::with_capacity(dataset_size));
    
    // Populate with test data
    println!("Populating {} entries for cleanup test...", dataset_size);
    let populate_start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("cleanup-{}", i), None, Duration::from_secs(300)).await.unwrap();
    }
    let populate_time = populate_start.elapsed();
    
    println!("Population completed in {:?}", populate_time);
    
    let stats_before = storage.get_stats().await.unwrap();
    println!("Memory usage before cleanup: {}", stats_before.backend_info);
    
    // Test cleanup performance
    let cleanup_start = Instant::now();
    let deleted = storage.cleanup_expired(9999999999).await.unwrap();
    let cleanup_time = cleanup_start.elapsed();
    
    println!("Cleanup performance test:");
    println!("  Cleaned up {} entries in {:?}", deleted, cleanup_time);
    println!("  Cleanup rate: {:.0} entries/sec", deleted as f64 / cleanup_time.as_secs_f64());
    
    assert_eq!(deleted, dataset_size);
    
    let stats_after = storage.get_stats().await.unwrap();
    assert_eq!(stats_after.total_records, 0);
    
    // Should be able to cleanup at least 1M entries per second
    let cleanup_rate = deleted as f64 / cleanup_time.as_secs_f64();
    assert!(cleanup_rate > 1_000_000.0, "Cleanup should exceed 1M entries/sec");
}

#[tokio::test]
async fn test_memory_usage_accuracy() {
    let storage = MemoryStorage::with_capacity(1000);
    
    // Test with various nonce sizes
    let test_cases = vec![
        ("short", None),
        ("medium_length_nonce_name", Some("ctx")),
        ("very_very_long_nonce_name_for_memory_testing", Some("very_long_context_name_here")),
    ];
    
    for (nonce, context) in test_cases {
        storage.set(nonce, context, Duration::from_secs(300)).await.unwrap();
    }
    
    let stats = storage.get_stats().await.unwrap();
    println!("Memory usage test:");
    println!("  {}", stats.backend_info);
    
    // Should include capacity information
    assert!(stats.backend_info.contains("capacity"));
    assert!(stats.backend_info.contains("bytes"));
    assert_eq!(stats.total_records, 3);
    
    // Memory calculation should be reasonable (not just counting fixed size)
    // With string overhead, should be more than just 3 * sizeof(NonceEntry)
    let base_size = 3 * std::mem::size_of::<nonce_auth::storage::NonceEntry>();
    assert!(stats.backend_info.contains(&format!("{}", base_size + 100))); // Should be much larger
}

#[tokio::test]
async fn test_mixed_workload_performance() {
    let storage = Arc::new(MemoryStorage::with_capacity(5000));
    let tasks = 10;
    let ops_per_task = 500;
    
    let start = Instant::now();
    let mut mixed_tasks = JoinSet::new();
    
    for task_id in 0..tasks {
        let storage_clone = storage.clone();
        mixed_tasks.spawn(async move {
            for i in 0..ops_per_task {
                let nonce = format!("mixed-{}-{}", task_id, i);
                
                match i % 4 {
                    0 => {
                        // Write
                        let _ = storage_clone.set(&nonce, None, Duration::from_secs(60)).await;
                    }
                    1 => {
                        // Read
                        let _ = storage_clone.get(&nonce, None).await;
                    }
                    2 => {
                        // Exists check
                        let _ = storage_clone.exists(&nonce, None).await;
                    }
                    _ => {
                        // Write with context
                        let _ = storage_clone.set(&nonce, Some("ctx"), Duration::from_secs(60)).await;
                    }
                }
            }
        });
    }
    
    while let Some(_) = mixed_tasks.join_next().await {}
    let mixed_time = start.elapsed();
    
    let total_ops = tasks * ops_per_task;
    println!("Mixed workload test:");
    println!("  Mixed operations ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, mixed_time, total_ops as f64 / mixed_time.as_secs_f64());
    
    let final_stats = storage.get_stats().await.unwrap();
    println!("  Final records: {}", final_stats.total_records);
    println!("  Final memory: {}", final_stats.backend_info);
    
    // Should handle mixed workload efficiently
    let mixed_ops_per_sec = total_ops as f64 / mixed_time.as_secs_f64();
    assert!(mixed_ops_per_sec > 200_000.0, "Mixed workload should exceed 200k ops/sec");
}

#[tokio::test]
async fn test_batch_exists_performance() {
    let dataset_size = MEDIUM_DATASET_SIZE;
    let storage = Arc::new(MemoryStorage::with_capacity(dataset_size));
    
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
    let time_individual = start.elapsed();
    
    // Batch exists checks
    let exists_nonces: Vec<(&str, Option<&str>)> = (0..dataset_size)
        .map(|i| (Box::leak(format!("exists-test-{}", i).into_boxed_str()) as &str, None))
        .collect();
    
    let start = Instant::now();
    let exists_results = storage.batch_exists(exists_nonces).await.unwrap();
    let time_batch = start.elapsed();
    
    println!("Batch exists test:");
    println!("  Individual exists: {:?} ({:.0} ops/sec)", 
        time_individual, dataset_size as f64 / time_individual.as_secs_f64());
    println!("  Batch exists: {:?} ({:.0} ops/sec)", 
        time_batch, dataset_size as f64 / time_batch.as_secs_f64());
    
    let improvement = time_individual.as_secs_f64() / time_batch.as_secs_f64();
    println!("  Improvement: {:.1}x faster", improvement);
    
    let existing_count = exists_results.iter().filter(|&&r| r).count();
    assert_eq!(existing_count, dataset_size);
    // Batch exists should be significantly faster
    assert!(improvement > 2.0, "Batch exists should provide at least 2x improvement");
}