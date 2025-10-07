// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Performance and stress tests for rsproperties public API
//!
//! These tests verify performance characteristics and robustness
//! under various stress conditions.

use rsproperties::{self, Result};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[path = "common.rs"]
mod common;
use common::init_test;

async fn setup_perf_test_env() {
    let _ = env_logger::builder().is_test(true).try_init();
    init_test().await;
}

#[tokio::test]
async fn test_property_get_performance() -> Result<()> {
    setup_perf_test_env().await;

    // Set up some test properties
    let test_props = vec![
        ("perf.test.prop1", "value1"),
        ("perf.test.prop2", "value2"),
        ("perf.test.prop3", "value3"),
        ("perf.test.prop4", "value4"),
        ("perf.test.prop5", "value5"),
    ];

    for (name, value) in &test_props {
        rsproperties::set(name, value)?;
    }

    // Measure get performance
    let iterations = 10000;
    let start = Instant::now();

    for i in 0..iterations {
        let prop_name = &test_props[i % test_props.len()].0;
        let _value: String = rsproperties::get(prop_name).unwrap_or_default();
    }

    let elapsed = start.elapsed();
    let avg_time = elapsed / iterations as u32;

    println!("Get performance: {iterations} iterations in {elapsed:?}");
    println!("Average time per get: {avg_time:?}");
    println!(
        "Gets per second: {:.0}",
        iterations as f64 / elapsed.as_secs_f64()
    );

    // Verify performance is reasonable (less than 100μs per get on average)
    assert!(
        avg_time < Duration::from_micros(100),
        "Get operation too slow: {avg_time:?} per operation"
    );

    Ok(())
}

#[tokio::test]
async fn test_property_get_or_performance() -> Result<()> {
    setup_perf_test_env().await;

    // Test both existing and non-existing properties
    rsproperties::set("existing.perf.prop", "existing_value")?;

    let iterations = 5000;

    // Test existing property performance
    let start = Instant::now();
    for _ in 0..iterations {
        let _value = rsproperties::get_or("existing.perf.prop", "default".to_string());
    }
    let existing_elapsed = start.elapsed();

    // Test non-existing property performance
    let start = Instant::now();
    for _ in 0..iterations {
        let _value = rsproperties::get_or("nonexistent.perf.prop", "default".to_string());
    }
    let nonexistent_elapsed = start.elapsed();

    println!("get_or performance:");
    println!(
        "  Existing property: {} ops in {:?} ({:?} avg)",
        iterations,
        existing_elapsed,
        existing_elapsed / iterations
    );
    println!(
        "  Non-existing property: {} ops in {:?} ({:?} avg)",
        iterations,
        nonexistent_elapsed,
        nonexistent_elapsed / iterations
    );

    // Both should be reasonably fast
    assert!(existing_elapsed / iterations < Duration::from_micros(60));
    assert!(nonexistent_elapsed / iterations < Duration::from_micros(50));

    Ok(())
}

#[tokio::test]
async fn test_property_set_performance() -> Result<()> {
    setup_perf_test_env().await;

    let iterations = 100;
    let start = Instant::now();

    for i in 0..iterations {
        let prop_name = format!("perf.set.prop.{i}");
        let prop_value = format!("value_{i}");
        rsproperties::set(&prop_name, &prop_value)?;
    }

    let elapsed = start.elapsed();
    let avg_time = elapsed / iterations;

    println!("Set performance: {iterations} iterations in {elapsed:?}");
    println!("Average time per set: {avg_time:?}");
    println!(
        "Sets per second: {:.0}",
        iterations as f64 / elapsed.as_secs_f64()
    );

    // Verify set performance (should be under 1ms per operation)
    assert!(
        avg_time < Duration::from_millis(1),
        "Set operation too slow: {avg_time:?} per operation"
    );

    Ok(())
}

#[tokio::test]
async fn test_large_property_values() -> Result<()> {
    setup_perf_test_env().await;

    // Test with various sizes approaching PROP_VALUE_MAX
    let sizes = vec![10, 50, 80, rsproperties::PROP_VALUE_MAX - 5];

    for size in sizes {
        let prop_name = format!("perf.large.prop.{size}");
        let large_value = "x".repeat(size);

        let start = Instant::now();
        rsproperties::set(&prop_name, &large_value)?;
        let set_time = start.elapsed();

        let start = Instant::now();
        let retrieved: String = rsproperties::get(&prop_name)?;
        let get_time = start.elapsed();

        assert_eq!(retrieved, large_value);

        println!("Size {size}: set={set_time:?}, get={get_time:?}");

        // Performance should not degrade significantly with size
        assert!(set_time < Duration::from_millis(10));
        assert!(get_time < Duration::from_millis(1));
    }

    Ok(())
}

#[tokio::test]
async fn test_concurrent_reads() -> Result<()> {
    setup_perf_test_env().await;

    // Set up test properties
    let num_props = 100;
    for i in 0..num_props {
        let prop_name = format!("concurrent.read.prop.{i}");
        let prop_value = format!("value_{i}");
        rsproperties::set(&prop_name, &prop_value)?;
    }

    let num_threads = 4;
    let reads_per_thread = 1000;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let barrier = Arc::clone(&barrier);

            thread::spawn(move || {
                barrier.wait(); // Synchronize start

                let start = Instant::now();
                for i in 0..reads_per_thread {
                    let prop_name = format!("concurrent.read.prop.{}", i % num_props);
                    let expected = format!("value_{}", i % num_props);
                    let value: String = rsproperties::get(&prop_name).unwrap_or_default();
                    assert_eq!(value, expected, "Failed to get property {prop_name}");
                }
                let elapsed = start.elapsed();

                println!("Thread {thread_id} completed {reads_per_thread} reads in {elapsed:?}");
                elapsed
            })
        })
        .collect();

    let mut total_time = Duration::new(0, 0);
    for handle in handles {
        let thread_time = handle.join().unwrap();
        total_time += thread_time;
    }

    let total_reads = num_threads * reads_per_thread;
    println!(
        "Concurrent reads: {} total reads, avg thread time: {:?}",
        total_reads,
        total_time / num_threads as u32
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_writes() -> Result<()> {
    setup_perf_test_env().await;

    let num_threads = 3;
    let writes_per_thread = 20;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let barrier = Arc::clone(&barrier);

            thread::spawn(move || -> Result<Duration> {
                barrier.wait(); // Synchronize start

                let start = Instant::now();
                for i in 0..writes_per_thread {
                    let prop_name = format!("concurrent.write.{thread_id}.prop.{i}");
                    let prop_value = format!("thread_{thread_id}_value_{i}");
                    rsproperties::set(&prop_name, &prop_value)?;
                }
                let elapsed = start.elapsed();

                println!("Thread {thread_id} completed {writes_per_thread} writes in {elapsed:?}");
                Ok(elapsed)
            })
        })
        .collect();

    let mut total_time = Duration::new(0, 0);
    for handle in handles {
        let thread_time = handle.join().unwrap()?;
        total_time += thread_time;
    }

    // Verify writes completed
    for thread_id in 0..num_threads {
        for i in 0..writes_per_thread {
            let prop_name = format!("concurrent.write.{thread_id}.prop.{i}");
            let expected = format!("thread_{thread_id}_value_{i}");
            let value: String = rsproperties::get(&prop_name).unwrap_or_default();
            assert_eq!(value, expected);
        }
    }

    let total_writes = num_threads * writes_per_thread;
    println!(
        "Concurrent writes: {} total writes, avg thread time: {:?}",
        total_writes,
        total_time / num_threads as u32
    );

    Ok(())
}

#[tokio::test]
async fn test_mixed_read_write_workload() -> Result<()> {
    setup_perf_test_env().await;

    // Set up initial properties
    for i in 0..50 {
        let prop_name = format!("mixed.initial.prop.{i}");
        let prop_value = format!("initial_value_{i}");
        rsproperties::set(&prop_name, &prop_value)?;
    }

    let num_threads = 4;
    let operations_per_thread = 50;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let barrier = Arc::clone(&barrier);

            thread::spawn(move || -> Result<()> {
                barrier.wait();

                let start = Instant::now();
                for i in 0..operations_per_thread {
                    if i % 3 == 0 {
                        // Write operation
                        let prop_name = format!("mixed.thread.{thread_id}.prop.{i}");
                        let prop_value = format!("value_{thread_id}_{i}");
                        rsproperties::set(&prop_name, &prop_value)?;
                    } else {
                        // Read operation
                        let prop_name = format!("mixed.initial.prop.{}", i % 50);
                        let _value: String = rsproperties::get(&prop_name).unwrap_or_default();
                    }
                }
                let elapsed = start.elapsed();

                println!("Mixed workload thread {thread_id} completed in {elapsed:?}");
                Ok(())
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap()?;
    }

    println!("Mixed read/write workload completed successfully");

    Ok(())
}

#[tokio::test]
async fn test_property_name_patterns() -> Result<()> {
    setup_perf_test_env().await;

    // Test various property name patterns
    let patterns = vec![
        ("short", "value"),
        ("medium.length.property", "value"),
        (
            "very.long.property.name.with.many.segments.and.dots",
            "value",
        ),
        ("property_with_underscores", "value"),
        ("property.with.123.numbers", "value"),
        ("ro.build.version.sdk", "33"),  // Android-style
        ("persist.sys.locale", "en-US"), // Android-style
    ];

    let iterations = 1000;

    for (prop_name, prop_value) in &patterns {
        // Set the property
        rsproperties::set(prop_name, prop_value)?;

        // Measure get performance for this pattern
        let start = Instant::now();
        for _ in 0..iterations {
            let _value: String = rsproperties::get(prop_name).unwrap_or_default();
        }
        let elapsed = start.elapsed();

        println!(
            "Pattern '{}': {} gets in {:?} ({:?} avg)",
            prop_name,
            iterations,
            elapsed,
            elapsed / iterations
        );

        // Verify correctness
        let retrieved: String = rsproperties::get(prop_name)?;
        assert_eq!(retrieved, *prop_value);
    }

    Ok(())
}
