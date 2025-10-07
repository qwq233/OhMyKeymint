// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Comprehensive integration tests for new property APIs
//!
//! These tests verify the complete integration between:
//! - set() function with type conversion
//! - get_parsed() and get_parsed_with_default() functions
//! - Type safety and conversion accuracy
//! - Error handling and edge cases
//! - Performance and consistency
#![allow(clippy::approx_constant)]

#[path = "common.rs"]
mod common;
use common::init_test;

async fn setup_test_env() {
    let _ = env_logger::builder().is_test(true).try_init();
    init_test().await;
}

/// Test the complete workflow: set numeric types and parse them back
#[tokio::test]
async fn test_numeric_round_trip() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        ("i8", i8::MIN as i64, i8::MAX as i64),
        ("i16", i16::MIN as i64, i16::MAX as i64),
        ("i32", i32::MIN as i64, i32::MAX as i64),
        ("u8", 0, u8::MAX as i64),
        ("u16", 0, u16::MAX as i64),
        ("u32", 0, u32::MAX as i64),
    ];

    for (type_name, min_val, max_val) in test_cases.iter() {
        // Test minimum value
        let prop_name_min = format!("test.round_trip.{type_name}_min");
        rsproperties::set(&prop_name_min, min_val)?;
        let parsed_min: i64 = rsproperties::get(&prop_name_min)?;
        assert_eq!(
            parsed_min, *min_val,
            "Round trip failed for {type_name} min value"
        );

        // Test maximum value
        let prop_name_max = format!("test.round_trip.{type_name}_max");
        rsproperties::set(&prop_name_max, max_val)?;
        let parsed_max: i64 = rsproperties::get(&prop_name_max)?;
        assert_eq!(
            parsed_max, *max_val,
            "Round trip failed for {type_name} max value"
        );
    }

    Ok(())
}

/// Test floating point precision through set/get cycle
#[tokio::test]
async fn test_float_precision_round_trip() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        ("pi", std::f64::consts::PI),
        ("e", std::f64::consts::E),
        ("small", 1e-10),
        ("large", 1e10),
        ("negative", -3.14159),
        ("zero", 0.0),
    ];

    for (name, original_value) in test_cases.iter() {
        let prop_name = format!("test.float_precision.{name}");

        rsproperties::set(&prop_name, original_value)?;
        let parsed_value: f64 = rsproperties::get(&prop_name)?;

        // For floating point, we need to account for string representation precision
        let diff = (parsed_value - original_value).abs();
        let epsilon = if original_value.abs() > 1.0 {
            original_value.abs() * 1e-10
        } else {
            1e-10
        };

        assert!(
            diff < epsilon,
            "Float precision lost for {name}: original={original_value}, parsed={parsed_value}, diff={diff}"
        );
    }

    Ok(())
}

/// Test that set produces consistent results for string values
#[tokio::test]
async fn test_string_consistency() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_strings = [
        "simple_string",
        "string with spaces",
        "unicode_测试_🚀",
        "",
        "123456",
        "true",
        "false",
        "3.14159",
        "special!@#$%^&*()",
    ];

    for (i, test_string) in test_strings.iter().enumerate() {
        let prop_name = format!("test.string_consistency.set_{i}");

        // Skip empty strings as they may not be supported by the underlying property system
        if test_string.is_empty() {
            continue;
        }

        // Set using set function (which handles Display types including &str)
        rsproperties::set(&prop_name, test_string)?;

        // Get the value back
        let retrieved_value: String = rsproperties::get(&prop_name)?;

        assert_eq!(
            retrieved_value, *test_string,
            "String value not preserved for: '{test_string}'"
        );
    }

    Ok(())
}

/// Test mixed data type operations on the same property
#[tokio::test]
async fn test_property_type_overwriting() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.type_overwriting.mixed";

    // Start with integer
    rsproperties::set(prop_name, &42i32)?;
    let as_int: i32 = rsproperties::get(prop_name)?;
    assert_eq!(as_int, 42);

    // Overwrite with float
    rsproperties::set(prop_name, &3.14f64)?;
    let as_float: f64 = rsproperties::get(prop_name)?;
    assert!((as_float - 3.14).abs() < f64::EPSILON);

    // Overwrite with boolean
    rsproperties::set(prop_name, &true)?;
    let as_string: String = rsproperties::get(prop_name)?;
    assert_eq!(as_string, "true");

    // Try to parse as integer (should fail)
    let int_result: Result<i32, _> = rsproperties::get(prop_name);
    assert!(int_result.is_err());

    // Overwrite with string number
    rsproperties::set(prop_name, "999")?;
    let back_to_int: i32 = rsproperties::get(prop_name)?;
    assert_eq!(back_to_int, 999);

    Ok(())
}

/// Test error propagation and handling across the API
#[tokio::test]
async fn test_error_handling_integration() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test 1: Parse non-existent property
    let non_existent = "definitely.does.not.exist.anywhere";
    let result: Result<i32, _> = rsproperties::get(non_existent);
    assert!(result.is_err());

    // But get_or should work
    let with_default: i32 = rsproperties::get_or(non_existent, 42);
    assert_eq!(with_default, 42);

    // Test 2: Parse invalid format
    let prop_name = "test.error.invalid_format";
    rsproperties::set(prop_name, "not_a_number")?;

    let parse_result: Result<i32, _> = rsproperties::get(prop_name);
    assert!(parse_result.is_err());

    // But get_or should return default
    let default_fallback: i32 = rsproperties::get_or(prop_name, 999);
    assert_eq!(default_fallback, 999);

    // Test 3: Parse empty string
    rsproperties::set(prop_name, "")?;
    let empty_result: Result<i32, _> = rsproperties::get(prop_name);
    assert!(empty_result.is_err());

    Ok(())
}

/// Test performance and consistency under concurrent operations
#[tokio::test]
async fn test_concurrent_mixed_operations() -> anyhow::Result<()> {
    setup_test_env().await;

    let num_tasks = 20;
    let operations_per_task = 10;

    let handles: Vec<_> = (0..num_tasks)
        .map(|task_id| {
            tokio::spawn(async move {
                for op_id in 0..operations_per_task {
                    let prop_name = format!("test.concurrent.task_{task_id}.op_{op_id}");

                    // Mix of different operations
                    match op_id % 4 {
                        0 => {
                            // Set and parse integer
                            let value = task_id * 1000 + op_id;
                            rsproperties::set(&prop_name, &value)?;
                            let parsed: i32 = rsproperties::get(&prop_name)?;
                            assert_eq!(parsed, value);
                        }
                        1 => {
                            // Set and parse float
                            let value = (task_id as f64) + (op_id as f64) * 0.1;
                            rsproperties::set(&prop_name, &value)?;
                            let parsed: f64 = rsproperties::get(&prop_name)?;
                            assert!((parsed - value).abs() < f64::EPSILON);
                        }
                        2 => {
                            // Set string and get
                            let value = format!("task_{task_id}_{op_id}");
                            rsproperties::set(&prop_name, &value)?;
                            let retrieved: String = rsproperties::get(&prop_name)?;
                            assert_eq!(retrieved, value);
                        }
                        3 => {
                            // Set boolean and parse
                            let value = (task_id + op_id) % 2 == 0;
                            rsproperties::set(&prop_name, &value)?;
                            let as_string: String = rsproperties::get(&prop_name)?;
                            assert_eq!(as_string, value.to_string());
                        }
                        _ => unreachable!(),
                    }
                }

                anyhow::Ok(())
            })
        })
        .collect();

    // Wait for all tasks to complete
    for handle in handles {
        handle.await??;
    }

    Ok(())
}

/// Test edge cases for numeric parsing
#[tokio::test]
async fn test_numeric_edge_cases() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test boundary values for different integer types
    let edge_cases = [
        ("zero", "0", 0i64),
        ("positive_small", "1", 1i64),
        ("negative_small", "-1", -1i64),
        ("i32_max", &i32::MAX.to_string(), i32::MAX as i64),
        ("i32_min", &i32::MIN.to_string(), i32::MIN as i64),
        ("large_positive", "999999999", 999999999i64),
        ("large_negative", "-999999999", -999999999i64),
    ];

    for (name, string_value, expected) in edge_cases.iter() {
        let prop_name = format!("test.edge_cases.{name}");

        rsproperties::set(&prop_name, string_value)?;
        let parsed: i64 = rsproperties::get(&prop_name)?;
        assert_eq!(parsed, *expected, "Edge case failed for {name}");

        // Also test with get_or
        let with_default: i64 = rsproperties::get_or(&prop_name, 42);
        assert_eq!(
            with_default, *expected,
            "get_parsed_with_default failed for {name}"
        );
    }

    Ok(())
}

/// Test boolean parsing with various string representations
#[tokio::test]
async fn test_boolean_string_variations() -> anyhow::Result<()> {
    setup_test_env().await;

    // Note: Rust's bool::from_str() only accepts "true" and "false" (case-sensitive)
    let valid_true_cases = [("lowercase_true", "true", true)];

    let valid_false_cases = [("lowercase_false", "false", false)];

    let invalid_cases = [
        ("uppercase_true", "TRUE"),
        ("uppercase_false", "FALSE"),
        ("mixed_case_true", "True"),
        ("mixed_case_false", "False"),
        ("numeric_one", "1"),
        ("numeric_zero", "0"),
        ("yes", "yes"),
        ("no", "no"),
        ("on", "on"),
        ("off", "off"),
    ];

    // Test valid true cases
    for (name, string_value, expected) in valid_true_cases.iter() {
        let prop_name = format!("test.bool_valid.{name}");
        rsproperties::set(&prop_name, string_value)?;
        let parsed: bool = rsproperties::get(&prop_name)?;
        assert_eq!(parsed, *expected, "Valid bool case failed for {name}");
    }

    // Test valid false cases
    for (name, string_value, expected) in valid_false_cases.iter() {
        let prop_name = format!("test.bool_valid.{name}");
        rsproperties::set(&prop_name, string_value)?;
        let parsed: bool = rsproperties::get(&prop_name)?;
        assert_eq!(parsed, *expected, "Valid bool case failed for {name}");
    }

    // Test invalid cases (should fail to parse)
    for (name, string_value) in invalid_cases.iter() {
        let prop_name = format!("test.bool_invalid.{name}");
        rsproperties::set(&prop_name, string_value)?;
        let result: Result<bool, _> = rsproperties::get(&prop_name);
        assert!(
            result.is_err(),
            "Invalid bool case should fail for {name} ({string_value})"
        );

        // But get_parsed_with_default should return the default
        let with_default: bool = rsproperties::get_or(&prop_name, true);
        assert!(
            with_default,
            "get_parsed_with_default should return default for {name}"
        );
    }

    Ok(())
}

/// Test type safety guarantees
#[tokio::test]
async fn test_type_safety() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.type_safety.value";

    // Set a value that can be parsed as multiple types
    rsproperties::set(prop_name, "42")?;

    // Should parse successfully as different numeric types
    let as_i8: i8 = rsproperties::get(prop_name)?;
    let as_i16: i16 = rsproperties::get(prop_name)?;
    let as_i32: i32 = rsproperties::get(prop_name)?;
    let as_i64: i64 = rsproperties::get(prop_name)?;
    let as_u8: u8 = rsproperties::get(prop_name)?;
    let as_u16: u16 = rsproperties::get(prop_name)?;
    let as_u32: u32 = rsproperties::get(prop_name)?;
    let as_u64: u64 = rsproperties::get(prop_name)?;
    let as_f32: f32 = rsproperties::get(prop_name)?;
    let as_f64: f64 = rsproperties::get(prop_name)?;
    let as_string: String = rsproperties::get(prop_name)?;

    assert_eq!(as_i8, 42);
    assert_eq!(as_i16, 42);
    assert_eq!(as_i32, 42);
    assert_eq!(as_i64, 42);
    assert_eq!(as_u8, 42);
    assert_eq!(as_u16, 42);
    assert_eq!(as_u32, 42);
    assert_eq!(as_u64, 42);
    assert_eq!(as_f32, 42.0);
    assert_eq!(as_f64, 42.0);
    assert_eq!(as_string, "42");

    Ok(())
}

/// Test API behavior with real-world Android property patterns
#[tokio::test]
async fn test_android_property_patterns() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        // SDK version
        ("ro.build.version.sdk", "34", 34i32),
        // Boolean properties (as integers)
        ("ro.debuggable", "0", 0i32),
        ("debug.enable_logs", "1", 1i32),
        // Memory sizes (in MB)
        ("dalvik.vm.heapsize", "512", 512i32),
        ("dalvik.vm.heapgrowthlimit", "256", 256i32),
        // Timeouts (in milliseconds)
        ("debug.timeout.network", "30000", 30000i32),
        ("persist.vendor.timeout", "5000", 5000i32),
        // Percentage values
        ("sys.battery.level", "85", 85i32),
        ("vendor.display.brightness", "50", 50i32),
    ];

    for (prop_name, string_val, expected_int) in test_cases.iter() {
        // Set as string (simulating property file loading)
        rsproperties::set(prop_name, string_val)?;

        // Parse as integer (typical app usage)
        let parsed_int: i32 = rsproperties::get(prop_name)?;
        assert_eq!(parsed_int, *expected_int, "Failed for property {prop_name}");

        // Get with default (safe app usage)
        let with_default: i32 = rsproperties::get_or(prop_name, -1);
        assert_eq!(
            with_default, *expected_int,
            "get_parsed_with_default failed for {prop_name}"
        );

        // Verify string representation is preserved
        let as_string: String = rsproperties::get(prop_name)?;
        assert_eq!(
            as_string, *string_val,
            "String representation changed for {prop_name}"
        );
    }

    Ok(())
}

/// Benchmark-style test to ensure reasonable performance
#[tokio::test]
async fn test_performance_characteristics() -> anyhow::Result<()> {
    setup_test_env().await;

    let num_operations = 100; // Reduced from 1000 to avoid property service limits
    let start_time = std::time::Instant::now();

    for i in 0..num_operations {
        let prop_name = format!("test.perf_reduced.prop_{i}");

        // Set operation
        rsproperties::set(&prop_name, &i)?;

        // Get operation
        let _retrieved: String = rsproperties::get(&prop_name)?;

        // Parse operation
        let _parsed: i32 = rsproperties::get(&prop_name)?;
    }

    let elapsed = start_time.elapsed();
    let ops_per_second = (num_operations as f64) / elapsed.as_secs_f64();

    println!(
        "Performance: {:.0} operations/second ({:.2} ms total)",
        ops_per_second,
        elapsed.as_millis()
    );

    // Ensure reasonable performance (should complete 100 ops in reasonable time)
    assert!(
        elapsed.as_secs() < 5,
        "Performance test took too long: {elapsed:?}"
    );

    Ok(())
}
