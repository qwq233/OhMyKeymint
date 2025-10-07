// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Summary tests for newly added property APIs
//!
//! This test file provides a comprehensive overview of the new APIs:
//! - get_parsed_with_default<T>() - Parse property values with fallback
//! - get_parsed<T>() - Parse property values with error handling
//! - set() - Set property with string value
//! - set<T>() - Set property with any Display type
//!
//! These tests demonstrate real-world usage patterns and serve as examples.

#[path = "common.rs"]
mod common;
use common::init_test;

async fn setup_test_env() {
    let _ = env_logger::builder().is_test(true).try_init();
    init_test().await;
}

/// Demonstrate the complete workflow for the new parsed property APIs
#[tokio::test]
async fn test_new_api_showcase() -> anyhow::Result<()> {
    setup_test_env().await;

    // =================================
    // Part 1: Setting Properties
    // =================================

    // Set string property using set()
    rsproperties::set("app.config.name", "MyApplication")?;

    // Set numeric properties using set() with different types
    rsproperties::set("app.config.version_code", &123i32)?;
    rsproperties::set("app.config.version_minor", &4u8)?;
    rsproperties::set("app.config.memory_limit", &512.5f64)?;
    rsproperties::set("app.config.debug_enabled", &true)?;

    // Set using string literals (also uses set())
    rsproperties::set("app.config.api_timeout", "30000")?;

    // Set a floating point value
    rsproperties::set("app.config.ratio", &2.5f64)?;

    // =================================
    // Part 2: Getting and Parsing Properties
    // =================================

    // Get properties as strings (traditional approach)
    let app_name: String = rsproperties::get("app.config.name")?;
    assert_eq!(app_name, "MyApplication");

    // Parse properties to specific types using get_parsed()
    let version_code: i32 = rsproperties::get("app.config.version_code")?;
    assert_eq!(version_code, 123);

    let version_minor: u8 = rsproperties::get("app.config.version_minor")?;
    assert_eq!(version_minor, 4);

    let memory_limit: f64 = rsproperties::get("app.config.memory_limit")?;
    assert!((memory_limit - 512.5).abs() < f64::EPSILON);

    let debug_enabled: bool = rsproperties::get("app.config.debug_enabled")?;
    assert!(debug_enabled);

    // Parse string that was set as string
    let api_timeout: u32 = rsproperties::get("app.config.api_timeout")?;
    assert_eq!(api_timeout, 30000);

    // =================================
    // Part 3: Safe Parsing with Defaults
    // =================================

    // Get with defaults for existing properties
    let existing_timeout: u32 = rsproperties::get_or("app.config.api_timeout", 5000);
    assert_eq!(existing_timeout, 30000); // Should return actual value, not default

    // Get with defaults for non-existent properties
    let missing_prop: i32 = rsproperties::get_or("app.config.nonexistent", 42);
    assert_eq!(missing_prop, 42); // Should return default

    // Get with defaults for properties with invalid format
    rsproperties::set("app.config.invalid_number", "not_a_number")?;
    let invalid_parsed: i32 = rsproperties::get_or("app.config.invalid_number", 999);
    assert_eq!(invalid_parsed, 999); // Should return default when parsing fails

    // =================================
    // Part 4: Error Handling
    // =================================

    // Attempting to parse non-existent property should fail
    let missing_result: Result<i32, _> = rsproperties::get("app.config.does_not_exist");
    assert!(missing_result.is_err());

    // Attempting to parse invalid format should fail
    let invalid_result: Result<i32, _> = rsproperties::get("app.config.invalid_number");
    assert!(invalid_result.is_err());

    println!("✅ All new API functionality demonstrated successfully!");

    Ok(())
}

/// Demonstrate Android-style property usage patterns
#[tokio::test]
async fn test_android_style_usage() -> anyhow::Result<()> {
    setup_test_env().await;

    // Simulate loading properties from build.prop files
    rsproperties::set("ro.build.version.sdk", "34")?;
    rsproperties::set("ro.debuggable", "0")?;
    rsproperties::set("dalvik.vm.heapsize", "512m")?;
    rsproperties::set("debug.my_app.log_level", "verbose")?;

    // Application code reading these properties

    // SDK version as integer
    let sdk_version: i32 = rsproperties::get_or("ro.build.version.sdk", 28);
    assert_eq!(sdk_version, 34);

    // Debug flag as boolean (0/1 pattern)
    let is_debuggable: i32 = rsproperties::get_or("ro.debuggable", 0);
    let debug_enabled = is_debuggable != 0;
    assert!(!debug_enabled);

    // Memory setting parsing (would need additional logic for "m" suffix in real usage)
    // For this demo, we'll set a numeric value
    rsproperties::set("dalvik.vm.heapsize.mb", "512")?;
    let heap_size: u32 = rsproperties::get_or("dalvik.vm.heapsize.mb", 256);
    assert_eq!(heap_size, 512);

    // String property with fallback
    let log_level = rsproperties::get_or("debug.my_app.log_level", "info".to_string());
    assert_eq!(log_level, "verbose");

    // Non-existent property with fallback
    let unknown_feature: i32 = rsproperties::get_or("vendor.unknown.feature", 0);
    assert_eq!(unknown_feature, 0);

    println!("✅ Android-style property patterns work correctly!");

    Ok(())
}

/// Demonstrate type conversion capabilities
#[tokio::test]
async fn test_type_conversion_showcase() -> anyhow::Result<()> {
    setup_test_env().await;

    // Set a numeric value that can be interpreted as different types
    rsproperties::set("config.numeric_value", "42")?;

    // Parse as different integer types
    let as_i8: i8 = rsproperties::get("config.numeric_value")?;
    let as_i16: i16 = rsproperties::get("config.numeric_value")?;
    let as_i32: i32 = rsproperties::get("config.numeric_value")?;
    let as_i64: i64 = rsproperties::get("config.numeric_value")?;
    let as_u32: u32 = rsproperties::get("config.numeric_value")?;
    let as_u64: u64 = rsproperties::get("config.numeric_value")?;

    assert_eq!(as_i8, 42);
    assert_eq!(as_i16, 42);
    assert_eq!(as_i32, 42);
    assert_eq!(as_i64, 42);
    assert_eq!(as_u32, 42);
    assert_eq!(as_u64, 42);

    // Parse as floating point
    let as_f32: f32 = rsproperties::get("config.numeric_value")?;
    let as_f64: f64 = rsproperties::get("config.numeric_value")?;

    assert_eq!(as_f32, 42.0);
    assert_eq!(as_f64, 42.0);

    // Parse as string
    let as_string: String = rsproperties::get("config.numeric_value")?;
    assert_eq!(as_string, "42");

    // Set floating point and parse back
    rsproperties::set("config.pi", &std::f64::consts::PI)?;
    let pi_back: f64 = rsproperties::get("config.pi")?;
    assert!((pi_back - std::f64::consts::PI).abs() < 1e-10);

    // Set boolean values
    rsproperties::set("config.feature_flag", &true)?;
    let flag_value: String = rsproperties::get("config.feature_flag")?;
    assert_eq!(flag_value, "true");

    // Note: Parsing "true"/"false" strings as bool works with Rust's FromStr
    rsproperties::set("config.bool_string", "false")?;
    let bool_parsed: bool = rsproperties::get("config.bool_string")?;
    assert!(!bool_parsed);

    println!("✅ Type conversion showcase completed successfully!");

    Ok(())
}

/// Demonstrate error handling and safe programming patterns
#[tokio::test]
async fn test_safe_programming_patterns() -> anyhow::Result<()> {
    setup_test_env().await;

    // Pattern 1: Safe parsing with defaults (never fails)
    let safe_timeout = rsproperties::get_or("config.timeout", 5000u32);
    assert_eq!(safe_timeout, 5000); // Default because property doesn't exist

    // Pattern 2: Explicit error handling
    match rsproperties::get::<i32>("config.nonexistent") {
        Ok(_value) => panic!("Should not succeed for non-existent property"),
        Err(_) => println!("✅ Correctly handled missing property error"),
    }

    // Pattern 3: Validation after setting
    rsproperties::set("config.validation_test", "123")?;
    let validated: Result<u32, _> = rsproperties::get("config.validation_test");
    match validated {
        Ok(val) => {
            assert_eq!(val, 123);
            println!("✅ Property validation passed: {val}");
        }
        Err(e) => panic!("Validation should have succeeded: {e}"),
    }

    // Pattern 4: Fallback chain
    let config_value = rsproperties::get_or(
        "config.primary",
        rsproperties::get_or("config.secondary", 42),
    );
    assert_eq!(config_value, 42); // Falls back to final default

    // Pattern 5: Type-safe configuration loading
    struct AppConfig {
        name: String,
        version: u32,
        debug: bool,
        timeout: u64,
    }

    // Set configuration properties
    rsproperties::set("app.name", "TestApp")?;
    rsproperties::set("app.version", &100u32)?;
    rsproperties::set("app.debug", &false)?;
    rsproperties::set("app.timeout", &30000u64)?;

    // Load configuration safely
    let config = AppConfig {
        name: rsproperties::get_or("app.name", "DefaultApp".to_string()),
        version: rsproperties::get_or("app.version", 1),
        debug: rsproperties::get_or("app.debug", false),
        timeout: rsproperties::get_or("app.timeout", 5000),
    };

    assert_eq!(config.name, "TestApp");
    assert_eq!(config.version, 100);
    assert!(!config.debug);
    assert_eq!(config.timeout, 30000);

    println!("✅ Safe programming patterns demonstrated successfully!");

    Ok(())
}

/// Performance and concurrent usage demonstration
#[tokio::test]
async fn test_performance_and_concurrency() -> anyhow::Result<()> {
    setup_test_env().await;

    // Concurrent property operations
    let handles: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                let prop_name = format!("perf.test.prop_{i}");

                // Set different types concurrently
                match i % 3 {
                    0 => {
                        rsproperties::set(&prop_name, &(i * 100))?;
                        let value: i32 = rsproperties::get(&prop_name)?;
                        assert_eq!(value, i * 100);
                    }
                    1 => {
                        rsproperties::set(&prop_name, &(i as f64 * 1.5))?;
                        let value: f64 = rsproperties::get(&prop_name)?;
                        assert!((value - (i as f64 * 1.5)).abs() < f64::EPSILON);
                    }
                    2 => {
                        rsproperties::set(&prop_name, &format!("string_{i}"))?;
                        let value: String = rsproperties::get(&prop_name)?;
                        assert_eq!(value, format!("string_{i}"));
                    }
                    _ => unreachable!(),
                }

                anyhow::Ok(i)
            })
        })
        .collect();

    // Wait for all concurrent operations to complete
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await??);
    }

    // Verify all tasks completed
    assert_eq!(results.len(), 10);
    for (i, result) in results.iter().enumerate() {
        assert_eq!(*result, i as i32);
    }

    println!("✅ Concurrent operations completed successfully!");

    // Performance measurement
    let start_time = std::time::Instant::now();
    let num_ops = 50; // Reduced for reliability

    for i in 0..num_ops {
        let prop_name = format!("perf.measurement.{i}");

        // Combined set/get/parse operation
        rsproperties::set(&prop_name, &i)?;
        let _retrieved: String = rsproperties::get(&prop_name)?;
        let _parsed: i32 = rsproperties::get(&prop_name)?;
    }

    let elapsed = start_time.elapsed();
    let ops_per_second = (num_ops as f64 * 3.0) / elapsed.as_secs_f64(); // 3 operations per iteration

    println!("✅ Performance: {ops_per_second:.0} operations/second");

    // Should be reasonably fast
    assert!(
        elapsed.as_millis() < 1000,
        "Operations took too long: {elapsed:?}"
    );

    Ok(())
}

/// Summary test showcasing all key features
#[tokio::test]
async fn test_complete_feature_summary() -> anyhow::Result<()> {
    setup_test_env().await;

    println!("🚀 Testing rsproperties new APIs - Complete Feature Summary");

    // Feature 1: Enhanced Property Setting
    println!("📝 Feature 1: Enhanced Property Setting");
    rsproperties::set("demo.string_prop", "Hello World")?;
    rsproperties::set("demo.int_prop", &42i32)?;
    rsproperties::set("demo.float_prop", &2.5f64)?;
    rsproperties::set("demo.bool_prop", &true)?;
    println!("   ✅ Properties set using set() and set() functions");

    // Feature 2: Type-Safe Property Parsing
    println!("📊 Feature 2: Type-Safe Property Parsing");
    let string_val: String = rsproperties::get("demo.string_prop")?;
    let int_val: i32 = rsproperties::get("demo.int_prop")?;
    let float_val: f64 = rsproperties::get("demo.float_prop")?;
    let bool_val: bool = rsproperties::get("demo.bool_prop")?;

    assert_eq!(string_val, "Hello World");
    assert_eq!(int_val, 42);
    assert!((float_val - 2.5).abs() < f64::EPSILON);
    assert!(bool_val);
    println!("   ✅ Type-safe parsing with get_parsed() function");

    // Feature 3: Safe Defaults
    println!("🛡️ Feature 3: Safe Defaults");
    let safe_int: i32 = rsproperties::get_or("demo.missing_prop", 999);
    let safe_str: String = rsproperties::get_or("demo.missing_string", "default".to_string());

    assert_eq!(safe_int, 999);
    assert_eq!(safe_str, "default");
    println!("   ✅ Safe defaults with get_parsed_with_default() function");

    // Feature 4: Error Handling
    println!("⚠️ Feature 4: Error Handling");
    let error_result: Result<i32, _> = rsproperties::get("demo.nonexistent");
    assert!(error_result.is_err());

    rsproperties::set("demo.invalid_int", "not_a_number")?;
    let parse_error: Result<i32, _> = rsproperties::get("demo.invalid_int");
    assert!(parse_error.is_err());
    println!("   ✅ Proper error handling for missing and invalid properties");

    // Feature 5: Backward Compatibility
    println!("🔄 Feature 5: Backward Compatibility");
    let traditional_get: String = rsproperties::get("demo.string_prop")?;
    let traditional_with_default = rsproperties::get_or("demo.int_prop", "0".to_string());

    assert_eq!(traditional_get, "Hello World");
    assert_eq!(traditional_with_default, "42");
    println!("   ✅ Full backward compatibility with existing APIs");

    println!("🎉 All new rsproperties API features working correctly!");
    println!("    - Enhanced property setting with type safety");
    println!("    - Type-safe property parsing");
    println!("    - Safe defaults and error handling");
    println!("    - Full backward compatibility");
    println!("    - Concurrent operation support");

    Ok(())
}
