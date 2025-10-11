// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Tests for property setting API functions
//!
//! These tests verify the functionality of the property setting APIs:
//! - set() - Set property with any Display type (includes strings)
//! - Type conversion and validation
//! - Error handling and edge cases
#![allow(clippy::approx_constant)]

#[path = "common.rs"]
mod common;
use common::init_test;

async fn setup_test_env() {
    let _ = env_logger::builder().is_test(true).try_init();
    init_test().await;
}

#[tokio::test]
async fn test_set_basic() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.set.basic";
    let prop_value = "test_string_value";

    // Set property using set
    rsproperties::set(prop_name, prop_value)?;

    // Verify the property was set correctly
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, prop_value);

    Ok(())
}

#[tokio::test]
async fn test_set_special_characters() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.set.special";
    let prop_value = "special!@#$%^&*()_+-={}[]|\\:;\"'<>?,./";

    rsproperties::set(prop_name, prop_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, prop_value);

    Ok(())
}

#[tokio::test]
async fn test_set_unicode() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.set.unicode";
    let prop_value = "안녕하세요 🌍 こんにちは Здравствуй";

    rsproperties::set(prop_name, prop_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, prop_value);

    Ok(())
}

#[tokio::test]
async fn test_set_whitespace() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        ("test.set.spaces", "value with spaces"),
        ("test.set.tabs", "value\twith\ttabs"),
        ("test.set.newlines", "value\nwith\nnewlines"),
        ("test.set.leading_space", " leading_space"),
        ("test.set.trailing_space", "trailing_space "),
        ("test.set.multiple_spaces", "multiple   spaces   here"),
    ];

    for (prop_name, prop_value) in test_cases.iter() {
        rsproperties::set(prop_name, prop_value)?;
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(
            retrieved_value, *prop_value,
            "Failed for property {prop_name}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_set_display_integers() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test i8
    let prop_name = "test.set.i8";
    let test_value = i8::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test i16
    let prop_name = "test.set.i16";
    let test_value = i16::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test i32
    let prop_name = "test.set.i32";
    let test_value = i32::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test i64
    let prop_name = "test.set.i64";
    let test_value = i64::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test u8
    let prop_name = "test.set.u8";
    let test_value = u8::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test u16
    let prop_name = "test.set.u16";
    let test_value = u16::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test u32
    let prop_name = "test.set.u32";
    let test_value = u32::MAX;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test u64 (using a smaller value to avoid potential issues)
    let prop_name = "test.set.u64";
    let test_value = u64::MAX / 2;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    Ok(())
}

#[tokio::test]
async fn test_set_display_negative_integers() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test i8 min
    let prop_name = "test.set.neg_i8";
    let test_value = i8::MIN;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test i16 min
    let prop_name = "test.set.neg_i16";
    let test_value = i16::MIN;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test i32 min
    let prop_name = "test.set.neg_i32";
    let test_value = i32::MIN;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test i64 min
    let prop_name = "test.set.neg_i64";
    let test_value = i64::MIN;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test zero
    let prop_name = "test.set.neg_zero";
    let test_value = 0i32;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test small negative
    let prop_name = "test.set.neg_small";
    let test_value = -42i32;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    Ok(())
}

#[tokio::test]
async fn test_set_display_floats() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test f32
    let prop_name = "test.set.f32";
    let test_value = 3.14159f32;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test f64
    let prop_name = "test.set.f64";
    let test_value = 2.718281828459045f64;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test f32 zero
    let prop_name = "test.set.f32_zero";
    let test_value = 0.0f32;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test f64 negative
    let prop_name = "test.set.f64_negative";
    let test_value = -123.456f64;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test f32 small
    let prop_name = "test.set.f32_small";
    let test_value = f32::EPSILON;
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    // Test f64 large (use smaller value to avoid length limits)
    let prop_name = "test.set.f64_large";
    let test_value = 1e10f64; // Smaller than 1e100 to fit in 92 chars
    rsproperties::set(prop_name, &test_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, test_value.to_string());

    Ok(())
}

#[tokio::test]
async fn test_set_display_booleans() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        ("test.set.bool_true", true, "true"),
        ("test.set.bool_false", false, "false"),
    ];

    for (prop_name, test_value, expected_str) in test_cases.iter() {
        rsproperties::set(prop_name, test_value)?;
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(
            retrieved_value, *expected_str,
            "Failed for property {prop_name} with value {test_value}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_set_display_strings() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        ("test.set.string", "plain_string".to_string()),
        ("test.set.string_empty", String::new()),
        ("test.set.string_medium", "a".repeat(50)), // Shorter than 92 chars
        ("test.set.string_unicode", "测试🚀".to_string()),
    ];

    for (prop_name, test_value) in test_cases.iter() {
        rsproperties::set(prop_name, test_value)?;
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(
            retrieved_value, *test_value,
            "Failed for property {prop_name} with value '{test_value}'"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_set_display_string_slices() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_cases = [
        ("test.set.str_slice", "string_slice_value"),
        ("test.set.str_ref", "string_reference"),
        ("test.set.str_borrowed", "borrowed_string"),
    ];

    for (prop_name, test_value) in test_cases.iter() {
        rsproperties::set(prop_name, test_value)?;
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(
            retrieved_value,
            test_value.to_string(),
            "Failed for property {prop_name}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_set_overwrite_existing() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.set.overwrite";

    // Set initial value
    let initial_value = "initial_value";
    rsproperties::set(prop_name, initial_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, initial_value);

    // Overwrite with different type
    let new_value = 12345i32;
    rsproperties::set(prop_name, &new_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, new_value.to_string());

    // Overwrite with another string
    let final_value = "final_value";
    rsproperties::set(prop_name, final_value)?;
    let retrieved_value: String = rsproperties::get(prop_name)?;
    assert_eq!(retrieved_value, final_value);

    Ok(())
}

#[tokio::test]
async fn test_set_multiple_properties() -> anyhow::Result<()> {
    setup_test_env().await;

    let properties = [
        ("test.multi.int", "42"),
        ("test.multi.float", "3.14"),
        ("test.multi.bool", "true"),
        ("test.multi.string", "hello"),
        ("test.multi.negative", "-999"),
    ];

    // Set all properties
    for (prop_name, prop_value) in properties.iter() {
        rsproperties::set(prop_name, prop_value)?;
    }

    // Verify all properties were set correctly
    for (prop_name, expected_value) in properties.iter() {
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(
            retrieved_value, *expected_value,
            "Failed for property {prop_name}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_set_property_name_validation() {
    setup_test_env().await;

    // Test various property name patterns
    let valid_names = [
        "test.valid.name",
        "ro.build.version.sdk",
        "debug.my_app.enabled",
        "persist.vendor.radio.config",
        "sys.boot_completed",
        "dalvik.vm.heapsize",
        "test.123.numbered",
        "test.with-dashes",
        "test.with_underscores",
    ];

    for prop_name in valid_names.iter() {
        let result = rsproperties::set(prop_name, "test_value");
        assert!(
            result.is_ok(),
            "Valid property name should succeed: {prop_name}"
        );
    }
}

#[tokio::test]
async fn test_set_and_get_integration() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.integration.complete";

    // Test the complete cycle: set -> get -> parse
    let original_value = 98765i32;

    // Set using Display trait
    rsproperties::set(prop_name, &original_value)?;

    // Get as string
    let string_value: String = rsproperties::get(prop_name)?;
    assert_eq!(string_value, original_value.to_string());

    // Parse back to integer
    let parsed_value: i32 = rsproperties::get(prop_name)?;
    assert_eq!(parsed_value, original_value);

    // Get with default (should return the actual value, not default)
    let with_default: i32 = rsproperties::get_or(prop_name, 999);
    assert_eq!(with_default, original_value);

    Ok(())
}

#[tokio::test]
async fn test_set_concurrent_properties() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test setting properties concurrently (basic test)
    let handles: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                let prop_name = format!("test.concurrent.prop_{i}");
                let prop_value = format!("value_{i}");

                rsproperties::set(&prop_name, &prop_value).unwrap();

                let retrieved: String = rsproperties::get(&prop_name).unwrap();
                assert_eq!(retrieved, prop_value);

                (prop_name, prop_value)
            })
        })
        .collect();

    // Wait for all tasks to complete
    for handle in handles {
        let (prop_name, expected_value) = handle.await?;
        let final_value: String = rsproperties::get(&prop_name)?;
        assert_eq!(final_value, expected_value);
    }

    Ok(())
}

#[tokio::test]
async fn test_set_real_world_android_properties() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test setting properties that simulate real Android system properties
    let properties = [
        ("debug.real_world_test.log_level", "verbose"),
        ("debug.real_world_test.timeout_ms", "5000"),
        ("debug.real_world_test.enabled", "true"),
        ("persist.real_world_test.feature", "enabled"),
        ("sys.real_world_test.ready", "1"),
        ("real_world_test.app.version", "1.2.3"),
        ("real_world_test.app.build_number", "456"),
        ("test.real_world.iterations", "1000"),
        ("test.real_world.batch_size", "128"),
        ("vendor.real_world_test.calibration", "0.95"),
    ];

    for (prop_name, prop_value) in properties.iter() {
        rsproperties::set(prop_name, prop_value)?;
        let retrieved: String = rsproperties::get(prop_name)?;
        assert_eq!(
            retrieved, *prop_value,
            "Failed for Android-style property {prop_name}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_set_error_handling() {
    setup_test_env().await;

    // Test edge cases for error handling
    let very_long_name = "a".repeat(1000);
    let very_long_value = "b".repeat(10000);

    // Very long property name - should either succeed or fail gracefully
    let result = rsproperties::set(&very_long_name, "test");
    // We don't assert success/failure as it depends on system limits
    // But we ensure it doesn't panic
    match result {
        Ok(_) => println!("Long property name was accepted"),
        Err(e) => println!("Long property name was rejected: {e}"),
    }

    // Very long property value - should either succeed or fail gracefully
    let result = rsproperties::set("test.long.value", &very_long_value);
    match result {
        Ok(_) => println!("Long property value was accepted"),
        Err(e) => println!("Long property value was rejected: {e}"),
    }
}

#[tokio::test]
async fn test_set_consistency_between_set_and_set() -> anyhow::Result<()> {
    setup_test_env().await;

    let test_value = "consistent_test_value";

    // Set using set with &str
    let prop_name1 = "test.consistency.set_str";
    rsproperties::set(prop_name1, test_value)?;

    // Set using set with String
    let prop_name2 = "test.consistency.set";
    rsproperties::set(prop_name2, &test_value.to_string())?;

    // Both should produce the same result
    let value1: String = rsproperties::get(prop_name1)?;
    let value2: String = rsproperties::get(prop_name2)?;

    assert_eq!(value1, value2);
    assert_eq!(value1, test_value);

    Ok(())
}
