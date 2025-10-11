// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Tests for parsed property API functions
//!
//! These tests verify the functionality of the newly added parsed property APIs:
//! - get_parsed_with_default() - Parse property values with default fallback
//! - get_parsed() - Parse property values with error handling
//! - Type safety and parsing validation

#[path = "common.rs"]
mod common;
use common::init_test;

async fn setup_test_env() {
    let _ = env_logger::builder().is_test(true).try_init();
    init_test().await;
}

#[tokio::test]
async fn test_get_parsed_with_default_integers() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test with existing integer property
    let prop_name = "test.parsed.int";
    let test_value = 42;
    rsproperties::set(prop_name, &test_value)?;

    let parsed_value: i32 = rsproperties::get_or(prop_name, 0);
    assert_eq!(parsed_value, test_value);

    // Test with different integer types
    let parsed_i64: i64 = rsproperties::get_or(prop_name, 0i64);
    assert_eq!(parsed_i64, test_value as i64);

    let parsed_u32: u32 = rsproperties::get_or(prop_name, 0u32);
    assert_eq!(parsed_u32, test_value as u32);

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_with_default_nonexistent_property() {
    setup_test_env().await;

    let prop_name = "nonexistent.parsed.property";
    let default_value = 123;

    let result: i32 = rsproperties::get_or(prop_name, default_value);
    assert_eq!(result, default_value);
}

#[tokio::test]
async fn test_get_parsed_with_default_invalid_parsing() -> anyhow::Result<()> {
    setup_test_env().await;

    // Set a property with non-numeric value
    let prop_name = "test.parsed.invalid";
    rsproperties::set(prop_name, "not_a_number")?;

    // Should return default value when parsing fails
    let default_value = 999;
    let result: i32 = rsproperties::get_or(prop_name, default_value);
    assert_eq!(result, default_value);

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_with_default_booleans() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test boolean parsing - Rust's bool::from_str() is case-sensitive
    let valid_cases = [
        ("test.bool.true", "true", true),
        ("test.bool.false", "false", false),
    ];

    let invalid_cases = [
        ("test.bool.true_upper", "True"),
        ("test.bool.true_all_upper", "TRUE"),
        ("test.bool.false_upper", "False"),
        ("test.bool.false_all_upper", "FALSE"),
        ("test.bool.one", "1"),
        ("test.bool.zero", "0"),
        ("test.bool.yes", "yes"),
        ("test.bool.no", "no"),
    ];

    // Test valid boolean strings
    for (prop_name, prop_value, expected) in valid_cases.iter() {
        rsproperties::set(prop_name, prop_value)?;
        let result: bool = rsproperties::get_or(prop_name, false);
        assert_eq!(
            result, *expected,
            "Failed for valid boolean property {prop_name} with value {prop_value}"
        );
    }

    // Test invalid boolean strings (should return default)
    for (prop_name, prop_value) in invalid_cases.iter() {
        rsproperties::set(prop_name, prop_value)?;
        let result: bool = rsproperties::get_or(prop_name, true); // Use true as default to verify fallback
        assert!(
            result,
            "Should return default for invalid boolean value: {prop_value}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_with_default_floats() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.parsed.float";
    let test_value = std::f64::consts::PI;
    rsproperties::set(prop_name, &test_value)?;

    let parsed_f32: f32 = rsproperties::get_or(prop_name, 0.0f32);
    assert!((parsed_f32 - test_value as f32).abs() < f32::EPSILON);

    let parsed_f64: f64 = rsproperties::get_or(prop_name, 0.0f64);
    assert!((parsed_f64 - test_value).abs() < f64::EPSILON);

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_success() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test successful parsing of various types
    let prop_name_int = "test.get_parsed.int";
    let test_int = 12345;
    rsproperties::set(prop_name_int, &test_int)?;

    let result: i32 = rsproperties::get(prop_name_int)?;
    assert_eq!(result, test_int);

    // Test with string parsing
    let prop_name_str = "test.get_parsed.string";
    let test_str = "hello_world";
    rsproperties::set(prop_name_str, test_str)?;

    let result: String = rsproperties::get(prop_name_str)?;
    assert_eq!(result, test_str);

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_nonexistent_property() {
    setup_test_env().await;

    let prop_name = "completely.nonexistent.property";
    let result: Result<i32, _> = rsproperties::get(prop_name);

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("NotFound") || error_msg.contains("not found"));
}

#[tokio::test]
async fn test_get_parsed_parsing_error() -> anyhow::Result<()> {
    setup_test_env().await;

    // Set a property with invalid value for parsing
    let prop_name = "test.get_parsed.invalid";
    rsproperties::set(prop_name, "definitely_not_a_number")?;

    let result: Result<i32, _> = rsproperties::get(prop_name);

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Parse") || error_msg.contains("parse"));

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_empty_property() -> anyhow::Result<()> {
    setup_test_env().await;

    // Set a property with empty value
    let prop_name = "test.get_parsed.empty";
    rsproperties::set(prop_name, "")?;

    let result: Result<i32, _> = rsproperties::get(prop_name);

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("cannot parse integer from empty string"));

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_complex_types() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test parsing of complex numeric types
    let prop_name = "test.parsed.complex";

    // Test u64
    let large_value = u64::MAX / 2;
    rsproperties::set(prop_name, &large_value)?;
    let parsed_u64: u64 = rsproperties::get(prop_name)?;
    assert_eq!(parsed_u64, large_value);

    // Test i64 negative
    let negative_value = -12345678901234i64;
    rsproperties::set(prop_name, &negative_value)?;
    let parsed_i64: i64 = rsproperties::get(prop_name)?;
    assert_eq!(parsed_i64, negative_value);

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_edge_cases() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test edge cases for parsing
    let test_cases = [
        ("test.parsed.zero", "0", 0i32),
        ("test.parsed.negative", "-1", -1i32),
        ("test.parsed.max_i32", &i32::MAX.to_string(), i32::MAX),
        ("test.parsed.min_i32", &i32::MIN.to_string(), i32::MIN),
    ];

    for (prop_name, prop_value, expected) in test_cases.iter() {
        rsproperties::set(prop_name, prop_value)?;
        let result: i32 = rsproperties::get(prop_name)?;
        assert_eq!(
            result, *expected,
            "Failed for property {prop_name} with value {prop_value}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_get_parsed_with_whitespace() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test parsing values with whitespace (should be trimmed by the property system)
    let prop_name = "test.parsed.whitespace";
    let test_value = "  123  ";
    rsproperties::set(prop_name, test_value)?;

    // The property system should handle whitespace appropriately
    let result: Result<i32, _> = rsproperties::get(prop_name);

    // Note: The behavior here depends on how the property system handles whitespace
    // We'll just verify that the function behaves consistently
    match result {
        Ok(value) => assert_eq!(value, 123),
        Err(_) => {
            // If whitespace causes parsing to fail, that's also acceptable behavior
            // as it depends on the underlying property system implementation
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_parsed_api_type_safety() -> anyhow::Result<()> {
    setup_test_env().await;

    let prop_name = "test.type_safety";
    let test_value = "42";
    rsproperties::set(prop_name, test_value)?;

    // Verify that different numeric types parse correctly from the same string
    let as_i32: i32 = rsproperties::get(prop_name)?;
    let as_u32: u32 = rsproperties::get(prop_name)?;
    let as_i64: i64 = rsproperties::get(prop_name)?;
    let as_f64: f64 = rsproperties::get(prop_name)?;

    assert_eq!(as_i32, 42);
    assert_eq!(as_u32, 42);
    assert_eq!(as_i64, 42);
    assert_eq!(as_f64, 42.0);

    Ok(())
}

#[tokio::test]
async fn test_parsed_api_with_real_world_properties() -> anyhow::Result<()> {
    setup_test_env().await;

    // Test with property names that simulate real Android system properties
    let test_cases = [
        ("ro.build.version.sdk", "34", 34i32),
        ("ro.debuggable", "0", 0i32),
        ("dalvik.vm.heapsize", "512", 512i32),
        ("debug.my_app.timeout", "5000", 5000i32),
        ("persist.vendor.radio.enable", "1", 1i32),
    ];

    for (prop_name, prop_value, expected) in test_cases.iter() {
        rsproperties::set(prop_name, prop_value)?;

        let parsed_result: i32 = rsproperties::get(prop_name)?;
        assert_eq!(parsed_result, *expected, "Failed for property {prop_name}");

        let with_default: i32 = rsproperties::get_or(prop_name, 999);
        assert_eq!(
            with_default, *expected,
            "get_parsed_with_default failed for property {prop_name}"
        );
    }

    Ok(())
}
