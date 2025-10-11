// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for rsproperties public API
//!
//! These tests verify the core functionality of the public API including:
//! - Property initialization
//! - Getting properties with default values
//! - Getting properties without defaults
//! - Setting properties (when builder feature is enabled)
//! - Error handling

#[path = "common.rs"]
mod common;
use common::init_test;

async fn setup_test_env() {
    let _ = env_logger::builder().is_test(true).try_init();
    init_test().await;
}

#[tokio::test]
async fn test_get_with_default_nonexistent_property() {
    setup_test_env().await;

    let prop_name = "nonexistent.test.property";
    let default_value = "default_test_value";

    let result = rsproperties::get_or(prop_name, default_value.to_string());
    assert_eq!(result, default_value);
}

#[tokio::test]
async fn test_get_with_default_empty_default() {
    setup_test_env().await;

    let prop_name = "another.nonexistent.property";
    let default_value = "";

    let result = rsproperties::get_or(prop_name, default_value.to_string());
    assert_eq!(result, default_value);
}

#[tokio::test]
async fn test_get_nonexistent_property() {
    setup_test_env().await;

    let prop_name = "definitely.does.not.exist";
    let result: String = rsproperties::get(prop_name).unwrap_or_default();

    // Should return empty string for non-existent property
    assert!(result.is_empty());
}

mod builder_tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get_property() -> anyhow::Result<()> {
        setup_test_env().await;

        let prop_name = "test.set.property";
        let prop_value = "test_value_123";

        // Set the property
        rsproperties::set(prop_name, prop_value)?;

        // Get the property back
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(retrieved_value, prop_value);

        // Also test get_with_default
        let retrieved_with_default = rsproperties::get_or(prop_name, "fallback".to_string());
        assert_eq!(retrieved_with_default, prop_value);

        Ok(())
    }

    #[tokio::test]
    async fn test_set_property_with_special_characters() -> anyhow::Result<()> {
        setup_test_env().await;

        let prop_name = "test.special.chars";
        let prop_value = "value with spaces and symbols: !@#$%^&*()";

        rsproperties::set(prop_name, prop_value)?;
        let retrieved_value: String = rsproperties::get(prop_name)?;
        assert_eq!(retrieved_value, prop_value);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_existing_property() -> anyhow::Result<()> {
        setup_test_env().await;

        let prop_name = "test.update.property";
        let initial_value = "initial_value";
        let updated_value = "updated_value";

        // Set initial value
        rsproperties::set(prop_name, initial_value)?;
        let retrieved: String = rsproperties::get(prop_name)?;
        assert_eq!(retrieved, initial_value);

        // Update the value
        rsproperties::set(prop_name, updated_value)?;
        let retrieved: String = rsproperties::get(prop_name)?;
        assert_eq!(retrieved, updated_value);

        Ok(())
    }

    #[tokio::test]
    async fn test_set_invalid_property_name() {
        setup_test_env().await;

        // Test with empty property name
        let result = rsproperties::set("", "value");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_properties() -> anyhow::Result<()> {
        setup_test_env().await;

        let properties = vec![
            ("test.prop.one", "value1"),
            ("test.prop.two", "value2"),
            ("test.prop.three", "value3"),
            ("test.prop.four", "value4"),
        ];

        // Set all properties
        for (name, value) in &properties {
            rsproperties::set(name, value)?;
        }

        // Verify all properties
        for (name, expected_value) in &properties {
            let retrieved_value: String = rsproperties::get(name)?;
            assert_eq!(retrieved_value, *expected_value);
        }

        Ok(())
    }
}

mod linux_specific_tests {
    use super::*;

    #[tokio::test]
    async fn test_property_persistence() -> anyhow::Result<()> {
        setup_test_env().await;

        let prop_name = "persist.test.property";
        let prop_value = "persistent_value";

        // Set a property
        rsproperties::set(prop_name, prop_value)?;

        // Verify it's set
        let retrieved: String = rsproperties::get(prop_name)?;
        assert_eq!(retrieved, prop_value);

        Ok(())
    }
}

/// Test error handling and edge cases
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_with_very_long_property_name() {
        setup_test_env().await;

        // Create a very long property name
        let long_name = "a".repeat(1000);
        let default_value = "default";

        let result = rsproperties::get_or(&long_name, default_value.to_string());
        // Should return default value when property doesn't exist
        assert_eq!(result, default_value);
    }

    #[tokio::test]
    async fn test_set_property_with_max_value_length() {
        setup_test_env().await;

        let prop_name = "test.max.value";
        // Create a value close to PROP_VALUE_MAX
        let long_value = "x".repeat(rsproperties::PROP_VALUE_MAX - 10);

        let result = rsproperties::set(prop_name, &long_value);
        // This should succeed since it's within limits
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_set_property_exceeding_max_value_length() {
        setup_test_env().await;

        let prop_name = "test.exceeding.max";
        // Create a value that exceeds PROP_VALUE_MAX
        let too_long_value = "x".repeat(rsproperties::PROP_VALUE_MAX + 10);

        let result = rsproperties::set(prop_name, &too_long_value);
        // This should fail or truncate the value
        // The exact behavior depends on implementation
        println!("Result for too long value: {result:?}");
    }
}

/// Test concurrent access patterns
mod concurrency_tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[tokio::test]
    async fn test_concurrent_property_access() -> anyhow::Result<()> {
        setup_test_env().await;

        let prop_name = "test.concurrent.property";
        let prop_value = "concurrent_value";

        // Set initial property
        rsproperties::set(prop_name, prop_value)?;

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let name = prop_name.to_string();
                let expected = prop_value.to_string();

                thread::spawn(move || {
                    for _ in 0..10 {
                        let value: String = rsproperties::get(&name).unwrap_or_default();
                        assert_eq!(value, expected);
                        thread::sleep(Duration::from_millis(1));
                    }
                    println!("Thread {i} completed");
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_property_updates() -> anyhow::Result<()> {
        setup_test_env().await;

        let prop_name = "test.concurrent.updates";

        // Set initial property
        rsproperties::set(prop_name, "initial")?;

        let handles: Vec<_> = (0..3)
            .map(|i| {
                let name = prop_name.to_string();

                thread::spawn(move || {
                    let value = format!("thread_{i}_value");
                    rsproperties::set(&name, &value).unwrap();
                    // thread::sleep(Duration::from_millis(10));

                    // Verify we can read some value back
                    let retrieved: String = rsproperties::get(&name).unwrap_or_default();
                    assert!(!retrieved.is_empty());

                    println!("Thread {i} set value: {value}, got: {retrieved}");
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Final verification
        let final_value: String = rsproperties::get(prop_name).unwrap_or_default();
        assert!(!final_value.is_empty());

        Ok(())
    }
}
