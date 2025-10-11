// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Simple example tests demonstrating basic usage of rsproperties
//!
//! These tests serve as both verification and documentation
//! of the most common use cases.

use rsproperties::{self, Result};

#[path = "common.rs"]
mod common;
use common::init_test;

/// Basic usage example - demonstrates the most common patterns
#[tokio::test]
async fn example_basic_usage() -> Result<()> {
    // Initialize the library with a test directory
    init_test().await;

    // Reading a property that doesn't exist - use get_with_default
    let sdk_version = rsproperties::get_or("ro.build.version.sdk", "unknown".to_string());
    println!("SDK Version: {sdk_version}");
    assert_eq!(sdk_version, "unknown"); // Should return default since property doesn't exist

    // Reading a property that might not exist - get returns String directly now
    let model: String = rsproperties::get("ro.product.model").unwrap_or_default();
    if model.is_empty() {
        println!("Product model not available");
    } else {
        println!("Product Model: {model}");
    }

    Ok(())
}

#[tokio::test]
async fn example_setting_properties() -> Result<()> {
    // Initialize for testing
    init_test().await;

    // Set a simple property
    rsproperties::set("my.app.version", "1.0.0")?;

    // Read it back
    let version: String = rsproperties::get("my.app.version")?;
    assert_eq!(version, "1.0.0");
    println!("App version: {version}");

    // Update the property
    rsproperties::set("my.app.version", "1.0.1")?;
    let updated_version: String = rsproperties::get("my.app.version")?;
    assert_eq!(updated_version, "1.0.1");
    println!("Updated app version: {updated_version}");

    // Set multiple properties
    let app_properties = vec![
        ("my.app.name", "RsProperties Example"),
        ("my.app.author", "Rust Developer"),
        ("my.app.debug", "true"),
    ];

    for (key, value) in &app_properties {
        rsproperties::set(key, value)?;
    }

    // Read them all back
    for (key, expected_value) in &app_properties {
        let actual_value: String = rsproperties::get(key)?;
        assert_eq!(actual_value, *expected_value);
        println!("{key} = {actual_value}");
    }

    Ok(())
}

/// Example showing error handling patterns
#[tokio::test]
async fn example_error_handling() {
    init_test().await;

    // Safe way - always get a value, using default for missing properties
    let timeout = rsproperties::get_or("network.timeout", "30".to_string());
    let timeout_seconds: u32 = timeout.parse().unwrap_or(30);
    println!("Network timeout: {timeout_seconds} seconds");

    // Check property value
    let status: String = rsproperties::get("service.status").unwrap_or_default();
    if !status.is_empty() {
        println!("Service status: {status}");
        // Process the status...
    } else {
        eprintln!("Could not get service status: property not found");
        // Handle the missing property appropriately...
    }

    // Using Result in a function that can fail
    fn get_required_config() -> Result<String> {
        let config: String = rsproperties::get("app.required.config")?;
        if config.is_empty() {
            return Err(rsproperties::Error::new_not_found(
                "app.required.config".to_string(),
            ));
        }
        Ok(config)
    }

    match get_required_config() {
        Ok(config) => println!("Config: {config}"),
        Err(e) => println!("Configuration error: {e}"),
    }
}

/// Example showing different property patterns used in Android
#[tokio::test]
async fn example_android_property_patterns() {
    init_test().await;

    // Common Android property patterns and their typical usage
    let android_properties = vec![
        // Read-only build properties
        ("ro.build.version.release", "Release version"),
        ("ro.build.version.sdk", "SDK API level"),
        ("ro.product.manufacturer", "Device manufacturer"),
        ("ro.product.model", "Device model"),
        ("ro.product.name", "Product name"),
        ("ro.hardware", "Hardware platform"),
        // System properties
        ("sys.boot_completed", "Boot completion status"),
        ("sys.usb.state", "USB connection state"),
        // Persistent properties (survive reboots)
        ("persist.sys.timezone", "System timezone"),
        ("persist.sys.locale", "System locale"),
        // Service properties
        ("service.adb.tcp.port", "ADB TCP port"),
        // Dalvik VM properties
        ("dalvik.vm.heapsize", "VM heap size"),
        // Network properties
        ("net.hostname", "Network hostname"),
    ];

    for (prop, description) in android_properties {
        let value = rsproperties::get_or(prop, "not_set".to_string());
        println!("{description}: {prop} = {value}");

        // Demonstrate type conversion for numeric properties
        if prop.contains("sdk") || prop.contains("port") {
            if let Ok(numeric_value) = value.parse::<i32>() {
                println!("  Parsed as number: {numeric_value}");
            }
        }

        // Demonstrate boolean conversion
        if prop.contains("completed") || prop.contains("debug") {
            let bool_value = value == "1" || value.to_lowercase() == "true";
            println!("  Parsed as boolean: {bool_value}");
        }
    }
}

#[tokio::test]
async fn example_configuration_management() -> Result<()> {
    init_test().await;

    // Example: Managing application configuration through properties

    // Set up default configuration
    let default_config = vec![
        ("app.log.level", "info"),
        ("app.max.connections", "100"),
        ("app.timeout.seconds", "30"),
        ("app.feature.experimental", "false"),
        ("app.cache.size.mb", "256"),
    ];

    println!("Setting up default configuration...");
    for (key, value) in &default_config {
        rsproperties::set(key, value)?;
        println!("  {key} = {value}");
    }

    // Simulate configuration updates
    println!("\nUpdating configuration...");
    rsproperties::set("app.log.level", "debug")?;
    rsproperties::set("app.feature.experimental", "true")?;

    // Read and use configuration
    println!("\nReading current configuration:");

    let log_level: String = rsproperties::get("app.log.level")?;
    println!("Log level: {log_level}");

    let max_connections: i32 = rsproperties::get("app.max.connections").unwrap_or(50);
    println!("Max connections: {max_connections}");

    let timeout: u64 = rsproperties::get("app.timeout.seconds").unwrap_or(10);
    println!("Timeout: {timeout} seconds");

    let experimental_enabled =
        rsproperties::get_or("app.feature.experimental", "".to_owned()).to_lowercase() == "true";
    println!("Experimental features: {experimental_enabled}");

    let cache_size: u32 = rsproperties::get("app.cache.size.mb").unwrap_or(128);
    println!("Cache size: {cache_size} MB");

    // Demonstrate conditional logic based on properties
    if experimental_enabled {
        println!("🧪 Experimental features are enabled!");
        rsproperties::set("app.experimental.new_algorithm", "active")?;
    }

    if log_level == "debug" {
        println!("🔍 Debug logging is enabled");
        rsproperties::set("app.debug.verbose", "true")?;
    }

    Ok(())
}

/// Example showing property watching patterns (conceptual)
#[tokio::test]
async fn example_property_monitoring() {
    init_test().await;

    // This demonstrates how you might monitor properties in a real application
    // Note: Actual watching would require the wait functionality from SystemProperties

    println!("Property monitoring example:");

    let monitored_properties = vec![
        "system.state",
        "network.connected",
        "battery.level",
        "app.should_exit",
    ];

    for prop in &monitored_properties {
        let current_value = rsproperties::get_or(prop, "unknown".to_string());
        println!("Currently monitoring {prop}: {current_value}");
    }

    // In a real application, you might:
    // 1. Set up a monitoring thread
    // 2. Use system_properties().wait() to wait for changes
    // 3. React to property changes

    println!("In a real app, you would set up listeners for these properties...");
}

/// Example demonstrating best practices
#[tokio::test]
async fn example_best_practices() {
    init_test().await;

    // ✅ Good: Use meaningful property names with clear hierarchy
    {
        println!("Setting up application properties...");
        rsproperties::set("com.myapp.feature.cache.enabled", "true").unwrap();
        rsproperties::set("com.myapp.network.retry.count", "3").unwrap();
        rsproperties::set("com.myapp.ui.theme", "dark").unwrap();
        println!("Properties set successfully.");
    }

    // ✅ Good: Always provide sensible defaults
    let cache_enabled =
        rsproperties::get_or("com.myapp.feature.cache.enabled", "false".to_string());
    let retry_count: u32 = rsproperties::get_or("com.myapp.network.retry.count", "1".to_string())
        .parse()
        .unwrap_or(1);

    println!("Cache enabled: {cache_enabled}");
    println!("Retry count: {retry_count}");

    // ✅ Good: Handle missing properties appropriately
    let setting: String = rsproperties::get("com.myapp.critical.setting").unwrap_or_default();
    if !setting.is_empty() {
        println!("Critical setting: {setting}");
        // Proceed with the setting
    } else {
        println!("Critical setting not found, using safe defaults");
        // Use safe defaults or fail safely
    }

    // ✅ Good: Validate property values
    let theme = rsproperties::get_or("com.myapp.ui.theme", "light".to_string());
    let valid_theme = match theme.as_str() {
        "light" | "dark" | "auto" => theme,
        _ => {
            println!("Invalid theme '{theme}', using 'light'");
            "light".to_string()
        }
    };
    println!("Using theme: {valid_theme}");

    // ✅ Good: Use constants for property names to avoid typos
    const FEATURE_FLAG_ANALYTICS: &str = "com.myapp.feature.analytics.enabled";
    const FEATURE_FLAG_TELEMETRY: &str = "com.myapp.feature.telemetry.enabled";

    let analytics_enabled =
        rsproperties::get_or(FEATURE_FLAG_ANALYTICS, "false".to_string()) == "true";
    let telemetry_enabled =
        rsproperties::get_or(FEATURE_FLAG_TELEMETRY, "false".to_string()) == "true";

    println!("Analytics: {analytics_enabled}, Telemetry: {telemetry_enabled}");
}
