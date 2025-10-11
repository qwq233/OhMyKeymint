# rsproperties-service

An async, tokio-based service implementation for Android system properties with Unix domain socket support.

[![Crates.io](https://img.shields.io/crates/v/rsproperties-service.svg)](https://crates.io/crates/rsproperties-service)
[![Documentation](https://docs.rs/rsproperties-service/badge.svg)](https://docs.rs/rsproperties-service)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Overview

`rsproperties-service` provides a high-performance, async property service that mimics Android's property system. It features a Unix domain socket server that handles property operations using an actor-based architecture powered by the `rsactor` framework.

## Key Features

- **🔄 Async Operations**: Built on tokio for high-performance async I/O
- **🎭 Actor-Based Architecture**: Uses rsactor for reliable message passing and state management
- **🔌 Unix Domain Socket Server**: Compatible with Android's property service protocol
- **⚡ High Performance**: Non-blocking property operations with concurrent client handling
- **🛡️ Robust Error Handling**: Comprehensive error handling with graceful degradation
- **📂 File-Based Configuration**: Supports property contexts and build.prop file loading
- **🔧 Configurable**: Flexible directory and socket path configuration

## Architecture

The service consists of two main components running as separate actors:

### PropertiesService
- Manages the actual property storage and retrieval
- Loads property contexts from files
- Processes build.prop files
- Handles property addition, updates, and lookups
- Maintains system property state

### SocketService
- Provides Unix domain socket interface
- Handles client connections and commands
- Implements Android-compatible property service protocol
- Supports SETPROP2 command for property setting
- Manages concurrent client sessions

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rsproperties-service = "0.1"
```

Or add it with the builder feature:

```toml
[dependencies]
rsproperties-service = { version = "0.1", features = ["builder"] }
```

## Quick Start

### Basic Service Setup

```rust
use rsproperties_service;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = rsproperties::PropertyConfig::with_both_dirs(
        PathBuf::from("/tmp/properties"),
        PathBuf::from("/tmp/sockets")
    );

    // Start the services
    let (socket_service, properties_service) = rsproperties_service::run(
        config,
        vec![], // property_contexts_files
        vec![], // build_prop_files
    ).await?;

    println!("Services started successfully!");

    // Keep services running
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Shutdown signal received");
        }
        result = socket_service.join_handle => {
            if let Err(e) = result {
                eprintln!("Socket service error: {}", e);
            }
        }
        result = properties_service.join_handle => {
            if let Err(e) = result {
                eprintln!("Properties service error: {}", e);
            }
        }
    }

    Ok(())
}
```

### Advanced Configuration with Files

```rust
use rsproperties_service;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup directories
    let properties_dir = PathBuf::from("/system/etc/properties");
    let socket_dir = PathBuf::from("/dev/socket");

    // Configure property context files
    let property_contexts = vec![
        PathBuf::from("/system/etc/selinux/property_contexts"),
        PathBuf::from("/vendor/etc/selinux/vendor_property_contexts"),
    ];

    // Configure build.prop files
    let build_props = vec![
        PathBuf::from("/system/build.prop"),
        PathBuf::from("/vendor/build.prop"),
        PathBuf::from("/product/build.prop"),
    ];

    let config = rsproperties::PropertyConfig::with_both_dirs(
        properties_dir,
        socket_dir
    );

    // Start services with configuration files
    let (socket_service, properties_service) = rsproperties_service::run(
        config,
        property_contexts,
        build_props,
    ).await?;

    // Services are now running with full Android-compatible configuration
    tokio::join!(
        socket_service.join_handle,
        properties_service.join_handle
    );

    Ok(())
}
```

## Service Components

### ServiceContext

Each service returns a `ServiceContext` containing:

```rust
pub struct ServiceContext<T: Actor> {
    pub actor_ref: ActorRef<T>,           // Reference for sending messages
    pub join_handle: JoinHandle<ActorResult<T>>, // Handle for awaiting completion
}
```

### Message Types

The services communicate using these message types:

- **ReadyMessage**: Check if service is ready
- **PropertyMessage**: Set/update property values

```rust
// Check if service is ready
let is_ready = properties_service.actor_ref.ask(ReadyMessage {}).await?;

// Send property update
let success = properties_service.actor_ref.ask(PropertyMessage {
    key: "my.app.debug".to_string(),
    value: "true".to_string(),
}).await?;
```

## Protocol Compatibility

The socket service implements the Android property service protocol:

- **Socket Names**: Uses standard Android socket names (`property_service`, `property_service_for_system`)
- **Commands**: Supports `PROP_MSG_SETPROP2` (0x00020001) command
- **Response Codes**: Returns `PROP_SUCCESS` (0) or `PROP_ERROR` (-1)
- **Message Format**: Compatible with Android's binary protocol

## Error Handling

The service provides comprehensive error handling:

```rust
match rsproperties_service::run(config, contexts, props).await {
    Ok((socket_service, properties_service)) => {
        // Services started successfully
        println!("All services running");
    }
    Err(e) => {
        eprintln!("Failed to start services: {}", e);
        // Handle specific error types
        if e.to_string().contains("Permission denied") {
            eprintln!("Check directory permissions");
        }
    }
}
```

## Performance Features

- **Concurrent Connections**: Each client connection handled in separate tasks
- **Non-blocking I/O**: All operations use async/await for optimal performance
- **Memory Efficient**: Property data shared between services using actor references
- **Fast Lookups**: Optimized property storage for quick access

## Directory Structure

The service expects this directory layout:

```
properties_dir/
├── property_info          # Property metadata (generated)
├── properties_serial      # Property versioning
└── u:object_r:*:s0       # SELinux context files

socket_dir/
├── property_service                    # Main property socket
└── property_service_for_system        # System property socket
```

## Security Features

- **Path Validation**: Validates all file and directory paths
- **Size Limits**: Enforces reasonable limits on property names (1KB) and values (8KB)
- **SELinux Support**: Handles SELinux property contexts when provided
- **Permission Handling**: Respects file system permissions

## Logging

The service provides detailed logging at multiple levels:

```rust
// Enable logging
env_logger::Builder::from_env(
    env_logger::Env::default().default_filter_or("info")
).init();
```

Log levels:
- **ERROR**: Service failures, connection errors
- **WARN**: Graceful shutdowns, configuration issues
- **INFO**: Service lifecycle, property operations
- **DEBUG**: Client connections, message details
- **TRACE**: Protocol-level details, fine-grained operations

## Examples

### Running the Example Service

```bash
cargo run --example example_service -- \
    --properties-dir /tmp/test_properties \
    --socket-dir /tmp/test_sockets
```

### Testing with netcat

```bash
# Connect to the property service socket
nc -U /tmp/test_sockets/property_service
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run specific test category
cargo test integration_tests
cargo test performance_tests
```

## Dependencies

- **tokio**: Async runtime and I/O
- **rsactor**: Actor framework for message passing
- **rsproperties**: Core property system implementation
- **log**: Logging framework
- **thiserror**: Error handling

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.

## Contributing

Contributions are welcome! Please see the main [rsproperties](../README.md) project for contribution guidelines.

## Related Projects

- **[rsproperties](../rsproperties/)**: Core property system library
- **Android Property System**: Original implementation this project emulates
