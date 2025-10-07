// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Async property socket service implementation for Android system properties
//!
//! This crate provides a tokio-based async implementation of the Android property
//! socket service, allowing for non-blocking property value reception and parsing.

use std::path::PathBuf;

use rsactor::{Actor, ActorRef, ActorResult};

pub mod properties_service;
pub mod socket_service;

pub use socket_service::{SocketService, SocketServiceArgs};

pub use properties_service::PropertiesService;

pub(crate) struct ReadyMessage {}

#[derive(Debug, Clone)]
pub(crate) struct PropertyMessage {
    pub key: String,
    pub value: String,
}

pub struct ServiceContext<T: Actor> {
    pub actor_ref: ActorRef<T>,
    pub join_handle: tokio::task::JoinHandle<ActorResult<T>>,
}

/// Runs the property socket service with the given configuration.
///
/// # Requirements
/// All folders specified in the PropertyConfig must be valid and accessible
/// for the function to execute successfully.
pub async fn run(
    config: rsproperties::PropertyConfig,
    property_contexts_files: Vec<PathBuf>,
    build_prop_files: Vec<PathBuf>,
) -> Result<
    (
        ServiceContext<SocketService>,
        ServiceContext<PropertiesService>,
    ),
    Box<dyn std::error::Error>,
> {
    rsproperties::init(config);

    let properties_service = properties_service::run(property_contexts_files, build_prop_files);

    // Initialize the socket service
    let socket_service = socket_service::run(SocketServiceArgs {
        socket_dir: rsproperties::socket_dir().to_path_buf(),
        properties_service: properties_service.actor_ref.clone(),
    });

    let _ = socket_service
        .actor_ref
        .ask(ReadyMessage {})
        .await
        .map_err(|e| format!("Failed to start socket service: {e}"))?;
    let _ = properties_service
        .actor_ref
        .ask(ReadyMessage {})
        .await
        .map_err(|e| format!("Failed to start properties service: {e}"))?;

    Ok((socket_service, properties_service))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_message() {
        let msg = PropertyMessage {
            key: "test.key".to_string(),
            value: "test.value".to_string(),
        };
        assert_eq!(msg.key, "test.key");
        assert_eq!(msg.value, "test.value");
    }
}
