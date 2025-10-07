// Copyright 2024 Jeff Kim <hiking90@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use log::{debug, error, info, trace, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use rsactor::{Actor, ActorRef, ActorWeak};

use rsproperties::errors::*;

const PROP_MSG_SETPROP2: u32 = 0x00020001;
const PROP_SUCCESS: i32 = 0;
const PROP_ERROR: i32 = -1;

pub struct SocketServiceArgs {
    pub socket_dir: PathBuf,
    pub properties_service: ActorRef<crate::PropertiesService>,
}

// Run the service in a separate task
/// This function runs the socket service by spawning a new actor with the provided arguments.
///
/// # Returns
/// A reference to the spawned actor that can be used to interact with the socket service.
/// The actor can be stopped by calling `actor_ref.stop()` when the service is no longer needed.
///
pub fn run(args: SocketServiceArgs) -> crate::ServiceContext<SocketService> {
    let (actor_ref, join_handle) = rsactor::spawn(args);
    crate::ServiceContext {
        actor_ref,
        join_handle,
    }
}

/// Tokio-based property socket service
pub struct SocketService {
    socket_dir: PathBuf,
    property_listener: UnixListener,
    system_listener: UnixListener,
    properties_service: ActorRef<crate::PropertiesService>,
}

impl Actor for SocketService {
    type Args = SocketServiceArgs;
    type Error = rsproperties::errors::Error;

    async fn on_start(
        args: Self::Args,
        _actor_ref: &ActorRef<Self>,
    ) -> std::result::Result<Self, Self::Error> {
        // Create parent directory if it doesn't exist
        if !args.socket_dir.exists() {
            debug!("Creating parent directory: {:?}", args.socket_dir);
            fs::create_dir_all(&args.socket_dir).map_err(rsproperties::errors::Error::new_io)?;
        }

        let property_socket_path = args
            .socket_dir
            .join(rsproperties::PROPERTY_SERVICE_SOCKET_NAME);
        let system_socket_path = args
            .socket_dir
            .join(rsproperties::PROPERTY_SERVICE_FOR_SYSTEM_SOCKET_NAME);
        // Remove existing socket files if they exist
        if property_socket_path.exists() {
            debug!(
                "Removing existing property socket file: {}",
                property_socket_path.display()
            );
            fs::remove_file(&property_socket_path).map_err(rsproperties::errors::Error::new_io)?;
        }
        if system_socket_path.exists() {
            debug!(
                "Removing existing system socket file: {}",
                system_socket_path.display()
            );
            fs::remove_file(&system_socket_path).map_err(rsproperties::errors::Error::new_io)?;
        }
        info!(
            "Property socket services successfully created at: {} and {}",
            property_socket_path.display(),
            system_socket_path.display()
        );
        // Bind both sockets
        trace!(
            "Binding property service Unix domain socket: {}",
            property_socket_path.display()
        );
        let property_listener = UnixListener::bind(&property_socket_path)
            .map_err(rsproperties::errors::Error::new_io)?;
        trace!(
            "Binding system property service Unix domain socket: {}",
            system_socket_path.display()
        );
        let system_listener =
            UnixListener::bind(&system_socket_path).map_err(rsproperties::errors::Error::new_io)?;
        info!("AsyncPropertySocketService started successfully");

        Ok(Self {
            socket_dir: args.socket_dir,
            property_listener,
            system_listener,
            properties_service: args.properties_service,
        })
    }

    async fn on_run(
        &mut self,
        _actor_weak: &ActorWeak<Self>,
    ) -> std::result::Result<(), Self::Error> {
        tokio::select! {
            _ = Self::handle_socket_connections(&self.property_listener, self.properties_service.clone()) => {
                trace!("Property socket service task completed");
            }
            _ = Self::handle_socket_connections(&self.system_listener, self.properties_service.clone()) => {
                trace!("System property socket service task completed");
            }
        }
        Ok(())
    }

    async fn on_stop(
        &mut self,
        _actor_weak: &ActorWeak<Self>,
        killed: bool,
    ) -> std::result::Result<(), Self::Error> {
        warn!("=====================================");
        warn!("      SOCKET SERVICE SHUTDOWN       ");
        warn!("=====================================");

        if killed {
            error!(
                "*** FORCED TERMINATION *** SocketService is being killed, cleaning up resources."
            );
        } else {
            warn!("*** GRACEFUL SHUTDOWN *** SocketService is stopping gracefully.");
        }

        warn!("SocketService cleanup completed - SERVICE TERMINATED");
        warn!("=====================================");

        Ok(())
    }
}

impl rsactor::Message<crate::ReadyMessage> for SocketService {
    type Reply = bool;

    async fn handle(
        &mut self,
        _message: crate::ReadyMessage,
        _actor_ref: &ActorRef<Self>,
    ) -> Self::Reply {
        true
    }
}

impl SocketService {
    /// Handles socket connections for a specific socket type
    async fn handle_socket_connections(
        listener: &UnixListener,
        service: ActorRef<crate::PropertiesService>,
    ) -> Result<()> {
        // Try to accept a connection with timeout
        let connection_result = listener.accept().await;

        match connection_result {
            Ok((stream, _)) => {
                // Clone sender for this connection
                let connection_sender = service.clone();

                // Handle each connection in a separate task
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_client(stream, connection_sender).await {
                        error!("Error handling client: {e}");
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {e}");
            }
        }
        Ok(())
    }

    /// Handles a client connection
    async fn handle_client(
        mut stream: UnixStream,
        service: ActorRef<crate::PropertiesService>,
    ) -> Result<()> {
        trace!("Handling new client connection");

        // Read the command (u32)
        let mut cmd_buf = [0u8; 4];
        stream
            .read_exact(&mut cmd_buf)
            .await
            .map_err(rsproperties::errors::Error::new_io)?;
        let cmd = u32::from_ne_bytes(cmd_buf);

        debug!("Received command: 0x{cmd:08X}");

        match cmd {
            PROP_MSG_SETPROP2 => {
                trace!("Processing SETPROP2 command");
                Self::handle_setprop2(&mut stream, service).await?;
            }
            _ => {
                warn!("Unknown command received: 0x{cmd:08X}");
                Self::send_response(&mut stream, PROP_ERROR).await?;
                return Err(rsproperties::errors::Error::new_parse(format!(
                    "Unknown command: 0x{cmd:08X}"
                )));
            }
        }

        trace!("Client connection handled successfully");
        Ok(())
    }

    /// Handles SETPROP2 command
    async fn handle_setprop2(
        stream: &mut UnixStream,
        service: ActorRef<crate::PropertiesService>,
    ) -> Result<()> {
        trace!("Handling SETPROP2 request");

        // Read name length and name
        let name_len = Self::read_u32(stream).await?;
        trace!("Name length: {name_len}");

        if name_len > 1024 {
            // Reasonable limit
            error!("Name length too large: {name_len}");
            Self::send_response(stream, PROP_ERROR).await?;
            return Err(rsproperties::errors::Error::new_file_validation(format!(
                "Name length too large: {name_len}"
            )));
        }

        let name = Self::read_string(stream, name_len as usize).await?;
        debug!("Property name: '{name}'");

        // Read value length and value
        let value_len = Self::read_u32(stream).await?;
        trace!("Value length: {value_len}");

        if value_len > 8192 {
            // Reasonable limit for property values
            error!("Value length too large: {value_len}");
            Self::send_response(stream, PROP_ERROR).await?;
            return Err(rsproperties::errors::Error::new_file_validation(format!(
                "Value length too large: {value_len}"
            )));
        }

        let value = Self::read_string(stream, value_len as usize).await?;
        debug!("Property value: '{value}'");

        // Process the property setting
        info!("Successfully set property: '{name}' = '{value}'");

        // Send property data through channel if sender is available
        let property_msg = crate::PropertyMessage {
            key: name.clone(),
            value: value.clone(),
        };

        match service.ask(property_msg).await {
            Ok(true) => {
                debug!("Property message sent successfully: '{name}' = '{value}'");
                Self::send_response(stream, PROP_SUCCESS).await?;
            }
            Ok(false) => {
                warn!("Property message was not processed by service: '{name}' = '{value}'");
                // Don't fail the operation if service doesn't process it
                Self::send_response(stream, PROP_ERROR).await?;
            }
            Err(e) => {
                error!("Failed to send property message through channel: {e}");
                // Don't fail the operation if channel send fails
                Self::send_response(stream, PROP_ERROR).await?;
            }
        }

        Ok(())
    }

    /// Reads a u32 value from the stream
    async fn read_u32(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(rsproperties::errors::Error::new_io)?;
        Ok(u32::from_ne_bytes(buf))
    }

    /// Reads a string of specified length from the stream
    async fn read_string(stream: &mut UnixStream, len: usize) -> Result<String> {
        if len == 0 {
            return Ok(String::new());
        }

        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(rsproperties::errors::Error::new_io)?;

        // Remove null terminator if present
        if let Some(null_pos) = buf.iter().position(|&x| x == 0) {
            buf.truncate(null_pos);
        }

        String::from_utf8(buf).map_err(|e| rsproperties::errors::Error::new_encoding(e.to_string()))
    }

    /// Sends a response to the client
    async fn send_response(stream: &mut UnixStream, response: i32) -> Result<()> {
        trace!("Sending response: {response}");
        stream
            .write_all(&response.to_ne_bytes())
            .await
            .map_err(rsproperties::errors::Error::new_io)?;
        stream
            .flush()
            .await
            .map_err(rsproperties::errors::Error::new_io)?;
        trace!("Response sent successfully");
        Ok(())
    }
}

impl Drop for SocketService {
    fn drop(&mut self) {
        debug!("Cleaning up async socket service");

        // Remove socket files
        let property_socket_path = self
            .socket_dir
            .join(rsproperties::PROPERTY_SERVICE_SOCKET_NAME);
        if property_socket_path.exists() {
            if let Err(e) = fs::remove_file(&property_socket_path) {
                warn!(
                    "Failed to remove property socket file {}: {}",
                    property_socket_path.display(),
                    e
                );
            } else {
                debug!(
                    "Property socket file removed: {}",
                    property_socket_path.display()
                );
            }
        }

        let system_socket_path = self
            .socket_dir
            .join(rsproperties::PROPERTY_SERVICE_FOR_SYSTEM_SOCKET_NAME);
        if system_socket_path.exists() {
            if let Err(e) = fs::remove_file(&system_socket_path) {
                warn!(
                    "Failed to remove system socket file {}: {}",
                    system_socket_path.display(),
                    e
                );
            } else {
                debug!(
                    "System socket file removed: {}",
                    system_socket_path.display()
                );
            }
        }
    }
}
