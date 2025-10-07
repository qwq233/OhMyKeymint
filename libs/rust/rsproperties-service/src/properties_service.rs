use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use rsactor::{Actor, ActorRef, ActorWeak};
use rsproperties::{build_trie, load_properties_from_file, PropertyInfoEntry, SystemProperties};

pub struct PropertiesServiceArgs {
    property_contexts_files: Vec<PathBuf>,
    build_prop_files: Vec<PathBuf>,
}

pub struct PropertiesService {
    system_properties: SystemProperties,
}

impl PropertiesService {}

impl Actor for PropertiesService {
    type Args = PropertiesServiceArgs;
    type Error = std::io::Error;

    async fn on_start(
        args: Self::Args,
        _actor_ref: &rsactor::ActorRef<Self>,
    ) -> std::result::Result<Self, Self::Error> {
        let mut property_infos = Vec::new();
        for file in args.property_contexts_files {
            let (mut property_info, errors) =
                PropertyInfoEntry::parse_from_file(&file, false).unwrap();
            if !errors.is_empty() {
                log::error!("{errors:?}");
            }
            property_infos.append(&mut property_info);
        }

        let data: Vec<u8> =
            build_trie(&property_infos, "u:object_r:build_prop:s0", "string").unwrap();

        let dir = rsproperties::properties_dir();
        File::create(dir.join("property_info"))
            .unwrap()
            .write_all(&data)
            .unwrap();

        let mut properties = HashMap::new();
        for file in args.build_prop_files {
            load_properties_from_file(&file, None, "u:r:init:s0", &mut properties).unwrap();
        }

        let mut system_properties = SystemProperties::new_area(dir).unwrap_or_else(|e| {
            panic!("Cannot create system properties: {e}. Please check if {dir:?} exists.")
        });
        for (key, value) in properties.iter() {
            match system_properties.find(key.as_str()).unwrap() {
                Some(prop_ref) => {
                    system_properties.update(&prop_ref, value.as_str()).unwrap();
                }
                None => {
                    system_properties.add(key.as_str(), value.as_str()).unwrap();
                }
            }
        }

        Ok(PropertiesService {
            // Initialize the service with the provided arguments
            system_properties,
        })
    }

    async fn on_stop(
        &mut self,
        _actor_weak: &ActorWeak<Self>,
        killed: bool,
    ) -> std::result::Result<(), Self::Error> {
        log::warn!("=====================================");
        log::warn!("    PROPERTIES SERVICE SHUTDOWN     ");
        log::warn!("=====================================");

        if killed {
            log::error!("*** FORCED TERMINATION *** PropertiesService is being killed, cleaning up resources.");
        } else {
            log::warn!("*** GRACEFUL SHUTDOWN *** PropertiesService is stopping gracefully.");
        }

        // Perform any necessary cleanup here
        // For example, you might want to save the current state or close any open files

        log::warn!("PropertiesService cleanup completed - SERVICE TERMINATED");
        log::warn!("=====================================");

        Ok(())
    }
}

impl rsactor::Message<crate::ReadyMessage> for PropertiesService {
    type Reply = bool;

    async fn handle(
        &mut self,
        _message: crate::ReadyMessage,
        _actor_ref: &ActorRef<Self>,
    ) -> Self::Reply {
        true
    }
}

impl rsactor::Message<crate::PropertyMessage> for PropertiesService {
    type Reply = bool;

    async fn handle(
        &mut self,
        message: crate::PropertyMessage,
        _actor_ref: &ActorRef<Self>,
    ) -> Self::Reply {
        log::debug!("Handling property message: {message:?}");
        // Process the property message
        let key = message.key;
        let value = message.value;

        // Check if the property exists in the system properties
        match self.system_properties.find(&key) {
            Ok(Some(prop_ref)) => {
                // Update the existing property
                if let Err(e) = self.system_properties.update(&prop_ref, &value) {
                    log::error!("Failed to update property '{key}': {e}");
                    false // Indicate failure
                } else {
                    log::info!("Updated property: {key} = {value}");
                    true // Indicate success
                }
            }
            Ok(None) => {
                // Property does not exist, add it
                if let Err(e) = self.system_properties.add(&key, &value) {
                    log::error!("Failed to add property '{key}': {e}");
                    false // Indicate failure
                } else {
                    log::info!("Added property: {key} = {value}");
                    true // Indicate success
                }
            }
            Err(e) => {
                log::error!("Failed to find property '{key}': {e}");
                false // Indicate failure
            }
        }
    }
}

pub fn run(
    property_contexts_files: Vec<PathBuf>,
    build_prop_files: Vec<PathBuf>,
) -> crate::ServiceContext<PropertiesService> {
    let args = PropertiesServiceArgs {
        property_contexts_files,
        build_prop_files,
    };

    let (actor_ref, join_handle) = rsactor::spawn(args);
    crate::ServiceContext {
        actor_ref,
        join_handle,
    }
}
