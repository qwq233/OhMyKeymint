use log::info;
use rsproperties::PropertyConfig;

#[cfg(not(target_os = "android"))]
use rsproperties_service;

use anyhow::{anyhow, Context, Ok, Result};

#[cfg(target_os = "linux")]
static HAS_INIT: std::sync::Once = std::sync::Once::new();

pub struct PropertyWatcher {
    name: String,
}

impl PropertyWatcher {
    #[cfg(not(target_os = "android"))]
    pub fn new(name: &str) -> anyhow::Result<Self> {
        HAS_INIT.call_once(|| {
            init().unwrap();
        });
        Ok(PropertyWatcher {
            name: name.to_string(),
        })
    }

    #[cfg(target_os = "android")]
    pub fn new(name: &str) -> anyhow::Result<Self> {
        Ok(PropertyWatcher { name: name.to_string() })
    }

    pub fn read(&self) -> Result<String> {
        rsproperties::system_properties()
            .get_with_result(&self.name.as_str())
            .context(anyhow!("Property '{}' not found", self.name))
    }

    pub fn read_and_parse<T, F>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&str) -> Result<T>,
    {
        rsproperties::system_properties()
            .get_with_result(&self.name.as_str())
            .context(anyhow!("Property '{}' not found", self.name))
            .and_then(|value| f(value.as_str()))
    }

    pub fn wait(&self, _old_value: Option<&str>) -> Result<()> {
        let system_props = rsproperties::system_properties();
        let val = system_props.find(&self.name)?;
        if let Some(val) = val {
            system_props.wait(Some(&val), None);
            Ok(())
        } else {
            Err(anyhow!("Property '{}' not found", self.name))
        }
    }
}

#[tokio::main]
#[cfg(not(target_os = "android"))]
async fn init() -> Result<()> {
    std::fs::create_dir_all("./omk/properties").unwrap();
    std::fs::create_dir_all("./omk/property_socket").unwrap();
    // Configure the service
    let config = PropertyConfig {
        properties_dir: Some("./omk/properties".into()),
        socket_dir: Some("./omk/property_socket".into()),
    };

    rsproperties::init(config.clone());

    // Optional: Load property contexts and build.prop files
    let property_contexts: Vec<std::path::PathBuf> = vec![];

    let build_props: Vec<std::path::PathBuf> = vec!["device.prop".into()];

    // Start the property service
    let srv = rsproperties_service::run(config, property_contexts, build_props).await;

    if let Err(e) = srv {
        panic!("Property service failed to start, {}", e);
    }

    info!("Property service running...");

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;
    info!("Property service shutting down...");

    Ok(())
}
