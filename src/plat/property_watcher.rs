use anyhow::{anyhow, Context, Ok, Result};

pub struct PropertyWatcher {
    name: String,
}

impl PropertyWatcher {
    pub fn new(name: &str) -> anyhow::Result<Self> {
        Ok(PropertyWatcher {
            name: name.to_string(),
        })
    }

    pub fn read(&self) -> Result<String> {
        rsproperties::system_properties()
            .get_with_result(self.name.as_str())
            .context(anyhow!("Property '{}' not found", self.name))
    }

    pub fn read_and_parse<T, F>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&str) -> Result<T>,
    {
        rsproperties::system_properties()
            .get_with_result(self.name.as_str())
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
