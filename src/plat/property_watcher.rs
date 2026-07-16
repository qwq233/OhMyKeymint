use anyhow::{anyhow, Context, Ok, Result};

pub struct PropertyWatcher {
    name: String,
}

impl PropertyWatcher {
    pub fn new(name: &str) -> anyhow::Result<Self> {
        Ok(Self {
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
        self.read().and_then(|value| f(value.as_str()))
    }

    pub fn wait(&self, old_value: Option<&str>) -> Result<()> {
        let system_props = rsproperties::system_properties();
        let val = system_props
            .find(&self.name)?
            .ok_or_else(|| anyhow!("Property '{}' not found", self.name))?;
        let serial = system_props
            .serial(&val)
            .ok_or_else(|| anyhow!("Failed to read property '{}' serial", self.name))?;
        if let Some(old_value) = old_value {
            let current = self.read()?;
            if current != old_value {
                return Ok(());
            }
        }
        system_props.wait(Some(&val), Some(serial), None);
        Ok(())
    }
}
