// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Retrieve and populate information about userspace.

use kmr_wire::SetHalInfoRequest;
use regex::Regex;

// The OS version property is of form "12" or "12.1" or "12.1.3".
const OS_VERSION_PROPERTY: &str = "ro.build.version.release";
const OS_VERSION_REGEX: &str = r"^(?P<major>\d{1,2})(\.(?P<minor>\d{1,2}))?(\.(?P<sub>\d{1,2}))?$";

// The patchlevel properties are of form "YYYY-MM-DD".
/// Name of property that holds the OS patchlevel.
pub const OS_PATCHLEVEL_PROPERTY: &str = "ro.build.version.security_patch";
const VENDOR_PATCHLEVEL_PROPERTY: &str = "ro.vendor.build.security_patch";
const PATCHLEVEL_REGEX: &str = r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})$";

// Just use [`String`] for errors here.
type Error = String;

/// Retrieve a numeric value from a possible match.
fn extract_u32(value: Option<regex::Match>) -> Result<u32, Error> {
    match value {
        Some(m) => {
            let s = m.as_str();
            match s.parse::<u32>() {
                Ok(v) => Ok(v),
                Err(e) => Err(format!("failed to parse integer: {:?}", e)),
            }
        }
        None => Err("failed to find match".to_string()),
    }
}

/// Retrieve the value of a property identified by `name`.
pub fn get_property(name: &str) -> Result<String, Error> {
    match rustutils::system_properties::read(name) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(format!("no value for property {}", name)),
        Err(e) => Err(format!("failed to get property {}: {:?}", name, e)),
    }
}

/// Extract a patchlevel in form YYYYMM from a "YYYY-MM-DD" property value.
pub fn extract_truncated_patchlevel(prop_value: &str) -> Result<u32, Error> {
    let patchlevel_regex = Regex::new(PATCHLEVEL_REGEX)
        .map_err(|e| format!("failed to compile patchlevel regexp: {:?}", e))?;

    let captures = patchlevel_regex
        .captures(prop_value)
        .ok_or_else(|| "failed to match patchlevel regex".to_string())?;
    let year = extract_u32(captures.name("year"))?;
    let month = extract_u32(captures.name("month"))?;
    if !(1..=12).contains(&month) {
        return Err(format!("month out of range: {}", month));
    }
    // no day
    Ok(year * 100 + month)
}

/// Extract a patchlevel in form YYYYMMDD from a "YYYY-MM-DD" property value.
pub fn extract_patchlevel(prop_value: &str) -> Result<u32, Error> {
    let patchlevel_regex = Regex::new(PATCHLEVEL_REGEX)
        .map_err(|e| format!("failed to compile patchlevel regexp: {:?}", e))?;

    let captures = patchlevel_regex
        .captures(prop_value)
        .ok_or_else(|| "failed to match patchlevel regex".to_string())?;
    let year = extract_u32(captures.name("year"))?;
    let month = extract_u32(captures.name("month"))?;
    if !(1..=12).contains(&month) {
        return Err(format!("month out of range: {}", month));
    }
    let day = extract_u32(captures.name("day"))?;
    if !(1..=31).contains(&day) {
        return Err(format!("day out of range: {}", day));
    }
    Ok(year * 10000 + month * 100 + day)
}

/// Generate HAL information from property values.
fn populate_hal_info_from(
    os_version_prop: &str,
    os_patchlevel_prop: &str,
    vendor_patchlevel_prop: &str,
) -> Result<SetHalInfoRequest, Error> {
    let os_version_regex = Regex::new(OS_VERSION_REGEX)
        .map_err(|e| format!("failed to compile version regexp: {:?}", e))?;
    let captures = os_version_regex
        .captures(os_version_prop)
        .ok_or_else(|| "failed to match OS version regex".to_string())?;
    let major = extract_u32(captures.name("major"))?;
    let minor = extract_u32(captures.name("minor")).unwrap_or(0u32);
    let sub = extract_u32(captures.name("sub")).unwrap_or(0u32);
    let os_version = (major * 10000) + (minor * 100) + sub;

    Ok(SetHalInfoRequest {
        os_version,
        os_patchlevel: extract_truncated_patchlevel(os_patchlevel_prop)?,
        vendor_patchlevel: extract_patchlevel(vendor_patchlevel_prop)?,
    })
}

/// Populate a [`SetHalInfoRequest`] based on property values read from the environment.
pub fn populate_hal_info() -> Result<SetHalInfoRequest, Error> {
    let os_version_prop = get_property(OS_VERSION_PROPERTY)
        .map_err(|e| format!("failed to retrieve property: {:?}", e))?;
    let os_patchlevel_prop = get_property(OS_PATCHLEVEL_PROPERTY)
        .map_err(|e| format!("failed to retrieve property: {:?}", e))?;
    let vendor_patchlevel_prop = get_property(VENDOR_PATCHLEVEL_PROPERTY)
        .map_err(|e| format!("failed to retrieve property: {:?}", e))?;

    populate_hal_info_from(&os_version_prop, &os_patchlevel_prop, &vendor_patchlevel_prop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_wire::SetHalInfoRequest;
    #[test]
    fn test_hal_info() {
        let tests = vec![
            (
                "12",
                "2021-02-02",
                "2022-03-04",
                SetHalInfoRequest {
                    os_version: 120000,
                    os_patchlevel: 202102,
                    vendor_patchlevel: 20220304,
                },
            ),
            (
                "12.5",
                "2021-02-02",
                "2022-03-04",
                SetHalInfoRequest {
                    os_version: 120500,
                    os_patchlevel: 202102,
                    vendor_patchlevel: 20220304,
                },
            ),
            (
                "12.5.7",
                "2021-02-02",
                "2022-03-04",
                SetHalInfoRequest {
                    os_version: 120507,
                    os_patchlevel: 202102,
                    vendor_patchlevel: 20220304,
                },
            ),
        ];
        for (os_version, os_patch, vendor_patch, want) in tests {
            let got = populate_hal_info_from(os_version, os_patch, vendor_patch).unwrap();
            assert_eq!(
                got, want,
                "Mismatch for input ({}, {}, {})",
                os_version, os_patch, vendor_patch
            );
        }
    }

    #[test]
    fn test_invalid_hal_info() {
        let tests = vec![
            ("xx", "2021-02-02", "2022-03-04", "failed to match OS version"),
            ("12.xx", "2021-02-02", "2022-03-04", "failed to match OS version"),
            ("12.5.xx", "2021-02-02", "2022-03-04", "failed to match OS version"),
            ("12", "20212-02-02", "2022-03-04", "failed to match patchlevel regex"),
            ("12", "2021-xx-02", "2022-03-04", "failed to match patchlevel"),
            ("12", "2021-13-02", "2022-03-04", "month out of range"),
            ("12", "2022-03-04", "2021-xx-02", "failed to match patchlevel"),
            ("12", "2022-03-04", "2021-13-02", "month out of range"),
            ("12", "2022-03-04", "2021-03-32", "day out of range"),
        ];
        for (os_version, os_patch, vendor_patch, want_err) in tests {
            let result = populate_hal_info_from(os_version, os_patch, vendor_patch);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains(want_err),
                "Mismatch for input ({}, {}, {}), got error '{}', want '{}'",
                os_version,
                os_patch,
                vendor_patch,
                err,
                want_err
            );
        }
    }
}
