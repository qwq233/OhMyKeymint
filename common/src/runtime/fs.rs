// Copyright 2026, The Android Open Source Project
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

use std::format;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::Context;

pub fn backup_file_with_reason(
    path: &Path,
    backup: &Path,
    reason_header: &str,
    reason: &str,
    allow_copy_fallback: bool,
) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if backup.exists() {
        fs::remove_file(backup)
            .with_context(|| format!("failed to remove stale backup {}", backup.display()))?;
    }

    let rename_result = fs::rename(path, backup);
    if let Err(rename_error) = rename_result {
        if !allow_copy_fallback {
            return Err(rename_error)
                .with_context(|| format!("failed to move invalid file to {}", backup.display()));
        }

        fs::copy(path, backup)
            .with_context(|| {
                format!(
                    "failed to copy invalid file to backup {} after rename error {rename_error}",
                    backup.display()
                )
            })
            .and_then(|_| {
                fs::remove_file(path)
                    .with_context(|| format!("failed to remove original file {}", path.display()))
            })
            .with_context(|| format!("failed to move invalid file to {}", backup.display()))?;
    }

    let mut file = OpenOptions::new()
        .append(true)
        .open(backup)
        .with_context(|| format!("failed to open backup {}", backup.display()))?;
    writeln!(file)?;
    writeln!(file, "# {reason_header}:")?;
    for line in reason.lines() {
        writeln!(file, "# {line}")?;
    }
    Ok(())
}
