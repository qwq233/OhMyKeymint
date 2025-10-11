// Copyright 2023, The Android Open Source Project
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

//! Helpers for the watchdog module.

use std::sync::{Arc, LazyLock};
use std::time::Duration;
pub use watchdog_rs::WatchPoint;
use watchdog_rs::Watchdog;

/// Default timeout interval, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 500;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(DEFAULT_TIMEOUT_MS);

/// A Watchdog thread, that can be used to create watch points.
static WD: LazyLock<Arc<Watchdog>> = LazyLock::new(|| Watchdog::new(Duration::from_secs(10)));

/// Sets a watch point with `id` and a timeout of `millis` milliseconds.
pub fn watch_millis(id: &'static str, millis: u64) -> Option<WatchPoint> {
    Watchdog::watch(&WD, id, Duration::from_millis(millis))
}

/// Sets a watch point with `id` and a default timeout of [`DEFAULT_TIMEOUT_MS`] milliseconds.
pub fn watch(id: &'static str) -> Option<WatchPoint> {
    Watchdog::watch(&WD, id, DEFAULT_TIMEOUT)
}

/// Like `watch_millis` but with context that is included every time a report is printed about
/// this watch point.
pub fn watch_millis_with(
    id: &'static str,
    millis: u64,
    context: impl std::fmt::Debug + Send + 'static,
) -> Option<WatchPoint> {
    Watchdog::watch_with(&WD, id, Duration::from_millis(millis), context)
}
