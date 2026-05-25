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

use std::time::Duration;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReadRaceErrorKind {
    Retryable,
    Fatal,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RetryOutcome<T> {
    pub value: T,
    pub retries: usize,
}

pub fn retry_read_race<T, E, Load, Classify, Sleep, OnRetry>(
    mut load: Load,
    classify: Classify,
    retry_limit: usize,
    retry_interval: Duration,
    mut sleep: Sleep,
    mut on_retry: OnRetry,
) -> Result<RetryOutcome<T>, E>
where
    Load: FnMut() -> Result<T, E>,
    Classify: Fn(&E) -> ReadRaceErrorKind,
    Sleep: FnMut(Duration),
    OnRetry: FnMut(usize, &E, Duration),
{
    let mut retries = 0usize;

    loop {
        match load() {
            Ok(value) => return Ok(RetryOutcome { value, retries }),
            Err(error) if classify(&error) == ReadRaceErrorKind::Retryable => {
                if retries >= retry_limit {
                    return Err(error);
                }
                retries += 1;
                on_retry(retries, &error, retry_interval);
                sleep(retry_interval);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Eq, PartialEq)]
    enum TestError {
        Missing,
        Parse,
    }

    fn classify(error: &TestError) -> ReadRaceErrorKind {
        match error {
            TestError::Missing => ReadRaceErrorKind::Retryable,
            TestError::Parse => ReadRaceErrorKind::Fatal,
        }
    }

    #[test]
    fn retries_retryable_errors() {
        let mut attempts = 0usize;
        let result = retry_read_race(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(TestError::Missing)
                } else {
                    Ok("loaded")
                }
            },
            classify,
            5,
            Duration::from_millis(1),
            |_| {},
            |_, _, _| {},
        )
        .unwrap();

        assert_eq!(result.value, "loaded");
        assert_eq!(result.retries, 2);
    }

    #[test]
    fn does_not_retry_fatal_errors() {
        let mut attempts = 0usize;
        let error = retry_read_race(
            || {
                attempts += 1;
                Err::<(), _>(TestError::Parse)
            },
            classify,
            5,
            Duration::from_millis(1),
            |_| {},
            |_, _, _| {},
        )
        .unwrap_err();

        assert_eq!(error, TestError::Parse);
        assert_eq!(attempts, 1);
    }
}
