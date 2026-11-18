/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::future::Future;
use std::pin::Pin;

/// A type alias for a pinned, boxed future that lets you write shorter code without littering it
/// with Pin and Send bounds.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A thread pool for running binder transactions.
pub trait BinderAsyncPool {
    /// This function should conceptually behave like this:
    ///
    /// ```text
    /// let result = spawn_thread(|| spawn_me()).await;
    /// return after_spawn(result).await;
    /// ```
    ///
    /// If the spawning fails for some reason, the method may also skip the `after_spawn` closure
    /// and immediately return an error.
    ///
    /// The only difference between different implementations should be which
    /// `spawn_thread` method is used. For Tokio, it would be `tokio::task::spawn_blocking`.
    ///
    /// This method has the design it has because the only way to define a trait that
    /// allows the return type of the spawn to be chosen by the caller is to return a
    /// boxed `Future` trait object, and including `after_spawn` in the trait function
    /// allows the caller to avoid double-boxing if they want to do anything to the value
    /// returned from the spawned thread.
    fn spawn<'a, F1, F2, Fut, A, B, E>(
        spawn_me: F1,
        after_spawn: F2,
    ) -> BoxFuture<'a, Result<B, E>>
    where
        F1: FnOnce() -> A,
        F2: FnOnce(A) -> Fut,
        Fut: Future<Output = Result<B, E>>,
        F1: Send + 'static,
        F2: Send + 'a,
        Fut: Send + 'a,
        A: Send + 'static,
        B: Send + 'a,
        E: From<crate::StatusCode>;
}

/// A runtime for executing an async binder server.
pub trait BinderAsyncRuntime {
    /// Block on the provided future, running it to completion and returning its output.
    fn block_on<F: Future>(&self, future: F) -> F::Output;
}
