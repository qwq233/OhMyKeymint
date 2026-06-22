// Copyright 2020, The Android Open Source Project
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

//! Async task tests.
use super::{AsyncTask, Shelf};
use std::sync::{
    mpsc::{channel, sync_channel, RecvTimeoutError},
    Arc,
};
use std::time::Duration;

#[test]
fn test_shelf() {
    let mut shelf = Shelf::default();

    let s = "A string".to_string();
    assert_eq!(shelf.put(s), None);

    let s2 = "Another string".to_string();
    assert_eq!(shelf.put(s2), Some("A string".to_string()));

    // Put something of a different type on the shelf.
    #[derive(Debug, PartialEq, Eq)]
    struct Elf {
        pub name: String,
    }
    let e1 = Elf {
        name: "Glorfindel".to_string(),
    };
    assert_eq!(shelf.put(e1), None);

    // The String value is still on the shelf.
    let s3 = shelf.get_downcast_ref::<String>().unwrap();
    assert_eq!(s3, "Another string");

    // As is the Elf.
    {
        let e2 = shelf.get_downcast_mut::<Elf>().unwrap();
        assert_eq!(e2.name, "Glorfindel");
        e2.name = "Celeborn".to_string();
    }

    // Take the Elf off the shelf.
    let e3 = shelf.remove_downcast_ref::<Elf>().unwrap();
    assert_eq!(e3.name, "Celeborn");

    assert_eq!(shelf.remove_downcast_ref::<Elf>(), None);

    // No u64 value has been put on the shelf, so getting one gives the default value.
    {
        let i = shelf.get_mut::<u64>();
        assert_eq!(*i, 0);
        *i = 42;
    }
    let i2 = shelf.get_downcast_ref::<u64>().unwrap();
    assert_eq!(*i2, 42);

    // No i32 value has ever been seen near the shelf.
    assert_eq!(shelf.get_downcast_ref::<i32>(), None);
    assert_eq!(shelf.get_downcast_mut::<i32>(), None);
    assert_eq!(shelf.remove_downcast_ref::<i32>(), None);
}

#[test]
fn test_async_task() {
    let at = AsyncTask::default();

    // First queue up a job that blocks until we release it, to avoid
    // unpredictable synchronization.
    let (start_sender, start_receiver) = channel();
    at.queue_hi(move |shelf| {
        start_receiver.recv().unwrap();
        // Put a trace vector on the shelf
        shelf.put(Vec::<String>::new());
    });

    // Queue up some high-priority and low-priority jobs.
    for i in 0..3 {
        let j = i;
        at.queue_lo(move |shelf| {
            let trace = shelf.get_mut::<Vec<String>>();
            trace.push(format!("L{j}"));
        });
        let j = i;
        at.queue_hi(move |shelf| {
            let trace = shelf.get_mut::<Vec<String>>();
            trace.push(format!("H{j}"));
        });
    }

    // Finally queue up a low priority job that emits the trace.
    let (trace_sender, trace_receiver) = channel();
    at.queue_lo(move |shelf| {
        let trace = shelf.get_downcast_ref::<Vec<String>>().unwrap();
        trace_sender.send(trace.clone()).unwrap();
    });

    // Ready, set, go.
    start_sender.send(()).unwrap();
    let trace = trace_receiver.recv().unwrap();

    assert_eq!(trace, vec!["H0", "H1", "H2", "L0", "L1", "L2"]);
}

#[test]
fn test_async_task_chain() {
    let at = Arc::new(AsyncTask::default());
    let (sender, receiver) = channel();
    // Queue up a job that will queue up another job. This confirms
    // that the job is not invoked with any internal AsyncTask locks held.
    let at_clone = at.clone();
    at.queue_hi(move |_shelf| {
        at_clone.queue_lo(move |_shelf| {
            sender.send(()).unwrap();
        });
    });
    receiver.recv().unwrap();
}

#[test]
#[should_panic(expected = "AsyncTask panicked")]
fn test_async_task_panic() {
    let at = AsyncTask::default();
    at.queue_hi(|_shelf| {
        panic!("Panic from queued job");
    });

    let thread = {
        let (_condvar, state) = &*at.state;
        state.lock().unwrap().thread.take().unwrap()
    };
    if thread.join().is_err() {
        panic!("AsyncTask panicked");
    }
}

#[test]
fn test_async_task_idle() {
    let at = AsyncTask::new(Duration::from_secs(3));
    // Need a SyncSender as it is Send+Sync.
    let (idle_done_sender, idle_done_receiver) = sync_channel::<()>(3);
    at.add_idle(move |_shelf| {
        idle_done_sender.send(()).unwrap();
    });

    // Queue up some high-priority and low-priority jobs that take time.
    for _i in 0..3 {
        at.queue_lo(|_shelf| {
            std::thread::sleep(Duration::from_millis(500));
        });
        at.queue_hi(|_shelf| {
            std::thread::sleep(Duration::from_millis(500));
        });
    }
    // Final low-priority job.
    let (done_sender, done_receiver) = channel();
    at.queue_lo(move |_shelf| {
        done_sender.send(()).unwrap();
    });

    // Nothing happens until the last job completes.
    assert_eq!(
        idle_done_receiver.recv_timeout(Duration::from_secs(1)),
        Err(RecvTimeoutError::Timeout)
    );
    done_receiver.recv().unwrap();
    // Now that the last low-priority job has completed, the idle task should
    // fire pretty much immediately.
    idle_done_receiver
        .recv_timeout(Duration::from_millis(50))
        .unwrap();

    // Idle callback not executed again even if we wait for a while.
    assert_eq!(
        idle_done_receiver.recv_timeout(Duration::from_secs(3)),
        Err(RecvTimeoutError::Timeout)
    );

    // However, if more work is done then there's another chance to go idle.
    let (done_sender, done_receiver) = channel();
    at.queue_hi(move |_shelf| {
        std::thread::sleep(Duration::from_millis(500));
        done_sender.send(()).unwrap();
    });
    // Idle callback not immediately executed, because the high priority
    // job is taking a while.
    assert_eq!(
        idle_done_receiver.recv_timeout(Duration::from_millis(1)),
        Err(RecvTimeoutError::Timeout)
    );
    done_receiver.recv().unwrap();
    idle_done_receiver
        .recv_timeout(Duration::from_millis(50))
        .unwrap();
}

#[test]
fn test_async_task_multiple_idle() {
    let at = AsyncTask::new(Duration::from_secs(3));
    let (idle_sender, idle_receiver) = sync_channel::<i32>(5);
    // Queue a high priority job to start things off
    at.queue_hi(|_shelf| {
        std::thread::sleep(Duration::from_millis(500));
    });

    // Multiple idle callbacks.
    for i in 0..3 {
        let idle_sender = idle_sender.clone();
        at.add_idle(move |_shelf| {
            idle_sender.send(i).unwrap();
        });
    }

    // Nothing happens immediately.
    assert_eq!(
        idle_receiver.recv_timeout(Duration::from_millis(1)),
        Err(RecvTimeoutError::Timeout)
    );
    // Wait for a moment and the idle jobs should have run.
    std::thread::sleep(Duration::from_secs(1));

    let mut results = Vec::new();
    while let Ok(i) = idle_receiver.recv_timeout(Duration::from_millis(1)) {
        results.push(i);
    }
    assert_eq!(results, [0, 1, 2]);
}

#[test]
fn test_async_task_idle_queues_job() {
    let at = Arc::new(AsyncTask::new(Duration::from_secs(1)));
    let at_clone = at.clone();
    let (idle_sender, idle_receiver) = sync_channel::<i32>(100);
    // Add an idle callback that queues a low-priority job.
    at.add_idle(move |shelf| {
        at_clone.queue_lo(|_shelf| {
            // Slow things down so the channel doesn't fill up.
            std::thread::sleep(Duration::from_millis(50));
        });
        let i = shelf.get_mut::<i32>();
        idle_sender.send(*i).unwrap();
        *i += 1;
    });

    // Nothing happens immediately.
    assert_eq!(
        idle_receiver.recv_timeout(Duration::from_millis(1500)),
        Err(RecvTimeoutError::Timeout)
    );

    // Once we queue a normal job, things start.
    at.queue_hi(|_shelf| {});
    assert_eq!(
        0,
        idle_receiver
            .recv_timeout(Duration::from_millis(200))
            .unwrap()
    );

    // The idle callback queues a job, and completion of that job
    // means the task is going idle again...so the idle callback will
    // be called repeatedly.
    assert_eq!(
        1,
        idle_receiver
            .recv_timeout(Duration::from_millis(100))
            .unwrap()
    );
    assert_eq!(
        2,
        idle_receiver
            .recv_timeout(Duration::from_millis(100))
            .unwrap()
    );
    assert_eq!(
        3,
        idle_receiver
            .recv_timeout(Duration::from_millis(100))
            .unwrap()
    );
}

#[test]
#[should_panic(expected = "AsyncTask panicked")]
fn test_async_task_idle_panic() {
    let at = AsyncTask::new(Duration::from_secs(1));
    let (idle_sender, idle_receiver) = sync_channel::<()>(3);
    // Add an idle callback that panics.
    at.add_idle(move |_shelf| {
        idle_sender.send(()).unwrap();
        panic!("Panic from idle callback");
    });
    // Queue a job to trigger idleness and ensuing panic.
    at.queue_hi(|_shelf| {});
    idle_receiver.recv_timeout(Duration::from_secs(1)).unwrap();

    let thread = {
        let (_condvar, state) = &*at.state;
        state.lock().unwrap().thread.take().unwrap()
    };
    if thread.join().is_err() {
        panic!("AsyncTask panicked");
    }
}
