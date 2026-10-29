use super::*;

#[test]
fn reused_fd_fails_closed_once_then_accepts_the_new_generation() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 89;
    reset_binder_fd_for_test(fd);

    let original = synchronize_binder_fd_generation(fd).unwrap();
    invalidate_binder_fd(fd);
    assert_eq!(synchronize_binder_fd_generation(fd), Err(original));
    let replacement = synchronize_binder_fd_generation(fd).unwrap();

    assert_ne!(replacement.connection, original.connection);
    assert!(!binder_fd_token_is_current(original));
    assert!(binder_fd_token_is_current(replacement));
    reset_binder_fd_for_test(fd);
}

#[test]
fn binder_fd_duplicated_before_first_io_shares_its_lifecycle() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = unsafe { libc::open(c"/dev/binder".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    assert!(fd >= 0, "test requires the Android Binder driver");
    assert!(existing_binder_fd_lifecycle(fd).is_none());

    let alias = unsafe { duplicate_binder_fd_with_lifecycle(fd, None, || libc::dup(fd)) };
    assert!(alias >= 0);
    let source = existing_binder_fd_lifecycle(fd).expect("source should be registered");
    let destination =
        existing_binder_fd_lifecycle(alias).expect("destination should inherit source");
    assert!(Arc::ptr_eq(&source, &destination));

    assert_eq!(unsafe { close_with_binder_fd_lifecycle(alias, || libc::close(alias)) }, 0);
    assert_eq!(unsafe { close_with_binder_fd_lifecycle(fd, || libc::close(fd)) }, 0);
}

#[test]
fn binder_fd_close_and_replacement_serialize_with_ioctl() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 91;
    reset_binder_fd_for_test(fd);
    let original = binder_fd_token(fd);
    assert!(binder_fd_token_is_current(original));
    let lifecycle = binder_fd_lifecycle(fd);
    let ioctl = lifecycle.state.lock().expect("binder fd lifecycle poisoned");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let close_thread = std::thread::spawn(move || {
        let result = unsafe {
            close_with_binder_fd_lifecycle(fd, || {
                started_tx.send(()).unwrap();
                0
            })
        };
        done_tx.send(result).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(done_rx.try_recv().is_err());
    drop(ioctl);
    assert_eq!(done_rx.recv().unwrap(), 0);
    close_thread.join().unwrap();
    assert!(!binder_fd_token_is_current(original));

    let after_close = binder_fd_token(fd);
    unsafe { *libc::__errno() = libc::EIO };
    assert_eq!(
        unsafe {
            duplicate_binder_fd_with_lifecycle(fd + 1, Some(fd), || {
                *libc::__errno() = libc::EPERM;
                -1
            })
        },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    assert!(binder_fd_token_is_current(after_close));
    assert_eq!(unsafe { duplicate_binder_fd_with_lifecycle(fd + 1, Some(fd), || fd) }, fd);
    assert!(!binder_fd_token_is_current(after_close));
    reset_binder_fd_for_test(fd);
    reset_binder_fd_for_test(fd + 1);
}
