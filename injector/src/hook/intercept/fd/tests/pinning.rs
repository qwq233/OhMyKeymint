use super::*;

#[test]
fn blocking_binder_read_does_not_hold_the_fd_lifecycle_lock() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let fd = pipe[0];
    reset_binder_fd_for_test(fd);
    let token = binder_fd_token(fd);
    let lifecycle = existing_binder_fd_lifecycle(fd).unwrap();
    let ioctl_thread = std::thread::spawn(move || unsafe {
        call_binder_ioctl(token, blocking_ioctl, BINDER_WRITE_READ as c_int, std::ptr::null_mut())
    });
    PINNED_IOCTL_ENTERED.wait();
    let pinned_fd = *lifecycle.pinned_fd.get().unwrap();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let close_thread = std::thread::spawn(move || {
        let result = unsafe { close_with_binder_fd_lifecycle(fd, || 7) };
        done_tx.send(result).unwrap();
    });
    let close_result = done_rx.recv_timeout(Duration::from_secs(1));
    assert!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) } >= 0);
    PINNED_IOCTL_RELEASE.wait();

    assert_eq!(ioctl_thread.join().unwrap(), BinderIoctlCall::Called(0));
    close_thread.join().unwrap();
    assert_eq!(close_result.unwrap(), 7);
    drop(lifecycle);
    assert_eq!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) }, -1);
    unsafe {
        libc::syscall(libc::SYS_close, pipe[0]);
        libc::syscall(libc::SYS_close, pipe[1]);
    }
    reset_binder_fd_for_test(fd);
}

#[test]
fn binder_ioctl_reuses_one_pin_until_connection_retires() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let fd = pipe[0];
    reset_binder_fd_for_test(fd);
    let token = binder_fd_token(fd);

    let first = BinderIoctlGuard::begin(token).unwrap();
    let pinned_fd = first.fd();
    assert_ne!(pinned_fd, fd);
    drop(first);
    assert!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) } >= 0);

    let second = BinderIoctlGuard::begin(token).unwrap();
    assert_eq!(second.fd(), pinned_fd);
    drop(second);

    assert_eq!(unsafe { close_with_binder_fd_lifecycle(fd, || libc::close(fd)) }, 0);
    assert_eq!(unsafe { libc::fcntl(pinned_fd, libc::F_GETFD) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    unsafe { libc::close(pipe[1]) };
}
