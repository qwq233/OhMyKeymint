use super::*;

#[test]
fn binder_status_classification() {
    let status = Status::from(StatusCode::DeadObject);
    assert!(is_dead_object_status(&status));

    let status = Status::from(StatusCode::Ok);
    assert!(!is_dead_object_status(&status));

    for status in [StatusCode::DeadObject, StatusCode::RpcError, StatusCode::NotEnoughData] {
        assert!(is_stale_rpc_status_code(status));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(Status::from(status))));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(status)));
    }

    for status in [
        StatusCode::NoInit,
        StatusCode::Errno(libc::ECONNRESET),
        StatusCode::Errno(libc::ENOTCONN),
        StatusCode::Errno(libc::EPIPE),
    ] {
        assert!(is_rpc_cache_invalidating_status_code(status));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(Status::from(status))));
        assert!(is_rpc_cache_invalidating_error(&anyhow::Error::new(status)));
    }

    let stale = anyhow::Error::new(Status::from(StatusCode::Unknown));
    assert!(!is_stale_rpc_status_code(StatusCode::Unknown));
    assert!(is_rpc_cache_invalidating_error(&stale));
    assert!(!is_dead_object_error(&stale));

    let direct_unknown = anyhow::Error::new(StatusCode::Unknown);
    assert!(!is_rpc_cache_invalidating_error(&direct_unknown));

    let business = anyhow::Error::new(Status::new_service_specific_error(1, None));
    assert!(!is_rpc_cache_invalidating_error(&business));
}

struct AuthStub;

static TEST_CACHE: Mutex<RpcCache> =
    Mutex::new(RpcCache { service: None, auth_token: None, lifecycle: None });
static TEST_CONNECT: Mutex<()> = Mutex::new(());
thread_local! {
    static TEST_AUTH: RefCell<CachedRpcClient<Strong<dyn IOhMyAuthorizationService>>> = RefCell::default();
}

impl rsbinder::Remotable for AuthStub {
    fn descriptor() -> &'static str {
        "top.qwq2333.ohmykeymint.IOhMyAuthorizationService"
    }

    fn on_transact(
        &self,
        _: u32,
        _: &mut rsbinder::Parcel,
        reply: &mut rsbinder::Parcel,
    ) -> rsbinder::Result<()> {
        reply.write(&Status::from(StatusCode::Ok))?;
        reply.write(&1i64)
    }

    fn on_dump(&self, _: &mut dyn std::io::Write, _: &[String]) -> rsbinder::Result<()> {
        Ok(())
    }
}

struct TestServer {
    server: Arc<rsbinder::rpc::RpcServer>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.server.stop_accepting();
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        self.server.terminate();
        self.server.join_workers();
    }
}

fn with_test_auth<T>(
    path: &std::path::Path,
    f: impl FnOnce(&Strong<dyn IOhMyAuthorizationService>) -> Result<T>,
) -> Result<T> {
    with_rpc_client(
        || {
            Ok(RpcSession::setup_client_android13plus_with_config(
                RpcClientConfig::unix(path, rpc::WIRE_MAX_VERSION).outgoing_connections(1),
            )?)
        },
        &TEST_CACHE,
        &TEST_CONNECT,
        &TEST_AUTH,
        |cache| &mut cache.auth_token,
        |session| Ok(session.get_interface(rpc::AUTHORIZATION_SERVICE)?),
        f,
    )
}

#[test]
fn rpc_cache_serializes_connection_and_preserves_new_client_after_reentrant_failure() {
    use rsbinder::Interface;
    use std::sync::atomic::AtomicUsize;
    ensure_process_state();
    let path = std::env::temp_dir().join(format!("omk-rpc-{}.sock", std::process::id()));
    let server = rsbinder::rpc::RpcServer::setup_unix_server(&path).unwrap();
    server.set_android13plus(rpc::WIRE_MAX_VERSION);
    server.set_max_threads(8);
    let accepted = Arc::new(AtomicUsize::new(0));
    let connections = Arc::clone(&accepted);
    server.set_authorizer(move |_| {
        connections.fetch_add(1, Ordering::Relaxed);
        true
    });
    server
        .add_service(rpc::AUTHORIZATION_SERVICE, rsbinder::Binder::new(AuthStub).as_binder())
        .unwrap();
    let _server = TestServer { accept: Some(server.run_background()), server };
    let barrier = std::sync::Barrier::new(8);
    let identities = std::thread::scope(|scope| {
        let handles = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    assert_eq!(
                        with_test_auth(&path, |auth| Ok(auth.r#getLastAuthTime(None, 7, &[])?))
                            .unwrap(),
                        1
                    );
                    TEST_AUTH.with(|local| Arc::as_ptr(local.borrow().as_ref().unwrap()) as usize)
                })
            })
            .collect::<Vec<_>>();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
    });
    assert!(identities.iter().all(|identity| *identity == identities[0]));
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert_eq!(with_test_auth(&path, |auth| Ok(auth.r#getLastAuthTime(None, 7, &[])?)).unwrap(), 1);
    let previous = TEST_CACHE.lock().unwrap().auth_token.as_ref().unwrap().clone();
    let result: Result<()> = with_test_auth(&path, |_| {
        previous.active.store(false, Ordering::Release);
        assert_eq!(with_test_auth(&path, |auth| Ok(auth.r#getLastAuthTime(None, 7, &[])?))?, 1);
        Err(anyhow::Error::new(StatusCode::DeadObject))
    });
    assert!(result.is_err());
    let current = TEST_CACHE.lock().unwrap().auth_token.as_ref().unwrap().clone();
    assert!(!Arc::ptr_eq(&current, &previous));
    assert!(current.is_current());
    assert_eq!(with_test_auth(&path, |auth| Ok(auth.r#getLastAuthTime(None, 7, &[])?)).unwrap(), 1);
    TEST_AUTH.with(|local| assert!(Arc::ptr_eq(local.borrow().as_ref().unwrap(), &current)));
    let retired = TEST_AUTH.with(|local| local.borrow_mut().take());
    drop(retired);
    let retired = TEST_CACHE.lock().unwrap().auth_token.take();
    drop(retired);
}
