/* SPDX-License-Identifier: Apache-2.0 */

//! Unix Binder RPC using the device's native transport and the existing named directory.

use super::native::{self, CppStrong, NativeStrong};
use crate::binder_impl::{
    Binder, BorrowedParcel, IBinderInternal, Remotable, FIRST_CALL_TRANSACTION,
};
use crate::error::Result as BinderResult;
use crate::{
    sys, DeathRecipient, FromIBinder, IBinder, Interface, SpIBinder, Status, StatusCode, Strong,
};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{c_char, c_void, CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{fmt, fs, io};

// Preserve the established private directory wire contract; this is not a new service API.
const DIRECTORY: &str = "rsbinder.rpc.IServiceDirectory";

/// A native setup/transport error or a Binder reply from the named directory.
#[derive(Debug)]
pub enum RpcError {
    Native(i32),
    Binder(Status),
    Io(io::Error),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(code) => write!(f, "native Binder RPC error {code}"),
            Self::Binder(status) => fmt::Display::fmt(status, f),
            Self::Io(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for RpcError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binder(status) => Some(status),
            Self::Io(error) => Some(error),
            Self::Native(_) => None,
        }
    }
}

impl From<StatusCode> for RpcError {
    fn from(code: StatusCode) -> Self {
        Self::Native(code as i32)
    }
}

impl From<io::Error> for RpcError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

type Result<T> = std::result::Result<T, RpcError>;
type Server = c_void;
type Session = c_void;
type SetRoot = unsafe extern "C" fn(*mut Server, *const NativeStrong);
type SetThreads = unsafe extern "C" fn(*mut Server, usize);
type Join = unsafe extern "C" fn(*mut Server);
type ServerSetup = unsafe extern "C" fn(*mut Server, *const c_char) -> i32;
type ClientSetup = unsafe extern "C" fn(*mut Session, *const c_char) -> i32;

struct ServiceDirectory {
    services: Arc<Mutex<HashMap<String, SpIBinder>>>,
}

impl Remotable for ServiceDirectory {
    fn get_descriptor() -> &'static str {
        DIRECTORY
    }

    fn on_transact(
        &self,
        code: u32,
        data: &BorrowedParcel<'_>,
        reply: &mut BorrowedParcel<'_>,
    ) -> BinderResult<()> {
        if code != FIRST_CALL_TRANSACTION {
            return Err(StatusCode::UNKNOWN_TRANSACTION);
        }
        let name: String = data.read()?;
        let service =
            self.services.lock().expect("RPC service directory poisoned").get(&name).cloned();
        match service {
            Some(service) => {
                reply.write(&Status::ok())?;
                reply.write(&service)
            }
            None => reply.write(&Status::from(StatusCode::NAME_NOT_FOUND)),
        }
    }

    fn on_dump(&self, _: &mut dyn io::Write, _: &[&CStr]) -> BinderResult<()> {
        Ok(())
    }

    fn on_shell_command(
        &self,
        _: &mut dyn io::Read,
        _: &mut dyn io::Write,
        _: &mut dyn io::Write,
        _: &[&CStr],
    ) -> BinderResult<()> {
        Ok(())
    }

    binder_fn_get_class!(Binder<Self>);
}

/// Named services on a private Unix socket. Native Binder owns the wire and Parcel handling.
pub struct RpcServer {
    native: CppStrong,
    _directory: SpIBinder,
    services: Arc<Mutex<HashMap<String, SpIBinder>>>,
}

impl RpcServer {
    /// Bind the private directory, replacing any existing socket at `path`.
    pub fn setup_unix_server(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref();
        let address =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| StatusCode::BAD_VALUE)?;
        // SAFETY: These fixed symbols use the corresponding typed AOSP RPC member-function ABIs.
        let setup: ServerSetup = unsafe {
            native::native_function(b"_ZN7android9RpcServer21setupUnixDomainServerEPKc\0")
        }?;
        let set_root: SetRoot = unsafe {
            native::native_function(
                b"_ZN7android9RpcServer13setRootObjectERKNS_2spINS_7IBinderEEE\0",
            )
        }?;
        let _: SetThreads =
            unsafe { native::native_function(b"_ZN7android9RpcServer13setMaxThreadsEm\0") }?;
        let _: Join = unsafe { native::native_function(b"_ZN7android9RpcServer4joinEv\0") }?;
        let mut factory: *mut c_void = std::ptr::null_mut();
        // SAFETY: factory is the writable unique_ptr argument slot; the adapter handles sp return.
        let native = unsafe {
            CppStrong::call(
                b"_ZN7android9RpcServer4makeENSt3__110unique_ptrINS_22RpcTransportCtxFactoryENS1_14default_deleteIS3_EEEE\0",
                (&mut factory as *mut *mut c_void) as usize,
                0,
            )
        };
        if !factory.is_null() {
            // SAFETY: make leaves a live factory unique_ptr; Itanium vtable[1] is its deleting
            // destructor, called once to consume the temporary argument's remaining ownership.
            unsafe {
                let vtable = factory.cast::<*const unsafe extern "C" fn(*mut c_void)>().read();
                vtable.add(1).read()(factory);
            }
        }
        let native = native?;
        let services = Arc::new(Mutex::new(HashMap::new()));
        let directory =
            Binder::new(ServiceDirectory { services: Arc::clone(&services) }).as_binder();
        let root = CppStrong::from_binder(&directory)?;
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // SAFETY: Both strong owners and the NUL-terminated address outlive these native calls.
        unsafe {
            set_root(native.as_ptr().cast(), root.as_slot());
            let status = setup(native.as_ptr().cast(), address.as_ptr());
            if status != 0 {
                return Err(RpcError::Native(status));
            }
        }
        Ok(Arc::new(Self { native, _directory: directory, services }))
    }

    pub fn add_service(&self, name: &str, binder: SpIBinder) -> BinderResult<()> {
        if binder.is_remote() {
            return Err(StatusCode::INVALID_OPERATION);
        }
        self.services
            .lock()
            .expect("RPC service directory poisoned")
            .insert(name.to_owned(), binder);
        Ok(())
    }

    pub fn set_max_threads(&self, threads: u32) {
        // SAFETY: The fixed setter has a server receiver/size_t ABI, checked during setup.
        let set: SetThreads =
            unsafe { native::native_function(b"_ZN7android9RpcServer13setMaxThreadsEm\0") }
                .expect("server thread setter checked during setup");
        // SAFETY: self retains the server and the positive count satisfies its native bound.
        unsafe { set(self.native.as_ptr().cast(), threads.max(1) as usize) };
    }

    pub fn run(&self) -> BinderResult<()> {
        // SAFETY: join has a receiver-only void ABI.
        let join: Join = unsafe { native::native_function(b"_ZN7android9RpcServer4joinEv\0") }?;
        // SAFETY: self retains the native server throughout the blocking join call.
        unsafe { join(self.native.as_ptr().cast()) };
        Ok(())
    }

    /// Start the native join thread once, after configuring this server.
    pub fn start(&self) -> BinderResult<()> {
        // Resolve shutdown before starting so this owned thread can always be stopped.
        let _: unsafe extern "C" fn(*mut Server) -> bool =
            unsafe { native::native_function(b"_ZN7android9RpcServer8shutdownEv\0") }?;
        // SAFETY: start has the receiver-only void ABI on Android 13-17.
        let start: Join = unsafe { native::native_function(b"_ZN7android9RpcServer5startEv\0") }?;
        // SAFETY: self retains the configured native server.
        unsafe { start(self.native.as_ptr().cast()) };
        Ok(())
    }

    /// Stop a started server and wait for its native threads; never call from its callbacks.
    pub fn shutdown(&self) -> BinderResult<bool> {
        // SAFETY: shutdown has the receiver-only bool ABI on Android 13-17.
        let shutdown: unsafe extern "C" fn(*mut Server) -> bool =
            unsafe { native::native_function(b"_ZN7android9RpcServer8shutdownEv\0") }?;
        // SAFETY: self retains the server through its synchronous native shutdown.
        Ok(unsafe { shutdown(self.native.as_ptr().cast()) })
    }
}

/// A native RPC session; returned proxies retain their native session ownership.
pub struct RpcSession {
    _native: CppStrong,
    root: SpIBinder,
}

impl RpcSession {
    /// Resolve the client ABI before an interceptor starts accepting requests.
    pub fn init_client_apis() -> BinderResult<()> {
        // SAFETY: Only addresses are resolved for the non-trivial sp return factories.
        unsafe {
            let _: unsafe extern "C" fn() =
                native::native_function(b"_ZN7android10RpcSession4makeEv\0")?;
            let _: unsafe extern "C" fn() =
                native::native_function(b"_ZN7android10RpcSession13getRootObjectEv\0")?;
            let _: ClientSetup =
                native::native_function(b"_ZN7android10RpcSession21setupUnixDomainClientEPKc\0")?;
            let setter: &[u8] = if sys::compat::api_level() == 33 {
                b"_ZN7android10RpcSession21setMaxOutgoingThreadsEm\0"
            } else {
                b"_ZN7android10RpcSession25setMaxOutgoingConnectionsEm\0"
            };
            let _: unsafe extern "C" fn(*mut Session, usize) = native::native_function(setter)?;
        }
        Ok(())
    }

    /// Android 13 supports a client thread cap; newer transports negotiate all server threads.
    pub fn connect(
        path: impl AsRef<Path>,
        outgoing_connections: usize,
        incoming_threads: usize,
    ) -> crate::Result<Self> {
        let address = CString::new(path.as_ref().as_os_str().as_bytes())
            .map_err(|_| StatusCode::BAD_VALUE)?;
        // SAFETY: setupUnixDomainClient takes a session receiver and NUL-terminated address.
        let setup: ClientSetup = unsafe {
            native::native_function(b"_ZN7android10RpcSession21setupUnixDomainClientEPKc\0")
        }?;
        // SAFETY: This zero-argument factory returns its sp through the native ABI adapter.
        let native = unsafe { CppStrong::call(b"_ZN7android10RpcSession4makeEv\0", 0, 0)? };
        // SAFETY: The session is strongly held. Version-selected setters take size_t, setup borrows
        // the live address, and getRootObject returns its own sp through the native ABI adapter.
        unsafe {
            let incoming: unsafe extern "C" fn(*mut Session, usize) =
                native::native_function(b"_ZN7android10RpcSession21setMaxIncomingThreadsEm\0")?;
            let shutdown: unsafe extern "C" fn(*mut Session, bool) -> bool =
                native::native_function(b"_ZN7android10RpcSession15shutdownAndWaitEb\0")?;
            incoming(native.as_ptr().cast(), incoming_threads);
            if sys::compat::api_level() == 33 {
                let set: unsafe extern "C" fn(*mut Session, usize) =
                    native::native_function(b"_ZN7android10RpcSession21setMaxOutgoingThreadsEm\0")?;
                set(native.as_ptr().cast(), outgoing_connections.max(1));
            } else {
                let set: unsafe extern "C" fn(*mut Session, usize) = native::native_function(
                    b"_ZN7android10RpcSession25setMaxOutgoingConnectionsEm\0",
                )?;
                // This private endpoint is trusted; native requires enough connections for its pool.
                set(native.as_ptr().cast(), usize::MAX);
            }
            let status = setup(native.as_ptr().cast(), address.as_ptr());
            if status != 0 {
                return Err(Status::from(status));
            }
            let root = CppStrong::call(
                b"_ZN7android10RpcSession13getRootObjectEv\0",
                native.as_ptr() as usize,
                0,
            )
            .and_then(|root| root.to_binder());
            match root {
                Ok(root) => Ok(Self { _native: native, root }),
                Err(error) => {
                    shutdown(native.as_ptr(), true);
                    Err(error.into())
                }
            }
        }
    }

    pub fn is_ended(&self) -> bool {
        !self.root.is_binder_alive()
    }

    pub fn ping(&self) -> BinderResult<()> {
        self.root.clone().ping_binder()
    }

    pub fn link_to_death(&self, recipient: &mut DeathRecipient) -> BinderResult<()> {
        self.root.clone().link_to_death(recipient)
    }

    pub fn shutdown(&self) -> BinderResult<bool> {
        // SAFETY: The fixed release headers declare bool shutdownAndWait(bool).
        let shutdown: unsafe extern "C" fn(*mut Session, bool) -> bool =
            unsafe { native::native_function(b"_ZN7android10RpcSession15shutdownAndWaitEb\0")? };
        // SAFETY: This owner retains the native session until its incoming threads have stopped.
        Ok(unsafe { shutdown(self._native.as_ptr(), true) })
    }

    pub fn get_service(&self, name: &str) -> crate::Result<SpIBinder> {
        super::associate_descriptor(&self.root, DIRECTORY)?;
        let mut data = self.root.prepare_transact()?;
        data.write(name)?;
        let reply = self.root.submit_transact(FIRST_CALL_TRANSACTION, data, 0)?;
        let status: Status = reply.read()?;
        if !status.is_ok() {
            return Err(status);
        }
        Ok(reply.read()?)
    }

    pub fn get_interface<T: FromIBinder + ?Sized>(&self, name: &str) -> crate::Result<Strong<T>> {
        Ok(FromIBinder::try_from(self.get_service(name)?)?)
    }
}
