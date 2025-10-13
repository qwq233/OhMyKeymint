pub mod IPackageManager {
    #![allow(non_upper_case_globals, non_snake_case, dead_code)]
    pub trait IPackageManager: rsbinder::Interface + Send {
        fn descriptor() -> &'static str
        where
            Self: Sized,
        {
            "android.content.pm.IPackageManager"
        }
        fn r#getPackagesForUid(&self, _arg_uid: i32) -> rsbinder::status::Result<Vec<String>>;
        fn getDefaultImpl() -> Option<IPackageManagerDefaultRef>
        where
            Self: Sized,
        {
            DEFAULT_IMPL.get().cloned()
        }
        fn setDefaultImpl(d: IPackageManagerDefaultRef) -> IPackageManagerDefaultRef
        where
            Self: Sized,
        {
            DEFAULT_IMPL.get_or_init(|| d).clone()
        }
    }
    pub trait IPackageManagerAsync<P>: rsbinder::Interface + Send {
        fn descriptor() -> &'static str
        where
            Self: Sized,
        {
            "android.content.pm.IPackageManager"
        }
        fn r#getPackagesForUid<'a>(
            &'a self,
            _arg_uid: i32,
        ) -> rsbinder::BoxFuture<'a, rsbinder::status::Result<Vec<String>>>;
    }
    #[::async_trait::async_trait]
    pub trait IPackageManagerAsyncService: rsbinder::Interface + Send {
        fn descriptor() -> &'static str
        where
            Self: Sized,
        {
            "android.content.pm.IPackageManager"
        }
        async fn r#getPackagesForUid(&self, _arg_uid: i32)
            -> rsbinder::status::Result<Vec<String>>;
    }
    impl BnPackageManager {
        pub fn new_async_binder<T, R>(inner: T, rt: R) -> rsbinder::Strong<dyn IPackageManager>
        where
            T: IPackageManagerAsyncService + Sync + Send + 'static,
            R: rsbinder::BinderAsyncRuntime + Send + Sync + 'static,
        {
            struct Wrapper<T, R> {
                _inner: T,
                _rt: R,
            }
            impl<T, R> rsbinder::Interface for Wrapper<T, R>
            where
                T: rsbinder::Interface,
                R: Send + Sync,
            {
                fn as_binder(&self) -> rsbinder::SIBinder {
                    self._inner.as_binder()
                }
                fn dump(
                    &self,
                    _writer: &mut dyn std::io::Write,
                    _args: &[String],
                ) -> rsbinder::Result<()> {
                    self._inner.dump(_writer, _args)
                }
            }
            impl<T, R> BnPackageManagerAdapter for Wrapper<T, R>
            where
                T: IPackageManagerAsyncService + Sync + Send + 'static,
                R: rsbinder::BinderAsyncRuntime + Send + Sync + 'static,
            {
                fn as_sync(&self) -> &dyn IPackageManager {
                    self
                }
                fn as_async(&self) -> &dyn IPackageManagerAsyncService {
                    &self._inner
                }
            }
            impl<T, R> IPackageManager for Wrapper<T, R>
            where
                T: IPackageManagerAsyncService + Sync + Send + 'static,
                R: rsbinder::BinderAsyncRuntime + Send + Sync + 'static,
            {
                fn r#getPackagesForUid(
                    &self,
                    _arg_uid: i32,
                ) -> rsbinder::status::Result<Vec<String>> {
                    self._rt.block_on(self._inner.r#getPackagesForUid(_arg_uid))
                }
            }
            let wrapped = Wrapper {
                _inner: inner,
                _rt: rt,
            };
            let binder = rsbinder::native::Binder::new_with_stability(
                BnPackageManager(Box::new(wrapped)),
                rsbinder::Stability::default(),
            );
            rsbinder::Strong::new(Box::new(binder))
        }
    }
    pub trait IPackageManagerDefault: Send + Sync {
        fn r#getPackagesForUid(&self, _arg_uid: i32) -> rsbinder::status::Result<Vec<String>> {
            Err(rsbinder::StatusCode::UnknownTransaction.into())
        }
    }
    pub(crate) mod transactions {
        pub(crate) const r#getPackagesForUid: rsbinder::TransactionCode =
            rsbinder::FIRST_CALL_TRANSACTION + 0;
    }
    pub type IPackageManagerDefaultRef = std::sync::Arc<dyn IPackageManagerDefault>;
    static DEFAULT_IMPL: std::sync::OnceLock<IPackageManagerDefaultRef> =
        std::sync::OnceLock::new();
    rsbinder::declare_binder_interface! {
        IPackageManager["android.content.pm.IPackageManager"] {
            native: {
                BnPackageManager(on_transact),
                adapter: BnPackageManagerAdapter,
                r#async: IPackageManagerAsyncService,
            },
            proxy: BpPackageManager,
            r#async: IPackageManagerAsync,
        }
    }
    impl BpPackageManager {
        fn build_parcel_getPackagesForUid(
            &self,
            _arg_uid: i32,
        ) -> rsbinder::Result<rsbinder::Parcel> {
            let mut data = self.binder.as_proxy().unwrap().prepare_transact(true)?;
            data.write(&_arg_uid)?;
            Ok(data)
        }
        fn read_response_getPackagesForUid(
            &self,
            _arg_uid: i32,
            _aidl_reply: rsbinder::Result<Option<rsbinder::Parcel>>,
        ) -> rsbinder::status::Result<Vec<String>> {
            if let Err(rsbinder::StatusCode::UnknownTransaction) = _aidl_reply {
                if let Some(_aidl_default_impl) = <Self as IPackageManager>::getDefaultImpl() {
                    return _aidl_default_impl.r#getPackagesForUid(_arg_uid);
                }
            }
            let mut _aidl_reply = _aidl_reply?.ok_or(rsbinder::StatusCode::UnexpectedNull)?;
            let _status = _aidl_reply.read::<rsbinder::Status>()?;
            if !_status.is_ok() {
                return Err(_status);
            }
            let _aidl_return: Vec<String> = _aidl_reply.read()?;
            Ok(_aidl_return)
        }
    }
    impl IPackageManager for BpPackageManager {
        fn r#getPackagesForUid(&self, _arg_uid: i32) -> rsbinder::status::Result<Vec<String>> {
            let _aidl_data = self.build_parcel_getPackagesForUid(_arg_uid)?;
            let _aidl_reply = self.binder.as_proxy().unwrap().submit_transact(
                transactions::r#getPackagesForUid,
                &_aidl_data,
                rsbinder::FLAG_CLEAR_BUF,
            );
            self.read_response_getPackagesForUid(_arg_uid, _aidl_reply)
        }
    }
    impl<P: rsbinder::BinderAsyncPool> IPackageManagerAsync<P> for BpPackageManager {
        fn r#getPackagesForUid<'a>(
            &'a self,
            _arg_uid: i32,
        ) -> rsbinder::BoxFuture<'a, rsbinder::status::Result<Vec<String>>> {
            let _aidl_data = match self.build_parcel_getPackagesForUid(_arg_uid) {
                Ok(_aidl_data) => _aidl_data,
                Err(err) => return Box::pin(std::future::ready(Err(err.into()))),
            };
            let binder = self.binder.clone();
            P::spawn(
                move || {
                    binder.as_proxy().unwrap().submit_transact(
                        transactions::r#getPackagesForUid,
                        &_aidl_data,
                        rsbinder::FLAG_CLEAR_BUF | rsbinder::FLAG_PRIVATE_LOCAL,
                    )
                },
                move |_aidl_reply| async move {
                    self.read_response_getPackagesForUid(_arg_uid, _aidl_reply)
                },
            )
        }
    }
    impl<P: rsbinder::BinderAsyncPool> IPackageManagerAsync<P> for rsbinder::Binder<BnPackageManager> {
        fn r#getPackagesForUid<'a>(
            &'a self,
            _arg_uid: i32,
        ) -> rsbinder::BoxFuture<'a, rsbinder::status::Result<Vec<String>>> {
            self.0.as_async().r#getPackagesForUid(_arg_uid)
        }
    }
    impl IPackageManager for rsbinder::Binder<BnPackageManager> {
        fn r#getPackagesForUid(&self, _arg_uid: i32) -> rsbinder::status::Result<Vec<String>> {
            self.0.as_sync().r#getPackagesForUid(_arg_uid)
        }
    }
    fn on_transact(
        _service: &dyn IPackageManager,
        _code: rsbinder::TransactionCode,
        _reader: &mut rsbinder::Parcel,
        _reply: &mut rsbinder::Parcel,
    ) -> rsbinder::Result<()> {
        match _code {
            transactions::r#getPackagesForUid => {
                let _arg_uid: i32 = _reader.read()?;
                let _aidl_return = _service.r#getPackagesForUid(_arg_uid);
                match &_aidl_return {
                    Ok(_aidl_return) => {
                        _reply.write(&rsbinder::Status::from(rsbinder::StatusCode::Ok))?;
                        _reply.write(_aidl_return)?;
                    }
                    Err(_aidl_status) => {
                        _reply.write(_aidl_status)?;
                    }
                }
                Ok(())
            }
            _ => Err(rsbinder::StatusCode::UnknownTransaction),
        }
    }
}
