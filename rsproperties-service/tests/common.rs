use std::fs::{create_dir_all, remove_dir_all};
use std::{path::PathBuf, str::FromStr};

use tokio::sync::OnceCell;

use rsproperties::PropertyConfig;

use rsproperties_service::{PropertiesService, ServiceContext, SocketService};

use rsactor::ActorRef;

pub static TEST_PROPERTIES_DIR: &str = "__properties__";

static SERVICES: OnceCell<(ActorRef<SocketService>, ActorRef<PropertiesService>)> =
    OnceCell::const_new();

async fn inti() -> (
    ServiceContext<SocketService>,
    ServiceContext<PropertiesService>,
) {
    let _ = env_logger::builder().is_test(true).try_init();

    let properties_dir =
        PathBuf::from_str(TEST_PROPERTIES_DIR).expect("Failed to parse properties directory path");
    let socket_dir = properties_dir.join("sockets");

    remove_dir_all(&properties_dir).unwrap_or_default();
    remove_dir_all(&socket_dir).unwrap_or_default();
    create_dir_all(&properties_dir).expect("Failed to create properties directory");
    create_dir_all(&socket_dir).expect("Failed to create socket directory");

    let config = PropertyConfig::with_both_dirs(properties_dir, socket_dir);

    rsproperties_service::run(config, vec![], vec![])
        .await
        .expect("Failed to start services")
}

pub async fn init_test() -> (ActorRef<SocketService>, ActorRef<PropertiesService>) {
    SERVICES
        .get_or_init(|| async {
            let (sender, receiver) = tokio::sync::oneshot::channel::<(
                ActorRef<SocketService>,
                ActorRef<PropertiesService>,
            )>();

            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create Tokio runtime");

                runtime.block_on(async {
                    let services = inti().await;
                    let _ =
                        sender.send((services.0.actor_ref.clone(), services.1.actor_ref.clone()));

                    let (res1, res2) =
                        tokio::join!(services.0.join_handle, services.1.join_handle,);
                    // Handle potential errors from join handles
                    if let Err(e) = res1 {
                        eprintln!("Socket service error: {e}");
                    }
                    if let Err(e) = res2 {
                        eprintln!("Properties service error: {e}");
                    }
                });
            });

            receiver.await.expect("Failed to receive services")
        })
        .await
        .clone()
}
