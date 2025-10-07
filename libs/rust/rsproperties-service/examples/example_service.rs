use std::fs::{create_dir_all, remove_dir_all};
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "example_service")]
#[command(about = "Example service for rsproperties-service")]
struct Args {
    /// Properties directory path
    #[arg(long, help = "Directory path for system properties")]
    properties_dir: Option<PathBuf>,

    /// Socket directory path
    #[arg(long, help = "Directory path for property service sockets")]
    socket_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Setup directories
    let properties_dir = args
        .properties_dir
        .unwrap_or_else(|| PathBuf::from("__properties__"));
    let socket_dir = args
        .socket_dir
        .unwrap_or_else(|| properties_dir.join("sockets"));

    // Clean and create directories
    let _ = remove_dir_all(&properties_dir);
    let _ = remove_dir_all(&socket_dir);
    create_dir_all(&properties_dir)?;
    create_dir_all(&socket_dir)?;

    println!("📁 Created directories:");
    println!("   Properties: {properties_dir:?}");
    println!("   Sockets: {socket_dir:?}");

    // Create PropertyConfig
    let config = rsproperties::PropertyConfig::with_both_dirs(properties_dir, socket_dir);

    println!("🚀 Starting rsproperties services...");

    // Initialize the services
    let (socket_service, properties_service) = rsproperties_service::run(
        config,
        vec![], // property_contexts_files
        vec![], // build_prop_files
    )
    .await?;

    println!("✅ Services started successfully!");
    println!("🔄 Services are running. Press Ctrl+C to stop.");

    // Handle graceful shutdown
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n🛑 Shutdown signal received...");
        }
        result1 = socket_service.join_handle => {
            if let Err(e) = result1 {
                eprintln!("❌ Socket service error: {e}");
            }
        }
        result2 = properties_service.join_handle => {
            if let Err(e) = result2 {
                eprintln!("❌ Properties service error: {e}");
            }
        }
    }

    println!("👋 Services stopped.");
    Ok(())
}
