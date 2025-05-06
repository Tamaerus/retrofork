// retrofork/packages/client/src-tauri/src/main.rs
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{fs::OpenOptions, str};
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tauri::command;
use hyper::{Body, Client, Request};
use hyper::client::HttpConnector;
use hyper_proxy::{Proxy, ProxyConnector, Intercept};
use hyper_tls::HttpsConnector;
use tracing::{info, error};
use arti_client::{TorClient, TorClientConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tauri::State;
use tokio::sync::Mutex;

// Import the correct runtime type for TorClient
use tor_rtcompat::PreferredRuntime;

// Import dotenvy for environment variable loading
use dotenvy;

// Ensure all plugins are imported
use retrom_plugin_steam;
use retrom_plugin_launcher;
use tauri_plugin_fs;
use retrom_plugin_config;
use retrom_plugin_standalone;
use retrom_plugin_installer;
use tauri_plugin_updater;
use tauri_plugin_single_instance;
use tauri_plugin_opener;
use tauri_plugin_shell;
use tauri_plugin_system_info;
use tauri_plugin_dialog;
use tauri_plugin_process;
use tauri_plugin_window_state;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}!! You've been greeted from Rust!", name)
}

// Shared state for TorClient to avoid creating multiple instances
// Specify the runtime type for TorClient using PreferredRuntime from tor_rtcompat
type TorClientState = Mutex<Option<Arc<TorClient<PreferredRuntime>>>>;

#[tauri::command(async)]
async fn fetch_onion_url(url: String, state: State<'_, TorClientState>) -> Result<String, String> {
    // Log that the command was invoked with the exact URL
    info!("Attempting to fetch onion URL: {}", url);

    // Basic validation: just check if it contains ".onion"
    if !url.contains(".onion") {
        let err_msg = "Invalid URL: Must contain a .onion address".to_string();
        error!("{}", err_msg);
        return Err(err_msg);
    }

    // Get or initialize the Tor client from shared state
    let tor_client = {
        let mut guard = state.lock().await; // Use async lock
        if let Some(client) = guard.as_ref() {
            info!("Reusing existing Tor client");
            client.clone()
        } else {
            info!("Setting up Arti (Tor) client directly");
            let config = TorClientConfig::default();
            match TorClient::create_bootstrapped(config).await {
                Ok(client) => {
                    info!("Tor client bootstrapped successfully");
                    let client_arc = Arc::new(client);
                    *guard = Some(client_arc.clone());
                    client_arc
                }
                Err(e) => {
                    let err_msg = format!("Failed to bootstrap Tor client: {}", e);
                    error!("{}", err_msg);
                    return Err(err_msg);
                }
            }
        }
    };

    // Extract host (the .onion part) for Tor connection
    let host = url
        .split('/')
        .find(|part| part.ends_with(".onion"))
        .map(|part| part.to_string())
        .ok_or_else(|| {
            let err_msg = "Failed to extract .onion host from URL".to_string();
            error!("{}", err_msg);
            err_msg
        })?;
    info!("Connecting to onion host: {}", host);

    // Connect to the onion service (assuming port 80 for HTTP)
    let mut stream = match tor_client.connect(format!("{}:80", host)).await {
        Ok(stream) => {
            info!("Connected to onion service successfully");
            stream
        }
        Err(e) => {
            let err_msg = format!("Failed to connect to onion service: {}", e);
            error!("{}", err_msg);
            return Err(err_msg);
        }
    };

    // Build a simple HTTP GET request, preserving the full path
    let request_path = if url.contains(&host) {
        url.split_once(&host).map(|(_, path)| path).unwrap_or("")
    } else {
        ""
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        if request_path.is_empty() { "/" } else { request_path },
        host
    );
    info!("Sending request with path: {}", if request_path.is_empty() { "/" } else { request_path });

    // Write the request to the stream using async I/O
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        let err_msg = format!("Failed to send request: {}", e);
        error!("{}", err_msg);
        return Err(err_msg);
    }
    if let Err(e) = stream.flush().await {
        let err_msg = format!("Failed to flush request: {}", e);
        error!("{}", err_msg);
        return Err(err_msg);
    }

    // Read the response
    let mut response = String::new();
    let mut buffer = [0; 4096];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                info!("Received complete response from onion service");
                break;
            }
            Ok(n) => {
                let chunk = match std::str::from_utf8(&buffer[..n]) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        let err_msg = format!("Failed to decode response chunk as UTF-8: {}", e);
                        error!("{}", err_msg);
                        return Err(err_msg);
                    }
                };
                response.push_str(&chunk);
            }
            Err(e) => {
                let err_msg = format!("Failed to read response: {}", e);
                error!("{}", err_msg);
                return Err(err_msg);
            }
        }
    }

    info!("Response received ({} bytes)", response.len());
    Ok(response)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // We'll delay full tracing initialization until we have the log directory in setup
    // For now, do minimal initialization or none at all
    // Avoid moving layers prematurely

    tauri::Builder::default()
        .manage(Mutex::new(None::<Arc<TorClient<PreferredRuntime>>>) as TorClientState) // Initialize empty TorClient state
        .setup(|app| {
            // Define env_filter and fmt_layer inside setup to avoid move issues
            let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,".into())
                .add_directive("app=warn".parse().unwrap());

            let fmt_layer = tracing_subscriber::fmt::layer()
                .pretty()
                .without_time()
                .with_target(false)
                .with_ansi(true);

            let log_dir = app.path().app_log_dir().expect("failed to get log dir");
            if !log_dir.exists() {
                std::fs::create_dir_all(&log_dir).unwrap();
            }
            let log_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(log_dir.join("retrom.log"))
                .expect("failed to open log file");

            let file_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(log_file);

            // Initialize tracing with all layers at once inside setup
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(file_layer)
                .init();

            let app_handle_ctrlc = app.handle().clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to listen for ctrl-c");

                app_handle_ctrlc.exit(0);
            });

            // Handle async initialization of launcher plugin without blocking
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                println!("Initializing launcher plugin asynchronously...");
                let launcher_plugin = retrom_plugin_launcher::init().await;
                if let Err(e) = app_handle.plugin(launcher_plugin) {
                    eprintln!("Failed to register launcher plugin: {}", e);
                } else {
                    println!("Launcher plugin registered successfully after async init");
                }
            });

            Ok(())
        })
        .plugin(retrom_plugin_config::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(retrom_plugin_standalone::init())
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if !cfg!(dev) {
                app.webview_windows()
                    .values()
                    .next()
                    .expect("no window found")
                    .set_focus()
                    .expect("failed to set focus");
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_system_info::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(retrom_plugin_steam::init())
        .plugin(retrom_plugin_installer::init())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .invoke_handler(tauri::generate_handler![greet, fetch_onion_url])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
