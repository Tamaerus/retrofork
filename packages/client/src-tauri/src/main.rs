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

// Import dotenvy for environment variable loading
use dotenvy;

// Ensure all plugins are imported
use retrom_plugin_steam;
use retrom_plugin_launcher;
use tauri_plugin_fs;
use retrom_plugin_config;
use retrom_plugin_standalone;
use retrom_plugin_installer;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}!! You've been greeted from Rust!", name)
}

#[tauri::command(async)]
async fn fetch_onion_url(url: String) -> Result<String, String> {
    // Log that the command was invoked
    info!("Attempting to fetch onion URL: {}", url);

    // Validate the URL to ensure it ends with .onion (basic check)
    if !url.ends_with(".onion") {
        let err_msg = "Invalid URL: Must be a .onion address".to_string();
        error!("{}", err_msg);
        return Err(err_msg);
    }
    info!("Setting up Tor proxy client for socks5://localhost:9050");
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnector::new_with_connector(http);
    let proxy = Proxy::new(Intercept::All, "socks5h://127.0.0.1:9050".parse().unwrap());
    let proxy_connector = ProxyConnector::from_proxy(https, proxy).expect("Failed to create proxy connector");
    let client = Client::builder().build::<_, hyper::Body>(proxy_connector);
    info!("Tor SOCKS5 client setup complete");

    // Build the request for the .onion URL
    // Hyper expects a valid URI, so we must use http:// or https:// with the .onion host
    let onion_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.clone()
    } else {
        format!("http://{}", url)
    };
    info!("Building GET request for {}", onion_url);
    let request = match Request::builder()
        .method("GET")
        .uri(&onion_url)
        .body(Body::empty())
    {
        Ok(req) => {
            info!("Request built successfully");
            req
        }
        Err(e) => {
            let err_msg = format!("Failed to build request: {}", e);
            error!("{}", err_msg);
            return Err(err_msg);
        }
    };

    // Send the request through the Tor proxy
    info!("Sending request to {}", url);
    let response = match client.request(request).await {
        Ok(resp) => {
            info!("Received response with status: {}", resp.status());
            resp
        }
        Err(e) => {
            let err_msg = format!("Request failed: {}", e);
            error!("{}", err_msg);
            return Err(err_msg);
        }
    };

    // Check if the response status is successful
    let status = response.status();
    if !status.is_success() {
        let err_msg = format!("Request failed with status: {}", status);
        error!("{}", err_msg);
        return Err(err_msg);
    }

    // Read the response body as text
    info!("Reading response body");
    let body_bytes = match hyper::body::to_bytes(response.into_body()).await {
        Ok(bytes) => {
            info!("Response body read successfully ({} bytes)", bytes.len());
            bytes
        }
        Err(e) => {
            let err_msg = format!("Failed to read response body: {}", e);
            error!("{}", err_msg);
            return Err(err_msg);
        }
    };

    let body_text = match std::str::from_utf8(&body_bytes) {
        Ok(text) => {
            info!("Response body decoded as UTF-8 successfully");
            text.to_string()
        }
        Err(e) => {
            let err_msg = format!("Failed to decode response as UTF-8: {}", e);
            error!("{}", err_msg);
            return Err(err_msg);
        }
    };

    Ok(body_text)
}

#[tokio::main]
pub async fn main() {
    dotenvy::dotenv().ok();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,".into())
        .add_directive("app=warn".parse().unwrap());

    let fmt_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .without_time()
        .with_target(false)
        .with_ansi(true);

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    tauri::async_runtime::set(tokio::runtime::Handle::current());

    tauri::Builder::default()
        .setup(|app| {
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

            registry.with(file_layer).init();

            // Window state plugin is registered outside setup via .plugin(), so nothing to do here.

            let app_handle_ctrlc = app.handle().clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to listen for ctrl-c");

                app_handle_ctrlc.exit(0);
            });

            // Await and register the async launcher plugin
            let app_handle = app.handle();
            tauri::async_runtime::block_on(async {
                let launcher_plugin = retrom_plugin_launcher::init().await;
                app_handle.plugin(launcher_plugin);
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
        .invoke_handler(tauri::generate_handler![greet, fetch_onion_url]) // Add our command here
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
