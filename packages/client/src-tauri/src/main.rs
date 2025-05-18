// retrofork/packages/client/src-tauri/src/main.rs
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{fs::OpenOptions, str};
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
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
use sysinfo::{System, Pid, Disks, Networks, Process};
use std::ffi::OsStr;
use std::borrow::Cow;
use serde_json::json;
use tauri::command;
use tor_rtcompat::PreferredRuntime;
use dotenvy;
use nvml_wrapper;
use network_interface::NetworkInterfaceConfig;
use ping_rs;
use port_check;
use cpal::traits::{HostTrait, DeviceTrait};
use battery;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::Emitter;
use serde::{Serialize, Deserialize};
use std::process::Command;


//plugins
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

// Add this struct definition near the top of the file, after imports, around line 50 or before `greet` function
#[derive(serde::Serialize, Debug)]
struct OsInfo {
    name: String,
    version: String,
    host_name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct BiosInfo {
    vendor: String,
    version: String,
    release_date: String,
    status: String,
    message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct UsbInfo {
    devices: Vec<UsbDevice>,
    status: String,
    message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct UsbDevice {
    name: String,
    device_id: String,
    manufacturer: String,
}

// Add EventLogInfo struct near other struct definitions (e.g., after UsbInfo)
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct EventLogInfo {
    events: Vec<EventEntry>,
    status: String,
    message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct EventEntry {
    time_created: String,
    event_id: String,
    level: String,
    source: String,
    message: String,
}

// Add DiskHealthInfo struct near other struct definitions (e.g., after EventLogInfo)
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct DiskHealthInfo {
    disks: Vec<DiskHealthEntry>,
    status: String,
    message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct DiskHealthEntry {
    device_id: String,
    model: String,
    serial_number: String,
    operational_status: String,
    health_status: String,
    size_bytes: u64,
}

// Add NetworkAdapterInfo struct near other struct definitions (e.g., after DiskHealthInfo)
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct NetworkAdapterInfo {
    adapters: Vec<NetworkAdapterEntry>,
    status: String,
    message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct NetworkAdapterEntry {
    name: String,
    interface_description: String,
    status: String,
    mac_address: String,
    link_speed_mbps: u64,
}

// Add SystemUptimeInfo struct near other struct definitions (e.g., after NetworkAdapterInfo)
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct SystemUptimeInfo {
    boot_time: String,
    uptime_seconds: u64,
    status: String,
    message: String,
}

// Add this function near the top of the file, after the structs
fn start_system_monitoring(app_handle: tauri::AppHandle, stop_rx: Receiver<bool>) {
    // Spawn the monitoring thread
    thread::spawn(move || {
        let mut sys = sysinfo::System::new_all();
        let mut networks = Networks::new_with_refreshed_list();
        let mut disks = Disks::new_with_refreshed_list();
        let mut disk_refresh_counter = 0; // Counter to track time for disk refresh (every 60s)
        let mut battery_refresh_counter = 0; // Counter to track time for battery refresh (every 60s)
        let mut network_adapter_counter = 0; // Counter to track time for network adapter refresh (every 60s)
        let mut event_log_counter = 0; // Counter to track time for event log refresh (every 60s)
        let mut last_event_timestamp: Option<String> = None; // Track the timestamp of the last processed event
        let mut ports_refresh_counter = 0; // Counter to track time for listening ports refresh (every 60s)
        let mut video_refresh_counter = 0; // Counter to track time for video diagnostics refresh (every 60s)

        loop {
            // Check for stop signal from the channel (non-blocking)
            if let Ok(should_stop) = stop_rx.try_recv() {
                if should_stop {
                    println!("System monitoring thread stopped by shutdown signal.");
                    break;
                }
            }
            // Refresh system metrics
            sys.refresh_cpu();
            sys.refresh_memory();
            networks.refresh();
            // CPU and Memory stats
            let cpu_usage = sys.global_cpu_info().cpu_usage();
            let total_memory = sys.total_memory();
            let used_memory = sys.used_memory();
            let memory_usage_percent = if total_memory > 0 {
                (used_memory as f64 / total_memory as f64) * 100.0
            } else {
                0.0
            };
            println!("CPU Usage Update: {}%", cpu_usage);
            println!("Memory Usage Update: {}% (Used: {} KB / Total: {} KB)", memory_usage_percent, used_memory, total_memory);
            // Network stats (total across all interfaces)
            let mut total_received = 0;
            let mut total_transmitted = 0;
            for (_, data) in networks.iter() {
                total_received += data.total_received();
                total_transmitted += data.total_transmitted();
            }
            println!("Network Activity Update: Received {} bytes, Transmitted {} bytes", total_received, total_transmitted);
            // Disk stats (total across all disks, refreshed every 60 seconds)
            disk_refresh_counter += 5; // Increment by 5 seconds each loop
            if disk_refresh_counter >= 60 {
                disks.refresh();
                let mut total_disk_space = 0;
                let mut available_disk_space = 0;
                for disk in disks.iter() {
                    total_disk_space += disk.total_space();
                    available_disk_space += disk.available_space();
                }
                let used_disk_space = total_disk_space - available_disk_space;
                let disk_usage_percent = if total_disk_space > 0 {
                    (used_disk_space as f64 / total_disk_space as f64) * 100.0
                } else {
                    0.0
                };
                println!("Disk Usage Update: {}% (Used: {} KB / Total: {} KB)", disk_usage_percent, used_disk_space, total_disk_space);
                disk_refresh_counter = 0; // Reset counter after update
            }
            // Battery stats (refreshed every 60 seconds)
            battery_refresh_counter += 5; // Increment by 5 seconds each loop
            if battery_refresh_counter >= 60 {
                if let Ok(manager) = battery::Manager::new() {
                    if let Ok(batteries) = manager.batteries() {
                        for (index, battery_result) in batteries.enumerate() {
                            if let Ok(battery) = battery_result {
                                let charge_percent = battery.state_of_charge().value * 100.0;
                                let state = format!("{:?}", battery.state());
                                println!("Battery {} Update: Charge {}%, State: {}", index, charge_percent, state);
                            }
                        }
                    }
                }
                battery_refresh_counter = 0; // Reset counter after update
            }
            // Network adapter stats (refreshed every 60 seconds)
            network_adapter_counter += 5; // Increment by 5 seconds each loop
            if network_adapter_counter >= 600 {
                #[cfg(target_os = "windows")]
                {
                    let command = r#"Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | ConvertTo-Json"#;
                    match std::process::Command::new("powershell")
                        .args(&["-Command", command])
                        .output()
                    {
                        Ok(output) => {
                            if output.status.success() {
                                let output_str = String::from_utf8_lossy(&output.stdout);
                                println!("Network Adapter Status Update: {}", output_str);
                            } else {
                                println!("Network Adapter Status Update: Failed to retrieve data");
                            }
                        }
                        Err(_) => {
                            println!("Network Adapter Status Update: Error executing PowerShell command");
                        }
                    }
                }
                network_adapter_counter = 0; // Reset counter after update
            }

// Event log stats (refreshed every 60 seconds for hardware/driver changes)
            event_log_counter += 5; // Increment by 5 seconds each loop
            if event_log_counter >= 300 {
                #[cfg(target_os = "windows")]
                {
                    let command = r#"Get-EventLog -LogName System -Newest 1 -ErrorAction SilentlyContinue | Where-Object { $_.EventID -in (566, 105, 7021, 7040, 1, 130) } | Select-Object TimeWritten, EventID, Source, Message | ConvertTo-Json"#;
                    match std::process::Command::new("powershell")
                        .args(&["-Command", command])
                        .output()
                    {
                        Ok(output) => {
                            if output.status.success() {
                                let output_str = String::from_utf8_lossy(&output.stdout);
                                if !output_str.is_empty() {
                                    // Attempt to parse JSON to check timestamp and display formatted output
                                    match serde_json::from_str::<serde_json::Value>(&output_str) {
                                        Ok(json_data) => {
                                            if let Some(event) = json_data.as_object() {
                                                if let Some(time_written) = event.get("TimeWritten").and_then(|v| v.as_str()) {
                                                    if let Some(last_time) = &last_event_timestamp {
                                                        if time_written != last_time {
                                                            if let Some(event_id) = event.get("EventID").and_then(|v| v.as_i64()) {
                                                                if let Some(source) = event.get("Source").and_then(|v| v.as_str()) {
                                                                    let message = event.get("Message").and_then(|v| v.as_str()).unwrap_or("Message not available");
                                                                    println!("Event Log Update (New Hardware/Driver Event):");
                                                                    println!("  Time: {}", time_written);
                                                                    println!("  Event ID: {}", event_id);
                                                                    println!("  Source: {}", source);
                                                                    println!("  Message: {}", message);
                                                                    last_event_timestamp = Some(time_written.to_string());
                                                                } else {
                                                                    println!("Event Log Update: Failed to parse event source.");
                                                                }
                                                            } else {
                                                                println!("Event Log Update: Failed to parse event ID.");
                                                            }
                                                        } else {
                                                            println!("Event Log Update: No new hardware/driver events since last check.");
                                                        }
                                                    } else {
                                                        if let Some(event_id) = event.get("EventID").and_then(|v| v.as_i64()) {
                                                            if let Some(source) = event.get("Source").and_then(|v| v.as_str()) {
                                                                let message = event.get("Message").and_then(|v| v.as_str()).unwrap_or("Message not available");
                                                                println!("Event Log Update (Hardware/Driver Event):");
                                                                println!("  Time: {}", time_written);
                                                                println!("  Event ID: {}", event_id);
                                                                println!("  Source: {}", source);
                                                                println!("  Message: {}", message);
                                                                last_event_timestamp = Some(time_written.to_string());
                                                            } else {
                                                                println!("Event Log Update: Failed to parse event source.");
                                                            }
                                                        } else {
                                                            println!("Event Log Update: Failed to parse event ID.");
                                                        }
                                                    }
                                                } else {
                                                    println!("Event Log Update: Failed to parse event timestamp.");
                                                }
                                            } else if let Some(events) = json_data.as_array() {
                                                if let Some(event) = events.first() {
                                                    if let Some(time_written) = event.get("TimeWritten").and_then(|v| v.as_str()) {
                                                        if let Some(last_time) = &last_event_timestamp {
                                                            if time_written != last_time {
                                                                if let Some(event_id) = event.get("EventID").and_then(|v| v.as_i64()) {
                                                                    if let Some(source) = event.get("Source").and_then(|v| v.as_str()) {
                                                                        let message = event.get("Message").and_then(|v| v.as_str()).unwrap_or("Message not available");
                                                                        println!("Event Log Update (New Hardware/Driver Event):");
                                                                        println!("  Time: {}", time_written);
                                                                        println!("  Event ID: {}", event_id);
                                                                        println!("  Source: {}", source);
                                                                        println!("  Message: {}", message);
                                                                        last_event_timestamp = Some(time_written.to_string());
                                                                    } else {
                                                                        println!("Event Log Update: Failed to parse event source.");
                                                                    }
                                                                } else {
                                                                    println!("Event Log Update: Failed to parse event ID.");
                                                                }
                                                            } else {
                                                                println!("Event Log Update: No new hardware/driver events since last check.");
                                                            }
                                                        } else {
                                                            if let Some(event_id) = event.get("EventID").and_then(|v| v.as_i64()) {
                                                                if let Some(source) = event.get("Source").and_then(|v| v.as_str()) {
                                                                    let message = event.get("Message").and_then(|v| v.as_str()).unwrap_or("Message not available");
                                                                    println!("Event Log Update (Hardware/Driver Event):");
                                                                    println!("  Time: {}", time_written);
                                                                    println!("  Event ID: {}", event_id);
                                                                    println!("  Source: {}", source);
                                                                    println!("  Message: {}", message);
                                                                    last_event_timestamp = Some(time_written.to_string());
                                                                } else {
                                                                    println!("Event Log Update: Failed to parse event source.");
                                                                }
                                                            } else {
                                                                println!("Event Log Update: Failed to parse event ID.");
                                                            }
                                                        }
                                                    } else {
                                                        println!("Event Log Update: Failed to parse event timestamp.");
                                                    }
                                                } else {
                                                    println!("Event Log Update: No recent hardware/driver events found.");
                                                }
                                            } else {
                                                println!("Event Log Update: Failed to parse event data structure.");
                                            }
                                        }
                                        Err(_) => {
                                            println!("Event Log Update: Failed to parse JSON output.");
                                        }
                                    }
                                } else {
                                    println!("Event Log Update: No recent hardware/driver events found.");
                                }
                            } else {
                                let error_str = String::from_utf8_lossy(&output.stderr);
                                println!("Event Log Update: Failed to retrieve data, error: {}", error_str);
                            }
                        }
                        Err(e) => {
                            println!("Event Log Update: Error executing PowerShell command: {}", e);
                        }
                    }
                }
                event_log_counter = 0; // Reset counter after update
            }
            // Listening ports stats (refreshed every 60 seconds)
            ports_refresh_counter += 5; // Increment by 5 seconds each loop
            if ports_refresh_counter >= 600 {
                let listening_ports_info = get_listening_ports();
                println!("Listening Ports Update: {:?}", listening_ports_info);
                ports_refresh_counter = 0; // Reset counter after update
            }
            // Video diagnostics stats (refreshed every 60 seconds)
            video_refresh_counter += 5; // Increment by 5 seconds each loop
            if video_refresh_counter >= 300 {
                let video_diagnostics_info = get_video_diagnostics();
                println!("Video Diagnostics Update: {:?}", video_diagnostics_info);
                video_refresh_counter = 0; // Reset counter after update
            }

            // Sleep for 5 seconds before next update
            thread::sleep(Duration::from_secs(5));
        }
    });
}


//greeting
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}!! You've been greeted from Rust!", name)
}

type TorClientState = Mutex<Option<Arc<TorClient<PreferredRuntime>>>>;

#[tauri::command(async)]
async fn fetch_onion_url(
    url: String,
    method: Option<String>, // New: HTTP method, defaults to GET
    headers: Option<Vec<(String, String)>>, // New: Optional custom headers as Vec of (key, value) pairs
    body: Option<String>, // New: Optional request body for POST or other methods
    state: State<'_, TorClientState>
) -> Result<String, String> {
    info!("Attempting to fetch onion URL: {}", url);
    if !url.contains(".onion") {
        let err_msg = "Invalid URL: Must contain a .onion address".to_string();
        error!("{}", err_msg);
        return Err(err_msg);
    }
    let tor_client = {
        let mut guard = state.lock().await;
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
    let request_path = if url.contains(&host) {
        url.split_once(&host).map(|(_, path)| path).unwrap_or("")
    } else {
        ""
    };
    // Use provided method or default to GET
    let http_method = method.unwrap_or_else(|| "GET".to_string()).to_uppercase();
    info!("Using HTTP method: {}", http_method);
    
    // Start building the request with method and path
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        http_method,
        if request_path.is_empty() { "/" } else { request_path },
        host
    );
    
    // Add custom headers if provided
    if let Some(header_pairs) = headers {
        for (key, value) in header_pairs {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
    }
    
    // If there's a body (e.g., for POST), add Content-Length header
    if let Some(body_content) = &body {
        if !http_method.eq("GET") && !http_method.eq("HEAD") {
            request.push_str(&format!("Content-Length: {}\r\n", body_content.len()));
        }
    }
    
    // End headers section
    request.push_str("\r\n");
    
    // Append body if provided and method supports it
    if let Some(body_content) = body {
        if !http_method.eq("GET") && !http_method.eq("HEAD") {
            request.push_str(&body_content);
        }
    }
    
    info!("Sending request with path: {}", if request_path.is_empty() { "/" } else { request_path });
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

// Add this new command below the existing `fetch_onion_url` function in your main.rs
#[tauri::command(async)]
async fn get_tor_status(state: State<'_, TorClientState>) -> Result<serde_json::Value, String> {
    info!("Checking Tor connection status");
    let guard = state.lock().await;
    let status = if guard.is_some() {
        json!({
            "status": "connected",
            "message": "Tor client is initialized and ready"
        })
    } else {
        json!({
            "status": "disconnected",
            "message": "Tor client is not initialized. Attempting to connect..."
        })
    };
    info!("Tor status: {}", status["status"].as_str().unwrap_or("unknown"));
    Ok(status)
}

// Update the `get_system_info()` function
#[tauri::command]
fn get_system_info() -> Result<serde_json::Value, String> {
    info!("Fetching system information");
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_count = sys.cpus().len();
    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let cpu_usage = sys.global_cpu_info().cpu_usage();

    let disks = Disks::new_with_refreshed_list();
    let disk_info: Vec<serde_json::Value> = disks
        .iter()
        .map(|disk| {
            json!({
                "name": disk.name().to_string_lossy().into_owned(),
                "mount_point": disk.mount_point().to_string_lossy().into_owned(),
                "total_space_kb": disk.total_space(),
                "available_space_kb": disk.available_space(),
                "file_system": disk.file_system().to_string_lossy().into_owned()
            })
        })
        .collect();

    let networks = Networks::new_with_refreshed_list();
    let network_info: Vec<serde_json::Value> = networks
        .iter()
        .map(|(interface_name, data)| {
            json!({
                "interface_name": interface_name.to_string(),
                "total_received_bytes": data.total_received(),
                "total_transmitted_bytes": data.total_transmitted()
            })
        })
        .collect();

    sys.refresh_processes();
    let mut process_vec: Vec<(&Pid, &Process)> = sys.processes().iter().collect();
    process_vec.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));
    let process_info: Vec<serde_json::Value> = process_vec
        .into_iter()
        .take(10)
        .map(|(pid, process)| {
            json!({
                "pid": pid.to_string(),
                "cpu_usage_percent": process.cpu_usage(),
                "memory_kb": process.memory() / 1024
            })
        })
        .collect();

    let os = OsInfo {
        name: System::name().unwrap_or("Unknown".to_string()),
        version: System::os_version().unwrap_or("Unknown".to_string()),
        host_name: System::host_name().unwrap_or("Unknown".to_string()),
    };

// GPU information using nvml-wrapper (already implemented)
    let gpu_info: Vec<serde_json::Value> = match nvml_wrapper::Nvml::init() {
        Ok(nvml) => {
            match nvml.device_count() {
                Ok(count) => {
                    let mut gpus = Vec::new();
                    for i in 0..count {
                        if let Ok(device) = nvml.device_by_index(i) {
                            let name = device.name().unwrap_or_else(|_| "Unknown GPU".to_string());
                            let memory_info = device.memory_info().unwrap_or_else(|_| nvml_wrapper::struct_wrappers::device::MemoryInfo {
                                total: 0,
                                used: 0,
                                free: 0,
                            });
                            let utilization = device.utilization_rates().unwrap_or_else(|_| nvml_wrapper::struct_wrappers::device::Utilization {
                                gpu: 0,
                                memory: 0,
                            });
                            gpus.push(json!({
                                "index": i,
                                "name": name,
                                "total_memory_mb": memory_info.total / 1024 / 1024,
                                "used_memory_mb": memory_info.used / 1024 / 1024,
                                "gpu_utilization_percent": utilization.gpu,
                                "memory_utilization_percent": utilization.memory
                            }));
                        }
                    }
                    gpus
                }
                Err(_) => vec![json!({"error": "Could not retrieve GPU count"})],
            }
        }
        Err(_) => vec![json!({"error": "NVML initialization failed"})],
    };
// Video and Screen Sharing Diagnostics
    let video_diagnostics = get_video_diagnostics();

// Network connectivity diagnostics
    let interfaces_data: serde_json::Value = match network_interface::NetworkInterface::show() {
        Ok(interfaces) => {
            let data: Vec<serde_json::Value> = interfaces
                .iter()
                .map(|iface| {
                    json!({
                        "name": iface.name.clone(),
                        "index": iface.index,
                        "mac_addr": iface.mac_addr.clone().unwrap_or("Unknown".to_string()),
                        "addr": iface.addr.first().map(|a| a.ip().to_string()).unwrap_or("None".to_string())
                    })
                })
                .collect();
            serde_json::Value::Array(data)
        }
        Err(e) => json!([{"error": format!("Failed to get interfaces: {}", e)}]),
    };

    let ping_data: serde_json::Value = {
        let ping_result = ping_rs::send_ping(
            &std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            std::time::Duration::from_millis(2000),
            &[0u8; 32][..], // Payload as a 32-byte slice
            None
        );
        match ping_result {
            Ok(reply) => json!({
                "target": "8.8.8.8 (Google DNS)",
                "latency_ms": reply.rtt,
                "status": "success"
            }),
            Err(e) => json!({
                "target": "8.8.8.8 (Google DNS)",
                "error": format!("Ping failed: {:?}", e),
                "status": "failed"
            }),
        }
    };

    let ports_data: serde_json::Value = {
        let common_ports = vec![80, 443, 8080];
        let port_status: Vec<serde_json::Value> = common_ports
            .iter()
            .map(|&port| {
                let address = format!("127.0.0.1:{}", port);
                let is_open = port_check::is_port_reachable(&address);
                json!({
                    "port": port,
                    "is_open": is_open,
                    "target": "localhost"
                })
            })
            .collect();
        serde_json::Value::Array(port_status)
    };

    let connectivity_info = json!({
        "interfaces": interfaces_data,
        "ping": ping_data,
        "ports": ports_data
    });

// Networking: Listening Ports
    let listening_ports_info = get_listening_ports();
// Firewall Status Diagnostics (for security monitoring)
    let firewall_status = get_firewall_status();
// VPN and Proxy Status Diagnostics (for security monitoring)
    let vpn_proxy_status = get_vpn_proxy_status();
// Audio diagnostics using cpal
    let audio_info: serde_json::Value = {
        use cpal::traits::{DeviceTrait, HostTrait};
        let host = cpal::default_host();
        let input_devices: Vec<serde_json::Value> = match host.input_devices() {
            Ok(devices) => {
                devices.into_iter()
                    .map(|device| {
                        let name = device.name().unwrap_or_else(|_| "Unknown Input Device".to_string());
                        let supported_configs = device.supported_input_configs()
                            .map(|configs| {
                                configs.into_iter()
                                    .map(|config| {
                                        json!({
                                            "channels": config.channels(),
                                            "min_sample_rate": config.min_sample_rate().0,
                                            "max_sample_rate": config.max_sample_rate().0,
                                            "buffer_size": format!("{:?}", config.buffer_size()),
                                            "sample_format": format!("{:?}", config.sample_format())
                                        })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_else(|_| Vec::new());
                        json!({
                            "name": name,
                            "type": "input",
                            "supported_configs": supported_configs
                        })
                    })
                    .collect()
            }
            Err(e) => vec![json!({"error": format!("Failed to get input devices: {:?}", e)})],
        };

        let output_devices: Vec<serde_json::Value> = match host.output_devices() {
            Ok(devices) => {
                devices.into_iter()
                    .map(|device| {
                        let name = device.name().unwrap_or_else(|_| "Unknown Output Device".to_string());
                        let supported_configs = device.supported_output_configs()
                            .map(|configs| {
                                configs.into_iter()
                                    .map(|config| {
                                        json!({
                                            "channels": config.channels(),
                                            "min_sample_rate": config.min_sample_rate().0,
                                            "max_sample_rate": config.max_sample_rate().0,
                                            "buffer_size": format!("{:?}", config.buffer_size()),
                                            "sample_format": format!("{:?}", config.sample_format())
                                        })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_else(|_| Vec::new());
                        json!({
                            "name": name,
                            "type": "output",
                            "supported_configs": supported_configs
                        })
                    })
                    .collect()
            }
            Err(e) => vec![json!({"error": format!("Failed to get output devices: {:?}", e)})],
        };

        let default_input = match host.default_input_device() {
            Some(device) => device.name().unwrap_or_else(|_| "Unknown Default Input".to_string()),
            None => "No Default Input Device".to_string(),
        };

        let default_output = match host.default_output_device() {
            Some(device) => device.name().unwrap_or_else(|_| "Unknown Default Output".to_string()),
            None => "No Default Output Device".to_string(),
        };

        // Attempt to gather sound card or driver info on Windows, including driver version and date
        let mut sound_card_info: Vec<serde_json::Value> = Vec::new();
        #[cfg(target_os = "windows")]
        {
            let command = r#"Get-WmiObject Win32_SoundDevice | ForEach-Object { $device = $_; $driver = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceID -eq $device.DeviceID }; Select-Object -InputObject $device Name, Manufacturer, ProductName, DeviceID, Status, @{Name='DriverVersion';Expression={$driver.DriverVersion}}, @{Name='DriverDate';Expression={$driver.DriverDate}} } | ConvertTo-Json"#;
            match std::process::Command::new("powershell")
                .args(&["-Command", command])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&output_str) {
                            sound_card_info = if parsed.is_array() {
                                parsed.as_array().unwrap().clone()
                            } else {
                                vec![parsed]
                            };
                        } else {
                            sound_card_info = vec![json!({"error": "Failed to parse sound card JSON", "raw_output": output_str.to_string()})];
                        }
                    } else {
                        sound_card_info = vec![json!({"error": "PowerShell command failed"})];
                    }
                }
                Err(e) => {
                    sound_card_info = vec![json!({"error": format!("Failed to execute PowerShell command: {:?}", e)})];
                }
            }
        }

        // Attempt to gather audio power management settings on Windows
        let mut audio_power_settings: Vec<serde_json::Value> = Vec::new();
        #[cfg(target_os = "windows")]
        {
            let command = r#"Get-WmiObject Win32_SoundDevice | Select-Object Name, DeviceID, Status, @{Name='PowerManagementSupported';Expression={$_.PowerManagementSupported}}, @{Name='PowerManagementCapabilities';Expression={$_.PowerManagementCapabilities}} | ConvertTo-Json"#;
            match std::process::Command::new("powershell")
                .args(&["-Command", command])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&output_str) {
                            audio_power_settings = if parsed.is_array() {
                                parsed.as_array().unwrap().clone()
                            } else {
                                vec![parsed]
                            };
                        } else {
                            audio_power_settings = vec![json!({"error": "Failed to parse audio power settings JSON", "raw_output": output_str.to_string()})];
                        }
                    } else {
                        audio_power_settings = vec![json!({"error": "PowerShell command for power settings failed", "details": String::from_utf8_lossy(&output.stderr).to_string()})];
                    }
                }
                Err(e) => {
                    audio_power_settings = vec![json!({"error": format!("Failed to execute PowerShell command for power settings: {:?}", e)})];
                }
            }
        }

        json!({
            "default_input": default_input,
            "default_output": default_output,
            "input_devices": input_devices,
            "output_devices": output_devices,
            "sound_card_info": sound_card_info,
            "audio_power_settings": audio_power_settings
        })
    };
    
// Battery and power diagnostics
    let battery_info: serde_json::Value = {
        match battery::Manager::new() {
            Ok(manager) => {
                match manager.batteries() {
                    Ok(batteries) => {
                        let battery_data: Vec<serde_json::Value> = batteries
                            .filter_map(|b| b.ok())
                            .enumerate()
                            .map(|(index, battery)| {
                                json!({
                                    "index": index,
                                    "state": format!("{:?}", battery.state()),
                                    "charge_percent": battery.state_of_charge().value * 100.0,
                                    "health_percent": battery.state_of_health().value * 100.0,
                                    "energy_wh": battery.energy().value,
                                    "energy_full_wh": battery.energy_full().value,
                                    "vendor": battery.vendor().unwrap_or("Unknown"),
                                    "model": battery.model().unwrap_or("Unknown"),
                                    "serial_number": battery.serial_number().unwrap_or("Unknown")
                                })
                            })
                            .collect();
                        if battery_data.is_empty() {
                            json!({
                                "status": "no_battery",
                                "message": "No batteries detected on this system",
                                "batteries": []
                            })
                        } else {
                            json!({
                                "status": "success",
                                "message": "Battery information retrieved",
                                "batteries": battery_data
                            })
                        }
                    }
                    Err(e) => json!({
                        "status": "error",
                        "message": format!("Failed to retrieve battery information: {}", e),
                        "batteries": []
                    }),
                }
            }
            Err(e) => json!({
                "status": "error",
                "message": format!("Failed to initialize battery manager: {}", e),
                "batteries": []
            }),
        }
    };

// Thermal diagnostics
    let thermal_info: serde_json::Value = {
        let output = if cfg!(target_os = "windows") {
            std::process::Command::new("powershell")
                .args(&["-Command", "Get-WmiObject -Namespace root\\wmi -Class MSAcpi_ThermalZoneTemperature | Select-Object CurrentTemperature | Format-List"])
                .output()
        } else {
            std::process::Command::new("sh")
                .arg("-c")
                .arg("echo 'Thermal data not supported on this platform'")
                .output()
        };

        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout).to_string();
                if cfg!(target_os = "windows") {
                    if let Some(temp_line) = output_str.lines().find(|line| line.contains("CurrentTemperature")) {
                        if let Some(temp_str) = temp_line.split(':').last().map(|s| s.trim()) {
                            if let Ok(temp_tenths_kelvin) = temp_str.parse::<f32>() {
                                let temp_celsius = (temp_tenths_kelvin / 10.0) - 273.15; // Convert from Kelvin to Celsius
                                json!({
                                    "status": "success",
                                    "message": "Thermal information retrieved via PowerShell",
                                    "sensors": [{
                                        "index": 0,
                                        "name": "System Thermal Zone",
                                        "temperature_celsius": temp_celsius
                                    }]
                                })
                            } else {
                                json!({
                                    "status": "no_data",
                                    "message": "No valid temperature data found via PowerShell",
                                    "sensors": []
                                })
                            }
                        } else {
                            json!({
                                "status": "no_data",
                                "message": "No valid temperature data found via PowerShell",
                                "sensors": []
                            })
                        }
                    } else {
                        json!({
                            "status": "no_data",
                            "message": "No valid temperature data found via PowerShell",
                            "sensors": []
                        })
                    }
                } else {
                    json!({
                        "status": "not_supported",
                        "message": "Thermal data not supported on this platform",
                        "sensors": []
                    })
                }
            }
            Ok(result) => {
                let error_str = String::from_utf8_lossy(&result.stderr).to_string();
                json!({
                    "status": "error",
                    "message": format!("Failed to retrieve thermal data: {}", error_str),
                    "sensors": []
                })
            }
            Err(e) => json!({
                "status": "error",
                "message": format!("Failed to execute thermal data command: {}", e),
                "sensors": []
            }),
        }
    };

// Add BIOS information (Windows-specific via WMI/PowerShell)
    let bios = match get_bios_info() {
        Ok(bios_info) => bios_info,
        Err(e) => BiosInfo {
            vendor: String::new(),
            version: String::new(),
            release_date: String::new(),
            status: "error".to_string(),
            message: format!("Failed to retrieve BIOS info: {}", e),
        },
    };

// Add USB information (Windows-specific via WMI/PowerShell)
    let usb = match get_usb_info() {
        Ok(usb_info) => usb_info,
        Err(e) => UsbInfo {
            devices: vec![],
            status: "error".to_string(),
            message: format!("Failed to retrieve USB info: {}", e),
        },
    };

// Add Event Log information (Windows-specific via PowerShell)
    let event_log = match get_event_log_info() {
        Ok(event_log_info) => event_log_info,
        Err(e) => EventLogInfo {
            events: vec![],
            status: "error".to_string(),
            message: format!("Failed to retrieve event log info: {}", e),
        },
    };

// Add Disk Health information (Windows-specific via PowerShell)
    let disk_health = match get_disk_health_info() {
        Ok(disk_health_info) => disk_health_info,
        Err(e) => DiskHealthInfo {
            disks: vec![],
            status: "error".to_string(),
            message: format!("Failed to retrieve disk health info: {}", e),
        },
    };

// Add Enhanced Network Adapter information (Windows-specific via PowerShell)
    let network_adapters = match get_network_adapter_info() {
        Ok(network_adapter_info) => network_adapter_info,
        Err(e) => NetworkAdapterInfo {
            adapters: vec![],
            status: "error".to_string(),
            message: format!("Failed to retrieve network adapter info: {}", e),
        },
    };

// Add System Uptime and Boot Time information (Windows-specific via PowerShell)
    let system_uptime = match get_system_uptime_info() {
        Ok(system_uptime_info) => system_uptime_info,
        Err(e) => SystemUptimeInfo {
            boot_time: String::new(),
            uptime_seconds: 0,
            status: "error".to_string(),
            message: format!("Failed to retrieve system uptime info: {}", e),
        },
    };

// Boot Log Diagnostics (for detecting live USB systems like TAILS)
    let boot_log_diagnostics = get_boot_log_diagnostics();
    
    let system_info = json!({
        "cpu_count": cpu_count,
        "cpu_usage_percent": cpu_usage,
        "total_memory_kb": total_memory,
        "used_memory_kb": used_memory,
        "disks": disk_info,
        "networks": network_info,
        "processes": process_info,
        "os": os,
        "gpus": gpu_info,
        "connectivity": connectivity_info,
        "audio": audio_info,
        "battery": battery_info,
        "thermal": thermal_info,
        "bios": bios,
        "usb": usb,
        "event_log": event_log,
        "disk_health": disk_health,
        "network_adapters": network_adapters,
        "system_uptime": system_uptime,
        "listening_ports": listening_ports_info,
        "video_diagnostics": video_diagnostics,
        "boot_log_diagnostics": boot_log_diagnostics,
        "firewall_status": firewall_status,
        "vpn_proxy_status": vpn_proxy_status,
    });

    info!("System information retrieved successfully. Diagnostics data collected.");
    Ok(system_info)
}

// Define `get_bios_info()` function before it's used in `get_system_info()`
fn get_bios_info() -> Result<BiosInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query WMI for BIOS information
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate | Format-List | Out-String",
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        if !output.status.success() {
            return Err(format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut vendor = String::new();
        let mut version = String::new();
        let mut release_date = String::new();

        for line in output_str.lines() {
            if line.contains("Manufacturer") {
                if let Some(pos) = line.find(':') {
                    vendor = line[pos + 1..].trim().to_string();
                }
            } else if line.contains("SMBIOSBIOSVersion") {
                if let Some(pos) = line.find(':') {
                    version = line[pos + 1..].trim().to_string();
                }
            } else if line.contains("ReleaseDate") {
                if let Some(pos) = line.find(':') {
                    release_date = line[pos + 1..].trim().to_string();
                }
            }
        }

        if vendor.is_empty() && version.is_empty() && release_date.is_empty() {
            return Err("No BIOS information found in PowerShell output".to_string());
        }

        Ok(BiosInfo {
            vendor,
            version,
            release_date,
            status: "success".to_string(),
            message: "BIOS information retrieved".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for non-Windows platforms
        Ok(BiosInfo {
            vendor: String::new(),
            version: String::new(),
            release_date: String::new(),
            status: "error".to_string(),
            message: "BIOS information not supported on this platform".to_string(),
        })
    }
}

// Replace the existing `get_usb_info()` function with this updated version
fn get_usb_info() -> Result<UsbInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query WMI for USB device information with a detailed scope
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.DeviceID -like 'USB\\*' -or $_.Service -like 'usb*'} | Select-Object Name, DeviceID, Manufacturer, Description, Status | Format-List | Out-String",
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        if !output.status.success() {
            return Err(format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut devices: Vec<UsbDevice> = Vec::new();
        let mut current_device: Option<UsbDevice> = None;

        for line in output_str.lines() {
            let line = line.trim();
            if line.is_empty() {
                if let Some(device) = current_device.take() {
                    devices.push(device);
                }
                continue;
            }

            if let Some(device) = current_device.as_mut() {
                if line.contains("Name") {
                    if let Some(pos) = line.find(':') {
                        device.name = line[pos + 1..].trim().to_string();
                    }
                } else if line.contains("DeviceID") {
                    if let Some(pos) = line.find(':') {
                        device.device_id = line[pos + 1..].trim().to_string();
                    }
                } else if line.contains("Manufacturer") {
                    if let Some(pos) = line.find(':') {
                        device.manufacturer = line[pos + 1..].trim().to_string();
                    }
                }
            } else {
                current_device = Some(UsbDevice {
                    name: String::new(),
                    device_id: String::new(),
                    manufacturer: String::new(),
                });
            }
        }

        if let Some(device) = current_device.take() {
            devices.push(device);
        }

        if devices.is_empty() {
            return Err("No USB devices found in PowerShell output".to_string());
        }

        Ok(UsbInfo {
            devices,
            status: "success".to_string(),
            message: "USB information retrieved".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for non-Windows platforms
        Ok(UsbInfo {
            devices: vec![],
            status: "error".to_string(),
            message: "USB information not supported on this platform".to_string(),
        })
    }
}

// Event logging
fn get_event_log_info() -> Result<EventLogInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query recent System event logs with structured JSON output (limited to last 5 for brevity, filtered for hardware/driver events)
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-EventLog -LogName System -Newest 5 | Where-Object { $_.EventID -in (566, 105, 7021, 7040, 1, 130) } | Select-Object @{Name='TimeCreated';Expression={$_.TimeWritten -as [string]}}, EventID, @{Name='LevelDisplayName';Expression={if ($_.LevelDisplayName) {$_.LevelDisplayName} else {'Unknown'}}}, Source, @{Name='Message';Expression={$_.Message.Substring(0, [Math]::Min($_.Message.Length, 100)) -replace \"\\r\\n\", \" \"}} | ConvertTo-Json",
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        if !output.status.success() {
            return Err(format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        // Log the raw output for debugging purposes
        info!("Raw event log JSON output: {}", output_str);
        // Clean up the output string by removing potential trailing commas or other JSON-breaking characters
        let cleaned_output = output_str.replace(",}", "}").replace(",]", "]");
        let events_result: Result<Vec<EventEntry>, serde_json::Error> = serde_json::from_str(&cleaned_output)
            .or_else(|_| {
                // Fallback to manual parsing if JSON parsing fails
                let mut events: Vec<EventEntry> = Vec::new();
                let mut current_event: Option<EventEntry> = None;

                for line in cleaned_output.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        if let Some(event) = current_event.take() {
                            events.push(event);
                        }
                        continue;
                    }

                    if let Some(event) = current_event.as_mut() {
                        if line.contains("TimeCreated") {
                            if let Some(pos) = line.find(':') {
                                event.time_created = line[pos + 1..].trim().replace(',', "").replace('"', "").to_string();
                            }
                        } else if line.contains("EventID") {
                            if let Some(pos) = line.find(':') {
                                event.event_id = line[pos + 1..].trim().replace(',', "").replace('"', "").to_string();
                            }
                        } else if line.contains("LevelDisplayName") {
                            if let Some(pos) = line.find(':') {
                                event.level = line[pos + 1..].trim().replace(',', "").replace('"', "").to_string();
                            }
                        } else if line.contains("Source") {
                            if let Some(pos) = line.find(':') {
                                event.source = line[pos + 1..].trim().replace(',', "").replace('"', "").to_string();
                            }
                        } else if line.contains("Message") {
                            if let Some(pos) = line.find(':') {
                                event.message = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        }
                    } else {
                        current_event = Some(EventEntry {
                            time_created: String::new(),
                            event_id: String::new(),
                            level: String::new(),
                            source: String::new(),
                            message: String::new(),
                        });
                    }
                }

                if let Some(event) = current_event.take() {
                    events.push(event);
                }
                Ok(events)
            });

        let events = match events_result {
            Ok(events) if !events.is_empty() => events,
            Ok(_) => return Err("No event log entries found in PowerShell output".to_string()),
            Err(e) => return Err(format!("Failed to parse event log JSON: {}", e)),
        };

        Ok(EventLogInfo {
            events,
            status: "success".to_string(),
            message: "Event log information retrieved".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for non-Windows platforms
        Ok(EventLogInfo {
            events: vec![],
            status: "error".to_string(),
            message: "Event log information not supported on this platform".to_string(),
        })
    }
}

// helper function to retrieve Disk Health information
fn get_disk_health_info() -> Result<DiskHealthInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query disk health information via Get-PhysicalDisk with JSON output
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-PhysicalDisk | Select-Object DeviceId, Model, SerialNumber, OperationalStatus, @{Name='HealthStatus';Expression={$_.PhysicalDiskHealthStatus}}, Size | ConvertTo-Json",
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        if !output.status.success() {
            return Err(format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        // Log the raw output for debugging purposes
        info!("Raw disk health JSON output: {}", output_str);
        // Clean up the output string by removing potential trailing commas or other JSON-breaking characters
        let cleaned_output = output_str.replace(",}", "}").replace(",]", "]");
        let disks_result: Result<Vec<DiskHealthEntry>, serde_json::Error> = serde_json::from_str(&cleaned_output)
            .or_else(|_| {
                // Fallback to manual parsing if JSON parsing fails
                let mut disks: Vec<DiskHealthEntry> = Vec::new();
                let mut current_disk: Option<DiskHealthEntry> = None;

                for line in cleaned_output.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        if let Some(disk) = current_disk.take() {
                            disks.push(disk);
                        }
                        continue;
                    }

                    if let Some(disk) = current_disk.as_mut() {
                        if line.contains("DeviceId") {
                            if let Some(pos) = line.find(':') {
                                disk.device_id = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("Model") {
                            if let Some(pos) = line.find(':') {
                                disk.model = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("SerialNumber") {
                            if let Some(pos) = line.find(':') {
                                disk.serial_number = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("OperationalStatus") {
                            if let Some(pos) = line.find(':') {
                                disk.operational_status = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("HealthStatus") {
                            if let Some(pos) = line.find(':') {
                                let health_str = line[pos + 1..].trim().replace('"', "").replace(',', "");
                                disk.health_status = if health_str == "null" { "Unknown".to_string() } else { health_str };
                            }
                        } else if line.contains("Size") {
                            if let Some(pos) = line.find(':') {
                                let size_str = line[pos + 1..].trim().replace('"', "").replace(',', "");
                                disk.size_bytes = size_str.parse::<u64>().unwrap_or(0);
                            }
                        }
                    } else {
                        current_disk = Some(DiskHealthEntry {
                            device_id: String::new(),
                            model: String::new(),
                            serial_number: String::new(),
                            operational_status: String::new(),
                            health_status: String::new(),
                            size_bytes: 0,
                        });
                    }
                }

                if let Some(disk) = current_disk.take() {
                    disks.push(disk);
                }
                Ok(disks)
            });

        let disks = match disks_result {
            Ok(disks) if !disks.is_empty() => disks,
            Ok(_) => return Err("No disk health information found in PowerShell output".to_string()),
            Err(e) => return Err(format!("Failed to parse disk health JSON: {}", e)),
        };

        Ok(DiskHealthInfo {
            disks,
            status: "success".to_string(),
            message: "Disk health information retrieved".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for non-Windows platforms
        Ok(DiskHealthInfo {
            disks: vec![],
            status: "error".to_string(),
            message: "Disk health information not supported on this platform".to_string(),
        })
    }
}

// get network adapter info function
fn get_network_adapter_info() -> Result<NetworkAdapterInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query network adapter information via Get-NetAdapter with JSON output
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, @{Name='LinkSpeedMbps';Expression={$_.LinkSpeed -replace ' Mbps', '' -replace ' Gbps', '000'}} | ConvertTo-Json",
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        if !output.status.success() {
            return Err(format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        // Log the raw output for debugging purposes
        info!("Raw network adapter JSON output: {}", output_str);
        // Clean up the output string by removing potential trailing commas or other JSON-breaking characters
        let cleaned_output = output_str.replace(",}", "}").replace(",]", "]");
        let adapters_result: Result<Vec<NetworkAdapterEntry>, serde_json::Error> = serde_json::from_str(&cleaned_output)
            .or_else(|_| {
                // Fallback to manual parsing if JSON parsing fails
                let mut adapters: Vec<NetworkAdapterEntry> = Vec::new();
                let mut current_adapter: Option<NetworkAdapterEntry> = None;
                let lines: Vec<&str> = cleaned_output.lines().collect();
                let mut i = 0;

                while i < lines.len() {
                    let line = lines[i].trim();
                    if line.is_empty() {
                        if let Some(adapter) = current_adapter.take() {
                            adapters.push(adapter);
                        }
                        i += 1;
                        continue;
                    }

                    if line.contains("{") && !line.contains("}") {
                        current_adapter = Some(NetworkAdapterEntry {
                            name: String::new(),
                            interface_description: String::new(),
                            status: String::new(),
                            mac_address: String::new(),
                            link_speed_mbps: 0,
                        });
                        i += 1;
                        continue;
                    }

                    if let Some(adapter) = current_adapter.as_mut() {
                        if line.contains("Name") {
                            if let Some(pos) = line.find(':') {
                                adapter.name = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("InterfaceDescription") {
                            if let Some(pos) = line.find(':') {
                                adapter.interface_description = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("Status") {
                            if let Some(pos) = line.find(':') {
                                adapter.status = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("MacAddress") {
                            if let Some(pos) = line.find(':') {
                                adapter.mac_address = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                            }
                        } else if line.contains("LinkSpeedMbps") {
                            if let Some(pos) = line.find(':') {
                                let speed_str = line[pos + 1..].trim().replace('"', "").replace(',', "");
                                adapter.link_speed_mbps = speed_str.parse::<u64>().unwrap_or(0);
                            }
                        }
                    }

                    if line.contains("}") {
                        if let Some(adapter) = current_adapter.take() {
                            adapters.push(adapter);
                        }
                    }
                    i += 1;
                }

                if let Some(adapter) = current_adapter.take() {
                    adapters.push(adapter);
                }
                Ok(adapters)
            });

        let adapters = match adapters_result {
            Ok(adapters) if !adapters.is_empty() => adapters,
            Ok(_) => return Err("No network adapter information found in PowerShell output".to_string()),
            Err(e) => return Err(format!("Failed to parse network adapter JSON: {}", e)),
        };

        Ok(NetworkAdapterInfo {
            adapters,
            status: "success".to_string(),
            message: "Network adapter information retrieved".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for non-Windows platforms
        Ok(NetworkAdapterInfo {
            adapters: vec![],
            status: "error".to_string(),
            message: "Network adapter information not supported on this platform".to_string(),
        })
    }
}

// Add a new helper function to retrieve System Uptime and Boot Time information (place this after `get_network_adapter_info`)
fn get_system_uptime_info() -> Result<SystemUptimeInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query system uptime and boot time via Get-CimInstance with JSON output
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime, @{Name='UptimeSeconds';Expression={((Get-Date) - $_.LastBootUpTime).TotalSeconds -as [int]}} | ConvertTo-Json",
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        if !output.status.success() {
            return Err(format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        // Log the raw output for debugging purposes
        info!("Raw system uptime JSON output: {}", output_str);
        // Clean up the output string by removing potential trailing commas or other JSON-breaking characters
        let cleaned_output = output_str.replace(",}", "}").replace(",]", "]");
        
        // Since the output might be a single object (not an array), we parse it directly
        let uptime_result: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&cleaned_output)
            .or_else(|_| {
                // Fallback to manual parsing if JSON parsing fails
                let mut boot_time = String::new();
                let mut uptime_seconds = 0u64;

                for line in cleaned_output.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    if line.contains("LastBootUpTime") {
                        if let Some(pos) = line.find(':') {
                            boot_time = line[pos + 1..].trim().replace('"', "").replace(',', "").to_string();
                        }
                    } else if line.contains("UptimeSeconds") {
                        if let Some(pos) = line.find(':') {
                            let uptime_str = line[pos + 1..].trim().replace('"', "").replace(',', "");
                            uptime_seconds = uptime_str.parse::<u64>().unwrap_or(0);
                        }
                    }
                }

                let result = json!({
                    "LastBootUpTime": boot_time,
                    "UptimeSeconds": uptime_seconds
                });
                Ok(result)
            });

        let uptime_data = match uptime_result {
            Ok(data) => data,
            Err(e) => return Err(format!("Failed to parse system uptime JSON: {}", e)),
        };

        let boot_time = uptime_data.get("LastBootUpTime")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let uptime_seconds = uptime_data.get("UptimeSeconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if boot_time.is_empty() && uptime_seconds == 0 {
            return Err("No valid system uptime information found in PowerShell output".to_string());
        }

        Ok(SystemUptimeInfo {
            boot_time,
            uptime_seconds,
            status: "success".to_string(),
            message: "System uptime information retrieved".to_string(),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for non-Windows platforms
        Ok(SystemUptimeInfo {
            boot_time: String::new(),
            uptime_seconds: 0,
            status: "error".to_string(),
            message: "System uptime information not supported on this platform".to_string(),
        })
    }
}

// Helper function to get listening ports using netstat crate
fn get_listening_ports() -> serde_json::Value {
    use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
    use serde_json::json;

    let mut listening_ports = Vec::new();

    // Attempt to retrieve socket information for TCP and UDP
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    match get_sockets_info(af_flags, proto_flags) {
        Ok(sockets) => {
            for socket in sockets {
                match &socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp_info) => {
                        // Directly access state since it's not an Option
                        let state_str = tcp_info.state.to_string();
                        // Check if state indicates listening (case-insensitive)
                        if state_str.to_lowercase().contains("listen") {
                            listening_ports.push(json!({
                                "protocol": "TCP",
                                "local_address": tcp_info.local_addr.to_string(),
                                "local_port": tcp_info.local_port,
                                "state": state_str,
                                "associated_pids": socket.associated_pids
                            }));
                        }
                    }
                    ProtocolSocketInfo::Udp(udp_info) => {
                        // UDP doesn't have a "state" like TCP, list active UDP sockets
                        listening_ports.push(json!({
                            "protocol": "UDP",
                            "local_address": udp_info.local_addr.to_string(),
                            "local_port": udp_info.local_port,
                            "state": "N/A",
                            "associated_pids": socket.associated_pids
                        }));
                    }
                }
            }
            json!({
                "status": "success",
                "message": "Listening ports information retrieved",
                "ports": listening_ports
            })
        }
        Err(e) => json!({
            "status": "error",
            "message": format!("Failed to retrieve listening ports: {}", e),
            "ports": []
        }),
    }
}

// Helper function to get video hardware and screen sharing diagnostics using sysinfo
fn get_video_diagnostics() -> serde_json::Value {
    use sysinfo::{Components, System};
    use serde_json::json;

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut video_adapters = Vec::new();
    let components = Components::new_with_refreshed_list();
    
    // Gather video adapter information (if available through sysinfo components)
    for component in components.iter() {
        let label = component.label().to_lowercase();
        if label.contains("video") || label.contains("graphics") || label.contains("gpu") {
            video_adapters.push(json!({
                "label": component.label(),
                "temperature": component.temperature(),
                "critical_temp": component.critical().unwrap_or(0.0),
                "max_temp": component.max()
            }));
        }
    }

    // Fallback if no video-specific components are found
    if video_adapters.is_empty() {
        video_adapters.push(json!({
            "label": "Video adapter information not available via sysinfo",
            "temperature": "N/A",
            "critical_temp": "N/A",
            "max_temp": "N/A"
        }));
    }

    // Check for potential screen sharing processes (basic heuristic based on common process names)
    sys.refresh_processes();
    let mut potential_screen_sharing = Vec::new();
    for (pid, process) in sys.processes() {
        let name = process.name().to_lowercase();
        if name.contains("teamviewer") || name.contains("anydesk") || name.contains("rdp") || 
           name.contains("remote") || name.contains("zoom") || name.contains("skype") {
            potential_screen_sharing.push(json!({
                "pid": pid.to_string(),
                "name": process.name(),
                "cpu_usage": process.cpu_usage(),
                "memory": process.memory()
            }));
        }
    }

    json!({
        "status": "success",
        "message": "Video and screen sharing diagnostics retrieved",
        "video_adapters": video_adapters,
        "potential_screen_sharing": potential_screen_sharing
    })
}

// Helper function to get boot log diagnostics (for detecting live USB systems like TAILS)
fn get_boot_log_diagnostics() -> serde_json::Value {
    use serde_json::json;
    use std::process::Command;

    let mut boot_events = Vec::new();
    let mut status = "success";
    let mut message = "Boot log diagnostics retrieved";
    let mut error_message_storage = String::new(); // Storage for error messages to ensure lifetime

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to get boot-related events from System log
        let command = r#"Get-EventLog -LogName System -Source Microsoft-Windows-Kernel-Boot -Newest 5 -ErrorAction SilentlyContinue | Select-Object TimeWritten, EventID, Source, Message | ConvertTo-Json"#;
        match Command::new("powershell")
            .args(&["-Command", command])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if !output_str.is_empty() {
                        // Attempt to parse JSON output
                        match serde_json::from_str::<serde_json::Value>(&output_str) {
                            Ok(json_data) => {
                                if let Some(events) = json_data.as_array() {
                                    for event in events {
                                        if let Some(time_written) = event.get("TimeWritten").and_then(|v| v.as_str()) {
                                            if let Some(event_id) = event.get("EventID").and_then(|v| v.as_i64()) {
                                                if let Some(source) = event.get("Source").and_then(|v| v.as_str()) {
                                                    let message_text = event.get("Message").and_then(|v| v.as_str()).unwrap_or("Message not available");
                                                    boot_events.push(json!({
                                                        "time_created": time_written,
                                                        "event_id": event_id,
                                                        "source": source,
                                                        "message": message_text
                                                    }));
                                                }
                                            }
                                        }
                                    }
                                } else if let Some(event) = json_data.as_object() {
                                    if let Some(time_written) = event.get("TimeWritten").and_then(|v| v.as_str()) {
                                        if let Some(event_id) = event.get("EventID").and_then(|v| v.as_i64()) {
                                            if let Some(source) = event.get("Source").and_then(|v| v.as_str()) {
                                                let message_text = event.get("Message").and_then(|v| v.as_str()).unwrap_or("Message not available");
                                                boot_events.push(json!({
                                                    "time_created": time_written,
                                                    "event_id": event_id,
                                                    "source": source,
                                                    "message": message_text
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                status = "error";
                                error_message_storage = format!("Failed to parse boot log JSON: {}", e);
                                message = &error_message_storage;
                            }
                        }
                    } else {
                        status = "warning";
                        message = "No boot log events found";
                    }
                } else {
                    let error_str = String::from_utf8_lossy(&output.stderr);
                    status = "error";
                    error_message_storage = format!("Failed to retrieve boot logs: {}", error_str);
                    message = &error_message_storage;
                }
            }
            Err(e) => {
                status = "error";
                error_message_storage = format!("Error executing PowerShell command for boot logs: {}", e);
                message = &error_message_storage;
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        status = "warning";
        message = "Boot log diagnostics not supported on non-Windows platforms";
    }

    json!({
        "status": status,
        "message": message,
        "boot_events": boot_events
    })
}

// Helper function to get firewall status diagnostics (for security monitoring)
fn get_firewall_status() -> serde_json::Value {
    use serde_json::json;
    use std::process::Command;

    let mut firewall_profiles = Vec::new();
    let mut status = "success";
    let mut message = "Firewall status diagnostics retrieved";
    let mut error_message_storage = String::new(); // Storage for error messages to ensure lifetime

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to get firewall status for all profiles
        let command = r#"Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json"#;
        match Command::new("powershell")
            .args(&["-Command", command])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if !output_str.is_empty() {
                        // Attempt to parse JSON output
                        match serde_json::from_str::<serde_json::Value>(&output_str) {
                            Ok(json_data) => {
                                if let Some(profiles) = json_data.as_array() {
                                    for profile in profiles {
                                        if let Some(name) = profile.get("Name").and_then(|v| v.as_str()) {
                                            if let Some(enabled) = profile.get("Enabled").and_then(|v| v.as_bool()) {
                                                let inbound_action = profile.get("DefaultInboundAction").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                                let outbound_action = profile.get("DefaultOutboundAction").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                                firewall_profiles.push(json!({
                                                    "profile_name": name,
                                                    "enabled": enabled,
                                                    "default_inbound_action": inbound_action,
                                                    "default_outbound_action": outbound_action
                                                }));
                                            }
                                        }
                                    }
                                } else if let Some(profile) = json_data.as_object() {
                                    if let Some(name) = profile.get("Name").and_then(|v| v.as_str()) {
                                        if let Some(enabled) = profile.get("Enabled").and_then(|v| v.as_bool()) {
                                            let inbound_action = profile.get("DefaultInboundAction").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                            let outbound_action = profile.get("DefaultOutboundAction").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                            firewall_profiles.push(json!({
                                                "profile_name": name,
                                                "enabled": enabled,
                                                "default_inbound_action": inbound_action,
                                                "default_outbound_action": outbound_action
                                            }));
                                        }
                                    }
                                }
                                if firewall_profiles.is_empty() {
                                    status = "warning";
                                    message = "No firewall profile data found";
                                }
                            }
                            Err(e) => {
                                status = "error";
                                error_message_storage = format!("Failed to parse firewall status JSON: {}", e);
                                message = &error_message_storage;
                            }
                        }
                    } else {
                        status = "warning";
                        message = "No firewall status data returned";
                    }
                } else {
                    let error_str = String::from_utf8_lossy(&output.stderr);
                    status = "error";
                    error_message_storage = format!("Failed to retrieve firewall status: {}", error_str);
                    message = &error_message_storage;
                }
            }
            Err(e) => {
                status = "error";
                error_message_storage = format!("Error executing PowerShell command for firewall status: {}", e);
                message = &error_message_storage;
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        status = "warning";
        message = "Firewall status diagnostics not supported on non-Windows platforms";
    }

    json!({
        "status": status,
        "message": message,
        "firewall_profiles": firewall_profiles
    })
}

// Helper function to get VPN/proxy status diagnostics (for security monitoring)
fn get_vpn_proxy_status() -> serde_json::Value {
    use serde_json::json;
    use std::process::Command;

    let mut vpn_connections = Vec::new();
    let mut proxy_info = Vec::new();
    let mut status = "success";
    let mut message = "VPN and proxy status diagnostics retrieved";
    let mut error_message_storage = String::new(); // Storage for error messages to ensure lifetime

    #[cfg(target_os = "windows")]
    {
        // Check for active VPN connections using PowerShell (e.g., RAS or VPN adapters)
        let vpn_command = r#"Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*VPN*' -or $_.InterfaceDescription -like '*Tunnel*' } | Select-Object Name, Status, InterfaceDescription | ConvertTo-Json"#;
        match Command::new("powershell")
            .args(&["-Command", vpn_command])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if !output_str.is_empty() {
                        // Attempt to parse JSON output for VPN connections
                        match serde_json::from_str::<serde_json::Value>(&output_str) {
                            Ok(json_data) => {
                                if let Some(adapters) = json_data.as_array() {
                                    for adapter in adapters {
                                        if let Some(name) = adapter.get("Name").and_then(|v| v.as_str()) {
                                            if let Some(status_val) = adapter.get("Status").and_then(|v| v.as_str()) {
                                                let description = adapter.get("InterfaceDescription").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                                vpn_connections.push(json!({
                                                    "name": name,
                                                    "status": status_val,
                                                    "description": description
                                                }));
                                            }
                                        }
                                    }
                                } else if let Some(adapter) = json_data.as_object() {
                                    if let Some(name) = adapter.get("Name").and_then(|v| v.as_str()) {
                                        if let Some(status_val) = adapter.get("Status").and_then(|v| v.as_str()) {
                                            let description = adapter.get("InterfaceDescription").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                            vpn_connections.push(json!({
                                                "name": name,
                                                "status": status_val,
                                                "description": description
                                            }));
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                status = "error";
                                error_message_storage = format!("Failed to parse VPN adapter JSON: {}", e);
                                message = &error_message_storage;
                            }
                        }
                    }
                } else {
                    let error_str = String::from_utf8_lossy(&output.stderr);
                    status = "error";
                    error_message_storage = format!("Failed to retrieve VPN adapter status: {}", error_str);
                    message = &error_message_storage;
                }
            }
            Err(e) => {
                status = "error";
                error_message_storage = format!("Error executing PowerShell command for VPN status: {}", e);
                message = &error_message_storage;
            }
        }

        // Check for proxy settings using PowerShell (e.g., Internet Options proxy)
        let proxy_command = r#"Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable, ProxyServer | ConvertTo-Json"#;
        match Command::new("powershell")
            .args(&["-Command", proxy_command])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if !output_str.is_empty() {
                        // Attempt to parse JSON output for proxy settings
                        match serde_json::from_str::<serde_json::Value>(&output_str) {
                            Ok(json_data) => {
                                if let Some(settings) = json_data.as_object() {
                                    if let Some(proxy_enable) = settings.get("ProxyEnable").and_then(|v| v.as_i64()) {
                                        let proxy_server = settings.get("ProxyServer").and_then(|v| v.as_str()).unwrap_or("Not set");
                                        proxy_info.push(json!({
                                            "proxy_enabled": proxy_enable == 1,
                                            "proxy_server": proxy_server
                                        }));
                                    }
                                }
                            }
                            Err(e) => {
                                if status != "error" { // Only overwrite if no prior error
                                    status = "warning";
                                    error_message_storage = format!("Failed to parse proxy settings JSON: {}", e);
                                    message = &error_message_storage;
                                }
                            }
                        }
                    } else {
                        if status != "error" { // Only overwrite if no prior error
                            status = "warning";
                            message = "No proxy settings data returned";
                        }
                    }
                } else {
                    let error_str = String::from_utf8_lossy(&output.stderr);
                    if status != "error" { // Only overwrite if no prior error
                        status = "warning";
                        error_message_storage = format!("Failed to retrieve proxy settings: {}", error_str);
                        message = &error_message_storage;
                    }
                }
            }
            Err(e) => {
                if status != "error" { // Only overwrite if no prior error
                    status = "warning";
                    error_message_storage = format!("Error executing PowerShell command for proxy settings: {}", e);
                    message = &error_message_storage;
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        status = "warning";
        message = "VPN and proxy status diagnostics not supported on non-Windows platforms";
    }

    json!({
        "status": status,
        "message": message,
        "vpn_connections": vpn_connections,
        "proxy_info": proxy_info
    })
}


#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let app = tauri::Builder::default()
        .manage(Mutex::new(None::<Arc<TorClient<PreferredRuntime>>>) as TorClientState)
        .setup(|app| {
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

            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await; // Delay to ensure app is ready
                info!("Testing system diagnostics on startup");
                let system_info_result = get_system_info();
                match system_info_result {
                    Ok(system_info) => info!("Diagnostics test completed: {:?}", system_info),
                    Err(e) => error!("Failed to run get_system_info on startup: {}", e),
                }
            });

            // Create a channel for stopping the system monitoring thread
            let (stop_tx, stop_rx) = channel::<bool>();
           let app_handle = app.handle().clone();
            start_system_monitoring(app_handle, stop_rx);

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
        .invoke_handler(tauri::generate_handler![greet, fetch_onion_url, get_system_info, get_tor_status])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } => {
            // Removed api.prevent_exit() to allow Ctrl+C to terminate the app
            // Removed emit line as it’s no longer needed with the mpsc channel approach
        }
        _ => {}
    });
}

