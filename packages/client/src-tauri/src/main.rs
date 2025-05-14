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

// Add this function near the top of the file, after the structs, around line 60 or so
// Replace the existing `start_system_monitoring` function (already correct in your code)
fn start_system_monitoring(app_handle: tauri::AppHandle, stop_rx: Receiver<bool>) {
    // Spawn the monitoring thread
    thread::spawn(move || {
        let mut sys = sysinfo::System::new_all();
        loop {
            // Check for stop signal from the channel (non-blocking)
            if let Ok(should_stop) = stop_rx.try_recv() {
                if should_stop {
                    println!("System monitoring thread stopped by shutdown signal.");
                    break;
                }
            }
            sys.refresh_cpu();
            sys.refresh_memory();
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
            thread::sleep(Duration::from_secs(5));
        }
    });
}


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

    // Audio diagnostics using cpal
    let audio_info: serde_json::Value = {
        let host = cpal::default_host();
        let input_devices: Vec<serde_json::Value> = match host.input_devices() {
            Ok(devices) => {
                devices.into_iter()
                    .map(|device| {
                        let name = device.name().unwrap_or_else(|_| "Unknown Input Device".to_string());
                        json!({
                            "name": name,
                            "type": "input"
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
                        json!({
                            "name": name,
                            "type": "output"
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

        json!({
            "input_devices": input_devices,
            "output_devices": output_devices,
            "default_input": default_input,
            "default_output": default_output
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
        "usb": usb
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

// Define `get_usb_info()` function with explicit type annotations to resolve inference issues
fn get_usb_info() -> Result<UsbInfo, String> {
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query WMI for USB device information
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-WmiObject -Class Win32_USBHub | Select-Object Name, DeviceID, Manufacturer | Format-List | Out-String",
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

