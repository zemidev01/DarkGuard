// Copyright (c) 2026 zemidev01
// Licensed under the GNU General Public License v3.0

use std::sync::Mutex;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::os::windows::process::CommandExt;
use tauri::{State, Manager};
use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton};
use tauri::menu::{Menu, MenuItem};
use tauri_plugin_notification::NotificationExt;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

const DATA_FILE: &str = "darkguard_tunnels.json";
const WIREGUARD_EXE: &str = "C:\\Program Files\\WireGuard\\wireguard.exe";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunnelInterface {
    pub private_key: String,
    pub public_key: String,
    pub mtu: u32,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub listen_port: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunnelTransfer {
    pub rx: String,
    pub tx: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunnelPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: String,
    pub latest_handshake: String,
    pub transfer: TunnelTransfer,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub interface: TunnelInterface,
    pub peer: TunnelPeer,
}

struct AppState {
    tunnels: Mutex<Vec<Tunnel>>,
}

fn generate_wireguard_conf(tunnel: &Tunnel) -> String {
    let mut conf = String::new();

    conf.push_str("[Interface]\n");
    conf.push_str(&format!("PrivateKey = {}\n", tunnel.interface.private_key));
    if !tunnel.interface.addresses.is_empty() {
        conf.push_str(&format!("Address = {}\n", tunnel.interface.addresses.join(", ")));
    }
    if !tunnel.interface.dns_servers.is_empty() {
        conf.push_str(&format!("DNS = {}\n", tunnel.interface.dns_servers.join(", ")));
    }
    if tunnel.interface.mtu > 0 {
        conf.push_str(&format!("MTU = {}\n", tunnel.interface.mtu));
    }

    conf.push_str("\n");

    conf.push_str("[Peer]\n");
    conf.push_str(&format!("PublicKey = {}\n", tunnel.peer.public_key));
    if !tunnel.peer.allowed_ips.is_empty() {
        conf.push_str(&format!("AllowedIPs = {}\n", tunnel.peer.allowed_ips.join(", ")));
    }
    if !tunnel.peer.endpoint.is_empty() {
        conf.push_str(&format!("Endpoint = {}\n", tunnel.peer.endpoint));
    }
    conf.push_str("PersistentKeepalive = 25\n");

    conf
}

fn get_service_name(tunnel_name: &str) -> String {
    tunnel_name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn install_tunnel_service(tunnel: &Tunnel) -> Result<(), String> {
    validate_keys(tunnel)?;

    let conf_content = generate_wireguard_conf(tunnel);
    let safe_name = get_service_name(&tunnel.name);
    
    let temp_dir = std::env::temp_dir();
    let conf_path = temp_dir.join(format!("{}.conf", safe_name));
    
    fs::write(&conf_path, conf_content)
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(format!("Start-Process '{}' -ArgumentList '/installtunnelservice', '{}' -Verb RunAs -WindowStyle Hidden -Wait", WIREGUARD_EXE, conf_path.display()))
        .creation_flags(0x08000000) 
        .output()
        .map_err(|e| format!("Failed to execute powershell: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("Failed to start tunnel service (UAC denied? PwrShell Err?): {} {}", stdout, stderr));
    }
    
    std::thread::sleep(std::time::Duration::from_millis(1500));
    if !check_service_exists(tunnel) {
         return Err("Service failed to start. Check names/logs.".to_string());   
    }
    
    Ok(())
}

fn uninstall_tunnel_service(tunnel_name: &str) -> Result<(), String> {
    let safe_name = get_service_name(tunnel_name);

    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(format!("Start-Process '{}' -ArgumentList '/uninstalltunnelservice', '{}' -Verb RunAs -WindowStyle Hidden -Wait", WIREGUARD_EXE, safe_name))
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("Failed to execute powershell: {}", e))?;

    if !output.status.success() {
    }
    
    Ok(())
}

fn check_service_exists(tunnel: &Tunnel) -> bool {
    let service_name = format!("WireGuardTunnel${}", get_service_name(&tunnel.name));
    
    let output = Command::new("sc")
        .arg("query")
        .arg(&service_name)
        .creation_flags(0x08000000) 
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        return out.status.success() && stdout.contains("STATE") && stdout.contains("RUNNING");
    }
    false
}

fn load_tunnels_from_disk() -> Vec<Tunnel> {
    let mut tunnels = Vec::new();
    if let Ok(content) = fs::read_to_string(DATA_FILE) {
        if let Ok(loaded) = serde_json::from_str::<Vec<Tunnel>>(&content) {
            tunnels = loaded;
        }
    }

    for tunnel in &mut tunnels {
        tunnel.active = check_service_exists(tunnel);
    }
    
    tunnels
}

fn save_tunnels_to_disk(tunnels: &Vec<Tunnel>) {
    if let Ok(content) = serde_json::to_string_pretty(tunnels) {
         let _ = fs::write(DATA_FILE, content);
    }
}

const WG_EXE: &str = "C:\\Program Files\\WireGuard\\wg.exe";

fn update_tunnel_stats(tunnel: &mut Tunnel) {
    if !Path::new(WG_EXE).exists() {
        return;
    }

    let interface_name = get_service_name(&tunnel.name);

    let output = Command::new(WG_EXE)
        .arg("show")
        .arg(&interface_name)
        .arg("dump")
        .creation_flags(0x08000000)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = stdout.trim().split('\n').collect();
            
            if lines.len() > 0 {
                let parts: Vec<&str> = lines[0].split('\t').collect();
                 if parts.len() >= 3 {
                     if let Ok(port) = parts[2].parse::<u32>() {
                         tunnel.interface.listen_port = port;
                     }
                 }
            }

            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split('\t').collect();
                if parts.len() >= 7 {
                    tunnel.peer.endpoint = parts[2].to_string();
                    tunnel.peer.latest_handshake = parts[4].to_string(); 
                    tunnel.peer.transfer.rx = parts[5].to_string();   
                    tunnel.peer.transfer.tx = parts[6].to_string();   
                }
            }
        }
    }
}

#[tauri::command]
fn get_tunnels(state: State<AppState>) -> Vec<Tunnel> {
    let mut tunnels = state.tunnels.lock().unwrap();
    let mut dirty = false;
    
    for tunnel in tunnels.iter_mut() {
        let is_running = check_service_exists(tunnel);
        if tunnel.active != is_running {
            tunnel.active = is_running;
            dirty = true;
        }
        
        if tunnel.active {
            update_tunnel_stats(tunnel);
        }
    }
    
    if dirty {
        save_tunnels_to_disk(&tunnels);
    }

    tunnels.clone()
}

#[tauri::command]
fn toggle_tunnel(id: String, state: State<AppState>) -> Result<Vec<Tunnel>, String> {
    let mut tunnels = state.tunnels.lock().unwrap();
    
    if let Some(index) = tunnels.iter().position(|t| t.id == id) {
        let tunnel_active = tunnels[index].active;
        let tunnel = &tunnels[index];

        if tunnel_active {
            uninstall_tunnel_service(&tunnel.name)?;
            tunnels[index].active = false;
        } else {
            if !Path::new(WIREGUARD_EXE).exists() {
                return Err("WireGuard is not installed or not found at default location.".to_string());
            }

            install_tunnel_service(tunnel)?;
            tunnels[index].active = true;
        }
    }
    
    save_tunnels_to_disk(&tunnels);
    Ok(tunnels.clone())
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn save_tunnel(tunnel: Tunnel, state: State<AppState>) -> Result<Vec<Tunnel>, String> {
    let mut tunnels = state.tunnels.lock().unwrap();
    if let Some(index) = tunnels.iter().position(|t| t.id == tunnel.id) {
        tunnels[index] = tunnel;
    } else {
        tunnels.push(tunnel);
    }
    save_tunnels_to_disk(&tunnels);
    Ok(tunnels.clone())
}

#[tauri::command]
fn open_wireguard_log() -> Result<(), String> {
    if !Path::new(WIREGUARD_EXE).exists() {
        return Err("WireGuard not found".into());
    }
    Command::new(WIREGUARD_EXE)
        .arg("/showlog")
        .spawn()
        .map_err(|e| format!("Failed to open log: {}", e))?;
    Ok(())
}

#[tauri::command]
fn get_wg_show(tunnel_name: String) -> String {
    let interface_name = get_service_name(&tunnel_name);
    let mut combined_output = String::new();

    if Path::new(WG_EXE).exists() {
        let wg_output = Command::new(WG_EXE)
            .arg("show")
            .arg(&interface_name)
            .creation_flags(0x08000000)
            .output();

        if let Ok(o) = wg_output {
            if o.status.success() {
                combined_output.push_str("--- Interface Status ---\n");
                combined_output.push_str(&String::from_utf8_lossy(&o.stdout));
                combined_output.push_str("\n\n");
            }
        }
    }

    if Path::new(WIREGUARD_EXE).exists() {
        let log_output = Command::new(WIREGUARD_EXE)
            .arg("/dumplog")
            .creation_flags(0x08000000)
            .output();

        if let Ok(o) = log_output {
            combined_output.push_str("--- Service Log (from wireguard.exe /dumplog) ---\n");
            let full_log = String::from_utf8_lossy(&o.stdout); 
            combined_output.push_str(&full_log);
            
            if !o.stderr.is_empty() {
                 let stderr = String::from_utf8_lossy(&o.stderr);
                 if stderr.contains("Access is denied") {
                     combined_output.push_str("\n[System Info]: Log file access denied.\nTo view internal WireGuard logs here, please run DarkGuard as Administrator.\n(Or use the 'Open System Log Window' button above)");
                 } else {
                     combined_output.push_str("\n--- Stderr ---\n");
                     combined_output.push_str(&stderr);
                 }
            }
        } else {
             combined_output.push_str("\nFailed to read service logs.");
        }
    }

    if combined_output.is_empty() {
        return "No status or logs available.".to_string();
    }

    combined_output
}

#[tauri::command]
async fn check_wireguard_installation() -> bool {
   Path::new(WIREGUARD_EXE).exists()
}

#[tauri::command]
async fn install_wireguard_dependency() -> Result<String, String> {
    let url = "https://download.wireguard.com/windows-client/wireguard-amd64-0.5.3.msi";
    let temp_dir = std::env::temp_dir();
    let msi_path = temp_dir.join("wireguard_installer.msi");

    let download_cmd = format!("Invoke-WebRequest -Uri '{}' -OutFile '{}'", url, msi_path.display());
    let download = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&download_cmd)
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("Failed to run download command: {}", e))?;
        
    if !download.status.success() {
        return Err(format!("Download failed: {}", String::from_utf8_lossy(&download.stderr)));
    }

    let install_ps = format!("Start-Process msiexec.exe -ArgumentList '/i \"{}\" /qn' -Verb RunAs -Wait", msi_path.display());
    let install = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&install_ps)
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("Failed to trigger installation: {}", e))?;

    if !install.status.success() {
         return Err(format!("Installer launch failed: {}", String::from_utf8_lossy(&install.stderr)));
    }

    Ok("Installation started. Please wait for the WireGuard icon to appear or wait ~30 seconds.".to_string())
}

fn validate_keys(tunnel: &Tunnel) -> Result<(), String> {
    let decoded = general_purpose::STANDARD.decode(&tunnel.interface.private_key)
       .map_err(|_| "Invalid Private Key (Base64 error). Please check for missing '=' padding.".to_string())?;
    
    if decoded.len() != 32 {
        return Err(format!("Invalid Private Key length: {} bytes. Expected 32. Key might be truncated.", decoded.len()));
    }
    Ok(())
}


#[tauri::command]
fn generate_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        general_purpose::STANDARD.encode(secret.to_bytes()), 
        general_purpose::STANDARD.encode(public.as_bytes())
    )
}

#[tauri::command]
fn calculate_public_key(private_key: String) -> Result<String, String> {
    let decoded = general_purpose::STANDARD
        .decode(&private_key)
        .map_err(|e| format!("Invalid base64: {}", e))?;
        
    if decoded.len() != 32 {
         return Err("Private key must be 32 bytes".to_string());
    }
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    
    Ok(general_purpose::STANDARD.encode(public.as_bytes()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let initial_tunnels = load_tunnels_from_disk();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let quit_i = MenuItem::with_id(app, "quit", "Quit DarkGuard", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "quit" => {
                            app.exit(0);
                        }
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .icon(app.default_window_icon().unwrap().clone())
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();

                let _ = window.app_handle().notification()
                    .builder()
                    .title("DarkGuard")
                    .body("DarkGuard gets minimized to system tray.")
                    .show();
                api.prevent_close();
            }
        })
        .manage(AppState {
            tunnels: Mutex::new(initial_tunnels),
        })
        .invoke_handler(tauri::generate_handler![
            greet, 
            get_tunnels, 
            toggle_tunnel, 
            save_tunnel,
            generate_keypair,
            calculate_public_key,
            open_wireguard_log,
            get_wg_show,
            check_wireguard_installation,
            install_wireguard_dependency
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
