import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { 
  Plus, 
  FolderDown, 
  X, 
  ChevronDown, 
  FileText,
  MoreHorizontal
} from "lucide-react";
import "./App.css";
import "./app_status.css";

interface Tunnel {
  id: string;
  name: string;
  active: boolean;
  interface: {
    private_key: string;
    public_key: string;
    mtu: number;
    addresses: string[];
    dns_servers: string[];
    listen_port: number;
  };
  peer: {
    public_key: string;
    allowed_ips: string[];
    endpoint: string;
    latest_handshake: string;
    transfer: { rx: string; tx: string };
  };
}


const DEFAULT_TUNNEL: Tunnel = {
  id: "",
  name: "New Tunnel",
  active: false,
  interface: {
    private_key: "",
    public_key: "",
    mtu: 1420,
    addresses: [],
    dns_servers: [],
    listen_port: 51820
  },
  peer: {
    public_key: "",
    allowed_ips: ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
    endpoint: "",
    latest_handshake: "Never",
    transfer: { rx: "0 B", tx: "0 B" }
  }
};

function App() {
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [selectedTunnelId, setSelectedTunnelId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'tunnels' | 'log'>('tunnels');
  const [isAddMenuOpen, setIsAddMenuOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editForm, setEditForm] = useState<Tunnel | null>(null);
  const [configContent, setConfigContent] = useState("");

  useEffect(() => {
    checkWireGuard();
    fetchTunnels();
  }, []);

  async function checkWireGuard() {
      try {
          const installed = await invoke<boolean>("check_wireguard_installation");
          if (!installed) {
              const confirm = await window.confirm(
                  "WireGuard dependency is missing.\n\nDarkGuard requires the official WireGuard Windows client to function.\n\nClick OK to download and install it automatically (Administrator rights required)."
              );
              if (confirm) {
                  installWireGuard();
              }
          }
      } catch (e) {
          console.error("Failed to check WG:", e);
      }
  }

  async function installWireGuard() {
      try {
          alert("Downloading WireGuard... The installation window may appear or happen silently. Please approve the Admin Prompt.");
          const res = await invoke<string>("install_wireguard_dependency");
          alert(res);
      } catch (e) {
          alert("Failed to install: " + e);
      }
  }

  useEffect(() => {
    if (editForm?.interface.private_key && editForm.interface.private_key.length > 40) {
      const timeoutId = setTimeout(() => {
        invoke<string>("calculate_public_key", { privateKey: editForm.interface.private_key })
          .then(pubKey => {
            setEditForm(prev => {
              if (!prev) return null;
              if (prev.interface.public_key === pubKey) return prev;
              return { ...prev, interface: { ...prev.interface, public_key: pubKey } };
            });
          })
          .catch(() => {});
      }, 500);
      return () => clearTimeout(timeoutId);
    }
  }, [editForm?.interface.private_key]);


  async function fetchTunnels() {
    try {
      const result = await invoke<Tunnel[]>("get_tunnels");
      setTunnels(result);
      if (!selectedTunnelId && result.length > 0) {
        setSelectedTunnelId(result[0].id);
      }
    } catch (error) {
      console.error("Failed to fetch tunnels:", error);
    }
  }

  const selectedTunnel = tunnels.find(t => t.id === selectedTunnelId);

  async function toggleTunnel(id: string, e?: React.MouseEvent) {
    e?.stopPropagation(); 
    try {
      const updatedTunnels = await invoke<Tunnel[]>("toggle_tunnel", { id });
      setTunnels(updatedTunnels);
    } catch (error) {
      console.error("Failed to toggle tunnel:", error);
      alert("Failed to toggle tunnel: " + error);
    }
  }

  const handleEditClick = () => {
    if (selectedTunnel) {
      const tunnel = { ...selectedTunnel };
      setEditForm(tunnel);
      setConfigContent(generateConfig(tunnel));
      setIsEditModalOpen(true);
    }
  };

  const handleCreateEmptyClick = async () => {
    try {
      const [priv, pub] = await invoke<[string, string]>("generate_keypair");
      const newTunnel = { 
          ...DEFAULT_TUNNEL, 
          id: crypto.randomUUID(), 
          name: `tunnel-${tunnels.length + 1}`,
          interface: { 
              ...DEFAULT_TUNNEL.interface, 
              private_key: priv,
              public_key: pub 
          },
      };
      setEditForm(newTunnel);
      setConfigContent(generateConfig(newTunnel));
      setIsEditModalOpen(true);
      setIsAddMenuOpen(false);
    } catch (e) {
      console.error("Failed to generate keys", e);
      const newTunnel = { ...DEFAULT_TUNNEL, id: crypto.randomUUID(), name: `tunnel-${tunnels.length + 1}` };
      setEditForm(newTunnel);
      setConfigContent(generateConfig(newTunnel));
      setIsEditModalOpen(true);
      setIsAddMenuOpen(false);
    }
  };

  const saveTunnel = async () => {
    if (editForm) {
       try {
         const updatedTunnels = await invoke<Tunnel[]>("save_tunnel", { tunnel: editForm });
         setTunnels(updatedTunnels);
         setSelectedTunnelId(editForm.id); 
         setIsEditModalOpen(false);
       } catch(err) {
         console.error("Failed to save tunnel", err);
       }
    }
  };

  const parseConfigIntoForm = (config: string) => {
      if (!editForm) return;
      const newInterface = { ...editForm.interface };
      const newPeer = { ...editForm.peer };
      
      const lines = config.split('\n');
      let currentSection = '';
      
      for(const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
              currentSection = trimmed.slice(1, -1);
              continue;
          }
          if (trimmed.includes('=')) {
              const parts = trimmed.split('=');
              const key = parts[0].trim();
              const value = parts.slice(1).join('=').trim();
              
              if (currentSection === 'Interface') {
                 if (key === 'PrivateKey') newInterface.private_key = value;
                 if (key === 'PublicKey') newInterface.public_key = value; 
                 if (key === 'Address') newInterface.addresses = value.split(',').map(s => s.trim());
                 if (key === 'DNS') newInterface.dns_servers = value.split(',').map(s => s.trim());
                 if (key === 'MTU') newInterface.mtu = parseInt(value) || 1420;
              } else if (currentSection === 'Peer') {
                 if (key === 'PublicKey') newPeer.public_key = value;
                 if (key === 'AllowedIPs') newPeer.allowed_ips = value.split(',').map(s => s.trim());
                 if (key === 'Endpoint') newPeer.endpoint = value;
              }
          }
      }
      setEditForm({ ...editForm, interface: newInterface, peer: newPeer });
  };

  const addMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (addMenuRef.current && !addMenuRef.current.contains(event.target as Node)) {
        setIsAddMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [addMenuRef]);
const toggleKillSwitch = (e: React.ChangeEvent<HTMLInputElement>) => {
      if (!editForm) return;
      const enable = e.target.checked;
      const newPeer = { ...editForm.peer };
      
      if (enable) {
          newPeer.allowed_ips = ["0.0.0.0/0", "::/0"];
      } else {
          newPeer.allowed_ips = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];
      }
      
      const newTunnel = { ...editForm, peer: newPeer };
      setEditForm(newTunnel);
      setConfigContent(generateConfig(newTunnel));
  };

  const isKillSwitchEnabled = editForm?.peer.allowed_ips.join(', ') === "0.0.0.0/0, ::/0";

  useEffect(() => {
    let intervalId: any;
    if (tunnels.some(t => t.active)) {
      intervalId = setInterval(() => {
        fetchTunnels();
      }, 1000);
    }
    return () => {
       if (intervalId) clearInterval(intervalId);
    };
  }, [tunnels.some(t => t.active)]);

  const [logContent, setLogContent] = useState<string>("");

  useEffect(() => {
    if (activeTab === 'log' && selectedTunnelId) {
       const tunnel = tunnels.find(t => t.id === selectedTunnelId);
       if(tunnel) {
           invoke<string>("get_wg_show", { tunnelName: tunnel.name }).then(setLogContent);
           const interval = setInterval(() => {
             invoke<string>("get_wg_show", { tunnelName: tunnel.name }).then(setLogContent);
           }, 1000);
           return () => clearInterval(interval);
       }
    }
  }, [activeTab, selectedTunnelId]);

  async function openSystemLog() {
      try {
          await invoke("open_wireguard_log");
      } catch(e) { console.error(e); }
  }

  return (
    <div className="container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="tabs">
          <button 
            className={`tab-btn ${activeTab === 'tunnels' ? 'active' : ''}`}
            onClick={() => setActiveTab('tunnels')}
          >
            Tunnels
          </button>
          <button 
            className={`tab-btn ${activeTab === 'log' ? 'active' : ''}`}
            onClick={() => setActiveTab('log')}
          >
            Log
          </button>
        </div>

        {activeTab === 'tunnels' ? (
          <div className="tunnel-list">
            {tunnels.map(tunnel => (
              <div 
                key={tunnel.id}
                className={`tunnel-item ${selectedTunnelId === tunnel.id ? 'selected' : ''}`}
                onClick={() => setSelectedTunnelId(tunnel.id)}
              >
                <div className={`status-indicator ${tunnel.active ? 'active' : ''}`}>
                   {tunnel.active && <div className="status-dot"></div>}
                </div>
                <span className="tunnel-name">{tunnel.name}</span>
              </div>
            ))}
          </div>
        ) : (
           <div className="log-sidebar-placeholder"></div>
        )}

        <div className="sidebar-footer">
          <div className="add-tunnel-wrapper" ref={addMenuRef}>
            <button 
              className="footer-btn add-btn"
              onClick={() => setIsAddMenuOpen(!isAddMenuOpen)}
            >
              <Plus size={14} />
            </button>
            <button className="footer-btn chevron-btn" onClick={() => setIsAddMenuOpen(!isAddMenuOpen)}>
                 <ChevronDown size={12} />
            </button>
            
            {isAddMenuOpen && (
              <div className="dropdown-menu">
                <div className="dropdown-item">
                  <FolderDown size={14} />
                  <span>Import tunnel(s) from file...</span>
                  <span className="shortcut">Ctrl+O</span>
                </div>
                <div className="dropdown-item" onClick={handleCreateEmptyClick}>
                  <FileText size={14} />
                  <span>Add empty tunnel...</span>
                  <span className="shortcut">Ctrl+N</span>
                </div>
              </div>
            )}
          </div>

          <button className="footer-btn icon-only remove-btn" title="Delete selected">
            <span className="minus-icon">−</span>
          </button>
          
          <div style={{flex: 1}}></div>

          <button className="footer-btn icon-only" title="More actions">
             <div className="circle-btn">
                <MoreHorizontal size={12} />
             </div>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="main-content">
        {activeTab === 'tunnels' && selectedTunnel ? (
          <div className="details-container">
            <div className="panel interface-panel">
              
                <div className="property-grid">
                  <div className="label">Status:</div>
                  <div className="value status-row">
                    <div className={`status-circle ${selectedTunnel.active ? 'active' : 'inactive'}`}></div>
                    <span>{selectedTunnel.active ? 'Active' : 'Inactive'}</span>
                  </div>

                  <div className="label">Public key:</div>
                  <div className="value code">{selectedTunnel.interface.public_key || "None"}</div>

                  <div className="label">MTU:</div>
                  <div className="value">{selectedTunnel.interface.mtu}</div>

                  <div className="label">Addresses:</div>
                  <div className="value">{selectedTunnel.interface.addresses.length > 0 ? selectedTunnel.interface.addresses.join(', ') : "(none)"}</div>

                  <div className="label">DNS servers:</div>
                  <div className="value">{selectedTunnel.interface.dns_servers.length > 0 ? selectedTunnel.interface.dns_servers.join(', ') : "(none)"}</div>
                  
                  <div className="label"></div>
                  <div className="value actions-row">
                    <button 
                      className="macos-btn primary-action"
                      onClick={() => toggleTunnel(selectedTunnel.id)}
                    >
                      {selectedTunnel.active ? 'Deactivate' : 'Activate'}
                    </button>
                  </div>
                </div>
            </div>

            <div className="panel peer-panel">
              <div className="panel-header">
                <h3>Peer</h3>
              </div>
              
                <div className="property-grid">
                  <div className="label">Public key:</div>
                  <div className="value code">{selectedTunnel.peer.public_key || "None"}</div>

                  <div className="label">Allowed IPs:</div>
                  <div className="value">{selectedTunnel.peer.allowed_ips.join(', ')}</div>

                  <div className="label">Endpoint:</div>
                  <div className="value">{selectedTunnel.peer.endpoint || "(none)"}</div>

                  <div className="label">Persistent keepalive:</div>
                  <div className="value">every 25 seconds</div> 

                  {selectedTunnel.active && (
                    <>
                      <div className="label">Latest handshake:</div>
                      <div className={`value ${selectedTunnel.peer.latest_handshake === '0' ? 'warning-text' : ''}`}>
                          {formatHandshake(selectedTunnel.peer.latest_handshake)}
                          {selectedTunnel.peer.latest_handshake === '0' && (
                              <div className="status-tip">
                                  ⚠️ Tunnel is running but not connected. Check keys & firewall.
                              </div>
                          )}
                      </div>
                      
                      <div className="label">Transfer:</div>
                      <div className="value">
                        {formatBytes(selectedTunnel.peer.transfer.rx)} received, {formatBytes(selectedTunnel.peer.transfer.tx)} sent
                      </div>
                    </>
                  )}
                </div>
            </div>
            
            <div className="spacer"></div>

            <div className="main-footer">
               <div className="on-demand-row">
                  <label>On-Demand:</label>
                  <span>Off</span>
               </div>
               <button className="macos-btn" onClick={handleEditClick}>
                  Edit
               </button>
            </div>
          </div>
        ) : activeTab === 'log' ? (
          <div className="log-view" style={{display: 'flex', flexDirection: 'column', height: '100%'}}>
             <div className="log-header-bar" style={{padding: '10px', borderBottom: '1px solid #333', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                <div className="log-title" style={{color:'#fff', fontWeight:600}}>System Log</div>
                <button className="macos-btn small" onClick={openSystemLog}>Open System Log Window</button>
             </div>
             <div className="log-content" style={{flex: 1, padding: '10px', overflow: 'auto', fontFamily: 'monospace', fontSize: '12px', color: '#ccc'}}>
                 {selectedTunnel ? (
                     <>
                        <div style={{marginBottom: '10px', color: '#aaa'}}>Status for: {selectedTunnel.name}</div>
                        <pre>{logContent || "No info available (tunnel might be inactive)"}</pre>
                     </>
                 ) : (
                     <div>Select a tunnel to view status.</div>
                 )}
             </div>
          </div>
        ) : (
           <div className="empty-state">
              <p>No tunnels defined</p>
              <button className="macos-btn" onClick={handleCreateEmptyClick}>Create Tunnel</button>
           </div>
        )}
      </div>

       {/* Edit Modal */}
       {isEditModalOpen && editForm && (
        <div className="modal-overlay">
          <div className="modal-content large">
            <div className="modal-header">
               <div className="modal-title-row">
                  <FileText size={16} /> 
                  <h2>Edit tunnel</h2>
               </div>
               <button className="close-btn" onClick={() => setIsEditModalOpen(false)}><X size={16}/></button>
            </div>
            <div className="modal-body-wrapper">
               <div className="meta-row">
                  <label>Name:</label>
                  <input type="text" value={editForm.name} onChange={(e) => setEditForm({...editForm, name: e.target.value})} />
               </div>
               <div className="meta-row">
                  <label>Public key:</label>
                  <input type="text" readOnly value={editForm.interface.public_key} className="readonly-input" />
               </div>
               
               <div className="config-editor">
                  <textarea 
                    spellCheck={false}
                    value={configContent}
                    onChange={(e) => {
                        setConfigContent(e.target.value);
                        parseConfigIntoForm(e.target.value);
                    }}
                  ></textarea>
               </div>
               
            </div>
            <div className="modal-footer" style={{justifyContent: "space-between"}}>
               <div className="checkbox-row" style={{marginLeft: 0}}>
                  <input type="checkbox" id="killswitch" checked={!!isKillSwitchEnabled} onChange={toggleKillSwitch} />
                  <label htmlFor="killswitch">Block untunneled traffic (kill-switch)</label>
               </div>
               <div style={{display: "flex", gap: "10px"}}>
                   <button className="macos-btn small" onClick={() => setIsEditModalOpen(false)}>Cancel</button>
                   <button className="macos-btn small primary-action" onClick={saveTunnel}>Save</button>
               </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

function generateConfig(tunnel: Tunnel): string {
    let config = `[Interface]\n`;
    config += `PrivateKey = ${tunnel.interface.private_key || ""}\n`;
    if (tunnel.interface.addresses.length) config += `Address = ${tunnel.interface.addresses.join(', ')}\n`;
    if (tunnel.interface.dns_servers.length) config += `DNS = ${tunnel.interface.dns_servers.join(', ')}\n`;
    if (tunnel.interface.mtu) config += `MTU = ${tunnel.interface.mtu}\n`;
    
    config += `\n[Peer]\n`;
    config += `PublicKey = ${tunnel.peer.public_key}\n`;
    if (tunnel.peer.allowed_ips.length) config += `AllowedIPs = ${tunnel.peer.allowed_ips.join(', ')}\n`;
    if (tunnel.peer.endpoint) config += `Endpoint = ${tunnel.peer.endpoint}\n`;
    
    return config;
}

function formatBytes(bytesStr: string | number): string {
    const bytes = Number(bytesStr);
    if (!bytes || isNaN(bytes)) return "0 B";
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KiB", "MiB", "GiB", "TiB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatHandshake(timestampStr: string): string {
    const ts = Number(timestampStr);
    if (!ts || isNaN(ts) || ts === 0) return "None (No Connection)";
    
    const now = Math.floor(Date.now() / 1000);
    const diff = now - ts;
    
    if (diff < 0) return "Now"; 
    if (diff > 180) return `${Math.floor(diff / 60)} mins ago (Stalled)`; 

    if (diff < 60) return `${diff} second${diff === 1 ? '' : 's'} ago`;
    if (diff < 3600) {
        const mins = Math.floor(diff / 60);
        return `${mins} minute${mins === 1 ? '' : 's'} ago`;
    }
    const hours = Math.floor(diff / 3600);
    return `${hours} hour${hours === 1 ? '' : 's'} ago`;
}

export default App;
