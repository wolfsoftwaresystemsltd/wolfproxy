//! Monitoring module for WolfProxy
//! Provides a web interface to monitor upstream servers and traffic

use axum::{
    extract::State,
    http::{StatusCode, HeaderMap, header},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::upstream::UpstreamManager;

/// Traffic statistics
#[derive(Debug, Default)]
pub struct TrafficStats {
    /// Total requests received
    pub total_requests: AtomicU64,
    /// Total bytes received from clients
    pub bytes_in: AtomicU64,
    /// Total bytes sent to clients
    pub bytes_out: AtomicU64,
    /// Requests per upstream
    pub upstream_requests: dashmap::DashMap<String, AtomicU64>,
    /// Start time
    pub start_time: Option<Instant>,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            upstream_requests: dashmap::DashMap::new(),
            start_time: Some(Instant::now()),
        }
    }

    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_bytes_in(&self, bytes: u64) {
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_bytes_out(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_upstream_request(&self, upstream_name: &str) {
        self.upstream_requests
            .entry(upstream_name.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn uptime(&self) -> Duration {
        self.start_time.map(|t| t.elapsed()).unwrap_or_default()
    }
}

/// Monitoring configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MonitoringConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_username")]
    pub username: String,
    #[serde(default = "default_password")]
    pub password: String,
}

fn default_enabled() -> bool { true }
fn default_port() -> u16 { 5001 }
fn default_username() -> String { "admin".to_string() }
fn default_password() -> String { "admin".to_string() }

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 5001,
            username: "admin".to_string(),
            password: "admin".to_string(),
        }
    }
}

/// Monitoring state shared with handlers
pub struct MonitoringState {
    pub upstreams: Arc<UpstreamManager>,
    pub stats: Arc<TrafficStats>,
    pub config: MonitoringConfig,
    pub vhost_count: usize,
    pub server_blocks: usize,
}

/// Check HTTP Basic Auth
fn check_auth(headers: &HeaderMap, username: &str, password: &str) -> bool {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Basic ") {
                let encoded = &auth_str[6..];
                if let Ok(decoded) = BASE64.decode(encoded) {
                    if let Ok(credentials) = String::from_utf8(decoded) {
                        let expected = format!("{}:{}", username, password);
                        return credentials == expected;
                    }
                }
            }
        }
    }
    false
}

/// Response requiring authentication
fn require_auth() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"WolfProxy Monitoring\"")
        .body(axum::body::Body::from("Authentication required"))
        .unwrap()
}

/// Format bytes into human readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration into human readable string
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Main monitoring page handler
async fn monitoring_page(
    State(state): State<Arc<MonitoringState>>,
    headers: HeaderMap,
) -> Response {
    // Check authentication
    if !check_auth(&headers, &state.config.username, &state.config.password) {
        return require_auth();
    }

    let stats = &state.stats;
    let uptime = format_duration(stats.uptime());
    let total_requests = stats.total_requests.load(Ordering::Relaxed);
    let bytes_in = format_bytes(stats.bytes_in.load(Ordering::Relaxed));
    let bytes_out = format_bytes(stats.bytes_out.load(Ordering::Relaxed));

    // Build upstream servers HTML
    let mut upstream_html = String::new();
    
    for (name, lb) in state.upstreams.all() {
        upstream_html.push_str(&format!(r#"
        <div class="upstream-group">
            <h3>Upstream: {} <span class="method">{:?}</span></h3>
            <table>
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>Status</th>
                        <th>Weight</th>
                        <th>Requests</th>
                        <th>Active Conn</th>
                        <th>Failures</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
        "#, name, lb.method));

        for server in &lb.servers {
            let status_class = if server.is_available() { "status-up" } else { "status-down" };
            let status_text = if server.is_available() { "UP" } else { "DOWN" };
            let requests = server.health.total_requests.load(Ordering::Relaxed);
            let active = server.health.active_connections.load(Ordering::Relaxed);
            let failures = server.health.failures.load(Ordering::Relaxed);
            
            upstream_html.push_str(&format!(r#"
                <tr>
                    <td>{}</td>
                    <td class="{}">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>Primary</td>
                </tr>
            "#, server.url, status_class, status_text, server.config.weight, requests, active, failures));
        }

        for server in &lb.backup_servers {
            let status_class = if server.is_available() { "status-up" } else { "status-down" };
            let status_text = if server.is_available() { "UP" } else { "DOWN" };
            let requests = server.health.total_requests.load(Ordering::Relaxed);
            let active = server.health.active_connections.load(Ordering::Relaxed);
            let failures = server.health.failures.load(Ordering::Relaxed);
            
            upstream_html.push_str(&format!(r#"
                <tr>
                    <td>{}</td>
                    <td class="{}">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td class="backup">Backup</td>
                </tr>
            "#, server.url, status_class, status_text, server.config.weight, requests, active, failures));
        }

        upstream_html.push_str("</tbody></table></div>");
    }

    // Build per-upstream request counts
    let mut upstream_stats_html = String::new();
    for entry in stats.upstream_requests.iter() {
        let count = entry.value().load(Ordering::Relaxed);
        upstream_stats_html.push_str(&format!(r#"
            <tr>
                <td>{}</td>
                <td>{}</td>
            </tr>
        "#, entry.key(), count));
    }

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5">
    <title>WolfProxy Monitor</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            text-align: center;
            color: #00d4ff;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
        }}
        h2 {{
            color: #00d4ff;
            margin: 25px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #00d4ff33;
        }}
        h3 {{
            color: #4dabf7;
            margin-bottom: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #00d4ff;
        }}
        .stat-label {{
            font-size: 0.9em;
            color: #888;
            margin-top: 5px;
            text-transform: uppercase;
        }}
        .upstream-group {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        th {{
            background: rgba(0, 212, 255, 0.1);
            color: #00d4ff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
        }}
        tr:hover {{
            background: rgba(255, 255, 255, 0.03);
        }}
        .status-up {{
            color: #51cf66;
            font-weight: bold;
        }}
        .status-down {{
            color: #ff6b6b;
            font-weight: bold;
        }}
        .backup {{
            color: #ffa94d;
        }}
        .method {{
            font-size: 0.7em;
            background: rgba(0, 212, 255, 0.2);
            padding: 3px 8px;
            border-radius: 5px;
            margin-left: 10px;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        .logo {{
            font-family: monospace;
            white-space: pre;
            font-size: 0.7em;
            color: #00d4ff;
            text-align: center;
            margin-bottom: 20px;
            line-height: 1.2;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
 __          ______  _      ______ _____  _____   ______   ____     __
 \ \        / / __ \| |    |  ____|  __ \|  __ \ / __ \ \ / /\ \   / /
  \ \  /\  / / |  | | |    | |__  | |__) | |__) | |  | \ V /  \ \_/ / 
   \ \/  \/ /| |  | | |    |  __| |  ___/|  _  /| |  | |> <    \   /  
    \  /\  / | |__| | |____| |    | |    | | \ \| |__| / . \    | |   
     \/  \/   \____/|______|_|    |_|    |_|  \_\\____/_/ \_\   |_|   
        </div>
        <h1>🐺 WolfProxy Monitor</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Uptime</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Data In</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Data Out</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Virtual Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Server Blocks</div>
            </div>
        </div>

        <h2>🔄 Upstream Servers</h2>
        {}

        <h2>📊 Traffic by Upstream</h2>
        <table>
            <thead>
                <tr>
                    <th>Upstream</th>
                    <th>Requests</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>

        <div class="footer">
            (C)2025 Wolf Software Systems Ltd - <a href="http://wolf.uk.com" style="color: #00d4ff;">wolf.uk.com</a>
            <br>
            Auto-refresh: 5 seconds
        </div>
    </div>
</body>
</html>"#, 
        uptime,
        total_requests,
        bytes_in,
        bytes_out,
        state.vhost_count,
        state.server_blocks,
        upstream_html,
        upstream_stats_html
    );

    Html(html).into_response()
}

/// JSON API endpoint for stats
async fn stats_json(
    State(state): State<Arc<MonitoringState>>,
    headers: HeaderMap,
) -> Response {
    // Check authentication
    if !check_auth(&headers, &state.config.username, &state.config.password) {
        return require_auth();
    }

    let stats = &state.stats;
    
    let mut upstream_stats: HashMap<String, serde_json::Value> = HashMap::new();
    
    for (name, lb) in state.upstreams.all() {
        let mut servers = Vec::new();
        
        for server in lb.servers.iter().chain(lb.backup_servers.iter()) {
            servers.push(serde_json::json!({
                "url": server.url,
                "address": server.config.address,
                "port": server.config.port,
                "weight": server.config.weight,
                "available": server.is_available(),
                "backup": server.config.backup,
                "down": server.config.down,
                "requests": server.health.total_requests.load(Ordering::Relaxed),
                "active_connections": server.health.active_connections.load(Ordering::Relaxed),
                "failures": server.health.failures.load(Ordering::Relaxed),
            }));
        }
        
        upstream_stats.insert(name.clone(), serde_json::json!({
            "method": format!("{:?}", lb.method),
            "servers": servers,
        }));
    }

    let response = serde_json::json!({
        "uptime_seconds": stats.uptime().as_secs(),
        "total_requests": stats.total_requests.load(Ordering::Relaxed),
        "bytes_in": stats.bytes_in.load(Ordering::Relaxed),
        "bytes_out": stats.bytes_out.load(Ordering::Relaxed),
        "vhost_count": state.vhost_count,
        "server_blocks": state.server_blocks,
        "upstreams": upstream_stats,
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(serde_json::to_string_pretty(&response).unwrap()))
        .unwrap()
}

/// Create the monitoring router
pub fn create_monitoring_router(state: Arc<MonitoringState>) -> Router {
    Router::new()
        .route("/", get(monitoring_page))
        .route("/stats", get(stats_json))
        .with_state(state)
}

/// Start the monitoring server
pub async fn start_monitoring_server(
    host: &str,
    config: MonitoringConfig,
    upstreams: Arc<UpstreamManager>,
    stats: Arc<TrafficStats>,
    vhost_count: usize,
    server_blocks: usize,
) {
    if !config.enabled {
        tracing::info!("Monitoring server disabled");
        return;
    }

    let port = config.port;
    let state = Arc::new(MonitoringState {
        upstreams,
        stats,
        config,
        vhost_count,
        server_blocks,
    });

    let app = create_monitoring_router(state);
    
    let addr: std::net::SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    
    tracing::info!("WolfProxy monitoring server listening on http://{}", addr);
    
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("Monitoring server error: {}", e);
            }
        }
        Err(e) => {
            tracing::error!("Failed to bind monitoring server to {}: {}", addr, e);
        }
    }
}
