//! WolfProxy - A Rust-based nginx proxy replacement
//! 
//! This server reads nginx configuration files from sites-enabled
//! and provides reverse proxy functionality with automatic SSL support.
//!
//! (C) 2025 Wolf Software Systems Ltd - http://wolf.uk.com

use axum::{
    extract::{Request, State, ConnectInfo},
    http::{StatusCode, HeaderMap, HeaderValue, header, Uri, Method},
    response::{Response, IntoResponse},
    routing::any,
    Router,
    body::Body,
};
use tower::Service;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::fs::File;
use std::io::BufReader;

use tokio::fs;
use tokio::time::Duration;

use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use http_body_util::{BodyExt, Full};
use bytes::Bytes;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;
use futures_util::future::join_all;

use serde::Deserialize;
use tracing::{info, warn, error, debug};
use regex::Regex;

mod nginx;
mod upstream;

use nginx::{NginxConfig, ServerBlock, LocationBlock, ProxyHeader, RewriteFlag, IfCondition};
use upstream::UpstreamManager;

use hyper_util::rt::TokioIo;

/// Marker for HTTPS connections
#[derive(Clone, Copy, Debug)]
pub struct IsHttps(pub bool);

/// Tower to Hyper service adapter
#[derive(Clone)]
pub struct TowerToHyperService<S> {
    service: S,
}

impl<S, R> hyper::service::Service<R> for TowerToHyperService<S>
where
    S: tower::Service<R> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, req: R) -> Self::Future {
        self.service.clone().call(req)
    }
}

/// SSL Certificate resolver for SNI
#[derive(Debug)]
struct ServerCertResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
    default_cert: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(sni_hostname) = client_hello.server_name() {
            if let Some(cert) = self.certs.get(sni_hostname) {
                return Some(cert.clone());
            }
            // Try wildcard match
            let parts: Vec<&str> = sni_hostname.split('.').collect();
            if parts.len() >= 2 {
                let wildcard = format!("*.{}", parts[1..].join("."));
                if let Some(cert) = self.certs.get(&wildcard) {
                    return Some(cert.clone());
                }
            }
        }
        self.default_cert.clone()
    }
}

/// Load SSL certificates
fn load_ssl_keys(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertifiedKey> {
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let key_file = &mut BufReader::new(File::open(key_path)?);

    let cert_chain = rustls_pemfile::certs(cert_file)
        .collect::<Result<Vec<_>, _>>()?;
    
    let mut keys = Vec::new();
    for item in rustls_pemfile::read_all(key_file) {
        match item? {
            rustls_pemfile::Item::Pkcs1Key(key) => keys.push(key.into()),
            rustls_pemfile::Item::Pkcs8Key(key) => keys.push(key.into()),
            rustls_pemfile::Item::Sec1Key(key) => keys.push(key.into()),
            _ => {},
        }
    }
        
    if keys.is_empty() {
        anyhow::bail!("No private keys found in {}", key_path.display());
    }
    
    let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&keys[0])
        .map_err(|_| anyhow::anyhow!("Invalid private key"))?;
        
    Ok(CertifiedKey::new(cert_chain, key))
}

/// Configuration file for wolfproxy
#[derive(Debug, Clone, Deserialize)]
struct Config {
    server: ServerConfig,
    nginx: NginxConfigSettings,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct ServerConfig {
    host: String,
    #[serde(default = "default_http_port")]
    http_port: u16,
    #[serde(default = "default_https_port")]
    https_port: u16,
}

fn default_http_port() -> u16 { 80 }
fn default_https_port() -> u16 { 443 }

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct NginxConfigSettings {
    #[serde(default = "default_nginx_dir")]
    config_dir: String,
    #[serde(default)]
    auto_reload: bool,
}

fn default_nginx_dir() -> String {
    "/etc/nginx".to_string()
}

impl Default for NginxConfigSettings {
    fn default() -> Self {
        Self {
            config_dir: default_nginx_dir(),
            auto_reload: false,
        }
    }
}

/// Virtual host with resolved configuration
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct VirtualHost {
    server_names: Vec<String>,
    port: u16,
    ssl: bool,
    locations: Vec<LocationBlock>,
    root: Option<PathBuf>,
    index: Vec<String>,
    if_conditions: Vec<IfCondition>,
    error_pages: HashMap<u16, String>,
    default_server: bool,
    proxy_headers: Vec<ProxyHeader>,
    client_max_body_size: Option<u64>,
}

impl VirtualHost {
    fn from_server_block(block: &ServerBlock) -> Vec<Self> {
        let mut vhosts = Vec::new();
        
        // Group by port
        let mut ports: HashMap<u16, bool> = HashMap::new();
        for listen in &block.listen {
            ports.insert(listen.port, listen.ssl);
        }
        
        for (port, ssl) in ports {
            vhosts.push(VirtualHost {
                server_names: block.server_names.clone(),
                port,
                ssl,
                locations: block.locations.clone(),
                root: block.root.clone(),
                index: if block.index.is_empty() {
                    vec!["index.html".to_string(), "index.htm".to_string()]
                } else {
                    block.index.clone()
                },
                if_conditions: block.if_conditions.clone(),
                error_pages: block.error_pages.clone(),
                default_server: block.default_server,
                proxy_headers: block.proxy_headers.clone(),
                client_max_body_size: block.client_max_body_size,
            });
        }
        
        vhosts
    }
}

/// Application state
#[allow(dead_code)]
struct AppState {
    config: Config,
    nginx_config: NginxConfig,
    vhosts: HashMap<String, VirtualHost>,
    default_vhosts: HashMap<u16, VirtualHost>,
    upstreams: UpstreamManager,
    http_client: HyperClient<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
}

/// Check if error is a common connection error (for logging purposes)
fn is_common_connection_error(err: &dyn std::error::Error) -> bool {
    let s = format!("{:?}", err);
    s.contains("BrokenPipe") || 
    s.contains("ConnectionReset") || 
    s.contains("UnexpectedEof") ||
    s.contains("ConnectionAborted") ||
    s.contains("NotConnected") ||
    s.contains("TimedOut") ||
    s.contains("IncompleteMessage")
}

#[tokio::main]
async fn main() {
    println!(r#"
 __          ______  _      ______ _____  _____   ______   ____     __
 \ \        / / __ \| |    |  ____|  __ \|  __ \ / __ \ \ / /\ \   / /
  \ \  /\  / / |  | | |    | |__  | |__) | |__) | |  | \ V /  \ \_/ / 
   \ \/  \/ /| |  | | |    |  __| |  ___/|  _  /| |  | |> <    \   /  
    \  /\  / | |__| | |____| |    | |    | | \ \| |__| / . \    | |   
     \/  \/   \____/|______|_|    |_|    |_|  \_\\____/_/ \_\   |_|   
                                                                      
 (C)2025 Wolf Software Systems Ltd - http://wolf.uk.com
 Nginx Proxy Replacement - Using nginx sites-enabled configuration
"#);

    tracing_subscriber::fmt::init();

    // Load configuration
    let config_str = match fs::read_to_string("wolfproxy.toml").await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Configuration file 'wolfproxy.toml' not found. Creating default.");
            let default_config = r#"[server]
host = "0.0.0.0"
http_port = 80
https_port = 443

[nginx]
config_dir = "/etc/nginx"
auto_reload = false
"#;
            fs::write("wolfproxy.toml", default_config).await.unwrap();
            default_config.to_string()
        }
    };

    let config: Config = toml::from_str(&config_str).expect("Failed to parse wolfproxy.toml");
    
    info!("Loading nginx configuration from {}", config.nginx.config_dir);
    
    // Load nginx configuration
    let nginx_config = nginx::load_nginx_sites(Path::new(&config.nginx.config_dir));
    
    info!("Loaded {} server blocks and {} upstreams", 
          nginx_config.servers.len(), 
          nginx_config.upstreams.len());
    
    // Build virtual hosts map
    let mut vhosts: HashMap<String, VirtualHost> = HashMap::new();
    let mut default_vhosts: HashMap<u16, VirtualHost> = HashMap::new();
    let mut ssl_certs: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut default_ssl_cert: Option<Arc<CertifiedKey>> = None;
    let mut http_ports: Vec<u16> = Vec::new();
    let mut https_ports: Vec<u16> = Vec::new();
    
    for server in &nginx_config.servers {
        let vhost_list = VirtualHost::from_server_block(server);
        
        for vhost in vhost_list {
            // Track ports
            if vhost.ssl {
                if !https_ports.contains(&vhost.port) {
                    https_ports.push(vhost.port);
                }
                // Remove from http_ports if it was added there
                http_ports.retain(|&p| p != vhost.port);
            } else if !http_ports.contains(&vhost.port) && !https_ports.contains(&vhost.port) {
                http_ports.push(vhost.port);
            }
            
            // Load SSL certificates
            if vhost.ssl {
                if let (Some(cert_path), Some(key_path)) = (&server.ssl.certificate, &server.ssl.certificate_key) {
                    match load_ssl_keys(cert_path, key_path) {
                        Ok(certified_key) => {
                            let cert_arc = Arc::new(certified_key);
                            for name in &vhost.server_names {
                                if name != "_" {
                                    ssl_certs.insert(name.clone(), cert_arc.clone());
                                    info!("Loaded SSL certificate for {}", name);
                                }
                            }
                            if vhost.default_server && default_ssl_cert.is_none() {
                                default_ssl_cert = Some(cert_arc.clone());
                            }
                        }
                        Err(e) => {
                            warn!("Failed to load SSL for {:?}: {}", vhost.server_names, e);
                        }
                    }
                }
            }
            
            // Register vhost
            for name in &vhost.server_names {
                if name == "_" {
                    continue;
                }
                info!("Registered VHost: {} on port {} (SSL: {})", name, vhost.port, vhost.ssl);
                vhosts.insert(format!("{}:{}", name, vhost.port), vhost.clone());
                vhosts.insert(name.clone(), vhost.clone());
            }
            
            if vhost.default_server || vhost.server_names.contains(&"_".to_string()) {
                default_vhosts.insert(vhost.port, vhost.clone());
            }
        }
    }
    
    // Build upstream manager
    let mut upstreams = UpstreamManager::new();
    for (name, upstream) in &nginx_config.upstreams {
        info!("Loaded upstream: {} with {} servers ({:?})", 
              name, upstream.servers.len(), upstream.method);
        upstreams.add_upstream(upstream);
    }
    
    // Create HTTP client for proxying
    let http_client = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(32)
        .build_http();

    let state = Arc::new(AppState {
        config: config.clone(),
        nginx_config,
        vhosts,
        default_vhosts,
        upstreams,
        http_client,
    });
    
    let app = Router::new()
        .fallback(any(handle_request))
        .with_state(state.clone());

    let mut tasks = Vec::new();
    let host_ip = config.server.host.clone();

    // Ensure we have at least the default ports
    if http_ports.is_empty() {
        http_ports.push(config.server.http_port);
    }

    // Start HTTP Listeners
    for port in http_ports {
        let addr: SocketAddr = format!("{}:{}", host_ip, port).parse().unwrap();
        let app_clone = app.clone();
        tasks.push(tokio::spawn(async move {
            info!("WolfProxy HTTP listening on {}", addr);
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app_clone.into_make_service_with_connect_info::<SocketAddr>()).await {
                        error!("HTTP server error on {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!("Failed to bind HTTP to {}: {} (try running with sudo or use ports > 1024)", addr, e);
                }
            }
        }));
    }

    // Start HTTPS Listeners
    if !https_ports.is_empty() && (!ssl_certs.is_empty() || default_ssl_cert.is_some()) {
        let resolver = Arc::new(ServerCertResolver { 
            certs: ssl_certs,
            default_cert: default_ssl_cert,
        });
        let tls_config = Arc::new(rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver));
            
        for port in https_ports {
            let addr: SocketAddr = format!("{}:{}", host_ip, port).parse().unwrap();
            let app_clone = app.clone();
            let tls_config_clone = tls_config.clone();
            
            tasks.push(tokio::spawn(async move {
                info!("WolfProxy HTTPS listening on {}", addr);
                let tls_acceptor = TlsAcceptor::from(tls_config_clone);
                let listener = match tokio::net::TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind HTTPS to {}: {} (try running with sudo or use ports > 1024)", addr, e);
                        return;
                    }
                };
                
                loop {
                    let (stream, remote_addr) = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    
                    let acceptor = tls_acceptor.clone();
                    let app = app_clone.clone();
                    
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let io = TokioIo::new(tls_stream);
                                // Create a service that injects ConnectInfo and IsHttps marker
                                let service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                                    let mut app = app.clone();
                                    async move {
                                        // Insert ConnectInfo and IsHttps extensions
                                        req.extensions_mut().insert(ConnectInfo(remote_addr));
                                        req.extensions_mut().insert(IsHttps(true));
                                        let req = Request::from(req);
                                        let resp = app.call(req).await.unwrap_or_else(|_| {
                                            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
                                        });
                                        Ok::<_, std::convert::Infallible>(resp)
                                    }
                                });
                                
                                if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                    .serve_connection(io, service)
                                    .await 
                                {
                                    if !is_common_connection_error(err.as_ref()) {
                                        error!("Error serving connection: {:?}", err);
                                    }
                                }
                            }
                            Err(e) => {
                                if !is_common_connection_error(&e) {
                                    warn!("TLS Accept Error: {}", e);
                                }
                            }
                        }
                    });
                }
            }));
        }
    }

    join_all(tasks).await;
}

/// Main request handler
async fn handle_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let uri = req.uri().clone();
    let method = req.method().clone();
    let uri_path = uri.path().to_string();
    let _query_string = uri.query().unwrap_or("").to_string();
    
    // Check if this is an HTTPS connection (marker set by HTTPS handler)
    let is_https = req.extensions().get::<IsHttps>().map(|h| h.0).unwrap_or(false);
    let scheme = if is_https { "https" } else { "http" };
    
    debug!("Request: {} {} {} from {}", scheme, method, uri_path, addr);
    
    // Safety: prevent path traversal
    if uri_path.contains("..") {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    // Get host from headers
    let host_name = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();
    
    // Find matching virtual host
    // Use port from Host header if present, otherwise default based on scheme
    let default_port = if is_https { 443 } else { 80 };
    let port = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split(':').nth(1))
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port);
    
    let vhost = state.vhosts.get(&format!("{}:{}", host_name, port))
        .or_else(|| state.vhosts.get(&host_name))
        .or_else(|| state.default_vhosts.get(&port));
    
    let vhost = match vhost {
        Some(v) => v,
        None => {
            debug!("No vhost found for {} on port {}", host_name, port);
            return (StatusCode::NOT_FOUND, "No server configured for this host").into_response();
        }
    };

    // Check if conditions at server level
    for condition in &vhost.if_conditions {
        if let Some(response) = evaluate_if_condition(condition, &host_name, &uri_path, &method, scheme) {
            return response;
        }
    }

    // Find matching location
    let location = find_matching_location(&vhost.locations, &uri_path);
    
    // Handle the request based on location configuration
    if let Some(loc) = location {
        // Check for return directive
        if let Some(code) = loc.return_code {
            if let Some(response) = handle_return(code, loc.return_value.as_deref(), &host_name, &uri_path, scheme) {
                return response;
            }
            // If handle_return returns None, continue processing (skip redirect)
        }
        
        // Check deny/allow
        if loc.deny_all {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
        
        // Check rewrites
        for rewrite in &loc.rewrites {
            if let Some(response) = apply_rewrite(rewrite, &uri_path) {
                return response;
            }
        }
        
        // Handle proxy_pass
        if let Some(proxy_pass) = &loc.proxy_pass {
            return handle_proxy(
                &state,
                req,
                headers,
                proxy_pass,
                loc,
                &vhost.proxy_headers,
                addr,
            ).await;
        }
        
        // Handle static files
        let root = loc.root.as_ref().or(vhost.root.as_ref());
        if let Some(root) = root {
            let file_path = if let Some(alias) = &loc.alias {
                // For alias, replace the location path with the alias path
                let remainder = uri_path.strip_prefix(&loc.path).unwrap_or(&uri_path);
                alias.join(remainder.trim_start_matches('/'))
            } else {
                root.join(uri_path.trim_start_matches('/'))
            };
            
            return serve_static_file(file_path, &loc.index, &vhost.index, &vhost.error_pages).await;
        }
    } else {
        // No matching location, try serving from root
        if let Some(root) = &vhost.root {
            let file_path = root.join(uri_path.trim_start_matches('/'));
            return serve_static_file(file_path, &[], &vhost.index, &vhost.error_pages).await;
        }
    }
    
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

/// Find the best matching location for a path
fn find_matching_location<'a>(locations: &'a [LocationBlock], path: &str) -> Option<&'a LocationBlock> {
    let mut best_match: Option<&LocationBlock> = None;
    let mut best_match_len = 0;
    let found_exact = false;
    let mut found_priority = false;
    
    for loc in locations {
        // Exact match
        if loc.exact && path == loc.path {
            return Some(loc);
        }
        
        // Regex match
        if loc.is_regex {
            let pattern = if loc.case_sensitive {
                loc.path.clone()
            } else {
                format!("(?i){}", loc.path)
            };
            
            if let Ok(re) = Regex::new(&pattern) {
                if re.is_match(path) && !found_exact && !found_priority {
                    best_match = Some(loc);
                }
            }
            continue;
        }
        
        // Prefix match
        if path.starts_with(&loc.path) {
            let match_len = loc.path.len();
            
            // Priority prefix (^~) beats regex
            if loc.priority && match_len > best_match_len {
                best_match = Some(loc);
                best_match_len = match_len;
                found_priority = true;
            } else if !found_priority && match_len > best_match_len {
                best_match = Some(loc);
                best_match_len = match_len;
            }
        }
    }
    
    best_match
}

/// Evaluate an if condition
fn evaluate_if_condition(condition: &IfCondition, host: &str, path: &str, method: &Method, scheme: &str) -> Option<Response> {
    let cond = &condition.condition;
    
    // Common conditions
    let matched = if cond.contains("$host") {
        // if ($host = example.com)
        if let Some(expected) = cond.split('=').nth(1) {
            let expected = expected.trim().trim_end_matches(')').trim();
            host == expected
        } else {
            false
        }
    } else if cond.contains("$request_method") {
        if let Some(expected) = cond.split('=').nth(1) {
            let expected = expected.trim().trim_end_matches(')').trim();
            method.as_str() == expected
        } else {
            false
        }
    } else if cond.contains("$scheme") {
        // if ($scheme = http) or if ($scheme != https)
        if cond.contains("!=") {
            if let Some(expected) = cond.split("!=").nth(1) {
                let expected = expected.trim().trim_end_matches(')').trim();
                scheme != expected
            } else {
                false
            }
        } else if let Some(expected) = cond.split('=').nth(1) {
            let expected = expected.trim().trim_end_matches(')').trim();
            scheme == expected
        } else {
            false
        }
    } else {
        // Unsupported condition
        false
    };
    
    if matched {
        if let Some(code) = condition.return_code {
            return handle_return(code, condition.return_value.as_deref(), host, path, scheme);
        }
    }
    
    None
}

/// Handle a return directive - returns None if redirect should be skipped (already at target)
fn handle_return(code: u16, value: Option<&str>, host: &str, path: &str, scheme: &str) -> Option<Response> {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
    
    if (300..400).contains(&code) {
        // Redirect
        if let Some(url) = value {
            // Expand variables - use actual scheme to prevent redirect loops
            let url = url
                .replace("$host", host)
                .replace("$request_uri", path)
                .replace("$scheme", scheme);
            
            // If we're already on HTTPS and the redirect is to the same URL, skip redirect
            if scheme == "https" && url == format!("https://{}{}", host, path) {
                // Already on HTTPS at the target URL, continue normal processing
                return None;
            }
            
            Some(Response::builder()
                .status(status)
                .header(header::LOCATION, &url)
                .header(header::CONTENT_TYPE, "text/html")
                .body(Body::from(format!(
                    "<html><head><title>{} Redirect</title></head><body><h1>{}</h1><p>Redirecting to <a href=\"{}\">{}</a></p></body></html>",
                    code, status.canonical_reason().unwrap_or("Redirect"), url, url
                )))
                .unwrap())
        } else {
            Some((status, "Redirect").into_response())
        }
    } else {
        // Other status codes
        let body = value.unwrap_or("").to_string();
        Some((status, body).into_response())
    }
}

/// Apply a rewrite rule
fn apply_rewrite(rule: &nginx::RewriteRule, path: &str) -> Option<Response> {
    if let Ok(re) = Regex::new(&rule.pattern) {
        if let Some(caps) = re.captures(path) {
            let mut new_path = rule.replacement.clone();
            
            // Replace capture groups
            for i in 0..=9 {
                if let Some(m) = caps.get(i) {
                    new_path = new_path.replace(&format!("${}", i), m.as_str());
                }
            }
            
            match rule.flag {
                RewriteFlag::Permanent => {
                    return Some(Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header(header::LOCATION, &new_path)
                        .body(Body::empty())
                        .unwrap());
                }
                RewriteFlag::Redirect => {
                    return Some(Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, &new_path)
                        .body(Body::empty())
                        .unwrap());
                }
                _ => {
                    // Internal rewrite - would need to re-process
                    // For now, just redirect
                }
            }
        }
    }
    None
}

/// Handle proxy pass
async fn handle_proxy(
    state: &Arc<AppState>,
    req: Request,
    headers: HeaderMap,
    proxy_pass: &str,
    location: &LocationBlock,
    server_headers: &[ProxyHeader],
    client_addr: SocketAddr,
) -> Response {
    // Parse the proxy_pass URL
    let (backend_url, path_suffix) = if proxy_pass.starts_with("http://") || proxy_pass.starts_with("https://") {
        // Direct URL
        (proxy_pass.to_string(), req.uri().path_and_query().map(|pq| pq.to_string()).unwrap_or_default())
    } else {
        // Upstream reference
        let upstream_name = proxy_pass.trim_start_matches("http://").trim_start_matches("https://");
        
        if let Some(lb) = state.upstreams.get(upstream_name) {
            let client_ip = headers.get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim())
                .unwrap_or(&client_addr.ip().to_string())
                .to_string();
            
            if let Some(server) = lb.next_server(Some(&client_ip)) {
                (server.url.clone(), req.uri().path_and_query().map(|pq| pq.to_string()).unwrap_or_default())
            } else {
                return (StatusCode::BAD_GATEWAY, "No healthy upstream servers").into_response();
            }
        } else {
            // Not an upstream, treat as direct URL
            (format!("http://{}", upstream_name), req.uri().path_and_query().map(|pq| pq.to_string()).unwrap_or_default())
        }
    };
    
    // Build the proxy URL
    let proxy_url = format!("{}{}", backend_url.trim_end_matches('/'), path_suffix);
    
    let uri: Uri = match proxy_url.parse() {
        Ok(u) => u,
        Err(e) => {
            error!("Invalid proxy URL {}: {}", proxy_url, e);
            return (StatusCode::BAD_GATEWAY, "Invalid upstream URL").into_response();
        }
    };
    
    // Read the request body
    let method = req.method().clone();
    let (_parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };
    
    // Build proxy request
    let mut proxy_req = hyper::Request::builder()
        .method(method.clone())
        .uri(&uri);
    
    // Copy headers
    for (name, value) in headers.iter() {
        // Skip hop-by-hop headers
        let name_str = name.as_str().to_lowercase();
        if name_str == "host" || name_str == "connection" || name_str == "keep-alive" ||
           name_str == "transfer-encoding" || name_str == "te" || name_str == "trailer" ||
           name_str == "upgrade" || name_str == "proxy-authorization" || name_str == "proxy-connection" {
            continue;
        }
        proxy_req = proxy_req.header(name, value);
    }
    
    // Add Host header for the backend
    if let Some(host) = uri.host() {
        let host_header = if let Some(port) = uri.port() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        proxy_req = proxy_req.header(header::HOST, &host_header);
    }
    
    // Apply proxy_set_header directives from location
    for ph in &location.proxy_headers {
        let value = expand_proxy_header_value(&ph.value, &headers, client_addr);
        if let Ok(hv) = HeaderValue::from_str(&value) {
            proxy_req = proxy_req.header(&ph.name, hv);
        }
    }
    
    // Apply server-level proxy headers
    for ph in server_headers {
        let value = expand_proxy_header_value(&ph.value, &headers, client_addr);
        if let Ok(hv) = HeaderValue::from_str(&value) {
            proxy_req = proxy_req.header(&ph.name, hv);
        }
    }
    
    // Set HTTP version header if specified
    if !location.proxy_http_version.is_empty() {
        proxy_req = proxy_req.header("Connection", "");
    }
    
    let proxy_req = match proxy_req.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build proxy request: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build proxy request").into_response();
        }
    };
    
    // Send the request
    debug!("Proxying to {}", uri);
    
    let response = match state.http_client.request(proxy_req).await {
        Ok(r) => r,
        Err(e) => {
            error!("Proxy request failed: {}", e);
            return (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response();
        }
    };
    
    // Build response
    let status = response.status();
    let resp_headers = response.headers().clone();
    
    let body_bytes = match response.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!("Failed to read upstream response: {}", e);
            return (StatusCode::BAD_GATEWAY, "Failed to read upstream response").into_response();
        }
    };
    
    let mut resp = Response::builder().status(status);
    
    // Copy response headers
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip hop-by-hop headers
        if name_str == "connection" || name_str == "keep-alive" || name_str == "transfer-encoding" ||
           name_str == "te" || name_str == "trailer" || name_str == "upgrade" {
            continue;
        }
        resp = resp.header(name, value);
    }
    
    // Add headers from add_header directive
    for ah in &location.add_headers {
        if let Ok(hv) = HeaderValue::from_str(&ah.value) {
            resp = resp.header(&ah.name, hv);
        }
    }
    
    resp.body(Body::from(body_bytes)).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response()
    })
}

/// Expand nginx variables in proxy header values
fn expand_proxy_header_value(value: &str, headers: &HeaderMap, client_addr: SocketAddr) -> String {
    let mut result = value.to_string();
    
    // $http_host
    if let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) {
        result = result.replace("$http_host", host);
    }
    
    // $host
    if let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) {
        let host_only = host.split(':').next().unwrap_or(host);
        result = result.replace("$host", host_only);
    }
    
    // $remote_addr
    result = result.replace("$remote_addr", &client_addr.ip().to_string());
    
    // $proxy_add_x_forwarded_for
    let xff = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|existing| format!("{}, {}", existing, client_addr.ip()))
        .unwrap_or_else(|| client_addr.ip().to_string());
    result = result.replace("$proxy_add_x_forwarded_for", &xff);
    
    // $scheme
    let scheme = if headers.get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .map(|s| s == "https")
        .unwrap_or(false) {
        "https"
    } else {
        "http"
    };
    result = result.replace("$scheme", scheme);
    
    // $request_uri
    // This would need the actual URI from the request
    
    // $server_port
    result = result.replace("$server_port", &client_addr.port().to_string());
    
    result
}

/// Serve a static file
async fn serve_static_file(
    mut path: PathBuf,
    location_index: &[String],
    server_index: &[String],
    error_pages: &HashMap<u16, String>,
) -> Response {
    // If directory, look for index files
    if path.is_dir() {
        let index_files: Vec<&String> = location_index.iter()
            .chain(server_index.iter())
            .collect();
        
        let mut found = false;
        for index in index_files {
            let index_path = path.join(index);
            if index_path.exists() {
                path = index_path;
                found = true;
                break;
            }
        }
        
        if !found {
            return (StatusCode::FORBIDDEN, "Directory listing denied").into_response();
        }
    }
    
    // Check if file exists
    if !path.exists() {
        // Check for custom error page
        if let Some(error_page) = error_pages.get(&404) {
            let error_path = path.parent()
                .unwrap_or(Path::new("/"))
                .join(error_page.trim_start_matches('/'));
            if error_path.exists() {
                if let Ok(content) = fs::read(&error_path).await {
                    let mime = mime_guess::from_path(&error_path).first_or_text_plain();
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(header::CONTENT_TYPE, mime.to_string())
                        .body(Body::from(content))
                        .unwrap();
                }
            }
        }
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    
    // Read and serve the file
    match fs::read(&path).await {
        Ok(content) => {
            let mime = mime_guess::from_path(&path).first_or_text_plain();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.to_string())
                .body(Body::from(content))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to read file {:?}: {}", path, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file").into_response()
        }
    }
}
