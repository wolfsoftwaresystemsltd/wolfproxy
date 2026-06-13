//! Nginx configuration parser module
//! Parses nginx sites-available/sites-enabled configurations

use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use regex::Regex;

/// Represents an upstream server in a load balancing group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServer {
    /// Server address (host:port or just host)
    pub address: String,
    /// Server port (default 80)
    pub port: u16,
    /// Weight for weighted round-robin
    pub weight: u32,
    /// Maximum number of failures before marking server down
    pub max_fails: u32,
    /// Timeout after which the server is considered down
    pub fail_timeout: u64,
    /// Is this a backup server?
    pub backup: bool,
    /// Is this server temporarily down?
    pub down: bool,
}

impl Default for UpstreamServer {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: 80,
            weight: 1,
            max_fails: 1,
            fail_timeout: 300,
            backup: false,
            down: false,
        }
    }
}

/// Load balancing method
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum LoadBalanceMethod {
    #[default]
    RoundRobin,
    IpHash,
    LeastConn,
    Random,
    WeightedRoundRobin,
}

/// Represents an upstream block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    /// Name of the upstream group
    pub name: String,
    /// Load balancing method
    pub method: LoadBalanceMethod,
    /// List of backend servers
    pub servers: Vec<UpstreamServer>,
    /// Keepalive connections
    pub keepalive: Option<u32>,
}

/// Proxy header configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHeader {
    pub name: String,
    pub value: String,
}

/// Location block configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocationBlock {
    /// Location path or pattern
    pub path: String,
    /// Is this a regex location (~, ~*, ^~)?
    pub is_regex: bool,
    /// Case sensitive regex?
    pub case_sensitive: bool,
    /// Exact match (=)?
    pub exact: bool,
    /// Priority modifier (^~)
    pub priority: bool,
    /// Proxy pass destination
    pub proxy_pass: Option<String>,
    /// Root directory for static files
    pub root: Option<PathBuf>,
    /// Alias directory
    pub alias: Option<PathBuf>,
    /// Index files
    pub index: Vec<String>,
    /// Try files directive
    pub try_files: Vec<String>,
    /// Proxy headers to set
    pub proxy_headers: Vec<ProxyHeader>,
    /// Proxy HTTP version
    pub proxy_http_version: String,
    /// Proxy buffer size
    pub proxy_buffer_size: Option<String>,
    /// Proxy buffers count and size
    pub proxy_buffers: Option<String>,
    /// Proxy connect timeout
    pub proxy_connect_timeout: Option<u64>,
    /// Proxy read timeout  
    pub proxy_read_timeout: Option<u64>,
    /// Proxy send timeout
    pub proxy_send_timeout: Option<u64>,
    /// Return status code
    pub return_code: Option<u16>,
    /// Return URL or body
    pub return_value: Option<String>,
    /// Deny all
    pub deny_all: bool,
    /// Allow specific IPs
    pub allow: Vec<String>,
    /// Deny specific IPs
    pub deny: Vec<String>,
    /// FastCGI pass
    pub fastcgi_pass: Option<String>,
    /// Rewrite rules
    pub rewrites: Vec<RewriteRule>,
    /// Add headers to response
    pub add_headers: Vec<ProxyHeader>,
    /// Client max body size
    pub client_max_body_size: Option<u64>,
}

/// Rewrite rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRule {
    pub pattern: String,
    pub replacement: String,
    pub flag: RewriteFlag,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum RewriteFlag {
    #[default]
    None,
    Last,        // last
    Break,       // break
    Redirect,    // redirect (302)
    Permanent,   // permanent (301)
}

/// SSL Configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SslConfig {
    pub enabled: bool,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
    pub dhparam: Option<PathBuf>,
    pub protocols: Vec<String>,
    pub ciphers: Option<String>,
    pub prefer_server_ciphers: bool,
    pub session_timeout: Option<String>,
    pub session_cache: Option<String>,
}

/// If condition block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfCondition {
    pub condition: String,
    pub return_code: Option<u16>,
    pub return_value: Option<String>,
    pub rewrite: Option<RewriteRule>,
}

/// Server block configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerBlock {
    /// Listen ports (can be multiple)
    pub listen: Vec<ListenDirective>,
    /// Server names
    pub server_names: Vec<String>,
    /// SSL configuration
    pub ssl: SslConfig,
    /// Default root directory
    pub root: Option<PathBuf>,
    /// Default index files
    pub index: Vec<String>,
    /// Location blocks
    pub locations: Vec<LocationBlock>,
    /// If conditions at server level
    pub if_conditions: Vec<IfCondition>,
    /// Error pages
    pub error_pages: HashMap<u16, String>,
    /// Access log path
    pub access_log: Option<PathBuf>,
    /// Error log path
    pub error_log: Option<PathBuf>,
    /// Client max body size
    pub client_max_body_size: Option<u64>,
    /// Keepalive timeout
    pub keepalive_timeout: Option<u64>,
    /// Is this a default server?
    pub default_server: bool,
    /// Gzip enabled?
    pub gzip: bool,
    /// Gzip types
    pub gzip_types: Vec<String>,
    /// Proxy headers at server level
    pub proxy_headers: Vec<ProxyHeader>,
}

/// Listen directive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenDirective {
    pub address: Option<String>,
    pub port: u16,
    pub ssl: bool,
    pub http2: bool,
    pub default_server: bool,
    pub ipv6only: bool,
}

impl Default for ListenDirective {
    fn default() -> Self {
        Self {
            address: None,
            port: 80,
            ssl: false,
            http2: false,
            default_server: false,
            ipv6only: false,
        }
    }
}

/// Complete nginx configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NginxConfig {
    pub upstreams: HashMap<String, Upstream>,
    pub servers: Vec<ServerBlock>,
    pub includes: Vec<PathBuf>,
    /// Human-readable problems found while resolving `include` directives:
    /// a glob that matched no files, an explicit include whose file is
    /// missing, or an invalid glob pattern. These are NOT part of the proxy's
    /// routing state — they exist purely so `wolfproxy --test` and the startup
    /// log can tell the operator their include pulled in nothing, instead of
    /// failing silently (the wabil report, 2026-06-13). Real nginx errors
    /// loudly here; WolfProxy used to swallow it.
    #[serde(default)]
    pub include_warnings: Vec<String>,
}

/// Parse an nginx configuration file
pub fn parse_nginx_config(path: &Path) -> NginxConfig {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read nginx config {}: {}", path.display(), e);
            return NginxConfig::default();
        }
    };
    
    parse_nginx_content(&content, path.parent())
}

/// Parse nginx configuration content
pub fn parse_nginx_content(content: &str, base_dir: Option<&Path>) -> NginxConfig {
    let mut config = NginxConfig::default();
    
    // Remove comments but preserve strings
    let content = remove_comments(content);
    
    // Parse upstreams
    config.upstreams = parse_upstreams(&content);
    
    // Parse server blocks
    config.servers = parse_server_blocks(&content, base_dir);
    
    // Parse includes and merge
    if let Some(base) = base_dir {
        for include in find_includes(&content) {
            let include_path = if include.starts_with('/') {
                PathBuf::from(&include)
            } else {
                base.join(&include)
            };
            
            // Handle glob patterns
            if include.contains('*') {
                match glob::glob(&include_path.to_string_lossy()) {
                    Ok(paths) => {
                        let mut matched = 0usize;
                        for entry in paths.flatten() {
                            let sub_config = parse_nginx_config(&entry);
                            merge_configs(&mut config, sub_config);
                            matched += 1;
                        }
                        // A glob matching nothing is legal in nginx (not an
                        // error) but is almost always a mistake — e.g.
                        // `sites-enabled/*.conf` against Debian's extensionless
                        // symlinks. Surface it so it isn't silent.
                        if matched == 0 {
                            config.include_warnings.push(format!(
                                "include '{}' matched no files — check the path and that the \
                                 filenames match the pattern (Debian sites-enabled entries often \
                                 have no .conf suffix, so '*.conf' matches nothing; try '*')",
                                include_path.display()
                            ));
                        }
                    }
                    Err(e) => config.include_warnings.push(format!(
                        "include '{}' is not a valid glob pattern: {}", include, e
                    )),
                }
            } else if include_path.exists() {
                let sub_config = parse_nginx_config(&include_path);
                merge_configs(&mut config, sub_config);
            } else {
                // An explicit (non-glob) include of a file that doesn't exist:
                // real nginx treats this as a fatal `-t` error. We surface it
                // loudly but don't refuse to load — a proxy that's been running
                // shouldn't suddenly fail to start on upgrade (see main.rs).
                config.include_warnings.push(format!(
                    "include '{}' refers to a file that does not exist",
                    include_path.display()
                ));
            }
        }
    }
    
    config
}

fn remove_comments(content: &str) -> String {
    let mut result = String::new();
    let mut in_string = false;
    let mut chars = content.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            in_string = !in_string;
            result.push(c);
        } else if c == '#' && !in_string {
            // Skip until newline
            while let Some(&next) = chars.peek() {
                if next == '\n' {
                    break;
                }
                chars.next();
            }
        } else {
            result.push(c);
        }
    }
    
    result
}

fn find_includes(content: &str) -> Vec<String> {
    let re = Regex::new(r"include\s+([^;]+);").unwrap();
    re.captures_iter(content)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().trim().trim_matches('"').trim_matches('\'').to_string()))
        .collect()
}

fn parse_upstreams(content: &str) -> HashMap<String, Upstream> {
    let mut upstreams = HashMap::new();
    
    // Match upstream blocks
    let re = Regex::new(r"upstream\s+(\w+)\s*\{([^}]+)\}").unwrap();
    
    for cap in re.captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let block_content = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        
        let mut upstream = Upstream {
            name: name.clone(),
            method: LoadBalanceMethod::RoundRobin,
            servers: Vec::new(),
            keepalive: None,
        };
        
        for line in block_content.lines() {
            let line = line.trim();
            
            if line.starts_with("ip_hash") {
                upstream.method = LoadBalanceMethod::IpHash;
            } else if line.starts_with("least_conn") {
                upstream.method = LoadBalanceMethod::LeastConn;
            } else if line.starts_with("random") {
                upstream.method = LoadBalanceMethod::Random;
            } else if line.starts_with("keepalive") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    upstream.keepalive = parts[1].trim_end_matches(';').parse().ok();
                }
            } else if line.starts_with("server") {
                if let Some(server) = parse_upstream_server(line) {
                    // Only switch to weighted if no explicit method was set earlier
                    // (ip_hash/least_conn/random should remain as declared)
                    if server.weight > 1 && matches!(upstream.method, LoadBalanceMethod::RoundRobin) {
                        upstream.method = LoadBalanceMethod::WeightedRoundRobin;
                    }
                    upstream.servers.push(server);
                }
            }
        }
        
        if !upstream.servers.is_empty() {
            upstreams.insert(name, upstream);
        }
    }
    
    upstreams
}

fn parse_upstream_server(line: &str) -> Option<UpstreamServer> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    
    let mut server = UpstreamServer::default();
    
    // Parse address and port
    let addr = parts[1].trim_end_matches(';');
    if let Some(colon_idx) = addr.rfind(':') {
        server.address = addr[..colon_idx].to_string();
        server.port = addr[colon_idx + 1..].parse().unwrap_or(80);
    } else {
        server.address = addr.to_string();
        server.port = 80;
    }
    
    // Parse additional options
    for part in parts.iter().skip(2) {
        let part = part.trim_end_matches(';');
        if let Some(v) = part.strip_prefix("weight=") {
            server.weight = v.parse().unwrap_or(1);
        } else if let Some(v) = part.strip_prefix("max_fails=") {
            server.max_fails = v.parse().unwrap_or(1);
        } else if let Some(v) = part.strip_prefix("fail_timeout=") {
            let timeout_str = v.trim_end_matches('s');
            server.fail_timeout = timeout_str.parse().unwrap_or(300);
        } else if part == "backup" {
            server.backup = true;
        } else if part == "down" {
            server.down = true;
        }
    }
    
    Some(server)
}

/// Maximum `include` nesting depth inside a server block — a guard against a
/// cyclic or pathological include chain.
const MAX_SERVER_INCLUDE_DEPTH: usize = 16;

/// Textually expand `include` directives found inside a server block, returning
/// the body with each include replaced by the (recursively expanded) contents
/// of the file(s) it matches. nginx treats `include` as a textual inclusion at
/// parse time, so an included file may itself contain `location { ... }`
/// blocks, flat directives, or further includes — all parsed in the
/// surrounding server context. `*` globs are supported here exactly as at the
/// top level (a zero-match glob is not an error); a missing literal file or an
/// invalid glob is warned about and skipped.
///
/// Before this, server-block includes were fed line-by-line to
/// `parse_server_directive`, which can't parse nested `location` blocks, and
/// globs were rejected outright — so an `include sites/*.conf;` inside a server
/// silently dropped every directive (wabil 2026-06-13).
fn expand_server_includes(body: &str, base_dir: Option<&Path>, depth: usize) -> String {
    if depth >= MAX_SERVER_INCLUDE_DEPTH {
        eprintln!(
            "wolfproxy: server-block include nesting exceeded {} levels — stopping (possible include cycle)",
            MAX_SERVER_INCLUDE_DEPTH
        );
        return body.to_string();
    }
    let base = base_dir.unwrap_or(Path::new("/"));
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        // Match an `include <path>;` directive specifically — not `include_foo`
        // or a value that merely contains the word.
        let inc = line.trim()
            .strip_prefix("include")
            .filter(|rest| rest.starts_with(|c: char| c.is_whitespace()))
            .map(|rest| rest.trim().trim_end_matches(';').trim().trim_matches('"').trim_matches('\''))
            .filter(|p| !p.is_empty());
        let Some(path) = inc else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let resolved = if path.starts_with('/') { PathBuf::from(path) } else { base.join(path) };
        let mut files: Vec<PathBuf> = if path.contains('*') {
            match glob::glob(&resolved.to_string_lossy()) {
                Ok(paths) => {
                    let matched: Vec<PathBuf> = paths.flatten().collect();
                    // A zero-match glob is legal in nginx (not an error), but
                    // almost always a mistake — surface it. Reported only here,
                    // so a glob ERROR (below) doesn't also trip a "no files".
                    if matched.is_empty() {
                        eprintln!("wolfproxy: include '{}' inside a server block matched no files", resolved.display());
                    }
                    matched
                }
                Err(e) => {
                    eprintln!("wolfproxy: include '{}' inside a server block is not a valid glob: {}", path, e);
                    Vec::new()
                }
            }
        } else if resolved.exists() {
            vec![resolved.clone()]
        } else {
            eprintln!("wolfproxy: include '{}' inside a server block refers to a file that does not exist", resolved.display());
            Vec::new()
        };
        // Deterministic, nginx-like lexical order regardless of glob() ordering.
        files.sort();
        for f in files {
            match fs::read_to_string(&f) {
                Ok(content) => {
                    let stripped = remove_comments(&content);
                    // A server-context include is meant to pull in directives /
                    // location blocks — NOT a whole `server { }` (nginx can't
                    // nest those). If a file carries one it was meant as a
                    // top-level include (where find_includes already loads it),
                    // so skip it here rather than inject a server-in-server and
                    // silently fold its directives into the outer server.
                    let has_server_block = stripped.lines().any(|l| {
                        l.trim().strip_prefix("server")
                            .map(|r| r.trim_start().starts_with('{'))
                            .unwrap_or(false)
                    });
                    if has_server_block {
                        eprintln!(
                            "wolfproxy: server-block include '{}' contains a `server {{ }}` block, which can't be nested inside another server — skipping it (use a top-level include for full server blocks)",
                            f.display()
                        );
                        continue;
                    }
                    let child_base = f.parent().unwrap_or(base);
                    out.push_str(&expand_server_includes(&stripped, Some(child_base), depth + 1));
                    if !out.ends_with('\n') { out.push('\n'); }
                }
                Err(e) => eprintln!("wolfproxy: could not read server include '{}': {}", f.display(), e),
            }
        }
    }
    out
}

fn parse_server_blocks(content: &str, base_dir: Option<&Path>) -> Vec<ServerBlock> {
    let mut servers = Vec::new();
    
    // Find server blocks - this is simplified and may need improvement for nested braces
    let mut in_server = false;
    let mut server_content = String::new();
    let mut brace_count = 0;
    
    for line in content.lines() {
        let trimmed = line.trim();
        
        if trimmed.starts_with("server") && trimmed.contains('{') && !in_server {
            in_server = true;
            brace_count = 1;
            server_content.clear();
            // Don't include the "server {" line
            if let Some(brace_idx) = line.find('{') {
                server_content.push_str(&line[brace_idx + 1..]);
                server_content.push('\n');
            }
            continue;
        }
        
        if in_server {
            // Count braces
            for c in trimmed.chars() {
                match c {
                    '{' => brace_count += 1,
                    '}' => brace_count -= 1,
                    _ => {}
                }
            }
            
            if brace_count == 0 {
                // End of server block. Expand any `include`s textually first so
                // included location/if blocks and directives parse in the server
                // context (nginx's textual-include semantics).
                let expanded = expand_server_includes(&server_content, base_dir, 0);
                if let Some(server) = parse_server_content(&expanded) {
                    servers.push(server);
                }
                in_server = false;
                server_content.clear();
            } else {
                server_content.push_str(line);
                server_content.push('\n');
            }
        }
    }
    
    servers
}

fn parse_server_content(content: &str) -> Option<ServerBlock> {
    let mut server = ServerBlock {
        listen: Vec::new(),
        server_names: Vec::new(),
        ssl: SslConfig::default(),
        root: None,
        index: Vec::new(),
        locations: Vec::new(),
        if_conditions: Vec::new(),
        error_pages: HashMap::new(),
        access_log: None,
        error_log: None,
        client_max_body_size: None,
        keepalive_timeout: None,
        default_server: false,
        gzip: false,
        gzip_types: Vec::new(),
        proxy_headers: Vec::new(),
    };
    
    // Parse line by line, handling nested blocks
    let lines = content.lines().peekable();
    let mut current_location: Option<LocationBlock> = None;
    let mut location_depth = 0;
    let mut location_content = String::new();
    let mut in_if = false;
    let mut if_content = String::new();
    let mut if_condition = String::new();
    
    for line in lines {
        let trimmed = line.trim();
        
        // Handle if blocks
        if trimmed.starts_with("if ") && trimmed.contains('{') {
            in_if = true;
            // Extract condition
            if let Some(start) = trimmed.find('(') {
                if let Some(end) = trimmed.rfind(')') {
                    if_condition = trimmed[start + 1..end].to_string();
                }
            }
            if_content.clear();
            continue;
        }
        
        if in_if {
            if trimmed.contains('}') {
                // Parse if content
                if let Some(cond) = parse_if_block(&if_condition, &if_content) {
                    server.if_conditions.push(cond);
                }
                in_if = false;
                if_content.clear();
                if_condition.clear();
            } else {
                if_content.push_str(line);
                if_content.push('\n');
            }
            continue;
        }
        
        // Handle location blocks
        if trimmed.starts_with("location") && trimmed.contains('{') {
            location_depth = 1;
            current_location = Some(parse_location_header(trimmed));
            location_content.clear();
            continue;
        }
        
        if current_location.is_some() {
            for c in trimmed.chars() {
                match c {
                    '{' => location_depth += 1,
                    '}' => location_depth -= 1,
                    _ => {}
                }
            }
            
            if location_depth == 0 {
                if let Some(mut loc) = current_location.take() {
                    parse_location_content(&mut loc, &location_content);
                    server.locations.push(loc);
                }
                location_content.clear();
            } else {
                location_content.push_str(line);
                location_content.push('\n');
            }
            continue;
        }
        
        // Parse server-level directives
        parse_server_directive(&mut server, trimmed);
    }
    
    Some(server)
}

fn parse_location_header(line: &str) -> LocationBlock {
    let mut loc = LocationBlock::default();
    let parts: Vec<&str> = line.split_whitespace().collect();
    
    // Skip "location" keyword
    let mut idx = 1;
    
    // Check for modifiers
    while idx < parts.len() {
        let part = parts[idx].trim_end_matches('{');
        match part {
            "=" => {
                loc.exact = true;
                idx += 1;
            }
            "~" => {
                loc.is_regex = true;
                loc.case_sensitive = true;
                idx += 1;
            }
            "~*" => {
                loc.is_regex = true;
                loc.case_sensitive = false;
                idx += 1;
            }
            "^~" => {
                loc.priority = true;
                idx += 1;
            }
            _ => {
                // This is the path
                loc.path = part.to_string();
                break;
            }
        }
    }
    
    loc
}

fn parse_location_content(loc: &mut LocationBlock, content: &str) {
    for line in content.lines() {
        let trimmed = line.trim();
        
        if trimmed.starts_with("proxy_pass") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.proxy_pass = Some(parts[1].trim_end_matches(';').to_string());
            }
        } else if trimmed.starts_with("proxy_set_header") {
            let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
            if parts.len() >= 3 {
                let value = parts[2].trim_end_matches(';')
                    .trim_matches('"')  // Remove surrounding quotes
                    .trim_matches('\''); // Also handle single quotes
                loc.proxy_headers.push(ProxyHeader {
                    name: parts[1].to_string(),
                    value: value.to_string(),
                });
            }
        } else if trimmed.starts_with("proxy_http_version") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.proxy_http_version = parts[1].trim_end_matches(';').to_string();
            }
        } else if trimmed.starts_with("proxy_buffer_size") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.proxy_buffer_size = Some(parts[1].trim_end_matches(';').to_string());
            }
        } else if trimmed.starts_with("proxy_buffers") {
            // proxy_buffers 256 1024k;
            let rest = trimmed.strip_prefix("proxy_buffers").unwrap_or("").trim();
            loc.proxy_buffers = Some(rest.trim_end_matches(';').to_string());
        } else if trimmed.starts_with("proxy_connect_timeout") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.proxy_connect_timeout = parse_time_value(parts[1].trim_end_matches(';'));
            }
        } else if trimmed.starts_with("proxy_read_timeout") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.proxy_read_timeout = parse_time_value(parts[1].trim_end_matches(';'));
            }
        } else if trimmed.starts_with("proxy_send_timeout") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.proxy_send_timeout = parse_time_value(parts[1].trim_end_matches(';'));
            }
        } else if trimmed.starts_with("root") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.root = Some(PathBuf::from(parts[1].trim_end_matches(';').trim_matches('"')));
            }
        } else if trimmed.starts_with("alias") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.alias = Some(PathBuf::from(parts[1].trim_end_matches(';').trim_matches('"')));
            }
        } else if trimmed.starts_with("index") {
            let parts: Vec<&str> = trimmed.split_whitespace().skip(1).collect();
            for part in parts {
                let index = part.trim_end_matches(';');
                if !index.is_empty() {
                    loc.index.push(index.to_string());
                }
            }
        } else if trimmed.starts_with("try_files") {
            let parts: Vec<&str> = trimmed.split_whitespace().skip(1).collect();
            for part in parts {
                let file = part.trim_end_matches(';');
                if !file.is_empty() {
                    loc.try_files.push(file.to_string());
                }
            }
        } else if trimmed.starts_with("return") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].trim_end_matches(';').parse::<u16>() {
                    loc.return_code = Some(code);
                    if parts.len() >= 3 {
                        loc.return_value = Some(parts[2..].join(" ").trim_end_matches(';').to_string());
                    }
                }
            }
        } else if trimmed == "deny all;" || trimmed == "deny all" {
            loc.deny_all = true;
        } else if trimmed.starts_with("allow") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.allow.push(parts[1].trim_end_matches(';').to_string());
            }
        } else if trimmed.starts_with("deny") && !trimmed.starts_with("deny all") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.deny.push(parts[1].trim_end_matches(';').to_string());
            }
        } else if trimmed.starts_with("fastcgi_pass") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.fastcgi_pass = Some(parts[1].trim_end_matches(';').to_string());
            }
        } else if trimmed.starts_with("rewrite") {
            if let Some(rule) = parse_rewrite_rule(trimmed) {
                loc.rewrites.push(rule);
            }
        } else if trimmed.starts_with("add_header") {
            let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
            if parts.len() >= 3 {
                loc.add_headers.push(ProxyHeader {
                    name: parts[1].to_string(),
                    value: parts[2].trim_end_matches(';').trim_matches('"').to_string(),
                });
            }
        } else if trimmed.starts_with("client_max_body_size") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                loc.client_max_body_size = parse_size_value(parts[1].trim_end_matches(';'));
            }
        }
    }
}

fn parse_server_directive(server: &mut ServerBlock, line: &str) {
    if line.starts_with("listen") {
        if let Some(listen) = parse_listen_directive(line) {
            if listen.default_server {
                server.default_server = true;
            }
            if listen.ssl {
                server.ssl.enabled = true;
            }
            server.listen.push(listen);
        }
    } else if line.starts_with("server_name") {
        let parts: Vec<&str> = line.split_whitespace().skip(1).collect();
        for part in parts {
            let name = part.trim_end_matches(';').trim();
            if !name.is_empty() {
                server.server_names.push(name.to_string());
            }
        }
    } else if line.starts_with("ssl_certificate_key") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.ssl.certificate_key = Some(PathBuf::from(parts[1].trim_end_matches(';').trim_matches('"')));
        }
    } else if line.starts_with("ssl_certificate") && !line.starts_with("ssl_certificate_key") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.ssl.certificate = Some(PathBuf::from(parts[1].trim_end_matches(';').trim_matches('"')));
        }
    } else if line.starts_with("ssl_dhparam") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.ssl.dhparam = Some(PathBuf::from(parts[1].trim_end_matches(';').trim_matches('"')));
        }
    } else if line.starts_with("ssl_protocols") {
        let parts: Vec<&str> = line.split_whitespace().skip(1).collect();
        for part in parts {
            let proto = part.trim_end_matches(';').trim();
            if !proto.is_empty() {
                server.ssl.protocols.push(proto.to_string());
            }
        }
    } else if line.starts_with("ssl_ciphers") {
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() >= 2 {
            server.ssl.ciphers = Some(parts[1].trim_end_matches(';').to_string());
        }
    } else if line.starts_with("ssl_prefer_server_ciphers") {
        server.ssl.prefer_server_ciphers = line.contains("on");
    } else if line.starts_with("ssl_session_timeout") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.ssl.session_timeout = Some(parts[1].trim_end_matches(';').to_string());
        }
    } else if line.starts_with("ssl_session_cache") {
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() >= 2 {
            server.ssl.session_cache = Some(parts[1].trim_end_matches(';').to_string());
        }
    } else if line.starts_with("root") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.root = Some(PathBuf::from(parts[1].trim_end_matches(';').trim_matches('"')));
        }
    } else if line.starts_with("index") {
        let parts: Vec<&str> = line.split_whitespace().skip(1).collect();
        for part in parts {
            let index = part.trim_end_matches(';');
            if !index.is_empty() {
                server.index.push(index.to_string());
            }
        }
    } else if line.starts_with("error_page") {
        // error_page 404 /404.html;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            if let Ok(code) = parts[1].parse::<u16>() {
                server.error_pages.insert(code, parts[2].trim_end_matches(';').to_string());
            }
        }
    } else if line.starts_with("access_log") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] != "off" && parts[1] != "off;" {
            server.access_log = Some(PathBuf::from(parts[1].trim_end_matches(';')));
        }
    } else if line.starts_with("error_log") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.error_log = Some(PathBuf::from(parts[1].trim_end_matches(';')));
        }
    } else if line.starts_with("client_max_body_size") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.client_max_body_size = parse_size_value(parts[1].trim_end_matches(';'));
        }
    } else if line.starts_with("keepalive_timeout") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            server.keepalive_timeout = parse_time_value(parts[1].trim_end_matches(';'));
        }
    } else if line.starts_with("gzip on") {
        server.gzip = true;
    } else if line.starts_with("gzip_types") {
        let parts: Vec<&str> = line.split_whitespace().skip(1).collect();
        for part in parts {
            let t = part.trim_end_matches(';').trim();
            if !t.is_empty() {
                server.gzip_types.push(t.to_string());
            }
        }
    } else if line.starts_with("proxy_set_header") {
        let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
        if parts.len() >= 3 {
            let value = parts[2].trim_end_matches(';')
                .trim_matches('"')  // Remove surrounding quotes
                .trim_matches('\''); // Also handle single quotes
            server.proxy_headers.push(ProxyHeader {
                name: parts[1].to_string(),
                value: value.to_string(),
            });
        }
    }
    // NB: `include` inside a server block is handled BEFORE this function, by
    // expand_server_includes (textual expansion in parse_server_blocks), so the
    // included content — including nested location blocks — is parsed in the
    // proper server context. No include arm here.
}

fn parse_if_block(condition: &str, content: &str) -> Option<IfCondition> {
    let mut cond = IfCondition {
        condition: condition.to_string(),
        return_code: None,
        return_value: None,
        rewrite: None,
    };
    
    for line in content.lines() {
        let trimmed = line.trim();
        
        if trimmed.starts_with("return") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].trim_end_matches(';').parse::<u16>() {
                    cond.return_code = Some(code);
                    if parts.len() >= 3 {
                        cond.return_value = Some(parts[2..].join(" ").trim_end_matches(';').to_string());
                    }
                }
            }
        } else if trimmed.starts_with("rewrite") {
            cond.rewrite = parse_rewrite_rule(trimmed);
        }
    }
    
    Some(cond)
}

fn parse_listen_directive(line: &str) -> Option<ListenDirective> {
    let mut listen = ListenDirective::default();
    let parts: Vec<&str> = line.split_whitespace().skip(1).collect();
    
    if parts.is_empty() {
        return None;
    }
    
    // Parse address:port or just port
    let addr_part = parts[0].trim_end_matches(';');
    
    // Check for [::] IPv6 notation
    if let Some(port_str) = addr_part.strip_prefix("[::]:") {
        listen.port = port_str.parse().unwrap_or(80);
        listen.address = Some("[::]:".to_string());
    } else if addr_part.starts_with("[::]") {
        listen.port = 80;
        listen.address = Some("[::]:".to_string());
    } else if let Some(colon_idx) = addr_part.rfind(':') {
        listen.address = Some(addr_part[..colon_idx].to_string());
        listen.port = addr_part[colon_idx + 1..].parse().unwrap_or(80);
    } else {
        listen.port = addr_part.parse().unwrap_or(80);
    }
    
    // Parse flags
    for part in parts.iter().skip(1) {
        let flag = part.trim_end_matches(';');
        match flag {
            "ssl" => listen.ssl = true,
            "http2" => listen.http2 = true,
            "default_server" => listen.default_server = true,
            _ if flag.starts_with("ipv6only=") => {
                listen.ipv6only = flag.contains("on");
            }
            _ => {}
        }
    }
    
    Some(listen)
}

fn parse_rewrite_rule(line: &str) -> Option<RewriteRule> {
    // rewrite pattern replacement [flag];
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    
    let pattern = parts[1].to_string();
    let replacement = parts[2].trim_end_matches(';').to_string();
    
    let flag = if parts.len() >= 4 {
        match parts[3].trim_end_matches(';') {
            "last" => RewriteFlag::Last,
            "break" => RewriteFlag::Break,
            "redirect" => RewriteFlag::Redirect,
            "permanent" => RewriteFlag::Permanent,
            _ => RewriteFlag::None,
        }
    } else {
        RewriteFlag::None
    };
    
    Some(RewriteRule {
        pattern,
        replacement,
        flag,
    })
}

fn parse_time_value(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse().ok()
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>().ok().map(|v| v * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>().ok().map(|v| v * 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        n.parse::<u64>().ok().map(|v| v * 86400)
    } else {
        s.parse().ok()
    }
}

fn parse_size_value(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if s.ends_with('k') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 1024)
    } else if s.ends_with('m') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 1024 * 1024)
    } else if s.ends_with('g') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 1024 * 1024 * 1024)
    } else {
        s.parse().ok()
    }
}

fn merge_configs(main: &mut NginxConfig, other: NginxConfig) {
    main.upstreams.extend(other.upstreams);
    main.servers.extend(other.servers);
    main.includes.extend(other.includes);
    // Bubble include problems up from nested includes so `--test` and the log
    // see every one, no matter how deep the include chain.
    main.include_warnings.extend(other.include_warnings);
}

/// Load the proxy's configuration the way nginx itself does.
///
/// nginx has no auto-discovery: it reads ONE main config file and that file's
/// `include` directives pull in everything else (conf.d, sites, subfolders —
/// relative paths and `*` globs both work, resolved against each file's own
/// directory). WolfProxy now honours that model: if a main config file exists
/// in `nginx_dir`, parse it and let its includes do the work.
///
/// The conventional main file is `root.conf`. It is a non-standard filename, so
/// detecting it *by presence* can only ever opt a user IN — an existing install
/// that doesn't have one keeps the historical auto-scan behaviour below,
/// unchanged. (We deliberately do NOT auto-adopt `nginx.conf`: on a box that
/// also has nginx installed that file already exists and adopting it could
/// change what an existing WolfProxy install loads.)
pub fn load_nginx_config(nginx_dir: &Path) -> NginxConfig {
    let main = nginx_dir.join("root.conf");
    if main.is_file() {
        // parse_nginx_config sets base_dir = nginx_dir, so the main file's
        // includes resolve exactly like nginx, recursively.
        return parse_nginx_config(&main);
    }
    // No main config — fall back to auto-scanning sites-enabled/ + conf.d/
    // (the original WolfProxy behaviour; kept so nothing breaks on upgrade).
    load_nginx_sites(nginx_dir)
}

/// Load all nginx configurations from sites-enabled
pub fn load_nginx_sites(nginx_dir: &Path) -> NginxConfig {
    let mut config = NginxConfig::default();
    
    // Check sites-enabled directory
    let sites_enabled = nginx_dir.join("sites-enabled");
    if sites_enabled.exists() {
        if let Ok(entries) = fs::read_dir(&sites_enabled) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let sub_config = parse_nginx_config(&path);
                    merge_configs(&mut config, sub_config);
                }
            }
        }
    }
    
    // Also check conf.d directory
    let conf_d = nginx_dir.join("conf.d");
    if conf_d.exists() {
        if let Ok(entries) = fs::read_dir(&conf_d) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "conf") {
                    let sub_config = parse_nginx_config(&path);
                    merge_configs(&mut config, sub_config);
                }
            }
        }
    }
    
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_upstream() {
        let content = r#"
        upstream backend {
            ip_hash;
            server 10.0.0.1:8080 weight=3 max_fails=3 fail_timeout=30s;
            server 10.0.0.2:8080;
            server 10.0.0.3:8080 backup;
        }
        "#;
        
        let upstreams = parse_upstreams(content);
        assert!(upstreams.contains_key("backend"));
        
        let upstream = &upstreams["backend"];
        assert!(matches!(upstream.method, LoadBalanceMethod::IpHash));
        assert_eq!(upstream.servers.len(), 3);
        assert_eq!(upstream.servers[0].weight, 3);
        assert!(upstream.servers[2].backup);
    }
    
    #[test]
    fn test_parse_listen() {
        let listen = parse_listen_directive("listen 443 ssl http2;").unwrap();
        assert_eq!(listen.port, 443);
        assert!(listen.ssl);
        assert!(listen.http2);
        
        let listen2 = parse_listen_directive("listen [::]:80 default_server;").unwrap();
        assert_eq!(listen2.port, 80);
        assert!(listen2.default_server);
    }

    #[test]
    fn test_root_conf_includes_subfolders_like_nginx() {
        // A root.conf that pulls in a subfolder via a glob include — the
        // nginx model. The server defined in the included file must show up.
        let dir = std::env::temp_dir().join(format!("wolfproxy-rootconf-{}", std::process::id()));
        let sites = dir.join("sites");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&sites).unwrap();

        fs::write(
            dir.join("root.conf"),
            "http {\n    include sites/*.conf;\n}\n",
        )
        .unwrap();
        fs::write(
            sites.join("app.conf"),
            "server {\n    listen 443 ssl;\n    server_name app.example.com;\n}\n",
        )
        .unwrap();

        let config = load_nginx_config(&dir);
        assert!(
            config.servers.iter().any(|s| s.server_names.iter().any(|n| n == "app.example.com")),
            "included server from sites/app.conf should be loaded via root.conf include; got {} server(s)",
            config.servers.len()
        );

        // And with NO root.conf, it must fall back to the auto-scan (conf.d).
        let dir2 = std::env::temp_dir().join(format!("wolfproxy-autoscan-{}", std::process::id()));
        let confd = dir2.join("conf.d");
        let _ = fs::remove_dir_all(&dir2);
        fs::create_dir_all(&confd).unwrap();
        fs::write(
            confd.join("site.conf"),
            "server {\n    listen 80;\n    server_name legacy.example.com;\n}\n",
        )
        .unwrap();
        let config2 = load_nginx_config(&dir2);
        assert!(
            config2.servers.iter().any(|s| s.server_names.iter().any(|n| n == "legacy.example.com")),
            "auto-scan fallback should still load conf.d servers when there's no root.conf"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn test_include_problems_are_surfaced_not_swallowed() {
        // A root.conf whose includes resolve to nothing must produce
        // include_warnings — silence is what left the operator stranded.
        let dir = std::env::temp_dir().join(format!("wolfproxy-incwarn-{}", std::process::id()));
        let sites = dir.join("sites-enabled");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&sites).unwrap();
        // The file exists but has NO .conf suffix (Debian symlink style), so a
        // `*.conf` glob matches nothing, and an explicit include points at a
        // file that isn't there.
        fs::write(sites.join("sonarr"), "server {\n    listen 80;\n    server_name s.example.com;\n}\n").unwrap();
        fs::write(
            dir.join("root.conf"),
            format!(
                "http {{\n    include {sites}/*.conf;\n    include {sites}/missing.conf;\n}}\n",
                sites = sites.display()
            ),
        )
        .unwrap();

        let config = load_nginx_config(&dir);
        assert_eq!(config.servers.len(), 0, "neither include should have matched a server");
        assert_eq!(config.include_warnings.len(), 2,
            "both the zero-match glob and the missing explicit include must warn; got {:?}",
            config.include_warnings);
        assert!(config.include_warnings.iter().any(|w| w.contains("matched no files")),
            "zero-match glob warning missing: {:?}", config.include_warnings);
        assert!(config.include_warnings.iter().any(|w| w.contains("does not exist")),
            "missing-file warning missing: {:?}", config.include_warnings);

        // Fixing the glob to `*` (which matches the extensionless file) loads
        // the server AND clears the glob warning.
        fs::write(
            dir.join("root.conf"),
            format!("http {{\n    include {sites}/*;\n}}\n", sites = sites.display()),
        )
        .unwrap();
        let ok = load_nginx_config(&dir);
        assert!(ok.servers.iter().any(|s| s.server_names.iter().any(|n| n == "s.example.com")),
            "`*` should match the extensionless file and load its server");
        assert!(ok.include_warnings.is_empty(),
            "a healthy include must produce no warnings; got {:?}", ok.include_warnings);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_server_block_glob_include_loads_locations() {
        // wabil 2026-06-13: `include sites/*.conf;` INSIDE a server block, where
        // the included file holds a location block. Previously this logged
        // "glob only supported for top-level includes" and dropped the
        // directives; now the locations must load into the server.
        let dir = std::env::temp_dir().join(format!("wp-srvinc-{}", std::process::id()));
        let sub = dir.join("sub");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            dir.join("root.conf"),
            format!(
                "http {{\n    server {{\n        listen 80;\n        server_name app.example.com;\n        include {}/*.conf;\n    }}\n}}\n",
                sub.display()
            ),
        )
        .unwrap();
        // Two included files with location blocks — both must merge in.
        fs::write(sub.join("api.conf"),
            "location /api/ {\n    proxy_pass http://127.0.0.1:9000;\n}\n").unwrap();
        fs::write(sub.join("static.conf"),
            "location /static/ {\n    proxy_pass http://127.0.0.1:9001;\n}\n").unwrap();

        let config = load_nginx_config(&dir);
        let _ = fs::remove_dir_all(&dir);
        let srv = config.servers.iter()
            .find(|s| s.server_names.iter().any(|n| n == "app.example.com"))
            .expect("server app.example.com should be parsed");
        assert!(srv.locations.len() >= 2,
            "both globbed server-block includes should load; got {} location(s): {:?}",
            srv.locations.len(), srv.locations.iter().map(|l| &l.path).collect::<Vec<_>>());
        assert!(srv.locations.iter().any(|l| l.proxy_pass.as_deref().is_some_and(|p| p.contains("9000"))),
            "included /api/ location's proxy_pass should be loaded; got {:?}",
            srv.locations.iter().map(|l| &l.proxy_pass).collect::<Vec<_>>());
        assert!(srv.locations.iter().any(|l| l.proxy_pass.as_deref().is_some_and(|p| p.contains("9001"))),
            "included /static/ location's proxy_pass should be loaded");
    }

    #[test]
    fn test_server_block_include_recursive_literal_and_skips_nested_server() {
        let dir = std::env::temp_dir().join(format!("wp-srvinc2-{}", std::process::id()));
        let sub = dir.join("sub");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&sub).unwrap();
        // app.example.com pulls in a LITERAL (non-glob) include and a file that
        // itself includes another (recursion), plus a file that wrongly holds a
        // full server block.
        fs::write(
            dir.join("root.conf"),
            format!(
                "http {{\n    server {{\n        listen 80;\n        server_name app.example.com;\n        include {sub}/outer.conf;\n        include {sub}/oops.conf;\n    }}\n}}\n",
                sub = sub.display()
            ),
        )
        .unwrap();
        fs::write(
            sub.join("outer.conf"),
            format!("location /a/ {{\n    proxy_pass http://127.0.0.1:7000;\n}}\ninclude {}/inner.conf;\n", sub.display()),
        )
        .unwrap();
        fs::write(sub.join("inner.conf"),
            "location /b/ {\n    proxy_pass http://127.0.0.1:7001;\n}\n").unwrap();
        // A full server block — must be skipped by the guard, NOT folded into app.
        fs::write(sub.join("oops.conf"),
            "server {\n    listen 81;\n    server_name nested.example.com;\n    location /evil/ { proxy_pass http://127.0.0.1:6666; }\n}\n").unwrap();

        let config = load_nginx_config(&dir);
        let _ = fs::remove_dir_all(&dir);
        let srv = config.servers.iter()
            .find(|s| s.server_names.iter().any(|n| n == "app.example.com"))
            .expect("app.example.com server should parse");
        // Literal include and the recursively-included file both loaded.
        assert!(srv.locations.iter().any(|l| l.proxy_pass.as_deref().is_some_and(|p| p.contains("7000"))),
            "literal server-block include (/a/) should load; got {:?}",
            srv.locations.iter().map(|l| &l.proxy_pass).collect::<Vec<_>>());
        assert!(srv.locations.iter().any(|l| l.proxy_pass.as_deref().is_some_and(|p| p.contains("7001"))),
            "recursively-included (/b/) should load");
        // The nested `server { }` must NOT fold its directives into app.
        assert!(!srv.locations.iter().any(|l| l.proxy_pass.as_deref().is_some_and(|p| p.contains("6666"))),
            "a server{{}}-containing include must be skipped, not folded into the outer server");
    }
}
