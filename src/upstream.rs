//! Upstream load balancer module
//! Handles load balancing across multiple backend servers

use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use dashmap::DashMap;
use fnv::FnvHasher;
use rand::Rng;
use tokio::sync::RwLock;
use hyper::http::Method;

use crate::nginx::{Upstream, UpstreamServer, LoadBalanceMethod};

/// WolfScale cluster state tracking
/// Tracks which server is the current leader for write routing
#[derive(Debug)]
pub struct WolfScaleState {
    /// Index of the current leader in the servers list
    pub leader_index: RwLock<Option<usize>>,
    /// Last time we refreshed leader info
    pub last_refresh: RwLock<Instant>,
    /// Refresh interval (default 1 second)
    pub refresh_interval: Duration,
}

/// Health status of a backend server
#[allow(dead_code)]
#[derive(Debug)]
pub struct ServerHealth {
    /// Is the server healthy?
    pub healthy: bool,
    /// Number of consecutive failures
    pub failures: AtomicUsize,
    /// Last failure time
    pub last_failure: Option<Instant>,
    /// Total requests served
    pub total_requests: AtomicU64,
    /// Active connections
    pub active_connections: AtomicUsize,
}

impl Default for ServerHealth {
    fn default() -> Self {
        Self {
            healthy: true,
            failures: AtomicUsize::new(0),
            last_failure: None,
            total_requests: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }
}

/// A backend server with health tracking
#[derive(Debug, Clone)]
pub struct BackendServer {
    pub config: UpstreamServer,
    pub health: Arc<ServerHealth>,
    pub url: String,
}

impl BackendServer {
    pub fn new(config: UpstreamServer) -> Self {
        let url = if config.port == 80 {
            format!("http://{}", config.address)
        } else if config.port == 443 {
            format!("https://{}", config.address)
        } else {
            format!("http://{}:{}", config.address, config.port)
        };
        
        Self {
            config,
            health: Arc::new(ServerHealth::default()),
            url,
        }
    }
    
    /// Check if the server is available
    pub fn is_available(&self) -> bool {
        if self.config.down {
            return false;
        }
        
        // Check if we've exceeded max_fails
        let failures = self.health.failures.load(Ordering::Relaxed);
        if failures >= self.config.max_fails as usize {
            // Check if fail_timeout has elapsed
            if let Some(last_failure) = self.health.last_failure {
                if last_failure.elapsed() < Duration::from_secs(self.config.fail_timeout) {
                    return false;
                }
                // Reset failures after timeout
                self.health.failures.store(0, Ordering::Relaxed);
            }
        }
        
        true
    }
    
    /// Record a successful request
    #[allow(dead_code)]
    pub fn record_success(&self) {
        self.health.failures.store(0, Ordering::Relaxed);
        self.health.total_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record a failed request
    #[allow(dead_code)]
    pub fn record_failure(&self) {
        self.health.failures.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increment active connections
    #[allow(dead_code)]
    pub fn connect(&self) {
        self.health.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Decrement active connections
    #[allow(dead_code)]
    pub fn disconnect(&self) {
        self.health.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Load balancer for an upstream group
#[allow(dead_code)]
pub struct LoadBalancer {
    pub name: String,
    pub method: LoadBalanceMethod,
    pub servers: Vec<BackendServer>,
    pub backup_servers: Vec<BackendServer>,
    /// Current index for round-robin
    current_index: AtomicUsize,
    /// Affinity cache keyed by IP or session identifier
    affinity_cache: DashMap<String, usize>,
    /// Keepalive connections count
    pub keepalive: Option<u32>,
    /// WolfScale cluster state (only used when method is WolfScale)
    pub wolfscale_state: Option<Arc<WolfScaleState>>,
}

impl LoadBalancer {
    pub fn new(upstream: &Upstream) -> Self {
        let mut servers = Vec::new();
        let mut backup_servers = Vec::new();
        
        for server in &upstream.servers {
            let backend = BackendServer::new(server.clone());
            if server.backup {
                backup_servers.push(backend);
            } else {
                servers.push(backend);
            }
        }
        
        // Create WolfScale state if needed
        let wolfscale_state = if matches!(upstream.method, LoadBalanceMethod::WolfScale) {
            Some(Arc::new(WolfScaleState {
                leader_index: RwLock::new(None),
                last_refresh: RwLock::new(Instant::now()),
                refresh_interval: Duration::from_secs(1),
            }))
        } else {
            None
        };
        
        Self {
            name: upstream.name.clone(),
            method: upstream.method.clone(),
            servers,
            backup_servers,
            current_index: AtomicUsize::new(0),
            affinity_cache: DashMap::new(),
            keepalive: upstream.keepalive,
            wolfscale_state,
        }
    }
    
    /// Get the next available backend server
    pub fn next_server(&self, affinity_key: Option<&str>) -> Option<&BackendServer> {
        // Try primary servers first
        if let Some(server) = self.select_server(&self.servers, affinity_key) {
            return Some(server);
        }
        
        // Fall back to backup servers
        self.select_server(&self.backup_servers, affinity_key)
    }
    
    fn select_server<'a>(&'a self, servers: &'a [BackendServer], affinity_key: Option<&str>) -> Option<&'a BackendServer> {
        let available: Vec<usize> = servers.iter()
            .enumerate()
            .filter(|(_, s)| s.is_available())
            .map(|(i, _)| i)
            .collect();
        
        if available.is_empty() {
            return None;
        }

        // If we have an affinity key (e.g., PHPSESSID), pin to the hashed server when healthy
        if let Some(key) = affinity_key {
            if let Some(server) = self.sticky_by_key(servers, &available, key) {
                return Some(server);
            }
        }
        
        let index = match &self.method {
            LoadBalanceMethod::RoundRobin => {
                self.round_robin(&available)
            }
            LoadBalanceMethod::WeightedRoundRobin => {
                self.weighted_round_robin(servers, &available)
            }
            LoadBalanceMethod::IpHash => {
                let key = affinity_key.unwrap_or("default");
                self.hash_by_key(&available, key)
            }
            LoadBalanceMethod::LeastConn => {
                self.least_connections(servers, &available)
            }
            LoadBalanceMethod::Random => {
                self.random(&available)
            }
            LoadBalanceMethod::WolfScale => {
                // For reads, use round-robin across all available servers
                // Write routing is handled separately via next_server_for_method
                self.round_robin(&available)
            }
        };
        
        servers.get(index)
    }
    
    fn round_robin(&self, available: &[usize]) -> usize {
        let idx = self.current_index.fetch_add(1, Ordering::Relaxed);
        available[idx % available.len()]
    }
    
    fn weighted_round_robin(&self, servers: &[BackendServer], available: &[usize]) -> usize {
        // Build weighted list
        let mut weighted_available: Vec<usize> = Vec::new();
        for &idx in available {
            let weight = servers[idx].config.weight as usize;
            for _ in 0..weight {
                weighted_available.push(idx);
            }
        }
        
        if weighted_available.is_empty() {
            return available[0];
        }
        
        let idx = self.current_index.fetch_add(1, Ordering::Relaxed);
        weighted_available[idx % weighted_available.len()]
    }
    
    fn hash_by_key(&self, available: &[usize], key: &str) -> usize {
        let mut hasher = FnvHasher::default();
        key.hash(&mut hasher);
        let hash = hasher.finish() as usize;
        available[hash % available.len()]
    }

    fn sticky_by_key<'a>(&'a self, servers: &'a [BackendServer], available: &[usize], key: &str) -> Option<&'a BackendServer> {
        // Check cache first
        if let Some(cached) = self.affinity_cache.get(key) {
            if available.contains(&*cached) {
                return servers.get(*cached);
            }
        }

        // Build weighted pool so affinity respects weights
        let mut weighted: Vec<usize> = Vec::new();
        for &idx in available {
            let weight = servers
                .get(idx)
                .map(|s| s.config.weight.max(1) as usize)
                .unwrap_or(1);
            for _ in 0..weight {
                weighted.push(idx);
            }
        }

        let pool: Vec<usize> = if weighted.is_empty() {
            available.to_vec()
        } else {
            weighted
        };

        let selected = self.hash_by_key(&pool, key);
        self.affinity_cache.insert(key.to_string(), selected);

        servers.get(selected)
    }
    
    fn least_connections(&self, servers: &[BackendServer], available: &[usize]) -> usize {
        let mut min_connections = usize::MAX;
        let mut min_idx = available[0];
        
        for &idx in available {
            let connections = servers[idx].health.active_connections.load(Ordering::Relaxed);
            if connections < min_connections {
                min_connections = connections;
                min_idx = idx;
            }
        }
        
        min_idx
    }
    
    fn random(&self, available: &[usize]) -> usize {
        let mut rng = rand::thread_rng();
        available[rng.gen_range(0..available.len())]
    }
    
    /// Get the next available backend server, considering HTTP method for WolfScale mode
    /// For WolfScale upstreams:
    /// - Write methods (POST, PUT, DELETE, PATCH) go to the leader
    /// - Read methods (GET, HEAD, OPTIONS) are load balanced
    pub fn next_server_for_method(&self, affinity_key: Option<&str>, method: Option<&Method>) -> Option<&BackendServer> {
        // If not WolfScale mode, use normal server selection
        if !matches!(self.method, LoadBalanceMethod::WolfScale) {
            return self.next_server(affinity_key);
        }
        
        // Check if this is a write request
        let is_write = method.map(|m| {
            matches!(m, &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH)
        }).unwrap_or(false);
        
        if is_write {
            // For writes, use the leader if we know it
            if let Some(ref state) = self.wolfscale_state {
                // Try to get cached leader synchronously (blocking read)
                // In real async context, caller should use async version
                if let Ok(leader_guard) = state.leader_index.try_read() {
                    if let Some(leader_idx) = *leader_guard {
                        if leader_idx < self.servers.len() {
                            let server = &self.servers[leader_idx];
                            if server.is_available() {
                                return Some(server);
                            }
                        }
                    }
                }
            }
            // Fall back to first available server if leader unknown
            // The first server is typically the one with lowest priority/ID
            return self.servers.iter().find(|s| s.is_available());
        }
        
        // For reads, load balance across all servers
        self.next_server(affinity_key)
    }
    
    /// Set the current WolfScale leader by server index
    pub async fn set_leader_index(&self, index: usize) {
        if let Some(ref state) = self.wolfscale_state {
            let mut leader = state.leader_index.write().await;
            *leader = Some(index);
            let mut last_refresh = state.last_refresh.write().await;
            *last_refresh = Instant::now();
        }
    }
    
    /// Find server index by address/hostname
    pub fn find_server_index(&self, address: &str) -> Option<usize> {
        self.servers.iter().position(|s| {
            s.config.address == address || 
            s.url.contains(address) ||
            address.contains(&s.config.address)
        })
    }
    
    /// Check if WolfScale leader info needs refresh
    pub async fn needs_leader_refresh(&self) -> bool {
        if let Some(ref state) = self.wolfscale_state {
            let last_refresh = state.last_refresh.read().await;
            last_refresh.elapsed() > state.refresh_interval
        } else {
            false
        }
    }
    
    /// Get all healthy servers
    #[allow(dead_code)]
    pub fn healthy_servers(&self) -> Vec<&BackendServer> {
        self.servers.iter()
            .chain(self.backup_servers.iter())
            .filter(|s| s.is_available())
            .collect()
    }
    
    /// Get server by address
    #[allow(dead_code)]
    pub fn get_server(&self, address: &str) -> Option<&BackendServer> {
        self.servers.iter()
            .chain(self.backup_servers.iter())
            .find(|s| s.url == address || s.config.address == address)
    }
}

/// Manager for all upstreams
#[derive(Clone)]
pub struct UpstreamManager {
    upstreams: HashMap<String, Arc<LoadBalancer>>,
}

impl UpstreamManager {
    pub fn new() -> Self {
        Self {
            upstreams: HashMap::new(),
        }
    }
    
    pub fn add_upstream(&mut self, upstream: &Upstream) {
        let lb = LoadBalancer::new(upstream);
        self.upstreams.insert(upstream.name.clone(), Arc::new(lb));
    }
    
    pub fn get(&self, name: &str) -> Option<Arc<LoadBalancer>> {
        self.upstreams.get(name).cloned()
    }
    
    #[allow(dead_code)]
    pub fn all(&self) -> &HashMap<String, Arc<LoadBalancer>> {
        &self.upstreams
    }
}

impl Default for UpstreamManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard for tracking active connections
#[allow(dead_code)]
pub struct ConnectionGuard<'a> {
    server: &'a BackendServer,
}

impl<'a> ConnectionGuard<'a> {
    #[allow(dead_code)]
    pub fn new(server: &'a BackendServer) -> Self {
        server.connect();
        Self { server }
    }
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        self.server.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn make_upstream() -> Upstream {
        Upstream {
            name: "test".to_string(),
            method: LoadBalanceMethod::RoundRobin,
            servers: vec![
                UpstreamServer {
                    address: "10.0.0.1".to_string(),
                    port: 8080,
                    weight: 1,
                    max_fails: 3,
                    fail_timeout: 30,
                    backup: false,
                    down: false,
                },
                UpstreamServer {
                    address: "10.0.0.2".to_string(),
                    port: 8080,
                    weight: 1,
                    max_fails: 3,
                    fail_timeout: 30,
                    backup: false,
                    down: false,
                },
            ],
            keepalive: Some(32),
        }
    }
    
    #[test]
    fn test_round_robin() {
        let upstream = make_upstream();
        let lb = LoadBalancer::new(&upstream);
        
        let s1 = lb.next_server(None).unwrap();
        let s2 = lb.next_server(None).unwrap();
        let s3 = lb.next_server(None).unwrap();
        
        // Should cycle through servers
        assert_ne!(s1.config.address, s2.config.address);
        assert_eq!(s1.config.address, s3.config.address);
    }
    
    #[test]
    fn test_ip_hash() {
        let mut upstream = make_upstream();
        upstream.method = LoadBalanceMethod::IpHash;
        let lb = LoadBalancer::new(&upstream);
        
        // Same IP should always get same server
        let s1 = lb.next_server(Some("192.168.1.1")).unwrap();
        let s2 = lb.next_server(Some("192.168.1.1")).unwrap();
        
        assert_eq!(s1.config.address, s2.config.address);
    }

    #[test]
    fn test_session_affinity() {
        let upstream = make_upstream();
        let lb = LoadBalancer::new(&upstream);

        // Same session id should stick to the same backend
        let s1 = lb.next_server(Some("php-session-123")).unwrap();
        let s2 = lb.next_server(Some("php-session-123")).unwrap();
        assert_eq!(s1.config.address, s2.config.address);
    }
}
