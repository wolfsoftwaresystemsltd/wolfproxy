//! Firewall module for WolfProxy
//! Automatically blocks IPs that exhibit malicious behavior
//! such as repeated TLS failures, path traversal attempts, or excessive requests

/// Hard caps to prevent memory exhaustion
const MAX_BLOCKED_IPS: usize = 10_000;
const MAX_TRACKED_IPS: usize = 50_000;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tracing::warn;

/// Reason an IP was blocked
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BlockReason {
    TlsAbuse,           // Repeated TLS handshake failures
    PathTraversal,      // Attempted path traversal (..)
    RateLimit,          // Too many requests per second
    BadRequests,        // Too many 4xx errors
    Scanner,            // Known scanner behavior (no SNI, random ports)
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::TlsAbuse => write!(f, "TLS abuse"),
            BlockReason::PathTraversal => write!(f, "path traversal attempt"),
            BlockReason::RateLimit => write!(f, "rate limit exceeded"),
            BlockReason::BadRequests => write!(f, "excessive bad requests"),
            BlockReason::Scanner => write!(f, "scanner/probe detected"),
        }
    }
}

/// Tracking info for a single IP
struct IpTracker {
    /// Failed TLS handshakes
    tls_failures: u32,
    /// Bad requests (4xx)
    bad_requests: u32,
    /// Total requests in current window
    request_count: u32,
    /// Window start time
    window_start: Instant,
    /// Path traversal attempts  
    traversal_attempts: u32,
}

impl IpTracker {
    fn new() -> Self {
        Self {
            tls_failures: 0,
            bad_requests: 0,
            request_count: 0,
            window_start: Instant::now(),
            traversal_attempts: 0,
        }
    }

    /// Reset counters if the window has expired
    fn maybe_reset(&mut self, window: Duration) {
        if self.window_start.elapsed() > window {
            self.tls_failures = 0;
            self.bad_requests = 0;
            self.request_count = 0;
            self.traversal_attempts = 0;
            self.window_start = Instant::now();
        }
    }
}

/// A blocked IP entry
#[allow(dead_code)]
struct BlockEntry {
    reason: BlockReason,
    blocked_at: Instant,
    expires_at: Instant,
}

/// Firewall configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct FirewallConfig {
    /// Enable the firewall
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Time window for counting violations (seconds)
    #[serde(default = "default_window")]
    pub window_secs: u64,

    /// Ban duration (seconds) - default 10 minutes
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,

    /// TLS failures before ban
    #[serde(default = "default_tls_threshold")]
    pub tls_failure_threshold: u32,

    /// Bad requests (4xx) before ban
    #[serde(default = "default_bad_request_threshold")]
    pub bad_request_threshold: u32,

    /// Requests per window before rate limit ban
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,

    /// Path traversal attempts before ban (low threshold - always malicious)
    #[serde(default = "default_traversal_threshold")]
    pub traversal_threshold: u32,
}

fn default_enabled() -> bool { false }
fn default_window() -> u64 { 60 }
fn default_ban_duration() -> u64 { 600 }
fn default_tls_threshold() -> u32 { 100 }
fn default_bad_request_threshold() -> u32 { 50 }
fn default_rate_limit() -> u32 { 1000 }
fn default_traversal_threshold() -> u32 { 3 }

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: 60,
            ban_duration_secs: 600,
            tls_failure_threshold: 100,
            bad_request_threshold: 50,
            rate_limit: 1000,
            traversal_threshold: 3,
        }
    }
}

/// The firewall - tracks IPs and blocks offenders
pub struct Firewall {
    config: FirewallConfig,
    /// Active blocks
    blocked: DashMap<IpAddr, BlockEntry>,
    /// Per-IP tracking
    trackers: DashMap<IpAddr, IpTracker>,
    /// Total blocks ever
    pub total_blocks: AtomicU64,
    /// Total requests denied
    pub total_denied: AtomicU64,
}

#[allow(dead_code)]
impl Firewall {
    pub fn new(config: FirewallConfig) -> Self {
        let fw = Self {
            config,
            blocked: DashMap::new(),
            trackers: DashMap::new(),
            total_blocks: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        };

        // Spawn cleanup task
        fw
    }

    /// Check if an IP is blocked. Returns true if blocked.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Skip localhost
        if ip.is_loopback() {
            return false;
        }

        if let Some(entry) = self.blocked.get(ip) {
            if Instant::now() < entry.expires_at {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                return true;
            } else {
                // Ban expired, remove it
                drop(entry);
                self.blocked.remove(ip);
            }
        }
        false
    }

    /// Record a TLS handshake failure
    pub fn record_tls_failure(&self, ip: IpAddr) {
        if !self.config.enabled || ip.is_loopback() {
            return;
        }

        let window = Duration::from_secs(self.config.window_secs);
        // Don't track if we've hit the cap
        if self.trackers.len() >= MAX_TRACKED_IPS && !self.trackers.contains_key(&ip) {
            return;
        }
        let mut tracker = self.trackers.entry(ip).or_insert_with(IpTracker::new);
        tracker.maybe_reset(window);
        tracker.tls_failures += 1;

        if tracker.tls_failures >= self.config.tls_failure_threshold {
            drop(tracker);
            self.block_ip(ip, BlockReason::TlsAbuse);
        }
    }

    /// Record a bad request (4xx error)
    pub fn record_bad_request(&self, ip: IpAddr) {
        if !self.config.enabled || ip.is_loopback() {
            return;
        }

        let window = Duration::from_secs(self.config.window_secs);
        let mut tracker = self.trackers.entry(ip).or_insert_with(IpTracker::new);
        tracker.maybe_reset(window);
        tracker.bad_requests += 1;

        if tracker.bad_requests >= self.config.bad_request_threshold {
            drop(tracker);
            self.block_ip(ip, BlockReason::BadRequests);
        }
    }

    /// Record a request (for rate limiting)
    pub fn record_request(&self, ip: IpAddr) {
        if !self.config.enabled || ip.is_loopback() {
            return;
        }

        let window = Duration::from_secs(self.config.window_secs);
        let mut tracker = self.trackers.entry(ip).or_insert_with(IpTracker::new);
        tracker.maybe_reset(window);
        tracker.request_count += 1;

        if tracker.request_count >= self.config.rate_limit {
            drop(tracker);
            self.block_ip(ip, BlockReason::RateLimit);
        }
    }

    /// Record a path traversal attempt
    pub fn record_traversal(&self, ip: IpAddr) {
        if !self.config.enabled || ip.is_loopback() {
            return;
        }

        let window = Duration::from_secs(self.config.window_secs);
        let mut tracker = self.trackers.entry(ip).or_insert_with(IpTracker::new);
        tracker.maybe_reset(window);
        tracker.traversal_attempts += 1;

        if tracker.traversal_attempts >= self.config.traversal_threshold {
            drop(tracker);
            self.block_ip(ip, BlockReason::PathTraversal);
        }
    }

    /// Block an IP
    fn block_ip(&self, ip: IpAddr, reason: BlockReason) {
        // Don't re-block if already blocked
        if self.blocked.contains_key(&ip) {
            return;
        }

        // Enforce hard cap - evict expired entries first
        if self.blocked.len() >= MAX_BLOCKED_IPS {
            self.cleanup();
            if self.blocked.len() >= MAX_BLOCKED_IPS {
                return; // Still full, skip to avoid memory exhaustion
            }
        }

        let now = Instant::now();
        let ban_duration = Duration::from_secs(self.config.ban_duration_secs);

        warn!("🛡️ BLOCKED {} for {} (ban duration: {}s)", ip, reason, self.config.ban_duration_secs);

        self.blocked.insert(ip, BlockEntry {
            reason,
            blocked_at: now,
            expires_at: now + ban_duration,
        });

        self.total_blocks.fetch_add(1, Ordering::Relaxed);
        // Clean up tracker
        self.trackers.remove(&ip);
    }

    /// Get count of currently blocked IPs
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// Clean up expired blocks and stale trackers
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs * 5);

        // Remove expired blocks
        self.blocked.retain(|_ip, entry| {
            now < entry.expires_at
        });

        // Remove stale trackers (no activity for 5x the window)
        self.trackers.retain(|_ip, tracker| {
            tracker.window_start.elapsed() < window
        });
    }

    /// Get list of currently blocked IPs for monitoring
    pub fn blocked_list(&self) -> Vec<(IpAddr, String, u64)> {
        let now = Instant::now();
        self.blocked.iter()
            .filter(|entry| now < entry.expires_at)
            .map(|entry| {
                let remaining = (entry.expires_at - now).as_secs();
                (*entry.key(), entry.reason.to_string(), remaining)
            })
            .collect()
    }
}
