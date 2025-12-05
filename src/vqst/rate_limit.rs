//! Rate limiting and DoS protection for VQST
//!
//! Protects against:
//! - Connection flooding
//! - Excessive handshake attempts
//! - Resource exhaustion attacks

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Rate limiter configuration
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum connections per IP per time window
    pub max_connections_per_ip: usize,
    /// Time window for connection counting
    pub connection_window: Duration,
    /// Maximum handshake attempts per IP per window
    pub max_handshakes_per_ip: usize,
    /// Time window for handshake counting
    pub handshake_window: Duration,
    /// Maximum failed handshakes before temporary ban
    pub max_failed_handshakes: usize,
    /// Ban duration for excessive failures
    pub ban_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 10,
            connection_window: Duration::from_secs(60),
            max_handshakes_per_ip: 20,
            handshake_window: Duration::from_secs(60),
            max_failed_handshakes: 5,
            ban_duration: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Connection tracking entry
#[derive(Debug)]
struct ConnectionEntry {
    count: usize,
    first_seen: Instant,
    last_seen: Instant,
}

/// Handshake tracking entry
#[derive(Debug)]
struct HandshakeEntry {
    attempts: usize,
    failures: usize,
    first_attempt: Instant,
    last_attempt: Instant,
}

/// Ban entry
#[derive(Debug)]
struct BanEntry {
    banned_at: Instant,
    reason: String,
}

/// Rate limiter for VQST connections
pub struct RateLimiter {
    config: RateLimitConfig,
    connections: HashMap<IpAddr, ConnectionEntry>,
    handshakes: HashMap<IpAddr, HandshakeEntry>,
    bans: HashMap<IpAddr, BanEntry>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            handshakes: HashMap::new(),
            bans: HashMap::new(),
        }
    }

    /// Check if an IP is allowed to connect
    pub fn check_connection(&mut self, ip: IpAddr) -> Result<(), String> {
        // Check if IP is banned
        if let Some(ban) = self.bans.get(&ip) {
            if ban.banned_at.elapsed() < self.config.ban_duration {
                let remaining = self.config.ban_duration - ban.banned_at.elapsed();
                return Err(format!(
                    "IP banned for {}: {} ({}s remaining)",
                    ban.reason,
                    ip,
                    remaining.as_secs()
                ));
            } else {
                // Ban expired, remove it
                self.bans.remove(&ip);
            }
        }

        // Get or create connection entry
        let now = Instant::now();
        let entry = self.connections.entry(ip).or_insert(ConnectionEntry {
            count: 0,
            first_seen: now,
            last_seen: now,
        });

        // Check if window has expired
        if now.duration_since(entry.first_seen) > self.config.connection_window {
            // Reset window
            entry.count = 0;
            entry.first_seen = now;
        }

        // Check rate limit
        if entry.count >= self.config.max_connections_per_ip {
            return Err(format!(
                "Rate limit exceeded: {} connections from {} in {}s",
                entry.count,
                ip,
                self.config.connection_window.as_secs()
            ));
        }

        // Update entry
        entry.count += 1;
        entry.last_seen = now;

        Ok(())
    }

    /// Record a handshake attempt
    pub fn record_handshake_attempt(&mut self, ip: IpAddr) -> Result<(), String> {
        let now = Instant::now();
        let entry = self.handshakes.entry(ip).or_insert(HandshakeEntry {
            attempts: 0,
            failures: 0,
            first_attempt: now,
            last_attempt: now,
        });

        // Check if window has expired
        if now.duration_since(entry.first_attempt) > self.config.handshake_window {
            // Reset window
            entry.attempts = 0;
            entry.failures = 0;
            entry.first_attempt = now;
        }

        // Check rate limit
        if entry.attempts >= self.config.max_handshakes_per_ip {
            return Err(format!(
                "Handshake rate limit exceeded: {} attempts from {} in {}s",
                entry.attempts,
                ip,
                self.config.handshake_window.as_secs()
            ));
        }

        // Update entry
        entry.attempts += 1;
        entry.last_attempt = now;

        Ok(())
    }

    /// Record a handshake failure
    pub fn record_handshake_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let entry = self.handshakes.entry(ip).or_insert(HandshakeEntry {
            attempts: 0,
            failures: 0,
            first_attempt: now,
            last_attempt: now,
        });

        entry.failures += 1;
        let failure_count = entry.failures;
        let max_failures = self.config.max_failed_handshakes;

        // Drop the borrow before calling ban_ip
        drop(entry);

        // Check if we should ban this IP
        if failure_count >= max_failures {
            self.ban_ip(ip, format!("{} failed handshakes", failure_count));
        }
    }

    /// Record a successful handshake
    pub fn record_handshake_success(&mut self, ip: IpAddr) {
        // Reset failure count on success
        if let Some(entry) = self.handshakes.get_mut(&ip) {
            entry.failures = 0;
        }
    }

    /// Ban an IP address
    pub fn ban_ip(&mut self, ip: IpAddr, reason: String) {
        self.bans.insert(ip, BanEntry {
            banned_at: Instant::now(),
            reason,
        });
    }

    /// Unban an IP address
    pub fn unban_ip(&mut self, ip: IpAddr) {
        self.bans.remove(&ip);
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if let Some(ban) = self.bans.get(&ip) {
            ban.banned_at.elapsed() < self.config.ban_duration
        } else {
            false
        }
    }

    /// Clean up expired entries (call periodically)
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        // Remove old connection entries
        self.connections.retain(|_, entry| {
            now.duration_since(entry.last_seen) < self.config.connection_window * 2
        });

        // Remove old handshake entries
        self.handshakes.retain(|_, entry| {
            now.duration_since(entry.last_attempt) < self.config.handshake_window * 2
        });

        // Remove expired bans
        self.bans.retain(|_, ban| {
            ban.banned_at.elapsed() < self.config.ban_duration
        });
    }

    /// Get statistics
    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            tracked_ips: self.connections.len(),
            active_handshakes: self.handshakes.len(),
            banned_ips: self.bans.len(),
        }
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub tracked_ips: usize,
    pub active_handshakes: usize,
    pub banned_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, IpAddr};

    #[test]
    fn test_connection_rate_limit() {
        let config = RateLimitConfig {
            max_connections_per_ip: 3,
            connection_window: Duration::from_secs(60),
            ..Default::default()
        };
        let mut limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 connections should succeed
        assert!(limiter.check_connection(ip).is_ok());
        assert!(limiter.check_connection(ip).is_ok());
        assert!(limiter.check_connection(ip).is_ok());

        // 4th should fail
        assert!(limiter.check_connection(ip).is_err());
    }

    #[test]
    fn test_handshake_failure_ban() {
        let config = RateLimitConfig {
            max_failed_handshakes: 3,
            ..Default::default()
        };
        let mut limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Record failures
        limiter.record_handshake_failure(ip);
        limiter.record_handshake_failure(ip);
        assert!(!limiter.is_banned(ip));

        // 3rd failure should trigger ban
        limiter.record_handshake_failure(ip);
        assert!(limiter.is_banned(ip));
    }

    #[test]
    fn test_cleanup() {
        let config = RateLimitConfig {
            connection_window: Duration::from_millis(10),
            ..Default::default()
        };
        let mut limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        limiter.check_connection(ip).unwrap();
        assert_eq!(limiter.stats().tracked_ips, 1);

        std::thread::sleep(Duration::from_millis(30));
        limiter.cleanup();

        // Should be cleaned up
        assert_eq!(limiter.stats().tracked_ips, 0);
    }
}
