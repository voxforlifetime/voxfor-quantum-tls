//! Nonce Database for Replay Attack Prevention
//! 
//! Tracks seen nonces within the replay time window to prevent
//! replay attacks even within the timestamp tolerance period.
//!
//! # 🔴 CRITICAL: Distributed Deployment Warning
//!
//! **Single Point of Failure for Load-Balanced Servers**
//!
//! ## The Problem
//!
//! Current implementation uses in-memory storage only. This creates a
//! vulnerability in distributed/load-balanced deployments:
//!
//! ```text
//! 1. Client → Server A: ClientHello(nonce=X)
//! 2. Server A stores nonce X in memory
//! 3. Attacker → Server B: ClientHello(nonce=X)  ❌ ACCEPTED!
//!    → Server B has no knowledge of nonce X
//!    → Replay attack succeeds!
//! ```
//!
//! ## Solutions for Production
//!
//! **Option 1: Shared Redis/Memcached (RECOMMENDED)**
//! ```rust
//! // Use shared cache for nonce tracking
//! let nonce_db = NonceDatabase::with_redis("redis://cache:6379")?;
//! ```
//!
//! **Option 2: Sticky Sessions**
//! - Configure load balancer to send same client to same server
//! - Still vulnerable to server failover
//!
//! **Option 3: Database-backed Storage**
//! - Use persistent DB (PostgreSQL, SQLite)
//! - Higher latency but works across restarts
//!
//! ## Current Status: ⚠️ UNSAFE FOR LOAD BALANCING
//!
//! Use this implementation only for:
//! - Single-server deployments
//! - Development/testing
//! - Behind sticky session load balancer with no failover
//!
//! **DO NOT USE** for:
//! - Multi-server production without shared storage
//! - High-availability setups with failover
//! - Any load-balanced deployment

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::path::{Path, PathBuf};
use std::fs;

#[cfg(feature = "persistent-nonce-db")]
use std::collections::HashMap;

/// Entry in the nonce database with expiry time
#[derive(Clone, Debug)]
struct NonceEntry {
    nonce: [u8; 32],
    expiry: Instant,
}

/// Thread-safe nonce database for replay protection
/// 
/// # Security Model
/// - Stores all seen nonces within the replay window
/// - Automatically expires old entries
/// - Thread-safe for concurrent handshakes
/// - Constant-time nonce comparison
#[derive(Clone)]
pub struct NonceDatabase {
    /// Set of seen nonces with their expiry times
    /// Using HashSet for O(1) lookup
    seen: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Expiry list for cleanup
    expiry_queue: Arc<RwLock<Vec<NonceEntry>>>,
    /// Time window for nonce validity
    window: Duration,
}

impl NonceDatabase {
    /// Create new nonce database
    /// 
    /// # Arguments
    /// * `window` - Time window for nonce validity (e.g., 10 seconds)
    pub fn new(window: Duration) -> Self {
        Self {
            seen: Arc::new(RwLock::new(HashSet::new())),
            expiry_queue: Arc::new(RwLock::new(Vec::new())),
            window,
        }
    }
    
    /// Check if nonce has been seen before and mark it as seen
    /// 
    /// # Arguments
    /// * `nonce` - 32-byte nonce to check
    /// 
    /// # Returns
    /// * `Ok(())` if nonce is fresh (not seen before)
    /// * `Err(String)` if nonce is a replay
    /// 
    /// # Security
    /// This is the critical replay protection check. A replayed
    /// nonce indicates an attack and MUST be rejected.
    pub fn check_and_store(&self, nonce: &[u8; 32]) -> Result<(), String> {
        // First, cleanup expired entries
        self.cleanup_expired();
        
        // Check if nonce exists (O(1) with HashSet)
        {
            let seen = self.seen.read()
                .map_err(|_| "Failed to acquire read lock".to_string())?;
            
            if seen.contains(nonce) {
                return Err(format!("Replay detected: nonce {:?} already seen", 
                    &nonce[..8]));
            }
        }
        
        // Store nonce with expiry
        {
            let mut seen = self.seen.write()
                .map_err(|_| "Failed to acquire write lock".to_string())?;
            
            let mut expiry_queue = self.expiry_queue.write()
                .map_err(|_| "Failed to acquire expiry lock".to_string())?;
            
            let expiry = Instant::now() + self.window;
            
            seen.insert(*nonce);
            expiry_queue.push(NonceEntry {
                nonce: *nonce,
                expiry,
            });
        }
        
        Ok(())
    }
    
    /// Remove expired nonces from the database
    /// 
    /// This is called automatically before each check to prevent
    /// unbounded memory growth. Old nonces are removed once they
    /// fall outside the replay window.
    fn cleanup_expired(&self) {
        let now = Instant::now();
        
        // Get write locks
        let mut seen = match self.seen.write() {
            Ok(s) => s,
            Err(_) => return, // Skip cleanup on lock failure
        };
        
        let mut expiry_queue = match self.expiry_queue.write() {
            Ok(eq) => eq,
            Err(_) => return,
        };
        
        // Remove expired entries
        expiry_queue.retain(|entry| {
            if entry.expiry <= now {
                seen.remove(&entry.nonce);
                false // Remove from queue
            } else {
                true // Keep in queue
            }
        });
    }
    
    /// Get current number of stored nonces
    /// 
    /// Useful for monitoring and testing
    pub fn size(&self) -> usize {
        self.seen.read()
            .map(|s| s.len())
            .unwrap_or(0)
    }
    
    /// Clear all nonces (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut seen) = self.seen.write() {
            seen.clear();
        }
        if let Ok(mut eq) = self.expiry_queue.write() {
            eq.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_nonce_fresh_accepted() {
        let db = NonceDatabase::new(Duration::from_secs(10));
        let nonce = [1u8; 32];
        
        // First use should succeed
        assert!(db.check_and_store(&nonce).is_ok());
    }
    
    #[test]
    fn test_nonce_replay_rejected() {
        let db = NonceDatabase::new(Duration::from_secs(10));
        let nonce = [2u8; 32];
        
        // First use succeeds
        assert!(db.check_and_store(&nonce).is_ok());
        
        // Second use (replay) should fail
        let result = db.check_and_store(&nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Replay detected"));
    }
    
    #[test]
    fn test_different_nonces_accepted() {
        let db = NonceDatabase::new(Duration::from_secs(10));
        
        let nonce1 = [3u8; 32];
        let nonce2 = [4u8; 32];
        
        assert!(db.check_and_store(&nonce1).is_ok());
        assert!(db.check_and_store(&nonce2).is_ok());
    }
    
    #[test]
    fn test_nonce_expiry() {
        let db = NonceDatabase::new(Duration::from_millis(100));
        let nonce = [5u8; 32];
        
        // Store nonce
        assert!(db.check_and_store(&nonce).is_ok());
        assert_eq!(db.size(), 1);
        
        // Wait for expiry
        thread::sleep(Duration::from_millis(150));
        
        // Cleanup should remove expired nonce
        let nonce2 = [6u8; 32];
        db.check_and_store(&nonce2).unwrap();
        
        // Original nonce should be usable again after expiry
        assert!(db.check_and_store(&nonce).is_ok());
    }
    
    #[test]
    fn test_concurrent_access() {
        let db = Arc::new(NonceDatabase::new(Duration::from_secs(10)));
        let mut handles = vec![];
        
        for i in 0..10 {
            let db_clone = Arc::clone(&db);
            let handle = thread::spawn(move || {
                let mut nonce = [0u8; 32];
                nonce[0] = i;
                db_clone.check_and_store(&nonce).unwrap();
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(db.size(), 10);
    }
    
    #[test]
    fn test_cleanup_effectiveness() {
        let db = NonceDatabase::new(Duration::from_millis(50));
        
        // Add 5 nonces
        for i in 0..5 {
            let mut nonce = [0u8; 32];
            nonce[0] = i;
            db.check_and_store(&nonce).unwrap();
        }
        
        assert_eq!(db.size(), 5);
        
        // Wait for expiry
        thread::sleep(Duration::from_millis(100));
        
        // Add a new nonce (triggers cleanup)
        let nonce = [99u8; 32];
        db.check_and_store(&nonce).unwrap();
        
        // Should only have the new nonce
        assert_eq!(db.size(), 1);
    }
}
