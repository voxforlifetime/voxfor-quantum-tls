//! DoS Protection for VLK-1 Key Generation
//! 
//! Key generation is computationally expensive (~10-30ms per keypair).
//! Without rate limiting, attackers can cause resource exhaustion by
//! requesting many key generations in parallel.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Rate limiter for key generation operations
/// 
/// # Security Model
/// 
/// **DoS Protection**: Limits the rate of key generation requests to prevent
/// resource exhaustion attacks.
/// 
/// **Token Bucket Algorithm**:
/// - Bucket capacity: MAX_BURST (simultaneous requests allowed)
/// - Refill rate: REFILL_RATE per second
/// - Each key generation consumes 1 token
/// 
/// **Example**: With MAX_BURST=10, REFILL_RATE=5:
/// - Up to 10 immediate requests allowed
/// - After burst, limited to 5 requests/second
/// - Prevents attacker from consuming unlimited CPU
#[derive(Clone)]
pub struct KeyGenRateLimiter {
    state: Arc<Mutex<RateLimitState>>,
}

struct RateLimitState {
    /// Token bucket (available capacity)
    tokens: f64,
    /// Last refill time
    last_refill: Instant,
    /// Request timestamps (for statistics)
    recent_requests: VecDeque<Instant>,
}

impl KeyGenRateLimiter {
    /// Maximum burst capacity (tokens)
    const MAX_BURST: f64 = 10.0;
    
    /// Refill rate (tokens per second)
    const REFILL_RATE: f64 = 5.0;
    
    /// Window for tracking recent requests
    const STATS_WINDOW: Duration = Duration::from_secs(60);
    
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimitState {
                tokens: Self::MAX_BURST,
                last_refill: Instant::now(),
                recent_requests: VecDeque::new(),
            })),
        }
    }
    
    /// Check if key generation is allowed (returns immediately)
    /// 
    /// # Returns
    /// - `Ok(())` if request is allowed
    /// - `Err(KeyGenDenied)` if rate limit exceeded
    pub fn check_rate_limit(&self) -> Result<(), KeyGenDenied> {
        let mut state = self.state.lock().unwrap();
        
        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill);
        let refill_amount = elapsed.as_secs_f64() * Self::REFILL_RATE;
        state.tokens = (state.tokens + refill_amount).min(Self::MAX_BURST);
        state.last_refill = now;
        
        // Check if we have tokens available
        if state.tokens < 1.0 {
            let requests_in_window = state.recent_requests.len();
            return Err(KeyGenDenied {
                retry_after: Duration::from_secs_f64(1.0 / Self::REFILL_RATE),
                requests_in_last_minute: requests_in_window,
            });
        }
        
        // Consume token
        state.tokens -= 1.0;
        
        // Track request for statistics
        state.recent_requests.push_back(now);
        
        // Clean old requests from tracking window
        while let Some(&oldest) = state.recent_requests.front() {
            if now.duration_since(oldest) > Self::STATS_WINDOW {
                state.recent_requests.pop_front();
            } else {
                break;
            }
        }
        
        Ok(())
    }
    
    /// Get current rate limit statistics
    pub fn stats(&self) -> RateLimitStats {
        let state = self.state.lock().unwrap();
        
        RateLimitStats {
            available_tokens: state.tokens,
            requests_in_last_minute: state.recent_requests.len(),
        }
    }
}

impl Default for KeyGenRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when rate limit is exceeded
#[derive(Debug, Clone)]
pub struct KeyGenDenied {
    /// Suggested retry delay
    pub retry_after: Duration,
    /// Number of requests in last minute
    pub requests_in_last_minute: usize,
}

impl std::fmt::Display for KeyGenDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Key generation rate limit exceeded ({} requests in last minute). Retry after {:?}",
            self.requests_in_last_minute,
            self.retry_after
        )
    }
}

impl std::error::Error for KeyGenDenied {}

/// Rate limit statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    /// Current available tokens
    pub available_tokens: f64,
    /// Requests in last 60 seconds
    pub requests_in_last_minute: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_burst_allowed() {
        let limiter = KeyGenRateLimiter::new();
        
        // First 10 requests should succeed (burst capacity)
        for i in 0..10 {
            assert!(limiter.check_rate_limit().is_ok(), "Request {} should succeed", i);
        }
        
        // 11th request should fail (bucket exhausted)
        assert!(limiter.check_rate_limit().is_err(), "Request 11 should fail");
    }
    
    #[test]
    fn test_refill() {
        let limiter = KeyGenRateLimiter::new();
        
        // Exhaust bucket
        for _ in 0..10 {
            let _ = limiter.check_rate_limit();
        }
        
        // Should fail immediately
        assert!(limiter.check_rate_limit().is_err());
        
        // Wait for refill (1 token = 0.2 seconds at 5/sec rate)
        thread::sleep(Duration::from_millis(250));
        
        // Should succeed now (1 token refilled)
        assert!(limiter.check_rate_limit().is_ok());
    }
    
    #[test]
    fn test_stats() {
        let limiter = KeyGenRateLimiter::new();
        
        for _ in 0..5 {
            let _ = limiter.check_rate_limit();
        }
        
        let stats = limiter.stats();
        assert_eq!(stats.requests_in_last_minute, 5);
        assert!(stats.available_tokens < 10.0);
        assert!(stats.available_tokens >= 4.0);
    }
}
