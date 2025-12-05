use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl Validity {
    /// Grace period for clock skew tolerance (5 minutes)
    /// Accounts for minor time differences between client/server
    const GRACE_PERIOD_SECONDS: i64 = 300;
    
    pub fn new(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        Self { not_before, not_after }
    }
    
    /// Check if certificate is currently valid
    /// 
    /// Includes grace period for clock skew:
    /// - Accepts certificates up to 5 minutes before not_before
    /// - Accepts certificates up to 5 minutes after not_after
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        let grace = chrono::Duration::seconds(Self::GRACE_PERIOD_SECONDS);
        
        // Apply grace period on both boundaries
        let effective_not_before = self.not_before - grace;
        let effective_not_after = self.not_after + grace;
        
        now >= effective_not_before && now <= effective_not_after
    }
    
    /// Strict validation without grace period
    /// Use for testing or when exact timing is required
    pub fn is_valid_strict(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }
}
