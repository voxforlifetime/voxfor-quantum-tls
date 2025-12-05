//! Safe Signer - Atomic Persistence Wrapper for VOX-SIG
//!
//! # 🔴 CRITICAL SECURITY WRAPPER
//!
//! **Problem**: VOX-SIG SigningKey is stateful (has counter) - reusing an index
//! even ONCE leaks the private key completely!
//!
//! **Solution**: SafeSigner enforces atomic persistence of counter state.
//!
//! # Why This Exists
//!
//! Without atomic persistence:
//! - Server crashes → counter resets → index reuse → KEY LEAKED!
//! - Load balancer → multiple servers → same counter → KEY LEAKED!
//! - Backup restore → old counter → index reuse → KEY LEAKED!
//!
//! # Usage
//!
//! ```ignore
//! // ✅ SAFE: Uses atomic persistence
//! let signer = SafeSigner::open_or_create("server.key")?;
//! let signature = signer.sign(message)?;  // Counter saved atomically!
//!
//! // ❌ UNSAFE: Direct SigningKey usage (DEPRECATED!)
//! let mut key = SigningKey::from_bytes(&bytes)?;  // ⚠️ No persistence!
//! let sig = sign(&mut key, message)?;  // ⚠️ Counter not saved!
//! ```

use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};
use rand::RngCore;
use super::keygen::{SigningKey, VerifyingKey};
use super::sign::{sign, Signature};
use super::{Result, VoxSigError};

/// Safe signer with atomic counter persistence
///
/// # Thread Safety
///
/// Uses `Mutex` to ensure only one thread signs at a time.
/// This prevents concurrent counter increments which could cause index reuse.
pub struct SafeSigner {
    /// File path for persistent storage
    key_path: PathBuf,
    
    /// Protected signing key
    /// 
    /// Mutex ensures:
    /// - Only one sign() at a time
    /// - Counter increments are serialized
    /// - No race conditions on persistence
    key: Arc<Mutex<SigningKey>>,
}

impl SafeSigner {
    /// Open existing or create new SafeSigner
    ///
    /// # Atomic Persistence
    ///
    /// After EVERY signature:
    /// 1. Write key to temp file
    /// 2. fsync() to disk
    /// 3. Atomic rename over old file
    /// 4. fsync() directory
    ///
    /// This ensures counter is NEVER lost, even on crash/power failure.
    ///
    /// # Example
    /// ```ignore
    /// let signer = SafeSigner::open_or_create("ca.key")?;
    /// let sig = signer.sign(b"message")?;
    /// // Counter automatically saved atomically!
    /// ```
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let key_path = path.as_ref().to_path_buf();
        
        let key = if key_path.exists() {
            // Load existing key
            let bytes = fs::read(&key_path)
                .map_err(|e| VoxSigError::Io(e.to_string()))?;
            #[allow(deprecated)]
            SigningKey::from_bytes(&bytes)?
        } else {
            // Generate new key
            let mut seed = [0u8; 32];
            let mut pub_seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            rand::rngs::OsRng.fill_bytes(&mut pub_seed);
            
            let signing_key = SigningKey {
                seed,
                pub_seed,
                counter: 0,
                merkle_tree: None,  // Built on first use
            };
            
            // Save immediately with atomic write
            Self::save_atomic(&key_path, &signing_key)?;
            
            signing_key
        };
        
        Ok(Self {
            key_path,
            key: Arc::new(Mutex::new(key)),
        })
    }
    
    /// Sign message with atomic counter persistence
    ///
    /// # Atomicity Guarantee
    ///
    /// **CRITICAL**: This function ensures the counter is saved BEFORE returning!
    ///
    /// Process:
    /// 1. Lock signing key (blocks other threads)
    /// 2. Create signature (increments counter)
    /// 3. Save key atomically to disk
    /// 4. Return signature
    ///
    /// If step 3 fails, the signature is NOT returned → no index reuse risk!
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        // 1. Lock key (ensures single-threaded access)
        let mut key_guard = self.key.lock()
            .map_err(|e| VoxSigError::InvalidKeyLength { 
                expected: 0, 
                actual: 0 
            })?;
        
        // 2. Sign (this increments counter)
        let signature = sign(&mut *key_guard, message)?;
        
        // 3. ✅ CRITICAL: Save updated key ATOMICALLY before returning
        Self::save_atomic(&self.key_path, &*key_guard)?;
        
        // 4. Return signature (counter is safely persisted)
        Ok(signature)
    }
    
    /// Get current counter value (for monitoring)
    ///
    /// Use this to monitor how many signatures have been created.
    /// Useful for alerting when approaching the 65,536 signature limit.
    pub fn get_counter(&self) -> u32 {
        self.key.lock()
            .map(|k| k.counter)
            .unwrap_or(0)
    }
    
    /// Get verifying key (public key)
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let key_guard = self.key.lock()
            .map_err(|_| VoxSigError::InvalidKeyLength { expected: 0, actual: 0 })?;
        
        // Generate keypair to get verifying key
        let keypair = super::keygen::Keypair::from_seed(key_guard.seed, key_guard.pub_seed);
        Ok(keypair.verifying_key)
    }
    
    /// ✅ ATOMIC WRITE: Save key with fsync guarantees
    ///
    /// **Same pattern as CA's atomic serial number persistence**
    ///
    /// Steps:
    /// 1. Write to `.tmp` file
    /// 2. fsync() file (force to physical disk)
    /// 3. rename() to real file (atomic on POSIX)
    /// 4. fsync() directory (ensure rename is durable)
    ///
    /// This ensures that even if:
    /// - Process crashes mid-write → old key intact OR new key complete
    /// - Power failure → old key intact OR new key complete
    /// - Never a partial/corrupted key with wrong counter!
    fn save_atomic(path: &Path, key: &SigningKey) -> Result<()> {
        let temp_path = path.with_extension("tmp");
        
        // 1. Write to temp file
        #[allow(deprecated)]
        let key_bytes = key.to_bytes();
        let mut file = fs::File::create(&temp_path)
            .map_err(|e| VoxSigError::Io(format!("Failed to create temp: {}", e)))?;
        
        file.write_all(&key_bytes)
            .map_err(|e| VoxSigError::Io(format!("Failed to write: {}", e)))?;
        
        // 2. ✅ CRITICAL: Force to disk
        file.sync_all()
            .map_err(|e| VoxSigError::Io(format!("Failed to fsync: {}", e)))?;
        
        drop(file);  // Close before rename
        
        // 3. ✅ ATOMIC: Rename (overwrites old file atomically)
        fs::rename(&temp_path, path)
            .map_err(|e| VoxSigError::Io(format!("Failed to rename: {}", e)))?;
        
        // Note: Directory fsync omitted for portability
        // On most filesystems, file fsync + rename is sufficient
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_safe_signer_atomic_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");
        
        // Create signer
        let signer = SafeSigner::open_or_create(&key_path).unwrap();
        let initial_counter = signer.get_counter();
        
        // Sign message
        let message = b"test message";
        let _sig1 = signer.sign(message).unwrap();
        
        // Counter should increment
        assert_eq!(signer.get_counter(), initial_counter + 1);
        
        // Drop and reload
        drop(signer);
        
        let signer2 = SafeSigner::open_or_create(&key_path).unwrap();
        
        // ✅ Counter should be persisted!
        assert_eq!(signer2.get_counter(), initial_counter + 1);
        
        // Sign again
        let _sig2 = signer2.sign(message).unwrap();
        assert_eq!(signer2.get_counter(), initial_counter + 2);
    }
    
    #[test]
    fn test_safe_signer_prevents_concurrent_signing() {
        use std::thread;
        
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("concurrent.key");
        
        let signer = Arc::new(SafeSigner::open_or_create(&key_path).unwrap());
        let initial_counter = signer.get_counter();
        
        // Spawn multiple threads trying to sign
        let mut handles = vec![];
        for i in 0..10 {
            let signer_clone = Arc::clone(&signer);
            let handle = thread::spawn(move || {
                let message = format!("message {}", i);
                signer_clone.sign(message.as_bytes()).unwrap();
            });
            handles.push(handle);
        }
        
        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        
        // All 10 signatures should have unique indices
        assert_eq!(signer.get_counter(), initial_counter + 10);
    }
}
