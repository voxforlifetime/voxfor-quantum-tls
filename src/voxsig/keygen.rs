//! VOX-SIG Key Generation

use crate::voxsig::{params::*, lamport::*, merkle::*, Result, VoxSigError};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;

/// SigningKey with cached Merkle tree
///
/// # 🔴 CRITICAL SECURITY ISSUE: Stateful Signature Index Management
///
/// ## THE PROBLEM
///
/// VOX-SIG uses **stateful** Lamport signatures where each signature MUST use a unique index.
/// **Reusing an index even once allows an attacker to recover the private key!**
///
/// ## CURRENT IMPLEMENTATION (UNSAFE FOR PRODUCTION)
///
/// The `counter` field tracks the next signature index, but it's **NOT persisted atomically**.
/// This means:
/// - **Server crash**: Counter resets → index reuse → PRIVATE KEY LEAKED
/// - **Load balancer**: Multiple servers → same counter → PRIVATE KEY LEAKED
/// - **Backup/restore**: Old counter restored → index reuse → PRIVATE KEY LEAKED
///
/// ## WHAT YOU MUST DO FOR PRODUCTION
///
/// **Option 1: Implement Robust Atomic Persistence (RECOMMENDED)**
/// - Use `SafeSigner` or a similar pattern that guarantees the counter is never rolled back.
/// - Treat the signature state as critical security state (like an HSM monotonic counter).
///
/// **Option 2: Use Stateless Signatures (ALTERNATIVE DESIGN)**
/// - Stateless schemes such as **Dilithium** or **SPHINCS+** avoid index management entirely.
/// - These are different designs, not drop‑in replacements for VOX‑SIG.
///
/// **Option 3: Use Hardware Security Module (HSM)**
/// ```rust
/// // Pseudocode - requires careful implementation
/// impl SigningKey {
///     fn sign_with_persistence(&mut self, msg: &[u8], db: &mut StateDB) -> Result<Signature> {
///         // 1. Write-ahead log BEFORE signing
///         db.write_ahead_log(self.counter + 1)?;
///         db.fsync()?;  // Force to disk!
///         
///         // 2. Sign with current counter
///         let sig = self.sign_internal(msg)?;
///         
///         // 3. Commit counter increment
///         self.counter += 1;
///         db.commit_counter(self.counter)?;
///         db.fsync()?;
///         
///         Ok(sig)
///     }
/// }
/// ```
///
/// - Store counter in tamper-resistant hardware
/// - Guarantees atomicity and prevents rollback
///
/// ## WHY THIS IS CRITICAL
///
/// Lamport signatures reveal one of two secret keys per bit:
/// ```
/// Signature_1 at index 42: reveals keys for bits where message_1[i] = 1
/// Signature_2 at index 42: reveals keys for bits where message_2[i] = 1
/// ```
/// If `message_1` and `message_2` differ, attacker gets BOTH keys for some positions
/// → can forge signatures for ANY message!
///
/// ## CURRENT STATUS: ⚠️ NOT PRODUCTION READY
///
/// This implementation is acceptable for:
/// - Research/academic use
/// - Single-process applications with careful shutdown
/// - Testing and development
///
/// **DO NOT USE** for:
/// - Web servers (can crash)
/// - Load-balanced deployments
/// - Any production system
///
/// The Merkle tree is built once during key generation and cached.
/// This avoids O(2^HEIGHT) computation on every signature.
#[derive(Clone)]
pub struct SigningKey {
    pub seed: [u8; 32],
    pub pub_seed: [u8; 32],
    
    /// ⚠️ CRITICAL: This counter MUST NEVER repeat!
    /// See struct documentation for persistence requirements.
    pub counter: u32,
    
    /// Cached Merkle tree (not serialized, rebuilt on deserialization)
    pub(crate) merkle_tree: Option<MerkleTree>,
}

// Manual Zeroize implementation (skip merkle_tree)
impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.pub_seed.zeroize();
        self.counter.zeroize();
        // merkle_tree contains only public data (hashes), no need to zeroize
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SigningKey {
    /// ⚠️ DEPRECATED: Use SafeSigner instead!
    ///
    /// **Direct usage is DANGEROUS** - no atomic persistence of counter!
    ///
    /// This function is marked internal and should only be used by:
    /// - SafeSigner (which handles persistence)
    /// - CA modules (which have their own atomic persistence)
    /// - Tests
    ///
    /// **For production**: Use `SafeSigner` which guarantees atomic counter persistence!
    #[deprecated(note = "Use SafeSigner::open_or_create() instead - ensures atomic persistence")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed);
        bytes.extend_from_slice(&self.pub_seed);
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != SIGNING_KEY_BYTES {
            return Err(VoxSigError::InvalidKeyLength {
                expected: SIGNING_KEY_BYTES,
                actual: data.len(),
            });
        }
        
        let mut seed = [0u8; 32];
        let mut pub_seed = [0u8; 32];
        
        seed.copy_from_slice(&data[0..32]);
        pub_seed.copy_from_slice(&data[32..64]);
        let counter = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
        
        // Tree will be built lazily on first use
        Ok(Self { seed, pub_seed, counter, merkle_tree: None })
    }
    
    /// Ensure the Merkle tree is built (builds if not cached)
    pub(crate) fn ensure_tree_built(&mut self) -> Result<()> {
        if self.merkle_tree.is_none() {
            // Build the tree once
            let leaves = (0..(1 << MERKLE_HEIGHT))
                .map(|i| {
                    let (_sk, pk) = LamportPrivateKey::generate(&self.seed, i);
                    pk.bind_to_seed(&self.pub_seed, i)
                })
                .collect::<Vec<_>>();
            
            self.merkle_tree = Some(MerkleTree::build(&leaves));
        }
        Ok(())
    }
    
    /// Get the cached Merkle tree (builds if necessary)
    pub(crate) fn get_tree(&mut self) -> Result<&MerkleTree> {
        self.ensure_tree_built()?;
        // Safe: ensure_tree_built guarantees tree is Some
        self.merkle_tree.as_ref()
            .ok_or_else(|| VoxSigError::InvalidSigningKey)
    }
}

#[derive(Clone)]
pub struct VerifyingKey {
    pub root: [u8; HASH_SIZE],
    pub pub_seed: [u8; 32],
}

pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut seed = [0u8; 32];
        let mut pub_seed = [0u8; 32];
        
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut pub_seed);
        
        Self::from_seed(seed, pub_seed)
    }
    
    pub fn from_seed(seed: [u8; 32], pub_seed: [u8; 32]) -> Self {
        let leaves = Self::generate_leaves(&seed, &pub_seed);
        let tree = MerkleTree::build(&leaves);
        
        let signing_key = SigningKey {
            seed,
            pub_seed,
            counter: 0,
            merkle_tree: Some(tree.clone()),  // Cache the tree!
        };
        
        let verifying_key = VerifyingKey {
            root: tree.root,
            pub_seed,
        };
        
        Self { signing_key, verifying_key }
    }
    
    fn generate_leaves(seed: &[u8; 32], pub_seed: &[u8; 32]) -> Vec<[u8; HASH_SIZE]> {
        (0..(1 << MERKLE_HEIGHT))
            .map(|i| {
                let (_sk, pk) = LamportPrivateKey::generate(seed, i);
                pk.bind_to_seed(pub_seed, i)
            })
            .collect()
    }
}

impl VerifyingKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.pub_seed);
        bytes
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != VERIFYING_KEY_BYTES {
            return Err(VoxSigError::InvalidKeyLength {
                expected: VERIFYING_KEY_BYTES,
                actual: data.len(),
            });
        }
        
        let mut root = [0u8; HASH_SIZE];
        let mut pub_seed = [0u8; 32];
        
        root.copy_from_slice(&data[0..HASH_SIZE]);
        pub_seed.copy_from_slice(&data[HASH_SIZE..]);
        
        Ok(Self { root, pub_seed })
    }
}
