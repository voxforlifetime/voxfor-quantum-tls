//! VOX-SIG Signing

use crate::voxsig::{*, lamport::*, merkle::*, keygen::*};
use sha3::{Sha3_256, Digest};

/// VOX-SIG Signature
/// 
/// # Security Fix: Full Lamport Public Key Inclusion
/// 
/// **Previous vulnerability**: Only stored `lamport_pk_compressed` (single hash),
/// which prevented verifying preimages of revealed keys.
/// 
/// **Fix**: Now stores full Lamport public key (256 pairs of hashes).
/// Each pair contains:
/// - H(key0): Hash of the "0" key for this bit
/// - H(key1): Hash of the "1" key for this bit
/// 
/// During verification, we check: `Hash(revealed_key) == expected_hash[bit]`
/// 
/// **Size Impact**: +16KB per signature (256 pairs * 2 * 32 bytes)
/// But necessary for security - cannot verify Lamport signatures without full PK!
pub struct Signature {
    pub lamport_sig: LamportSignature,
    pub merkle_path: Vec<[u8; HASH_SIZE]>,
    pub leaf_index: u32,
    pub poly_commit: [u8; HASH_SIZE],
    
    // ✅ SECURITY FIX: Store full Lamport public key for verification
    // This allows checking: Hash(revealed_key) == lamport_pk_full[bit][message_bit]
    pub lamport_pk_full: Vec<([u8; HASH_SIZE], [u8; HASH_SIZE])>,  // 256 pairs
    
    // Keep compressed for Merkle tree (backward compat with tree structure)
    pub lamport_pk_compressed: [u8; HASH_SIZE],
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        // Size: 4 (index) + 32 (poly) + 32 (compressed) + 16KB (full PK) + lamport + merkle
        let mut bytes = Vec::with_capacity(100_000);  // ~100KB estimate
        
        bytes.extend_from_slice(&self.leaf_index.to_le_bytes());
        bytes.extend_from_slice(&self.poly_commit);
        bytes.extend_from_slice(&self.lamport_pk_compressed);
        
        // ✅ NEW: Serialize full Lamport PK
        for (hash0, hash1) in &self.lamport_pk_full {
            bytes.extend_from_slice(hash0);
            bytes.extend_from_slice(hash1);
        }
        
        bytes.extend_from_slice(&self.lamport_sig.to_bytes());
        
        for node in &self.merkle_path {
            bytes.extend_from_slice(node);
        }
        
        bytes
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        #[cfg(test)]
        eprintln!("[SIGN::from_bytes] data.len() = {}", data.len());
        
        let mut offset = 0;
        
        if data.len() < 4 {
            return Err(VoxSigError::SerializationError("Data too short".into()));
        }
        
        let leaf_index = u32::from_le_bytes([
            data[0], data[1], data[2], data[3]
        ]);
        offset += 4;
        
        if data.len() < offset + HASH_SIZE * 2 {
            return Err(VoxSigError::SerializationError("Data too short for commits".into()));
        }
        
        let mut poly_commit = [0u8; HASH_SIZE];
        poly_commit.copy_from_slice(&data[offset..offset + HASH_SIZE]);
        offset += HASH_SIZE;
        
        let mut lamport_pk_compressed = [0u8; HASH_SIZE];
        lamport_pk_compressed.copy_from_slice(&data[offset..offset + HASH_SIZE]);
        offset += HASH_SIZE;
        
        // ✅ NEW: Deserialize full Lamport PK (256 pairs)
        let mut lamport_pk_full = Vec::with_capacity(LAMPORT_N);
        for _ in 0..LAMPORT_N {
            if data.len() < offset + HASH_SIZE * 2 {
                return Err(VoxSigError::SerializationError("Data too short for PK pairs".into()));
            }
            
            let mut hash0 = [0u8; HASH_SIZE];
            hash0.copy_from_slice(&data[offset..offset + HASH_SIZE]);
            offset += HASH_SIZE;
            
            let mut hash1 = [0u8; HASH_SIZE];
            hash1.copy_from_slice(&data[offset..offset + HASH_SIZE]);
            offset += HASH_SIZE;
            
            lamport_pk_full.push((hash0, hash1));
        }
        
        if data.len() < offset + LAMPORT_N * HASH_SIZE {
            return Err(VoxSigError::SerializationError("Data too short for Lamport sig".into()));
        }
        
        let lamport_data = &data[offset..offset + LAMPORT_N * HASH_SIZE];
        let lamport_sig = LamportSignature::from_bytes(lamport_data)
            .ok_or(VoxSigError::SerializationError("Invalid Lamport signature".into()))?;
        offset += LAMPORT_N * HASH_SIZE;
        
        if data.len() < offset + MERKLE_HEIGHT * HASH_SIZE {
            return Err(VoxSigError::SerializationError("Data too short for Merkle path".into()));
        }
        
        let mut merkle_path = Vec::new();
        for _ in 0..MERKLE_HEIGHT {
            let mut node = [0u8; HASH_SIZE];
            node.copy_from_slice(&data[offset..offset + HASH_SIZE]);
            merkle_path.push(node);
            offset += HASH_SIZE;
        }
        
        Ok(Self {
            lamport_sig,
            merkle_path,
            leaf_index,
            poly_commit,
            lamport_pk_full,
            lamport_pk_compressed,
        })
    }
}

pub fn sign(signing_key: &mut SigningKey, message: &[u8]) -> Result<Signature> {
    if signing_key.counter >= MAX_SIGNATURES as u32 {
        return Err(VoxSigError::KeyExhausted);
    }
    
    let leaf_index = signing_key.counter;
    signing_key.counter += 1;
    
    // Hash the message
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    hasher.update(b"vox_sig_v1");
    let message_hash: [u8; 32] = hasher.finalize().into();
    
    // Generate Lamport key pair for this signature
    let (lamport_sk, lamport_pk) = LamportPrivateKey::generate(
        &signing_key.seed,
        leaf_index,
    );
    
    // Sign the message
    let lamport_sig = lamport_sk.sign(&message_hash);
    
    // Compress PK for Merkle tree (backward compat)
    let lamport_pk_compressed = lamport_pk.compress();
    
    // ✅ SECURITY FIX COMPLETE: Extract full Lamport PK pairs
    // lamport_pk.pairs now contains the REAL (H(key0), H(key1)) values!
    let lamport_pk_full = lamport_pk.pairs.clone();
    
    // Create poly_commit that binds signature to message
    let mut commit_hasher = Sha3_256::new();
    commit_hasher.update(&message_hash);
    commit_hasher.update(&leaf_index.to_le_bytes());
    commit_hasher.update(&signing_key.pub_seed);
    let poly_commit: [u8; 32] = commit_hasher.finalize().into();
    
    #[cfg(test)]
    {
        eprintln!("[SIGN] message_hash: {:?}", &message_hash[..8]);
        eprintln!("[SIGN] leaf_index: {}", leaf_index);
        eprintln!("[SIGN] pub_seed: {:?}", &signing_key.pub_seed[..8]);
        eprintln!("[SIGN] poly_commit: {:?}", &poly_commit[..8]);
    }
    
    // Use cached Merkle tree
    let tree = signing_key.get_tree()?;
    let merkle_path = tree.get_path(leaf_index as usize);
    
    Ok(Signature {
        lamport_sig,
        merkle_path,
        leaf_index,
        poly_commit,
        lamport_pk_full,  // ✅ NEW field
        lamport_pk_compressed,
    })
}

// Removed: generate_all_leaves - tree is now cached in SigningKey

fn generate_poly_commit_leaves(pub_seed: &[u8; 32]) -> Vec<[u8; HASH_SIZE]> {
    (0..(1 << MERKLE_HEIGHT))
        .map(|i| {
            // Generate deterministic poly_commit for each leaf
            // This must match what's done in signing
            let mut h = Sha3_256::new();
            h.update(b"leaf_placeholder");  // Placeholder - will be replaced by actual message hash
            h.update(&(i as u32).to_le_bytes());
            h.update(pub_seed);
            let poly_commit: [u8; 32] = h.finalize().into();
            
            // Bind to seed (same as verify)
            let mut h2 = Sha3_256::new();
            h2.update(&poly_commit);
            h2.update(pub_seed);
            h2.update(&(i as u32).to_le_bytes());
            h2.finalize().into()
        })
        .collect()
}
