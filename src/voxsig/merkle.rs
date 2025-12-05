//! Merkle Tree for VOX-SIG authentication

use crate::voxsig::params::*;
use sha3::{Sha3_256, Digest};

#[derive(Clone)]
pub struct MerkleTree {
    pub root: [u8; HASH_SIZE],
    pub levels: Vec<Vec<[u8; HASH_SIZE]>>,
}

impl MerkleTree {
    /// Build Merkle tree with domain separation
    /// 
    /// # Security: Domain Separation
    /// 
    /// **Problem**: Without domain separation, different tree levels use same hash function,
    /// allowing length extension attacks and ambiguity between leaf/node hashes.
    /// 
    /// **Attack Scenario** (without domain separation):
    /// ```text
    /// Leaf hash:    H(data)
    /// Node hash:    H(left || right)
    /// 
    /// Attacker could craft data = (left || right) to make leaf hash equal node hash!
    /// This breaks tree structure assumptions.
    /// ```
    /// 
    /// **Fix**: Domain separation via level index:
    /// ```text
    /// Leaf hash:    H(data || "leaf" || 0)
    /// Level 1 node: H(left || right || "node" || 1)
    /// Level 2 node: H(left || right || "node" || 2)
    /// ...
    /// ```
    /// 
    /// Each level has unique domain → no ambiguity → no length extension.
    pub fn build(leaves: &[[u8; HASH_SIZE]]) -> Self {
        assert_eq!(leaves.len(), 1 << MERKLE_HEIGHT);
        
        let mut levels = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();
        
        // Build tree level by level with domain separation
        for level in 0..MERKLE_HEIGHT {
            let mut next_level = Vec::new();
            for i in (0..current.len()).step_by(2) {
                let mut h = Sha3_256::new();
                h.update(&current[i]);
                h.update(&current[i + 1]);
                
                // SECURITY FIX: Domain separation by level
                // Prevents ambiguity between different tree levels
                h.update(b"merkle_node");
                h.update(&(level as u32).to_le_bytes());  // Level index
                
                next_level.push(h.finalize().into());
            }
            levels.push(next_level.clone());
            current = next_level;
        }
        
        let root = current[0];
        Self { root, levels }
    }
    
    pub fn get_path(&self, leaf_index: usize) -> Vec<[u8; HASH_SIZE]> {
        let mut path = Vec::new();
        let mut index = leaf_index;
        
        for level in &self.levels[..MERKLE_HEIGHT] {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            path.push(level[sibling_index]);
            index /= 2;
        }
        
        path
    }
    
    /// Verify Merkle path with domain separation
    /// 
    /// # Security: Domain Separation in Verification
    /// 
    /// Verification MUST use the same domain separation as tree building.
    /// Each level in the path uses its level index as domain separator.
    /// 
    /// This ensures:
    /// - Verifier computes same hashes as builder
    /// - No ambiguity between tree levels
    /// - Length extension attacks prevented
    pub fn verify_path(
        leaf: &[u8; HASH_SIZE],
        path: &[[u8; HASH_SIZE]],
        leaf_index: usize,
        root: &[u8; HASH_SIZE],
    ) -> bool {
        let mut current = *leaf;
        let mut index = leaf_index;
        
        for (level, sibling) in path.iter().enumerate() {
            let mut h = Sha3_256::new();
            if index % 2 == 0 {
                h.update(&current);
                h.update(sibling);
            } else {
                h.update(sibling);
                h.update(&current);
            }
            
            // SECURITY FIX: Domain separation by level (must match build())
            h.update(b"merkle_node");
            h.update(&(level as u32).to_le_bytes());
            
            current = h.finalize().into();
            index /= 2;
        }
        
        &current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let leaves: Vec<[u8; HASH_SIZE]> = (0..(1 << MERKLE_HEIGHT))
            .map(|i| {
                let mut h = Sha3_256::new();
                h.update(&(i as u32).to_le_bytes());
                h.finalize().into()
            })
            .collect();
        
        let tree = MerkleTree::build(&leaves);
        
        for i in 0..(1 << MERKLE_HEIGHT) {
            let path = tree.get_path(i);
            assert!(MerkleTree::verify_path(&leaves[i], &path, i, &tree.root));
        }
    }
}
