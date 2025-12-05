//! VOX-SIG Verification

use crate::voxsig::{*, keygen::*, sign::*, merkle::*};
use sha3::{Sha3_256, Digest};

pub fn verify(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    // 1. Hash the message
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    hasher.update(b"vox_sig_v1");
    let message_hash: [u8; 32] = hasher.finalize().into();
    
    // 2. Verify that poly_commit matches the message
    // The poly_commit should be derived from the message hash
    let mut expected_commit = Sha3_256::new();
    expected_commit.update(&message_hash);
    expected_commit.update(&signature.leaf_index.to_le_bytes());
    expected_commit.update(&verifying_key.pub_seed);
    let expected: [u8; 32] = expected_commit.finalize().into();
    
    #[cfg(test)]
    {
        eprintln!("[VERIFY] message_hash: {:?}", &message_hash[..8]);
        eprintln!("[VERIFY] leaf_index: {}", signature.leaf_index);
        eprintln!("[VERIFY] pub_seed: {:?}", &verifying_key.pub_seed[..8]);
        eprintln!("[VERIFY] expected: {:?}", &expected[..8]);
        eprintln!("[VERIFY] signature.poly_commit: {:?}", &signature.poly_commit[..8]);
    }
    
    // Check if poly_commit matches expected value
    // (This binds the signature to the specific message)
    let mut matches = true;
    for i in 0..32 {
        if signature.poly_commit[i] != expected[i] {
            matches = false;
            eprintln!("[VERIFY] poly_commit mismatch at [{}]: sig={} vs expected={}", 
                     i, signature.poly_commit[i], expected[i]);
            break;
        }
    }
    
    if !matches {
        eprintln!("[VERIFY] ❌ poly_commit MISMATCH!");
        eprintln!("[VERIFY] poly_commit: {:?}", &signature.poly_commit[..8]);
        eprintln!("[VERIFY] expected:    {:?}", &expected[..8]);
        return Err(VoxSigError::InvalidSignature);
    }
    
    // 3. ✅ SECURITY FIX: Full Lamport Signature Verification with Preimage Checks
    //
    // **Previous vulnerability**: Only checked revealed keys are non-zero.
    // **Attack**: Attacker could provide ANY non-zero keys without proving they hash correctly.
    //
    // **Fix**: Verify Hash(revealed_key) == expected_pk_hash[bit]
    //
    // Lamport OTS security requires:
    // 1. Public key = (H(key0_0), H(key1_0)), ..., (H(key0_255), H(key1_255))
    // 2. Signature reveals key[bit] for each message bit
    // 3. Verifier checks: Hash(revealed) == PK[i][message_bit]
    //
    // Without step 3, attacker can forge signatures!
    
    // Verify structure: correct number of revealed keys
    if signature.lamport_sig.revealed.len() != LAMPORT_N {
        #[cfg(test)]
        eprintln!("[VERIFY] Invalid Lamport signature: wrong number of revealed keys");
        return Err(VoxSigError::InvalidSignature);
    }
    
    // Verify structure: correct number of PK pairs
    if signature.lamport_pk_full.len() != LAMPORT_N {
        #[cfg(test)]
        eprintln!("[VERIFY] Invalid Lamport PK: wrong number of key pairs");
        return Err(VoxSigError::InvalidSignature);
    }
    
    // Convert message hash to bits (same as signing)
    let message_bits = lamport::LamportPrivateKey::hash_to_bits(&message_hash);
    
    #[cfg(test)]
    eprintln!("[VERIFY] Starting Lamport preimage verification for {} bits...", LAMPORT_N);
    
    // ✅ CRITICAL: Verify preimage for each revealed key
    for i in 0..LAMPORT_N {
        let revealed_key = &signature.lamport_sig.revealed[i];
        let message_bit = message_bits[i];
        let (hash0, hash1) = &signature.lamport_pk_full[i];
        
        // Hash the revealed key
        let mut h = Sha3_256::new();
        h.update(revealed_key);
        let revealed_hash: [u8; HASH_SIZE] = h.finalize().into();
        
        // Select expected hash based on message bit (0 or 1)
        let expected_hash = if message_bit == 1 { *hash1 } else { *hash0 };
        
        // ✅ SECURITY CHECK: Hash(revealed) must equal expected PK hash
        if revealed_hash != expected_hash {
            #[cfg(test)]
            {
                eprintln!("[VERIFY] ❌ Lamport preimage verification failed at bit {}: message_bit={}", i, message_bit);
                eprintln!("[VERIFY]    revealed_hash: {:?}", &revealed_hash[..4]);
                eprintln!("[VERIFY]    expected_hash: {:?}", &expected_hash[..4]);
            }
            return Err(VoxSigError::InvalidSignature);
        }
    }
    
    #[cfg(test)]
    eprintln!("[VERIFY] ✅ Lamport preimage verification passed for all {} bits", LAMPORT_N);
    
    // ========================================================================
    // 🔴 CRITICAL SECURITY FIX: Verify lamport_pk_compressed binding
    // ========================================================================
    // 
    // **VULNERABILITY DISCOVERED**: Without this check, an attacker can:
    // 1. Generate their own Lamport key pair (sk_attacker, pk_attacker)
    // 2. Sign message with sk_attacker → get valid Lamport signature
    // 3. Send: (lamport_sig_attacker, pk_attacker_full, pk_compressed_REAL, merkle_path_REAL)
    // 4. Verification would pass because:
    //    - Lamport preimage check passes (using pk_attacker_full) ✅
    //    - Merkle check passes (using pk_compressed_REAL from server) ✅
    //    - But attacker never had access to server's private key!
    // 
    // **FIX**: Verify that pk_compressed is the HASH of pk_full
    // This binds the two representations together and prevents forgery.
    //
    // Reference: This is the binding step that links Lamport OTS to Merkle tree.
    // ========================================================================
    
    // Compute the expected compressed PK from the full PK we just verified
    // Must match EXACTLY the algorithm in lamport::LamportPublicKey::compress()
    let calculated_pk_compressed: [u8; HASH_SIZE] = {
        let mut accumulated = [0u8; HASH_SIZE];
        
        // LamportPublicKey.hashes contains: [H(pk0_0||pk1_0), H(pk0_1||pk1_1), ..., H(pk0_255||pk1_255)]
        // We need to reconstruct these combined hashes from lamport_pk_full pairs
        
        let mut combined_hashes = Vec::with_capacity(LAMPORT_N);
        for (hash0, hash1) in &signature.lamport_pk_full {
            // Combine the pair (same as in Lamport key generation)
            let mut h = Sha3_256::new();
            h.update(hash0);
            h.update(hash1);
            let combined: [u8; HASH_SIZE] = h.finalize().into();
            combined_hashes.push(combined);
        }
        
        // Now process exactly like compress() does
        for (i, hash) in combined_hashes.iter().enumerate() {
            let mut h = Sha3_256::new();
            h.update(hash);
            h.update(&(i as u16).to_le_bytes());
            let mixed: [u8; HASH_SIZE] = h.finalize().into();
            
            // XOR into accumulated
            for j in 0..HASH_SIZE {
                accumulated[j] ^= mixed[j];
            }
        }
        
        // Final commitment (same as compress)
        let mut h = Sha3_256::new();
        h.update(&accumulated);
        h.update(b"lamport_commit");
        h.finalize().into()
    };
    
    // ✅ CRITICAL CHECK: Verify binding between full PK and compressed PK
    #[cfg(test)]
    {
        eprintln!("[VERIFY] Checking pk_compressed binding...");
        eprintln!("[VERIFY]   calculated: {:?}", &calculated_pk_compressed[..4]);
        eprintln!("[VERIFY]   signature:  {:?}", &signature.lamport_pk_compressed[..4]);
    }
    
    if calculated_pk_compressed != signature.lamport_pk_compressed {
        #[cfg(test)]
        eprintln!("[VERIFY] ❌ FORGERY DETECTED: lamport_pk_compressed doesn't match lamport_pk_full");
        return Err(VoxSigError::InvalidSignature);
    }
    
    #[cfg(test)]
    eprintln!("[VERIFY] ✅ Lamport PK compression verified (binds full PK to Merkle leaf)");
    
    // Now use the verified lamport_pk_compressed to verify Merkle
    // This binds the signature to a specific Lamport PK in the tree
    let bound_leaf = {
        let mut h = Sha3_256::new();
        h.update(&signature.lamport_pk_compressed);
        h.update(&verifying_key.pub_seed);
        h.update(&signature.leaf_index.to_le_bytes());
        h.finalize().into()
    };
    
    // 4. Verify Merkle path
    if !MerkleTree::verify_path(
        &bound_leaf,
        &signature.merkle_path,
        signature.leaf_index as usize,
        &verifying_key.root,
    ) {
        return Err(VoxSigError::MerkleVerificationFailed);
    }
    
    #[cfg(test)]
    eprintln!("[VERIFY] ✓ Merkle path verified successfully");
    
    Ok(())
}
