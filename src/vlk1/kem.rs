//! Key Encapsulation Mechanism (KEM) for VLK-1
//! 
//! Implements IND-CCA2 secure key encapsulation

use crate::vlk1::{params::*, poly::Polynomial, keygen::*, Result, Vlk1Error, ntt::barrett_reduce};
use sha3::{Sha3_256, Sha3_512, Digest};
use rand::{RngCore, CryptoRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Shared secret from KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    secret: [u8; SHARED_SECRET_BYTES],
}

impl SharedSecret {
    /// Get reference to secret bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_BYTES]) -> Self {
        Self { secret: bytes }
    }
}

/// Ciphertext from encapsulation
#[derive(Clone)]
pub struct Ciphertext {
    /// Ciphertext polynomials (u = A^T * r + e1)
    pub u: Vec<Polynomial>,
    /// Ciphertext value (v = pk^T * r + e2 + encode(m))
    pub v: Polynomial,
    /// Cached serialized bytes (to ensure consistency)
    cached_bytes: Option<Vec<u8>>,
}

impl Ciphertext {
    /// Serialize ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        // Use cached bytes if available (from from_bytes())
        if let Some(ref bytes) = self.cached_bytes {
            return bytes.clone();
        }
        
        // Otherwise, compress and serialize
        let mut bytes = Vec::new();
        
        // Compress and serialize u
        for poly in &self.u {
            bytes.extend_from_slice(&poly.compress(10)); // 10 bits compression
        }
        
        // Compress and serialize v
        bytes.extend_from_slice(&self.v.compress(4)); // 4 bits compression
        
        bytes
    }

    /// Deserialize ciphertext
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != CIPHERTEXT_BYTES {
            #[cfg(test)]
            eprintln!("[from_bytes] Expected {} bytes, got {}", CIPHERTEXT_BYTES, data.len());
            return Err(Vlk1Error::InvalidCiphertext);
        }
        
        let _u_bytes = K * N * 10 / 8; // Compressed size
        let _v_bytes = N * 4 / 8;
        
        let mut offset = 0;
        
        // Decompress u
        let mut u = Vec::new();
        for _ in 0..K {
            let poly_data = &data[offset..offset + N * 10 / 8];
            u.push(Polynomial::decompress(poly_data, 10));
            offset += N * 10 / 8;
        }
        
        // Decompress v
        let v = Polynomial::decompress(&data[offset..], 4);
        
        // Cache the original bytes to ensure to_bytes() returns identical data
        Ok(Self { 
            u, 
            v,
            cached_bytes: Some(data.to_vec()),
        })
    }
}

/// Encapsulate: Generate shared secret and ciphertext
/// 
/// Returns (ciphertext, shared_secret)
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    let mut rng = rand::rngs::OsRng;
    encapsulate_with_rng(public_key, &mut rng)
}

/// Encapsulate with specific RNG
pub fn encapsulate_with_rng<R: RngCore + CryptoRng>(
    public_key: &PublicKey,
    rng: &mut R,
) -> Result<(Ciphertext, SharedSecret)> {
    // Generate random message
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    
    #[cfg(test)]
    eprintln!("[ENCAP] m = {:?}", &m[..8]);
    
    // Hash message for coins
    let mut hasher = Sha3_256::new();
    hasher.update(&m);
    hasher.update(&public_key.as_bytes());
    let coins = hasher.finalize();
    
    // Derive randomness r
    let r = derive_randomness(&coins);
    
    // Regenerate public matrix A
    let a = generate_a_transpose(&public_key.matrix_seed);
    
    // Compute u = A^T * r + e1
    let e1 = generate_error_vector(&coins, b"e1");
    let mut u = compute_u(&a, &r, &e1);
    
    // Compute v = pk^T * r + e2 + encode(m)
    let e2 = generate_small_error(&coins, b"e2");
    let mut v = compute_v(&public_key.pk_enc, &r, &e2, &m);
    
    // Compress to bytes, then decompress back to get the "wire format" polynomials
    // This ensures the ciphertext matches what will be reconstructed from bytes
    let mut ct_bytes = Vec::new();
    for poly in &u {
        ct_bytes.extend_from_slice(&poly.compress(10));
    }
    ct_bytes.extend_from_slice(&v.compress(4));
    
    // Now decompress to get the actual polynomials that will be used
    let mut offset = 0;
    let mut u_wire = Vec::new();
    for _ in 0..K {
        let poly_data = &ct_bytes[offset..offset + N * 10 / 8];
        u_wire.push(Polynomial::decompress(poly_data, 10));
        offset += N * 10 / 8;
    }
    let v_wire = Polynomial::decompress(&ct_bytes[offset..], 4);
    
    let ciphertext = Ciphertext { 
        u: u_wire, 
        v: v_wire,
        cached_bytes: Some(ct_bytes), // Store the bytes we just created
    };
    
    // Derive shared secret
    let shared_secret = derive_shared_secret(&m, &ciphertext);
    
    Ok((ciphertext, shared_secret))
}

/// Decapsulate: Recover shared secret from ciphertext
pub fn decapsulate(ciphertext: &Ciphertext, secret_key: &SecretKey) -> Result<SharedSecret> {
    // Expand secret key
    let (s_enc, _s_auth) = secret_key.expand();
    
    // Compute m' = v - s^T * u
    let mut s_u = Polynomial::zero();
    for (si, ui) in s_enc.iter().zip(&ciphertext.u) {
        let prod = si.multiply(ui);
        s_u = s_u.add(&prod);
    }
    
    // Ensure s_u is in coefficient form before subtraction
    s_u.from_ntt();
    
    let mut m_poly = ciphertext.v.clone();
    m_poly = m_poly.sub(&s_u);
    
    // m_poly should already be in coefficient form, no need for from_ntt()
    
    // Decode message
    let m = decode_message(&m_poly);
    
    #[cfg(test)]
    eprintln!("[DECAP] m = {:?}", &m[..8]);
    
    // Re-encapsulate to check correctness (CCA2 security)
    // Use the cached public key bytes from secret key for exact match
    let mut hasher = Sha3_256::new();
    hasher.update(&m);
    hasher.update(&secret_key.cached_pk_bytes); // Use cached bytes directly!
    let coins = hasher.finalize();
    
    // Verify by re-encryption (Fujisaki-Okamoto transform for IND-CCA2)
    let r_check = derive_randomness(&coins);
    let a = generate_a_transpose(&secret_key.matrix_seed);
    let e1_check = generate_error_vector(&coins, b"e1");
    let u_check = compute_u(&a, &r_check, &e1_check);
    
    // Reconstruct public key from cached bytes for v computation
    let public_key = PublicKey::from_bytes(&secret_key.cached_pk_bytes)
        .map_err(|_| Vlk1Error::DecapsulationFailed)?;
    
    let e2_check = generate_small_error(&coins, b"e2");
    let v_check = compute_v(&public_key.pk_enc, &r_check, &e2_check, &m);
    
    // Build expected ciphertext with compress/decompress cycle to match encapsulation
    // This is CRITICAL: encapsulation compresses then decompresses to get "wire format"
    // So we must do the same here for byte-level comparison to work!
    let mut ct_bytes_temp = Vec::new();
    for poly in &u_check {
        ct_bytes_temp.extend_from_slice(&poly.compress(10));
    }
    ct_bytes_temp.extend_from_slice(&v_check.compress(4));
    
    // Now decompress to get the actual polynomials (matching encapsulation)
    let mut offset = 0;
    let mut u_check_wire = Vec::new();
    for _ in 0..K {
        let poly_data = &ct_bytes_temp[offset..offset + N * 10 / 8];
        u_check_wire.push(Polynomial::decompress(poly_data, 10));
        offset += N * 10 / 8;
    }
    let v_check_wire = Polynomial::decompress(&ct_bytes_temp[offset..], 4);
    
    let ciphertext_check = Ciphertext {
        u: u_check_wire,
        v: v_check_wire,
        cached_bytes: Some(ct_bytes_temp), // Cache the bytes we just created
    };
    
    // Compare ciphertext BYTES
    let ct_bytes_orig = ciphertext.to_bytes();
    let ct_bytes_check = ciphertext_check.to_bytes();
    
    // Constant-time byte comparison
    let mut diff = 0u32;
    for (&orig, &chk) in ct_bytes_orig.iter().zip(ct_bytes_check.iter()) {
        diff |= (orig ^ chk) as u32;
    }
    
    // Always log verification result for debugging
    if diff != 0 {
        eprintln!("[VERIFY] ⚠️  Ciphertext verification FAILED (diff={})", diff);
        eprintln!("[VERIFY] Original CT length: {}", ct_bytes_orig.len());
        eprintln!("[VERIFY] Check CT length: {}", ct_bytes_check.len());
    } else {
        eprintln!("[VERIFY] ✅ Ciphertext verification PASSED");
    }
    
    // Constant-time mask
    let is_valid = ((diff | diff.wrapping_neg()) >> 31).wrapping_sub(1);
    
    // FO Implicit Rejection with constant-time selection
    let real_secret = derive_shared_secret(&m, ciphertext);
    
    let mut hasher_fake = Sha3_256::new();
    hasher_fake.update(b"IMPLICIT_REJECTION");
    hasher_fake.update(&secret_key.seed);
    hasher_fake.update(&ciphertext.to_bytes());
    let fake_secret_bytes = hasher_fake.finalize();
    let fake_secret = SharedSecret::from_bytes(fake_secret_bytes.into());
    
    // Constant-time select
    let mut result_bytes = [0u8; SHARED_SECRET_BYTES];
    for i in 0..SHARED_SECRET_BYTES {
        let mask = is_valid as u8;
        result_bytes[i] = (real_secret.as_bytes()[i] & mask) | (fake_secret.as_bytes()[i] & !mask);
    }
    
    Ok(SharedSecret::from_bytes(result_bytes))
}

/// Derive randomness from coins
fn derive_randomness(coins: &[u8]) -> Vec<Polynomial> {
    let mut r = Vec::new();
    for i in 0..K {
        let mut seed = [0u8; 32];
        let mut hasher = Sha3_256::new();
        hasher.update(coins);
        hasher.update(b"r");
        hasher.update(&(i as u32).to_le_bytes());
        seed.copy_from_slice(&hasher.finalize());
        
        r.push(Polynomial::sample_cbd(ETA_LOW, &seed));
    }
    r
}

/// Generate A transpose
fn generate_a_transpose(matrix_seed: &[u8; 32]) -> Vec<Vec<Polynomial>> {
    let mut a_t = Vec::new();
    for j in 0..K {
        let mut col = Vec::new();
        for i in 0..K {
            let nonce = (i * K + j) as u16;
            col.push(Polynomial::sample_uniform(matrix_seed, nonce));
        }
        a_t.push(col);
    }
    a_t
}

/// Generate error vector
fn generate_error_vector(coins: &[u8], label: &[u8]) -> Vec<Polynomial> {
    let mut errors = Vec::new();
    for i in 0..K {
        let mut seed = [0u8; 32];
        let mut hasher = Sha3_256::new();
        hasher.update(coins);
        hasher.update(label);
        hasher.update(&(i as u32).to_le_bytes());
        seed.copy_from_slice(&hasher.finalize());
        
        errors.push(Polynomial::sample_cbd(ETA_LOW, &seed));
    }
    errors
}

/// Generate small error
fn generate_small_error(coins: &[u8], label: &[u8]) -> Polynomial {
    let mut seed = [0u8; 32];
    let mut hasher = Sha3_256::new();
    hasher.update(coins);
    hasher.update(label);
    seed.copy_from_slice(&hasher.finalize());
    
    Polynomial::sample_cbd(ETA_LOW, &seed)
}

/// Compute u = A^T * r + e1
fn compute_u(
    a_t: &[Vec<Polynomial>],
    r: &[Polynomial],
    e1: &[Polynomial],
) -> Vec<Polynomial> {
    let mut u = Vec::new();
    
    for (col, e) in a_t.iter().zip(e1) {
        let mut sum = Polynomial::zero();
        for (a_ij, r_j) in col.iter().zip(r) {
            let prod = a_ij.multiply(r_j);
            sum = sum.add(&prod);
        }
        sum = sum.add(e);
        
        // Ensure in coefficient form for consistency
        sum.from_ntt();
        
        u.push(sum);
    }
    
    u
}

/// Compute v = pk^T * r + e2 + encode(m)
fn compute_v(
    pk: &[Polynomial],
    r: &[Polynomial],
    e2: &Polynomial,
    m: &[u8; 32],
) -> Polynomial {
    let mut v = Polynomial::zero();
    
    for (pk_i, r_i) in pk.iter().zip(r) {
        let prod = pk_i.multiply(r_i);
        v = v.add(&prod);
    }
    
    v = v.add(e2);
    
    // Encode message
    let m_poly = encode_message(m);
    v = v.add(&m_poly);
    
    // Ensure in coefficient form
    v.from_ntt();
    
    v
}

/// Encode message as polynomial
fn encode_message(m: &[u8; 32]) -> Polynomial {
    let mut coeffs = [0i32; N];
    
    for (i, &byte) in m.iter().enumerate() {
        for j in 0..8 {
            let bit = (byte >> j) & 1;
            if i * 8 + j < N {
                // Scale to ±Q/4
                coeffs[i * 8 + j] = if bit == 1 { Q / 4 } else { -Q / 4 };
            }
        }
    }
    
    Polynomial::from_coeffs(coeffs)
}

/// Decode message from polynomial
fn decode_message(poly: &Polynomial) -> [u8; 32] {
    let mut m = [0u8; 32];
    
    for i in 0..32 {
        let mut byte = 0u8;
        for j in 0..8 {
            let idx = i * 8 + j;
            if idx < N {
                let coeff = poly.coeffs[idx];
                // Reduce to [-Q/2, Q/2] range first
                let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                // Threshold decoding: positive = 1, negative = 0
                let bit = if centered > 0 { 1 } else { 0 };
                byte |= bit << j;
            }
        }
        m[i] = byte;
    }
    
    m
}

/// Derive final shared secret
fn derive_shared_secret(m: &[u8; 32], ciphertext: &Ciphertext) -> SharedSecret {
    let mut hasher = Sha3_512::new();
    hasher.update(m);
    hasher.update(&ciphertext.to_bytes());
    let hash = hasher.finalize();
    
    let mut secret = [0u8; SHARED_SECRET_BYTES];
    secret.copy_from_slice(&hash[..SHARED_SECRET_BYTES]);
    
    SharedSecret::from_bytes(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_correctness() {
        let keypair = KeyPair::generate();
        
        let (ciphertext, ss1) = encapsulate(&keypair.public_key).unwrap();
        println!("Alice SS1: {:?}", &ss1.as_bytes()[..8]);
        
        let ss2 = decapsulate(&ciphertext, &keypair.secret_key).unwrap();
        println!("Bob   SS2: {:?}", &ss2.as_bytes()[..8]);
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let keypair = KeyPair::generate();
        let (ct, ss1) = encapsulate(&keypair.public_key).unwrap();
        
        // Serialize and deserialize
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), CIPHERTEXT_BYTES);
        
        let ct_recovered = Ciphertext::from_bytes(&bytes).unwrap();
        
        // Verify that decapsulation still works after ser/deser
        let ss2 = decapsulate(&ct_recovered, &keypair.secret_key).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets must match after serialization");
    }

    #[test]
    fn test_invalid_ciphertext() {
        let keypair = KeyPair::generate();
        let (ct, ss_original) = encapsulate(&keypair.public_key).unwrap();
        
        // Tamper with ciphertext BYTES (not polynomials!)
        // This simulates network corruption or active attack
        let mut ct_bytes = ct.to_bytes();
        ct_bytes[0] ^= 1; // Flip one bit in the serialized ciphertext
        
        // Reconstruct from tampered bytes
        let ct_tampered = Ciphertext::from_bytes(&ct_bytes).unwrap();
        
        // Decapsulate should SUCCEED (return Ok) due to Implicit Rejection
        let result = decapsulate(&ct_tampered, &keypair.secret_key);
        assert!(result.is_ok(), "Decapsulation should not return error on bad ciphertext due to Implicit Rejection");
        
        // But the secret must be GARBAGE (different from original)
        let ss_fake = result.unwrap();
        assert_ne!(ss_original.as_bytes(), ss_fake.as_bytes(), "Shared secret must be different (garbage) for invalid ciphertext");
    }
}
