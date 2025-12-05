//! Key generation for VLK-1
//! 
//! Production-grade key generation with:
//! - Dual-state keys (encryption + authentication)
//! - Seed-based private keys for compact storage
//! - Constant-time operations

use crate::vlk1::{params::*, poly::Polynomial, Result, Vlk1Error};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use rand::{RngCore, CryptoRng};
use sha3::{Sha3_256, Digest};

/// Public key for VLK-1
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Public key polynomials (encryption state)
    pub pk_enc: Vec<Polynomial>,
    /// Public key polynomials (authentication state)  
    pub pk_auth: Vec<Polynomial>,
    /// Matrix seed (for deterministic matrix generation)
    pub matrix_seed: [u8; 32],
    /// Cached serialized bytes (for consistent hashing in KEM)
    pub cached_bytes: Option<Vec<u8>>,
}

/// Secret key for VLK-1
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Master seed (compact representation)
    pub seed: [u8; 32],
    /// Matrix seed (needed for reconstruction)
    pub matrix_seed: [u8; 32],
    /// Cached public key bytes (needed for CCA2 verification)
    /// This is NOT zeroized (it's public anyway)
    #[zeroize(skip)]
    pub cached_pk_bytes: Vec<u8>,
}

/// Key pair for VLK-1
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl PublicKey {
    /// Serialize public key to bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        // Return cached bytes if available (ensures consistency)
        if let Some(ref cached) = self.cached_bytes {
            return cached.clone();
        }
        
        // Otherwise serialize fresh
        let mut bytes = Vec::new();
        
        // Add matrix seed
        bytes.extend_from_slice(&self.matrix_seed);
        
        // Add encryption state polynomials
        for poly in &self.pk_enc {
            bytes.extend_from_slice(&poly.to_bytes());
        }
        
        // Add authentication state polynomials
        for poly in &self.pk_auth {
            bytes.extend_from_slice(&poly.to_bytes());
        }
        
        bytes
    }

    /// Deserialize public key from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(Vlk1Error::InvalidKeyLength {
                expected: PUBLIC_KEY_BYTES,
                actual: data.len(),
            });
        }
        
        let mut offset = 0;
        
        // Parse matrix seed
        let mut matrix_seed = [0u8; 32];
        matrix_seed.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // Parse encryption state
        let mut pk_enc = Vec::new();
        for _ in 0..K {
            let poly = Polynomial::from_bytes(&data[offset..offset + N * 2])
                .ok_or(Vlk1Error::SerializationError("Invalid polynomial".to_string()))?;
            pk_enc.push(poly);
            offset += N * 2;
        }
        
        // Parse authentication state
        let mut pk_auth = Vec::new();
        for _ in 0..K {
            let poly = Polynomial::from_bytes(&data[offset..offset + N * 2])
                .ok_or(Vlk1Error::SerializationError("Invalid polynomial".to_string()))?;
            pk_auth.push(poly);
            offset += N * 2;
        }
        
        // Cache the original bytes for consistent hashing
        Ok(Self {
            pk_enc,
            pk_auth,
            matrix_seed,
            cached_bytes: Some(data.to_vec()),
        })
    }
}

impl SecretKey {
    /// Serialize secret key to bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed);
        bytes.extend_from_slice(&self.matrix_seed);
        // Add cached public key bytes length (4 bytes) + bytes
        bytes.extend_from_slice(&(self.cached_pk_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.cached_pk_bytes);
        bytes
    }

    /// Deserialize secret key from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 64 + 4 {
            return Err(Vlk1Error::InvalidKeyLength {
                expected: SECRET_KEY_BYTES,
                actual: data.len(),
            });
        }
        
        let mut seed = [0u8; 32];
        let mut matrix_seed = [0u8; 32];
        
        seed.copy_from_slice(&data[0..32]);
        matrix_seed.copy_from_slice(&data[32..64]);
        
        // Read cached pk length
        let pk_len = u32::from_le_bytes([data[64], data[65], data[66], data[67]]) as usize;
        
        if data.len() < 64 + 4 + pk_len {
            return Err(Vlk1Error::InvalidKeyLength {
                expected: 64 + 4 + pk_len,
                actual: data.len(),
            });
        }
        
        let cached_pk_bytes = data[68..68 + pk_len].to_vec();
        
        Ok(Self { seed, matrix_seed, cached_pk_bytes })
    }

    /// Expand secret key to polynomials
    /// 
    /// Regenerates the secret polynomials from the seed
    pub fn expand(&self) -> (Vec<Polynomial>, Vec<Polynomial>) {
        expand_secret_key(&self.seed)
    }
}

impl KeyPair {
    /// Generate a new random key pair using OS random number generator
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self::generate_with_rng(&mut rng)
    }

    /// Generate key pair with specific RNG
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Generate master seed
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        
        // Generate matrix seed
        let mut matrix_seed = [0u8; 32];
        rng.fill_bytes(&mut matrix_seed);
        
        Self::generate_from_seed(seed, matrix_seed)
    }

    /// Generate key pair from given seeds (deterministic)
    pub fn generate_from_seed(seed: [u8; 32], matrix_seed: [u8; 32]) -> Self {
        // Expand secret key
        let (s_enc, s_auth) = expand_secret_key(&seed);
        
        // Generate public matrix A
        let a = generate_public_matrix(&matrix_seed);
        
        // Generate error polynomials
        let e = generate_error_polynomials(&matrix_seed);
        
        // Compute public key: pk = A * s + e
        let pk_enc = compute_public_key_part(&a[0..K], &s_enc, &e[0..K]);
        let pk_auth = compute_public_key_part(&a[K..2*K], &s_auth, &e[K..2*K]);
        
        // Create public key WITHOUT cached_bytes first
        let mut public_key = PublicKey {
            pk_enc,
            pk_auth,
            matrix_seed,
            cached_bytes: None,
        };
        
        // Serialize public key and cache it
        let pk_bytes = public_key.as_bytes();
        public_key.cached_bytes = Some(pk_bytes.clone());
        
        let secret_key = SecretKey {
            seed,
            matrix_seed,
            cached_pk_bytes: pk_bytes,
        };
        
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get reference to public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get reference to secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Reconstruct key pair from secret key
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        // Use cached public key bytes to reconstruct EXACT same public key
        let public_key = PublicKey::from_bytes(&secret_key.cached_pk_bytes)
            .expect("Cached public key bytes must be valid");
        
        Self {
            public_key,
            secret_key,
        }
    }
}

/// Expand secret key from seed
/// 
/// Returns (encryption_state, authentication_state)
fn expand_secret_key(seed: &[u8; 32]) -> (Vec<Polynomial>, Vec<Polynomial>) {
    let mut hasher = Sha3_256::new();
    hasher.update(seed);
    hasher.update(b"enc");
    let enc_seed = hasher.finalize_reset();
    
    hasher.update(seed);
    hasher.update(b"auth");
    let auth_seed = hasher.finalize();
    
    // Generate encryption state
    let mut s_enc = Vec::new();
    for i in 0..K {
        let mut poly_seed = [0u8; 32];
        let mut h = Sha3_256::new();
        h.update(&enc_seed);
        h.update(&(i as u32).to_le_bytes());
        poly_seed.copy_from_slice(&h.finalize());
        
        s_enc.push(Polynomial::sample_cbd(ETA_LOW, &poly_seed));
    }
    
    // Generate authentication state (with noise folding)
    let mut s_auth = Vec::new();
    for i in 0..K {
        let mut poly_seed = [0u8; 32];
        let mut h = Sha3_256::new();
        h.update(&auth_seed);
        h.update(&(i as u32).to_le_bytes());
        poly_seed.copy_from_slice(&h.finalize());
        
        let base = Polynomial::sample_cbd(ETA_LOW, &poly_seed);
        
        // Noise folding: add additional high-variance noise
        let mut fold_seed = [0u8; 32];
        let mut h = Sha3_256::new();
        h.update(&poly_seed);
        h.update(b"fold");
        fold_seed.copy_from_slice(&h.finalize());
        
        let fold = Polynomial::sample_cbd(ETA_HIGH, &fold_seed);
        s_auth.push(base.add(&fold));
    }
    
    (s_enc, s_auth)
}

/// Generate public matrix A
fn generate_public_matrix(seed: &[u8; 32]) -> Vec<Vec<Polynomial>> {
    let mut a = Vec::new();
    
    for i in 0..(K * 2) {
        let mut row = Vec::new();
        for j in 0..K {
            let nonce = (i * K + j) as u16;
            row.push(Polynomial::sample_uniform(seed, nonce));
        }
        a.push(row);
    }
    
    a
}

/// Generate error polynomials
fn generate_error_polynomials(seed: &[u8; 32]) -> Vec<Polynomial> {
    let mut hasher = Sha3_256::new();
    hasher.update(seed);
    hasher.update(b"error");
    let error_seed = hasher.finalize();
    
    let mut errors = Vec::new();
    for i in 0..(K * 2) {
        let mut poly_seed = [0u8; 32];
        let mut h = Sha3_256::new();
        h.update(&error_seed);
        h.update(&(i as u32).to_le_bytes());
        poly_seed.copy_from_slice(&h.finalize());
        
        errors.push(Polynomial::sample_cbd(ETA_LOW, &poly_seed));
    }
    
    errors
}

/// Compute part of public key: pk = A * s + e
fn compute_public_key_part(
    a_rows: &[Vec<Polynomial>],
    s: &[Polynomial],
    e: &[Polynomial],
) -> Vec<Polynomial> {
    let mut pk = Vec::new();
    
    for (i, row) in a_rows.iter().enumerate() {
        // Compute A[i] * s
        let mut result = Polynomial::zero();
        
        for (j, a_ij) in row.iter().enumerate() {
            let prod = a_ij.multiply(&s[j]);
            result = result.add(&prod);
        }
        
        // Add error
        result = result.add(&e[i]);
        
        pk.push(result);
    }
    
    pk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate();
        
        assert_eq!(keypair.public_key.as_bytes().len(), PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret_key.as_bytes().len(), SECRET_KEY_BYTES);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = KeyPair::generate();
        
        // Test public key
        let pk_bytes = keypair.public_key.as_bytes();
        let pk_recovered = PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk_recovered.matrix_seed, keypair.public_key.matrix_seed);
        
        // Test secret key
        let sk_bytes = keypair.secret_key.as_bytes();
        let sk_recovered = SecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk_recovered.seed, keypair.secret_key.seed);
    }

    #[test]
    fn test_key_reconstruction() {
        let keypair1 = KeyPair::generate();
        let sk_bytes = keypair1.secret_key.as_bytes();
        
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let keypair2 = KeyPair::from_secret_key(sk);
        
        // Public keys should match
        let pk1 = keypair1.public_key.as_bytes();
        let pk2 = keypair2.public_key.as_bytes();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_dual_state_keys() {
        let keypair = KeyPair::generate();
        
        // Should have K polynomials in each state
        assert_eq!(keypair.public_key.pk_enc.len(), K);
        assert_eq!(keypair.public_key.pk_auth.len(), K);
        
        let (s_enc, s_auth) = keypair.secret_key.expand();
        assert_eq!(s_enc.len(), K);
        assert_eq!(s_auth.len(), K);
    }

    #[test]
    fn test_deterministic_generation() {
        let seed = [42u8; 32];
        let matrix_seed = [99u8; 32];
        
        let kp1 = KeyPair::generate_from_seed(seed, matrix_seed);
        let kp2 = KeyPair::generate_from_seed(seed, matrix_seed);
        
        // Should generate identical keys
        assert_eq!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes());
        assert_eq!(kp1.secret_key.as_bytes(), kp2.secret_key.as_bytes());
    }
}
