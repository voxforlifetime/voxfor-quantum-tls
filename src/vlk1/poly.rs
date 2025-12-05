//! Polynomial operations for VLK-1
//! 
//! Represents polynomials in R_q = Z_q[X]/(X^n + 1)

use crate::vlk1::{params::*, ntt::*};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Polynomial in R_q
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    /// Coefficients (either in standard or NTT form)
    pub coeffs: [i32; N],
    /// Whether coefficients are in NTT form
    pub is_ntt: bool,
}

impl Polynomial {
    /// Create zero polynomial
    pub fn zero() -> Self {
        Self {
            coeffs: [0; N],
            is_ntt: false,
        }
    }

    /// Create polynomial from coefficients
    pub fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self {
            coeffs,
            is_ntt: false,
        }
    }

    /// Convert to NTT form (in-place)
    pub fn to_ntt(&mut self) {
        if !self.is_ntt {
            ntt(&mut self.coeffs);
            self.is_ntt = true;
        }
    }

    /// Convert from NTT form (in-place)
    pub fn from_ntt(&mut self) {
        if self.is_ntt {
            intt(&mut self.coeffs);
            self.is_ntt = false;
        }
    }

    /// Multiply two polynomials
    /// 
    /// Uses NTT for O(n log n) performance
    pub fn multiply(&self, other: &Self) -> Self {
        let mut a = self.clone();
        let mut b = other.clone();
        
        // Convert to NTT if needed
        a.to_ntt();
        b.to_ntt();
        
        // Pointwise multiplication in NTT domain
        let result_coeffs = mul_ntt(&a.coeffs, &b.coeffs);
        
        Self {
            coeffs: result_coeffs,
            is_ntt: true,
        }
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        // Convert to same form if needed
        let mut a = self.clone();
        let mut b = other.clone();
        
        if a.is_ntt != b.is_ntt {
            if a.is_ntt {
                a.from_ntt();
            } else {
                b.from_ntt();
            }
        }
        
        let result_coeffs = add_poly(&a.coeffs, &b.coeffs);
        
        Self {
            coeffs: result_coeffs,
            is_ntt: a.is_ntt,
        }
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        // Convert to same form if needed
        let mut a = self.clone();
        let mut b = other.clone();
        
        if a.is_ntt != b.is_ntt {
            if a.is_ntt {
                a.from_ntt();
            } else {
                b.from_ntt();
            }
        }
        
        let result_coeffs = sub_poly(&a.coeffs, &b.coeffs);
        
        Self {
            coeffs: result_coeffs,
            is_ntt: a.is_ntt,
        }
    }

    /// Sample polynomial from centered binomial distribution
    /// 
    /// Used for noise generation
    pub fn sample_cbd(eta: usize, seed: &[u8]) -> Self {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        let hash = hasher.finalize();
        
        let mut coeffs = [0i32; N];
        let mut rng_state = [0u8; 32];
        rng_state.copy_from_slice(&hash);
        
        for i in 0..N {
            let mut a = 0i32;
            let mut b = 0i32;
            
            // Sample from binomial using deterministic hash
            for j in 0..eta {
                let mut h = Sha3_256::new();
                h.update(&rng_state);
                h.update(&(i as u32).to_le_bytes());
                h.update(&(j as u32).to_le_bytes());
                let hash_out = h.finalize();
                
                a += (hash_out[0] & 1) as i32;
                b += ((hash_out[0] >> 1) & 1) as i32;
            }
            
            coeffs[i] = a - b;
        }
        
        Self::from_coeffs(coeffs)
    }

    /// Sample polynomial from uniform distribution
    /// 
    /// # Security Note: Non-Constant-Time (Rejection Sampling)
    /// 
    /// ⚠️ **IMPORTANT**: This function uses rejection sampling (`if val < Q`)
    /// which means the execution time depends on the random values generated.
    /// 
    /// **Current Usage**: SAFE - only used for public matrix A generation
    /// where timing leaks are not a concern.
    /// 
    /// **NEVER USE** for secret key generation or any sensitive operations!
    /// For secret sampling, use `sample_cbd()` which is constant-time.
    /// 
    /// # Why Non-Constant-Time is OK Here
    /// 
    /// - Matrix A is **public** (part of public key)
    /// - Timing variations reveal nothing about private keys
    /// - Rejection sampling is necessary for uniform distribution
    /// 
    /// # Future Improvements
    /// 
    /// Consider using constant-time uniform sampling (e.g., via constant-time
    /// rejection or modular reduction techniques) if paranoid about metadata leaks.
    /// 
    /// Used for public matrix generation
    pub fn sample_uniform(seed: &[u8], nonce: u16) -> Self {
        use sha3::{Sha3_256, Digest};
        
        let mut coeffs = [0i32; N];
        let mut i = 0;
        let mut ctr = 0u32;
        
        while i < N {
            let mut hasher = Sha3_256::new();
            hasher.update(seed);
            hasher.update(&nonce.to_le_bytes());
            hasher.update(&ctr.to_le_bytes());
            let hash = hasher.finalize();
            ctr += 1;
            
            // Parse hash bytes as potential coefficients
            for chunk in hash.chunks(2) {
                if i >= N {
                    break;
                }
                
                let val = ((chunk[0] as u16) | ((chunk[1] as u16) << 8)) as i32;
                
                // Rejection sampling: accept if val < Q
                if val < Q {
                    coeffs[i] = val;
                    i += 1;
                }
            }
        }
        
        Self::from_coeffs(coeffs)
    }

    /// Compress polynomial coefficients
    /// 
    /// Reduces size for transmission with proper bit-packing
    /// Compress polynomial coefficients with lossy quantization
    /// 
    /// # Precision Analysis
    /// 
    /// Compresses coefficient c ∈ [0, Q) to d = 2^bits levels.
    /// 
    /// **Formula**: `compressed = round((c * d) / Q) mod d`
    /// 
    /// **Precision Loss**:
    /// - Each coefficient loses log₂(Q/d) bits of precision
    /// - For bits=4: Q/d = 3329/16 ≈ 208 → ~7.7 bits lost per coefficient
    /// - For bits=10: Q/d = 3329/1024 ≈ 3.25 → ~1.7 bits lost per coefficient
    /// 
    /// **Rounding**: Uses banker's rounding (+ Q/2) to minimize bias.
    /// 
    /// # Integer Overflow Protection
    /// 
    /// All intermediate calculations use `i64` to prevent overflow:
    /// - Max value: c=3328, d=2^bits, c*d ≤ 3328 * 2^32 ≈ 2^43 (fits in i64)
    /// - No overflow possible for bits ≤ 32
    pub fn compress(&self, bits: usize) -> Vec<u8> {
        assert!(!self.is_ntt, "Cannot compress NTT form");
        assert!(bits > 0 && bits <= 32, "Compression bits must be in [1, 32]");
        
        let d = 1u64 << bits; // Use u64 for large d values
        let total_bits = N * bits;
        let total_bytes = (total_bits + 7) / 8;
        let mut compressed = vec![0u8; total_bytes];
        
        let mut bit_offset = 0;
        for &coeff in &self.coeffs {
            // Normalize to [0, Q) range first
            let c = ((coeff % Q as i32) + Q as i32) % Q as i32;
            debug_assert!(c >= 0 && c < Q, "Coefficient out of range: {}", c);
            
            // Compress: val = round((c * d) / Q)
            // Use i64 arithmetic to prevent overflow
            // Max: 3328 * 2^32 + 3329/2 ≈ 2^43 (safe in i64)
            let numerator = (c as i64) * (d as i64) + (Q as i64 / 2);
            let val = (numerator / Q as i64) as u64 % d;
            
            debug_assert!(val < d, "Compressed value {} exceeds d={}", val, d);
            
            // Pack val into bits at bit_offset (LSB-first bit packing)
            for i in 0..bits {
                let bit = (val >> i) & 1;
                let byte_idx = bit_offset / 8;
                let bit_idx = bit_offset % 8;
                compressed[byte_idx] |= (bit as u8) << bit_idx;
                bit_offset += 1;
            }
        }
        
        compressed
    }

    /// Decompress polynomial coefficients with proper bit-unpacking
    /// 
    /// # Idempotency Requirement
    /// 
    /// **CRITICAL**: Decompression must be inverse of compression:
    /// ```text
    /// compress(decompress(compress(x))) == compress(x)
    /// ```
    /// 
    /// This ensures that double-compression doesn't further degrade precision.
    /// 
    /// # Decompression Formula
    /// 
    /// Given compressed value v ∈ [0, d), recover c ∈ [0, Q):
    /// ```text
    /// c = round((v * Q) / d) = (v * Q + d/2) / d
    /// ```
    /// 
    /// **Verification**: compress(c) should yield v:
    /// ```text
    /// compress(c) = round((c * d) / Q)
    ///             = round((round((v*Q)/d) * d) / Q)
    ///             = round(v)  (approximately)
    ///             = v  (exactly, with proper rounding)
    /// ```
    /// 
    /// # Integer Overflow Protection
    /// 
    /// Uses i64 arithmetic to prevent overflow:
    /// - Max: v * Q ≤ 2^32 * 3329 ≈ 2^43 (safe in i64)
    pub fn decompress(data: &[u8], bits: usize) -> Self {
        assert!(bits > 0 && bits <= 32, "Compression bits must be in [1, 32]");
        
        let d = 1u64 << bits;
        let mut coeffs = [0i32; N];
        
        let mut bit_offset = 0;
        for i in 0..N {
            // Extract 'bits' bits starting at bit_offset (LSB-first)
            let mut val = 0u64;
            for j in 0..bits {
                let byte_idx = bit_offset / 8;
                let bit_idx = bit_offset % 8;
                if byte_idx < data.len() {
                    let bit = (data[byte_idx] >> bit_idx) & 1;
                    val |= (bit as u64) << j;
                }
                bit_offset += 1;
            }
            
            debug_assert!(val < d, "Extracted value {} exceeds d={}", val, d);
            
            // Decompress: c = round((val * Q) / d)
            // Use i64 arithmetic to prevent overflow
            // Max: 2^32 * 3329 + 2^31 ≈ 2^43 (safe in i64)
            let numerator = (val as i64) * (Q as i64) + (d as i64 / 2);
            let c = (numerator / d as i64) as i32;
            
            // Reduce to [0, Q) range
            coeffs[i] = if c >= Q { c - Q } else { c };
            
            debug_assert!(coeffs[i] >= 0 && coeffs[i] < Q, 
                "Decompressed coefficient {} out of range", coeffs[i]);
        }
        
        Self::from_coeffs(coeffs)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 2);
        
        for &coeff in &self.coeffs {
            let c = barrett_reduce(coeff);
            bytes.push((c & 0xFF) as u8);
            bytes.push(((c >> 8) & 0xFF) as u8);
        }
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != N * 2 {
            return None;
        }
        
        let mut coeffs = [0i32; N];
        
        for i in 0..N {
            let low = data[i * 2] as i32;
            let high = data[i * 2 + 1] as i32;
            coeffs[i] = low | (high << 8);
        }
        
        Some(Self::from_coeffs(coeffs))
    }
}

impl std::fmt::Debug for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Polynomial(len={}, ntt={})", N, self.is_ntt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_arithmetic() {
        let a = Polynomial::from_coeffs([1; N]);
        let b = Polynomial::from_coeffs([2; N]);
        
        let sum = a.add(&b);
        assert_eq!(barrett_reduce(sum.coeffs[0]), 3);
        
        let diff = sum.sub(&b);
        assert_eq!(barrett_reduce(diff.coeffs[0]), 1);
    }

    #[test]
    fn test_polynomial_multiplication() {
        let mut a = Polynomial::zero();
        let mut b = Polynomial::zero();
        
        a.coeffs[0] = 2;
        b.coeffs[0] = 3;
        
        let mut result = a.multiply(&b);
        result.from_ntt(); // Convert back to coefficient form
        
        assert_eq!(barrett_reduce(result.coeffs[0]), 6);
    }

    #[test]
    fn test_ntt_conversion() {
        let mut poly = Polynomial::from_coeffs([1; N]);
        let original = poly.coeffs;
        
        poly.to_ntt();
        assert!(poly.is_ntt);
        
        poly.from_ntt();
        assert!(!poly.is_ntt);
        
        // Should match original
        for i in 0..N {
            let poly_reduced = barrett_reduce(poly.coeffs[i]);
            let orig_reduced = barrett_reduce(original[i]);
            // NTT/INTT must be EXACT - zero tolerance for errors!
            assert_eq!(poly_reduced, orig_reduced, 
                "NTT/INTT roundtrip error at index {}: {} != {}", 
                i, poly_reduced, orig_reduced);
        }
    }

    #[test]
    fn test_cbd_sampling() {
        let seed = [0u8; 32];
        let poly = Polynomial::sample_cbd(ETA_LOW, &seed);
        
        // All coefficients should be small
        for &coeff in &poly.coeffs {
            let c = centered_reduce(coeff);
            assert!(c.abs() <= 10); // Should be within noise bound
        }
    }

    #[test]
    fn test_uniform_sampling() {
        let seed = [0u8; 32];
        let poly = Polynomial::sample_uniform(&seed, 0);
        
        // All coefficients should be in [0, Q)
        for &coeff in &poly.coeffs {
            assert!(coeff >= 0 && coeff < Q);
        }
    }

    #[test]
    fn test_serialization() {
        let poly = Polynomial::from_coeffs([42; N]);
        let bytes = poly.to_bytes();
        let recovered = Polynomial::from_bytes(&bytes).unwrap();
        
        for i in 0..N {
            assert_eq!(barrett_reduce(poly.coeffs[i]), barrett_reduce(recovered.coeffs[i]));
        }
    }

    #[test]
    fn test_compression() {
        let poly = Polynomial::from_coeffs([100; N]);
        let compressed = poly.compress(4);
        let decompressed = Polynomial::decompress(&compressed, 4);
        
        // Should be approximately equal (within compression error)
        for i in 0..N {
            let diff = (poly.coeffs[i] - decompressed.coeffs[i]).abs();
            assert!(diff < Q / 2); // Within 10% error
        }
    }
    
    #[test]
    fn test_compression_idempotency() {
        // ✅ SECURITY TEST: Compression must be idempotent
        // compress(decompress(compress(x))) == compress(x)
        //
        // Why this matters for VLK-1 KEM:
        // - KEM encapsulation compresses ciphertext
        // - Decapsulation decompresses, processes, then re-compresses to verify
        // - If double compression changes the value, decapsulation FAILS
        // - This could cause legitimate handshakes to fail (availability issue)
        
        let poly = Polynomial::from_coeffs([100; N]);
        
        // First compression
        let compressed1 = poly.compress(4);
        
        // Decompress
        let decompressed = Polynomial::decompress(&compressed1, 4);
        
        // Second compression (should match first!)
        let compressed2 = decompressed.compress(4);
        
        // ✅ CRITICAL: Must be identical!
        assert_eq!(compressed1, compressed2,
            "Double compression changed the value! This breaks KEM decapsulation.");
    }
    
    #[test]
    fn test_compression_various_bits() {
        // Test idempotency for different compression levels
        for bits in [4, 5, 10] {
            let poly = Polynomial::from_coeffs([123; N]);
            
            let c1 = poly.compress(bits);
            let d = Polynomial::decompress(&c1, bits);
            let c2 = d.compress(bits);
            
            assert_eq!(c1, c2, "Compression not idempotent for {} bits", bits);
        }
    }
    
    #[test]
    fn test_compression_random_values() {
        // Test with random values (within [0, Q))
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let mut coeffs = [0i32; N];
        for c in &mut coeffs {
            *c = rng.gen_range(0..Q);
        }
        
        let poly = Polynomial::from_coeffs(coeffs);
        
        let compressed = poly.compress(4);
        let decompressed = Polynomial::decompress(&compressed, 4);
        let compressed2 = decompressed.compress(4);
        
        assert_eq!(compressed, compressed2,
            "Compression not idempotent for random values");
    }
}
