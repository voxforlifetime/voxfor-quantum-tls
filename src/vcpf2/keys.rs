//! Key Derivation for VCPF-2
//! 
//! **CRITICAL SECURITY FIX**: Now uses proper HMAC-based HKDF (RFC 5869)
//! Previous implementation used only hash functions, which is NOT HKDF.
//! 
//! HKDF = HKDF-Extract + HKDF-Expand
//! - Extract: PRK = HMAC-Hash(salt, IKM)
//! - Expand: OKM = HMAC-Hash(PRK, T(i-1) || info || counter)

use sha3::Sha3_256;
use hmac::{Hmac, Mac};

type HmacSha3_256 = Hmac<Sha3_256>;

/// Derive encryption keys from master secret using proper HKDF
/// 
/// # Security Model
/// Uses RFC 5869 HMAC-based Key Derivation Function with SHA3-256:
/// 1. HKDF-Extract: Derives pseudorandom key (PRK) from master secret
/// 2. HKDF-Expand: Expands PRK into output key material with labels
/// 
/// This provides:
/// - ✅ Cryptographic separation between derived keys
/// - ✅ Forward secrecy (PRK doesn't leak master secret)
/// - ✅ Domain separation via labels
pub fn derive_keys(master_secret: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    // HKDF-Extract: derive PRK from master secret
    let prk = hkdf_extract(salt, master_secret);
    
    // HKDF-Expand: derive separate keys for client and server
    let client_key = hkdf_expand(&prk, b"client write key", 32);
    let server_key = hkdf_expand(&prk, b"server write key", 32);
    
    let mut ck = [0u8; 32];
    let mut sk = [0u8; 32];
    ck.copy_from_slice(&client_key);
    sk.copy_from_slice(&server_key);
    
    (ck, sk)
}

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
/// 
/// **Public API** for use in VQST KeySchedule
/// 
/// # RFC 5869 Section 2.2
/// ```text
/// HKDF-Extract(salt, IKM) -> PRK
/// 
/// PRK = HMAC-Hash(salt, IKM)
/// ```
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha3_256::new_from_slice(salt)
        .expect("HMAC can take key of any size");
    mac.update(ikm);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// HKDF-Expand: OKM = HMAC-Hash(PRK, T(i-1) || info || i)
/// 
/// # RFC 5869 Section 2.3
/// ```text
/// HKDF-Expand(PRK, info, L) -> OKM
/// 
/// Options:
///    Hash     a hash function; HashLen denotes the length of the hash function output in octets
/// Inputs:
///    PRK      a pseudorandom key of at least HashLen octets (usually, the output from HKDF-Extract)
///    info     optional context and application specific information (can be a zero-length string)
///    L        length of output keying material in octets (<= 255*HashLen)
/// Output:
///    OKM      output keying material (of L octets)
/// 
/// N = ceil(L/HashLen)
/// T = T(1) | T(2) | T(3) | ... | T(N)
/// OKM = first L octets of T
/// 
/// where:
/// T(0) = empty string (zero length)
/// T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
/// T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
/// T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
/// ...
/// ```
fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut t_prev = Vec::new();
    let mut counter: u8 = 1;
    
    // N = ceil(L / HashLen)
    let hash_len = 32; // SHA3-256 output size
    let iterations = (length + hash_len - 1) / hash_len;
    
    for _ in 0..iterations {
        let mut mac = HmacSha3_256::new_from_slice(prk)
            .expect("HMAC can take key of any size");
        
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[counter]);
        
        let t = mac.finalize().into_bytes();
        output.extend_from_slice(&t);
        
        // Store T(i) for next iteration
        t_prev = t.to_vec();
        
        counter += 1;
    }
    
    output.truncate(length);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let master = [42u8; 32];
        let salt = b"handshake salt";
        
        let (ck, sk) = derive_keys(&master, salt);
        
        assert_ne!(ck, sk);
        assert_ne!(ck, [0u8; 32]);
    }
}
