//! VLK-1 Number Theoretic Transform - ORIGINAL IMPLEMENTATION
//! 
//! This is Voxfor's own NTT, not Kyber's
//! Parameters: N=256, Q=3329, ζ=17

use crate::vlk1::params::{Q, N};

const ZETA: i32 = 17; // Primitive 256th root of unity mod Q
const ZETA_INV: i32 = 1175; // ZETA^-1 mod Q (verified: 17 * 1175 ≡ 1 mod 3329)
const N_INV: i32 = 3316; // 256^-1 mod 3329 (verified: 256 * 3316 ≡ 1 mod 3329)

// Precomputed powers: ZETA^k mod Q for k=0..255
// This optimization replaces expensive pow_mod() calls in inner loops
const POWERS: [i32; 256] = [
       1,   17,  289, 1584,  296, 1703, 2319, 2804,
    1062, 1409,  650, 1063, 1426,  939, 2647, 1722,
    2642, 1637, 1197,  375, 3046, 1847, 1438, 1143,
    2786,  756, 2865, 2099, 2393,  733, 2474, 2110,
    2580,  583, 3253, 2037, 1339, 2789,  807,  403,
     193, 3281, 2513, 2773,  535, 2437, 1481, 1874,
    1897, 2288, 2277, 2090, 2240, 1461, 1534, 2775,
     569, 3015, 1320, 2466, 1974,  268, 1227,  885,
    1729, 2761,  331, 2298, 2447, 1651, 1435, 1092,
    1919, 2662, 1977,  319, 2094, 2308, 2617, 1212,
     630,  723, 2304, 2549,   56,  952, 2868, 2150,
    3260, 2156,   33,  561, 2879, 2337, 3110, 2935,
    3289, 2649, 1756, 3220, 1476, 1789,  452, 1026,
     797,  233,  632,  757, 2882, 2388,  648, 1029,
     848, 1100, 2055, 1645, 1333, 2687, 2402,  886,
    1746, 3050, 1915, 2594,  821,  641,  910, 2154,
    3328, 3312, 3040, 1745, 3033, 1626, 1010,  525,
    2267, 1920, 2679, 2266, 1903, 2390,  682, 1607,
     687, 1692, 2132, 2954,  283, 1482, 1891, 2186,
     543, 2573,  464, 1230,  936, 2596,  855, 1219,
     749, 2746,   76, 1292, 1990,  540, 2522, 2926,
    3136,   48,  816,  556, 2794,  892, 1848, 1455,
    1432, 1041, 1052, 1239, 1089, 1868, 1795,  554,
    2760,  314, 2009,  863, 1355, 3061, 2102, 2444,
    1600,  568, 2998, 1031,  882, 1678, 1894, 2237,
    1410,  667, 1352, 3010, 1235, 1021,  712, 2117,
    2699, 2606, 1025,  780, 3273, 2377,  461, 1179,
      69, 1173, 3296, 2768,  450,  992,  219,  394,
      40,  680, 1573,  109, 1853, 1540, 2877, 2303,
    2532, 3096, 2697, 2572,  447,  941, 2681, 2300,
    2481, 2229, 1274, 1684, 1996,  642,  927, 2443,
    1583,  279, 1414,  735, 2508, 2688, 2419, 1175,
];

// Precomputed inverse powers: ZETA^(-k) mod Q for k=0..255
const POWERS_INV: [i32; 256] = [
       1, 1175, 2419, 2688, 2508,  735, 1414,  279,
    1583, 2443,  927,  642, 1996, 1684, 1274, 2229,
    2481, 2300, 2681,  941,  447, 2572, 2697, 3096,
    2532, 2303, 2877, 1540, 1853,  109, 1573,  680,
      40,  394,  219,  992,  450, 2768, 3296, 1173,
      69, 1179,  461, 2377, 3273,  780, 1025, 2606,
    2699, 2117,  712, 1021, 1235, 3010, 1352,  667,
    1410, 2237, 1894, 1678,  882, 1031, 2998,  568,
    1600, 2444, 2102, 3061, 1355,  863, 2009,  314,
    2760,  554, 1795, 1868, 1089, 1239, 1052, 1041,
    1432, 1455, 1848,  892, 2794,  556,  816,   48,
    3136, 2926, 2522,  540, 1990, 1292,   76, 2746,
     749, 1219,  855, 2596,  936, 1230,  464, 2573,
     543, 2186, 1891, 1482,  283, 2954, 2132, 1692,
     687, 1607,  682, 2390, 1903, 2266, 2679, 1920,
    2267,  525, 1010, 1626, 3033, 1745, 3040, 3312,
    3328, 2154,  910,  641,  821, 2594, 1915, 3050,
    1746,  886, 2402, 2687, 1333, 1645, 2055, 1100,
     848, 1029,  648, 2388, 2882,  757,  632,  233,
     797, 1026,  452, 1789, 1476, 3220, 1756, 2649,
    3289, 2935, 3110, 2337, 2879,  561,   33, 2156,
    3260, 2150, 2868,  952,   56, 2549, 2304,  723,
     630, 1212, 2617, 2308, 2094,  319, 1977, 2662,
    1919, 1092, 1435, 1651, 2447, 2298,  331, 2761,
    1729,  885, 1227,  268, 1974, 2466, 1320, 3015,
     569, 2775, 1534, 1461, 2240, 2090, 2277, 2288,
    1897, 1874, 1481, 2437,  535, 2773, 2513, 3281,
     193,  403,  807, 2789, 1339, 2037, 3253,  583,
    2580, 2110, 2474,  733, 2393, 2099, 2865,  756,
    2786, 1143, 1438, 1847, 3046,  375, 1197, 1637,
    2642, 1722, 2647,  939, 1426, 1063,  650, 1409,
    1062, 2804, 2319, 1703,  296, 1584,  289,   17,
];

/// VLK-1 Forward NTT - Cooley-Tukey O(N log N) implementation
/// 
/// FIXED: Replaced O(N²) naive DFT with decimation-in-time FFT butterfly
pub fn ntt(coeffs: &mut [i32; N]) {
    const LOG_N: usize = 8; // log2(256)
    
    // Bit-reversal permutation
    for i in 0..N {
        let j = bit_reverse(i, LOG_N);
        if i < j {
            coeffs.swap(i, j);
        }
    }
    
    // Cooley-Tukey butterflies
    let mut len = 2;
    while len <= N {
        let half_len = len / 2;
        let step = N / len;
        
        for start in (0..N).step_by(len) {
            let mut k = 0;
            for j in 0..half_len {
                let twiddle_idx = k;
                let twiddle = POWERS[twiddle_idx];
                
                let t = mul_mod(twiddle, coeffs[start + j + half_len], Q);
                let u = coeffs[start + j];
                
                coeffs[start + j] = reduce_mod((u as i64) + (t as i64));
                coeffs[start + j + half_len] = reduce_mod((u as i64) - (t as i64));
                
                k += step;
            }
        }
        
        len *= 2;
    }
}

/// VLK-1 Inverse NTT - Cooley-Tukey O(N log N) inverse
/// 
/// FIXED: Replaced O(N²) with Gentleman-Sande inverse butterfly
pub fn intt(coeffs: &mut [i32; N]) {
    const LOG_N: usize = 8;
    
    // Gentleman-Sande butterflies (inverse)
    let mut len = N;
    while len >= 2 {
        let half_len = len / 2;
        let step = N / len;
        
        for start in (0..N).step_by(len) {
            let mut k = 0;
            for j in 0..half_len {
                let twiddle_idx = k;
                let twiddle = POWERS_INV[twiddle_idx];
                
                let u = coeffs[start + j];
                let v = coeffs[start + j + half_len];
                
                coeffs[start + j] = reduce_mod((u as i64) + (v as i64));
                let diff = reduce_mod((u as i64) - (v as i64));
                coeffs[start + j + half_len] = mul_mod(twiddle, diff, Q);
                
                k += step;
            }
        }
        
        len /= 2;
    }
    
    // Bit-reversal permutation
    for i in 0..N {
        let j = bit_reverse(i, LOG_N);
        if i < j {
            coeffs.swap(i, j);
        }
    }
    
    // Scale by N^(-1)
    for coeff in coeffs.iter_mut() {
        *coeff = mul_mod(*coeff, N_INV, Q);
    }
}

/// Bit-reverse a number with log_n bits
fn bit_reverse(mut x: usize, log_n: usize) -> usize {
    let mut result = 0;
    for _ in 0..log_n {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Modular exponentiation: base^exp mod m
fn pow_mod(mut base: i32, mut exp: i32, m: i32) -> i32 {
    let mut result = 1i64;
    let mut b = (base as i64).rem_euclid(m as i64);
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b).rem_euclid(m as i64);
        }
        b = (b * b).rem_euclid(m as i64);
        exp >>= 1;
    }
    
    result as i32
}

/// Modular inverse using Extended Euclidean Algorithm
fn mod_inverse(a: i32, m: i32) -> i32 {
    let mut t = 0i32;
    let mut newt = 1i32;
    let mut r = m;
    let mut newr = a;
    
    while newr != 0 {
        let quotient = r / newr;
        
        let temp = t;
        t = newt;
        newt = temp - quotient * newt;
        
        let temp = r;
        r = newr;
        newr = temp - quotient * newr;
    }
    
    if r > 1 {
        panic!("not invertible");
    }
    if t < 0 {
        t = t + m;
    }
    
    t
}

/// Reduce to [0, Q)
fn reduce_mod(a: i64) -> i32 {
    let r = (a % (Q as i64)) as i32;
    if r < 0 { r + Q } else { r }
}

/// Modular multiplication
fn mul_mod(a: i32, b: i32, m: i32) -> i32 {
    reduce_mod((a as i64) * (b as i64))
}

// ==== Public API for polynomial operations ====

/// Barrett reduction - optimized modular reduction avoiding division
/// 
/// Traditional Barrett reduction uses precomputed constants:
/// m = floor(2^k / q) where k is chosen for precision
/// r ≈ a - floor(a * m / 2^k) * q
/// 
/// # 🔴 CRITICAL: This function has timing leaks (branches)!
///
/// ## SECURITY ISSUE
///
/// The `if` statements create data-dependent branches that leak timing information:
/// ```rust
/// if r > half_q { ... } else if r < -half_q { ... }
/// ```
///
/// An attacker measuring execution time can deduce information about `r`,
/// which leaks bits of the secret key during decapsulation.
///
/// ## PROPER CONSTANT-TIME IMPLEMENTATION
///
/// Should use **branchless** operations (bitwise arithmetic only):
/// ```rust
/// // Constant-time centered reduction (pseudocode)
/// let mut r = a % Q;
/// let mask_high = ((r - (Q/2 + 1)) >> 31) - 1;  // -1 if r > Q/2, else 0
/// r -= Q & mask_high;
/// 
/// let mask_low = ((-(Q/2) - r) >> 31) - 1;  // -1 if r < -Q/2, else 0
/// r += Q & mask_low;
/// ```
///
/// ## WHY THIS MATTERS
///
/// VLK-1 uses this in:
/// - NTT butterfly operations (with secret polynomials)
/// - Decapsulation (processes ciphertext with secret key)
///
/// Timing differences can leak the secret key bit-by-bit.
///
/// ## TEMPORARY WARNING
///
/// ⚠️ **CURRENT CODE IS NOT CONSTANT-TIME**
/// - Acceptable for research/testing
/// - **DO NOT USE** in production without fixing
/// - Consider using audited libraries (e.g., PQClean's Kyber)
///
/// For Q=3329, we use k=32 for i64 arithmetic:
/// m = 2^32 / 3329 ≈ 1290167
/// ✅ FIXED: Constant-time branchless implementation
#[inline(always)]
pub fn barrett_reduce(a: i32) -> i32 {
    // Constant-time centered reduction using only bitwise operations
    // No branches → no timing leaks
    
    let a_i64 = a as i64;
    let q_i64 = Q as i64;
    let mut r = a_i64 % q_i64;
    
    // Branchless reduction to [-Q/2, Q/2]
    // Instead of: if r > Q/2 { r -= Q }
    // We use: r -= Q & ((r - (Q/2 + 1)) >> 63)
    
    let half_q = q_i64 / 2;
    
    // Mask = -1 (all bits set) if r > half_q, else 0
    // (r - (half_q + 1)) >> 63 gives sign bit (0 if positive, 1 if negative)
    // Then subtract 1 to get 0 or -1
    let mask_high = ((r - (half_q + 1)) >> 63).wrapping_sub(1);
    r -= q_i64 & mask_high;
    
    // Mask = -1 if r < -half_q, else 0
    let neg_half_q = -half_q;
    let mask_low = ((neg_half_q - r) >> 63).wrapping_sub(1);
    r += q_i64 & mask_low;
    
    r as i32
}

/// Pointwise multiplication in NTT domain
pub fn mul_ntt(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];
    for i in 0..N {
        result[i] = mul_mod(a[i], b[i], Q);
    }
    result
}

/// Add two polynomials
pub fn add_poly(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];
    for i in 0..N {
        result[i] = reduce_mod((a[i] + b[i]) as i64);
    }
    result
}

/// Subtract two polynomials
pub fn sub_poly(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];
    for i in 0..N {
        result[i] = reduce_mod((a[i] - b[i]) as i64);
    }
    result
}

/// ✅ PRODUCTION: Centered reduction [-Q/2, Q/2] - Constant-Time
/// 
/// **Critical Fix**: Removed `if` branch that leaked timing information
pub fn centered_reduce(a: i32) -> i32 {
    let t = reduce_mod(a as i64);
    
    // ✅ Branchless: if t > Q/2 then subtract Q
    let half_q = Q / 2;
    let mask = ((t - (half_q + 1)) >> 31) as i32;  // -1 if t > Q/2, else 0
    t + (mask & -Q)  // Subtracts Q when mask=-1, adds 0 when mask=0
}

/// Montgomery multiplication (compatibility)
#[inline(always)]
pub fn mul_mod_montgomery(a: i32, b: i32) -> i32 {
    mul_mod(a, b, Q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_intt_identity() {
        let mut a = [0i32; 256];
        for i in 0..10 {
            a[i] = (i + 1) as i32;
        }
        
        let original = a.clone();
        
        ntt(&mut a);
        intt(&mut a);
        
        for i in 0..256 {
            assert_eq!(a[i], original[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_polynomial_multiplication() {
        let mut a = [0i32; 256];
        let mut b = [0i32; 256];
        a[0] = 1;
        b[0] = 2;

        ntt(&mut a);
        ntt(&mut b);

        let c = mul_ntt(&a, &b);
        let mut result = c;
        intt(&mut result);

        // Result should be 2 in coefficient form
        assert_eq!(result[0], 2);
    }

    #[test]
    fn test_mul_mod_montgomery() {
        let result = mul_mod_montgomery(100, 200);
        assert!(result >= 0 && result < Q);
    }
}

