//! VOX-SIG Parameters

/// Hash function output size (SHA3-256)
pub const HASH_SIZE: usize = 32;

/// Number of bits in message hash (256)
pub const LAMPORT_N: usize = 256;

/// Merkle tree height
/// 
/// **Default:** 16 (65,536 signatures) - Balanced for most use cases
/// - Root CA: 65K certificates (10/day = 17.9 years) ✅
/// - Intermediate CA: 65K certificates (100/day = 1.8 years) ⚠️
/// - TLS Server: 65K handshakes (100/sec = 11 minutes, 1/sec = 18 hours) ⚠️
/// 
/// **Production Options:**
/// - HEIGHT=16: Fast keygen (~30s), sufficient for CAs
/// - HEIGHT=18: 262K signatures (~2min keygen), good for intermediate CAs
/// - HEIGHT=20: 1M signatures (~9min keygen), high-volume servers
/// - HEIGHT=24: 16M signatures (~2.5hr keygen), enterprise deployments
/// 
/// **Security vs DoS Trade-off:**
/// Lower height = faster keygen, less DoS risk, but key rotation needed
/// Higher height = slower keygen (DoS vector), but longer key lifetime
/// 
/// **Compile-time override:** 
/// `RUSTFLAGS="--cfg merkle_height_20" cargo build` for HEIGHT=20
#[cfg(not(any(merkle_height_18, merkle_height_20, merkle_height_24)))]
pub const MERKLE_HEIGHT: usize = 16;

#[cfg(merkle_height_18)]
pub const MERKLE_HEIGHT: usize = 18;

#[cfg(merkle_height_20)]
pub const MERKLE_HEIGHT: usize = 20;

#[cfg(merkle_height_24)]
pub const MERKLE_HEIGHT: usize = 24;

/// Maximum number of signatures per key
pub const MAX_SIGNATURES: usize = 1 << MERKLE_HEIGHT;

/// Verifying key size (merkle root + seed)
pub const VERIFYING_KEY_BYTES: usize = HASH_SIZE * 2;

/// Signing key size (seed + pub_seed + counter)
pub const SIGNING_KEY_BYTES: usize = HASH_SIZE * 2 + 4;

/// Signature size (Lamport sig + Merkle path + metadata)
pub const SIGNATURE_BYTES: usize = HASH_SIZE * (LAMPORT_N + MERKLE_HEIGHT + 1) + 8;

/// Security parameter in bits
pub const SECURITY_PARAM: usize = 128;
