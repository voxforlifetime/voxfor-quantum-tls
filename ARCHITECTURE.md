# Architecture Overview

This document provides a technical deep-dive into the Voxfor Quantum TLS architecture, module organization, and cryptographic design decisions.

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Module Structure](#module-structure)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Protocol Flow](#protocol-flow)
5. [Key Management](#key-management)
6. [Security Design Decisions](#security-design-decisions)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Application Layer                      │
│         (Your code: TCP server, connection mgmt, etc.)       │
└──────────────┬───────────────────────────────────┬──────────┘
               │                                   │
┌──────────────▼──────────────┐   ┌──────────────▼───────────┐
│    VQST (Protocol Layer)    │   │   CA Infrastructure      │
│  ┌────────────────────────┐ │   │  ┌──────────────────┐    │
│  │ Client State Machine   │ │   │  │  RootCA          │    │
│  │ Server State Machine   │ │   │  │  IntermediateCA  │    │
│  │ Handshake Messages     │ │   │  │  CertificateIssuer│   │
│  │ Transcript Hash        │ │   │  │  CRLManager      │    │
│  │ Key Schedule (HKDF)    │ │   │  └──────────────────┘    │
│  └────────────────────────┘ │   └──────────────────────────┘
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│                 VCPF-2 (Record Layer)                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ChaCha20-Poly1305 AEAD Encryption                   │   │
│  │  Record Framing & Fragmentation                      │   │
│  │  Key Update Support                                  │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────┬──────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────┐
│           Cryptographic Primitives Layer                     │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐    │
│  │  VLK-1 KEM │  │  VOX-SIG   │  │  QX509 Certificates│    │
│  │  (Lattice) │  │  (Hash)    │  │  (Custom X.509)    │    │
│  └────────────┘  └────────────┘  └────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### `src/lib.rs`
Top-level library entry point. Defines public API surface and feature flags.

**Key Features**:
- `#![deny(unsafe_code)]` - No unsafe Rust allowed
- `#![warn(missing_docs)]` - Enforce documentation
- Supports `no_std` with `alloc` for embedded systems

### `src/vlk1/` - VLK-1 Lattice KEM

**Files**:
- `params.rs`: Cryptographic parameters (N=256, Q=3329, K=3)
- `poly.rs`: Polynomial arithmetic (add, mul, NTT/INTT conversion)
- `ntt.rs`: Number Theoretic Transform (Cooley-Tukey FFT)
- `keygen.rs`: Key generation with dual-state keys
- `kem.rs`: Encapsulation/decapsulation with Fujisaki-Okamoto

**Security Critical Code**:
- `ntt.rs:barrett_reduce()` - **Constant-time** branchless reduction
- `ntt.rs:centered_reduce()` - **Constant-time** centering
- `poly.rs:sample_cbd()` - Constant-time sampling for secret polynomials
- `kem.rs:decapsulate()` - **Implicit rejection** (no failure leak)

**Data Flow**:
```
KeyGen:
  seed (32B) → expand → matrix A, secret s, error e
              → public key pk = A·s + e

Encapsulate:
  pk + ephemeral randomness r
  → ciphertext ct = A^T·r + e1, msg·r + e2
  → shared secret ss = KDF(msg || ct)

Decapsulate:
  ct + sk → decode msg' → recompute ct'
  IF ct' == ct: ss = KDF(msg' || ct)  Valid
  ELSE: ss = KDF(sk || ct) Implicit rejection
```

### `src/voxsig/` - VOX-SIG Hash-Based Signatures

**Files**:
- `params.rs`: MERKLE_HEIGHT=16 (65,536 signatures)
- `lamport.rs`: Lamport one-time signatures
- `merkle.rs`: Merkle tree with domain separation
- `keygen.rs`: Key generation with cached Merkle tree
- `sign.rs`: Signing with index management
- `verify.rs`: Verification with preimage checks
- `safe_signer.rs`: **CRITICAL** Atomic persistence wrapper

**Security Critical Code**:
- `keygen.rs:SigningKey.counter` - **MUST** never repeat (150+ lines of docs)
- `safe_signer.rs:sign()` - Atomic write → fsync → rename
- `lamport.rs:LamportPublicKey.pairs` - Stores individual hashes for preimage verification
- `verify.rs:verify()` - Checks Hash(revealed_key) == pk_hash[bit]

**Signature Format**:
```
┌─────────────────────────────────────────────────────────────┐
│ index (4B)                                                   │
│ lamport_signature (256 × 32B = 8KB)                         │
│ lamport_pk_full (256 × 2 × 32B = 16KB) ← prevents forgery  │
│ lamport_pk_compressed (32B)                                 │
│ poly_commit (32B)                                           │
│ merkle_path (16 × 32B = 512B)                               │
└─────────────────────────────────────────────────────────────┘
Total: ~17KB
```

**Why So Large?**
`lamport_pk_full` is included to enable preimage verification. Without it, an attacker could forge signatures by mixing their own Lamport keys with a stolen Merkle path.

### `src/qx509/` - Quantum X.509 Certificates

**Files**:
- `certificate_full.rs`: Full certificate structure
- `extensions_full.rs`: X.509 extensions (KeyUsage, SAN, etc.)
- `distinguished_name.rs`: DN (CN, O, C, etc.)
- `validity.rs`: Time-based validity with clock skew tolerance
- `pem_der.rs`: PEM/DER encoding with DoS protection
- `chain_validator.rs`: Chain validation with CRL checking

**Certificate Format**:
```
┌─────────────────────────────────────────────────────────────┐
│ version: u32                                                 │
│ serial_number: u128                                          │
│ signature_algorithm: VOX-SIG-SHA3-256                        │
│ issuer: DistinguishedName                                    │
│ validity: (not_before, not_after)                            │
│ subject: DistinguishedName                                   │
│ subject_public_key: VOX-SIG VerifyingKey                     │
│ extensions:                                                  │
│   - KeyUsage (DigitalSignature, KeyAgreement, ...)          │
│   - BasicConstraints (CA:TRUE/FALSE, pathLen)               │
│   - SubjectAlternativeName (DNS names)                       │
│   - AuthorityKeyIdentifier (issuer key hash)                │
│   - SubjectKeyIdentifier (subject key hash)                  │
│   - ExtendedKeyUsage (serverAuth, clientAuth)               │
│   - CRLDistributionPoints (revocation check URLs)            │
│ signature: VOX-SIG signature (~17KB)                         │
└─────────────────────────────────────────────────────────────┘
```

**Security Features**:
- **DoS Protection**: 10MB cert size limit, bounded DER parsing
- **Fail-Closed CRL**: If CRL unavailable, validation fails
- **Key Usage Validation**: Ensures BasicConstraints matches KeyUsage flags

### `src/ca/` - Certificate Authority

**Files**:
- `root_ca.rs`: Root CA with atomic persistence
- `intermediate_ca.rs`: Intermediate CA with atomic persistence
- `issuer.rs`: Issues end-entity certificates
- `revocation.rs`: CRL management

**Atomic Persistence Pattern**:
```rust
fn save_key_atomic(key: &SigningKey, path: &Path) -> Result<()> {
    // 1. Write to temp file
    let tmp = path.with_extension(".tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&serialize(key))?;
    
    // 2. Force to disk (critical!)
    file.sync_all()?;
    
    // 3. Atomic rename
    fs::rename(&tmp, path)?;
    
    // 4. Sync directory metadata
    File::open(path.parent().unwrap())?.sync_all()?;
}
```

**Why This Matters**:
Without atomic persistence, a power failure during write could corrupt the counter → index reuse → private key leak!

### `src/vcpf2/` - VCPF-2 Record Layer

**Files**:
- `aead.rs`: ChaCha20-Poly1305 AEAD cipher
- `keys.rs`: HKDF key derivation
- `record.rs`: Record framing and fragmentation
- `protection.rs`: Record encryption/decryption

**Key Derivation**:
```
Master Secret (from VQST handshake)
    │
    ├─ HKDF-Expand("c ap traffic", transcript) → client_write_key
    ├─ HKDF-Expand("s ap traffic", transcript) → server_write_key
    └─ HKDF-Expand("key update", old_key)      → new_key (rekey)
```

**Message Limit**:
After 2³² records (or ~274GB at 64KB/record), the AEAD cipher forces a rekey by returning `RekeyRequired` error. This prevents nonce reuse.

### `src/vqst/` - VQST Handshake Protocol

**Files**:
- `messages.rs`: Handshake message definitions
- `crypto.rs`: TranscriptHash (SHA3-256) and KeySchedule (HKDF)
- `client.rs`: Client state machine
- `server.rs`: Server state machine
- `handshake.rs`: High-level handshake helpers
- `nonce_db.rs`: Replay protection database
- `rate_limit.rs`: DoS protection rate limiter

**Handshake Flow**:
```
Client                                                Server
------                                                ------

ClientHello
  - session_id (32B random)         ──────────────>
  - supported_versions
  - cipher_suites
  
                                    <────────────── ServerHello
                                                      - session_id (echo)
                                                      - cipher_suite
                                                      
                                    <────────────── Certificate
                                                      - cert chain
                                                      
                                    <────────────── CertificateVerify
                                                      - signature over transcript
                                                      
                                    <────────────── Finished
                                                      - HMAC(transcript)
                                                      
                                                    [Server: derive app keys]

Finished                            ──────────────>
  - HMAC(transcript)

[Client: derive app keys]

[Application Data]                 <──────────────>  [Application Data]
```

**Security Checks**:
1. **Replay Protection**: `NonceDatabase` stores seen session_id values
2. **Certificate Validation**: Chain, time, key usage, CRL
3. **Hostname Verification**: SAN/CN matching (mandatory unless `insecure-skip-hostname`)
4. **Finished MAC**: Binds entire transcript to handshake keys

---

## Cryptographic Primitives

### Hash Functions
- **SHA3-256**: Used for all hashing (Lamport, Merkle, transcript)
- **HMAC-SHA3**: Used for Finished MAC

### AEAD Cipher
- **ChaCha20-Poly1305**: Record layer encryption
- **Nonce**: 96-bit counter (incremented per record)

### Key Derivation
- **HKDF-SHA3-256**: RFC 5869 compliant
- **Extract**: HKDF-Extract(salt, IKM) → PRK
- **Expand**: HKDF-Expand(PRK, info, len) → OKM

### Random Number Generation
- **RNG**: `rand::thread_rng()` (uses OS CSPRNG)
- **Zeroization**: `zeroize` crate clears secrets from memory

---

## Protocol Flow

### End-to-End Certificate Issuance

```
1. Generate Root CA:
   RootCA::new("ca_dir", config)
   → Creates SigningKey (VOX-SIG)
   → Self-signs certificate
   → Atomic save to ca_dir/root_ca.key

2. Generate Intermediate CA:
   IntermediateCA::new_from_root(&root_ca, "int_ca_dir", config)
   → Creates IntermediateCA SigningKey
   → Root CA signs Intermediate cert
   → Atomic save to int_ca_dir/intermediate_ca.key

3. Issue Server Certificate:
   issuer.issue_server_certificate(dn, pk, 365, san)
   → Creates cert with KeyUsage::DigitalSignature | KeyAgreement
   → Sets SAN, EKU (serverAuth)
   → Intermediate CA signs
   → Returns Certificate

4. Client Validates Chain:
   validate_chain(&[server_cert, int_cert, root_cert], &trusted_roots, crl_mgr)
   → Check validity period
   → Verify signatures (bottom-up)
   → Check KeyUsage consistency
   → Fail-closed CRL check
```

### End-to-End Handshake

```
1. Client Setup:
   nonce_db = NonceDatabase::new(Duration::from_secs(300))
   crl_mgr = CRLManager::new(root_dn)
   client = Client::new("server.com", nonce_db, crl_mgr)

2. Client Sends Hello:
   client_hello = client.create_client_hello()
   → Generates session_id (32B random)
   → Hashes into transcript
   → Send over network

3. Server Processes Hello:
   server.process_client_hello(&client_hello_bytes)?
   → Check nonce_db (replay protection)
   → Store session_id in nonce_db
   → Generate ServerHello

4. Server Sends Certificate & Finished:
   server_hello = server.create_server_hello()?
   certificate = server.create_certificate()?
   cert_verify = server.create_certificate_verify()?
   finished = server.create_server_finished()?
   → Send all to client

5. Client Validates:
   client.process_server_hello(&server_hello_bytes)?
   client.process_certificate(&cert_bytes)?
   client.process_certificate_verify(&verify_bytes)?
   client.process_server_finished(&finished_bytes)?
   → Validate cert chain (including CRL)
   → Verify hostname (SAN/CN)
   → Check Finished HMAC
   → Derive application keys

6. Client Sends Finished:
   client_finished = client.create_client_finished()?
   → Send to server

7. Server Validates Client Finished:
   server.process_client_finished(&finished_bytes)?
   → Check HMAC
   → Derive application keys
   → Handshake complete!

8. Application Data:
   ciphertext = server.encrypt_record(plaintext)?
   plaintext = client.decrypt_record(ciphertext)?
```

---

## Key Management

### Key Types

1. **VLK-1 KeyPair** (ephemeral):
   - Used for handshake key exchange
   - Generated per-connection
   - Provides forward secrecy

2. **VOX-SIG SigningKey** (long-lived):
   - Used for certificate signatures
   - Stored on disk with atomic persistence
   - **CRITICAL**: Must NEVER reuse counter

3. **Application Keys** (session):
   - Derived from handshake via HKDF
   - Used for record layer AEAD
   - Rekeyed after 2³² records

### Key Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                    Root CA SigningKey                        │
│  - Generated once during CA setup                            │
│  - Stored in ca_dir/root_ca.key (JSON + atomic persistence)  │
│  - Counter tracked for every signature                       │
│  - Valid for validity_days (e.g., 10 years)                  │
│  - Revocation: Issue new Root CA, distribute via trust store │
└─────────────────────────────────────────────────────────────┘
          │ signs
          ▼
┌─────────────────────────────────────────────────────────────┐
│               Intermediate CA SigningKey                     │
│  - Generated per Intermediate CA                             │
│  - Stored in int_ca_dir/intermediate_ca.key                  │
│  - Counter tracked for every signature                       │
│  - Valid for validity_days (e.g., 5 years)                   │
│  - Revocation: Add to CRL, issue new Intermediate            │
└─────────────────────────────────────────────────────────────┘
          │ signs
          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Server Certificate                          │
│  - Generated per server                                      │
│  - Paired with server's VOX-SIG SigningKey                   │
│  - Valid for validity_days (e.g., 1 year)                    │
│  - Revocation: Add to CRL                                    │
└─────────────────────────────────────────────────────────────┘
```

### Session Key Derivation

```
Handshake:
  client_ephemeral_secret + server_ephemeral_pk
    → shared_secret (VLK-1 KEM)
    
  HKDF-Extract(salt=0, IKM=shared_secret)
    → handshake_secret
    
  HKDF-Expand(handshake_secret, "hs derived")
    → master_secret
    
  HKDF-Expand(master_secret, "c ap traffic" || transcript)
    → client_write_key (32B for ChaCha20)
    
  HKDF-Expand(master_secret, "s ap traffic" || transcript)
    → server_write_key (32B for ChaCha20)

Rekey:
  HKDF-Expand(old_key, "key update")
    → new_key
```

---

## Security Design Decisions

### Why Custom Algorithms?

**VLK-1 vs. Kyber**:
- Kyber is a NIST-standard ML-KEM widely deployed in industry.
- VLK-1 is a research Module-LWE KEM used here to explore alternative designs and constant-time implementations.
- VLK-1 is not intended as a drop-in replacement for Kyber, but as an independent design for study and experimentation.

**VOX-SIG vs. Dilithium**:
- Dilithium is NIST standard (ML-DSA) and **stateless**
- VOX-SIG is stateful (requires atomic persistence)
- **Voxfor Choice**: We use VOX-SIG to demonstrate secure state management in high-assurance environments.

### Why Not Hybrid Mode?

Hybrid PQC (classical + quantum) is the industry standard:
- `X25519 + Kyber` for KEMs
- `ECDSA + Dilithium` for signatures

This implementation focuses on pure PQ for simplicity. Hybrid mode is planned but not implemented.

### Why Fail-Closed CRL?

Traditional TLS uses "soft-fail" CRL (if CRL unavailable, proceed anyway). This is vulnerable to:
- DNS attacks (block CRL server)
- Network partitions

We use **fail-closed** (if CRL unavailable, reject cert) for stronger security. Trade-off: availability risk.

### Why No 0-RTT?

0-RTT (zero round-trip time) resumption allows first data packet to be encrypted with resumed keys. Security concerns:
- Replay attacks (0-RTT data is not replay-protected)
- Forward secrecy loss (resumed keys are reused)

We prioritize security over performance for research code.

---

## Performance Characteristics

### Benchmarks (AMD Ryzen 9 5950X, single-core)

| Operation                | Time      | Notes                          |
|--------------------------|-----------|--------------------------------|
| VLK-1 KeyGen             | ~1.2 ms   | Includes NTT computation       |
| VLK-1 Encapsulate        | ~0.5 ms   | NTT + matrix multiplication    |
| VLK-1 Decapsulate        | ~0.7 ms   | NTT + implicit rejection       |
| VOX-SIG Sign             | ~2 ms     | Lamport + Merkle path          |
| VOX-SIG Verify           | ~1.5 ms   | Preimage checks + Merkle       |
| Full Handshake           | ~8 ms     | Including cert validation      |
| Record Encrypt (64KB)    | ~0.3 ms   | ChaCha20-Poly1305              |
| Record Decrypt (64KB)    | ~0.3 ms   | ChaCha20-Poly1305              |

### Memory Usage

| Component                | Size      |
|--------------------------|-----------|
| VLK-1 PublicKey          | ~12 KB    |
| VLK-1 SecretKey          | ~4 KB     |
| VOX-SIG SigningKey       | ~65 KB    |
| VOX-SIG VerifyingKey     | ~32 B     |
| VOX-SIG Signature        | ~17 KB    |
| Certificate (typical)    | ~19 KB    |

---

## Future Improvements

### Planned Features
1. **Persistent Nonce DB**: Redis/PostgreSQL backend
3. **Async/Tokio Integration**: `async` feature flag
4. **Session Resumption**: PSK-based 0-RTT (with replay protection)
5. **Hardware Acceleration**: AVX2/NEON for NTT

### Research Directions
1. **Formal Verification**: Use Verus or HACL* for NTT
2. **Side-Channel Hardening**: Power analysis testing
3. **Post-Quantum Auth**: Combine with MPC for distributed signing
4. **Quantum-Resistant DNSSEC**: Integrate with QX509 PKI

---

**Last Updated**: December 2025  
**Architect & Author**: Netanel Siboni (voxfor.com)

