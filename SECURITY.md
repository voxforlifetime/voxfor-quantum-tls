# Security Policy

## Overview

Voxfor Quantum TLS is a research implementation of a post-quantum TLS protocol stack. This document outlines the security model, known vulnerabilities, and responsible disclosure policy.

Current Status: NOT PRODUCTION READY

## Threat Model

### Assumptions

1. Adversary Capabilities:
   - Can intercept, modify, replay network traffic (active MITM)
   - Has access to quantum computers (breaks RSA, ECDH, ECDSA)
   - Cannot break SHA3-256 or ChaCha20-Poly1305
   - Cannot break Module-LWE with our parameters

2. Trusted Components:
   - Local filesystem (for atomic key persistence)
   - System RNG (`rand` crate using OS CSPRNG)
   - Rust standard library cryptographic primitives

3. Out of Scope:
   - Physical attacks (side-channel, fault injection, DPA)
   - Social engineering or phishing
   - Malware on client/server systems
   - Supply chain attacks on dependencies

### Security Goals

 - Confidentiality: Forward secrecy via ephemeral VLK-1 KEM  
 - Authenticity: VOX-SIG signatures bind certificates to entities  
 - Integrity: ChaCha20-Poly1305 AEAD protects record layer  
 - Replay Protection: Nonce database prevents handshake replays  
 - Revocation: CRL checking prevents use of compromised certificates  

 Session Resumption: Not implemented (0-RTT not supported)  
 Distributed Deployment: Stateful signatures and in-memory nonces are single-server only  

---

## Known Security Issues

### CRITICAL: Stateful Signature Index Management

Component: `voxsig` (VOX-SIG signatures)

Problem: 
VOX-SIG uses Lamport one-time signatures, where each signature MUST use a unique index. Reusing an index even once leaks the private key completely.

Attack Scenario:
```
1. Server signs message M1 with index 42 → reveals keys for bits where M1[i]=1
2. Server crashes and restarts → counter resets to 0
3. Server signs message M2 with index 42 → reveals keys for bits where M2[i]=1
4. Attacker now has BOTH keys for bits where M1 ≠ M2 → can forge any signature!
```

Mitigations in Code:
- `SafeSigner` provides atomic persistence (write → fsync → rename)
- `RootCA` and `IntermediateCA` use atomic counter persistence
- 150+ lines of inline documentation warn developers

Why Still Vulnerable:
- Does NOT protect against VM snapshot rollback
- Does NOT work in load-balanced deployments (multiple servers)
- Does NOT survive distributed signing scenarios

Recommended Fix:
Use the provided `SafeSigner` wrapper which enforces atomic persistence, or implement a similar mechanism ensuring the counter is never rolled back.

Severity: CRITICAL (private key compromise)  
CVSS: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  

---

### CRITICAL: In-Memory Replay Protection

Component: `vqst::NonceDatabase`

Problem:
Nonce database stores seen nonces in memory only. In multi-server deployments, an attacker can replay a handshake to a different server.

Attack Scenario:
```
1. Client connects to Server A → nonce X stored in Server A's memory
2. Attacker captures handshake
3. Attacker replays handshake to Server B → Server B accepts (never saw nonce X)
4. Replay attack succeeds!
```

Mitigations in Code:
- 50+ lines of inline documentation warn about the limitation
- Feature flag `persistent-nonce-db` exists (not yet implemented)

Why Still Vulnerable:
- Any load-balanced deployment without sticky sessions is vulnerable
- Server restart → all nonces forgotten
- HA/failover → replay across instances

Recommended Fix:
- Use shared Redis/Memcached for nonce storage
- Or implement PostgreSQL-backed nonce tracking
- Or enforce sticky sessions at load balancer (not recommended)

Severity: HIGH (replay attacks)  
CVSS: 7.5 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N  

---

### MEDIUM: No Independent Third-Party Security Audit

Problem:
This codebase has not yet undergone external security review by professional cryptographers or certified auditors.
It **does** include extensive internal QA, unit tests, integration tests, and real end‑to‑end client/server runs,
but no formal third‑party audit has been completed.

Why It Matters:
- Cryptographic implementations are notoriously difficult to get right
- Constant-time code can have subtle timing leaks
- Side-channel attacks may exist despite mitigation efforts

Recommended Action:
Before production use, commission an independent audit by:
- Trail of Bits
- NCC Group
- Kudelski Security
- Quarkslab

Severity: MEDIUM (unknown unknowns)

---

### MEDIUM: Large Signature Size

Component: `voxsig`

Problem:
VOX-SIG signatures are ~17KB (larger than many NIST PQ signatures, typically ~2.5KB).

Impact:
- Increased bandwidth usage
- Slower handshakes over low-bandwidth links
- Potential DoS vector (certificate chains with many signatures)

Mitigation:
- 10MB certificate size limit in PEM/DER parser
- This is a design trade-off, not a bug

Severity: LOW (performance/DoS concern)

---

## Security Features (What's Done Right)

### Constant-Time Operations

Where: `vlk1/ntt.rs`, `vlk1/poly.rs`, `vqst/crypto.rs`

- Branchless Barrett reduction
- Branchless centered reduction
- Constant-time MAC verification using `subtle::ConstantTimeEq`
- CBD sampling for secret polynomials

Testing: Manual code review, but no formal timing analysis yet.

### Implicit Rejection (KEM)

Where: `vlk1/kem.rs`

On decapsulation failure, return a random shared secret (derived from ciphertext hash) instead of an error. Prevents timing attacks that distinguish valid/invalid ciphertexts.

### Fail-Closed Validation

Where: `qx509/chain_validator.rs`, `vqst/client.rs`

- Certificate validation fails if CRL is unavailable (no bypass)
- Hostname verification is mandatory (no `insecure-skip-hostname` in production)
- No `Option<NonceDatabase>` - replay protection is mandatory

### DoS Hardening

Where: `qx509/pem_der.rs`, `vqst/rate_limit.rs`

- Integer overflow protection in DER length parsing
- 10MB certificate size limit
- Rate limiter for connection attempts (IP-based)

### Memory Safety

Language: Rust with `#![deny(unsafe_code)]`

- No use-after-free, buffer overflows, or double-free bugs
- Automatic memory cleanup with `zeroize` for secrets

---

## Reporting Security Vulnerabilities

If you discover a security vulnerability in Voxfor Quantum TLS:

### DO NOT:
- Open a public GitHub issue
- Discuss the vulnerability publicly before a fix is available
- Exploit the vulnerability maliciously

### DO:
1. Email: Send details to `admin@voxfor.com` (if this project becomes public)
2. Include:
   - Vulnerability description
   - Steps to reproduce
   - Proof-of-concept (if safe to share)
   - Suggested fix (optional)
3. Response Time: We aim to respond within 72 hours
4. Disclosure Timeline: 90 days from report to public disclosure (negotiable)


### Recommended Tests

1. Timing Attack Testing:
   ```bash
   # Use dudect or ctgrind to verify constant-time operations
   cargo test --release --features timing-tests
   ```

2. Fuzzing:
   ```bash
   # Fuzz PEM/DER parser
   cargo fuzz run pem_parser
   
   # Fuzz handshake messages
   cargo fuzz run vqst_messages
   ```

3. Side-Channel Analysis:
   - Use ChipWhisperer or similar for power analysis
   - Test on real hardware (not just emulators)

4. Formal Verification:
   - Consider Verus, Prusti, or HACL* for NTT implementation
   - Model protocol in Tamarin or ProVerif

### Current Test Coverage

- Unit Tests: 100+ tests across all modules
- Integration Tests: Handshake round-trips, certificate chains
- Property Tests: NTT correctness, compression idempotency
- Negative Tests: Tampered signatures, expired certificates, replay attacks

---



## Mathematical Foundations

For detailed cryptographic theory including:
- Quantum computing threat model (Shor's algorithm, Grover's algorithm)
- Module-LWE hardness proofs and security reductions
- Number Theoretic Transform (NTT) mathematical foundations
- Lamport signature security proofs
- Fujisaki-Okamoto transform (IND-CPA → IND-CCA2)
- Parameter selection and security analysis

See [CRYPTOGRAPHIC_THEORY.md](CRYPTOGRAPHIC_THEORY.md).

## References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Lamport Signatures](https://en.wikipedia.org/wiki/Lamport_signature)
- [Module-LWE Security](https://eprint.iacr.org/2015/1092)
- [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
- [Fujisaki-Okamoto Transform](https://eprint.iacr.org/1999/003)

---

Last Updated: December 2025  
Version: 1.0.0  
Author: Netanel Siboni (voxfor.com)

