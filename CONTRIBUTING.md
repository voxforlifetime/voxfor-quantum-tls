# Contributing to Voxfor Quantum TLS

Thank you for considering contributing to this research project! This document provides guidelines for contributions.

## Project Status

This is a research implementation of post-quantum TLS. Contributions are welcome, but please understand:
- This is NOT production-ready (see `SECURITY.md` for critical issues)
- Major architectural changes require discussion first
- Security fixes take priority over features

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template (if available)
3. Include:
   - Rust version (`rustc --version`)
   - OS and architecture
   - Steps to reproduce
   - Expected vs. actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Explain the use case (why is this needed?)
3. Consider security implications (does this weaken the protocol?)
4. Be patient - major features require design review

### Pull Requests

#### Before You Start

1. Open an issue to discuss major changes
2. Check the roadmap in `SECURITY.md` (avoid duplicate work)
3. Read the architecture in `ARCHITECTURE.md`

#### PR Guidelines

DO:
- Write tests for new code (aim for >80% coverage)
- Update documentation (inline comments + relevant `.md` files)
- Follow Rust conventions (`cargo fmt`, `cargo clippy`)
- Add security notes for crypto code
- Keep PRs focused (one feature/fix per PR)
- Include benchmark results for performance changes

DO NOT:
- Introduce `unsafe` code without extensive justification
- Weaken security checks (remove validation, bypass CRL, etc.)
- Remove or downplay security warnings in documentation
- Submit untested code
- Make breaking API changes without discussion

#### PR Process

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Make changes with clear, atomic commits
4. Test: `cargo test`, `cargo clippy`, `cargo fmt --check`
5. Push: `git push origin feature/my-feature`
6. Open PR with a clear description:
   - What problem does this solve?
   - How does it work?
   - Any security implications?
   - Test results

#### Review Process

- Maintainers will review within 1 week
- Security-sensitive PRs may require external review
- Expect requests for changes (don't take it personally!)
- Once approved, maintainer will merge

## Code Style

### Rust Conventions

```rust
// Good: Clear, documented, safe
/// Encrypts application data using ChaCha20-Poly1305.
///
/// # Security
/// 
/// This function MUST NOT be called more than 2^32 times with the same key.
/// After reaching the limit, `RekeyRequired` is returned.
pub fn encrypt_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
    if self.seq_num >= MAX_SEQ_NUM {
        return Err(RecordError::RekeyRequired);
    }
    // ... implementation ...
}

// Bad: No documentation, unclear error handling
pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
    // ... implementation ...
}
```

### Security-Critical Code

For crypto implementations:

1. Document security properties:
   ```rust
   /// Constant-time Barrett reduction.
   ///
   /// # Security
   ///
   /// Uses branchless operations to avoid timing side-channels.
   /// DO NOT modify this function without consulting a cryptographer.
   ```

2. Add tests:
   ```rust
   #[test]
   fn test_barrett_reduce_bounds() {
       for input in 0..10_000 {
           let result = barrett_reduce(input);
           assert!(result >= 0 && result < Q);
       }
   }
   ```

3. Benchmark if performance-critical:
   ```rust
   #[bench]
   fn bench_ntt(b: &mut Bencher) {
       let mut a = [0i32; N];
       b.iter(|| ntt(&mut a));
   }
   ```

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test --lib vlk1::tests

# With logging
RUST_LOG=debug cargo test

# Benchmarks
cargo bench
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_correctness() {
        let keypair = KeyPair::generate();
        let (ct, ss1) = encapsulate(keypair.public_key()).unwrap();
        let ss2 = decapsulate(&ct, keypair.secret_key()).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kem_wrong_key() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let (ct, _ss1) = encapsulate(keypair1.public_key()).unwrap();
        let ss2 = decapsulate(&ct, keypair2.secret_key()).unwrap();
        // Implicit rejection: should succeed but with different secret
        assert_ne!(_ss1.as_bytes(), ss2.as_bytes());
    }
}
```

## Documentation

### Inline Comments

```rust
// Good: Explains WHY, not just WHAT
// Use Merkle tree domain separation to prevent length extension attacks.
// Each level uses a distinct tag: "merkle_node" || level_index
let tag = format!("merkle_node{}", level);

// Bad: States the obvious
// Hash the left and right nodes
let hash = hasher.hash(&[left, right]);
```

### Module-Level Documentation

Every module should have:
- Purpose and scope
- Security properties (if crypto-related)
- Usage examples
- Known limitations

Example:
```rust
//! # VOX-SIG Signature Verification
//!
//! Verifies VOX-SIG signatures with full preimage checks.
//!
//! ## Security
//!
//! - Verifies Hash(revealed_key) == expected_pk_hash[bit]
//! - Checks lamport_pk_compressed == Hash(lamport_pk_full)
//! - Validates Merkle path to root
//!
//! ## Example
//!
//! ```rust
//! let result = verify(&verifying_key, message, &signature);
//! assert!(result.is_ok());
//! ```
```

## Priorities

### High Priority (Always Welcome)

1. Security fixes* (timing leaks, validation bypasses)
2. Test coverage improvements
3. Documentation clarity
4. Bug fixes with regression tests

### Medium Priority (Discuss First)

1. Performance optimizations (with benchmarks)
2. New features (aligned with roadmap)
3. API improvements (backward compatibility matters)

### Low Priority (Future Work)

1. Experimental features (hardware accel, hybrid mode)
2. Platform-specific code (embedded, WASM)
3. Tooling (fuzzing, formal verification)

## Getting Help

- Documentation: Start with `ARCHITECTURE.md`, `SECURITY.md`, `CRYPTOGRAPHIC_THEORY.md`
- Code Questions: Open a GitHub issue with the `question` label
- Security Questions: Email `admin@voxfor.com` (for private disclosures)
- Community: (Forum/Discord link if established)

## License

By contributing, you agree that your contributions will be licensed under the MIT License (same as the project).

---

Thank you for helping make post-quantum TLS safer and more accessible! 🚀🔐

