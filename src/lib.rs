//! Voxfor Quantum-Resistant TLS/SSL Library
//! 
//! Copyright (c) 2025 Netanel Siboni (voxfor.com). All rights reserved.
//!
//! A complete, production-grade implementation of quantum-resistant TLS/SSL.
//! 
//! # Features
//! 
//! - **VLK-1**: Quantum-resistant key exchange (Module-LWE based)
//! - **VOX-SIG**: Quantum-resistant signatures (Hash-based)
//! - **QX509**: Quantum-resistant certificates
//! - **VQST**: Full TLS 1.3-like handshake protocol
//! - **VCPF-2**: Encrypted record layer with AEAD
//! 
//! # Security
//! 
//! - ~128-bit post-quantum security
//! - Constant-time operations
//! - Side-channel resistant
//! - Forward secrecy
//! 
//! # Example
//! 
//! ```rust,no_run
//! use voxfor_quantum_tls::vlk1::KeyPair;
//! 
//! // Generate quantum-resistant keys
//! let keypair = KeyPair::generate();
//! 
//! // Use in TLS handshake...
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod vlk1;
pub mod voxsig;
pub mod qx509;
pub mod ca;
pub mod vcpf2;
pub mod vqst;

pub mod error;
pub mod utils;

pub use error::Error;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if running in production mode
pub fn is_production() -> bool {
    cfg!(not(debug_assertions))
}
