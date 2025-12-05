//! VQST Handshake Messages

use serde::{Serialize, Deserialize};
use crate::{vlk1, voxsig, qx509};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    KeyUpdate(KeyUpdate),  // TLS 1.3 KeyUpdate for long-lived connections
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub key_share: Vec<u8>, // VLK-1 public key
    pub timestamp: i64,      // Unix timestamp (milliseconds) - replay protection
}

impl ClientHello {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("ClientHello serialization failed: {}", e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub key_share: Vec<u8>, // VLK-1 public key (server's PK)
    pub kem_ciphertext: Vec<u8>, // VLK-1 ciphertext (server encapsulates to client's PK)
    pub timestamp: i64,      // Server timestamp for replay protection
}

impl ServerHello {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("ServerHello serialization failed: {}", e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate_chain: Vec<Vec<u8>>,
}

impl Certificate {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("Certificate serialization failed: {}", e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateVerify {
    pub signature: Vec<u8>, // VOX-SIG signature
}

impl CertificateVerify {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("CertificateVerify serialization failed: {}", e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finished {
    pub verify_data: Vec<u8>, // HMAC of transcript
}

impl Finished {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("Finished serialization failed: {}", e))
    }
}

/// TLS 1.3 KeyUpdate message
/// 
/// Allows updating encryption keys mid-connection without full handshake.
/// Used for:
/// - Long-lived connections approaching AEAD sequence number limit
/// - Perfect forward secrecy (periodic key rotation)
/// - Post-compromise security (recover from key leakage)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyUpdate {
    /// Whether peer should also update their keys
    pub update_requested: KeyUpdateRequest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyUpdateRequest {
    /// Update my keys, peer doesn't need to respond
    UpdateNotRequested = 0,
    /// Update my keys AND request peer to update theirs
    UpdateRequested = 1,
}

impl KeyUpdate {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("KeyUpdate serialization failed: {}", e))
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("KeyUpdate deserialization failed: {}", e))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CipherSuite {
    VLK1_VOXSIG_CHACHA20_SHA3,
}

impl HandshakeMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("HandshakeMessage serialization failed: {}", e))
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("HandshakeMessage deserialization failed: {}", e))
    }
}
