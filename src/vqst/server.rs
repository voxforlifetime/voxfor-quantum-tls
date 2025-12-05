//! VQST Server Implementation

use super::messages::*;
use super::crypto::*;
use super::nonce_db::NonceDatabase;
use crate::{vlk1, voxsig, qx509};
use rand::RngCore;
use std::sync::Arc;

pub enum ServerState {
    Start,
    WaitClientHello,
    WaitFinished,
    Connected,
}

/// VQST Server
/// 
/// # Security Fix: Nonce Database Now Mandatory
/// 
/// **Previous vulnerability**: `nonce_db` was `Option`, allowing bypass of replay protection.
/// **Fix**: Now required in constructor.
pub struct Server {
    state: ServerState,
    server_random: [u8; 32],
    client_random: Option<[u8; 32]>,
    vlk1_keypair: vlk1::KeyPair,
    certificate: Vec<u8>,
    signing_key: voxsig::keygen::SigningKey,
    transcript: TranscriptHash,
    key_schedule: KeySchedule,
    nonce_db: Arc<NonceDatabase>,  // ✅ No Option! Always required
}

impl Server {
    /// Create new server with mandatory nonce database
    /// 
    /// # Parameters
    /// - `certificate`: Server certificate chain (DER encoded)
    /// - `signing_key`: VOX-SIG signing key for CertificateVerify
    /// - `nonce_db`: Shared nonce database for replay protection (REQUIRED)
    pub fn new(
        certificate: Vec<u8>, 
        signing_key: voxsig::keygen::SigningKey,
        nonce_db: Arc<NonceDatabase>,  // ✅ NEW required parameter
    ) -> Self {
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);
        
        Self {
            state: ServerState::WaitClientHello,
            server_random,
            client_random: None,
            vlk1_keypair: vlk1::KeyPair::generate(),
            certificate,
            signing_key,
            transcript: TranscriptHash::new(),
            key_schedule: KeySchedule::new(),
            nonce_db,  // ✅ Required
        }
    }
    
    // ✅ SECURITY FIX: Removed set_nonce_database()
    // Nonce DB is now mandatory in constructor
    
    pub fn process_client_hello(&mut self, hello: ClientHello) -> Result<ServerHello, String> {
        self.client_random = Some(hello.random);
        
        // Replay protection: Check timestamp freshness
        // Reduced from 60s to 10s based on security audit
        let now = chrono::Utc::now().timestamp_millis();
        let age_ms = (now - hello.timestamp).abs();
        const MAX_AGE_MS: i64 = 10_000; // 10 seconds tolerance (reduced from 60s)
        
        if age_ms > MAX_AGE_MS {
            return Err(format!("ClientHello timestamp too old: {}ms (max {}ms)", age_ms, MAX_AGE_MS));
        }
        
        // ✅ SECURITY FIX: Nonce database check (ALWAYS enforced, no bypass possible)
        // Check client_random for replay - MANDATORY
        self.nonce_db.check_and_store(&hello.random)
            .map_err(|e| format!("Replay protection failed: {}", e))?;
        
        let hello_bytes = hello.to_bytes()
            .map_err(|e| format!("Failed to serialize ClientHello: {}", e))?;
        self.transcript.update(&hello_bytes);
        
        // Parse client's VLK-1 public key
        let client_pk = vlk1::keygen::PublicKey::from_bytes(&hello.key_share)
            .map_err(|e| format!("Invalid key: {:?}", e))?;
        
        // Perform key exchange: Server encapsulates to client's PK
        let (ciphertext, shared_secret) = vlk1::encapsulate(&client_pk)
            .map_err(|e| format!("KEM failed: {:?}", e))?;
        
        let timestamp = chrono::Utc::now().timestamp_millis();
        
        let response = ServerHello {
            random: self.server_random,
            session_id: hello.session_id,
            cipher_suite: CipherSuite::VLK1_VOXSIG_CHACHA20_SHA3,
            key_share: self.vlk1_keypair.public_key().as_bytes(),
            kem_ciphertext: ciphertext.to_bytes(),
            timestamp,
        };
        
        let response_bytes = response.to_bytes()
            .map_err(|e| format!("Failed to serialize ServerHello: {}", e))?;
        self.transcript.update(&response_bytes);
        self.key_schedule.derive_handshake_secret(shared_secret.as_bytes());
        
        Ok(response)
    }
    
    pub fn create_certificate(&mut self) -> Result<Certificate, String> {
        let cert = Certificate {
            certificate_chain: vec![self.certificate.clone()],
        };
        
        // Update transcript with certificate
        let cert_bytes = cert.to_bytes()
            .map_err(|e| format!("Failed to serialize Certificate: {}", e))?;
        self.transcript.update(&cert_bytes);
        
        Ok(cert)
    }
    
    /// Create CertificateVerify message: sign the transcript hash
    /// This proves the server possesses the private key for its certificate
    pub fn create_certificate_verify(&mut self) -> Result<CertificateVerify, String> {
        // Get transcript hash up to this point
        let transcript_hash = self.transcript.current_hash();
        
        // Sign the transcript with VOX-SIG
        let signature = voxsig::sign(&mut self.signing_key, &transcript_hash)
            .map_err(|e| format!("Failed to sign transcript: {:?}", e))?;
        
        let cert_verify = CertificateVerify {
            signature: signature.to_bytes(),
        };
        
        // Update transcript with CertificateVerify
        let verify_bytes = cert_verify.to_bytes()
            .map_err(|e| format!("Failed to serialize CertificateVerify: {}", e))?;
        self.transcript.update(&verify_bytes);
        
        Ok(cert_verify)
    }
    
    pub fn create_finished(&mut self) -> Result<Finished, String> {
        let transcript_hash = self.transcript.finalize();
        let handshake_secret = self.key_schedule.handshake_secret();
        
        eprintln!("[SERVER] create_finished:");
        eprintln!("  handshake_secret: {:?}", &handshake_secret[..8]);
        eprintln!("  transcript_hash: {:?}", &transcript_hash[..8]);
        
        let verify_data = compute_finished(handshake_secret, &transcript_hash);
        eprintln!("  verify_data: {:?}", &verify_data[..8]);
        
        let finished = Finished { verify_data };
        
        // ✅ CRITICAL: Update transcript with Server Finished!
        // This is needed so that client and server have the same transcript
        // when client computes its Finished message
        let finished_bytes = finished.to_bytes()
            .map_err(|e| format!("Failed to serialize Server Finished: {}", e))?;
        self.transcript.update(&finished_bytes);
        
        Ok(finished)
    }
    
    /// ✅ SECURITY FIX: Process and verify client's Finished message
    /// 
    /// **CRITICAL**: This function was MISSING in the original implementation!
    /// 
    /// Verifies that the client has the same view of the handshake transcript
    /// by checking the client's Finished MAC.
    /// 
    /// # TLS 1.3 Mutual Finished
    /// 
    /// Both client and server send Finished messages:
    /// 1. Server sends Finished first (after CertificateVerify)
    /// 2. Client verifies server's Finished, then sends its own
    /// 3. Server verifies client's Finished ← **THIS FUNCTION**
    /// 
    /// Without mutual Finished verification, the handshake is incomplete!
    pub fn process_client_finished(&mut self, finished: &Finished) -> Result<(), String> {
        // Get handshake secret
        let handshake_secret = self.key_schedule.handshake_secret();
        
        // Compute transcript hash (includes all messages up to client's Finished)
        let transcript_hash = self.transcript.finalize();
        
        eprintln!("[SERVER] process_client_finished:");
        eprintln!("  handshake_secret: {:?}", &handshake_secret[..8]);
        eprintln!("  transcript_hash: {:?}", &transcript_hash[..8]);
        eprintln!("  received verify_data: {:?}", &finished.verify_data[..8]);
        
        // Compute expected
        let expected = super::crypto::compute_finished(handshake_secret, &transcript_hash);
        eprintln!("  expected verify_data: {:?}", &expected[..8]);
        
        // ✅ CRITICAL: Verify client's Finished MAC
        if !verify_finished(handshake_secret, &transcript_hash, &finished.verify_data) {
            eprintln!("[SERVER] ❌ Client Finished verification FAILED!");
            return Err("Client Finished verification failed! Possible MITM attack!".to_string());
        }
        
        eprintln!("[SERVER] ✅ Client Finished verification PASSED!");
        
        // Update transcript with client's Finished
        let finished_bytes = finished.to_bytes()
            .map_err(|e| format!("Failed to serialize client Finished: {}", e))?;
        self.transcript.update(&finished_bytes);
        
        Ok(())
    }
    
    /// Encrypt application data using ChaCha20-Poly1305 AEAD
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, AeadCore},
            ChaCha20Poly1305, Nonce
        };
        use rand::rngs::OsRng;
        
        // Derive application write key (server writes, client reads)
        let app_key = self.key_schedule.derive_application_key(b"server_write");
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&app_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        // Generate random nonce (96 bits = 12 bytes)
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        // Encrypt with AEAD
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Prepend nonce to ciphertext (nonce is public)
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt application data using ChaCha20-Poly1305 AEAD
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce
        };
        
        // Check minimum length (nonce + tag)
        if data.len() < 12 + 16 {
            return Err("Ciphertext too short".to_string());
        }
        
        // Derive application read key (client writes, server reads)
        let app_key = self.key_schedule.derive_application_key(b"client_write");
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&app_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        
        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt with AEAD (automatically verifies authentication tag)
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed (possible tampering): {}", e))?;
        
        Ok(plaintext)
    }
}
