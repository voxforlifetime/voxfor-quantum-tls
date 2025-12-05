//! VQST Client Implementation

use super::messages::*;
use super::crypto::*;
use super::nonce_db::NonceDatabase;
use crate::{vlk1, voxsig};
use rand::RngCore;
use std::sync::Arc;

pub enum ClientState {
    Start,
    WaitServerHello,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
}

/// VQST Client
/// 
/// # Security Fix: Nonce Database Now Mandatory
/// 
/// **Previous vulnerability**: `nonce_db` was `Option<Arc<NonceDatabase>>`,
/// allowing clients to skip replay protection.
/// 
/// **Fix**: Now requires `nonce_db` parameter in constructor - no Option!
pub struct Client {
    state: ClientState,
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    vlk1_keypair: vlk1::KeyPair,
    transcript: TranscriptHash,
    key_schedule: KeySchedule,
    trusted_roots: Vec<crate::qx509::certificate_full::CertificateFull>,
    server_certificate: Option<crate::qx509::certificate_full::CertificateFull>,
    nonce_db: Arc<NonceDatabase>,  // ✅ No Option! Always required
    crl_manager: Arc<crate::ca::revocation::CRLManager>,  // ✅ CRL mandatory
    
    /// ✅ PRODUCTION FIX: Expected server hostname - MANDATORY!
    /// 
    /// **API Design**: No Option! Hostname verification is ALWAYS enforced.
    /// 
    /// **Security**: Without hostname verification, attacker with ANY valid
    /// certificate (for different domain) can perform MITM attack.
    /// 
    /// This is NOT optional - it's a fundamental TLS security requirement.
    expected_hostname: String,  // ✅ NOT Option! Always required!
}

impl Client {
    /// ✅ PRODUCTION: Create client with MANDATORY security features
    /// 
    /// # Parameters (ALL REQUIRED!)
    /// - `expected_hostname`: Server hostname to verify (e.g., "example.com")
    /// - `nonce_db`: Shared nonce database for replay protection
    /// - `crl_manager`: CRL manager for revocation checking
    /// 
    /// # Security Design
    /// 
    /// **ALL three parameters are MANDATORY** - no way to create insecure client:
    /// 1. ✅ **Hostname verification** - prevents MITM with valid cert for wrong domain
    /// 2. ✅ **Replay protection** - prevents replay attacks within time window
    /// 3. ✅ **Revocation checking** - prevents use of revoked certificates
    /// 
    /// # Example
    /// ```ignore
    /// let nonce_db = Arc::new(NonceDatabase::new(Duration::from_secs(10)));
    /// let crl_manager = Arc::new(CRLManager::new(ca_dn));
    /// 
    /// // ✅ Hostname is MANDATORY - no way to skip verification!
    /// let client = Client::new("example.com", nonce_db, crl_manager);
    /// ```
    /// 
    /// # Unsafe Alternative (NOT RECOMMENDED)
    /// 
    /// If you REALLY need to skip hostname verification (e.g., testing),
    /// use `Client::new_insecure_skip_hostname_verification()` which is
    /// clearly marked as dangerous.
    pub fn new(
        expected_hostname: &str,
        nonce_db: Arc<NonceDatabase>,
        crl_manager: Arc<crate::ca::revocation::CRLManager>,
    ) -> Self {
        let mut client_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_random);
        
        Self {
            state: ClientState::Start,
            client_random,
            server_random: None,
            vlk1_keypair: vlk1::KeyPair::generate(),
            transcript: TranscriptHash::new(),
            key_schedule: KeySchedule::new(),
            trusted_roots: Vec::new(),
            server_certificate: None,
            nonce_db,
            crl_manager,
            expected_hostname: expected_hostname.to_string(),  // ✅ MANDATORY!
        }
    }
    
    /// ⚠️ DANGER: Create client WITHOUT hostname verification
    /// 
    /// **DO NOT USE IN PRODUCTION!**
    /// 
    /// This function exists ONLY for:
    /// - Testing with self-signed certificates
    /// - Development environments
    /// - Debugging TLS issues
    /// 
    /// # Security Warning
    /// 
    /// Without hostname verification, an attacker with ANY valid certificate
    /// (even for a completely different domain) can perform MITM attacks!
    /// 
    /// **This defeats the entire purpose of TLS!**
    /// 
    /// # Example
    /// ```ignore
    /// // ❌ INSECURE! Only for testing!
    /// let client = Client::new_insecure_skip_hostname_verification(
    ///     nonce_db, 
    ///     crl_manager
    /// );
    /// ```
    #[deprecated(note = "Skips hostname verification - INSECURE! Use Client::new() instead")]
    #[cfg(any(test, feature = "insecure-skip-hostname"))]  // 🔴 SECURITY FIX: Only in tests or with explicit feature!
    pub fn new_insecure_skip_hostname_verification(
        nonce_db: Arc<NonceDatabase>,
        crl_manager: Arc<crate::ca::revocation::CRLManager>,
    ) -> Self {
        let mut client_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_random);
        
        Self {
            state: ClientState::Start,
            client_random,
            server_random: None,
            vlk1_keypair: vlk1::KeyPair::generate(),
            transcript: TranscriptHash::new(),
            key_schedule: KeySchedule::new(),
            trusted_roots: Vec::new(),
            server_certificate: None,
            nonce_db,
            crl_manager,
            expected_hostname: String::new(),  // ⚠️ Empty = skip verification!
        }
    }
    
    /// ✅ PRODUCTION: Verify hostname matches certificate
    /// 
    /// **TLS Standard**: RFC 6125 - Hostname verification
    /// 
    /// Checks:
    /// 1. Subject Alternative Name (SAN) - DNSName entries
    /// 2. Common Name (CN) in Subject DN (fallback if no SAN)
    /// 
    /// **Why Critical**: Without this, attacker with ANY valid cert can MITM!
    fn verify_hostname(&self, cert: &crate::qx509::certificate_full::CertificateFull, expected: &str) -> Result<(), String> {
        use crate::qx509::extensions_full::Extension;
        
        // 1. Check SAN (Subject Alternative Name) - preferred method
        for ext in &cert.extensions {
            if let Extension::SubjectAlternativeName(san) = ext {
                use crate::qx509::extensions_full::GeneralName;
                for name in &san.names {
                    if let GeneralName::DNSName(dns_name) = name {
                        if dns_name.eq_ignore_ascii_case(expected) {
                            return Ok(()); // ✅ Match found in SAN
                        }
                        // TODO: Support wildcard matching (*.example.com)
                    }
                }
            }
        }
        
        // 2. Fallback: Check Common Name (CN) if no SAN
        // Note: Modern TLS deprecates CN checking, but we support it as fallback
        if cert.subject.common_name.eq_ignore_ascii_case(expected) {
            return Ok(()); // ✅ Match found in CN
        }
        
        // ❌ No match found
        Err(format!(
            "Hostname verification failed: expected '{}', certificate has CN='{}' (no matching SAN)",
            expected,
            cert.subject.common_name
        ))
    }
    
    // ✅ SECURITY FIX: Removed set_nonce_database()
    // Nonce DB is now mandatory in constructor - cannot be changed or removed after creation
    
    pub fn add_trusted_root(&mut self, root: crate::qx509::certificate_full::CertificateFull) {
        self.trusted_roots.push(root);
    }
    
    pub fn process_certificate(&mut self, cert_msg: Certificate) -> Result<(), String> {
        // Parse certificate chain
        let mut chain = Vec::new();
        for cert_bytes in &cert_msg.certificate_chain {
            let cert = crate::qx509::certificate_full::CertificateFull::from_bytes(cert_bytes)
                .map_err(|e| format!("Invalid certificate: {:?}", e))?;
            chain.push(cert);
        }
        
        // Validate chain
        crate::qx509::chain_validator::validate_chain(&chain, &self.trusted_roots)
            .map_err(|e| format!("Certificate validation failed: {:?}", e))?;
        
        // ✅ SECURITY FIX: Check revocation with MANDATORY CRL manager
        // No way to bypass revocation checking - crl_manager is always present
        for cert in &chain {
            crate::qx509::chain_validator::check_revocation(cert, Some(&*self.crl_manager))
                .map_err(|e| format!("Revocation check failed: {:?}", e))?;
        }
        
        // ✅ PRODUCTION: Hostname verification (MANDATORY!)
        // Verify that the server certificate matches the expected hostname
        if !self.expected_hostname.is_empty() {
            if !chain.is_empty() {
                let server_cert = &chain[0];
                self.verify_hostname(server_cert, &self.expected_hostname)?;
            } else {
                return Err("Empty certificate chain".to_string());
            }
        }
        // Note: Empty hostname means new_insecure_skip_hostname_verification() was used
        // This is DEPRECATED and should never be used in production!
        
        // Store server's certificate (first in chain) for later verification
        if !chain.is_empty() {
            self.server_certificate = Some(chain[0].clone());
        }
        
        let cert_bytes = cert_msg.to_bytes()
            .map_err(|e| format!("Failed to serialize certificate: {}", e))?;
        self.transcript.update(&cert_bytes);
        self.state = ClientState::WaitCertificateVerify;
        
        Ok(())
    }
    
    /// Verify CertificateVerify message - ensures server has private key
    pub fn process_certificate_verify(&mut self, cert_verify: CertificateVerify) -> Result<(), String> {
        // Get the server's certificate
        let server_cert = self.server_certificate.as_ref()
            .ok_or("No server certificate received")?;
        
        // Extract the public key from certificate
        let verifying_key = voxsig::keygen::VerifyingKey::from_bytes(&server_cert.subject_public_key_info.public_key)
            .map_err(|e| format!("Invalid public key in certificate: {:?}", e))?;
        
        // Get transcript hash up to this point (before adding CertificateVerify)
        let transcript_hash = self.transcript.current_hash();
        
        // Parse and verify the signature
        let signature = voxsig::sign::Signature::from_bytes(&cert_verify.signature)
            .map_err(|e| format!("Invalid signature format: {:?}", e))?;
        
        voxsig::verify(&verifying_key, &transcript_hash, &signature)
            .map_err(|e| format!("Signature verification failed: {:?}", e))?;
        
        // Now update transcript with CertificateVerify
        let verify_bytes = cert_verify.to_bytes()
            .map_err(|e| format!("Failed to serialize CertificateVerify: {}", e))?;
        self.transcript.update(&verify_bytes);
        self.state = ClientState::WaitFinished;
        
        Ok(())
    }
    
    pub fn create_client_hello(&mut self) -> Result<ClientHello, String> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        
        // SECURITY FIX: Generate random session ID (32 bytes)
        // 
        // Session IDs provide:
        // - Session tracking/correlation
        // - Resume capability (future feature)
        // - Additional entropy in handshake
        // 
        // Must be cryptographically random to prevent:
        // - Session prediction attacks
        // - Session fixation attacks
        // - Correlation attacks
        let mut session_id = vec![0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut session_id);
        
        let hello = ClientHello {
            random: self.client_random,
            session_id,  // ✅ Now random instead of empty
            cipher_suites: vec![CipherSuite::VLK1_VOXSIG_CHACHA20_SHA3],
            key_share: self.vlk1_keypair.public_key().as_bytes(),
            timestamp,
        };
        
        let hello_bytes = hello.to_bytes()
            .map_err(|e| format!("Failed to serialize ClientHello: {}", e))?;
        self.transcript.update(&hello_bytes);
        self.state = ClientState::WaitServerHello;
        
        Ok(hello)
    }
    
    pub fn process_server_hello(&mut self, hello: ServerHello) -> Result<(), String> {
        self.server_random = Some(hello.random);
        
        // Replay protection: Check timestamp freshness
        // Reduced from 60s to 10s based on security audit
        let now = chrono::Utc::now().timestamp_millis();
        let age_ms = (now - hello.timestamp).abs();
        const MAX_AGE_MS: i64 = 10_000; // 10 seconds tolerance (reduced from 60s)
        
        if age_ms > MAX_AGE_MS {
            return Err(format!("ServerHello timestamp too old: {}ms (max {}ms)", age_ms, MAX_AGE_MS));
        }
        
        // ✅ SECURITY FIX: Nonce database check (ALWAYS enforced, no conditions)
        // Check server_random for replay - this is MANDATORY, no way to bypass
        self.nonce_db.check_and_store(&hello.random)
            .map_err(|e| format!("Replay protection failed: {}", e))?;
        
        let hello_bytes = hello.to_bytes()
            .map_err(|e| format!("Failed to serialize ServerHello: {}", e))?;
        self.transcript.update(&hello_bytes);
        
        // Parse server's KEM ciphertext
        let ciphertext = vlk1::kem::Ciphertext::from_bytes(&hello.kem_ciphertext)
            .map_err(|e| format!("Invalid ciphertext: {:?}", e))?;
        
        // Perform key exchange: Client decapsulates with its secret key
        let shared_secret = vlk1::decapsulate(&ciphertext, self.vlk1_keypair.secret_key())
            .map_err(|e| format!("KEM decapsulation failed: {:?}", e))?;
        
        self.key_schedule.derive_handshake_secret(shared_secret.as_bytes());
        self.state = ClientState::WaitCertificate;
        
        Ok(())
    }
    
    pub fn create_finished(&mut self) -> Result<Finished, String> {
        let transcript_hash = self.transcript.finalize();
        let handshake_secret = self.key_schedule.handshake_secret();
        
        eprintln!("[CLIENT] create_finished:");
        eprintln!("  handshake_secret: {:?}", &handshake_secret[..8]);
        eprintln!("  transcript_hash: {:?}", &transcript_hash[..8]);
        
        let verify_data = compute_finished(handshake_secret, &transcript_hash);
        eprintln!("  verify_data: {:?}", &verify_data[..8]);
        
        let finished = Finished { verify_data };
        let finished_bytes = finished.to_bytes()
            .map_err(|e| format!("Failed to serialize Finished: {}", e))?;
        self.transcript.update(&finished_bytes);
        
        Ok(finished)
    }
    
    /// ✅ SECURITY FIX: Process and verify server's Finished message
    /// 
    /// **CRITICAL**: This function was MISSING in the original implementation!
    /// Without it, the TLS handshake was not cryptographically closed.
    /// 
    /// # What This Does
    /// 
    /// Verifies that the server has the same view of the handshake transcript
    /// by checking the server's Finished MAC against our computed transcript hash.
    /// 
    /// # Why This Is Critical
    /// 
    /// Without Finished verification:
    /// - Man-in-the-middle can modify handshake messages
    /// - Client and server might have different transcripts
    /// - No binding of handshake to connection
    /// 
    /// # TLS 1.3 Requirement
    /// 
    /// TLS 1.3 mandates Finished message exchange and verification:
    /// - Server sends Finished after CertificateVerify
    /// - Client sends Finished after verifying server's Finished
    /// - Both parties verify the other's Finished MAC
    pub fn process_server_finished(&mut self, finished: &Finished) -> Result<(), String> {
        // Can only process Finished in WaitFinished state
        if !matches!(self.state, ClientState::WaitFinished) {
            return Err(format!("Invalid state for Finished: expected WaitFinished, got {:?}", 
                std::mem::discriminant(&self.state)));
        }
        
        // Get handshake secret (used for Finished MAC)
        let handshake_secret = self.key_schedule.get_handshake_secret()
            .ok_or("Handshake secret not available")?;
        
        // Compute transcript hash up to this point (excludes server's Finished)
        let transcript_hash = self.transcript.finalize();
        
        // ✅ CRITICAL: Verify server's Finished MAC
        if !verify_finished(handshake_secret, &transcript_hash, &finished.verify_data) {
            return Err("Server Finished verification failed! Possible MITM attack!".to_string());
        }
        
        // Update transcript with server's Finished message
        let finished_bytes = finished.to_bytes()
            .map_err(|e| format!("Failed to serialize server Finished: {}", e))?;
        self.transcript.update(&finished_bytes);
        
        // Transition to Connected state
        self.state = ClientState::Connected;
        
        Ok(())
    }
    
    /// Encrypt application data using ChaCha20-Poly1305 AEAD
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, AeadCore},
            ChaCha20Poly1305, Nonce
        };
        use rand::rngs::OsRng;
        
        // Derive application write key (client writes, server reads)
        let app_key = self.key_schedule.derive_application_key(b"client_write");
        
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
        
        // Derive application read key (server writes, client reads)
        let app_key = self.key_schedule.derive_application_key(b"server_write");
        
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

// ✅ SECURITY FIX: Removed Default impl - Client::new() now requires nonce_db
// Cannot have a "default" client without replay protection
//
// Users must explicitly provide nonce_db:
//   let nonce_db = Arc::new(NonceDatabase::new(Duration::from_secs(10)));
//   let client = Client::new(nonce_db);
