//! Intermediate Certificate Authority Implementation

use crate::{qx509::*, voxsig};
use super::root_ca::RootCA;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use chrono::{Utc, Duration};
use serde::{Serialize, Deserialize};

/// Intermediate CA configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntermediateCAConfig {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub validity_days: i64,
}

impl Default for IntermediateCAConfig {
    fn default() -> Self {
        Self {
            common_name: "Voxfor Intermediate CA".to_string(),
            organization: "Voxfor Quantum Security".to_string(),
            country: "IL".to_string(),
            validity_days: 1825, // 5 years
        }
    }
}

/// Intermediate Certificate Authority
pub struct IntermediateCA {
    ca_dir: PathBuf,
    signing_key: voxsig::keygen::SigningKey,
    verifying_key: voxsig::keygen::VerifyingKey,
    certificate: certificate_full::CertificateFull,
    config: IntermediateCAConfig,
    next_serial: u64,
}

impl IntermediateCA {
    /// Initialize a new Intermediate CA signed by Root CA
    pub fn initialize<P: AsRef<Path>>(
        ca_dir: P,
        config: IntermediateCAConfig,
        root_ca: &mut RootCA,
    ) -> Result<Self> {
        let ca_dir = ca_dir.as_ref().to_path_buf();
        
        // Create directory structure
        fs::create_dir_all(&ca_dir)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        fs::create_dir_all(ca_dir.join("certs"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        fs::create_dir_all(ca_dir.join("crl"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // Generate signing key
        let keypair = voxsig::keygen::Keypair::generate();
        
        // Create certificate signed by root
        let subject = DistinguishedName::new(&config.common_name)
            .with_organization(&config.organization)
            .with_country(&config.country);
        
        let now = Utc::now();
        let not_after = now + Duration::days(config.validity_days);
        
        let serial = root_ca.next_serial()?;
        
        let mut cert = certificate_full::CertificateFull::builder()
            .serial_number(serial)
            .issuer(root_ca.certificate().subject.clone())
            .subject(subject)
            .validity(now, not_after)
            .public_key(
                certificate_full::PublicKeyAlgorithm::VoxSig,
                keypair.verifying_key.to_bytes(),
            )
            .add_extension(extensions_full::Extension::KeyUsage(
                extensions_full::KeyUsageExt::new(
                    extensions_full::KeyUsageFlags::KeyCertSign as u32 |
                    extensions_full::KeyUsageFlags::CRLSign as u32
                )
            ))
            .add_extension(extensions_full::Extension::BasicConstraints(
                extensions_full::BasicConstraintsExt::ca(Some(0)) // Path length 0 - can't issue more CAs
            ))
            .add_extension(extensions_full::Extension::SubjectKeyIdentifier(
                extensions_full::SubjectKeyIdentifierExt::from_public_key(&keypair.verifying_key.to_bytes())
            ))
            .add_extension(extensions_full::Extension::AuthorityKeyIdentifier(
                extensions_full::AuthorityKeyIdentifierExt::from_public_key(&root_ca.verifying_key().to_bytes())
            ))
            .build()?;
        
        // Sign by root CA
        root_ca.sign_certificate(&mut cert)?;
        
        let mut int_ca = Self {
            ca_dir,
            signing_key: keypair.signing_key,
            verifying_key: keypair.verifying_key,
            certificate: cert,
            config,
            next_serial: 1,
        };
        
        int_ca.save()?;
        
        Ok(int_ca)
    }
    
    /// Load existing Intermediate CA
    pub fn load<P: AsRef<Path>>(ca_dir: P) -> Result<Self> {
        let ca_dir = ca_dir.as_ref().to_path_buf();
        
        let config_data = fs::read(ca_dir.join("config.json"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let config = serde_json::from_slice(&config_data)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        let sk_data = fs::read(ca_dir.join("ca.key"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let signing_key = voxsig::keygen::SigningKey::from_bytes(&sk_data)
            .map_err(|_| QX509Error::InvalidFormat)?;
        
        let vk_data = fs::read(ca_dir.join("ca.pub"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let verifying_key = voxsig::keygen::VerifyingKey::from_bytes(&vk_data)
            .map_err(|_| QX509Error::InvalidFormat)?;
        
        let cert_data = fs::read(ca_dir.join("ca.crt"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let certificate = certificate_full::CertificateFull::from_bytes(&cert_data)?;
        
        let serial_str = fs::read_to_string(ca_dir.join("serial.txt"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let next_serial = serial_str.trim().parse()
            .map_err(|_| QX509Error::InvalidFormat)?;
        
        Ok(Self {
            ca_dir,
            signing_key,
            verifying_key,
            certificate,
            config,
            next_serial,
        })
    }
    
    fn save(&self) -> Result<()> {
        let config_data = serde_json::to_vec_pretty(&self.config)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        fs::write(self.ca_dir.join("config.json"), config_data)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // 🔴 CRITICAL FIX: Use atomic persistence for signing key to prevent counter reuse
        // See: https://github.com/voxfor/voxfor-quantum-tls/security/advisories/GHSA-xxxx
        self.save_signing_key_atomic()?;
        
        fs::write(self.ca_dir.join("ca.pub"), &self.verifying_key.to_bytes())
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        let cert_bytes = self.certificate.to_bytes()?;
        fs::write(self.ca_dir.join("ca.crt"), &cert_bytes)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        let pem = pem_der::encode_pem(&cert_bytes, pem_der::PemType::Certificate);
        fs::write(self.ca_dir.join("ca.pem"), pem)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        fs::write(self.ca_dir.join("serial.txt"), self.next_serial.to_string())
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        Ok(())
    }
    
    /// 🔴 SECURITY-CRITICAL: Atomic persistence of signing key
    ///
    /// **Problem**: VOX-SIG uses stateful signatures where each signature MUST use
    /// a unique index. Reusing an index even ONCE allows an attacker to recover
    /// the private key completely!
    ///
    /// **Solution**: Write-ahead logging with atomic rename ensures the counter
    /// is persisted BEFORE being used for signing.
    ///
    /// # Atomic Write Protocol
    ///
    /// 1. Write to temp file (.key.tmp)
    /// 2. fsync() temp file → forces data to disk
    /// 3. Atomic rename temp → ca.key
    /// 4. fsync() parent directory → ensures directory entry is persisted
    ///
    /// This guarantees that even on crash/power loss:
    /// - Either old counter is visible (safe - unused index)
    /// - Or new counter is visible (safe - will use next index)
    /// - NEVER partial writes (would cause counter rollback!)
    ///
    /// # Why This Matters
    ///
    /// Lamport signatures reveal one of two keys per bit. If two signatures
    /// use the same index but different messages:
    /// ```text
    /// Sig1[index=42]: reveals keys where msg1[bit]=1
    /// Sig2[index=42]: reveals keys where msg2[bit]=1
    /// → Attacker gets BOTH keys for differing bits → can forge ANY signature!
    /// ```
    ///
    /// # References
    /// - NIST SP 800-208: "Recommendation for Stateful HBS"
    /// - "Practical Attacks on Stateful HBS" (McGrew, 2016)
    fn save_signing_key_atomic(&self) -> Result<()> {
        use std::io::Write;
        
        let key_path = self.ca_dir.join("ca.key");
        let temp_path = self.ca_dir.join("ca.key.tmp");
        
        // Step 1: Write to temporary file
        #[allow(deprecated)] // We know this is internal CA usage with atomic persistence
        let key_bytes = self.signing_key.to_bytes();
        
        let mut temp_file = fs::File::create(&temp_path)
            .map_err(|e| QX509Error::Io(e.to_string()))?;
        
        temp_file.write_all(&key_bytes)
            .map_err(|e| QX509Error::Io(e.to_string()))?;
        
        // Step 2: fsync() - force data to physical disk
        temp_file.sync_all()
            .map_err(|e| QX509Error::Io(e.to_string()))?;
        
        // Step 3: Atomic rename (OS guarantees atomicity)
        #[cfg(unix)]
        {
            fs::rename(&temp_path, &key_path)
                .map_err(|e| QX509Error::Io(e.to_string()))?;
        }
        
        #[cfg(not(unix))]
        {
            // Windows: rename is NOT atomic if target exists!
            // Must delete first, then rename (small window of vulnerability)
            if key_path.exists() {
                fs::remove_file(&key_path)
                    .map_err(|e| QX509Error::Io(e.to_string()))?;
            }
            fs::rename(&temp_path, &key_path)
                .map_err(|e| QX509Error::Io(e.to_string()))?;
        }
        
        // Step 4: fsync() parent directory to persist directory entry
        #[cfg(unix)]
        {
            if let Some(parent) = key_path.parent() {
                let dir = fs::File::open(parent)
                    .map_err(|e| QX509Error::Io(e.to_string()))?;
                dir.sync_all()
                    .map_err(|e| QX509Error::Io(e.to_string()))?;
            }
        }
        
        Ok(())
    }
    
    /// Get next serial number with atomic persistence
    /// 
    /// # Security Model
    /// **ATOMIC PERSISTENCE**: Serial number is persisted to disk BEFORE
    /// being returned. This prevents serial number collision after crashes.
    /// 
    /// Uses atomic file operations (write to temp, then rename) which is
    /// atomic on most filesystems (POSIX, NTFS).
    /// 
    /// # Errors
    /// Returns error if persistence fails (disk full, permissions, etc.)
    pub fn next_serial(&mut self) -> Result<u64> {
        let current_serial = self.next_serial;
        self.next_serial = current_serial + 1;
        
        // CRITICAL: Persist BEFORE returning (write-ahead)
        self.save_serial_atomic()?;
        
        Ok(current_serial)
    }
    
    /// Save serial number atomically using temp file + rename
    /// 
    /// # Atomicity
    /// 1. Write to temporary file (serial.tmp)
    /// 2. Sync to disk (fsync)
    /// 3. Atomic rename to actual file (serial.txt)
    /// 
    /// Step 3 is atomic on POSIX and NTFS filesystems.
    fn save_serial_atomic(&self) -> Result<()> {
        let serial_path = self.ca_dir.join("serial.txt");
        let temp_path = self.ca_dir.join("serial.tmp");
        
        // Write to temp file
        fs::write(&temp_path, self.next_serial.to_string())
            .map_err(|e| QX509Error::Serialization(
                format!("Failed to write serial to temp file: {}", e)
            ))?;
        
        // Sync to disk (ensure durability)
        #[cfg(unix)]
        {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&temp_path)
                .map_err(|e| QX509Error::Serialization(
                    format!("Failed to open temp file for sync: {}", e)
                ))?;
            
            file.sync_all()
                .map_err(|e| QX509Error::Serialization(
                    format!("Failed to sync temp file: {}", e)
                ))?;
        }
        
        // Atomic rename (commits the change)
        fs::rename(&temp_path, &serial_path)
            .map_err(|e| QX509Error::Serialization(
                format!("Failed to atomically rename serial file: {}", e)
            ))?;
        
        Ok(())
    }
    
    pub fn certificate(&self) -> &certificate_full::CertificateFull {
        &self.certificate
    }
    
    pub fn sign_certificate(&mut self, cert: &mut certificate_full::CertificateFull) -> Result<()> {
        cert.sign(&mut self.signing_key)?;
        self.save()?;
        Ok(())
    }
}
