//! Root Certificate Authority Implementation

use crate::{qx509::*, voxsig};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;
use chrono::{Utc, Duration};
use serde::{Serialize, Deserialize};

/// Root CA configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootCAConfig {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub validity_days: i64,
}

impl Default for RootCAConfig {
    fn default() -> Self {
        Self {
            common_name: "Voxfor Root CA".to_string(),
            organization: "Voxfor Quantum Security".to_string(),
            country: "IL".to_string(),
            validity_days: 3650, // 10 years
        }
    }
}

/// Root Certificate Authority
pub struct RootCA {
    /// CA directory
    ca_dir: PathBuf,
    
    /// Signing keypair
    signing_key: voxsig::keygen::SigningKey,
    verifying_key: voxsig::keygen::VerifyingKey,
    
    /// Root certificate
    certificate: certificate_full::CertificateFull,
    
    /// Configuration
    config: RootCAConfig,
    
    /// Serial number counter
    next_serial: u64,
}

impl RootCA {
    /// Initialize a new Root CA
    pub fn initialize<P: AsRef<Path>>(
        ca_dir: P,
        config: RootCAConfig,
    ) -> Result<Self> {
        let ca_dir = ca_dir.as_ref().to_path_buf();
        
        // Create CA directory structure
        fs::create_dir_all(&ca_dir)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        fs::create_dir_all(ca_dir.join("certs"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        fs::create_dir_all(ca_dir.join("crl"))
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // Generate VOX-SIG signing key
        let keypair = voxsig::keygen::Keypair::generate();
        
        // Create self-signed root certificate
        let subject = DistinguishedName::new(&config.common_name)
            .with_organization(&config.organization)
            .with_country(&config.country);
        
        let now = Utc::now();
        let not_after = now + Duration::days(config.validity_days);
        
        let mut cert = certificate_full::CertificateFull::builder()
            .serial_number(1)
            .issuer(subject.clone())
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
                extensions_full::BasicConstraintsExt::ca(Some(2))
            ))
            .add_extension(extensions_full::Extension::SubjectKeyIdentifier(
                extensions_full::SubjectKeyIdentifierExt::from_public_key(&keypair.verifying_key.to_bytes())
            ))
            .build()?;
        
        // Sign the certificate (self-signed)
        let mut signing_key = keypair.signing_key;
        cert.sign(&mut signing_key)?;
        
        let mut root_ca = Self {
            ca_dir,
            signing_key,
            verifying_key: keypair.verifying_key,
            certificate: cert,
            config,
            next_serial: 2, // Serial 1 is the root cert
        };
        
        // Persist to disk
        root_ca.save()?;
        
        Ok(root_ca)
    }
    
    /// Load existing Root CA
    pub fn load<P: AsRef<Path>>(ca_dir: P) -> Result<Self> {
        let ca_dir = ca_dir.as_ref().to_path_buf();
        
        // Load config
        let config_path = ca_dir.join("config.json");
        let config_data = fs::read(&config_path)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let config: RootCAConfig = serde_json::from_slice(&config_data)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // Load signing key
        let sk_path = ca_dir.join("ca.key");
        let sk_data = fs::read(&sk_path)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let signing_key = voxsig::keygen::SigningKey::from_bytes(&sk_data)
            .map_err(|e| {
                #[cfg(test)]
                eprintln!("[CA] Failed to load signing key: {:?}, len={}", e, sk_data.len());
                QX509Error::InvalidFormat
            })?;
        
        // Load verifying key
        let vk_path = ca_dir.join("ca.pub");
        let vk_data = fs::read(&vk_path)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let verifying_key = voxsig::keygen::VerifyingKey::from_bytes(&vk_data)
            .map_err(|_| QX509Error::InvalidFormat)?;
        
        // Load certificate
        let cert_path = ca_dir.join("ca.crt");
        let cert_data = fs::read(&cert_path)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        let certificate = certificate_full::CertificateFull::from_bytes(&cert_data)?;
        
        // Load serial number
        let serial_path = ca_dir.join("serial.txt");
        let serial_str = fs::read_to_string(&serial_path)
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
    
    /// Save CA state to disk
    /// 
    /// ✅ SECURITY FIX: Atomic persistence for SigningKey counter
    fn save(&self) -> Result<()> {
        // Save config
        let config_data = serde_json::to_vec_pretty(&self.config)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        fs::write(self.ca_dir.join("config.json"), config_data)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // ✅ CRITICAL: Save signing key with ATOMIC write
        // Use same atomic pattern as serial numbers to prevent counter reuse
        self.save_signing_key_atomic()?;
        
        // Save verifying key (non-critical, no atomicity needed)
        fs::write(self.ca_dir.join("ca.pub"), &self.verifying_key.to_bytes())
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // Save certificate
        let cert_bytes = self.certificate.to_bytes()?;
        fs::write(self.ca_dir.join("ca.crt"), &cert_bytes)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // Save as PEM too
        let pem = pem_der::encode_pem(&cert_bytes, pem_der::PemType::Certificate);
        fs::write(self.ca_dir.join("ca.pem"), pem)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        // Save serial
        fs::write(self.ca_dir.join("serial.txt"), self.next_serial.to_string())
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        
        Ok(())
    }
    
    /// ✅ SECURITY FIX: Atomic persistence for SigningKey
    ///
    /// **CRITICAL**: SigningKey contains a `counter` that MUST NEVER repeat!
    ///
    /// This function uses the same atomic write pattern as `save_serial_atomic()`:
    /// 1. Write to temporary file
    /// 2. fsync() to force to disk
    /// 3. Atomic rename over old file
    ///
    /// This ensures that even if the process crashes mid-write, we either get:
    /// - Old key with old counter (safe to reuse)
    /// - New key with new counter (correct state)
    /// Never a partial/corrupted key!
    fn save_signing_key_atomic(&self) -> Result<()> {
        let key_path = self.ca_dir.join("ca.key");
        let temp_path = self.ca_dir.join("ca.key.tmp");
        
        // 1. Write to temporary file
        let key_bytes = self.signing_key.to_bytes();
        let mut file = fs::File::create(&temp_path)
            .map_err(|e| QX509Error::Serialization(format!("Failed to create temp key file: {}", e)))?;
        
        file.write_all(&key_bytes)
            .map_err(|e| QX509Error::Serialization(format!("Failed to write key: {}", e)))?;
        
        // 2. Force write to disk (CRITICAL for atomicity)
        file.sync_all()
            .map_err(|e| QX509Error::Serialization(format!("Failed to fsync key: {}", e)))?;
        
        drop(file); // Close file before rename
        
        // 3. Atomic rename (overwrites old file atomically)
        fs::rename(&temp_path, &key_path)
            .map_err(|e| QX509Error::Serialization(format!("Failed to rename key file: {}", e)))?;
        
        // 4. fsync directory (ensures rename is durable)
        // Note: Directory fsync omitted for portability
        // On most filesystems, file fsync + rename is sufficient
        
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
    
    /// Get CA certificate
    pub fn certificate(&self) -> &certificate_full::CertificateFull {
        &self.certificate
    }
    
    /// Get verifying key
    pub fn verifying_key(&self) -> &voxsig::keygen::VerifyingKey {
        &self.verifying_key
    }
    
    /// Sign a certificate
    pub fn sign_certificate(&mut self, cert: &mut certificate_full::CertificateFull) -> Result<()> {
        cert.sign(&mut self.signing_key)?;
        self.save()?;
        Ok(())
    }
    
    /// Export certificate to file
    pub fn export_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let cert_bytes = self.certificate.to_bytes()?;
        let pem = pem_der::encode_pem(&cert_bytes, pem_der::PemType::Certificate);
        fs::write(path, pem)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_root_ca_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let config = RootCAConfig::default();
        
        let root_ca = RootCA::initialize(temp_dir.path(), config).unwrap();
        
        assert!(root_ca.certificate().is_ca());
        assert_eq!(root_ca.next_serial, 2);
    }
    
    #[test]
    fn test_root_ca_load_save() {
        let temp_dir = TempDir::new().unwrap();
        let config = RootCAConfig::default();
        
        {
            let _root_ca = RootCA::initialize(temp_dir.path(), config.clone()).unwrap();
        }
        
        // Load it back
        let root_ca = RootCA::load(temp_dir.path()).unwrap();
        assert_eq!(root_ca.config.common_name, config.common_name);
    }
}
