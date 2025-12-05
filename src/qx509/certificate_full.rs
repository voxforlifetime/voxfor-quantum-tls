//! Complete QX509 Certificate Implementation

use super::*;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

/// Complete Certificate structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateFull {
    /// Certificate version (QX509 v1)
    pub version: u32,
    
    /// Serial number (unique per issuer)
    pub serial_number: u64,
    
    /// Signature algorithm identifier
    pub signature_algorithm: SignatureAlgorithm,
    
    /// Issuer distinguished name
    pub issuer: DistinguishedName,
    
    /// Validity period
    pub validity: Validity,
    
    /// Subject distinguished name
    pub subject: DistinguishedName,
    
    /// Subject public key info
    pub subject_public_key_info: SubjectPublicKeyInfo,
    
    /// Extensions
    pub extensions: Vec<extensions_full::Extension>,
    
    /// Signature (VOX-SIG)
    #[serde(skip)]
    pub signature: Option<Vec<u8>>,
}

/// Signature algorithm identifier
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// VOX-SIG with SHA3-256
    VoxSigSha3_256,
    /// Future: Other quantum-safe algorithms
    Future,
}

impl SignatureAlgorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            SignatureAlgorithm::VoxSigSha3_256 => 1,
            SignatureAlgorithm::Future => 255,
        }
    }
    
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(SignatureAlgorithm::VoxSigSha3_256),
            255 => Some(SignatureAlgorithm::Future),
            _ => None,
        }
    }
}

/// Subject public key information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubjectPublicKeyInfo {
    /// Algorithm identifier
    pub algorithm: PublicKeyAlgorithm,
    
    /// Public key bytes
    pub public_key: Vec<u8>,
}

/// Public key algorithm
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKeyAlgorithm {
    /// VLK-1 key exchange
    VLK1,
    
    /// VOX-SIG signatures
    VoxSig,
    
    /// Hybrid classical+quantum
    Hybrid,
}

impl PublicKeyAlgorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            PublicKeyAlgorithm::VLK1 => 1,
            PublicKeyAlgorithm::VoxSig => 2,
            PublicKeyAlgorithm::Hybrid => 3,
        }
    }
    
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(PublicKeyAlgorithm::VLK1),
            2 => Some(PublicKeyAlgorithm::VoxSig),
            3 => Some(PublicKeyAlgorithm::Hybrid),
            _ => None,
        }
    }
}

impl CertificateFull {
    /// Create a new certificate builder
    pub fn builder() -> CertificateBuilder {
        CertificateBuilder::new()
    }
    
    /// Get To-Be-Signed (TBS) certificate data
    pub fn tbs_certificate(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // Magic header
        data.extend_from_slice(b"QX509v1");
        
        // Version
        data.extend_from_slice(&self.version.to_le_bytes());
        
        // Serial number
        data.extend_from_slice(&self.serial_number.to_le_bytes());
        
        // Signature algorithm
        data.push(self.signature_algorithm.to_u8());
        
        // Issuer
        let issuer_bytes = bincode::serialize(&self.issuer)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        data.extend_from_slice(&(issuer_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&issuer_bytes);
        
        // Validity
        data.extend_from_slice(&self.validity.not_before.timestamp().to_le_bytes());
        data.extend_from_slice(&self.validity.not_after.timestamp().to_le_bytes());
        
        // Subject
        let subject_bytes = bincode::serialize(&self.subject)
            .map_err(|e| QX509Error::Serialization(e.to_string()))?;
        data.extend_from_slice(&(subject_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&subject_bytes);
        
        // Subject public key info
        data.push(self.subject_public_key_info.algorithm.to_u8());
        data.extend_from_slice(&(self.subject_public_key_info.public_key.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.subject_public_key_info.public_key);
        
        // Extensions
        data.extend_from_slice(&(self.extensions.len() as u16).to_le_bytes());
        for ext in &self.extensions {
            let ext_bytes = ext.to_bytes()?;
            data.extend_from_slice(&(ext_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&ext_bytes);
        }
        
        Ok(data)
    }
    
    /// Sign the certificate with VOX-SIG
    pub fn sign(&mut self, signing_key: &mut crate::voxsig::keygen::SigningKey) -> Result<()> {
        let tbs = self.tbs_certificate()?;
        
        let sig = crate::voxsig::sign::sign(signing_key, &tbs)
            .map_err(|_| QX509Error::InvalidSignature)?;
        
        self.signature = Some(sig.to_bytes());
        Ok(())
    }
    
    /// Verify certificate signature
    pub fn verify(&self, verifying_key: &crate::voxsig::keygen::VerifyingKey) -> Result<()> {
        let signature = self.signature.as_ref()
            .ok_or(QX509Error::InvalidSignature)?;
        
        let tbs = self.tbs_certificate()?;
        
        let sig = crate::voxsig::sign::Signature::from_bytes(signature)
            .map_err(|_| QX509Error::InvalidSignature)?;
        
        crate::voxsig::verify::verify(verifying_key, &tbs, &sig)
            .map_err(|_| QX509Error::InvalidSignature)?;
        
        Ok(())
    }
    
    /// Check if certificate is currently valid (time-wise)
    pub fn is_valid_now(&self) -> bool {
        self.validity.is_valid()
    }
    
    /// Check if certificate is a CA certificate
    pub fn is_ca(&self) -> bool {
        self.extensions.iter().any(|ext| {
            if let extensions_full::Extension::BasicConstraints(bc) = ext {
                bc.is_ca
            } else {
                false
            }
        })
    }
    
    /// Get key usage extension
    pub fn key_usage(&self) -> Option<&extensions_full::KeyUsageExt> {
        self.extensions.iter().find_map(|ext| {
            if let extensions_full::Extension::KeyUsage(ku) = ext {
                Some(ku)
            } else {
                None
            }
        })
    }
    
    /// Compute certificate fingerprint (SHA3-256)
    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        let bytes = self.to_bytes()?;
        let mut hasher = Sha3_256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }
    
    /// Serialize complete certificate
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.tbs_certificate()?;
        
        // Append signature
        if let Some(sig) = &self.signature {
            bytes.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            bytes.extend_from_slice(sig);
        } else {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        
        Ok(bytes)
    }
    
    /// Deserialize certificate
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        #[cfg(test)]
        eprintln!("[CERT::from_bytes] data.len() = {}", data.len());
        
        // Parse TBS certificate + signature
        // Format: TBS bytes (variable) + signature_len (4 bytes) + signature
        // We need to parse TBS first to know where it ends
        
        // Parse TBS (without knowing exact length)
        let (cert, tbs_end) = Self::parse_tbs_with_offset(data)?;
        
        #[cfg(test)]
        eprintln!("[CERT::from_bytes] TBS ends at offset {}", tbs_end);
        
        // Now parse signature
        if data.len() < tbs_end + 4 {
            #[cfg(test)]
            eprintln!("[CERT::from_bytes] No signature present");
            return Ok(cert);
        }
        
        let sig_len = u32::from_le_bytes([
            data[tbs_end], data[tbs_end+1], 
            data[tbs_end+2], data[tbs_end+3]
        ]) as usize;
        
        #[cfg(test)]
        eprintln!("[CERT::from_bytes] sig_len = {}", sig_len);
        
        let sig_start = tbs_end + 4;
        if data.len() < sig_start + sig_len {
            #[cfg(test)]
            eprintln!("[CERT::from_bytes] ERROR: not enough data for signature");
            return Err(QX509Error::InvalidFormat);
        }
        
        let mut cert = cert;
        cert.signature = if sig_len > 0 {
            Some(data[sig_start..sig_start + sig_len].to_vec())
        } else {
            None
        };
        
        Ok(cert)
    }
    
    /// Parse TBS and return (cert, offset_after_tbs)
    fn parse_tbs_with_offset(data: &[u8]) -> Result<(Self, usize)> {
        let cert = Self::parse_tbs(data)?;
        
        // Calculate how many bytes TBS consumed
        // This requires us to know the structure
        // For now, let's recalculate from cert
        let tbs_bytes = cert.tbs_certificate()?;
        let tbs_len = tbs_bytes.len();
        
        Ok((cert, tbs_len))
    }
    
    /// Parse TBS certificate
    fn parse_tbs(data: &[u8]) -> Result<Self> {
        let mut offset = 0;
        
        #[cfg(test)]
        eprintln!("[CERT::parse_tbs] Starting parse, data.len() = {}", data.len());
        
        // Magic header "QX509v1"
        if data.len() < 7 {
            #[cfg(test)]
            eprintln!("[CERT::parse_tbs] ERROR: too short for magic");
            return Err(QX509Error::InvalidFormat);
        }
        if &data[0..7] != b"QX509v1" {
            #[cfg(test)]
            eprintln!("[CERT::parse_tbs] ERROR: invalid magic header");
            return Err(QX509Error::InvalidFormat);
        }
        offset += 7;
        
        #[cfg(test)]
        eprintln!("[CERT::parse_tbs] Magic header OK, offset = {}", offset);
        
        // Version (4 bytes)
        if data.len() < offset + 4 {
            #[cfg(test)]
            eprintln!("[CERT::parse_tbs] ERROR: not enough bytes for version");
            return Err(QX509Error::InvalidFormat);
        }
        let version = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]);
        offset += 4;
        
        #[cfg(test)]
        eprintln!("[CERT::parse_tbs] version = {}, offset = {}", version, offset);
        
        // Serial number (8 bytes)
        if data.len() < offset + 8 {
            #[cfg(test)]
            eprintln!("[CERT::parse_tbs] ERROR: not enough for serial");
            return Err(QX509Error::InvalidFormat);
        }
        let serial_number = u64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
        ]);
        offset += 8;
        
        #[cfg(test)]
        eprintln!("[CERT::parse_tbs] serial = {}, offset = {}", serial_number, offset);
        
        // Signature algorithm (1 byte)
        if data.len() < offset + 1 {
            #[cfg(test)]
            eprintln!("[CERT::parse_tbs] ERROR: not enough for sig_alg");
            return Err(QX509Error::InvalidFormat);
        }
        let sig_alg_byte = data[offset];
        let sig_alg = SignatureAlgorithm::from_u8(sig_alg_byte)
            .ok_or_else(|| {
                #[cfg(test)]
                eprintln!("[CERT::parse_tbs] ERROR: invalid sig_alg byte: {}", sig_alg_byte);
                QX509Error::InvalidFormat
            })?;
        offset += 1;
        
        #[cfg(test)]
        eprintln!("[CERT::parse_tbs] sig_alg = {:?}, offset = {}", sig_alg, offset);
        
        // Issuer DN length + data
        if data.len() < offset + 4 {
            return Err(QX509Error::InvalidFormat);
        }
        let issuer_len = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + issuer_len {
            return Err(QX509Error::InvalidFormat);
        }
        let issuer = DistinguishedName::from_bytes(&data[offset..offset+issuer_len])?;
        offset += issuer_len;
        
        // Validity (16 bytes: 2 x i64 timestamps)
        if data.len() < offset + 16 {
            return Err(QX509Error::InvalidFormat);
        }
        let not_before_ts = i64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
        ]);
        offset += 8;
        let not_after_ts = i64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
        ]);
        offset += 8;
        
        let validity = Validity {
            not_before: DateTime::from_timestamp(not_before_ts, 0)
                .ok_or(QX509Error::InvalidFormat)?,
            not_after: DateTime::from_timestamp(not_after_ts, 0)
                .ok_or(QX509Error::InvalidFormat)?,
        };
        
        // Subject DN length + data
        if data.len() < offset + 4 {
            return Err(QX509Error::InvalidFormat);
        }
        let subject_len = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + subject_len {
            return Err(QX509Error::InvalidFormat);
        }
        let subject = DistinguishedName::from_bytes(&data[offset..offset+subject_len])?;
        offset += subject_len;
        
        // Subject public key info
        // Algorithm (1 byte)
        if data.len() < offset + 1 {
            return Err(QX509Error::InvalidFormat);
        }
        let pk_alg = PublicKeyAlgorithm::from_u8(data[offset])
            .ok_or(QX509Error::InvalidFormat)?;
        offset += 1;
        
        // Public key length + data
        if data.len() < offset + 4 {
            return Err(QX509Error::InvalidFormat);
        }
        let pk_len = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + pk_len {
            return Err(QX509Error::InvalidFormat);
        }
        let public_key = data[offset..offset+pk_len].to_vec();
        offset += pk_len;
        
        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: pk_alg,
            public_key,
        };
        
        // Extensions count (2 bytes)
        if data.len() < offset + 2 {
            return Err(QX509Error::InvalidFormat);
        }
        let ext_count = u16::from_le_bytes([
            data[offset], data[offset+1]
        ]) as usize;
        offset += 2;
        
        // Parse extensions
        let mut extensions = Vec::new();
        for _ in 0..ext_count {
            if data.len() < offset + 4 {
                return Err(QX509Error::InvalidFormat);
            }
            let ext_len = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            ]) as usize;
            offset += 4;
            
            if data.len() < offset + ext_len {
                return Err(QX509Error::InvalidFormat);
            }
            let ext = extensions_full::Extension::from_bytes(&data[offset..offset+ext_len])?;
            extensions.push(ext);
            offset += ext_len;
        }
        
        Ok(Self {
            version,
            serial_number,
            signature_algorithm: sig_alg,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
            signature: None,
        })
    }
}

/// Certificate builder for easy construction
pub struct CertificateBuilder {
    version: u32,
    serial_number: Option<u64>,
    signature_algorithm: SignatureAlgorithm,
    issuer: Option<DistinguishedName>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    subject: Option<DistinguishedName>,
    public_key_algorithm: Option<PublicKeyAlgorithm>,
    public_key: Option<Vec<u8>>,
    extensions: Vec<extensions_full::Extension>,
}

impl CertificateBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            version: 1,
            serial_number: None,
            signature_algorithm: SignatureAlgorithm::VoxSigSha3_256,
            issuer: None,
            not_before: None,
            not_after: None,
            subject: None,
            public_key_algorithm: None,
            public_key: None,
            extensions: Vec::new(),
        }
    }
    
    /// Set serial number
    pub fn serial_number(mut self, serial: u64) -> Self {
        self.serial_number = Some(serial);
        self
    }
    
    /// Set issuer
    pub fn issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = Some(issuer);
        self
    }
    
    /// Set subject
    pub fn subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = Some(subject);
        self
    }
    
    /// Set validity period
    pub fn validity(mut self, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        self.not_before = Some(not_before);
        self.not_after = Some(not_after);
        self
    }
    
    /// Set validity period from duration
    pub fn validity_days(mut self, days: i64) -> Self {
        let now = Utc::now();
        self.not_before = Some(now);
        self.not_after = Some(now + Duration::days(days));
        self
    }
    
    /// Set public key
    pub fn public_key(mut self, algorithm: PublicKeyAlgorithm, key: Vec<u8>) -> Self {
        self.public_key_algorithm = Some(algorithm);
        self.public_key = Some(key);
        self
    }
    
    /// Add extension
    pub fn add_extension(mut self, ext: extensions_full::Extension) -> Self {
        self.extensions.push(ext);
        self
    }
    
    /// Build the certificate
    pub fn build(self) -> Result<CertificateFull> {
        Ok(CertificateFull {
            version: self.version,
            serial_number: self.serial_number.ok_or(QX509Error::InvalidFormat)?,
            signature_algorithm: self.signature_algorithm,
            issuer: self.issuer.ok_or(QX509Error::InvalidFormat)?,
            validity: Validity::new(
                self.not_before.ok_or(QX509Error::InvalidFormat)?,
                self.not_after.ok_or(QX509Error::InvalidFormat)?,
            ),
            subject: self.subject.ok_or(QX509Error::InvalidFormat)?,
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: self.public_key_algorithm.ok_or(QX509Error::InvalidFormat)?,
                public_key: self.public_key.ok_or(QX509Error::InvalidFormat)?,
            },
            extensions: self.extensions,
            signature: None,
        })
    }
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_builder() {
        let dn = DistinguishedName::new("test.example.com");
        
        let cert = CertificateFull::builder()
            .serial_number(1)
            .issuer(dn.clone())
            .subject(dn)
            .validity_days(365)
            .public_key(PublicKeyAlgorithm::VoxSig, vec![1, 2, 3])
            .build()
            .unwrap();
        
        assert_eq!(cert.serial_number, 1);
        assert_eq!(cert.version, 1);
    }
    
    #[test]
    fn test_tbs_certificate() {
        let dn = DistinguishedName::new("test.example.com");
        
        let cert = CertificateFull::builder()
            .serial_number(1)
            .issuer(dn.clone())
            .subject(dn)
            .validity_days(365)
            .public_key(PublicKeyAlgorithm::VoxSig, vec![1, 2, 3])
            .build()
            .unwrap();
        
        let tbs = cert.tbs_certificate().unwrap();
        assert!(tbs.len() > 0);
        assert!(tbs.starts_with(b"QX509v1"));
    }
    
    #[test]
    fn test_ca_detection() {
        let dn = DistinguishedName::new("test.example.com");
        
        let mut cert = CertificateFull::builder()
            .serial_number(1)
            .issuer(dn.clone())
            .subject(dn)
            .validity_days(365)
            .public_key(PublicKeyAlgorithm::VoxSig, vec![1, 2, 3])
            .add_extension(extensions_full::Extension::BasicConstraints(extensions_full::BasicConstraintsExt {
                critical: true,
                is_ca: true,
                path_length: None,
            }))
            .build()
            .unwrap();
        
        assert!(cert.is_ca());
    }
}
