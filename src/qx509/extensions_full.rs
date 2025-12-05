//! Complete X.509 Extensions for QX509

use super::*;
use serde::{Serialize, Deserialize};

/// Extension types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Extension {
    /// Key usage flags
    KeyUsage(KeyUsageExt),
    
    /// Basic constraints (CA/path length)
    BasicConstraints(BasicConstraintsExt),
    
    /// Subject alternative names
    SubjectAlternativeName(SubjectAlternativeNameExt),
    
    /// Authority key identifier
    AuthorityKeyIdentifier(AuthorityKeyIdentifierExt),
    
    /// Subject key identifier
    SubjectKeyIdentifier(SubjectKeyIdentifierExt),
    
    /// Extended key usage
    ExtendedKeyUsage(ExtendedKeyUsageExt),
    
    /// CRL distribution points
    CRLDistributionPoints(CRLDistributionPointsExt),
    
    /// Custom/unknown extension
    Custom {
        oid: String,
        critical: bool,
        value: Vec<u8>,
    },
}

impl Extension {
    /// Get OID for this extension
    pub fn oid(&self) -> &str {
        match self {
            Self::KeyUsage(_) => "2.5.29.15",
            Self::BasicConstraints(_) => "2.5.29.19",
            Self::SubjectAlternativeName(_) => "2.5.29.17",
            Self::AuthorityKeyIdentifier(_) => "2.5.29.35",
            Self::SubjectKeyIdentifier(_) => "2.5.29.14",
            Self::ExtendedKeyUsage(_) => "2.5.29.37",
            Self::CRLDistributionPoints(_) => "2.5.29.31",
            Self::Custom { oid, .. } => oid,
        }
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        match self {
            Self::KeyUsage(ku) => ku.critical,
            Self::BasicConstraints(bc) => bc.critical,
            Self::SubjectAlternativeName(san) => san.critical,
            Self::AuthorityKeyIdentifier(aki) => aki.critical,
            Self::SubjectKeyIdentifier(ski) => ski.critical,
            Self::ExtendedKeyUsage(eku) => eku.critical,
            Self::CRLDistributionPoints(cdp) => cdp.critical,
            Self::Custom { critical, .. } => *critical,
        }
    }
    
    /// Serialize extension to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        
        // OID
        let oid = self.oid();
        bytes.extend_from_slice(&(oid.len() as u16).to_le_bytes());
        bytes.extend_from_slice(oid.as_bytes());
        
        // Critical flag
        bytes.push(self.is_critical() as u8);
        
        // Value
        let value = self.encode_value()?;
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&value);
        
        Ok(bytes)
    }
    
    /// Encode extension value
    fn encode_value(&self) -> Result<Vec<u8>> {
        match self {
            Self::KeyUsage(ku) => Ok(ku.flags.to_le_bytes().to_vec()),
            Self::BasicConstraints(bc) => {
                let mut bytes = vec![bc.is_ca as u8];
                if let Some(pl) = bc.path_length {
                    bytes.extend_from_slice(&pl.to_le_bytes());
                }
                Ok(bytes)
            }
            Self::SubjectAlternativeName(san) => {
                bincode::serialize(&san.names)
                    .map_err(|e| QX509Error::Serialization(e.to_string()))
            }
            Self::AuthorityKeyIdentifier(aki) => Ok(aki.key_identifier.clone()),
            Self::SubjectKeyIdentifier(ski) => Ok(ski.key_identifier.clone()),
            Self::ExtendedKeyUsage(eku) => {
                bincode::serialize(&eku.usages)
                    .map_err(|e| QX509Error::Serialization(e.to_string()))
            }
            Self::CRLDistributionPoints(cdp) => {
                bincode::serialize(&cdp.distribution_points)
                    .map_err(|e| QX509Error::Serialization(e.to_string()))
            }
            Self::Custom { value, .. } => Ok(value.clone()),
        }
    }
    
    /// Deserialize extension from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut offset = 0;
        
        // Parse OID
        if data.len() < 2 {
            return Err(QX509Error::InvalidFormat);
        }
        let oid_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
        offset += 2;
        
        if data.len() < offset + oid_len {
            return Err(QX509Error::InvalidFormat);
        }
        let oid = String::from_utf8(data[offset..offset+oid_len].to_vec())
            .map_err(|_| QX509Error::InvalidFormat)?;
        offset += oid_len;
        
        // Parse critical flag
        if data.len() < offset + 1 {
            return Err(QX509Error::InvalidFormat);
        }
        let critical = data[offset] != 0;
        offset += 1;
        
        // Parse value length
        if data.len() < offset + 4 {
            return Err(QX509Error::InvalidFormat);
        }
        let value_len = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]) as usize;
        offset += 4;
        
        if data.len() < offset + value_len {
            return Err(QX509Error::InvalidFormat);
        }
        let value = &data[offset..offset+value_len];
        
        // Decode based on OID
        match oid.as_str() {
            "2.5.29.15" => {
                // KeyUsage
                if value.len() < 4 {
                    return Err(QX509Error::InvalidFormat);
                }
                let flags = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Self::KeyUsage(KeyUsageExt { critical, flags }))
            }
            "2.5.29.19" => {
                // BasicConstraints
                if value.is_empty() {
                    return Err(QX509Error::InvalidFormat);
                }
                let is_ca = value[0] != 0;
                let path_length = if value.len() >= 5 {
                    Some(u32::from_le_bytes([value[1], value[2], value[3], value[4]]))
                } else {
                    None
                };
                Ok(Self::BasicConstraints(BasicConstraintsExt {
                    critical,
                    is_ca,
                    path_length,
                }))
            }
            "2.5.29.17" => {
                // SubjectAlternativeName
                let names: Vec<GeneralName> = bincode::deserialize(value)
                    .map_err(|e| QX509Error::Serialization(e.to_string()))?;
                Ok(Self::SubjectAlternativeName(SubjectAlternativeNameExt {
                    critical,
                    names,
                }))
            }
            "2.5.29.35" => {
                // AuthorityKeyIdentifier
                Ok(Self::AuthorityKeyIdentifier(AuthorityKeyIdentifierExt {
                    critical,
                    key_identifier: value.to_vec(),
                }))
            }
            "2.5.29.14" => {
                // SubjectKeyIdentifier
                Ok(Self::SubjectKeyIdentifier(SubjectKeyIdentifierExt {
                    critical,
                    key_identifier: value.to_vec(),
                }))
            }
            "2.5.29.37" => {
                // ExtendedKeyUsage
                let usages: Vec<ExtendedKeyUsageType> = bincode::deserialize(value)
                    .map_err(|e| QX509Error::Serialization(e.to_string()))?;
                Ok(Self::ExtendedKeyUsage(ExtendedKeyUsageExt {
                    critical,
                    usages,
                }))
            }
            "2.5.29.31" => {
                // CRLDistributionPoints
                let distribution_points: Vec<DistributionPoint> = bincode::deserialize(value)
                    .map_err(|e| QX509Error::Serialization(e.to_string()))?;
                Ok(Self::CRLDistributionPoints(CRLDistributionPointsExt {
                    critical,
                    distribution_points,
                }))
            }
            _ => {
                // Custom
                Ok(Self::Custom {
                    oid: oid.clone(),
                    critical,
                    value: value.to_vec(),
                })
            }
        }
    }
}

/// Key Usage extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyUsageExt {
    pub critical: bool,
    pub flags: u32,
}

/// Key usage flags
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsageFlags {
    DigitalSignature = 1 << 0,
    NonRepudiation = 1 << 1,
    KeyEncipherment = 1 << 2,
    DataEncipherment = 1 << 3,
    KeyAgreement = 1 << 4,
    KeyCertSign = 1 << 5,
    CRLSign = 1 << 6,
    EncipherOnly = 1 << 7,
    DecipherOnly = 1 << 8,
}

impl KeyUsageExt {
    /// Create new key usage
    pub fn new(flags: u32) -> Self {
        Self {
            critical: true,
            flags,
        }
    }
    
    /// Check if flag is set
    pub fn has_flag(&self, flag: KeyUsageFlags) -> bool {
        self.flags & (flag as u32) != 0
    }
    
    /// Set flag
    pub fn set_flag(&mut self, flag: KeyUsageFlags) {
        self.flags |= flag as u32;
    }
}

/// Basic Constraints extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicConstraintsExt {
    pub critical: bool,
    pub is_ca: bool,
    pub path_length: Option<u32>,
}

impl BasicConstraintsExt {
    /// Create CA constraint
    pub fn ca(path_length: Option<u32>) -> Self {
        Self {
            critical: true,
            is_ca: true,
            path_length,
        }
    }
    
    /// Create end-entity constraint
    pub fn end_entity() -> Self {
        Self {
            critical: true,
            is_ca: false,
            path_length: None,
        }
    }
}

/// Subject Alternative Name extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubjectAlternativeNameExt {
    pub critical: bool,
    pub names: Vec<GeneralName>,
}

/// General name types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GeneralName {
    DNSName(String),
    IPAddress(String),
    RFC822Name(String),
    URI(String),
    DirectoryName(String),
}

impl SubjectAlternativeNameExt {
    /// Create with DNS names
    pub fn dns_names(names: Vec<String>) -> Self {
        Self {
            critical: false,
            names: names.into_iter().map(GeneralName::DNSName).collect(),
        }
    }
    
    /// Add DNS name
    pub fn add_dns_name(&mut self, name: String) {
        self.names.push(GeneralName::DNSName(name));
    }
    
    /// Add IP address
    pub fn add_ip_address(&mut self, ip: String) {
        self.names.push(GeneralName::IPAddress(ip));
    }
}

/// Authority Key Identifier extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityKeyIdentifierExt {
    pub critical: bool,
    pub key_identifier: Vec<u8>,
}

impl AuthorityKeyIdentifierExt {
    /// Create from key identifier
    pub fn new(key_identifier: Vec<u8>) -> Self {
        Self {
            critical: false,
            key_identifier,
        }
    }
    
    /// Create from public key
    pub fn from_public_key(public_key: &[u8]) -> Self {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        Self {
            critical: false,
            key_identifier: hash[..20].to_vec(), // First 160 bits
        }
    }
}

/// Subject Key Identifier extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubjectKeyIdentifierExt {
    pub critical: bool,
    pub key_identifier: Vec<u8>,
}

impl SubjectKeyIdentifierExt {
    /// Create from public key
    pub fn from_public_key(public_key: &[u8]) -> Self {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        Self {
            critical: false,
            key_identifier: hash[..20].to_vec(), // First 160 bits
        }
    }
}

/// Extended Key Usage extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedKeyUsageExt {
    pub critical: bool,
    pub usages: Vec<ExtendedKeyUsageType>,
}

/// Extended key usage types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExtendedKeyUsageType {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OCSPSigning,
    Custom(String),
}

impl ExtendedKeyUsageType {
    /// Get OID for usage type
    pub fn oid(&self) -> &str {
        match self {
            Self::ServerAuth => "1.3.6.1.5.5.7.3.1",
            Self::ClientAuth => "1.3.6.1.5.5.7.3.2",
            Self::CodeSigning => "1.3.6.1.5.5.7.3.3",
            Self::EmailProtection => "1.3.6.1.5.5.7.3.4",
            Self::TimeStamping => "1.3.6.1.5.5.7.3.8",
            Self::OCSPSigning => "1.3.6.1.5.5.7.3.9",
            Self::Custom(oid) => oid,
        }
    }
}

/// CRL Distribution Points extension
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CRLDistributionPointsExt {
    pub critical: bool,
    pub distribution_points: Vec<DistributionPoint>,
}

/// Distribution point
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionPoint {
    pub uri: String,
    pub reasons: Option<Vec<RevocationReason>>,
}

/// Revocation reasons
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCRL,
    PrivilegeWithdrawn,
    AACompromise,
}

impl CRLDistributionPointsExt {
    /// Create with URIs
    pub fn new(uris: Vec<String>) -> Self {
        Self {
            critical: false,
            distribution_points: uris
                .into_iter()
                .map(|uri| DistributionPoint {
                    uri,
                    reasons: None,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_usage() {
        let mut ku = KeyUsageExt::new(0);
        ku.set_flag(KeyUsageFlags::DigitalSignature);
        ku.set_flag(KeyUsageFlags::KeyAgreement);
        
        assert!(ku.has_flag(KeyUsageFlags::DigitalSignature));
        assert!(ku.has_flag(KeyUsageFlags::KeyAgreement));
        assert!(!ku.has_flag(KeyUsageFlags::KeyCertSign));
    }
    
    #[test]
    fn test_basic_constraints() {
        let ca = BasicConstraintsExt::ca(Some(2));
        assert!(ca.is_ca);
        assert_eq!(ca.path_length, Some(2));
        
        let ee = BasicConstraintsExt::end_entity();
        assert!(!ee.is_ca);
        assert_eq!(ee.path_length, None);
    }
    
    #[test]
    fn test_subject_alternative_name() {
        let mut san = SubjectAlternativeNameExt::dns_names(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ]);
        
        san.add_ip_address("192.168.1.1".to_string());
        
        assert_eq!(san.names.len(), 3);
    }
    
    #[test]
    fn test_subject_key_identifier() {
        let public_key = vec![1, 2, 3, 4, 5];
        let ski = SubjectKeyIdentifierExt::from_public_key(&public_key);
        
        assert_eq!(ski.key_identifier.len(), 20);
        assert!(!ski.critical);
    }
    
    #[test]
    fn test_extended_key_usage() {
        let eku = ExtendedKeyUsageExt {
            critical: false,
            usages: vec![
                ExtendedKeyUsageType::ServerAuth,
                ExtendedKeyUsageType::ClientAuth,
            ],
        };
        
        assert_eq!(eku.usages.len(), 2);
        assert_eq!(eku.usages[0].oid(), "1.3.6.1.5.5.7.3.1");
    }
    
    #[test]
    fn test_crl_distribution_points() {
        let cdp = CRLDistributionPointsExt::new(vec![
            "http://crl.example.com/ca.crl".to_string(),
        ]);
        
        assert_eq!(cdp.distribution_points.len(), 1);
        assert!(!cdp.critical);
    }
    
    #[test]
    fn test_extension_oid() {
        let ku = Extension::KeyUsage(KeyUsageExt::new(0));
        assert_eq!(ku.oid(), "2.5.29.15");
        
        let bc = Extension::BasicConstraints(BasicConstraintsExt::end_entity());
        assert_eq!(bc.oid(), "2.5.29.19");
    }
}
