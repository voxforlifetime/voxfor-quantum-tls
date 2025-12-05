//! Certificate Revocation List (CRL) Management

use crate::qx509::*;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

/// Certificate Revocation List
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    pub issuer: DistinguishedName,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub revoked_certificates: Vec<RevokedCertificate>,
    pub crl_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokedCertificate {
    pub serial_number: u64,
    pub revocation_date: DateTime<Utc>,
    pub reason: RevocationReason,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

impl CertificateRevocationList {
    pub fn new(issuer: DistinguishedName, crl_number: u64, validity_days: i64) -> Self {
        let now = Utc::now();
        let next_update = now + chrono::Duration::days(validity_days);
        
        Self {
            issuer,
            this_update: now,
            next_update,
            revoked_certificates: Vec::new(),
            crl_number,
        }
    }
    
    pub fn add_revoked(&mut self, serial_number: u64, reason: RevocationReason) {
        let revoked = RevokedCertificate {
            serial_number,
            revocation_date: Utc::now(),
            reason,
        };
        self.revoked_certificates.push(revoked);
    }
    
    pub fn is_revoked(&self, serial_number: u64) -> bool {
        self.revoked_certificates.iter().any(|r| r.serial_number == serial_number)
    }
    
    pub fn get_reason(&self, serial_number: u64) -> Option<RevocationReason> {
        self.revoked_certificates
            .iter()
            .find(|r| r.serial_number == serial_number)
            .map(|r| r.reason)
    }
    
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.this_update && now <= self.next_update
    }
    
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| QX509Error::Serialization(e.to_string()))
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| QX509Error::Serialization(e.to_string()))
    }
    
    pub fn to_pem(&self) -> Result<String> {
        let bytes = self.to_bytes()?;
        Ok(format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
            BASE64.encode(&bytes)
        ))
    }
}

pub struct CRLManager {
    crl: CertificateRevocationList,
    revocation_db: HashMap<u64, RevocationReason>,
}

impl CRLManager {
    pub fn new(issuer: DistinguishedName) -> Self {
        Self {
            crl: CertificateRevocationList::new(issuer, 1, 30),
            revocation_db: HashMap::new(),
        }
    }
    
    pub fn revoke(&mut self, serial_number: u64, reason: RevocationReason) -> Result<()> {
        if self.revocation_db.contains_key(&serial_number) {
            return Err(QX509Error::AlreadyRevoked);
        }
        self.revocation_db.insert(serial_number, reason);
        self.crl.add_revoked(serial_number, reason);
        Ok(())
    }
    
    pub fn is_revoked(&self, serial_number: u64) -> bool {
        self.revocation_db.contains_key(&serial_number)
    }
    
    pub fn generate_crl(&mut self, validity_days: i64) -> &CertificateRevocationList {
        let crl_number = self.crl.crl_number + 1;
        let issuer = self.crl.issuer.clone();
        
        let mut new_crl = CertificateRevocationList::new(issuer, crl_number, validity_days);
        for (&serial, &reason) in &self.revocation_db {
            new_crl.add_revoked(serial, reason);
        }
        self.crl = new_crl;
        &self.crl
    }
    
    pub fn current_crl(&self) -> &CertificateRevocationList {
        &self.crl
    }
    
    pub fn load(data: &[u8]) -> Result<Self> {
        let crl = CertificateRevocationList::from_bytes(data)?;
        let mut revocation_db = HashMap::new();
        for revoked in &crl.revoked_certificates {
            revocation_db.insert(revoked.serial_number, revoked.reason);
        }
        Ok(Self { crl, revocation_db })
    }
    
    pub fn save(&self) -> Result<Vec<u8>> {
        self.crl.to_bytes()
    }
}
