//! Distinguished Name for QX509

use serde::{Serialize, Deserialize};
use crate::qx509::{QX509Error, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistinguishedName {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}

impl DistinguishedName {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        }
    }
    
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }
    
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }
    
    pub fn to_string(&self) -> String {
        let mut parts = vec![format!("CN={}", self.common_name)];
        
        if let Some(ou) = &self.organizational_unit {
            parts.push(format!("OU={}", ou));
        }
        if let Some(o) = &self.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(l) = &self.locality {
            parts.push(format!("L={}", l));
        }
        if let Some(st) = &self.state {
            parts.push(format!("ST={}", st));
        }
        if let Some(c) = &self.country {
            parts.push(format!("C={}", c));
        }
        
        parts.join(", ")
    }
    
    /// Deserialize from bytes (using bincode)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| QX509Error::Serialization(e.to_string()))
    }
}
