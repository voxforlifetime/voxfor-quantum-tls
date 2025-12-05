//! VCPF-2 Record Layer
//! 
//! TLS-like record protocol with quantum-resistant encryption

use serde::{Serialize, Deserialize};

/// Maximum record payload size (16KB)
pub const MAX_RECORD_SIZE: usize = 16384;

/// Record content types
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// Handshake messages
    Handshake = 22,
    
    /// Application data
    ApplicationData = 23,
    
    /// Alert messages
    Alert = 21,
    
    /// Change cipher spec (legacy)
    ChangeCipherSpec = 20,
}

impl ContentType {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            21 => Some(Self::Alert),
            20 => Some(Self::ChangeCipherSpec),
            _ => None,
        }
    }
}

/// TLS Record
#[derive(Clone, Debug)]
pub struct Record {
    /// Content type
    pub content_type: ContentType,
    
    /// Protocol version (VQST 1.0 = 0x0304)
    pub version: u16,
    
    /// Payload data
    pub payload: Vec<u8>,
}

impl Record {
    /// Create a new record
    pub fn new(content_type: ContentType, payload: Vec<u8>) -> Self {
        Self {
            content_type,
            version: 0x0304, // VQST 1.0
            payload,
        }
    }
    
    /// Serialize record to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Content type (1 byte)
        bytes.push(self.content_type as u8);
        
        // Version (2 bytes)
        bytes.extend_from_slice(&self.version.to_be_bytes());
        
        // Length (2 bytes)
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        
        // Payload
        bytes.extend_from_slice(&self.payload);
        
        bytes
    }
    
    /// Parse record from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), RecordError> {
        if data.len() < 5 {
            return Err(RecordError::InsufficientData);
        }
        
        let content_type = ContentType::from_u8(data[0])
            .ok_or(RecordError::InvalidContentType)?;
        
        let version = u16::from_be_bytes([data[1], data[2]]);
        
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;
        
        if length > MAX_RECORD_SIZE {
            return Err(RecordError::RecordTooLarge);
        }
        
        if data.len() < 5 + length {
            return Err(RecordError::InsufficientData);
        }
        
        let payload = data[5..5 + length].to_vec();
        
        let record = Self {
            content_type,
            version,
            payload,
        };
        
        Ok((record, 5 + length))
    }
    
    /// Split payload into multiple records if needed
    pub fn fragment(content_type: ContentType, data: &[u8]) -> Vec<Self> {
        let mut records = Vec::new();
        
        for chunk in data.chunks(MAX_RECORD_SIZE) {
            records.push(Self::new(content_type, chunk.to_vec()));
        }
        
        records
    }
}

/// Record reassembler for fragmented records
pub struct RecordReassembler {
    buffer: Vec<u8>,
    content_type: Option<ContentType>,
}

impl RecordReassembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            content_type: None,
        }
    }
    
    /// Add a record fragment
    pub fn add_fragment(&mut self, record: Record) -> Result<(), RecordError> {
        // Check content type consistency
        if let Some(ct) = self.content_type {
            if ct != record.content_type {
                return Err(RecordError::FragmentMismatch);
            }
        } else {
            self.content_type = Some(record.content_type);
        }
        
        self.buffer.extend_from_slice(&record.payload);
        
        Ok(())
    }
    
    /// Check if reassembly is complete (application-defined)
    pub fn is_complete(&self) -> bool {
        // For handshake messages, we'd check for complete message
        // For now, just return true if we have data
        !self.buffer.is_empty()
    }
    
    /// Get reassembled data
    pub fn take(&mut self) -> Option<(ContentType, Vec<u8>)> {
        if self.buffer.is_empty() {
            return None;
        }
        
        let content_type = self.content_type.take()?;
        let data = std::mem::take(&mut self.buffer);
        
        Some((content_type, data))
    }
}

impl Default for RecordReassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Record layer errors
#[derive(Debug, Clone)]
pub enum RecordError {
    InsufficientData,
    InvalidContentType,
    RecordTooLarge,
    FragmentMismatch,
    EncryptionError,
    DecryptionError,
    SequenceOverflow,
    /// Rekeying required - cryptographic message limit reached
    /// 
    /// ChaCha20-Poly1305 has a safe limit of 2^32 messages per key.
    /// This error indicates that limit has been reached and a new
    /// key must be negotiated via TLS rekeying/resumption.
    RekeyRequired {
        sequence_number: u64,
        threshold: u64,
    },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientData => write!(f, "Insufficient data"),
            Self::InvalidContentType => write!(f, "Invalid content type"),
            Self::RecordTooLarge => write!(f, "Record too large"),
            Self::FragmentMismatch => write!(f, "Fragment content type mismatch"),
            Self::EncryptionError => write!(f, "Encryption error"),
            Self::DecryptionError => write!(f, "Decryption error"),
            Self::SequenceOverflow => write!(f, "Sequence number overflow - connection must be rekeyed"),
            Self::RekeyRequired { sequence_number, threshold } => write!(
                f, 
                "Rekeying required: sequence {} reached threshold {} (ChaCha20-Poly1305 message limit)",
                sequence_number, threshold
            ),
        }
    }
}

impl std::error::Error for RecordError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_serialization() {
        let payload = vec![1, 2, 3, 4, 5];
        let record = Record::new(ContentType::ApplicationData, payload.clone());
        
        let bytes = record.to_bytes();
        assert_eq!(bytes[0], ContentType::ApplicationData as u8);
        
        let (parsed, _) = Record::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.content_type, ContentType::ApplicationData);
        assert_eq!(parsed.payload, payload);
    }
    
    #[test]
    fn test_record_fragmentation() {
        let large_data = vec![0u8; MAX_RECORD_SIZE * 2 + 100];
        let records = Record::fragment(ContentType::ApplicationData, &large_data);
        
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].payload.len(), MAX_RECORD_SIZE);
        assert_eq!(records[1].payload.len(), MAX_RECORD_SIZE);
        assert_eq!(records[2].payload.len(), 100);
    }
    
    #[test]
    fn test_reassembler() {
        let mut reassembler = RecordReassembler::new();
        
        let rec1 = Record::new(ContentType::Handshake, vec![1, 2, 3]);
        let rec2 = Record::new(ContentType::Handshake, vec![4, 5, 6]);
        
        reassembler.add_fragment(rec1).unwrap();
        reassembler.add_fragment(rec2).unwrap();
        
        let (ct, data) = reassembler.take().unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(data, vec![1, 2, 3, 4, 5, 6]);
    }
}
