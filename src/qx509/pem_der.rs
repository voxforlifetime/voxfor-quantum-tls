//! PEM and DER encoding/decoding for QX509

use super::*;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

/// PEM types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PemType {
    Certificate,
    PrivateKey,
    PublicKey,
    CertificateRequest,
}

impl PemType {
    /// Get PEM header for this type
    pub fn header(&self) -> &'static str {
        match self {
            Self::Certificate => "CERTIFICATE",
            Self::PrivateKey => "PRIVATE KEY",
            Self::PublicKey => "PUBLIC KEY",
            Self::CertificateRequest => "CERTIFICATE REQUEST",
        }
    }
    
    /// Get begin marker
    pub fn begin_marker(&self) -> String {
        format!("-----BEGIN {}-----", self.header())
    }
    
    /// Get end marker
    pub fn end_marker(&self) -> String {
        format!("-----END {}-----", self.header())
    }
}

/// Encode data to PEM format
pub fn encode_pem(data: &[u8], pem_type: PemType) -> String {
    let mut output = String::new();
    
    // Begin marker
    output.push_str(&pem_type.begin_marker());
    output.push('\n');
    
    // Base64 encode data in 64-character lines
    let b64 = BASE64.encode(data);
    for chunk in b64.as_bytes().chunks(64) {
        output.push_str(&String::from_utf8_lossy(chunk));
        output.push('\n');
    }
    
    // End marker
    output.push_str(&pem_type.end_marker());
    output.push('\n');
    
    output
}

/// Decode PEM format
pub fn decode_pem(pem: &str) -> Result<(Vec<u8>, PemType)> {
    // Find begin and end markers
    let lines: Vec<&str> = pem.lines().collect();
    
    let mut begin_index = None;
    let mut end_index = None;
    let mut pem_type = None;
    
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("-----BEGIN ") {
            begin_index = Some(i);
            // Extract type
            let type_str = line.trim_start_matches("-----BEGIN ")
                .trim_end_matches("-----");
            pem_type = match type_str {
                "CERTIFICATE" => Some(PemType::Certificate),
                "PRIVATE KEY" => Some(PemType::PrivateKey),
                "PUBLIC KEY" => Some(PemType::PublicKey),
                "CERTIFICATE REQUEST" => Some(PemType::CertificateRequest),
                _ => None,
            };
        } else if line.starts_with("-----END ") {
            end_index = Some(i);
            break;
        }
    }
    
    let begin = begin_index.ok_or(QX509Error::InvalidFormat)?;
    let end = end_index.ok_or(QX509Error::InvalidFormat)?;
    let pem_type = pem_type.ok_or(QX509Error::InvalidFormat)?;
    
    // Extract base64 data
    let b64_lines = &lines[begin + 1..end];
    let b64_data = b64_lines.join("");
    
    // Decode base64
    let data = BASE64.decode(b64_data.as_bytes())
        .map_err(|_| QX509Error::InvalidFormat)?;
    
    Ok((data, pem_type))
}

/// DER encoding utilities
pub mod der {
    use super::*;
    
    /// DER tags
    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Tag {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        Sequence = 0x30,
        Set = 0x31,
        PrintableString = 0x13,
        UtcTime = 0x17,
        GeneralizedTime = 0x18,
    }
    
    /// Encode TLV (Tag-Length-Value)
    pub fn encode_tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
        let mut output = vec![tag as u8];
        
        // Encode length
        let len = value.len();
        if len < 128 {
            output.push(len as u8);
        } else if len < 256 {
            output.push(0x81);
            output.push(len as u8);
        } else if len < 65536 {
            output.push(0x82);
            output.push((len >> 8) as u8);
            output.push((len & 0xFF) as u8);
        } else {
            output.push(0x83);
            output.push((len >> 16) as u8);
            output.push((len >> 8) as u8);
            output.push((len & 0xFF) as u8);
        }
        
        // Value
        output.extend_from_slice(value);
        
        output
    }
    
    /// Decode TLV with integer overflow protection
    /// 
    /// # Security
    /// 
    /// **Integer Overflow Protection**: DER length field can encode arbitrarily
    /// large values. Without validation, malicious input like:
    /// ```text
    /// Length: 0x84 FF FF FF FF (4-byte length = 4GB)
    /// ```
    /// Could cause:
    /// - Integer overflow in length calculation
    /// - Excessive memory allocation
    /// - DoS via resource exhaustion
    /// 
    /// **Protections Applied**:
    /// 1. Limit length octets to 4 bytes (max 4GB, reasonable for certificates)
    /// 2. Check for overflow during multi-byte length accumulation
    /// 3. Validate total length doesn't exceed available data
    /// 4. Validate offset arithmetic doesn't overflow
    pub fn decode_tlv(data: &[u8]) -> Result<(Tag, Vec<u8>, usize)> {
        if data.is_empty() {
            return Err(QX509Error::InvalidFormat);
        }
        
        let tag = Tag::from_u8(data[0])?;
        let mut offset = 1;
        
        // Decode length with overflow protection
        if offset >= data.len() {
            return Err(QX509Error::InvalidFormat);
        }
        
        let len_byte = data[offset];
        offset += 1;
        
        let length = if len_byte < 128 {
            // Short form: length < 128
            len_byte as usize
        } else {
            // Long form: length >= 128
            let num_octets = (len_byte & 0x7F) as usize;
            
            // SECURITY: Limit to 4 bytes (max 4GB, reasonable for certificates)
            // Prevents integer overflow and excessive memory allocation
            if num_octets == 0 || num_octets > 4 {
                return Err(QX509Error::Serialization(
                    format!("Invalid DER length octets: {} (must be 1-4)", num_octets)
                ));
            }
            
            // Check we have enough data for length octets
            if offset + num_octets > data.len() {
                return Err(QX509Error::InvalidFormat);
            }
            
            // ✅ SECURITY FIX: Maximum certificate size (10MB is generous for cert chains)
            // Typical certificate: <10KB. Max with large chains: <1MB. 10MB allows for extreme cases.
            const MAX_CERT_SIZE: usize = 10_000_000; // 10MB
            
            let mut length = 0usize;
            for _i in 0..num_octets {
                // SECURITY: Check for overflow before shift
                if length > (usize::MAX >> 8) {
                    return Err(QX509Error::Serialization(
                        "DER length overflow detected".to_string()
                    ));
                }
                
                length = (length << 8) | (data[offset] as usize);
                offset += 1;
                
                // ✅ CRITICAL FIX: Check size limit AFTER EVERY ITERATION
                // Previous code only checked on last iteration (i == num_octets - 1)
                // Attack scenario:
                //   Input: 0x84 7F FF FF FF (4-byte length)
                //   Iteration 1: length = 0x7F (OK)
                //   Iteration 2: length = 0x7FFF (OK)
                //   Iteration 3: length = 0x7FFFFF (OK)
                //   Iteration 4: length = 0x7FFFFFFF (2GB!) ❌ HUGE
                // The check `length > (usize::MAX >> 8)` passes because 0x7FFFFFFF < (usize::MAX >> 8)
                // But 2GB allocation causes OOM DoS!
                //
                // Fix: Check against MAX_CERT_SIZE after EVERY shift, not just last iteration
                if length > MAX_CERT_SIZE {
                    return Err(QX509Error::Serialization(
                        format!("DER length too large: {} bytes (max 10MB). Accumulated after shift.", length)
                    ));
                }
            }
            
            length
        };
        
        // SECURITY: Validate offset arithmetic won't overflow
        if offset > data.len() || length > data.len() - offset {
            return Err(QX509Error::Serialization(
                format!("DER length {} exceeds available data (offset={}, total={})", 
                    length, offset, data.len())
            ));
        }
        
        // Extract value
        let value = data[offset..offset + length].to_vec();
        
        // SECURITY: Validate final offset calculation
        let end_offset = offset.checked_add(length)
            .ok_or_else(|| QX509Error::Serialization("Offset overflow".to_string()))?;
        
        Ok((tag, value, end_offset))
    }
    
    impl Tag {
        fn from_u8(byte: u8) -> Result<Self> {
            match byte {
                0x01 => Ok(Self::Boolean),
                0x02 => Ok(Self::Integer),
                0x03 => Ok(Self::BitString),
                0x04 => Ok(Self::OctetString),
                0x05 => Ok(Self::Null),
                0x06 => Ok(Self::ObjectIdentifier),
                0x30 => Ok(Self::Sequence),
                0x31 => Ok(Self::Set),
                0x13 => Ok(Self::PrintableString),
                0x17 => Ok(Self::UtcTime),
                0x18 => Ok(Self::GeneralizedTime),
                _ => Err(QX509Error::InvalidFormat),
            }
        }
    }
    
    /// Encode integer to DER
    pub fn encode_integer(value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut v = value;
        
        if v == 0 {
            bytes.push(0);
        } else {
            while v > 0 {
                bytes.push((v & 0xFF) as u8);
                v >>= 8;
            }
            bytes.reverse();
            
            // Add leading zero if high bit is set
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0);
            }
        }
        
        encode_tlv(Tag::Integer, &bytes)
    }
    
    /// Encode OID (Object Identifier)
    pub fn encode_oid(oid: &str) -> Result<Vec<u8>> {
        let components: Vec<u64> = oid.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        if components.len() < 2 {
            return Err(QX509Error::InvalidFormat);
        }
        
        let mut bytes = Vec::new();
        
        // First two components are encoded as 40*c0 + c1
        bytes.push((40 * components[0] + components[1]) as u8);
        
        // Remaining components
        for &component in &components[2..] {
            if component < 128 {
                bytes.push(component as u8);
            } else {
                // Multi-byte encoding
                let mut temp = Vec::new();
                let mut v = component;
                temp.push((v & 0x7F) as u8);
                v >>= 7;
                
                while v > 0 {
                    temp.push(((v & 0x7F) | 0x80) as u8);
                    v >>= 7;
                }
                
                temp.reverse();
                bytes.extend(temp);
            }
        }
        
        Ok(encode_tlv(Tag::ObjectIdentifier, &bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_encode_decode() {
        let data = vec![1, 2, 3, 4, 5];
        
        let pem = encode_pem(&data, PemType::Certificate);
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
        
        let (decoded, pem_type) = decode_pem(&pem).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(pem_type, PemType::Certificate);
    }
    
    #[test]
    fn test_pem_markers() {
        assert_eq!(PemType::Certificate.header(), "CERTIFICATE");
        assert_eq!(PemType::PrivateKey.header(), "PRIVATE KEY");
    }
    
    #[test]
    fn test_der_tlv_encode_decode() {
        let value = vec![1, 2, 3, 4];
        let tlv = der::encode_tlv(der::Tag::OctetString, &value);
        
        let (tag, decoded_value, _) = der::decode_tlv(&tlv).unwrap();
        assert_eq!(tag, der::Tag::OctetString);
        assert_eq!(decoded_value, value);
    }
    
    #[test]
    fn test_der_integer() {
        let encoded = der::encode_integer(12345);
        assert!(encoded.len() > 2);
        assert_eq!(encoded[0], der::Tag::Integer as u8);
    }
    
    #[test]
    fn test_der_oid() {
        let oid = "2.5.29.15"; // KeyUsage
        let encoded = der::encode_oid(oid).unwrap();
        assert!(encoded.len() > 2);
        assert_eq!(encoded[0], der::Tag::ObjectIdentifier as u8);
    }
}
