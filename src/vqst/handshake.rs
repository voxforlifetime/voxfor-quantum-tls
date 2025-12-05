//! VQST Handshake State Machine

use super::messages::*;
use super::{client::Client, server::Server};
use super::nonce_db::NonceDatabase;
use std::sync::Arc;

pub struct Handshake;

impl Handshake {
    /// Create client handshake
    /// 
    /// # Security Fix
    /// 
    /// Now requires BOTH `nonce_db` and `crl_manager` parameters.
    /// No way to create a client without replay protection AND revocation checking!
    #[cfg(any(test, feature = "insecure-skip-hostname"))]
    pub fn client_handshake(
        nonce_db: Arc<NonceDatabase>,
        crl_manager: Arc<crate::ca::revocation::CRLManager>,
    ) -> Result<Client, String> {
        // ✅ Use insecure version for testing (hostname verification skipped)
        #[allow(deprecated)]
        let mut client = Client::new_insecure_skip_hostname_verification(nonce_db, crl_manager);
        let _hello = client.create_client_hello();
        Ok(client)
    }
    
    /// Create client handshake (SECURE VERSION)
    /// 
    /// # Security
    /// 
    /// This version enforces hostname verification for production use.
    #[cfg(not(any(test, feature = "insecure-skip-hostname")))]
    pub fn client_handshake(
        nonce_db: Arc<NonceDatabase>,
        crl_manager: Arc<crate::ca::revocation::CRLManager>,
        hostname: &str,
    ) -> Result<Client, String> {
        let mut client = Client::new(hostname, nonce_db, crl_manager);
        let _hello = client.create_client_hello();
        Ok(client)
    }
    
    /// Create server handshake
    /// 
    /// # Security Fix
    /// 
    /// Now requires `nonce_db` parameter for replay protection.
    pub fn server_handshake(
        cert: Vec<u8>, 
        key: crate::voxsig::keygen::SigningKey,
        nonce_db: Arc<NonceDatabase>,
    ) -> Result<Server, String> {
        Ok(Server::new(cert, key, nonce_db))
    }
}
