//! Error types for the library

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("VLK-1 error: {0}")]
    Vlk1(#[from] crate::vlk1::Vlk1Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
