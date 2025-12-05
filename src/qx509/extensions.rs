use serde::{Serialize, Deserialize};

// These are placeholders - real implementation is in extensions_full.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Extension {
    Placeholder,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyUsage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicConstraints;
