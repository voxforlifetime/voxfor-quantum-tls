//! Test for atomic serial number persistence
//! 
//! This test verifies that serial numbers are persisted atomically
//! to prevent collision after crashes.

use voxfor_quantum_tls::ca::root_ca::{RootCA, RootCAConfig};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_serial_atomic_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let ca_dir = temp_dir.path();
    
    let config = RootCAConfig {
        common_name: "Test Root CA".to_string(),
        organization: "Test Org".to_string(),
        country: "US".to_string(),
        validity_days: 365,
    };
    
    // Initialize CA (this will take time due to keygen, but only once)
    println!("Initializing CA (this may take 30s due to Merkle tree generation)...");
    let mut ca = RootCA::initialize(ca_dir, config).unwrap();
    println!("CA initialized!");
    
    // Get first serial
    let serial1 = ca.next_serial().unwrap();
    assert_eq!(serial1, 1);
    
    // Verify it was persisted to disk
    let serial_file = ca_dir.join("serial.txt");
    assert!(serial_file.exists(), "Serial file should exist after next_serial()");
    
    let saved_serial: u64 = fs::read_to_string(&serial_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    
    assert_eq!(saved_serial, 2, "Saved serial should be 2 (next available)");
    
    // Get second serial
    let serial2 = ca.next_serial().unwrap();
    assert_eq!(serial2, 2);
    
    // Verify persistence again
    let saved_serial: u64 = fs::read_to_string(&serial_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    
    assert_eq!(saved_serial, 3, "Saved serial should be 3 (next available)");
    
    println!(" Atomic serial persistence test PASSED!");
}

#[test]
fn test_serial_file_created_atomically() {
    let temp_dir = TempDir::new().unwrap();
    let ca_dir = temp_dir.path();
    
    let config = RootCAConfig {
        common_name: "Test Root CA".to_string(),
        organization: "Test Org".to_string(),
        country: "US".to_string(),
        validity_days: 365,
    };
    
    println!("Initializing CA for atomic file test...");
    let mut ca = RootCA::initialize(ca_dir, config).unwrap();
    
    // After next_serial(), temp file should NOT exist (it's renamed)
    let temp_file = ca_dir.join("serial.tmp");
    let serial_file = ca_dir.join("serial.txt");
    
    ca.next_serial().unwrap();
    
    assert!(!temp_file.exists(), "Temporary file should be removed after atomic rename");
    assert!(serial_file.exists(), "Final serial file should exist");
    
    println!(" Atomic file creation test PASSED!");
}

#[test]
fn test_serial_sequence_correctness() {
    let temp_dir = TempDir::new().unwrap();
    let ca_dir = temp_dir.path();
    
    let config = RootCAConfig::default();
    
    println!("Testing serial sequence...");
    let mut ca = RootCA::initialize(ca_dir, config).unwrap();
    
    // Test sequence
    for expected in 1..=10 {
        let serial = ca.next_serial().unwrap();
        assert_eq!(serial, expected, "Serial should be sequential");
    }
    
    // Verify final state
    let serial_file = ca_dir.join("serial.txt");
    let saved_serial: u64 = fs::read_to_string(&serial_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    
    assert_eq!(saved_serial, 11, "Next available serial should be 11");
    
    println!(" Serial sequence test PASSED!");
}
