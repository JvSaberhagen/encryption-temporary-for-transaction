extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::{Prover, Verifier, Variable};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::vec::Vec;

mod lib;

fn main() {
    let value = 42u64;
    let fee = 1u64;

    // Create Bulletproof for transaction value
    let (com_value, proof_value) = lib::create_bulletproof(value);

    // Create Bulletproof for transaction fee
    let (com_fee, proof_fee) = lib::create_bulletproof(fee);

    // Verify Bulletproof for transaction value
    let is_valid_value = lib::verify_bulletproof(&com_value, &proof_value);
    println!("Bulletproof for transaction value is valid: {}", is_valid_value);

    // Verify Bulletproof for transaction fee
    let is_valid_fee = lib::verify_bulletproof(&com_fee, &proof_fee);
    println!("Bulletproof for transaction fee is valid: {}", is_valid_fee);

    // Simulate propagation and mining
    if is_valid_value && is_valid_fee {
        println!("Transaction propagated and mined successfully.");
    } else {
        println!("Transaction verification failed.");
    }
}
