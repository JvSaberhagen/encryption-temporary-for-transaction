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

pub fn create_bulletproof(value: u64) -> (Vec<u8>, Vec<u8>) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let mut prover_transcript = Transcript::new(b"example");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let (com, var) = prover.commit(Scalar::from(value), Scalar::random(&mut thread_rng()));
    prover.constrain(var - Variable::One());

    let proof = prover.prove(&bp_gens).unwrap();
    (com.to_bytes().to_vec(), proof.to_bytes())
}

pub fn verify_bulletproof(com: &[u8], proof: &[u8]) -> bool {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let com = curve25519_dalek::ristretto::CompressedRistretto::from_slice(com).decompress().unwrap();
    let proof = bulletproofs::r1cs::R1CSProof::from_bytes(proof).unwrap();

    let mut verifier_transcript = Transcript::new(b"example");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let var = verifier.commit(com);
    verifier.constrain(var - Variable::One());

    verifier.verify(&proof, &pc_gens, &bp_gens).is_ok()
}
