BIP: TBD
Title: Encryption Temporary for Transaction: A Solution for Fungibility
Author: John van Saberhagen jvsaberhagen@proton.me
Status: Draft
Type: Standards Track
Created: 2024-08-01
License: BSD-2-Clause
Abstract
This BIP proposes a method for temporarily encrypting Bitcoin transactions before propagation to the mempool. The encrypted transactions reveal only the transaction fee, ensuring that miners can include transactions in blocks without seeing the full transaction details. Once a block is mined, transactions are decrypted and displayed in their entirety as they are today. This approach aims to enhance transaction fungibility and privacy.
Motivation
The fungibility of Bitcoin is compromised when transaction details are visible to miners before they are confirmed. This visibility allows miners and other network participants to analyze and potentially discriminate against certain transactions based on their content. By encrypting transaction details until a block is mined, we can improve privacy and fungibility, making each Bitcoin indistinguishable from another.
Specification
Transaction Verification and Encryption
Node Verification: Nodes verify the transaction's validity, ensuring it adheres to all consensus rules.
Encryption: Once verified, the transaction is encrypted using Bulletproofs, which hides the transaction details while maintaining the ability to verify the transaction fee.
Bulletproofs Implementation:
Utilize Pedersen Commitments and Bulletproofs to create an encrypted transaction format.
The encrypted transaction includes a commitment to the transaction amount and other details, with a separate, visible commitment to the transaction fee.
Propagation
The encrypted transaction is propagated to the mempool.
Miners can see the transaction fee but not the transaction details.
Mining and Decryption
Mining: Miners include the encrypted transaction in a block based on the visible transaction fee.
Decryption: Once a block is mined, the transactions are decrypted using Bulletproofs, revealing the full transaction details.
Block Validation: Nodes validate the decrypted transactions as part of the block validation process.

Example of Encrypted Transaction Flow

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::{Prover, Verifier, Variable};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

fn create_bulletproof(value: u64) -> (Vec<u8>, Vec<u8>) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let mut prover_transcript = Transcript::new(b"example");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let (com, var) = prover.commit(Scalar::from(value), Scalar::random(&mut thread_rng()));
    prover.constrain(var - Variable::One());

    let proof = prover.prove(&bp_gens).unwrap();
    (com.to_bytes().to_vec(), proof.to_bytes())
}

fn verify_bulletproof(com: &[u8], proof: &[u8]) -> bool {
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

fn main() {
    let value = 42u64;
    let (com, proof) = create_bulletproof(value);
    let is_valid = verify_bulletproof(&com, &proof);

    println!("Bulletproof is valid: {}", is_valid);
}

Rationale
This proposal uses Bulletproofs for transaction encryption due to their efficiency and proven security in confidential transactions, as seen in Monero. Bulletproofs reduce the size of cryptographic proofs, making them suitable for integration into Bitcoin without significant performance degradation.
Backwards Compatibility
This proposal introduces new transaction types and validation rules, requiring a soft fork. However, similar to Taproot and SegWit, the adoption can be gradual. Legacy nodes do not need to upgrade immediately. They will still recognize and process traditional unencrypted transactions and blocks containing the new encrypted transactions, even though they cannot validate the encrypted details.
Test Cases
Extensive testing is required to validate the functionality and performance of the proposed encryption scheme. Tests should include:
Verifying the correctness of transaction encryption and decryption.
Measuring the impact on transaction propagation times.
Ensuring that miners can correctly include and process encrypted transactions.
Analyzing the effect on block validation times.
Reference Implementation
A reference implementation is available at  https://github.com/JvSaberhagen/encryption-temporary-for-transaction . The implementation includes the necessary code for transaction encryption, propagation, decryption, and validation using Bulletproofs.
Copyright
This BIP is licensed under the BSD-2-Clause license.
