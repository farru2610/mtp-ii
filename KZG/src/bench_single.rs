// Run: cargo run --release --bin bench_single
// Outputs: single_point_results.json

use std::time::Instant;
use std::fs;
use serde::{Serialize, Deserialize};
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_std::UniformRand;
use std::ops::Mul;

use crate::kzg::KZG;
use crate::utils::evaluate;

#[derive(Serialize, Deserialize, Debug)]
pub struct SingleResult {
    pub curve:          String,
    pub degree:         usize,
    pub setup_ms:       f64,
    pub commit_ms:      f64,
    pub prove_ms:       f64,
    pub verify_ms:      f64,
    pub scalar_mul_ms:  f64, 
    pub pairing_ms:     f64,   
    pub proof_bytes:    usize,
}

const DEGREES: &[usize] = &[4, 8, 16, 32, 64, 128, 256, 512, 1024];
// const DEGREES: &[usize] = &[2048, 4096];
const REPEATS: u32 = 10;

fn avg_ms<F: FnMut()>(mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..REPEATS { f(); }
    t.elapsed().as_secs_f64() * 1000.0 / REPEATS as f64
}

// ── Generic function — works for ANY curve ──────────────────────────────────
fn run_for_curve<E: Pairing>(curve_name: &str, proof_bytes: usize) -> Vec<SingleResult>
where
    E::G1: UniformRand,
    E::G2: UniformRand,
    E::ScalarField: UniformRand,
{
    println!("\nKZG Single-Point Benchmark ({})", curve_name);
    println!(
        "{:<8} {:>10} {:>10} {:>10} {:>10} {:>15} {:>13} {:>12}",
        "degree", "setup(ms)", "commit(ms)", "prove(ms)", "verify(ms)",
        "scalar_mul(ms)", "pairing(ms)", "proof(bytes)"
    );
    println!("{}", "-".repeat(95));

    let mut rng = ark_std::test_rng();
    let mut results = Vec::new();

    // ── scalar multiplication benchmark (degree-independent) ────────────────
    // Measured once per curve since it does not depend on degree
    let base_g1 = E::G1::rand(&mut rng);
    let scalar  = E::ScalarField::rand(&mut rng);
    let scalar_mul_ms = avg_ms(|| { let _ = base_g1.mul(scalar); });

    // ── pairing benchmark (degree-independent) ───────────────────────────────
    let p = E::G1Affine::rand(&mut rng);
    let q = E::G2Affine::rand(&mut rng);
    let pairing_ms = avg_ms(|| { let _ = E::pairing(p, q); });

    for &degree in DEGREES {
        let g1     = E::G1::rand(&mut rng);
        let g2     = E::G2::rand(&mut rng);
        let secret = E::ScalarField::rand(&mut rng);
        let poly: Vec<E::ScalarField> = (0..=degree)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();
        let point = E::ScalarField::rand(&mut rng);

        // ── setup ────────────────────────────────────────────────────────────
        let setup_ms = avg_ms(|| {
            let mut kzg = KZG::<E>::new(g1, g2, degree);
            kzg.setup(secret);
        });
        let mut kzg = KZG::<E>::new(g1, g2, degree);
        kzg.setup(secret);

        // ── commit ───────────────────────────────────────────────────────────
        let commit_ms = avg_ms(|| { let _ = kzg.commit(&poly); });
        let commitment = kzg.commit(&poly);

        // ── prove (open) ─────────────────────────────────────────────────────
        let prove_ms = avg_ms(|| { let _ = kzg.open(&poly, point); });
        let pi = kzg.open(&poly, point);

        // ── verify ───────────────────────────────────────────────────────────
        let value = evaluate(&poly, point);
        let verify_ms = avg_ms(|| { let _ = kzg.verify(point, value, commitment, pi); });

        println!(
            "{:<8} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>15.4} {:>13.4} {:>12}",
            degree, setup_ms, commit_ms, prove_ms, verify_ms,
            scalar_mul_ms, pairing_ms, proof_bytes
        );

        results.push(SingleResult {
            curve: curve_name.to_string(),
            degree,
            setup_ms,
            commit_ms,
            prove_ms,
            verify_ms,
            scalar_mul_ms,
            pairing_ms,
            proof_bytes,
        });
    }

    results
}

// ── Entry point ──────────────────────────────────────────────────────────────
pub fn run() {
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_bls12_377::Bls12_377;

    let mut all_results: Vec<SingleResult> = Vec::new();

    // BLS12-381: 48-byte G1 proof
    all_results.extend(run_for_curve::<Bls12_381>("BLS12-381", 48));

    // BN254: 32-byte G1 proof
    all_results.extend(run_for_curve::<Bn254>("BN254", 32));

    // BLS12-377: 48-byte G1 proof
    all_results.extend(run_for_curve::<Bls12_377>("BLS12-377", 48));

    // Save everything to one JSON
    let json = serde_json::to_string_pretty(&all_results).unwrap();
    fs::write("single_point_results.json", &json).unwrap();
    println!("\n✓ Saved to single_point_results.json");
}