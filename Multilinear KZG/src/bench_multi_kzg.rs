// Run: cargo run --release --bin bench
use std::time::Instant;
use std::fs;
use serde::{Serialize, Deserialize};
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use std::ops::Mul;

use crate::multilinear_kzg::MultilinearKZG;

#[derive(Serialize, Deserialize, Debug)]
pub struct MultiResult {
    pub curve:          String,
    pub num_vars:       usize,
    pub poly_size:      usize,   // 2^num_vars  — number of evaluations
    pub setup_ms:       f64,
    pub commit_ms:      f64,
    pub prove_ms:       f64,
    pub verify_ms:      f64,
    pub scalar_mul_ms:  f64,     // single G1 scalar-mul (curve baseline)
    pub pairing_ms:     f64,     // single pairing        (curve baseline)
    pub proof_bytes:    usize,   // num_vars * g1_point_bytes
}

// num_vars=16  →  poly_size=65536.
const NUM_VARS: &[usize] = &[2, 4, 6, 8, 10, 12, 14];
// const NUM_VARS: &[usize] = &[16, 18];

const REPEATS: u32 = 5;

// ── Timing helper ─────────────────────────────────────────────────────────────
fn avg_ms<F: FnMut()>(mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..REPEATS { f(); }
    t.elapsed().as_secs_f64() * 1000.0 / REPEATS as f64
}

// ── Generic benchmark — works for any pairing-friendly curve ─────────────────
fn run_for_curve<E: Pairing>(
    curve_name:     &str,
    g1_point_bytes: usize,   // compressed G1 size: 48 for BLS12-381/377, 32 for BN254
) -> Vec<MultiResult>
where
    E::G1:         UniformRand + Copy,
    E::G2:         UniformRand + Copy,
    E::ScalarField: UniformRand + Copy,
    E::G1Affine:   UniformRand,
    E::G2Affine:   UniformRand,
{
    println!("\nMultilinear KZG Benchmark  ({})", curve_name);
    println!(
        "{:<10} {:>10} {:>12} {:>10} {:>10} {:>10} {:>15} {:>13} {:>12}",
        "num_vars", "poly_size", "setup(ms)", "commit(ms)",
        "prove(ms)", "verify(ms)", "scalar_mul(ms)", "pairing(ms)", "proof(bytes)"
    );
    println!("{}", "-".repeat(115));

    let mut rng     = ark_std::test_rng();
    let mut results = Vec::new();

    // ── Curve-level baselines (independent of num_vars) ──────────────────────
    let base_g1 = E::G1::rand(&mut rng);
    let scalar   = E::ScalarField::rand(&mut rng);
    let scalar_mul_ms = avg_ms(|| { let _ = base_g1.mul(scalar); });

    let p = E::G1Affine::rand(&mut rng);
    let q = E::G2Affine::rand(&mut rng);
    let pairing_ms = avg_ms(|| { let _ = E::pairing(p, q); });

    // ── Per-num_vars loop ─────────────────────────────────────────────────────
    for &num_vars in NUM_VARS {

        let poly_size   = 1 << num_vars;          // 2^num_vars evaluations
        let proof_bytes = num_vars * g1_point_bytes; // l proof elements

        let g1 = E::G1::rand(&mut rng);
        let g2 = E::G2::rand(&mut rng);

        // Toxic waste — cloned inside avg_ms because setup takes ownership.
        let r: Vec<E::ScalarField> = (0..num_vars)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        // Random evaluation table (the polynomial).
        let evals: Vec<E::ScalarField> = (0..poly_size)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        // Random opening point.
        let point: Vec<E::ScalarField> = (0..num_vars)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        // ── setup ─────────────────────────────────────────────────────────────
        // A fresh MultilinearKZG is created each repeat because setup
        // consumes r (the toxic waste is moved in and dropped).
        let setup_ms = avg_ms(|| {
            let mut mkzg = MultilinearKZG::<E>::new(g1, g2, num_vars);
            mkzg.setup(r.clone());
        });
        let mut mkzg = MultilinearKZG::<E>::new(g1, g2, num_vars);
        mkzg.setup(r.clone());

        // ── commit ────────────────────────────────────────────────────────────
        let commit_ms = avg_ms(|| { let _ = mkzg.commit(&evals); });
        let commitment = mkzg.commit(&evals);

        // ── prove (open) ──────────────────────────────────────────────────────
        // open() = evaluate_mle  +  compute_witnesses (l MSMs of size 2^l)
        let prove_ms = avg_ms(|| { let _ = mkzg.open(&evals, &point); });
        let (value, proof) = mkzg.open(&evals, &point);

        // ── verify ────────────────────────────────────────────────────────────
        // verify() does l+1 pairing operations
        let verify_ms = avg_ms(|| {
            let _ = mkzg.verify(commitment, &point, value, &proof);
        });

        println!(
            "{:<10} {:>10} {:>12.3} {:>10.3} {:>10.3} {:>10.3} {:>15.4} {:>13.4} {:>12}",
            num_vars, poly_size,
            setup_ms, commit_ms, prove_ms, verify_ms,
            scalar_mul_ms, pairing_ms, proof_bytes
        );

        results.push(MultiResult {
            curve: curve_name.to_string(),
            num_vars,
            poly_size,
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

// ── Entry point ───────────────────────────────────────────────────────────────
pub fn run() {
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_bls12_377::Bls12_377;

    let mut all: Vec<MultiResult> = Vec::new();

    // Compressed G1 sizes:  BLS12-381 = 48 bytes,  BN254 = 32 bytes,  BLS12-377 = 48 bytes
    all.extend(run_for_curve::<Bls12_381>("BLS12-381", 48));
    all.extend(run_for_curve::<Bn254>    ("BN254",     32));
    all.extend(run_for_curve::<Bls12_377>("BLS12-377", 48));

    let json = serde_json::to_string_pretty(&all).unwrap();
    fs::write("multilinear_kzg_results.json", &json).unwrap();
    println!("\nSaved to multilinear_kzg_results.json");
}
