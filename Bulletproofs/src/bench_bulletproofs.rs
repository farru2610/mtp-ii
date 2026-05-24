// Run: cargo run --release --bin bench_bulletproofs
// Outputs: bulletproofs_results.json

mod bulletproofs;
use bulletproofs::{BulletproofParams, inner_product, prove, verify};

use std::time::Instant;
use std::fs;
use serde::{Serialize, Deserialize};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_std::UniformRand;

#[derive(Serialize, Deserialize, Debug)]
pub struct BulletproofResult {
    pub curve:           String,
    pub n:               usize,
    pub setup_ms:        f64,
    pub commit_ms:       f64,
    pub prove_ms:        f64,
    pub verify_ms:       f64,
    pub scalar_mul_ms:   f64,
    pub msm_ms:          f64,
    pub proof_bytes:     usize,
}

const SIZES: &[usize] = &[4, 8, 16, 32, 64, 128, 256, 512, 1024];
const REPEATS: u32 = 10;

fn avg_ms<F: FnMut()>(mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..REPEATS { f(); }
    t.elapsed().as_secs_f64() * 1000.0 / REPEATS as f64
}

// ── Generic function — works for ANY curve ──────────────────────────────────
fn run_for_curve<G: CurveGroup>(curve_name: &str) -> Vec<BulletproofResult>
where
    G::ScalarField: UniformRand,
{
    println!("\nBulletproofs IPA Benchmark ({})", curve_name);
    println!(
        "{:<8} {:>10} {:>10} {:>10} {:>10} {:>15} {:>10} {:>12}",
        "n", "setup(ms)", "commit(ms)", "prove(ms)", "verify(ms)",
        "scalar_mul(ms)", "msm(ms)", "proof(bytes)"
    );
    println!("{}", "-".repeat(95));

    let mut rng = ark_std::test_rng();
    let mut results = Vec::new();

    // ── scalar multiplication benchmark (size-independent) ──────────────────
    let base = G::rand(&mut rng);
    let scalar = G::ScalarField::rand(&mut rng);
    let scalar_mul_ms = avg_ms(|| { let _ = base * scalar; });

    for &n in SIZES {
        // ── msm benchmark (size-dependent) ──────────────────────────────────
        let msm_scalars: Vec<G::ScalarField> =
            (0..n).map(|_| G::ScalarField::rand(&mut rng)).collect();
        let msm_points: Vec<G::Affine> =
            (0..n).map(|_| G::rand(&mut rng).into_affine()).collect();
        let msm_bigints: Vec<<G::ScalarField as PrimeField>::BigInt> =
            msm_scalars.iter().map(|s| s.into_bigint()).collect();
        let msm_ms = avg_ms(|| {
            let _ = <G as VariableBaseMSM>::msm_bigint(&msm_points, &msm_bigints);
        });

        // ── setup ────────────────────────────────────────────────────────────
        let setup_ms = avg_ms(|| { let _ = BulletproofParams::<G>::new(n); });
        let params = BulletproofParams::<G>::new(n);

        // ── commit ───────────────────────────────────────────────────────────
        let u: Vec<G::ScalarField> =
            (0..n).map(|_| G::ScalarField::rand(&mut rng)).collect();
        let commit_ms = avg_ms(|| {
            let _ = inner_product::<G>(&u, &params.g_vec);
        });
        let commitment = inner_product::<G>(&u, &params.g_vec);

        // ── prove ────────────────────────────────────────────────────────────
        let prove_ms = avg_ms(|| {
            let _ = prove::<G>(&commitment, u.clone(), params.g_vec.clone());
        });
        let proof = prove::<G>(&commitment, u.clone(), params.g_vec.clone());

        // ── verify ───────────────────────────────────────────────────────────
        let verify_ms = avg_ms(|| {
            let _ = verify::<G>(&params, commitment, &proof);
        });

        let point_size  = std::mem::size_of::<G::Affine>();
        let scalar_size = std::mem::size_of::<G::ScalarField>();
        let num_rounds  = (n as f64).log2() as usize;
        let proof_bytes = num_rounds * 2 * point_size + scalar_size + point_size;

        println!(
            "{:<8} {:>10.3} {:>10.3} {:>10.3} {:>10.3} {:>15.4} {:>10.4} {:>12}",
            n, setup_ms, commit_ms, prove_ms, verify_ms,
            scalar_mul_ms, msm_ms, proof_bytes
        );

        results.push(BulletproofResult {
            curve: curve_name.to_string(),
            n,
            setup_ms,
            commit_ms,
            prove_ms,
            verify_ms,
            scalar_mul_ms,
            msm_ms,
            proof_bytes,
        });
    }

    results
}

// ── Entry point ──────────────────────────────────────────────────────────────
fn main() {
    use ark_bls12_381::G1Projective as BLS381;
    use ark_bn254::G1Projective     as BN254;
    use ark_bls12_377::G1Projective as BLS377;

    let mut all_results: Vec<BulletproofResult> = Vec::new();

    all_results.extend(run_for_curve::<BLS381>("BLS12-381"));
    all_results.extend(run_for_curve::<BN254>("BN-254"));
    all_results.extend(run_for_curve::<BLS377>("BLS12-377"));

    let json = serde_json::to_string_pretty(&all_results).unwrap();
    fs::write("bulletproofs_results.json", &json).unwrap();
    println!("\n✓ Saved to bulletproofs_results.json");
}
