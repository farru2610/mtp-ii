// Run: cargo run --bin bench_dory --features bench-dory --release
// Outputs: dory_results.json

#![allow(missing_docs)]

use std::fs;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use dory_pcs::backends::arkworks::{ArkFr, Blake2bTranscript, BN254, G1Routines, G2Routines};
use dory_pcs::backends::bls12_381::{
    Bls381Fr, Bls381G1Routines, Bls381G2Routines, BLS12_381,
};
use dory_pcs::backends::bls12_377::{
    Bls377Fr, Bls377G1Routines, Bls377G2Routines, BLS12_377,
};
use dory_pcs::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use dory_pcs::primitives::poly::{MultilinearLagrange, Polynomial};
use dory_pcs::primitives::transcript::Transcript;
use dory_pcs::primitives::{DoryDeserialize, DorySerialize};
use dory_pcs::proof::DoryProof;
use dory_pcs::setup::{ProverSetup, VerifierSetup};
use dory_pcs::{DoryError, Transparent};

// ── Sizes ────────────────────────────────────────────────────────────────────

const SIZES: &[usize] = &[4, 8, 16, 32, 64, 128, 256, 512, 1024];
const REPEATS: u32 = 5;

fn avg_ms<F: FnMut()>(mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..REPEATS { f(); }
    t.elapsed().as_secs_f64() * 1000.0 / REPEATS as f64
}

// ── Result type ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct DoryResult {
    pub curve:        String,
    pub n:            usize,
    pub log_n:        usize,
    pub nu:           usize,
    pub sigma:        usize,
    pub setup_ms:     f64,
    pub commit_ms:    f64,
    pub prove_ms:     f64,
    pub verify_ms:    f64,
    pub pairing_ms:   f64,
    pub msm_g1_ms:    f64,
    pub msm_g2_ms:    f64,
    pub proof_bytes:  usize,
}

// ── Generic polynomial (defined here so commit works for any field) ───────────

struct GenericPoly<F: Field> {
    coeffs: Vec<F>,
    num_vars: usize,
}

impl<F: Field> GenericPoly<F> {
    fn new(coeffs: Vec<F>) -> Self {
        let len = coeffs.len();
        let num_vars = usize::BITS as usize - 1 - len.leading_zeros() as usize;
        assert_eq!(1 << num_vars, len, "length must be a power of 2");
        Self { coeffs, num_vars }
    }

    fn lagrange_basis(point: &[F]) -> Vec<F> {
        let n = 1 << point.len();
        let mut b = vec![F::zero(); n];
        if point.is_empty() { b[0] = F::one(); return b; }
        b[0] = F::one() - point[0];
        if n > 1 { b[1] = point[0]; }
        for (level, p) in point[1..].iter().enumerate() {
            let mid = 1 << (level + 1);
            let omp = F::one() - *p;
            let (left, right) = b.split_at_mut(mid);
            let k = left.len().min(right.len());
            for (l, r) in left[..k].iter_mut().zip(right[..k].iter_mut()) {
                let lv = *l;
                *r = lv.mul(p);
                *l = lv.mul(&omp);
            }
            for l in left[k..].iter_mut() { *l = l.mul(&omp); }
        }
        b
    }
}

impl<F: Field> Polynomial<F> for GenericPoly<F> {
    fn num_vars(&self) -> usize { self.num_vars }

    fn evaluate(&self, point: &[F]) -> F {
        let basis = Self::lagrange_basis(point);
        let mut result = F::zero();
        for (c, b) in self.coeffs.iter().zip(basis.iter()) {
            result = result + c.mul(b);
        }
        result
    }

    fn commit<E, Mo, M1>(
        &self,
        nu: usize,
        sigma: usize,
        setup: &ProverSetup<E>,
    ) -> Result<(E::GT, Vec<E::G1>, F), DoryError>
    where
        E: PairingCurve,
        Mo: dory_pcs::mode::Mode,
        M1: DoryRoutines<E::G1>,
        E::G1: Group<Scalar = F>,
        E::GT: Group<Scalar = F>,
    {
        let expected = 1 << (nu + sigma);
        if self.coeffs.len() != expected {
            return Err(DoryError::InvalidSize { expected, actual: self.coeffs.len() });
        }
        let num_rows = 1 << nu;
        let num_cols = 1 << sigma;
        let g1 = &setup.g1_vec[..num_cols];
        let row_commitments: Vec<E::G1> = (0..num_rows)
            .map(|i| M1::msm(g1, &self.coeffs[i * num_cols..(i + 1) * num_cols]))
            .collect();
        let tier2 = E::multi_pair_g2_setup(&row_commitments, &setup.g2_vec[..num_rows]);
        let r: F = Mo::sample();
        let commitment = Mo::mask(tier2, &setup.ht, &r);
        Ok((commitment, row_commitments, r))
    }
}

impl<F: Field> MultilinearLagrange<F> for GenericPoly<F> {
    fn vector_matrix_product(&self, left: &[F], nu: usize, sigma: usize) -> Vec<F> {
        let nc = 1 << sigma;
        let nr = 1 << nu;
        let mut v = vec![F::zero(); nc];
        for (j, vj) in v.iter_mut().enumerate() {
            let mut s = F::zero();
            for (i, lv) in left.iter().enumerate().take(nr) {
                let idx = i * nc + j;
                if idx < self.coeffs.len() { s = s + lv.mul(&self.coeffs[idx]); }
            }
            *vj = s;
        }
        v
    }
}

// ── Proof-size helper ─────────────────────────────────────────────────────────

fn proof_bytes<G1, G2, GT>(proof: &DoryProof<G1, G2, GT>) -> usize
where
    G1: Group + DorySerialize,
    G2: Group + DorySerialize,
    GT: Group + DorySerialize,
{
    let rounds = proof.first_messages.len();

    // VMV: c (GT), d2 (GT), e1 (G1)
    let gt_size = proof.vmv_message.c.compressed_size();
    let g1_size = proof.vmv_message.e1.compressed_size();
    let g2_size = if let Some(m) = proof.first_messages.first() {
        m.e2_beta.compressed_size()
    } else {
        proof.final_message.e2.compressed_size()
    };

    let vmv   = 2 * gt_size + g1_size;
    let first = rounds * (4 * gt_size + g1_size + g2_size);
    let second = rounds * (2 * gt_size + 2 * g1_size + 2 * g2_size);
    let fin   = g1_size + g2_size;
    vmv + first + second + fin
}

// ── Generic benchmark loop ────────────────────────────────────────────────────

fn run_for_curve<F, E, M1, M2>(curve_name: &str) -> Vec<DoryResult>
where
    F: Field + DorySerialize + DoryDeserialize,
    E: PairingCurve + Clone,
    E::G1: Group<Scalar = F> + DorySerialize + DoryDeserialize,
    E::G2: Group<Scalar = F> + DorySerialize + DoryDeserialize,
    E::GT: Group<Scalar = F> + DorySerialize + DoryDeserialize,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    ProverSetup<E>: DorySerialize + DoryDeserialize,
    VerifierSetup<E>: DorySerialize + DoryDeserialize,
    Blake2bTranscript<E>: Transcript<Curve = E>,
{
    println!("\nDory PCS Benchmark ({})", curve_name);
    println!(
        "{:<8} {:>10} {:>10} {:>10} {:>10} {:>12} {:>11} {:>11} {:>12}",
        "n", "setup(ms)", "commit(ms)", "prove(ms)", "verify(ms)",
        "pairing(ms)", "msm_g1(ms)", "msm_g2(ms)", "proof(bytes)"
    );
    println!("{}", "-".repeat(110));

    let mut results = Vec::new();

    for &n in SIZES {
        let log_n = usize::BITS as usize - 1 - n.leading_zeros() as usize;
        let nu    = log_n / 2;
        let sigma = log_n - nu; // sigma >= nu

        // ── setup ────────────────────────────────────────────────────────────
        let setup_ms = avg_ms(|| {
            let ps = ProverSetup::<E>::new(log_n);
            let _ = ps.to_verifier_setup();
        });
        let prover_setup   = ProverSetup::<E>::new(log_n);
        let verifier_setup = prover_setup.to_verifier_setup();

        // ── polynomial + point ───────────────────────────────────────────────
        let coeffs: Vec<F> = (0..n).map(|_| F::random()).collect();
        let poly  = GenericPoly::new(coeffs);
        let point: Vec<F> = (0..log_n).map(|_| F::random()).collect();

        // ── commit ───────────────────────────────────────────────────────────
        let commit_ms = avg_ms(|| {
            let _ = poly.commit::<E, Transparent, M1>(nu, sigma, &prover_setup);
        });
        let (commitment, row_commitments, commit_blind) =
            poly.commit::<E, Transparent, M1>(nu, sigma, &prover_setup).unwrap();
        let evaluation = poly.evaluate(&point);

        // ── prove ────────────────────────────────────────────────────────────
        let prove_ms = avg_ms(|| {
            let mut t = Blake2bTranscript::<E>::new(b"dory-bench");
            let _ = dory_pcs::prove::<F, E, M1, M2, GenericPoly<F>, _, Transparent>(
                &poly, &point, row_commitments.clone(), commit_blind,
                nu, sigma, &prover_setup, &mut t,
            );
        });
        let mut t = Blake2bTranscript::<E>::new(b"dory-bench");
        let (proof, _) = dory_pcs::prove::<F, E, M1, M2, GenericPoly<F>, _, Transparent>(
            &poly, &point, row_commitments.clone(), commit_blind,
            nu, sigma, &prover_setup, &mut t,
        ).unwrap();

        // ── verify ───────────────────────────────────────────────────────────
        let verify_ms = avg_ms(|| {
            let mut t = Blake2bTranscript::<E>::new(b"dory-bench");
            let _ = dory_pcs::verify::<F, E, M1, M2, _>(
                commitment, evaluation, &point, &proof,
                verifier_setup.clone(), &mut t,
            );
        });

        // ── pairing (atomic cost, like scalar_mul in Bulletproofs) ───────────
        let g1 = E::G1::random();
        let g2 = E::G2::random();
        let pairing_ms = avg_ms(|| { let _ = E::pair(&g1, &g2); });

        // ── MSM G1 ───────────────────────────────────────────────────────────
        let scalars: Vec<F>     = (0..n).map(|_| F::random()).collect();
        let g1_pts: Vec<E::G1>  = (0..n).map(|_| E::G1::random()).collect();
        let g2_pts: Vec<E::G2>  = (0..n).map(|_| E::G2::random()).collect();
        let msm_g1_ms = avg_ms(|| { let _ = M1::msm(&g1_pts, &scalars); });
        let msm_g2_ms = avg_ms(|| { let _ = M2::msm(&g2_pts, &scalars); });

        // ── proof size ───────────────────────────────────────────────────────
        let proof_bytes = proof_bytes::<E::G1, E::G2, E::GT>(&proof);

        println!(
            "{:<8} {:>10.3} {:>10.3} {:>10.3} {:>10.3} {:>12.4} {:>11.4} {:>11.4} {:>12}",
            n, setup_ms, commit_ms, prove_ms, verify_ms,
            pairing_ms, msm_g1_ms, msm_g2_ms, proof_bytes
        );

        results.push(DoryResult {
            curve: curve_name.to_string(),
            n, log_n, nu, sigma,
            setup_ms, commit_ms, prove_ms, verify_ms,
            pairing_ms, msm_g1_ms, msm_g2_ms, proof_bytes,
        });
    }

    results
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let mut all: Vec<DoryResult> = Vec::new();

    all.extend(run_for_curve::<Bls381Fr, BLS12_381, Bls381G1Routines, Bls381G2Routines>("BLS12-381"));
    all.extend(run_for_curve::<ArkFr,   BN254,    G1Routines,      G2Routines      >("BN-254"));
    all.extend(run_for_curve::<Bls377Fr, BLS12_377, Bls377G1Routines, Bls377G2Routines>("BLS12-377"));

    let json = serde_json::to_string_pretty(&all).unwrap();
    fs::write("dory_results.json", &json).unwrap();
    println!("\nSaved to dory_results.json");
}
