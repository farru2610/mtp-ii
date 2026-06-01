use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use sha2::{Digest, Sha256};

// ────────────────────────────────────────────────────────────
//  PUBLIC PARAMETERS
// ────────────────────────────────────────────────────────────

pub struct BulletproofParams<G: CurveGroup> {
    pub g_vec: Vec<G>,
}


impl<G: CurveGroup> BulletproofParams<G> {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two(), "n must be a power of 2");
        let mut rng = ark_std::test_rng();
        let g_vec = (0..n).map(|_| G::rand(&mut rng)).collect();
        Self { g_vec }
    }
}

// ────────────────────────────────────────────────────────────
//  SHA-256 TRANSCRIPT  (Fiat-Shamir)
// ────────────────────────────────────────────────────────────

struct Transcript {
    items: Vec<Vec<u8>>,
}

impl Transcript {
    fn new() -> Self {
        Self { items: Vec::new() }
    }

    fn append(&mut self, data: &[u8]) {
        self.items.push(data.to_vec());
    }

    fn challenge<F: PrimeField>(&self) -> F {
        let mut hasher = Sha256::new();
        for item in &self.items {
            hasher.update(item);
        }
        let hash_bytes = hasher.finalize();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&hash_bytes);
        F::from_le_bytes_mod_order(&wide)
    }
}

// ────────────────────────────────────────────────────────────
//  INNER PRODUCT  <u, g> = Σ uᵢ · gᵢ
// ────────────────────────────────────────────────────────────

pub fn inner_product<G: CurveGroup>(
    scalars: &[G::ScalarField],
    points: &[G],
) -> G {
    assert_eq!(scalars.len(), points.len());

    // Convert projective points → affine points
    let affine_points: Vec<G::Affine> =
        points.iter().map(|p| p.into_affine()).collect();

    // Convert scalars into BigInts
    let scalar_bigints: Vec<<G::ScalarField as PrimeField>::BigInt> =
        scalars.iter().map(|s| s.into_bigint()).collect();

    // Pippenger MSM
    VariableBaseMSM::msm_bigint(&affine_points, &scalar_bigints)
}

// ────────────────────────────────────────────────────────────
//  PROOF STRUCTURES
// ────────────────────────────────────────────────────────────

pub struct Round<G: CurveGroup> {
    pub v_l: G,
    pub v_r: G,
}

pub struct BulletproofIPA<G: CurveGroup> {
    pub rounds: Vec<Round<G>>,
    pub u_bar:  G::ScalarField,
    pub g_bar:  G,
}

// ────────────────────────────────────────────────────────────
//  PROVER
// ────────────────────────────────────────────────────────────

pub fn prove<G: CurveGroup>(
    commitment: &G,
    u: Vec<G::ScalarField>,
    g: Vec<G>,
) -> BulletproofIPA<G> {
    let mut u = u;
    let mut g = g;
    let mut rounds = Vec::new();

    let mut transcript = Transcript::new();
    transcript.append(&serialize_point::<G>(&commitment.into_affine()));

    while u.len() > 1 {
        let half = u.len() / 2;

        let u_l = u[..half].to_vec();
        let u_r = u[half..].to_vec();
        let g_l = g[..half].to_vec();
        let g_r = g[half..].to_vec();

        let v_l = inner_product::<G>(&u_l, &g_r);
        let v_r = inner_product::<G>(&u_r, &g_l);

        transcript.append(&serialize_point::<G>(&v_l.into_affine()));
        transcript.append(&serialize_point::<G>(&v_r.into_affine()));

        let alpha: G::ScalarField = transcript.challenge();
        let alpha_inv = alpha.inverse().expect("alpha is non-zero");

        rounds.push(Round { v_l, v_r });

        u = u_l.iter().zip(u_r.iter())
            .map(|(ul, ur)| alpha * ul + alpha_inv * ur)
            .collect();

        g = g_l.iter().zip(g_r.iter())
            .map(|(gl, gr)| *gl * alpha_inv + *gr * alpha)
            .collect();
    }

    BulletproofIPA { rounds, u_bar: u[0], g_bar: g[0] }
}

// ────────────────────────────────────────────────────────────
//  VERIFIER
// ────────────────────────────────────────────────────────────

pub fn verify<G: CurveGroup>(
    params: &BulletproofParams<G>,
    commitment: G,
    proof: &BulletproofIPA<G>,
) -> bool {
    let mut g = params.g_vec.clone();
    let mut c = commitment;

    let mut transcript = Transcript::new();
    transcript.append(&serialize_point::<G>(&commitment.into_affine()));

    for round in &proof.rounds {
        transcript.append(&serialize_point::<G>(&round.v_l.into_affine()));
        transcript.append(&serialize_point::<G>(&round.v_r.into_affine()));

        let alpha: G::ScalarField = transcript.challenge();
        let alpha_inv = alpha.inverse().expect("alpha is non-zero");
        let alpha_sq     = alpha * alpha;
        let alpha_inv_sq = alpha_inv * alpha_inv;

        c = c + round.v_l * alpha_sq + round.v_r * alpha_inv_sq;

        let half = g.len() / 2;
        let g_l = g[..half].to_vec();
        let g_r = g[half..].to_vec();
        g = g_l.iter().zip(g_r.iter())
            .map(|(gl, gr)| *gl * alpha_inv + *gr * alpha)
            .collect();
    }

    let expected_c = g[0] * proof.u_bar;
    c == expected_c && g[0] == proof.g_bar
}

// ────────────────────────────────────────────────────────────
//  HELPERS
// ────────────────────────────────────────────────────────────

fn serialize_point<G: CurveGroup>(point: &G::Affine) -> Vec<u8> {
    format!("{:?}", point).into_bytes()
}
