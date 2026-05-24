// cargo run

pub mod bulletproofs;
use bulletproofs::{BulletproofParams, BulletproofIPA, inner_product, prove, verify};
use ark_bls12_381::{G1Projective as BLS381, Fr};
use ark_std::UniformRand;

fn main() {
    // initialize bulletproof params
    let mut rng = ark_std::test_rng();
    let n = 8;
    let params = BulletproofParams::<BLS381>::new(n);

    // generate a random vector and commit to it
    let u: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let commitment = inner_product::<BLS381>(&u, &params.g_vec);

    // test single proof
    test_single_proof(&params, u, commitment);
}

pub fn test_single_proof(
    params: &BulletproofParams<BLS381>,
    u: Vec<Fr>,
    commitment: BLS381,
) {
    // generate a proof and verify it
    let proof: BulletproofIPA<BLS381> = prove::<BLS381>(&commitment, u, params.g_vec.clone());
    let valid = verify::<BLS381>(params, commitment, &proof);

    assert!(valid, "Bulletproof verification failed!");
    println!("Single instance Bulletproof IPA verified!");
}
