// Run: cargo run
mod mle;
mod multilinear_kzg;

use multilinear_kzg::MultilinearKZG;

use ark_std::UniformRand;

use ark_bls12_381::{
    Bls12_381,
    Fr,
    G1Projective as G1,
    G2Projective as G2,
};

fn main() {

    let mut rng = ark_std::test_rng();

    // number of variables
    let num_vars = 5;

    // initialize multilinear KZG
    let mut mkzg =
        MultilinearKZG::<Bls12_381>::new(
            G1::rand(&mut rng),
            G2::rand(&mut rng),
            num_vars,
        );

    // toxic waste vector r
    let r =
        (0..num_vars)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // setup
    mkzg.setup(r);

    // evaluations over Boolean hypercube
    //
    // size = 2^num_vars
    //
    let evals =
        (0..(1 << num_vars))
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // commit
    let commitment =
        mkzg.commit(&evals);

    // random opening point
    let point =
        (0..num_vars)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // open
    let (value, proof) =
        mkzg.open(&evals, &point);

    // verify
    let ok =
        mkzg.verify(
            commitment,
            &point,
            value,
            &proof,
        );

    assert!(ok);
    println!("Multilinear KZG verified!");
}