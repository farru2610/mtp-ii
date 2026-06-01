// Run: cargo run  |  cargo run --release --bin bench
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{VariableBaseMSM, CurveGroup};
use ark_ff::{Field, Zero};
use std::ops::Mul;

use crate::mle::{eq_poly, evaluate_mle};

pub struct MultilinearKZG<E: Pairing> {

    pub g1: E::G1,
    pub g2: E::G2,

    pub num_vars: usize,

    /// g^{χ_b(r)} for each b ∈ {0,1}^l
    pub srs_g1: Vec<E::G1>,

    /// g2^{r_i} for each i = 0..l-1
    pub g2_r: Vec<E::G2>,
}

impl<E: Pairing> MultilinearKZG<E> {

    pub fn new(
        g1: E::G1,
        g2: E::G2,
        num_vars: usize,
    ) -> Self {

        Self {
            g1,
            g2,
            num_vars,
            srs_g1: vec![],
            g2_r: vec![],
        }
    }

    /// Setup phase
    ///
    /// Builds the SRS from the toxic waste r, then r is dropped
    ///
    /// SRS in G1:  g1^{χ_b(r)}  for each b ∈ {0,1}^l
    /// SRS in G2:  g2^{r_i}     for each i = 0..l-1
    ///
    pub fn setup(
        &mut self,
        r: Vec<E::ScalarField>,
    ) {

        assert_eq!(r.len(), self.num_vars);

        let num_evals = 1 << self.num_vars;

        for i in 0..num_evals {

            let mut bits =
                vec![E::ScalarField::ZERO; self.num_vars];

            for j in 0..self.num_vars {
                if ((i >> j) & 1) == 1 {
                    bits[j] = E::ScalarField::ONE;
                }
            }

            let chi = eq_poly(&bits, &r);

            self.srs_g1.push(
                self.g1.mul(chi)
            );
        }

        for ri in r.iter() {
            self.g2_r.push(
                self.g2.mul(*ri)
            );
        }

        // The toxic waste never leaves this function.
    }

    /// Commit:
    ///
    /// C = Σ_b f(b) · g1^{χ_b(r)} = g1^{f(r)}
    ///
    pub fn commit(
        &self,
        evals: &[E::ScalarField],
    ) -> E::G1 {

        assert_eq!(
            evals.len(),
            self.srs_g1.len()
        );

        let bases: Vec<_> = self.srs_g1
            .iter()
            .map(|p| p.into_affine())
            .collect();

        E::G1::msm(&bases, evals).unwrap()
    }

    /// SRS-only witness computation — no knowledge of r required.
    ///
    /// Uses a bookkeeping table that is halved each step.
    ///
    /// At step i, the table holds:
    ///   table[b_{i},...,b_{l-1}] = f(z_0,...,z_{i-1}, b_i,...,b_{l-1})
    ///
    /// The quotient q_i depends only on variables x_{i+1},...,x_{l-1}:
    ///   q_i(b_{i+1},...,b_{l-1}) = table[1, b_{i+1},...] − table[0, b_{i+1},...]
    ///
    /// The proof element is:
    ///   π_i = Σ_{idx} q_i(bits_{i+1..l-1}(idx)) · srs_g1[idx]
    ///
    /// This is valid because:
    ///   Σ_{c ∈ {0,1}^{i+1}} χ_{(c, b)}(r) = χ_b(r_{i+1},...,r_{l-1})
    ///
    pub fn compute_witnesses(
        &self,
        evals: &[E::ScalarField],
        point: &[E::ScalarField],
    ) -> Vec<E::G1> {

        // Convert SRS to affine once — reused for every MSM in the loop.
        let bases: Vec<_> = self.srs_g1
            .iter()
            .map(|p| p.into_affine())
            .collect();

        let mut proofs = vec![];

        // table[j] = f(z_0,...,z_{i-1}, bit_0(j), bit_1(j), ..., bit_{l-i-1}(j))
        // starts as the full evaluation table (i = 0, no variables fixed yet)
        let mut table = evals.to_vec();

        for i in 0..self.num_vars {

            let half = table.len() / 2;
            let upper_bits = self.num_vars - i - 1;

            // Build weight vector for the MSM.
            //
            // For srs_g1[idx], weight = q_i(b_{i+1},...,b_{l-1})
            //                         = table[2j+1] − table[2j]
            //
            // where j encodes bits i+1,...,l-1 of idx:
            //   j = (idx >> (i+1)) & mask
            //
            let mut weights = vec![E::ScalarField::ZERO; 1 << self.num_vars];

            for idx in 0..(1usize << self.num_vars) {
                let j = if upper_bits == 0 {
                    0
                } else {
                    (idx >> (i + 1)) & ((1 << upper_bits) - 1)
                };
                weights[idx] = table[2 * j + 1] - table[2 * j];
            }

            proofs.push(E::G1::msm(&bases, &weights).unwrap());

            // Fix variable i to z_i for the next iteration:
            //   next[j] = (1 - z_i) · table[2j]  +  z_i · table[2j+1]
            let zi = point[i];
            table = (0..half)
                .map(|j| {
                    (E::ScalarField::ONE - zi) * table[2 * j]
                        + zi * table[2 * j + 1]
                })
                .collect();
        }

        // Sanity: after all l steps, table has one entry = f(z_0,...,z_{l-1})

        proofs
    }

    /// Open polynomial at point z.
    ///
    /// Returns (value, proofs) where proofs are G1 elements
    ///
    pub fn open(
        &self,
        evals: &[E::ScalarField],
        point: &[E::ScalarField],
    ) -> (
        E::ScalarField,
        Vec<E::G1>,
    ) {

        let value = evaluate_mle(evals, point);
        let proofs = self.compute_witnesses(evals, point);

        (value, proofs)
    }

    /// Verify multilinear KZG proof:
    ///
    /// e(C - g1^v, g2)  =  Π_i e(π_i, g2^{r_i} − g2^{z_i})
    ///
    pub fn verify(
        &self,
        commitment: E::G1,
        point: &[E::ScalarField],
        value: E::ScalarField,
        proofs: &[E::G1],
    ) -> bool {

        // e(C - g1^v, g2)
        let lhs =
            E::pairing(
                commitment - self.g1.mul(value),
                self.g2,
            );

        // Π_i e(π_i, g2^{r_i - z_i})
        // PairingOutput uses additive notation for G_T:
        //   zero()  = multiplicative identity (1 in G_T)
        //   a + b   = a · b in G_T
        let mut rhs = PairingOutput::<E>::zero();

        for i in 0..self.num_vars {
            rhs += E::pairing(
                proofs[i],
                self.g2_r[i] - self.g2.mul(point[i]),
            );
        }

        lhs == rhs
    }
}
