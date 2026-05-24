// Run: cargo run  |  cargo run --release --bin bench
use ark_ff::Field;

/// Computes multilinear Lagrange basis polynomial:
///
/// χ_b(x) = Π_i [ x_i*b_i + (1-x_i)(1-b_i) ]
///
pub fn eq_poly<F: Field>(
    b: &[F],
    x: &[F],
) -> F {
    assert_eq!(b.len(), x.len());

    let mut result = F::ONE;

    for i in 0..b.len() {
        result *=
            b[i] * x[i]
            + (F::ONE - b[i]) * (F::ONE - x[i]);
    }

    result
}

/// Evaluate multilinear polynomial from evaluations over Boolean hypercube.
///
/// evals length must be 2^num_vars.
///
/// Example:
///
/// num_vars = 2
///
/// index:
/// 0 -> (0,0)
/// 1 -> (0,1)
/// 2 -> (1,0)
/// 3 -> (1,1)
///
pub fn evaluate_mle<F: Field>(
    evals: &[F],
    point: &[F],
) -> F {

    let num_vars = point.len();

    assert_eq!(evals.len(), 1 << num_vars);

    let mut result = F::ZERO;

    for i in 0..evals.len() {

        let mut bits = vec![F::ZERO; num_vars];

        for j in 0..num_vars {
            if ((i >> j) & 1) == 1 {
                bits[j] = F::ONE;
            }
        }

        let chi = eq_poly(&bits, point);

        result += evals[i] * chi;
    }

    result
}