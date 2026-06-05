# MTP-II — Polynomial Commitment Schemes & Proof Systems

Rust implementations of four cryptographic proof protocols, each benchmarked across three elliptic curves. Built using the [arkworks](https://arkworks.rs) ecosystem.

---

## Protocols

| Protocol | Type | Setup | Proof Size | Verify |
|---|---|---|---|---|
| [KZG](KZG/) | Univariate polynomial commitment | Trusted (SRS) | **O(1)** — constant 1 point | O(1) — 2 pairings |
| [Multilinear KZG](Multilinear%20KZG/) | Multilinear polynomial commitment | Trusted (SRS) | O(l) — l points | O(l) — l+1 pairings |
| [Bulletproofs IPA](Bulletproofs/) | Inner product argument | Transparent | O(log n) | O(n) |
| [Dory](dory-main/) | Multilinear polynomial commitment | Transparent | O(log n) | O(log n) |

> **Note:** The Dory implementation is **not original code**. It is used here solely for benchmarking purposes.
> Credit: Markos Georghiades (a16z) — [github.com/a16z/dory](https://github.com/a16z/dory), licensed Apache-2.0 / MIT.

---

## Curves

All protocols are generic over the curve and were benchmarked on:

| Curve | Field Size | Security | G1 Point |
|---|---|---|---|
| **BLS12-381** | 381 bits | ~128-bit | 48 bytes |
| **BN-254** | 254 bits | ~100-bit | 32 bytes |
| **BLS12-377** | 377 bits | ~128-bit | 48 bytes |

BN-254 is the fastest (smaller field arithmetic) at a modest security trade-off. BLS12-381 and BLS12-377 offer similar 128-bit security with different pairing properties.

---

## Repository Structure

```
MTP-II/
├── KZG/                        ← Univariate KZG commitment scheme
│   ├── src/
│   │   ├── kzg.rs              ← Core protocol (setup, commit, prove, verify)
│   │   ├── utils.rs            ← Polynomial arithmetic (div, mul, interpolate)
│   │   ├── bench_single.rs     ← Multi-curve benchmark logic
│   │   ├── bench_single_main.rs← Benchmark binary entry point
│   │   └── main.rs             ← Correctness test
│   ├── single_point_results.json
│   └── README.md
│
├── Multilinear KZG/            ← Multilinear extension of KZG
│   ├── src/
│   │   ├── multilinear_kzg.rs  ← Core protocol (generic over pairing curves)
│   │   ├── mle.rs              ← MLE helpers (eq_poly, evaluate_mle)
│   │   ├── bench_multi_kzg.rs  ← Multi-curve benchmark logic
│   │   ├── bench_main.rs       ← Benchmark binary entry point
│   │   └── main.rs             ← Correctness test
│   ├── multilinear_kzg_results.json
│   └── README.md
│
├── Bulletproofs/               ← Bulletproofs inner product argument
│   ├── src/
│   │   ├── bulletproofs.rs     ← Core IPA protocol (generic over any curve)
│   │   ├── bench_bulletproofs.rs← Multi-curve benchmark logic
│   │   └── main.rs             ← Correctness test
│   ├── bulletproofs_results.json
│   └── README.md
│
└── dory-main/                  ← Dory transparent multilinear PCS — credit: Markos Georghiades (a16z/dory); used for benchmarking only
    ├── src/
    │   ├── setup.rs            ← Prover/Verifier setup, Δ/χ preprocessing
    │   ├── reduce_and_fold.rs  ← Protocol 14 prover + verifier state machines
    │   ├── evaluation_proof.rs ← Full Eval-VMV-RE protocol, Fiat-Shamir wrapping
    │   ├── proof.rs            ← Proof structs
    │   ├── messages.rs         ← Per-round message types
    │   ├── primitives/         ← Traits: fields, groups, pairings, transcript
    │   ├── backends/arkworks/  ← Concrete curve backends (BLS12-381, BLS12-377, BN-254)
    │   └── bin/bench_dory.rs   ← Multi-curve benchmark binary
    ├── dory_results.json
    ├── dory_plots/             ← Benchmark plots per curve
    └── DORY_ANALYSIS.md        ← Theory ↔ code correspondence analysis
```

---

## Quick Start

Each sub-project is an independent Cargo workspace. `cd` into the desired directory and run:

```bash
# Correctness test (verifies the protocol produces valid proofs)
cargo run

# Performance benchmark (release mode required for accurate timings)
cargo run --release --bin <bench_binary>
```

| Project | Bench binary |
|---|---|
| `KZG/` | `bench_single` |
| `Multilinear KZG/` | `bench` |
| `Bulletproofs/` | `bench_bulletproofs` |
| `dory-main/` | `bench_dory` |

Results are printed to stdout and saved to a `.json` file in the project directory.

---

## Benchmark Highlights

All timings are wall-clock averages over multiple repetitions, compiled in release mode on the same machine.

### KZG — Univariate (single_point_results.json)

Constant-size proofs regardless of polynomial degree.

| Curve | Degree | Setup (ms) | Commit (ms) | Prove (ms) | Verify (ms) | Proof |
|---|---|---|---|---|---|---|
| BLS12-381 | 256 | 225.7 | 12.8 | 12.3 | 3.6 | 48 B |
| BN-254 | 256 | 119.9 | 6.4 | 6.6 | 2.4 | **32 B** |
| BLS12-377 | 256 | 263.9 | 13.1 | 12.7 | 4.3 | 48 B |

Verify time is **constant** (~3.5 ms on BLS12-381) regardless of degree — dominated by two pairing evaluations.

### Multilinear KZG (multilinear_kzg_results.json)

Polynomial has 2^l evaluations; proof has l elements.

| Curve | num_vars (l) | poly_size | Setup (ms) | Commit (ms) | Prove (ms) | Verify (ms) | Proof |
|---|---|---|---|---|---|---|---|
| BLS12-381 | 10 | 1 024 | 235.9 | 39.5 | 263.4 | 21.8 | 480 B |
| BLS12-381 | 12 | 4 096 | 911.3 | 134.0 | 1 039.6 | 26.5 | 576 B |
| BN-254 | 12 | 4 096 | 501.4 | 69.7 | 543.6 | 17.4 | 384 B |
| BLS12-377 | 14 | 16 384 | 4 034.8 | 547.5 | 5 249.2 | 38.9 | 672 B |

Verify grows only as O(l) (logarithmic in poly size) — well-suited for large polynomials.

### Bulletproofs IPA (bulletproofs_results.json)

Transparent setup (no trusted party). Proof size and verify both grow with n.

| Curve | n | Setup (ms) | Commit (ms) | Prove (ms) | Verify (ms) | Proof |
|---|---|---|---|---|---|---|
| BLS12-381 | 256 | 37.5 | 13.0 | 142.9 | 116.5 | 1 800 B |
| BLS12-381 | 1 024 | 154.9 | 39.1 | 650.4 | 496.3 | 2 216 B |
| BN-254 | 1 024 | 18.4 | 15.4 | 415.7 | 329.6 | 1 544 B |
| BLS12-377 | 1 024 | 150.0 | 40.0 | 582.1 | 499.1 | 2 216 B |

### Dory (dory_results.json)

Transparent setup. Proof size and verify both grow as O(log n).
**Implementation credit:** Markos Georghiades (a16z) — [github.com/a16z/dory](https://github.com/a16z/dory). Used here for benchmarking only; not original code.

| Curve | n | Setup (ms) | Commit (ms) | Prove (ms) | Verify (ms) | Proof |
|---|---|---|---|---|---|---|
| BLS12-381 | 256 | 63.8 | 33.7 | 219.8 | 81.6 | 16 896 B |
| BLS12-381 | 1 024 | 111.0 | 91.0 | 264.3 | 95.8 | 20 784 B |
| BN-254 | 256 | 33.5 | 17.2 | 92.9 | 54.7 | 11 264 B |
| BN-254 | 1 024 | 57.6 | 49.2 | 173.1 | 61.9 | 13 856 B |
| BLS12-377 | 256 | 73.6 | 34.3 | 182.6 | 92.0 | 16 896 B |
| BLS12-377 | 1 024 | 126.0 | 101.8 | 309.9 | 112.1 | 20 784 B |

Verify grows only as O(log n) — significantly better than Bulletproofs' O(n) verifier. BN-254 is fastest across all metrics due to smaller field arithmetic.

---

## Protocol Comparison

| | KZG | Multilinear KZG | Bulletproofs | Dory |
|---|---|---|---|---|
| **Trusted setup** | Yes | Yes | No | No |
| **Proof size** | O(1) — 1 point | O(l) — l points | O(log n) | O(log n) |
| **Prove cost** | O(d) MSM | O(l · 2^l) MSMs | O(n) group ops | O(n) MSMs + O(log n) pairings |
| **Verify cost** | O(1) — 2 pairings | O(l) — l+1 pairings | O(n) group ops | O(log n) pairings |
| **Best for** | Univariate, SNARK backends | MLE-based SNARKs (Spartan, HyperPlonk) | No-setup range proofs | Transparent MLE-based SNARKs |

---

## Dependencies

All projects share the same core dependency set:

```toml
ark-bls12-381 = "0.4"
ark-bn254      = "0.4"
ark-bls12-377  = "0.4"
ark-ec         = "0.4"   # Elliptic curve & pairing traits
ark-ff         = "0.4"   # Finite field arithmetic
ark-std        = "0.4"   # Utilities, RNG
serde          = "1"     # Serialization
serde_json     = "1"     # JSON benchmark output
```

Bulletproofs additionally uses `sha2 = "0.10"` and `digest = "0.10"` for the Fiat-Shamir transcript.
