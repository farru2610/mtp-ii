# Multilinear KZG — Performance Analysis
### Curves: BLS12-381 | BN-254 | BLS12-377

---

## Project Structure

```
multilinear-kzg/
├── Cargo.toml
└── src/
    ├── multilinear_kzg.rs   ← Core protocol (generic over any pairing curve)
    ├── mle.rs               ← Multilinear extension helpers (eq_poly, evaluate_mle)
    ├── main.rs              ← Single-instance correctness test (BLS12-381)
    ├── bench_multi_kzg.rs   ← Multi-curve performance benchmark logic
    └── bench_main.rs        ← Benchmark binary entry point
```

---

## Setup

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone / enter project
cd "Multilinear KZG"

# Build in release mode (important for accurate timings)
cargo build --release
```

---

## Run

### Correctness Test

```bash
cargo run
```

Runs a single Multilinear KZG commit + open + verify on BLS12-381 with num_vars = 5 and prints:

```
Multilinear KZG verified!
```

### Performance Benchmark

```bash
cargo run --release --bin bench
```

Benchmarks all three curves across num_vars ∈ {2, 4, 6, 8, 10, 12, 14} (poly_size = 2^num_vars), averaging 5 repetitions each. Output:

```
Multilinear KZG Benchmark  (BLS12-381)
num_vars   poly_size    setup(ms) commit(ms)  prove(ms) verify(ms)  scalar_mul(ms)  pairing(ms) proof(bytes)
-------------------------------------------------------------------------------------------------------------------
2               4          x.xxx      x.xxx      x.xxx      x.xxx          x.xxxx       x.xxxx           xx
4              16          x.xxx      x.xxx      x.xxx      x.xxx          x.xxxx       x.xxxx           xx
...

Saved to multilinear_kzg_results.json
```

Results are also written to `multilinear_kzg_results.json`.

---

## What is Being Measured

| Metric            | Description                                                              |
|-------------------|--------------------------------------------------------------------------|
| `setup(ms)`       | Time to compute SRS: 2^l G1 elements + l G2 elements from toxic waste   |
| `commit(ms)`      | Time to compute `C = Σ_b f(b) · g1^{χ_b(r)}` via Pippenger MSM         |
| `prove(ms)`       | Time to compute l witness elements via bookkeeping table halving         |
| `verify(ms)`      | Time to verify using l+1 pairing operations                              |
| `scalar_mul(ms)`  | Time for a single G1 scalar multiplication (curve baseline)              |
| `pairing(ms)`     | Time for a single pairing evaluation (curve baseline)                    |
| `proof(bytes)`    | Proof size = l compressed G1 points (num_vars × g1_point_bytes)          |

---

## Complexity (Theoretical vs Observed)

| Phase      | Complexity    | Why                                                                 |
|------------|---------------|---------------------------------------------------------------------|
| Setup      | O(2^l)        | 2^l eq_poly evaluations for G1 SRS + l scalar muls for G2 SRS      |
| Commit     | O(2^l)        | One MSM of size 2^l over G1                                         |
| Prove      | O(l · 2^l)    | l MSMs of size 2^l — bookkeeping table halved each step             |
| Verify     | O(l)          | l+1 pairing operations                                              |
| Proof Size | O(l)          | l G1 proof elements, one per variable                               |

---

## Curve Parameters

| Curve      | Field Size | Security Level | G1 Point Size |
|------------|------------|----------------|---------------|
| BLS12-381  | 381 bits   | ~128 bit       | ~48 bytes     |
| BN-254     | 254 bits   | ~100 bit       | ~32 bytes     |
| BLS12-377  | 377 bits   | ~128 bit       | ~48 bytes     |

BN-254 will be fastest (smaller field) but has lower security.
BLS12-381 and BLS12-377 offer similar security with slightly different pairing properties.

---

## How It Works (Protocol Summary)

```
Trusted Setup
  r = (r_0, ..., r_{l-1})   ← toxic waste (random scalars, never stored)
  SRS_G1[b] = g1^{χ_b(r)}   for each b ∈ {0,1}^l     (2^l elements)
  SRS_G2[i] = g2^{r_i}      for each i = 0..l-1       (l elements)

Prover                                    Verifier
  |                                           |
  |─── C = Σ_b f(b)·SRS_G1[b] ────────────>|  commitment = g1^{f(r)}
  |                                           |
  | [Witness computation — no knowledge of r] |
  |  table = full evaluation table of f       |
  |  for i = 0..l-1:                          |
  |    q_i(b) = table[1,b] − table[0,b]      |
  |    π_i   = Σ_idx q_i(bits) · SRS_G1[idx] |
  |    fix x_i = z_i in table                 |
  |─── (v, π_0, ..., π_{l-1}) ─────────────>|
  |                                           |  check:
  |                                           |  e(C − g1^v, g2)
  |                                           |  == Π_i e(π_i, g2^{r_i} − g2^{z_i})
```

---

## Dependencies

```toml
ark-bls12-381 = "0.4"   # BLS12-381 curve
ark-bn254     = "0.4"   # BN-254 curve
ark-bls12-377 = "0.4"   # BLS12-377 curve
ark-ec        = "0.4"   # Elliptic curve and pairing traits
ark-ff        = "0.4"   # Finite field traits
ark-std       = "0.4"   # Utilities and RNG
serde         = "1"     # Serialization (derive)
serde_json    = "1"     # JSON output
```
