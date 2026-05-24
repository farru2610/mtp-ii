# Bulletproofs IPA — Performance Analysis
### Curves: BLS12-381 | BN-254 | BLS12-377

---

## Project Structure

```
bulletproofs/
├── Cargo.toml
└── src/
    ├── bulletproofs.rs      ← Core protocol (generic over any curve)
    ├── main.rs              ← Single-instance correctness test (BLS12-381)
    └── bench_bulletproofs.rs ← Multi-curve performance benchmark
```

---

## Setup

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone / enter project
cd bulletproofs

# Build in release mode (important for accurate timings)
cargo build --release
```

---

## Run

### Correctness Test

```bash
cargo run
```

Runs a single Bulletproof IPA prove + verify on BLS12-381 with n = 8 and prints:

```
Single instance Bulletproof IPA verified!
```

### Performance Benchmark

```bash
cargo run --release --bin bench_bulletproofs
```

Benchmarks all three curves across sizes n ∈ {4, 8, 16, 32, 64, 128, 256, 512, 1024}, averaging 10 repetitions each. Output:

```
Bulletproofs IPA Benchmark (BLS12-381)
n        setup(ms) commit(ms)  prove(ms) verify(ms)  scalar_mul(ms)    msm(ms)  proof(bytes)
-----------------------------------------------------------------------------------------------
4           x.xxx      x.xxx      x.xxx      x.xxx         x.xxxx     x.xxxx          xxx
8           x.xxx      x.xxx      x.xxx      x.xxx         x.xxxx     x.xxxx          xxx
...

✓ Saved to bulletproofs_results.json
```

Results are also written to `bulletproofs_results.json`.

---

## What is Being Measured

| Metric           | Description                                                      |
|------------------|------------------------------------------------------------------|
| `setup(ms)`      | Time to generate n random generators (transparent setup)         |
| `commit(ms)`     | Time to compute `c_u = Σ uᵢ · gᵢ` via Pippenger MSM            |
| `prove(ms)`      | Time to run the full log₂(n)-round IPA reduction                 |
| `verify(ms)`     | Time to verify the proof                                         |
| `scalar_mul(ms)` | Time for a single scalar multiplication (size-independent)       |
| `msm(ms)`        | Time for a size-n multi-scalar multiplication (Pippenger)        |
| `proof(bytes)`   | Proof size = 2·log₂(n) points + 1 scalar + 1 point              |

---

## Complexity (Theoretical vs Observed)

| Phase      | Complexity | Why                                              |
|------------|------------|--------------------------------------------------|
| Commit     | O(n)       | n scalar multiplications                        |
| Prove      | O(n)       | Each fold halves the work: n + n/2 + ... = 2n   |
| Verify     | O(n)       | Same folding on verifier side                   |
| Proof Size | O(log n)   | 2 points per round × log₂(n) rounds             |

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
Prover                              Verifier
  |                                    |
  |──── c_u = <u, g> ─────────────────>|  commitment
  |                                    |
  | [Round 1]                          |
  |  split u = u_L ∘ u_R              |
  |  split g = g_L ∘ g_R              |
  |  v_L = <u_L, g_R>                 |
  |  v_R = <u_R, g_L>                 |
  |──── v_L, v_R ─────────────────────>|
  |        α = SHA256(c_u, v_L, v_R)  |  (Fiat-Shamir)
  |  u' = α·u_L + α⁻¹·u_R            |
  |  g' = α⁻¹·g_L + α·g_R            |
  |  c' = c + α²·v_L + α⁻²·v_R       |
  |          ...  (log n rounds)  ...  |
  |──── ū, ḡ (single elements) ───────>|
  |                                    |  check: c^(logn) == ū·ḡ
  |                                    |  check: g^(logn) == ḡ
```

---

## Dependencies

```toml
ark-bls12-381 = "0.4"   # BLS12-381 curve
ark-bn254     = "0.4"   # BN-254 curve
ark-bls12-377 = "0.4"   # BLS12-377 curve
ark-ec        = "0.4"   # Elliptic curve traits
ark-ff        = "0.4"   # Finite field traits
ark-std       = "0.4"   # Utilities and RNG
sha2          = "0.10"  # SHA-256 (Fiat-Shamir transcript)
digest        = "0.10"  # Digest trait
serde         = "1"     # Serialization (derive)
serde_json    = "1"     # JSON output
```
