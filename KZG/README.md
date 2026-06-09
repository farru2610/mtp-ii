# KZG Polynomial Commitment — Performance Analysis
### Curves: BLS12-381 | BN-254 | BLS12-377

---

## Project Structure

```
KZG/
├── Cargo.toml
└── src/
    ├── kzg.rs               ← Core protocol (generic over any pairing curve)
    ├── utils.rs             ← Polynomial evaluation helpers
    ├── main.rs              ← Single-instance correctness test (BLS12-381)
    ├── bench_single.rs      ← Multi-curve performance benchmark logic
    └── bench_single_main.rs ← Benchmark binary entry point
```

---

## Setup

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone / enter project
cd KZG

# Build in release mode (important for accurate timings)
cargo build --release
```

---

## Run

### Correctness Test

```bash
cargo run
```

Runs a single KZG commit + open + verify on BLS12-381 with degree = 16 and prints:

```
KZG single-point evaluation verified!
```

### Performance Benchmark

```bash
cargo run --release --bin bench_single
```

Benchmarks all three curves across degrees ∈ {4, 8, 16, 32, 64, 128, 256, 512, 1024}, averaging 10 repetitions each. Output:

```
KZG Single-Point Benchmark (BLS12-381)
degree    setup(ms) commit(ms)  prove(ms) verify(ms)  scalar_mul(ms)  pairing(ms)  proof(bytes)
-----------------------------------------------------------------------------------------------
4           x.xxx      x.xxx      x.xxx      x.xxx         x.xxxx       x.xxxx            48
8           x.xxx      x.xxx      x.xxx      x.xxx         x.xxxx       x.xxxx            48
...

✓ Saved to single_point_results.json
```

Results are also written to `single_point_results.json`.

---

## What is Being Measured

| Metric            | Description                                                              |
|-------------------|--------------------------------------------------------------------------|
| `setup(ms)`       | Time to compute SRS: d+1 powers `[τⁱ]₁` in G1 + `[τ]₂` in G2          |
| `commit(ms)`      | Time to compute `C = Σ aᵢ·[τⁱ]₁` via Pippenger MSM                     |
| `prove(ms)`       | Time to compute quotient `q(X) = (f(X)−y)/(X−z)` and commit to it       |
| `verify(ms)`      | Time to verify using exactly 2 pairing evaluations                       |
| `scalar_mul(ms)`  | Time for a single G1 scalar multiplication (curve baseline)              |
| `pairing(ms)`     | Time for a single pairing evaluation (curve baseline)                    |
| `proof(bytes)`    | Proof size = 1 compressed G1 point (48 B for BLS12-381/377, 32 B for BN-254) |

---

## Complexity (Theoretical vs Observed)

| Phase      | Complexity | Why                                                       |
|------------|------------|-----------------------------------------------------------|
| Setup      | O(d)       | d+1 scalar multiplications for powers of τ                |
| Commit     | O(d)       | One MSM of size d+1 over G1                               |
| Prove      | O(d)       | Polynomial division O(d) + one MSM of size d              |
| Verify     | O(1)       | Exactly 2 pairings regardless of degree                   |
| Proof Size | O(1)       | Always 1 G1 point — independent of degree                 |

---

## Curve Parameters

| Curve      | Field Size | Security Level | G1 Point Size | G2 Point Size |
|------------|------------|----------------|---------------|---------------|
| BLS12-381  | 381 bits   | ~128 bit       | 48 bytes      | 96 bytes      |
| BN-254     | 254 bits   | ~100 bit       | 32 bytes      | 64 bytes      |
| BLS12-377  | 377 bits   | ~128 bit       | 48 bytes      | 96 bytes      |

BN-254 is fastest (smaller field) but has lower security.  
BLS12-381 and BLS12-377 offer ~128-bit security; BLS12-381 is slightly faster for single-proof workloads while BLS12-377 is preferred for recursive proof composition.

---

## How It Works (Protocol Summary)

```
Trusted Setup
  τ ← random secret (toxic waste, discarded after setup)
  SRS_G1 = ([1]₁, [τ]₁, [τ²]₁, ..., [τᵈ]₁)    ← d+1 G1 elements
  SRS_G2 = ([1]₂, [τ]₂)                          ← 2 G2 elements

Prover                                    Verifier
  |                                           |
  |─── C = Σ aᵢ·[τⁱ]₁ (MSM) ─────────────>|  commitment = [f(τ)]₁
  |                                           |
  | [Open at point z]                         |
  |  y = f(z)                                 |
  |  q(X) = (f(X) − y) / (X − z)             |
  |  π = Σ qᵢ·[τⁱ]₁  (MSM)                  |
  |─── (y, π) ─────────────────────────────>|
  |                                           |  check:
  |                                           |  e(π, [τ]₂ − [z]₂)
  |                                           |  == e(C − [y]₁, [1]₂)
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
rand          = "0.8"   # Random number generation
serde         = "1"     # Serialization (derive)
serde_json    = "1"     # JSON output
```
