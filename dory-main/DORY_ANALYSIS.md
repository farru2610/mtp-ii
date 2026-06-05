# Dory Implementation Analysis: Theory vs. Code

> **Source theory**: Section 15.4 of the textbook (pages 240–254), covering Sections 15.4.1–15.4.6 and Protocol 14.
> **Source code**: `/dory-main/src/` (Rust implementation).

---

## Table of Contents

1. [Protocol Overview](#1-protocol-overview)
2. [Core Theory–Code Correspondence](#2-core-theorycorrespondence)
3. [Structural Differences](#3-structural-differences)
4. [Optimizations Not in the Theory](#4-optimizations-not-in-the-theory)
5. [Zero-Knowledge Extension](#5-zero-knowledge-extension)
6. [File-by-File Map](#6-file-by-file-map)

---

## 1. Protocol Overview

Dory is a **transparent** polynomial commitment scheme with **O(log n)** verification cost and **O(log²n)** proof size (from Section 15.4.3), reduced to **O(log n)** communication and verification via Protocol 14 (Section 15.4.6).

The core idea:

1. **Commitment**: Arrange polynomial coefficients as a matrix `u ∈ F^(m×m)`. Commit via a two-tier AFGHO scheme:
   - Tier 1 (row commits): `cᵢ = MSM(Γ₁, row_i)` in G₁
   - Tier 2 (final commit): `c* = Σⱼ e(cⱼ, Γ₂ⱼ)` in Gₜ

2. **Evaluation proof**: For a query point `z`, express the evaluation as a vector–matrix–vector product `q(z) = bᵀ · u · a` (VMV). Transform the polynomial evaluation claim into an inner-pairing-product (IPP) claim about known commitments.

3. **Reduce-and-fold (Protocol 14)**: Prove knowledge of vectors `u, g ∈ Gⁿ` satisfying three IPP equations simultaneously, in `log n` rounds, each halving the vector length.

4. **Final check**: At length-1 vectors, verify directly via a pairing equation.

---

## 2. Core Theory–Code Correspondence

### 2.1 Setup and Preprocessing

| Theory | Code | File | Status |
|--------|------|------|--------|
| Public generators `Γ₁ = (g₁,...,gₙ) ∈ G₁ⁿ` | `ProverSetup::g1_vec` | `setup.rs:27` | ✅ |
| Public generators `Γ₂ = (g₁,...,gₙ) ∈ G₂ⁿ` | `ProverSetup::g2_vec` | `setup.rs:31` | ✅ |
| Preprocessing: `Δ_L^(k) = ⟨Γ₁[..2^(k-1)], Γ₂[..2^(k-1)]⟩` | `VerifierSetup::delta_1l[k]` | `setup.rs:49` | ✅ |
| Preprocessing: `Δ_R^(k) = ⟨Γ₁[2^(k-1)..], Γ₂[..2^(k-1)]⟩` | `VerifierSetup::delta_1r[k]` | `setup.rs:54` | ✅ |
| Preprocessing: `χ^(k) = ⟨Γ₁[..2^k], Γ₂[..2^k]⟩` | `VerifierSetup::chi[k]` | `setup.rs:62` | ✅ |

### 2.2 Commitment (Section 15.4.4 / 15.4.5)

**Theory** (Eq. 15.8, Section 15.4.5):
```
c* = Σⱼ Σᵢ e(uᵢⱼ · hᵢ, gⱼ)    (matrix commitment)
```

**Code** (`poly.rs`, `evaluation_proof.rs`):
```rust
// Tier 1: row_commit[i] = MSM(Γ₁[0..2^sigma], row_i_coefficients)
// Tier 2: commitment = Σⱼ e(row_commit[j], Γ₂[j])  →  e(MSM(row_commits, Γ₂), ·)
let c = E::pair(&M1::msm(&padded_row_commitments, &v_vec), g2_fin);
```

✅ The commitment structure is correct. The code correctly implements the two-tier AFGHO commitment.

### 2.3 VMV Message (Section 15.4.4)

The code sends three values in `VMVMessage`:

| Field | Formula | Theory Reference |
|-------|---------|-----------------|
| `C` | `e(MSM(T_vec', v_vec), Γ₂,fin)` | `c_q` from Section 15.4.4 |
| `D₂` | `e(MSM(Γ₁[σ], v_vec), Γ₂,fin)` | Initial `⟨u, Γ⟩` commitment |
| `E₁` | `MSM(T_vec', L_vec)` | Left evaluation vector commitment |

In transparent mode, `E₂ = evaluation · Γ₂,fin` is computed by the verifier directly (no message needed). ✅

### 2.4 Protocol 14 — Per-Round Reduce-and-Fold

Each round of Protocol 14 consists of two sub-messages and two challenges.

#### Sub-round 1 (β challenge)

**Theory** (Protocol 14, Step 4–6):
- Prover sends `D₁L, D₁R, D₂L, D₂R ∈ Gₜ` (AFGHO commits to halves of `u` and `g` under `Γ'`)
- Verifier picks `β ∈ 𝔽_p`
- Prover forms: `w₁ = u + β·Γ`, `w₂ = g + β⁻¹·Γ`

**Code** (`compute_first_message` + `apply_first_challenge`):
```rust
// D₁L = ⟨v₁L, Γ₂'⟩,  D₁R = ⟨v₁R, Γ₂'⟩
let d1_left  = E::multi_pair_g2_setup(v1_l, g2_prime);
let d1_right = E::multi_pair_g2_setup(v1_r, g2_prime);

// D₂L = ⟨Γ₁', v₂L⟩,  D₂R = ⟨Γ₁', v₂R⟩
// (with MSM+pair shortcut on first round — see Optimizations)

// Apply β: v₁ ← v₁ + β·Γ₁,  v₂ ← v₂ + β⁻¹·Γ₂
M1::fixed_scalar_mul_bases_then_add(&setup.g1_vec[..n], &mut self.v1, beta);
M2::fixed_scalar_mul_bases_then_add(&setup.g2_vec[..n], &mut self.v2, &beta_inv);
```
✅ Matches theory exactly.

#### Sub-round 2 (α challenge)

**Theory** (Protocol 14, Step 7–9):
- Prover sends `vL = ⟨w₁L, w₂R⟩`, `vR = ⟨w₁R, w₂L⟩ ∈ Gₜ`
- Verifier picks `α ∈ 𝔽_p`
- Prover folds: `u^(i) = α·w₁L + α⁻¹·w₁R`, `g^(i) = α⁻¹·w₂L + α·w₂R`

**Code** (`compute_second_message` + `apply_second_challenge`):
```rust
// C₊ = ⟨v₁L, v₂R⟩,  C₋ = ⟨v₁R, v₂L⟩   (same as vL, vR in theory)
let c_plus  = E::multi_pair(v1_l, v2_r);
let c_minus = E::multi_pair(v1_r, v2_l);

// Fold (ASYMMETRIC — see Section 3):
// v₁ ← α·v₁L + v₁R       (theory: α·w₁L + α⁻¹·w₁R)
// v₂ ← α⁻¹·v₂L + v₂R    (theory: α⁻¹·w₂L + α·w₂R)
M1::fixed_scalar_mul_vs_then_add(v1_l, v1_r, alpha);
M2::fixed_scalar_mul_vs_then_add(v2_l, v2_r, &alpha_inv);
```

> ⚠️ **Deviation**: The folding is **asymmetric** (see Section 3 below).

#### Verifier State Update (Protocol 14, Step 10)

**Theory** (Eqs. 15.26–15.28):
```
c₁' = c₁ + β⁻¹·c₂ + β·c₃ + ⟨Γ,Γ⟩ + α²·vL + α⁻²·vR
c₂' = α·D₁L + α⁻¹·D₁R + αβ·ΔL + α⁻¹β·ΔR
c₃' = α⁻¹·D₂L + α·D₂R + α⁻¹β⁻¹·ΔL + αβ⁻¹·ΔR
```

**Code** (`process_round`):
```rust
// c₁ update (C in code ↔ c₁ in theory, D₁ ↔ c₂, D₂ ↔ c₃):
self.c = self.c + chi[i] + D₂·β + D₁·β⁻¹ + C₊·α + C₋·α⁻¹;

// c₂ update (D₁ in code):
self.d1 = D₁L·α + D₁R + ΔL·(αβ) + ΔR·β;

// c₃ update (D₂ in code):
self.d2 = D₂L·α⁻¹ + D₂R + ΔL·(α⁻¹β⁻¹) + ΔR·β⁻¹;
```

> ⚠️ **Deviation**: Coefficients differ from theory due to asymmetric folding (see Section 3). Both are internally consistent.

---

## 3. Structural Differences

### 3.1 Asymmetric Folding Convention

This is the **only meaningful structural difference** between the code and the textbook.

#### Theory (symmetric, both halves scaled):
```
u^(i) = α · w₁L + α⁻¹ · w₁R          ← both scaled
g^(i) = α⁻¹ · w₂L + α · w₂R          ← both scaled

Inner product:
⟨u^(i), g^(i)⟩ = ⟨uL,gL⟩ + α²·⟨uL,gR⟩ + α⁻²·⟨uR,gL⟩ + ⟨uR,gR⟩
                = ⟨u,g⟩ + α²·vL + α⁻²·vR     ← squared α
```

#### Code (asymmetric, only left half scaled):
```
v₁_new = α · v₁L + v₁R                ← right half unscaled
v₂_new = α⁻¹ · v₂L + v₂R             ← right half unscaled

Inner product:
⟨v₁_new, v₂_new⟩ = ⟨uL,gL⟩ + α·⟨uL,gR⟩ + α⁻¹·⟨uR,gL⟩ + ⟨uR,gR⟩
                  = ⟨u,g⟩ + α·C₊ + α⁻¹·C₋   ← linear α
```

#### Why both are valid:
Both conventions are **sound** — the verifier's update formula is derived from the prover's folding formula, so as long as both sides agree, the protocol is correct. The code's convention is **internally consistent**: the prover folds asymmetrically, the verifier updates with linear (not squared) α, and the D₁/D₂ recurrences drop the α⁻¹ factor on the right half.

#### Practical benefit:
The code avoids computing `α²` and `α⁻²` in the verifier's c update, and avoids computing `α⁻¹` for the `D₁R` / `D₂R` terms — **fewer field inversions and multiplications per round**.

---

## 4. Optimizations Not in the Theory

### Opt-1: First-Round MSM+Pair Optimization

**File**: `reduce_and_fold.rs:226–237`, `evaluation_proof.rs:174`

In the first round, `v₂[i] = scalar[i] · Γ₂,fin` (all entries share the same G2 generator). Computing `D₂L = ⟨Γ₁'L, v₂L⟩` naively requires `n/2` pairings. The code instead:

```
Step 1: sum = MSM(Γ₁'L, scalars_L)    ← 1 MSM in G1 (cheap)
Step 2: D₂L = e(sum, Γ₂,fin)          ← 1 pairing (expensive)
```

vs naive: `n/2` pairings (each as expensive as step 2).

**Speedup**: ~n/2× reduction in pairing calls for this sub-computation. On BLS12-381, pairings cost ~4× a G1 MSM operation, so this is a significant win for large `n`.

**Theory**: Does not mention this shortcut.

---

### Opt-2: Incremental χ Computation

**File**: `setup.rs:154–155`

`χ[k] = ⟨Γ₁[..2^k], Γ₂[..2^k]⟩` is the inner pairing product of the first `2^k` generators.

**Naive approach**: Compute each χ[k] from scratch → `1 + 2 + 4 + ... + 2^max = O(n)` pairings but computed redundantly → O(n log n) total.

**Code approach** (incremental build):
```rust
// χ[k] = χ[k-1] + e(Γ₁[half..full], Γ₂[half..full])
chi.push(chi[k-1].add(&E::multi_pair(g1_second_half, g2_second_half)));
```

Only the **new generators** (second half at each level) need pairing — each generator pair is used exactly once. Total work: O(n) pairings.

**Theory**: States that preprocessing outputs these commitments but does not describe the incremental computation.

---

### Opt-3: Δ₂L = Δ₁L Storage Sharing

**File**: `setup.rs:162`

```rust
VerifierSetup {
    delta_1l: delta_1l.clone(),
    delta_2l: delta_1l,   // ← same slice, no recomputation
    ...
}
```

Both `Δ₁L[k]` and `Δ₂L[k]` equal `⟨Γ₁[..2^(k-1)], Γ₂[..2^(k-1)]⟩ = χ[k-1]`. The code stores only one copy and aliases it.

**Theory**: Treats them as logically separate preprocessing outputs.

---

### Opt-4: Prepared G2 Point Caching

**File**: `arithmetic.rs:107–128`, `backends/arkworks/ark_cache.rs`

The `PairingCurve` trait exposes two specialized multi-pairing methods:
```rust
fn multi_pair_g2_setup(ps: &[G1], qs: &[G2]) -> GT  // G2 points are setup generators
fn multi_pair_g1_setup(ps: &[G1], qs: &[G2]) -> GT  // G1 points are setup generators
```

Backend implementations can precompute **prepared** (affine-normalized, precomputed line-function coefficients) forms of the setup generators and cache them across all proof generations. This avoids recomputing the Miller loop preprocessing step for generators on every pairing call.

**Theory**: Has no notion of implementation-level pairing optimizations.

---

### Opt-5: Multi-Pairing Batching in Final Verification

**File**: `reduce_and_fold.rs:812`

```rust
let lhs = E::multi_pair(
    &[p1_g1, p2_g1, p3_g1, p4_g1],
    &[p1_g2, p2_g2, p3_g2, p4_g2],
);
```

All 4 pairings needed in the transparent-mode final check are computed as a **single multi-pairing**: run 4 Miller loops, combine, then apply **one** final exponentiation. Computing them individually would require 4 final exponentiations, which is the most expensive part of a pairing.

**Speedup**: ~3× reduction in final exponentiation cost.

**Theory**: Describes verification as separate pairing evaluations.

---

### Opt-6: Deferred VMV Check with d² Batching

**File**: `reduce_and_fold.rs:693–715`

The transparent-mode final verification batches two independent equations into one multi-pairing:

1. **Main equation**: The fold-scalars/reduce protocol check.
2. **VMV constraint**: `D₂_init = e(E₁_init, Γ₂₀)` (proves the VMV message is consistent).

These are combined as: `(main_eq) + d² · (VMV_eq)` where `d` is derived from the transcript **after** `D₂_init` and `E₁_init` are committed. The code uses `d²` (not `d`) to ensure linear independence from the `d·D₂` term already present in the main equation.

```rust
// Pair 4: e(d²·E₁_init, Γ₂₀) — deferred VMV check
let p4_g1 = self.e1_init.scale(&d_sq);
let p4_g2 = self.setup.g2_0;
// rhs includes: ... + self.d2_init.scale(&d_sq)
```

**Theory**: Describes separate verification of the VMV constraint.

---

### Opt-7: Non-Square Matrix Support (nu ≤ sigma)

**File**: `evaluation_proof.rs:107–129`, `reduce_and_fold.rs:193`

The code fully supports **rectangular** polynomial coefficient matrices with `2^nu` rows and `2^sigma` columns (constraint: `nu ≤ sigma`). When `nu < sigma`, vectors are padded with zeros to length `2^sigma`.

This allows flexible tradeoffs:
- **Smaller nu**: Fewer row commitments → shorter Tier 1 phase and smaller `E₁` vector.
- **Larger sigma**: More columns → more work in each reduce-and-fold round but same number of rounds (`sigma` rounds total).

**Theory**: Describes only the square `m×m` matrix case.

---

### Opt-8: Fiat-Shamir Non-Interactive Transform

**File**: `evaluation_proof.rs:153–237`, `backends/arkworks/blake2b_transcript.rs`

The interactive Protocol 14 is made non-interactive via the **Fiat-Shamir heuristic** using a Blake2b hash-based transcript. Every prover message is absorbed into the transcript before the verifier challenge is squeezed:

```rust
transcript.append_serde(b"d1_left",  &first_msg.d1_left);
transcript.append_serde(b"d1_right", &first_msg.d1_right);
// ...
let beta = transcript.challenge_scalar(b"beta");
```

**Theory**: Describes only the interactive protocol.

---

## 5. Zero-Knowledge Extension

The `zk` feature adds a full ZK layer not described in Section 15.4 of the textbook.

### Blinding Infrastructure

- `h₁ ∈ G₁`, `h₂ ∈ G₂`, `hₜ = e(h₁, h₂) ∈ Gₜ` — random blinding generators in setup.
- Every commitment to `Gₜ` is masked: `C ← C + r·hₜ`.
- Every commitment in `G₁`/`G₂` is masked: `E ← E + r·h`.

### Sigma Protocol 1 (Σ₁)

**File**: `reduce_and_fold.rs:441–497`

Proves that `E₂` (a blinded `G₂` element) and `y_com` (a Pedersen commitment in `G₁`) open to the same witness `y` (the polynomial evaluation). Uses a 3-move Schnorr-style proof with 3 response scalars `(z₁, z₂, z₃)`.

### Sigma Protocol 2 (Σ₂)

**File**: `reduce_and_fold.rs:499–554`

Proves `e(E₁, Γ₂,fin) − D₂ = e(H₁, t₁·Γ₂,fin + t₂·H₂)`, binding `E₁` to `D₂` in a way that prevents a cheating prover from constructing inconsistent VMV messages.

### ZK Scalar Product Proof

**File**: `reduce_and_fold.rs:400–436`

A Sigma-protocol in `Gₜ` that proves knowledge of `(v₁, v₂)` satisfying `e(v₁, g₂) = C`, `e(g₁, v₂) = D₁`, `e(v₁, v₂) = D₂` — i.e., consistency of the accumulated triple `(C, D₁, D₂)` with the blinded final vectors.

### ZK Final Verification

In ZK mode, the final verification uses **1 pairing + 1 field exponentiation** (instead of 4 pairings in transparent mode), because the scalar product proof already encodes the inner product relationship:

```
e(sp.e₁ + d·Γ₁₀, sp.e₂ + d⁻¹·Γ₂₀)
  = χ₀ + sp.r + c·sp.q + c²·C
    + d·(sp.p₂ + c·D₂) + d⁻¹·(sp.p₁ + c·D₁)
    − (sp.r₃ + d·sp.r₂ + d⁻¹·sp.r₁)·HT
```

---

## 6. File-by-File Map

| File | Theory Component |
|------|-----------------|
| `setup.rs` | Prover/Verifier setup, Δ/χ preprocessing (Section 15.4.3, preprocessing) |
| `reduce_and_fold.rs` | Protocol 14 prover + verifier state machines |
| `evaluation_proof.rs` | Full Eval-VMV-RE protocol, Fiat-Shamir wrapping |
| `proof.rs` | Proof struct (VMV + reduce messages + final message) |
| `messages.rs` | Per-round message types (`FirstReduceMessage`, `SecondReduceMessage`, `VMVMessage`, `ScalarProductMessage`) |
| `primitives/poly.rs` | Multilinear polynomial commitment + evaluation vector computation |
| `primitives/arithmetic.rs` | Field/Group/PairingCurve traits with multi-pairing hooks |
| `primitives/transcript.rs` | Fiat-Shamir transcript (non-interactive transform) |
| `backends/arkworks/` | Concrete curve implementations (BLS12-381, BLS12-377, BN254) with prepared-point caching |
| `mode.rs` | `Transparent` / `ZK` mode flags controlling blinding |

---

## Summary

| Aspect | Result |
|--------|--------|
| Overall protocol structure | ✅ Faithful to theory |
| Setup and preprocessing | ✅ Correct |
| VMV transformation | ✅ Correct |
| β-combination step | ✅ Exact match |
| Prover cross-term messages (C₊, C₋, D₁L/R, D₂L/R) | ✅ Correct |
| Verifier update formulas | ✅ Correct (under code's folding convention) |
| Folding convention | ⚠️ **Asymmetric** (differs from theory, but internally consistent and sound) |
| Non-interactive (Fiat-Shamir) | ➕ Extension beyond theory |
| Non-square matrices | ➕ Extension beyond theory |
| MSM+pair first-round optimization | ➕ Performance optimization |
| Incremental χ computation | ➕ Performance optimization |
| Δ₂L = Δ₁L sharing | ➕ Storage optimization |
| Prepared G2 caching | ➕ Backend performance optimization |
| Multi-pairing final check | ➕ Performance optimization |
| d² VMV batching | ➕ Optimization beyond theory |
| Zero-knowledge extension | ➕ Feature beyond theory |
