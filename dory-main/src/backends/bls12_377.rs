#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use ark_bls12_377::{Bls12_377, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field as ArkField, One, PrimeField, UniformRand, Zero as ArkZero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid as ArkValid};
use ark_std::ops::{Add, Mul, Neg, Sub};

use crate::backends::arkworks::Blake2bTranscript;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::primitives::serialization::{Compress, SerializationError, Valid, Validate};
use crate::primitives::transcript::Transcript;
use crate::primitives::{DoryDeserialize, DorySerialize};

// ── Field ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls377Fr(pub ark_bls12_377::Fr);

impl Field for Bls377Fr {
    fn zero() -> Self { Bls377Fr(ark_bls12_377::Fr::from(0u64)) }
    fn one() -> Self  { Bls377Fr(ark_bls12_377::Fr::from(1u64)) }
    fn is_zero(&self) -> bool { ArkZero::is_zero(&self.0) }
    fn add(&self, rhs: &Self) -> Self { Bls377Fr(self.0 + rhs.0) }
    fn sub(&self, rhs: &Self) -> Self { Bls377Fr(self.0 - rhs.0) }
    fn mul(&self, rhs: &Self) -> Self { Bls377Fr(self.0 * rhs.0) }
    fn inv(self) -> Option<Self> { ArkField::inverse(&self.0).map(Bls377Fr) }
    fn random() -> Self { Bls377Fr(ark_bls12_377::Fr::rand(&mut rand_core::OsRng)) }
    fn from_u64(val: u64) -> Self { Bls377Fr(ark_bls12_377::Fr::from(val)) }
    fn from_i64(val: i64) -> Self {
        if val >= 0 { Bls377Fr(ark_bls12_377::Fr::from(val as u64)) }
        else { Bls377Fr(-ark_bls12_377::Fr::from((-val) as u64)) }
    }
}

impl Add for Bls377Fr { type Output = Self; fn add(self, rhs: Self) -> Self { Bls377Fr(self.0 + rhs.0) } }
impl Sub for Bls377Fr { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls377Fr(self.0 - rhs.0) } }
impl Mul for Bls377Fr { type Output = Self; fn mul(self, rhs: Self) -> Self { Bls377Fr(self.0 * rhs.0) } }
impl Neg for Bls377Fr { type Output = Self; fn neg(self) -> Self { Bls377Fr(-self.0) } }
impl<'a> Add<&'a Bls377Fr> for Bls377Fr { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls377Fr(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls377Fr> for Bls377Fr { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls377Fr(self.0 - rhs.0) } }
impl<'a> Mul<&'a Bls377Fr> for Bls377Fr { type Output = Self; fn mul(self, rhs: &'a Self) -> Self { Bls377Fr(self.0 * rhs.0) } }

// ── G1 ───────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls377G1(pub G1Projective);

impl Group for Bls377G1 {
    type Scalar = Bls377Fr;
    fn identity() -> Self { Bls377G1(ArkZero::zero()) }
    fn add(&self, rhs: &Self) -> Self { Bls377G1(self.0 + rhs.0) }
    fn neg(&self) -> Self { Bls377G1(-self.0) }
    fn scale(&self, k: &Self::Scalar) -> Self { Bls377G1(self.0 * k.0) }
    fn random() -> Self { Bls377G1(G1Projective::rand(&mut rand_core::OsRng)) }
}

impl Add for Bls377G1  { type Output = Self; fn add(self, rhs: Self) -> Self { Bls377G1(self.0 + rhs.0) } }
impl Sub for Bls377G1  { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls377G1(self.0 - rhs.0) } }
impl Neg for Bls377G1  { type Output = Self; fn neg(self) -> Self { Bls377G1(-self.0) } }
impl<'a> Add<&'a Bls377G1> for Bls377G1 { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls377G1(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls377G1> for Bls377G1 { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls377G1(self.0 - rhs.0) } }
impl Mul<Bls377G1> for Bls377Fr { type Output = Bls377G1; fn mul(self, rhs: Bls377G1) -> Bls377G1 { Bls377G1(rhs.0 * self.0) } }
impl<'a> Mul<&'a Bls377G1> for Bls377Fr { type Output = Bls377G1; fn mul(self, rhs: &'a Bls377G1) -> Bls377G1 { Bls377G1(rhs.0 * self.0) } }

// ── G2 ───────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls377G2(pub G2Projective);

impl Group for Bls377G2 {
    type Scalar = Bls377Fr;
    fn identity() -> Self { Bls377G2(ArkZero::zero()) }
    fn add(&self, rhs: &Self) -> Self { Bls377G2(self.0 + rhs.0) }
    fn neg(&self) -> Self { Bls377G2(-self.0) }
    fn scale(&self, k: &Self::Scalar) -> Self { Bls377G2(self.0 * k.0) }
    fn random() -> Self { Bls377G2(G2Projective::rand(&mut rand_core::OsRng)) }
}

impl Add for Bls377G2  { type Output = Self; fn add(self, rhs: Self) -> Self { Bls377G2(self.0 + rhs.0) } }
impl Sub for Bls377G2  { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls377G2(self.0 - rhs.0) } }
impl Neg for Bls377G2  { type Output = Self; fn neg(self) -> Self { Bls377G2(-self.0) } }
impl<'a> Add<&'a Bls377G2> for Bls377G2 { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls377G2(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls377G2> for Bls377G2 { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls377G2(self.0 - rhs.0) } }
impl Mul<Bls377G2> for Bls377Fr { type Output = Bls377G2; fn mul(self, rhs: Bls377G2) -> Bls377G2 { Bls377G2(rhs.0 * self.0) } }
impl<'a> Mul<&'a Bls377G2> for Bls377Fr { type Output = Bls377G2; fn mul(self, rhs: &'a Bls377G2) -> Bls377G2 { Bls377G2(rhs.0 * self.0) } }

// ── GT ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls377GT(pub PairingOutput<Bls12_377>);

impl Default for Bls377GT {
    fn default() -> Self {
        Bls377GT(PairingOutput(<Bls12_377 as Pairing>::TargetField::one()))
    }
}

impl Group for Bls377GT {
    type Scalar = Bls377Fr;
    fn identity() -> Self { Self::default() }
    fn add(&self, rhs: &Self) -> Self { Bls377GT(self.0 + rhs.0) }
    fn neg(&self) -> Self {
        Bls377GT(PairingOutput(ArkField::inverse(&self.0.0).expect("GT inverse")))
    }
    fn scale(&self, k: &Self::Scalar) -> Self {
        Bls377GT(PairingOutput(self.0.0.pow(k.0.into_bigint())))
    }
    fn random() -> Self {
        Bls377GT(Bls12_377::pairing(
            G1Affine::rand(&mut rand_core::OsRng),
            G2Affine::rand(&mut rand_core::OsRng),
        ))
    }
}

impl Add for Bls377GT  { type Output = Self; fn add(self, rhs: Self) -> Self { Bls377GT(self.0 + rhs.0) } }
impl Sub for Bls377GT  { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls377GT(self.0 - rhs.0) } }
impl Neg for Bls377GT  { type Output = Self; fn neg(self) -> Self { Bls377GT(-self.0) } }
impl<'a> Add<&'a Bls377GT> for Bls377GT { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls377GT(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls377GT> for Bls377GT { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls377GT(self.0 - rhs.0) } }
impl Mul<Bls377GT> for Bls377Fr {
    type Output = Bls377GT;
    fn mul(self, rhs: Bls377GT) -> Bls377GT { Bls377GT(PairingOutput(rhs.0.0.pow(self.0.into_bigint()))) }
}
impl<'a> Mul<&'a Bls377GT> for Bls377Fr {
    type Output = Bls377GT;
    fn mul(self, rhs: &'a Bls377GT) -> Bls377GT { Bls377GT(PairingOutput(rhs.0.0.pow(self.0.into_bigint()))) }
}

// ── PairingCurve ─────────────────────────────────────────────────────────────

#[derive(Default, Clone, Debug)]
pub struct BLS12_377;

impl PairingCurve for BLS12_377 {
    type G1 = Bls377G1;
    type G2 = Bls377G2;
    type GT = Bls377GT;

    fn pair(p: &Bls377G1, q: &Bls377G2) -> Bls377GT {
        Bls377GT(Bls12_377::pairing(p.0, q.0))
    }

    fn multi_pair(ps: &[Bls377G1], qs: &[Bls377G2]) -> Bls377GT {
        assert_eq!(ps.len(), qs.len(), "multi_pair requires equal length vectors");
        if ps.is_empty() { return Bls377GT::identity(); }
        let ps_prep: Vec<<Bls12_377 as Pairing>::G1Prepared> =
            ps.iter().map(|p| { let a: G1Affine = p.0.into_affine(); a.into() }).collect();
        let qs_prep: Vec<<Bls12_377 as Pairing>::G2Prepared> =
            qs.iter().map(|q| { let a: G2Affine = q.0.into_affine(); a.into() }).collect();
        let out = Bls12_377::final_exponentiation(Bls12_377::multi_miller_loop(ps_prep, qs_prep))
            .expect("final_exponentiation failed");
        Bls377GT(out)
    }
}

// ── DoryRoutines ─────────────────────────────────────────────────────────────

pub struct Bls377G1Routines;

impl DoryRoutines<Bls377G1> for Bls377G1Routines {
    fn msm(bases: &[Bls377G1], scalars: &[Bls377Fr]) -> Bls377G1 {
        assert_eq!(bases.len(), scalars.len(), "MSM requires equal length vectors");
        if bases.is_empty() { return Bls377G1::identity(); }
        let aff: Vec<G1Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let frs: Vec<ark_bls12_377::Fr> = scalars.iter().map(|s| s.0).collect();
        Bls377G1(G1Projective::msm(&aff, &frs).expect("MSM failed"))
    }
    fn fixed_base_vector_scalar_mul(base: &Bls377G1, scalars: &[Bls377Fr]) -> Vec<Bls377G1> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }
    fn fixed_scalar_mul_bases_then_add(bases: &[Bls377G1], vs: &mut [Bls377G1], scalar: &Bls377Fr) {
        for (v, b) in vs.iter_mut().zip(bases.iter()) { *v = v.add(&b.scale(scalar)); }
    }
    fn fixed_scalar_mul_vs_then_add(vs: &mut [Bls377G1], addends: &[Bls377G1], scalar: &Bls377Fr) {
        for (v, a) in vs.iter_mut().zip(addends.iter()) { *v = v.scale(scalar).add(a); }
    }
}

pub struct Bls377G2Routines;

impl DoryRoutines<Bls377G2> for Bls377G2Routines {
    fn msm(bases: &[Bls377G2], scalars: &[Bls377Fr]) -> Bls377G2 {
        assert_eq!(bases.len(), scalars.len(), "MSM requires equal length vectors");
        if bases.is_empty() { return Bls377G2::identity(); }
        let aff: Vec<G2Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let frs: Vec<ark_bls12_377::Fr> = scalars.iter().map(|s| s.0).collect();
        Bls377G2(G2Projective::msm(&aff, &frs).expect("MSM failed"))
    }
    fn fixed_base_vector_scalar_mul(base: &Bls377G2, scalars: &[Bls377Fr]) -> Vec<Bls377G2> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }
    fn fixed_scalar_mul_bases_then_add(bases: &[Bls377G2], vs: &mut [Bls377G2], scalar: &Bls377Fr) {
        for (v, b) in vs.iter_mut().zip(bases.iter()) { *v = v.add(&b.scale(scalar)); }
    }
    fn fixed_scalar_mul_vs_then_add(vs: &mut [Bls377G2], addends: &[Bls377G2], scalar: &Bls377Fr) {
        for (v, a) in vs.iter_mut().zip(addends.iter()) { *v = v.scale(scalar).add(a); }
    }
}

// ── DorySerialize / DoryDeserialize ──────────────────────────────────────────

impl Valid for Bls377Fr {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls377Fr {
    fn serialize_with_mode<W: std::io::Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self.0.serialize_compressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
            Compress::No  => self.0.serialize_uncompressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
        }
    }
    fn serialized_size(&self, compress: Compress) -> usize {
        match compress { Compress::Yes => self.0.compressed_size(), Compress::No => self.0.uncompressed_size() }
    }
}
impl DoryDeserialize for Bls377Fr {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bls12_377::Fr::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => ark_bls12_377::Fr::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls377Fr(inner))
    }
}

impl Valid for Bls377G1 {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls377G1 {
    fn serialize_with_mode<W: std::io::Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self.0.serialize_compressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
            Compress::No  => self.0.serialize_uncompressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
        }
    }
    fn serialized_size(&self, compress: Compress) -> usize {
        match compress { Compress::Yes => self.0.compressed_size(), Compress::No => self.0.uncompressed_size() }
    }
}
impl DoryDeserialize for Bls377G1 {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => G1Projective::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => G1Projective::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls377G1(inner))
    }
}

impl Valid for Bls377G2 {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls377G2 {
    fn serialize_with_mode<W: std::io::Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self.0.serialize_compressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
            Compress::No  => self.0.serialize_uncompressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
        }
    }
    fn serialized_size(&self, compress: Compress) -> usize {
        match compress { Compress::Yes => self.0.compressed_size(), Compress::No => self.0.uncompressed_size() }
    }
}
impl DoryDeserialize for Bls377G2 {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => G2Projective::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => G2Projective::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls377G2(inner))
    }
}

impl Valid for Bls377GT {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls377GT {
    fn serialize_with_mode<W: std::io::Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self.0.serialize_compressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
            Compress::No  => self.0.serialize_uncompressed(writer).map_err(|e| SerializationError::InvalidData(format!("{e}"))),
        }
    }
    fn serialized_size(&self, compress: Compress) -> usize {
        match compress { Compress::Yes => self.0.compressed_size(), Compress::No => self.0.uncompressed_size() }
    }
}
impl DoryDeserialize for Bls377GT {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => PairingOutput::<Bls12_377>::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => PairingOutput::<Bls12_377>::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls377GT(inner))
    }
}

// ── Transcript ───────────────────────────────────────────────────────────────

impl Transcript for Blake2bTranscript<BLS12_377> {
    type Curve = BLS12_377;

    fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_bytes_impl(label, bytes);
    }

    fn append_field(&mut self, label: &[u8], x: &Bls377Fr) {
        self.append_field_impl(label, &x.0);
    }

    fn append_group<G: Group + DorySerialize>(&mut self, label: &[u8], g: &G) {
        let mut bytes: Vec<u8> = Vec::new();
        g.serialize_with_mode(&mut bytes, Compress::Yes).expect("DorySerialize should not fail");
        self.append_bytes_impl(label, &bytes);
    }

    fn append_serde<S: DorySerialize>(&mut self, label: &[u8], s: &S) {
        let mut bytes: Vec<u8> = Vec::new();
        s.serialize_with_mode(&mut bytes, Compress::Yes).expect("DorySerialize should not fail");
        self.append_bytes_impl(label, &bytes);
    }

    fn challenge_scalar(&mut self, label: &[u8]) -> Bls377Fr {
        Bls377Fr(self.challenge_scalar_impl(label))
    }

    fn reset(&mut self, domain_label: &[u8]) {
        self.reset_impl(domain_label);
    }
}
