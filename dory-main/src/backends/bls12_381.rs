#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
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
pub struct Bls381Fr(pub ark_bls12_381::Fr);

impl Field for Bls381Fr {
    fn zero() -> Self { Bls381Fr(ark_bls12_381::Fr::from(0u64)) }
    fn one() -> Self  { Bls381Fr(ark_bls12_381::Fr::from(1u64)) }
    fn is_zero(&self) -> bool { ArkZero::is_zero(&self.0) }
    fn add(&self, rhs: &Self) -> Self { Bls381Fr(self.0 + rhs.0) }
    fn sub(&self, rhs: &Self) -> Self { Bls381Fr(self.0 - rhs.0) }
    fn mul(&self, rhs: &Self) -> Self { Bls381Fr(self.0 * rhs.0) }
    fn inv(self) -> Option<Self> { ArkField::inverse(&self.0).map(Bls381Fr) }
    fn random() -> Self { Bls381Fr(ark_bls12_381::Fr::rand(&mut rand_core::OsRng)) }
    fn from_u64(val: u64) -> Self { Bls381Fr(ark_bls12_381::Fr::from(val)) }
    fn from_i64(val: i64) -> Self {
        if val >= 0 { Bls381Fr(ark_bls12_381::Fr::from(val as u64)) }
        else { Bls381Fr(-ark_bls12_381::Fr::from((-val) as u64)) }
    }
}

impl Add for Bls381Fr { type Output = Self; fn add(self, rhs: Self) -> Self { Bls381Fr(self.0 + rhs.0) } }
impl Sub for Bls381Fr { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls381Fr(self.0 - rhs.0) } }
impl Mul for Bls381Fr { type Output = Self; fn mul(self, rhs: Self) -> Self { Bls381Fr(self.0 * rhs.0) } }
impl Neg for Bls381Fr { type Output = Self; fn neg(self) -> Self { Bls381Fr(-self.0) } }
impl<'a> Add<&'a Bls381Fr> for Bls381Fr { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls381Fr(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls381Fr> for Bls381Fr { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls381Fr(self.0 - rhs.0) } }
impl<'a> Mul<&'a Bls381Fr> for Bls381Fr { type Output = Self; fn mul(self, rhs: &'a Self) -> Self { Bls381Fr(self.0 * rhs.0) } }

// ── G1 ───────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls381G1(pub G1Projective);

impl Group for Bls381G1 {
    type Scalar = Bls381Fr;
    fn identity() -> Self { Bls381G1(ArkZero::zero()) }
    fn add(&self, rhs: &Self) -> Self { Bls381G1(self.0 + rhs.0) }
    fn neg(&self) -> Self { Bls381G1(-self.0) }
    fn scale(&self, k: &Self::Scalar) -> Self { Bls381G1(self.0 * k.0) }
    fn random() -> Self { Bls381G1(G1Projective::rand(&mut rand_core::OsRng)) }
}

impl Add for Bls381G1  { type Output = Self; fn add(self, rhs: Self) -> Self { Bls381G1(self.0 + rhs.0) } }
impl Sub for Bls381G1  { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls381G1(self.0 - rhs.0) } }
impl Neg for Bls381G1  { type Output = Self; fn neg(self) -> Self { Bls381G1(-self.0) } }
impl<'a> Add<&'a Bls381G1> for Bls381G1 { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls381G1(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls381G1> for Bls381G1 { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls381G1(self.0 - rhs.0) } }
impl Mul<Bls381G1> for Bls381Fr { type Output = Bls381G1; fn mul(self, rhs: Bls381G1) -> Bls381G1 { Bls381G1(rhs.0 * self.0) } }
impl<'a> Mul<&'a Bls381G1> for Bls381Fr { type Output = Bls381G1; fn mul(self, rhs: &'a Bls381G1) -> Bls381G1 { Bls381G1(rhs.0 * self.0) } }

// ── G2 ───────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls381G2(pub G2Projective);

impl Group for Bls381G2 {
    type Scalar = Bls381Fr;
    fn identity() -> Self { Bls381G2(ArkZero::zero()) }
    fn add(&self, rhs: &Self) -> Self { Bls381G2(self.0 + rhs.0) }
    fn neg(&self) -> Self { Bls381G2(-self.0) }
    fn scale(&self, k: &Self::Scalar) -> Self { Bls381G2(self.0 * k.0) }
    fn random() -> Self { Bls381G2(G2Projective::rand(&mut rand_core::OsRng)) }
}

impl Add for Bls381G2  { type Output = Self; fn add(self, rhs: Self) -> Self { Bls381G2(self.0 + rhs.0) } }
impl Sub for Bls381G2  { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls381G2(self.0 - rhs.0) } }
impl Neg for Bls381G2  { type Output = Self; fn neg(self) -> Self { Bls381G2(-self.0) } }
impl<'a> Add<&'a Bls381G2> for Bls381G2 { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls381G2(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls381G2> for Bls381G2 { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls381G2(self.0 - rhs.0) } }
impl Mul<Bls381G2> for Bls381Fr { type Output = Bls381G2; fn mul(self, rhs: Bls381G2) -> Bls381G2 { Bls381G2(rhs.0 * self.0) } }
impl<'a> Mul<&'a Bls381G2> for Bls381Fr { type Output = Bls381G2; fn mul(self, rhs: &'a Bls381G2) -> Bls381G2 { Bls381G2(rhs.0 * self.0) } }

// ── GT ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[repr(transparent)]
pub struct Bls381GT(pub PairingOutput<Bls12_381>);

impl Default for Bls381GT {
    fn default() -> Self {
        Bls381GT(PairingOutput(<Bls12_381 as Pairing>::TargetField::one()))
    }
}

impl Group for Bls381GT {
    type Scalar = Bls381Fr;
    fn identity() -> Self { Self::default() }
    fn add(&self, rhs: &Self) -> Self { Bls381GT(self.0 + rhs.0) }
    fn neg(&self) -> Self {
        Bls381GT(PairingOutput(ArkField::inverse(&self.0.0).expect("GT inverse")))
    }
    fn scale(&self, k: &Self::Scalar) -> Self {
        Bls381GT(PairingOutput(self.0.0.pow(k.0.into_bigint())))
    }
    fn random() -> Self {
        Bls381GT(Bls12_381::pairing(
            G1Affine::rand(&mut rand_core::OsRng),
            G2Affine::rand(&mut rand_core::OsRng),
        ))
    }
}

impl Add for Bls381GT  { type Output = Self; fn add(self, rhs: Self) -> Self { Bls381GT(self.0 + rhs.0) } }
impl Sub for Bls381GT  { type Output = Self; fn sub(self, rhs: Self) -> Self { Bls381GT(self.0 - rhs.0) } }
impl Neg for Bls381GT  { type Output = Self; fn neg(self) -> Self { Bls381GT(-self.0) } }
impl<'a> Add<&'a Bls381GT> for Bls381GT { type Output = Self; fn add(self, rhs: &'a Self) -> Self { Bls381GT(self.0 + rhs.0) } }
impl<'a> Sub<&'a Bls381GT> for Bls381GT { type Output = Self; fn sub(self, rhs: &'a Self) -> Self { Bls381GT(self.0 - rhs.0) } }
impl Mul<Bls381GT> for Bls381Fr {
    type Output = Bls381GT;
    fn mul(self, rhs: Bls381GT) -> Bls381GT { Bls381GT(PairingOutput(rhs.0.0.pow(self.0.into_bigint()))) }
}
impl<'a> Mul<&'a Bls381GT> for Bls381Fr {
    type Output = Bls381GT;
    fn mul(self, rhs: &'a Bls381GT) -> Bls381GT { Bls381GT(PairingOutput(rhs.0.0.pow(self.0.into_bigint()))) }
}

// ── PairingCurve ─────────────────────────────────────────────────────────────

#[derive(Default, Clone, Debug)]
pub struct BLS12_381;

impl PairingCurve for BLS12_381 {
    type G1 = Bls381G1;
    type G2 = Bls381G2;
    type GT = Bls381GT;

    fn pair(p: &Bls381G1, q: &Bls381G2) -> Bls381GT {
        Bls381GT(Bls12_381::pairing(p.0, q.0))
    }

    fn multi_pair(ps: &[Bls381G1], qs: &[Bls381G2]) -> Bls381GT {
        assert_eq!(ps.len(), qs.len(), "multi_pair requires equal length vectors");
        if ps.is_empty() { return Bls381GT::identity(); }
        let ps_prep: Vec<<Bls12_381 as Pairing>::G1Prepared> =
            ps.iter().map(|p| { let a: G1Affine = p.0.into_affine(); a.into() }).collect();
        let qs_prep: Vec<<Bls12_381 as Pairing>::G2Prepared> =
            qs.iter().map(|q| { let a: G2Affine = q.0.into_affine(); a.into() }).collect();
        let out = Bls12_381::final_exponentiation(Bls12_381::multi_miller_loop(ps_prep, qs_prep))
            .expect("final_exponentiation failed");
        Bls381GT(out)
    }
}

// ── DoryRoutines ─────────────────────────────────────────────────────────────

pub struct Bls381G1Routines;

impl DoryRoutines<Bls381G1> for Bls381G1Routines {
    fn msm(bases: &[Bls381G1], scalars: &[Bls381Fr]) -> Bls381G1 {
        assert_eq!(bases.len(), scalars.len(), "MSM requires equal length vectors");
        if bases.is_empty() { return Bls381G1::identity(); }
        let aff: Vec<G1Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let frs: Vec<ark_bls12_381::Fr> = scalars.iter().map(|s| s.0).collect();
        Bls381G1(G1Projective::msm(&aff, &frs).expect("MSM failed"))
    }
    fn fixed_base_vector_scalar_mul(base: &Bls381G1, scalars: &[Bls381Fr]) -> Vec<Bls381G1> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }
    fn fixed_scalar_mul_bases_then_add(bases: &[Bls381G1], vs: &mut [Bls381G1], scalar: &Bls381Fr) {
        for (v, b) in vs.iter_mut().zip(bases.iter()) { *v = v.add(&b.scale(scalar)); }
    }
    fn fixed_scalar_mul_vs_then_add(vs: &mut [Bls381G1], addends: &[Bls381G1], scalar: &Bls381Fr) {
        for (v, a) in vs.iter_mut().zip(addends.iter()) { *v = v.scale(scalar).add(a); }
    }
}

pub struct Bls381G2Routines;

impl DoryRoutines<Bls381G2> for Bls381G2Routines {
    fn msm(bases: &[Bls381G2], scalars: &[Bls381Fr]) -> Bls381G2 {
        assert_eq!(bases.len(), scalars.len(), "MSM requires equal length vectors");
        if bases.is_empty() { return Bls381G2::identity(); }
        let aff: Vec<G2Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let frs: Vec<ark_bls12_381::Fr> = scalars.iter().map(|s| s.0).collect();
        Bls381G2(G2Projective::msm(&aff, &frs).expect("MSM failed"))
    }
    fn fixed_base_vector_scalar_mul(base: &Bls381G2, scalars: &[Bls381Fr]) -> Vec<Bls381G2> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }
    fn fixed_scalar_mul_bases_then_add(bases: &[Bls381G2], vs: &mut [Bls381G2], scalar: &Bls381Fr) {
        for (v, b) in vs.iter_mut().zip(bases.iter()) { *v = v.add(&b.scale(scalar)); }
    }
    fn fixed_scalar_mul_vs_then_add(vs: &mut [Bls381G2], addends: &[Bls381G2], scalar: &Bls381Fr) {
        for (v, a) in vs.iter_mut().zip(addends.iter()) { *v = v.scale(scalar).add(a); }
    }
}

// ── DorySerialize / DoryDeserialize ──────────────────────────────────────────

impl Valid for Bls381Fr {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls381Fr {
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
impl DoryDeserialize for Bls381Fr {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bls12_381::Fr::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => ark_bls12_381::Fr::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls381Fr(inner))
    }
}

impl Valid for Bls381G1 {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls381G1 {
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
impl DoryDeserialize for Bls381G1 {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => G1Projective::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => G1Projective::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls381G1(inner))
    }
}

impl Valid for Bls381G2 {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls381G2 {
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
impl DoryDeserialize for Bls381G2 {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => G2Projective::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => G2Projective::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls381G2(inner))
    }
}

impl Valid for Bls381GT {
    fn check(&self) -> Result<(), SerializationError> {
        ArkValid::check(&self.0).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))
    }
}
impl DorySerialize for Bls381GT {
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
impl DoryDeserialize for Bls381GT {
    fn deserialize_with_mode<R: std::io::Read>(reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => PairingOutput::<Bls12_381>::deserialize_compressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
            Compress::No  => PairingOutput::<Bls12_381>::deserialize_uncompressed(reader).map_err(|e| SerializationError::InvalidData(format!("{e}")))?,
        };
        if matches!(validate, Validate::Yes) { ArkValid::check(&inner).map_err(|e| SerializationError::InvalidData(format!("{e:?}")))?; }
        Ok(Bls381GT(inner))
    }
}

// ── Transcript ───────────────────────────────────────────────────────────────

impl Transcript for Blake2bTranscript<BLS12_381> {
    type Curve = BLS12_381;

    fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_bytes_impl(label, bytes);
    }

    fn append_field(&mut self, label: &[u8], x: &Bls381Fr) {
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

    fn challenge_scalar(&mut self, label: &[u8]) -> Bls381Fr {
        Bls381Fr(self.challenge_scalar_impl(label))
    }

    fn reset(&mut self, domain_label: &[u8]) {
        self.reset_impl(domain_label);
    }
}
