use elastic_elgamal::{group::Generic, Ciphertext};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, EncodedPoint, NistP256, ProjectivePoint,
};

use std::{ptr::copy_nonoverlapping, sync::OnceLock};

pub type PublicKey = elastic_elgamal::PublicKey<Generic<NistP256>>;
pub type SecretKey = elastic_elgamal::SecretKey<Generic<NistP256>>;
pub type Keypair = elastic_elgamal::Keypair<Generic<NistP256>>;

pub const SCALAR_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

pub trait ToUntaggedBytes {
    fn to_untagged_bytes(&self) -> Box<[u8]>;
}

impl<T: ToEncodedPoint<NistP256>> ToUntaggedBytes for T {
    fn to_untagged_bytes(&self) -> Box<[u8]> {
        self.to_encoded_point(false)
            .as_bytes()
            .iter()
            .copied()
            .skip(1) // skip tag
            .collect()
    }
}

pub trait FromBytes
where
    Self: Sized,
{
    type Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}

impl FromBytes for Keypair {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Keypair::from(
            SecretKey::from_bytes(bytes).ok_or(crate::Error::P256DecodeError)?,
        ))
    }
}

impl FromBytes for VerifyingKey {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let point = EncodedPoint::from_untagged_bytes(bytes.into());
        let point = AffinePoint::from_encoded_point(&point)
            .into_option()
            .ok_or(crate::Error::P256DecodeError)?;

        VerifyingKey::from_affine(point).or(Err(crate::Error::P256DecodeError))
    }
}

pub fn wmrm_public_key() -> &'static PublicKey {
    static CELL: OnceLock<PublicKey> = OnceLock::new();

    CELL.get_or_init(|| {
        const WMRM_KEY: [u8; 33] = [
            0x02, 0xc8, 0xb6, 0xaf, 0x16, 0xee, 0x94, 0x1a, 0xad, 0xaa, 0x53, 0x89, 0xb4, 0xaf,
            0x2c, 0x10, 0xe3, 0x56, 0xbe, 0x42, 0xaf, 0x17, 0x5e, 0xf3, 0xfa, 0xce, 0x93, 0x25,
            0x4e, 0x7b, 0x0b, 0x3d, 0x9b,
        ];

        PublicKey::from_bytes(&WMRM_KEY).unwrap()
    })
}

pub fn encrypt(public_key: &PublicKey, plaintext: ProjectivePoint) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let ciphertext = public_key.encrypt_element(plaintext, &mut rng);

    let point1 = ciphertext.random_element().to_untagged_bytes();
    let point2 = ciphertext.blinded_element().to_untagged_bytes();

    [point1, point2].concat()
}

pub fn decrypt(private_key: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let random_element = EncodedPoint::from_untagged_bytes(
        ciphertext
            .get(..64)
            .ok_or(crate::Error::SliceOutOfBoundsError(
                "ciphertext",
                ciphertext.len(),
            ))?
            .into(),
    );
    let random_element = AffinePoint::from_encoded_point(&random_element)
        .into_option()
        .ok_or(crate::Error::P256DecodeError)?;

    let blinded_element = EncodedPoint::from_untagged_bytes(
        ciphertext
            .get(64..)
            .ok_or(crate::Error::SliceOutOfBoundsError(
                "ciphertext",
                ciphertext.len(),
            ))?
            .into(),
    );
    let blinded_element = AffinePoint::from_encoded_point(&blinded_element)
        .into_option()
        .ok_or(crate::Error::P256DecodeError)?;

    let encrypted: Ciphertext<Generic<NistP256>> = Ciphertext::zero();

    // TODO: Remove unsafe code once https://github.com/slowli/elastic-elgamal/pull/157 is merged
    unsafe {
        copy_nonoverlapping(
            &random_element.into(),
            encrypted.random_element() as *const ProjectivePoint as *mut ProjectivePoint,
            1,
        );
        copy_nonoverlapping(
            &blinded_element.into(),
            encrypted.blinded_element() as *const ProjectivePoint as *mut ProjectivePoint,
            1,
        );
    };

    Ok(private_key
        .decrypt_to_element(encrypted)
        .to_untagged_bytes()
        .to_vec())
}

pub fn verify(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), p256::ecdsa::Error> {
    let signature = Signature::from_slice(signature)?;
    verifying_key.verify(msg, &signature)
}

pub fn sign(signing_key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(msg);
    signature.to_bytes().to_vec()
}
