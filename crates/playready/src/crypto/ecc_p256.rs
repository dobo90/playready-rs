use elastic_elgamal::{group::Generic, Ciphertext};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, FieldBytes, NistP256, ProjectivePoint, Scalar,
};

use std::sync::OnceLock;

pub type PublicKey = elastic_elgamal::PublicKey<Generic<NistP256>>;
pub type SecretKey = elastic_elgamal::SecretKey<Generic<NistP256>>;
pub type Keypair = elastic_elgamal::Keypair<Generic<NistP256>>;

pub fn wmrm_public_key() -> &'static PublicKey {
    static CELL: OnceLock<PublicKey> = OnceLock::new();

    CELL.get_or_init(|| {
        const WMRM_KEY: [u8; 64] = [
            0xc8, 0xb6, 0xaf, 0x16, 0xee, 0x94, 0x1a, 0xad, 0xaa, 0x53, 0x89, 0xb4, 0xaf, 0x2c,
            0x10, 0xe3, 0x56, 0xbe, 0x42, 0xaf, 0x17, 0x5e, 0xf3, 0xfa, 0xce, 0x93, 0x25, 0x4e,
            0x7b, 0x0b, 0x3d, 0x9b, 0x98, 0x2b, 0x27, 0xb5, 0xcb, 0x23, 0x41, 0x32, 0x6e, 0x56,
            0xaa, 0x85, 0x7d, 0xbf, 0xd5, 0xc6, 0x34, 0xce, 0x2c, 0xf9, 0xea, 0x74, 0xfc, 0xa8,
            0xf2, 0xaf, 0x59, 0x57, 0xef, 0xee, 0xa5, 0x62,
        ];

        let point = EncodedPoint::from_untagged_bytes(&WMRM_KEY.into());
        let point = AffinePoint::from_encoded_point(&point).unwrap();

        PublicKey::from_element(point.into())
    })
}

pub fn encrypt(public_key: &PublicKey, plaintext: ProjectivePoint) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let ciphertext = public_key.encrypt_element(plaintext, &mut rng);

    let point1 = ciphertext.random_element().to_encoded_point(false);
    let point2 = ciphertext.blinded_element().to_encoded_point(false);

    [&point1.as_bytes()[1..], &point2.as_bytes()[1..]].concat()
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

    let encrypted = Ciphertext::from_elements(random_element.into(), blinded_element.into());

    let point = private_key
        .decrypt_to_element(encrypted)
        .to_encoded_point(false);

    Ok(point.as_bytes()[1..].to_vec())
}

pub fn create_key_pair_from_bytes(private_key: &[u8]) -> Result<Keypair, crate::Error> {
    let private_key = FieldBytes::from_slice(private_key);
    let private_key = Scalar::from_repr(*private_key)
        .into_option()
        .ok_or(crate::Error::P256DecodeError)?;

    Ok(Keypair::from(SecretKey::new(private_key)))
}

pub fn create_verifying_key_from_bytes(pub_key: &[u8]) -> Result<VerifyingKey, crate::Error> {
    let point = EncodedPoint::from_untagged_bytes(pub_key.into());
    let point = AffinePoint::from_encoded_point(&point)
        .into_option()
        .ok_or(crate::Error::P256DecodeError)?;

    VerifyingKey::from_affine(point).or(Err(crate::Error::P256DecodeError))
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
