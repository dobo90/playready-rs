use crate::crypto::ecc_p256::{Keypair, PublicKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;

#[derive(Debug, Clone)]
pub struct XmlKey {
    shared_point: Keypair,
    aes_iv: [u8; 16],
    aes_key: [u8; 16],
}

impl XmlKey {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        let shared_point = Keypair::generate(&mut rng);
        let public = shared_point.public().as_element().to_encoded_point(false);
        let bytes = &public.as_bytes()[1..];

        let aes_iv = <[u8; 16]>::try_from(&bytes[..16]).unwrap();
        let aes_key = <[u8; 16]>::try_from(&bytes[16..32]).unwrap();

        Self {
            shared_point,
            aes_iv,
            aes_key,
        }
    }

    pub fn aes_iv(&self) -> &[u8; 16] {
        &self.aes_iv
    }

    pub fn aes_key(&self) -> &[u8; 16] {
        &self.aes_key
    }

    pub fn public_key(&self) -> &PublicKey {
        self.shared_point.public()
    }
}
