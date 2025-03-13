//! Core module of playready-rs.

use crate::{
    binary_format::xmr_license::CipherType,
    crypto::{
        aes,
        ecc_p256::{self, ToUntaggedBytes},
        sha256,
    },
    device::Device,
    license::License,
    pssh::WrmHeader,
    xml_key::XmlKey,
    xml_utils,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use rand::{thread_rng, Rng};
use std::{
    fmt,
    sync::{atomic::AtomicU32, Arc},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const PROTOCOL_VERSION: &str = "1";
const CLIENT_VERSION: &str = "10.0.16384.10011";
const RGB_MAGIC_CONSTANT_ZERO: [u8; 16] = [
    0x7e, 0xe9, 0xed, 0x4a, 0xf7, 0x73, 0x22, 0x4f, 0x00, 0xb8, 0xea, 0x7e, 0xfb, 0x02, 0x7c, 0xbb,
];

/// Structure representing key id (KID).
#[derive(Clone)]
pub struct KeyId([u8; 16]);

impl From<[u8; 16]> for KeyId {
    fn from(value: [u8; 16]) -> Self {
        KeyId(value)
    }
}

impl From<KeyId> for [u8; 16] {
    fn from(value: KeyId) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.0).as_str())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.0).as_str())
    }
}

/// Structure representing content key.
#[derive(Clone)]
pub struct ContentKey(Box<[u8]>);

impl From<Box<[u8]>> for ContentKey {
    fn from(value: Box<[u8]>) -> Self {
        ContentKey(value)
    }
}

impl From<ContentKey> for Box<[u8]> {
    fn from(value: ContentKey) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for ContentKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.0).as_str())
    }
}

impl fmt::Display for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.0).as_str())
    }
}

struct ContentIntegrityKey(Box<[u8]>);

impl From<Box<[u8]>> for ContentIntegrityKey {
    fn from(value: Box<[u8]>) -> Self {
        ContentIntegrityKey(value)
    }
}

impl From<ContentIntegrityKey> for Box<[u8]> {
    fn from(value: ContentIntegrityKey) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for ContentIntegrityKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ContentIntegrityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.0).as_str())
    }
}

impl fmt::Display for ContentIntegrityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.0).as_str())
    }
}

type KidCkCi = (KeyId, ContentKey, ContentIntegrityKey);
type KidCk = (KeyId, ContentKey);

/// The entry point of PlayReady CDM.
///
/// The easiest way to construct it is to use `from_device` function.
#[derive(Debug, Clone)]
pub struct Cdm {
    device: Arc<Device>,
}

/// Represents CDM session. Provides the core functionality of CDM.
#[derive(Debug, Clone)]
pub struct Session {
    id: u32,
    device: Arc<Device>,
    xml_key: XmlKey,
}

impl Cdm {
    /// Creates CDM from the `Device`.
    pub fn from_device(device: Device) -> Self {
        let device = Arc::new(device);

        Self { device }
    }

    /// Opens new CDM session.
    pub fn open_session(&self) -> Session {
        static SESSION_COUNTER: AtomicU32 = AtomicU32::new(0);
        let id = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Session::new(id, Arc::clone(&self.device))
    }
}

impl Session {
    fn new(id: u32, device: Arc<Device>) -> Self {
        let xml_key = XmlKey::new();

        Self {
            id,
            device,
            xml_key,
        }
    }

    /// Returns ID of the session.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Generates XML containing license acquisition challenge.
    /// XML prolog is deliberately missing as sometimes challenge XML is embedded in JSON.
    ///
    /// # Arguments
    ///
    /// `wrm_header` - header usually extracted from `Pssh`
    pub fn get_license_challenge(&self, wrm_header: WrmHeader) -> Result<String, crate::Error> {
        let nonce = BASE64_STANDARD.encode(thread_rng().gen::<[u8; 16]>());
        let wmrm_cipher = BASE64_STANDARD.encode(self.key_data());
        let cert_cipher = BASE64_STANDARD.encode(self.cipher_data()?);

        let la_content_tag = xml_utils::build_digest_content(
            String::from(PROTOCOL_VERSION),
            String::from(CLIENT_VERSION),
            Self::client_time(),
            wrm_header.into(),
            nonce,
            wmrm_cipher,
            cert_cipher,
        )?;

        let la_content = xml_utils::render(&la_content_tag)?;
        let la_hash = BASE64_STANDARD.encode(sha256::hash(&la_content));

        let signed_info_tag = xml_utils::build_signed_info(la_hash)?;
        let signed_info = xml_utils::render(&signed_info_tag)?;

        let signature = ecc_p256::sign(self.device.signing_key(), &signed_info);
        let signature = BASE64_STANDARD.encode(signature);

        let public_key = self
            .device
            .signing_key()
            .verifying_key()
            .as_affine()
            .to_untagged_bytes();
        let public_key = BASE64_STANDARD.encode(public_key);

        let challenge_tag = xml_utils::build_license_challenge(
            la_content_tag,
            signed_info_tag,
            signature,
            public_key,
        )?;

        let challenge = xml_utils::render(&challenge_tag)?;

        String::from_utf8(challenge).map_err(|e| e.into())
    }

    /// Parses response (usually got from the license server) and returns vector of KID and key tuples.
    pub fn get_keys_from_challenge_response(
        &self,
        response: &str,
    ) -> Result<Vec<KidCk>, crate::Error> {
        let licenses = xml_utils::parse_challenge_response(response)?;
        if licenses.is_empty() {
            return Err(crate::Error::LicenseMissingError);
        }

        let device_public_key = self
            .device
            .encryption_key()
            .public()
            .as_element()
            .to_untagged_bytes();

        let mut decrypted_keys = Vec::<KidCk>::with_capacity(licenses.len());

        for license in licenses {
            let license = match License::from_b64(license.as_str()) {
                Ok(license) => license,
                Err(e) => {
                    log::error!("Failed to create license: {e:?}");
                    continue;
                }
            };

            if *license.public_key()? != *device_public_key {
                return Err(crate::Error::PublicKeyMismatchError("device"));
            }

            let aux_key = license.auxiliary_key();

            decrypted_keys.extend(license.encrypted_keys().iter().filter_map(|encrypted_key| {
                let (kid, ck, ci) = self
                    .decrypt_key(encrypted_key, &aux_key)
                    .inspect_err(|e| log::error!("Failed to decrypt key: {e:?}"))
                    .ok()?;

                let (msg, signature) = license
                    .cmac_verification_data()
                    .inspect_err(|e| {
                        log::error!(
                            "Failed to get MAC verification data {e:?}. Skipping KID: {kid:?}"
                        )
                    })
                    .ok()?;

                aes::verify_cmac(ci.as_ref(), msg, &signature)
                    .inspect_err(|e| log::error!("Signature mismatch {e:?}. Skipping KID: {kid:?}"))
                    .ok()?;

                Some((kid, ck))
            }));
        }

        Ok(decrypted_keys)
    }

    fn decrypt_key(
        &self,
        encrypted_key: &(CipherType, [u8; 16], Vec<u8>),
        aux_key: &Option<[u8; 16]>,
    ) -> Result<KidCkCi, crate::Error> {
        match encrypted_key.0 {
            CipherType::Ecc256 | CipherType::Ecc256WithKZ | CipherType::Ecc256ViaSymmetric => (),
            _ => {
                return Err(crate::Error::UnsupportedCipherTypeError(encrypted_key.0));
            }
        };

        let decrypted = ecc_p256::decrypt(self.device.encryption_key().secret(), &encrypted_key.2)?;

        let mut ci = decrypted
            .get(..16)
            .ok_or(crate::Error::SliceOutOfBoundsError(
                "decrypted",
                decrypted.len(),
            ))?
            .to_vec();
        let mut ck = decrypted
            .get(16..32)
            .ok_or(crate::Error::SliceOutOfBoundsError(
                "decrypted",
                decrypted.len(),
            ))?
            .to_vec();

        if let Some(aux_key) = aux_key {
            ci = decrypted
                .iter()
                .copied()
                .step_by(2)
                .take(16)
                .collect::<Vec<u8>>();
            ck = decrypted
                .iter()
                .copied()
                .skip(1)
                .step_by(2)
                .take(16)
                .collect::<Vec<u8>>();

            if encrypted_key.0 == CipherType::Ecc256ViaSymmetric {
                let embedded_root_license =
                    &encrypted_key
                        .2
                        .get(..144)
                        .ok_or(crate::Error::SliceOutOfBoundsError(
                            "encrypted_key",
                            encrypted_key.2.len(),
                        ))?;
                let embedded_leaf_license =
                    &encrypted_key
                        .2
                        .get(144..)
                        .ok_or(crate::Error::SliceOutOfBoundsError(
                            "encrypted_key",
                            encrypted_key.2.len(),
                        ))?;

                let rgb_key = ck
                    .iter()
                    .zip(RGB_MAGIC_CONSTANT_ZERO)
                    .map(|v| v.0 ^ v.1)
                    .collect::<Vec<_>>();

                let content_key_prime = aes::encrypt_ecb(&ck, &rgb_key)?;
                let uplink_x_key = aes::encrypt_ecb(&content_key_prime, aux_key)?;

                let secondary_key = aes::encrypt_ecb(
                    &ck,
                    embedded_root_license
                        .get(128..)
                        .ok_or(crate::Error::SliceOutOfBoundsError(
                            "embedded_root_license",
                            embedded_root_license.len(),
                        ))?,
                )?;

                let embedded_leaf_license = aes::encrypt_ecb(&uplink_x_key, embedded_leaf_license)?;
                let embedded_leaf_license =
                    aes::encrypt_ecb(&secondary_key, &embedded_leaf_license)?;

                ci = embedded_leaf_license
                    .get(..16)
                    .ok_or(crate::Error::SliceOutOfBoundsError(
                        "embedded_leaf_license",
                        embedded_leaf_license.len(),
                    ))?
                    .to_vec();
                ck = embedded_leaf_license
                    .get(16..)
                    .ok_or(crate::Error::SliceOutOfBoundsError(
                        "embedded_leaf_license",
                        embedded_leaf_license.len(),
                    ))?
                    .to_vec();
            }
        }

        let uuid = Uuid::from_bytes_le(encrypted_key.1);
        let kid = *uuid.as_bytes();

        Ok((
            KeyId::from(kid),
            ContentKey::from(ck.into_boxed_slice()),
            ContentIntegrityKey::from(ci.into_boxed_slice()),
        ))
    }

    fn cipher_data(&self) -> Result<Vec<u8>, crate::Error> {
        let body_tag =
            xml_utils::build_cipher_data(BASE64_STANDARD.encode(self.device.group_certificate()))?;

        let body = xml_utils::render(&body_tag)?;
        let ciphertext = aes::encrypt_cbc(self.xml_key.aes_key(), self.xml_key.aes_iv(), &body)?;

        Ok([self.xml_key.aes_iv(), ciphertext.as_slice()].concat())
    }

    fn key_data(&self) -> Vec<u8> {
        ecc_p256::encrypt(
            ecc_p256::wmrm_public_key(),
            self.xml_key.public_key().as_element(),
        )
    }

    fn client_time() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }
}
