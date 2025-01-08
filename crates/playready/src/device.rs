//! Creating and parsing devices.

use crate::{
    binary_format::{self},
    certificate::CertificateChain,
    crypto::ecc_p256,
};
use binrw::BinRead;
use p256::ecdsa::SigningKey;
use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

/// Represents PlayReady device. Usually created from .prd file.
#[derive(Debug, Clone)]
pub struct Device {
    group_key: Option<[u8; 96]>,
    encryption_key: ecc_p256::Keypair,
    signing_key: SigningKey,
    cert_chain: CertificateChain,
}

impl Device {
    /// Creates new `Device`.
    pub fn new(
        group_key: Option<[u8; 96]>,
        encryption_key: ecc_p256::Keypair,
        signing_key: SigningKey,
        cert_chain: CertificateChain,
    ) -> Self {
        Self {
            group_key,
            encryption_key,
            signing_key,
            cert_chain,
        }
    }

    /// Creates new `Device` from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        let device = binary_format::device::Device::read(&mut Cursor::new(bytes))?;

        let group_key = match &device.inner {
            binary_format::device::DeviceInner::V2(_) => None,
            binary_format::device::DeviceInner::V3(v3) => Some(v3.group_key),
        };

        let encryption_key = match &device.inner {
            binary_format::device::DeviceInner::V2(v2) => v2.encryption_key,
            binary_format::device::DeviceInner::V3(v3) => v3.encryption_key,
        };

        let signing_key = match &device.inner {
            binary_format::device::DeviceInner::V2(v2) => v2.signing_key,
            binary_format::device::DeviceInner::V3(v3) => v3.signing_key,
        };

        let group_certificate = match &device.inner {
            binary_format::device::DeviceInner::V2(v2) => v2.group_certificate.clone(),
            binary_format::device::DeviceInner::V3(v3) => v3.group_certificate.clone(),
        };

        let cert_chain = CertificateChain::from_vec(group_certificate)?;

        let encryption_key = ecc_p256::create_key_pair_from_bytes(&encryption_key[..32])?;
        let signing_key = SigningKey::from_slice(&signing_key[..32])?;

        Ok(Self {
            group_key,
            encryption_key,
            signing_key,
            cert_chain,
        })
    }

    /// Creates new `Device` from .prd file.
    ///
    /// # Arguments
    ///
    /// `path` - path to .prd file
    pub fn from_prd(path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        let mut file = File::open(path)?;
        let mut bytes = Vec::<u8>::new();
        file.read_to_end(&mut bytes)?;

        Self::from_bytes(&bytes)
    }

    /// Returns device signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Returns device encryption key.
    pub fn encryption_key(&self) -> &ecc_p256::Keypair {
        &self.encryption_key
    }

    /// Returns device group certificate.
    pub fn group_certificate(&self) -> &[u8] {
        self.cert_chain.raw()
    }

    /// Returns device group key.
    pub fn group_key(&self) -> Option<&[u8; 96]> {
        self.group_key.as_ref()
    }

    /// Returns name of the device parsed from certificate chain.
    pub fn name(&self) -> Result<String, crate::Error> {
        self.cert_chain.name()
    }

    /// Returns security level (SL????) of the device parsed from certificate chain.
    pub fn security_level(&self) -> Result<u32, crate::Error> {
        self.cert_chain.security_level()
    }

    /// Performs signature verification of certificates bundled in `BCertChain`.
    pub fn verify_certificates(&self) -> Result<(), crate::Error> {
        self.cert_chain.verify_certificates()
    }
}

impl TryFrom<&[u8]> for Device {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}
