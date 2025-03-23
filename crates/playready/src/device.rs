//! Creating and parsing devices.

use crate::{
    binary_format::{self},
    certificate::CertificateChain,
    crypto::ecc_p256::{FromBytes, Keypair, ToUntaggedBytes},
};
use binrw::{BinRead, BinWrite};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::PrimeField;
use rand::{thread_rng, Rng};
use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

/// Represents PlayReady device. Usually created from .prd file.
#[derive(Debug, Clone)]
pub struct Device {
    group_key: Option<SigningKey>,
    encryption_key: Keypair,
    signing_key: SigningKey,
    cert_chain: CertificateChain,
}

impl Device {
    /// Creates new [`Device`].
    pub fn new(
        group_key: Option<SigningKey>,
        encryption_key: Keypair,
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

    /// Creates new [`Device`] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        let device = binary_format::device::Device::read(&mut Cursor::new(bytes))?;

        let group_key = match &device.inner {
            binary_format::device::DeviceInner::V2(_) => None,
            binary_format::device::DeviceInner::V3(v3) => Some(&v3.group_key),
        };

        let group_key = match group_key {
            Some(group_key) => Some(SigningKey::from_slice(&group_key[..32])?),
            None => None,
        };

        let encryption_key = match &device.inner {
            binary_format::device::DeviceInner::V2(v2) => &v2.encryption_key,
            binary_format::device::DeviceInner::V3(v3) => &v3.encryption_key,
        };

        let signing_key = match &device.inner {
            binary_format::device::DeviceInner::V2(v2) => &v2.signing_key,
            binary_format::device::DeviceInner::V3(v3) => &v3.signing_key,
        };

        let encryption_key = Keypair::from_bytes(&encryption_key[..32])?;
        let signing_key = SigningKey::from_slice(&signing_key[..32])?;

        let group_certificate = match device.inner {
            binary_format::device::DeviceInner::V2(v2) => v2.group_certificate,
            binary_format::device::DeviceInner::V3(v3) => v3.group_certificate,
        };

        let cert_chain = CertificateChain::from_vec(group_certificate)?;

        Ok(Self {
            group_key,
            encryption_key,
            signing_key,
            cert_chain,
        })
    }

    /// Creates new [`Device`] from .prd file.
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
    pub fn encryption_key(&self) -> &Keypair {
        &self.encryption_key
    }

    /// Returns device group certificate.
    pub fn group_certificate(&self) -> &[u8] {
        self.cert_chain.raw()
    }

    /// Returns device group key.
    pub fn group_key(&self) -> Option<&SigningKey> {
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

    /// Performs signature verification of certificates bundled in [`CertificateChain`].
    pub fn verify_certificates(&self) -> Result<(), crate::Error> {
        self.cert_chain.verify_certificates()
    }

    /// Creates and provisions device from certificate chain and group key.
    pub fn provision(
        cert_chain: CertificateChain,
        group_key: SigningKey,
    ) -> Result<Self, crate::Error> {
        let mut rng = thread_rng();

        let client_id = rng.gen::<[u8; 16]>();
        let cert_id = rng.gen::<[u8; 16]>();

        let encryption_key = Keypair::generate(&mut rng);
        let signing_key = SigningKey::random(&mut rng);

        let public_encryption_key = encryption_key
            .public()
            .as_element()
            .to_untagged_bytes()
            .to_vec();

        let public_signing_key = signing_key
            .verifying_key()
            .as_affine()
            .to_untagged_bytes()
            .to_vec();

        let cert_chain = cert_chain.provision(
            cert_id,
            client_id,
            public_signing_key,
            public_encryption_key,
            &group_key,
        )?;

        cert_chain.verify_certificates()?;

        Ok(Self {
            group_key: Some(group_key),
            encryption_key,
            signing_key,
            cert_chain,
        })
    }

    /// Generates reprovisioned [`Device`].
    pub fn reprovision(self) -> Result<Self, crate::Error> {
        let Device {
            cert_chain,
            group_key,
            ..
        } = self;

        let group_key = group_key.ok_or(crate::Error::GroupKeyMissingError)?;

        Self::provision(cert_chain, group_key)
    }

    /// Creates and provisions device from file containing certificate chain
    /// (usually named bgroupcert.dat) and file with group key (usually zgpriv.dat).
    pub fn provision_from_files(
        group_cert_path: impl AsRef<Path>,
        group_key_path: impl AsRef<Path>,
    ) -> Result<Self, crate::Error> {
        let mut file = File::open(group_cert_path)?;
        let mut bytes = Vec::<u8>::new();
        file.read_to_end(&mut bytes)?;

        let cert_chain = CertificateChain::from_bytes(&bytes)?;

        file = File::open(group_key_path)?;
        bytes.clear();
        file.read_to_end(&mut bytes)?;

        let group_key = SigningKey::from_slice(bytes.get(..32).ok_or(
            crate::Error::SliceOutOfBoundsError("group_key", bytes.len()),
        )?)?;

        Self::provision(cert_chain, group_key)
    }

    /// Serializes and writes device to file specified by path.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<(), crate::Error> {
        let mut group_key = [0u8; 96];
        let mut encryption_key = [0u8; 96];
        let mut signing_key = [0u8; 96];

        group_key[..32].copy_from_slice(
            &self
                .group_key
                .as_ref()
                .ok_or(crate::Error::GroupKeyMissingError)?
                .to_bytes(),
        );

        encryption_key[..32]
            .copy_from_slice(&self.encryption_key.secret().expose_scalar().to_repr());
        signing_key[..32].copy_from_slice(&self.signing_key.to_bytes());

        let group_certificate = self.group_certificate().to_vec();
        let group_certificate_length = u32::try_from(group_certificate.len()).unwrap();

        let device = binary_format::device::Device {
            version: 3,
            inner: binary_format::device::DeviceInner::V3(binary_format::device::DeviceV3 {
                group_key,
                encryption_key,
                signing_key,
                group_certificate_length,
                group_certificate,
            }),
        };

        let mut file = File::create(path)?;
        device.write(&mut file)?;

        Ok(())
    }
}

impl TryFrom<&[u8]> for Device {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}
