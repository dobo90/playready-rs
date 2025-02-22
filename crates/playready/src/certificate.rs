//! Helper structs for accessing BCert and BCertChain binary formats.

use crate::binary_format::StructTag;
use binrw::BinRead;
use std::io::Cursor;

use crate::{
    binary_format::bcert::{
        AttributeInner, BCert, BCertChain, DrmBCertBasicInfo, DrmBCertKeyInfo,
        DrmBCertManufacturerInfo, DrmBCertSignatureInfo,
    },
    crypto::ecc_p256,
};

const ROOT_ISSUER_KEY: [u8; 64] = [
    0x86, 0x4d, 0x61, 0xcf, 0xf2, 0x25, 0x6e, 0x42, 0x2c, 0x56, 0x8b, 0x3c, 0x28, 0x00, 0x1c, 0xfb,
    0x3e, 0x15, 0x27, 0x65, 0x85, 0x84, 0xba, 0x05, 0x21, 0xb7, 0x9b, 0x18, 0x28, 0xd9, 0x36, 0xde,
    0x1d, 0x82, 0x6a, 0x8f, 0xc3, 0xe6, 0xe7, 0xfa, 0x7a, 0x90, 0xd5, 0xca, 0x29, 0x46, 0xf1, 0xf6,
    0x4a, 0x2e, 0xfb, 0x9f, 0x5d, 0xcf, 0xfe, 0x7e, 0x43, 0x4e, 0xb4, 0x42, 0x93, 0xfa, 0xc5, 0xab,
];

#[derive(Debug, Clone)]
struct Certificate {
    parsed: BCert,
    raw: Vec<u8>,
}

impl Certificate {
    fn new(bcert: BCert, raw: Vec<u8>) -> Self {
        Self { parsed: bcert, raw }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, binrw::Error> {
        let parsed = BCert::read(&mut Cursor::new(&bytes))?;
        let raw = bytes.to_vec();

        Ok(Self { parsed, raw })
    }

    pub fn from_vec(vec: Vec<u8>) -> Result<Self, binrw::Error> {
        let parsed = BCert::read(&mut Cursor::new(&vec))?;

        Ok(Self { parsed, raw: vec })
    }

    fn issuer_key(&self) -> Option<Vec<u8>> {
        let attribute = self
            .parsed
            .attributes
            .iter()
            .find(|a| a.tag == DrmBCertKeyInfo::TAG)?;

        let cert_info = match &attribute.inner {
            AttributeInner::DrmBCertKeyInfo(inner) => Some(inner),
            _ => None,
        }?;

        for cert in &cert_info.cert_keys {
            if cert.usages.contains(&6) {
                return Some(cert.key.clone());
            }
        }

        None
    }

    fn verify(&self, public_key: &[u8]) -> Result<(), crate::Error> {
        let attribute = self
            .parsed
            .attributes
            .iter()
            .find(|a| a.tag == DrmBCertSignatureInfo::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError(
                "DrmBCertSignatureInfo",
            ))?;

        let sig_info = match &attribute.inner {
            AttributeInner::DrmBCertSignatureInfo(inner) => Some(inner),
            _ => None,
        }
        .ok_or(crate::Error::BinaryObjectNotFoundError(
            "DrmBCertSignatureInfo",
        ))?;

        if public_key != sig_info.signature_key {
            return Err(crate::Error::PublicKeyMismatchError("BCert"));
        }

        let msg_end = self.raw.len() - usize::try_from(attribute.length)?;

        ecc_p256::verify(
            &ecc_p256::create_verifying_key_from_bytes(&sig_info.signature_key)?,
            self.raw
                .get(..msg_end)
                .ok_or(crate::Error::SliceOutOfBoundsError(
                    "cert.raw",
                    self.raw.len(),
                ))?,
            &sig_info.signature,
        )
        .map_err(|e| e.into())
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = binrw::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for Certificate {
    type Error = binrw::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}

/// Wrapper structure for `BCertChain` structure.
#[derive(Debug, Clone)]
pub struct CertificateChain {
    parsed: BCertChain,
    raw: Vec<u8>,
}

impl CertificateChain {
    /// Creates new `CertificateChain` from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, binrw::Error> {
        let parsed = BCertChain::read(&mut Cursor::new(&bytes))?;
        let raw = bytes.to_vec();

        Ok(Self { parsed, raw })
    }

    /// Creates new `CertificateChain` from vector.
    pub fn from_vec(vec: Vec<u8>) -> Result<Self, binrw::Error> {
        let parsed = BCertChain::read(&mut Cursor::new(&vec))?;

        Ok(Self { parsed, raw: vec })
    }

    /// Creates raw bytes of `CertificateChain`.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Returns security level (SL????) of the device.
    pub fn security_level(&self) -> Result<u32, crate::Error> {
        let attributes = &self
            .parsed
            .certificates
            .first()
            .ok_or(crate::Error::CertificateMissingError)?
            .attributes;

        let attribute = attributes
            .iter()
            .find(|a| a.tag == DrmBCertBasicInfo::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError("DrmBCertBasicInfo"))?;

        match &attribute.inner {
            AttributeInner::DrmBCertBasicInfo(inner) => Ok(inner.security_level),
            _ => Err(crate::Error::BinaryObjectNotFoundError("DrmBCertBasicInfo")),
        }
    }

    /// Returns name of the device.
    pub fn name(&self) -> Result<String, crate::Error> {
        fn from_null_terminated_string(s: Vec<u8>) -> String {
            let s = s.into_iter().take_while(|c| *c != b'\x00').collect();
            String::from_utf8(s)
                .inspect_err(|e| log::error!("Failed to create utf8 string: {e:?}"))
                .unwrap_or_default()
        }

        let attributes = &self
            .parsed
            .certificates
            .first()
            .ok_or(crate::Error::CertificateMissingError)?
            .attributes;

        let attribute = attributes
            .iter()
            .find(|a| a.tag == DrmBCertManufacturerInfo::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError(
                "DrmBCertManufacturerInfo",
            ))?;

        match &attribute.inner {
            AttributeInner::DrmBCertManufacturerInfo(inner) => {
                let manufacturer = from_null_terminated_string(inner.manufacturer_name.clone());
                let model_name = from_null_terminated_string(inner.model_name.clone());
                let model_number = from_null_terminated_string(inner.model_number.clone());

                Ok(format!("{manufacturer} {model_name} {model_number}"))
            }
            _ => Err(crate::Error::BinaryObjectNotFoundError(
                "DrmBCertManufacturerInfo",
            )),
        }
    }

    /// Performs signature verification of certificates bundled in `BCertChain`.
    pub fn verify_certificates(&self) -> Result<(), crate::Error> {
        if self.parsed.certificates.is_empty() {
            return Err(crate::Error::CertificateMissingError);
        }

        let mut issuer_key = ROOT_ISSUER_KEY;

        for i in (0..self.parsed.certificates.len()).rev() {
            let bcert = &self.parsed.certificates[i];

            let cert = Certificate::new(bcert.val.clone(), bcert.raw.clone());
            cert.verify(&issuer_key)?;

            match cert.issuer_key() {
                Some(key) => issuer_key.copy_from_slice(&key),
                None => {
                    if i != 0 {
                        return Err(crate::Error::CertificateVerificationError(i));
                    }
                }
            }
        }

        Ok(())
    }
}

impl TryFrom<&[u8]> for CertificateChain {
    type Error = binrw::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for CertificateChain {
    type Error = binrw::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}
