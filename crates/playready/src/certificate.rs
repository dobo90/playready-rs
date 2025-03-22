//! Helper structs for accessing BCert and BCertChain binary formats.

use crate::{
    binary_format::{
        bcert::{
            Attribute, DrmBCertDeviceInfo, DrmBCertFeatureInfo, DrmBCertKeyInfoInner,
            PreprocessWrite,
        },
        StructTag,
    },
    crypto::{
        ecc_p256::{FromBytes, ToUntaggedBytes, SIGNATURE_SIZE},
        sha256,
    },
};
use binrw::{BinRead, BinWrite};
use p256::ecdsa::{SigningKey, VerifyingKey};
use std::{borrow::Cow, io::Cursor};

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
struct Certificate<'a, 'b> {
    parsed: Cow<'a, BCert>,
    raw: Cow<'b, Vec<u8>>,
}

impl<'a, 'b> Certificate<'a, 'b> {
    fn new(bcert: Cow<'a, BCert>, raw: Cow<'b, Vec<u8>>) -> Self {
        Self { parsed: bcert, raw }
    }

    fn into_bcert_and_raw(self) -> (BCert, Vec<u8>) {
        (self.parsed.into_owned(), self.raw.into_owned())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, binrw::Error> {
        Self::from_vec(bytes.to_vec())
    }

    pub fn from_vec(vec: Vec<u8>) -> Result<Self, binrw::Error> {
        let parsed = Cow::Owned(BCert::read(&mut Cursor::new(&vec))?);
        let raw = Cow::Owned(vec);

        Ok(Self { parsed, raw })
    }

    fn issuer_key(&self) -> Option<&[u8]> {
        let attribute = self
            .parsed
            .attributes
            .iter()
            .find(|a| a.tag == DrmBCertKeyInfo::TAG)?;

        let cert_info = match &attribute.inner {
            AttributeInner::DrmBCertKeyInfo(inner) => Some(inner),
            _ => None,
        };

        cert_info?
            .cert_keys
            .iter()
            .find(|c| c.usages.contains(&6))
            .map(|c| c.key.as_slice())
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
            &VerifyingKey::from_bytes(&sig_info.signature_key)?,
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

    pub fn new_leaf(
        cert_id: [u8; 16],
        client_id: [u8; 16],
        security_level: u32,
        manufacturer_info: Attribute,
        public_signing_key: Vec<u8>,
        public_encryption_key: Vec<u8>,
        group_key: &SigningKey,
    ) -> Result<Self, crate::Error> {
        let public_group_key = group_key
            .verifying_key()
            .as_affine()
            .to_untagged_bytes()
            .to_vec();

        let attributes = vec![
            Attribute {
                flags: 1,
                inner: AttributeInner::DrmBCertBasicInfo(DrmBCertBasicInfo {
                    cert_id,
                    security_level,
                    cert_type: 2,
                    public_key_digest: sha256::hash(&public_signing_key).try_into().unwrap(),
                    expiration_date: u32::MAX,
                    client_id,
                    ..Default::default()
                }),
                ..Default::default()
            },
            Attribute {
                flags: 1,
                inner: AttributeInner::DrmBCertDeviceInfo(DrmBCertDeviceInfo {
                    max_license: 10240,
                    max_header: 15360,
                    max_chain_depth: 2,
                }),
                ..Default::default()
            },
            Attribute {
                flags: 1,
                inner: AttributeInner::DrmBCertFeatureInfo(DrmBCertFeatureInfo {
                    features: vec![4, 9, 13],
                    ..Default::default()
                }),
                ..Default::default()
            },
            Attribute {
                flags: 1,
                inner: AttributeInner::DrmBCertKeyInfo(DrmBCertKeyInfo {
                    cert_keys: vec![
                        DrmBCertKeyInfoInner {
                            type_: 1,
                            key: public_signing_key,
                            usages: vec![1],
                            ..Default::default()
                        },
                        DrmBCertKeyInfoInner {
                            type_: 1,
                            key: public_encryption_key,
                            usages: vec![2],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
            manufacturer_info,
            Attribute {
                flags: 1,
                inner: AttributeInner::DrmBCertSignatureInfo(DrmBCertSignatureInfo {
                    signature_type: 1,
                    signature: vec![0u8; SIGNATURE_SIZE],
                    signature_key: public_group_key,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];

        let mut cert = BCert {
            version: 1,
            attributes,
            ..Default::default()
        };

        let mut raw = Vec::<u8>::new();
        cert.preprocess_write();
        cert.write(&mut Cursor::new(&mut raw))?;

        let signature = ecc_p256::sign(
            group_key,
            raw.get(0..usize::try_from(cert.certificate_length)?)
                .ok_or(crate::Error::SliceOutOfBoundsError("cert.raw", raw.len()))?,
        );

        assert!(signature.len() == SIGNATURE_SIZE);

        if let AttributeInner::DrmBCertSignatureInfo(inner) =
            &mut cert.attributes.last_mut().unwrap().inner
        {
            inner.signature.copy_from_slice(&signature)
        }

        raw.clear();
        cert.write(&mut Cursor::new(&mut raw))?;

        Ok(Self {
            parsed: Cow::Owned(cert),
            raw: Cow::Owned(raw),
        })
    }
}

impl<'a, 'b> TryFrom<&[u8]> for Certificate<'a, 'b> {
    type Error = binrw::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl<'a, 'b> TryFrom<Vec<u8>> for Certificate<'a, 'b> {
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
        Self::from_vec(bytes.to_vec())
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

            let cert = Certificate::new(Cow::Borrowed(&bcert.val), Cow::Borrowed(&bcert.raw));
            cert.verify(&issuer_key)?;

            match cert.issuer_key() {
                Some(key) => issuer_key.copy_from_slice(key),
                None => {
                    if i != 0 {
                        return Err(crate::Error::CertificateVerificationError(i));
                    }
                }
            }
        }

        Ok(())
    }

    /// Provisions certificate chain by creating new leaf certificate.
    pub fn provision(
        mut self,
        cert_id: [u8; 16],
        client_id: [u8; 16],
        public_signing_key: Vec<u8>,
        public_encryption_key: Vec<u8>,
        group_key: &SigningKey,
    ) -> Result<Self, crate::Error> {
        let public_group_key = group_key.verifying_key().as_affine().to_untagged_bytes();

        self.parsed.certificates = self
            .parsed
            .certificates
            .into_iter()
            .skip_while(|c| {
                Certificate::new(Cow::Borrowed(&c.val), Cow::Borrowed(&c.raw))
                    .issuer_key()
                    .map(|c| *c != *public_group_key)
                    .unwrap_or(true)
            })
            .collect();

        if self.parsed.certificates.is_empty() {
            return Err(crate::Error::PublicKeyMismatchError("group key"));
        }

        let first_cert = self
            .parsed
            .certificates
            .first()
            .ok_or(crate::Error::CertificateMissingError)?;

        let manufacturer_info = first_cert
            .attributes
            .iter()
            .find(|a| a.tag == DrmBCertManufacturerInfo::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError(
                "DrmBCertManufacturerInfo",
            ))
            .cloned()?;

        let security_level = self.security_level()?;

        let new_leaf = Certificate::new_leaf(
            cert_id,
            client_id,
            security_level,
            manufacturer_info,
            public_signing_key,
            public_encryption_key,
            group_key,
        )?;

        self.parsed
            .certificates
            .insert(0, new_leaf.into_bcert_and_raw().into());

        self.parsed
            .certificates
            .iter_mut()
            .for_each(|c| c.use_raw = true);

        self.parsed.preprocess_write();
        self.raw.clear();
        self.parsed.write(&mut Cursor::new(&mut self.raw))?;

        Ok(self)
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
