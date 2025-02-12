use crate::binary_format::xmr_license::{
    AuxiliaryKeysObject, CipherType, ContentKeyObject, ECCKeyObject, SignatureObject, XmrLicense,
    XmrObjectInner,
};
use crate::binary_format::StructTag;
use base64::{prelude::BASE64_STANDARD, Engine};
use binrw::BinRead;
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct License {
    parsed: XmrLicense,
    raw: Vec<u8>,
}

impl License {
    pub fn from_bytes(b: &[u8]) -> Result<Self, binrw::Error> {
        let parsed = XmrLicense::read(&mut Cursor::new(&b))?;

        Ok(Self {
            parsed,
            raw: b.to_vec(),
        })
    }

    pub fn from_b64(b64: &str) -> Result<Self, crate::Error> {
        let raw = BASE64_STANDARD.decode(b64)?;
        let parsed = XmrLicense::read(&mut Cursor::new(&raw))?;

        Ok(Self { parsed, raw })
    }

    pub fn public_key(&self) -> Result<Vec<u8>, crate::Error> {
        let ecc_key_object = self
            .parsed
            .containers
            .iter()
            .find(|o| o.type_ == ECCKeyObject::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError("ECCKeyObject"))?;

        match &ecc_key_object.data {
            XmrObjectInner::ECCKeyObject(inner) => Ok(inner.key.clone()),
            _ => Err(crate::Error::BinaryObjectNotFoundError("ECCKeyObject")),
        }
    }

    pub fn auxiliary_key(&self) -> Option<[u8; 16]> {
        let aux_key_object = self
            .parsed
            .containers
            .iter()
            .find(|o| o.type_ == AuxiliaryKeysObject::TAG)?;

        let aux_key_object = match &aux_key_object.data {
            XmrObjectInner::AuxiliaryKeysObject(inner) => Some(inner),
            _ => None,
        };

        aux_key_object
            .map(|o| &o.auxiliary_keys)
            .map(|v| v.first())
            .unwrap_or(None)
            .map(|aux| aux.key)
    }

    pub fn encrypted_keys(&self) -> Vec<(CipherType, [u8; 16], Vec<u8>)> {
        self.parsed
            .containers
            .iter()
            .filter(|o| o.type_ == ContentKeyObject::TAG)
            .filter_map(|xmr_object| {
                let content_key_object = match &xmr_object.data {
                    XmrObjectInner::ContentKeyObject(inner) => Some(inner),
                    _ => None,
                }?;

                Some((
                    content_key_object.cipher_type,
                    content_key_object.key_id,
                    content_key_object.encrypted_key.clone(),
                ))
            })
            .collect::<Vec<(CipherType, [u8; 16], Vec<u8>)>>()
    }

    pub fn cmac_verification_data(&self) -> Result<(&[u8], Vec<u8>), crate::Error> {
        let signature_object = self
            .parsed
            .containers
            .iter()
            .find(|o| o.type_ == SignatureObject::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError("SignatureObject"))?;

        match &signature_object.data {
            XmrObjectInner::SignatureObject(inner) => {
                let msg_end = self.raw.len() - (usize::from(inner.signature_data_length) + 12);
                Ok((
                    self.raw
                        .get(..msg_end)
                        .ok_or(crate::Error::SliceOutOfBoundsError(
                            "signature.raw",
                            self.raw.len(),
                        ))?,
                    inner.signature_data.clone(),
                ))
            }
            _ => Err(crate::Error::BinaryObjectNotFoundError("SignatureObject")),
        }
    }
}

impl TryFrom<&[u8]> for License {
    type Error = binrw::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}
