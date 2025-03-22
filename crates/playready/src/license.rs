use crate::binary_format::xmr_license::{
    AuxiliaryKeysObject, CipherType, ContentKeyObject, ECCKeyObject, SignatureObject, XmrLicense,
    XmrObject, XmrObjectInner,
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

    fn find_root_object(&self, tag: u16) -> Option<&XmrObject> {
        self.parsed
            .containers
            .iter()
            .filter_map(|o| match &o.data {
                XmrObjectInner::OuterContainer(inner) => Some(inner.containers.iter()),
                _ => None,
            })
            .flatten()
            .find(|o| o.type_ == tag)
    }

    fn find_key_object(&self, tag: u16) -> Option<&XmrObject> {
        self.parsed
            .containers
            .iter()
            .filter_map(|o| match &o.data {
                XmrObjectInner::OuterContainer(inner) => Some(inner.containers.iter()),
                _ => None,
            })
            .flatten()
            .filter_map(|o| match &o.data {
                XmrObjectInner::KeyMaterialContainer(inner) => {
                    Some(inner.containers.iter().filter(|o| o.type_ == tag))
                }
                _ => None,
            })
            .flatten()
            .next()
    }

    pub fn public_key(&self) -> Result<&[u8], crate::Error> {
        let ecc_key_object = self
            .find_key_object(ECCKeyObject::TAG)
            .ok_or(crate::Error::BinaryObjectNotFoundError("ECCKeyObject"))?;

        match &ecc_key_object.data {
            XmrObjectInner::ECCKeyObject(inner) => Ok(inner.key.as_slice()),
            _ => Err(crate::Error::BinaryObjectNotFoundError("ECCKeyObject")),
        }
    }

    pub fn auxiliary_key(&self) -> Option<&[u8; 16]> {
        let aux_key_object = self.find_key_object(AuxiliaryKeysObject::TAG)?;

        let aux_key_object = match &aux_key_object.data {
            XmrObjectInner::AuxiliaryKeysObject(inner) => Some(inner),
            _ => None,
        };

        aux_key_object
            .map(|o| &o.auxiliary_keys)
            .map(|v| v.first())
            .unwrap_or(None)
            .map(|aux| &aux.key)
    }

    pub fn encrypted_keys(&self) -> Vec<(CipherType, &[u8; 16], &[u8])> {
        self.parsed
            .containers
            .iter()
            .filter_map(|o| match &o.data {
                XmrObjectInner::OuterContainer(inner) => Some(inner.containers.iter()),
                _ => None,
            })
            .flatten()
            .filter_map(|o| match &o.data {
                XmrObjectInner::KeyMaterialContainer(inner) => Some(
                    inner
                        .containers
                        .iter()
                        .filter(|o| o.type_ == ContentKeyObject::TAG),
                ),
                _ => None,
            })
            .flatten()
            .filter_map(|xmr_object| {
                let content_key_object = match &xmr_object.data {
                    XmrObjectInner::ContentKeyObject(inner) => Some(inner),
                    _ => None,
                }?;

                Some((
                    content_key_object.cipher_type,
                    &content_key_object.key_id,
                    content_key_object.encrypted_key.as_slice(),
                ))
            })
            .collect()
    }

    pub fn cmac_verification_data(&self) -> Result<(&[u8], &[u8]), crate::Error> {
        let signature_object = self
            .find_root_object(SignatureObject::TAG)
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
                    &inner.signature_data,
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

#[cfg(test)]
mod test {
    use super::License;
    use crate::license::CipherType::Ecc256;

    #[test]
    fn parse_license_with_empty_playback_policy_container() {
        let lic = License::from_b64(concat!(
            "WE1SAAAAAAO6ZrBZY/dbvTGZkxnTjOH/AAMAAQAAAVAAAwACAAAAMgABAA0AAAAK",
            "AAEAAAAzAAAACgABAAEAMgAAAAwAAAArAAEANAAAAAoH0AACAAQAAAAIAAMACQAA",
            "APIAAQAKAAAAngEBAQEBAQEBAQEBAQEBAQEAAQADAIACAgICAgICAgICAgICAgIC",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
            "AgICAgICAgICAgICAgICAgAAACoAAABMAAEAQAMDAwMDAwMDAwMDAwMDAwMDAwMD",
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAAQAL",
            "AAAAHAABABAEBAQEBAQEBAQEBAQEBAQE"
        ))
        .unwrap();

        assert_eq!(
            lic.encrypted_keys(),
            vec![(Ecc256, &[1u8; 16], [2u8; 128].as_slice())]
        );
        assert_eq!(lic.public_key().unwrap(), [3u8; 64].as_slice());
        assert_eq!(
            lic.cmac_verification_data().unwrap(),
            (&lic.raw[..332], [4u8; 16].as_slice())
        );
        assert_eq!(lic.auxiliary_key(), None)
    }

    #[test]
    fn parse_license_with_non_empty_playback_policy_container() {
        let lic = License::from_b64(concat!(
            "WE1SAAAAAAOOieG5U75vQ7O6VHqb06OGAAMAAQAAAYwAAwACAAAAXAABABIAAAAQ",
            "AAAAAGeRPH8AAQAwAAAADAACowAAAAATAAAADGeQy/8AAAAaAAAADAABUYAAAAAz",
            "AAAACgABAAEAMgAAAAwAAABNAAEANAAAAAoH0AACAAQAAAAaAAEABQAAABIB9AD6",
            "AJYAZABkAAMACQAAAPIAAQAKAAAAngEBAQEBAQEBAQEBAQEBAQEAAQADAIACAgIC",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAACoAAABMAAEAQAMDAwMDAwMD",
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD",
            "AwMDAwMDAwMAAQALAAAAHAABABAEBAQEBAQEBAQEBAQEBAQE"
        ))
        .unwrap();

        assert_eq!(
            lic.encrypted_keys(),
            vec![(Ecc256, &[1u8; 16], [2u8; 128].as_slice())]
        );
        assert_eq!(lic.public_key().unwrap(), [3u8; 64].as_slice());
        assert_eq!(
            lic.cmac_verification_data().unwrap(),
            (&lic.raw[..392], [4u8; 16].as_slice())
        );
        assert_eq!(lic.auxiliary_key(), None)
    }
}
