//! PSSH module.

use crate::binary_format::pssh::{PSSHBox, PlayreadyHeader};
use base64::prelude::*;
use binrw::BinRead;
use std::io::Cursor;

#[derive(Debug, Clone)]
/// Wrm header which is extracted from PSSH box.
pub struct WrmHeader(pub String);

impl From<WrmHeader> for String {
    fn from(value: WrmHeader) -> Self {
        value.0
    }
}

/// Wrapper for `PlayreadyObject` binary format.
#[derive(Debug, Clone)]
pub struct Pssh {
    parsed: PlayreadyHeader,
}

impl Pssh {
    /// Creates `Pssh` from bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, binrw::Error> {
        let pssh_box = PSSHBox::read(&mut Cursor::new(b));

        match pssh_box {
            Ok(pssh_box) => Ok(Self {
                parsed: pssh_box.data,
            }),
            Err(_) => Ok(Self {
                parsed: PlayreadyHeader::read(&mut Cursor::new(b))?,
            }),
        }
    }

    /// Creates `Pssh` from Base64 encoded bytes.
    pub fn from_b64(b64: &[u8]) -> Result<Self, crate::Error> {
        let bytes = BASE64_STANDARD.decode(b64)?;
        Self::from_bytes(&bytes).map_err(|e| e.into())
    }

    /// Returns WRM headers parsed from `PSSHBox`.
    pub fn wrm_headers(&self) -> Vec<WrmHeader> {
        self.parsed
            .records
            .iter()
            .filter(|o| o.type_ == 1)
            .filter_map(|o| {
                String::from_utf16(&o.data)
                    .inspect_err(|e| {
                        log::error!("Failed create uf16 string from wrm header: {e:?}")
                    })
                    .map(WrmHeader)
                    .ok()
            })
            .collect()
    }
}

impl TryFrom<&[u8]> for Pssh {
    type Error = binrw::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}
