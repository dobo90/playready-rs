#![allow(dead_code)]

use binrw::{BinRead, BinWrite};

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(big)]
pub struct DeviceV2 {
    pub group_certificate_length: u32,
    #[br(count = group_certificate_length)]
    pub group_certificate: Vec<u8>,
    pub encryption_key: [u8; 96],
    pub signing_key: [u8; 96],
}

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(big)]
pub struct DeviceV3 {
    pub group_key: [u8; 96],
    pub encryption_key: [u8; 96],
    pub signing_key: [u8; 96],
    pub group_certificate_length: u32,
    #[br(count = group_certificate_length)]
    pub group_certificate: Vec<u8>,
}

#[derive(BinRead, BinWrite, Debug, Clone)]
#[br(big, import(version: u8))]
#[bw(big)]
pub enum DeviceInner {
    #[br(pre_assert(version == 2))]
    V2(DeviceV2),
    #[br(pre_assert(version == 3))]
    V3(DeviceV3),
}

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(big, magic = b"PRD")]
pub struct Device {
    pub version: u8,
    #[br(args(version))]
    pub inner: DeviceInner,
}
