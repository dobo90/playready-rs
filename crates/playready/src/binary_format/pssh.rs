#![allow(dead_code)]

use binrw::{helpers::read_u24, BinRead};

#[derive(BinRead, Debug, Clone)]
#[br(big,
    assert(&pssh == b"pssh" &&
        system_id == [0x9a, 0x04, 0xf0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xab, 0x92, 0xe6, 0x5b, 0xe0, 0x88, 0x5f, 0x95] &&
        [0, 1].contains(&version))
)]
pub struct PSSHBox {
    pub length: u32,
    pub pssh: [u8; 4],
    pub version: u8,
    #[br(parse_with = read_u24)]
    pub flags: u32,
    pub system_id: [u8; 16],
    #[br(if(version == 1))]
    pub kid_count: u32,
    #[br(if(version == 1), count = kid_count)]
    pub kids: Vec<[u8; 16]>,
    pub data_length: u32,
    pub data: PlayreadyHeader,
}

#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct PlayreadyObject {
    pub type_: u16,
    pub length: u16,
    #[br(count = length / 2)]
    pub data: Vec<u16>,
}

#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct PlayreadyHeader {
    pub length: u32,
    pub record_count: u16,
    #[br(count = record_count)]
    pub records: Vec<PlayreadyObject>,
}
