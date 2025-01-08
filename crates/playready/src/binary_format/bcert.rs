#![allow(dead_code)]

use super::{size_rounded_up_to_custom_align, until_exact_number_of_bytes};
use binrw::{BinRead, PosValue};

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertBasicInfo {
    pub cert_id: [u8; 16],
    pub security_level: u32,
    pub flags: u32,
    pub cert_type: u32,
    pub public_key_digest: [u8; 32],
    pub expiration_date: u32,
    pub client_id: [u8; 16],
}

impl DrmBCertBasicInfo {
    #[inline]
    pub const fn tag() -> u16 {
        1
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertDomainInfo {
    pub service_id: [u8; 16],
    pub account_id: [u8; 16],
    pub revision_timestamp: u32,
    pub domain_url_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(domain_url_length).unwrap(), 4))]
    pub domain_url: Vec<u8>,
}

impl DrmBCertDomainInfo {
    #[inline]
    pub const fn tag() -> u16 {
        2
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertPCInfo {
    pub security_version: u32,
}

impl DrmBCertPCInfo {
    #[inline]
    pub const fn tag() -> u16 {
        3
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertDeviceInfo {
    pub max_license: u32,
    pub max_header: u32,
    pub max_chain_depth: u32,
}

impl DrmBCertDeviceInfo {
    #[inline]
    pub const fn tag() -> u16 {
        4
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertFeatureInfo {
    pub feature_count: u32,
    #[br(count = feature_count)]
    pub features: Vec<u32>,
}

impl DrmBCertFeatureInfo {
    #[inline]
    pub const fn tag() -> u16 {
        5
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertKeyInfoInner {
    pub type_: u16,
    pub length: u16,
    pub flags: u32,
    #[br(count = length / 8)]
    pub key: Vec<u8>,
    pub usages_count: u32,
    #[br(count = usages_count)]
    pub usages: Vec<u32>,
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertKeyInfo {
    pub key_count: u32,
    #[br(count = key_count)]
    pub cert_keys: Vec<DrmBCertKeyInfoInner>,
}

impl DrmBCertKeyInfo {
    #[inline]
    pub const fn tag() -> u16 {
        6
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertManufacturerInfo {
    pub flags: u32,
    pub manufacturer_name_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(manufacturer_name_length).unwrap(), 4))]
    pub manufacturer_name: Vec<u8>,
    pub model_name_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(model_name_length).unwrap(), 4))]
    pub model_name: Vec<u8>,
    pub model_number_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(model_number_length).unwrap(), 4))]
    pub model_number: Vec<u8>,
}

impl DrmBCertManufacturerInfo {
    #[inline]
    pub const fn tag() -> u16 {
        7
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertSignatureInfo {
    pub signature_type: u16,
    pub signature_size: u16,
    #[br(count = signature_size)]
    pub signature: Vec<u8>,
    pub signature_key_size: u32,
    #[br(count = signature_key_size / 8)]
    pub signature_key: Vec<u8>,
}

impl DrmBCertSignatureInfo {
    #[inline]
    pub const fn tag() -> u16 {
        8
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertSilverlightInfo {
    pub security_version: u32,
    pub platform_identifier: u32,
}

impl DrmBCertSilverlightInfo {
    #[inline]
    pub const fn tag() -> u16 {
        9
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertMeteringInfo {
    pub metering_id: [u8; 16],
    pub metering_url_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(metering_url_length).unwrap(), 4))]
    pub metering_url: Vec<u8>,
}

impl DrmBCertMeteringInfo {
    #[inline]
    pub const fn tag() -> u16 {
        10
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertExtDataSignKeyInfo {
    pub key_type: u16,
    pub key_length: u16,
    pub flags: u32,
    #[br(count = key_length / 8)]
    pub key: Vec<u8>,
}

impl DrmBCertExtDataSignKeyInfo {
    #[inline]
    pub const fn tag() -> u16 {
        11
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct BCertExtDataRecord {
    pub data_size: u32,
    #[br(count = data_size)]
    pub data: Vec<u8>,
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertExtDataSignature {
    pub signature_type: u16,
    pub signature_size: u16,
    #[br(count = signature_size)]
    pub signature: Vec<u8>,
}

impl DrmBCertExtDataSignature {
    #[inline]
    pub const fn tag() -> u16 {
        13
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct BCertExtDataContainer {
    pub record_count: u32,
    #[br(count = record_count)]
    pub records: Vec<BCertExtDataRecord>,
    pub signature: DrmBCertExtDataSignature,
}

impl BCertExtDataContainer {
    #[inline]
    pub const fn tag() -> u16 {
        12
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBCertServerInfo {
    pub warning_days: u32,
}

impl DrmBCertServerInfo {
    #[inline]
    pub const fn tag() -> u16 {
        15
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct DrmBcertSecurityVersion {
    pub security_version: u32,
    pub platform_identifier: u32,
}

impl DrmBcertSecurityVersion {
    #[inline]
    pub const fn tags() -> [u16; 2] {
        [16, 17]
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(big, import { tag: u16, length: u32 })]

pub enum AttributeInner {
    #[br(pre_assert(tag == DrmBCertBasicInfo::tag()))]
    DrmBCertBasicInfo(DrmBCertBasicInfo),
    #[br(pre_assert(tag == DrmBCertDomainInfo::tag()))]
    DrmBCertDomainInfo(DrmBCertDomainInfo),
    #[br(pre_assert(tag == DrmBCertPCInfo::tag()))]
    DrmBCertPCInfo(DrmBCertPCInfo),
    #[br(pre_assert(tag == DrmBCertDeviceInfo::tag()))]
    DrmBCertDeviceInfo(DrmBCertDeviceInfo),
    #[br(pre_assert(tag == DrmBCertFeatureInfo::tag()))]
    DrmBCertFeatureInfo(DrmBCertFeatureInfo),
    #[br(pre_assert(tag == DrmBCertKeyInfo::tag()))]
    DrmBCertKeyInfo(DrmBCertKeyInfo),
    #[br(pre_assert(tag == DrmBCertManufacturerInfo::tag()))]
    DrmBCertManufacturerInfo(DrmBCertManufacturerInfo),
    #[br(pre_assert(tag == DrmBCertSignatureInfo::tag()))]
    DrmBCertSignatureInfo(DrmBCertSignatureInfo),
    #[br(pre_assert(tag == DrmBCertSilverlightInfo::tag()))]
    DrmBCertSilverlightInfo(DrmBCertSilverlightInfo),
    #[br(pre_assert(tag == DrmBCertMeteringInfo::tag()))]
    DrmBCertMeteringInfo(DrmBCertMeteringInfo),
    #[br(pre_assert(tag == DrmBCertExtDataSignKeyInfo::tag()))]
    DrmBCertExtDataSignKeyInfo(DrmBCertExtDataSignKeyInfo),
    #[br(pre_assert(tag == BCertExtDataContainer::tag()))]
    BCertExtDataContainer(BCertExtDataContainer),
    #[br(pre_assert(tag == DrmBCertExtDataSignature::tag()))]
    DrmBCertExtDataSignature(DrmBCertExtDataSignature),
    #[br(pre_assert(tag == DrmBCertServerInfo::tag()))]
    DrmBCertServerInfo(DrmBCertServerInfo),
    #[br(pre_assert(DrmBcertSecurityVersion::tags().contains(&tag)))]
    DrmBcertSecurityVersion(DrmBcertSecurityVersion),
    Unknown(#[br(count = length)] Vec<u8>),
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]

pub struct Attribute {
    pub flags: u16,
    pub tag: u16,
    pub length: u32,
    // size of inner in bytes = length of `Attribute` - sizeof(flags) - sizeof(tag) - sizeof(length)
    #[br(args { tag, length: length - 2 - 2 - 4 })]
    pub inner: AttributeInner,
}

#[derive(BinRead, Debug, Clone)]
#[br(big, magic = b"CERT")]
pub struct BCert {
    pub version: u32,
    pub total_length: u32,
    pub certificate_length: u32,
    // attributes size in bytes = total_length - b"CERT".len() - sizeof(version) - sizeof(total_length) - sizeof(certificate_length)
    #[br(parse_with = until_exact_number_of_bytes(u64::from(total_length) - 4 * 4))]
    pub attributes: Vec<Attribute>,
}

#[derive(BinRead, Debug, Clone)]
#[br(big, magic = b"CHAI")]
pub struct BCertChain {
    pub version: u32,
    pub total_length: u32,
    pub flags: u32,
    pub certificate_count: u32,
    #[br(count = certificate_count)]
    pub certificates: Vec<PosValue<BCert>>,
}
