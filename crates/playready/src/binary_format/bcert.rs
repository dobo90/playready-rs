#![allow(dead_code)]

use super::{
    size_rounded_up_to_custom_align, until_exact_number_of_bytes, StructRawSize, StructTag,
    ValueAndRaw,
};
use binrw::BinRead;
use playready_macros::{StructRawSize, StructTag};

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(1)]
pub struct DrmBCertBasicInfo {
    pub cert_id: [u8; 16],
    pub security_level: u32,
    pub flags: u32,
    pub cert_type: u32,
    pub public_key_digest: [u8; 32],
    pub expiration_date: u32,
    pub client_id: [u8; 16],
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(2)]
pub struct DrmBCertDomainInfo {
    pub service_id: [u8; 16],
    pub account_id: [u8; 16],
    pub revision_timestamp: u32,
    pub domain_url_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(domain_url_length).unwrap(), 4))]
    pub domain_url: Vec<u8>,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(3)]
pub struct DrmBCertPCInfo {
    pub security_version: u32,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(4)]
pub struct DrmBCertDeviceInfo {
    pub max_license: u32,
    pub max_header: u32,
    pub max_chain_depth: u32,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(5)]
pub struct DrmBCertFeatureInfo {
    pub feature_count: u32,
    #[br(count = feature_count)]
    pub features: Vec<u32>,
}

#[derive(BinRead, StructRawSize, Debug, Clone)]
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

#[derive(BinRead, StructRawSize, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(6)]
pub struct DrmBCertKeyInfo {
    pub key_count: u32,
    #[br(count = key_count)]
    pub cert_keys: Vec<DrmBCertKeyInfoInner>,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(7)]
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

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(8)]
pub struct DrmBCertSignatureInfo {
    pub signature_type: u16,
    pub signature_size: u16,
    #[br(count = signature_size)]
    pub signature: Vec<u8>,
    pub signature_key_size: u32,
    #[br(count = signature_key_size / 8)]
    pub signature_key: Vec<u8>,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(9)]
pub struct DrmBCertSilverlightInfo {
    pub security_version: u32,
    pub platform_identifier: u32,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(10)]
pub struct DrmBCertMeteringInfo {
    pub metering_id: [u8; 16],
    pub metering_url_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(metering_url_length).unwrap(), 4))]
    pub metering_url: Vec<u8>,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(11)]
pub struct DrmBCertExtDataSignKeyInfo {
    pub key_type: u16,
    pub key_length: u16,
    pub flags: u32,
    #[br(count = key_length / 8)]
    pub key: Vec<u8>,
}

#[derive(BinRead, StructRawSize, Debug, Clone)]
#[br(big)]
pub struct BCertExtDataRecord {
    pub data_size: u32,
    #[br(count = data_size)]
    pub data: Vec<u8>,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(13)]
pub struct DrmBCertExtDataSignature {
    pub signature_type: u16,
    pub signature_size: u16,
    #[br(count = signature_size)]
    pub signature: Vec<u8>,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(12)]
pub struct BCertExtDataContainer {
    pub record_count: u32,
    #[br(count = record_count)]
    pub records: Vec<BCertExtDataRecord>,
    pub signature: DrmBCertExtDataSignature,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(15)]
pub struct DrmBCertServerInfo {
    pub warning_days: u32,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(16)]
pub struct DrmBcertSecurityVersion {
    pub security_version: u32,
    pub platform_identifier: u32,
}

#[derive(BinRead, StructTag, StructRawSize, Debug, Clone)]
#[br(big)]
#[struct_tag(17)]
pub struct DrmBcertSecurityVersion2 {
    pub security_version: u32,
    pub platform_identifier: u32,
}

#[derive(BinRead, Debug, Clone)]
#[br(big, import { tag: u16, length: u32 })]

pub enum AttributeInner {
    #[br(pre_assert(tag == DrmBCertBasicInfo::TAG))]
    DrmBCertBasicInfo(DrmBCertBasicInfo),
    #[br(pre_assert(tag == DrmBCertDomainInfo::TAG))]
    DrmBCertDomainInfo(DrmBCertDomainInfo),
    #[br(pre_assert(tag == DrmBCertPCInfo::TAG))]
    DrmBCertPCInfo(DrmBCertPCInfo),
    #[br(pre_assert(tag == DrmBCertDeviceInfo::TAG))]
    DrmBCertDeviceInfo(DrmBCertDeviceInfo),
    #[br(pre_assert(tag == DrmBCertFeatureInfo::TAG))]
    DrmBCertFeatureInfo(DrmBCertFeatureInfo),
    #[br(pre_assert(tag == DrmBCertKeyInfo::TAG))]
    DrmBCertKeyInfo(DrmBCertKeyInfo),
    #[br(pre_assert(tag == DrmBCertManufacturerInfo::TAG))]
    DrmBCertManufacturerInfo(DrmBCertManufacturerInfo),
    #[br(pre_assert(tag == DrmBCertSignatureInfo::TAG))]
    DrmBCertSignatureInfo(DrmBCertSignatureInfo),
    #[br(pre_assert(tag == DrmBCertSilverlightInfo::TAG))]
    DrmBCertSilverlightInfo(DrmBCertSilverlightInfo),
    #[br(pre_assert(tag == DrmBCertMeteringInfo::TAG))]
    DrmBCertMeteringInfo(DrmBCertMeteringInfo),
    #[br(pre_assert(tag == DrmBCertExtDataSignKeyInfo::TAG))]
    DrmBCertExtDataSignKeyInfo(DrmBCertExtDataSignKeyInfo),
    #[br(pre_assert(tag == BCertExtDataContainer::TAG))]
    BCertExtDataContainer(BCertExtDataContainer),
    #[br(pre_assert(tag == DrmBCertExtDataSignature::TAG))]
    DrmBCertExtDataSignature(DrmBCertExtDataSignature),
    #[br(pre_assert(tag == DrmBCertServerInfo::TAG))]
    DrmBCertServerInfo(DrmBCertServerInfo),
    #[br(pre_assert(tag == DrmBcertSecurityVersion::TAG))]
    DrmBcertSecurityVersion(DrmBcertSecurityVersion),
    #[br(pre_assert(tag == DrmBcertSecurityVersion2::TAG))]
    DrmBcertSecurityVersion2(DrmBcertSecurityVersion2),
    Unknown(#[br(count = length)] Vec<u8>),
}

impl StructRawSize for AttributeInner {
    fn get_raw_size(&self) -> usize {
        match self {
            AttributeInner::DrmBCertBasicInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertDomainInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertPCInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertDeviceInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertFeatureInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertKeyInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertManufacturerInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertSignatureInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertSilverlightInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertMeteringInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertExtDataSignKeyInfo(inner) => inner.get_raw_size(),
            AttributeInner::BCertExtDataContainer(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertExtDataSignature(inner) => inner.get_raw_size(),
            AttributeInner::DrmBCertServerInfo(inner) => inner.get_raw_size(),
            AttributeInner::DrmBcertSecurityVersion(inner) => inner.get_raw_size(),
            AttributeInner::DrmBcertSecurityVersion2(inner) => inner.get_raw_size(),
            AttributeInner::Unknown(items) => items.len() * std::mem::size_of::<u8>(),
        }
    }
}

#[derive(BinRead, StructRawSize, Debug, Clone)]
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
    pub certificates: Vec<ValueAndRaw<BCert>>,
}
