#![allow(dead_code)]

use super::{
    size_rounded_up_to_custom_align, trim_and_pad_cstr, until_exact_number_of_bytes, StructRawSize,
    StructTag, ValueAndRaw,
};
use binrw::{BinRead, BinWrite};
use playready_macros::{StructRawSize, StructTag};

pub trait PreprocessWrite {
    fn preprocess_write(&mut self);
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
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

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(2)]
pub struct DrmBCertDomainInfo {
    pub service_id: [u8; 16],
    pub account_id: [u8; 16],
    pub revision_timestamp: u32,
    pub domain_url_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(domain_url_length).unwrap(), 4))]
    pub domain_url: Vec<u8>,
}

impl PreprocessWrite for DrmBCertDomainInfo {
    fn preprocess_write(&mut self) {
        let domain_url_length = trim_and_pad_cstr(&mut self.domain_url);
        self.domain_url_length = u32::try_from(domain_url_length).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(3)]
pub struct DrmBCertPCInfo {
    pub security_version: u32,
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(4)]
pub struct DrmBCertDeviceInfo {
    pub max_license: u32,
    pub max_header: u32,
    pub max_chain_depth: u32,
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(5)]
pub struct DrmBCertFeatureInfo {
    pub feature_count: u32,
    #[br(count = feature_count)]
    pub features: Vec<u32>,
}

impl PreprocessWrite for DrmBCertFeatureInfo {
    fn preprocess_write(&mut self) {
        self.feature_count = u32::try_from(self.features.len()).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
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

impl PreprocessWrite for DrmBCertKeyInfoInner {
    fn preprocess_write(&mut self) {
        self.length = u16::try_from(self.key.len()).unwrap() * 8;
        self.usages_count = u32::try_from(self.usages.len()).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructRawSize, StructTag, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(6)]
pub struct DrmBCertKeyInfo {
    pub key_count: u32,
    #[br(count = key_count)]
    pub cert_keys: Vec<DrmBCertKeyInfoInner>,
}

impl PreprocessWrite for DrmBCertKeyInfo {
    fn preprocess_write(&mut self) {
        for cert_key in &mut self.cert_keys {
            cert_key.preprocess_write();
        }

        self.key_count = u32::try_from(self.cert_keys.len()).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
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

impl PreprocessWrite for DrmBCertManufacturerInfo {
    fn preprocess_write(&mut self) {
        let manufacturer_name_length = trim_and_pad_cstr(&mut self.manufacturer_name);
        let model_name_length = trim_and_pad_cstr(&mut self.model_name);
        let model_number_length = trim_and_pad_cstr(&mut self.model_number);

        self.manufacturer_name_length = u32::try_from(manufacturer_name_length).unwrap();
        self.model_name_length = u32::try_from(model_name_length).unwrap();
        self.model_number_length = u32::try_from(model_number_length).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
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

impl PreprocessWrite for DrmBCertSignatureInfo {
    fn preprocess_write(&mut self) {
        self.signature_size = u16::try_from(self.signature.len()).unwrap();
        self.signature_key_size = u32::try_from(self.signature_key.len()).unwrap() * 8;
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(9)]
pub struct DrmBCertSilverlightInfo {
    pub security_version: u32,
    pub platform_identifier: u32,
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(10)]
pub struct DrmBCertMeteringInfo {
    pub metering_id: [u8; 16],
    pub metering_url_length: u32,
    #[br(count = size_rounded_up_to_custom_align(usize::try_from(metering_url_length).unwrap(), 4))]
    pub metering_url: Vec<u8>,
}

impl PreprocessWrite for DrmBCertMeteringInfo {
    fn preprocess_write(&mut self) {
        let metering_url_length = trim_and_pad_cstr(&mut self.metering_url);
        self.metering_url_length = u32::try_from(metering_url_length).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(11)]
pub struct DrmBCertExtDataSignKeyInfo {
    pub key_type: u16,
    pub key_length: u16,
    pub flags: u32,
    #[br(count = key_length / 8)]
    pub key: Vec<u8>,
}

impl PreprocessWrite for DrmBCertExtDataSignKeyInfo {
    fn preprocess_write(&mut self) {
        self.key_length = u16::try_from(self.key.len()).unwrap() * 8;
    }
}

#[derive(BinRead, BinWrite, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
pub struct BCertExtDataRecord {
    pub data_size: u32,
    #[br(count = data_size)]
    pub data: Vec<u8>,
}

impl PreprocessWrite for BCertExtDataRecord {
    fn preprocess_write(&mut self) {
        self.data_size = u32::try_from(self.data.len()).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(13)]
pub struct DrmBCertExtDataSignature {
    pub signature_type: u16,
    pub signature_size: u16,
    #[br(count = signature_size)]
    pub signature: Vec<u8>,
}

impl PreprocessWrite for DrmBCertExtDataSignature {
    fn preprocess_write(&mut self) {
        self.signature_size = u16::try_from(self.signature.len()).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(12)]
pub struct BCertExtDataContainer {
    pub record_count: u32,
    #[br(count = record_count)]
    pub records: Vec<BCertExtDataRecord>,
    pub signature: DrmBCertExtDataSignature,
}

impl PreprocessWrite for BCertExtDataContainer {
    fn preprocess_write(&mut self) {
        for record in &mut self.records {
            record.preprocess_write();
        }

        self.record_count = u32::try_from(self.records.len()).unwrap();
    }
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(15)]
pub struct DrmBCertServerInfo {
    pub warning_days: u32,
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(16)]
pub struct DrmBcertSecurityVersion {
    pub security_version: u32,
    pub platform_identifier: u32,
}

#[derive(BinRead, BinWrite, StructTag, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
#[struct_tag(17)]
pub struct DrmBcertSecurityVersion2 {
    pub security_version: u32,
    pub platform_identifier: u32,
}

#[derive(BinRead, BinWrite, Debug, Clone)]
#[br(big, import { tag: u16, length: u32 })]
#[bw(big)]
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

impl Default for AttributeInner {
    fn default() -> Self {
        Self::Unknown(vec![])
    }
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

impl PreprocessWrite for AttributeInner {
    fn preprocess_write(&mut self) {
        match self {
            AttributeInner::DrmBCertDomainInfo(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertFeatureInfo(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertKeyInfo(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertManufacturerInfo(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertSignatureInfo(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertMeteringInfo(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertExtDataSignKeyInfo(inner) => inner.preprocess_write(),
            AttributeInner::BCertExtDataContainer(inner) => inner.preprocess_write(),
            AttributeInner::DrmBCertExtDataSignature(inner) => inner.preprocess_write(),
            _ => (),
        }
    }
}

impl AttributeInner {
    fn get_tag(&self) -> Option<u16> {
        match self {
            AttributeInner::DrmBCertBasicInfo(_) => Some(DrmBCertBasicInfo::TAG),
            AttributeInner::DrmBCertDomainInfo(_) => Some(DrmBCertDomainInfo::TAG),
            AttributeInner::DrmBCertPCInfo(_) => Some(DrmBCertPCInfo::TAG),
            AttributeInner::DrmBCertDeviceInfo(_) => Some(DrmBCertDeviceInfo::TAG),
            AttributeInner::DrmBCertFeatureInfo(_) => Some(DrmBCertFeatureInfo::TAG),
            AttributeInner::DrmBCertKeyInfo(_) => Some(DrmBCertKeyInfo::TAG),
            AttributeInner::DrmBCertManufacturerInfo(_) => Some(DrmBCertManufacturerInfo::TAG),
            AttributeInner::DrmBCertSignatureInfo(_) => Some(DrmBCertSignatureInfo::TAG),
            AttributeInner::DrmBCertSilverlightInfo(_) => Some(DrmBCertSilverlightInfo::TAG),
            AttributeInner::DrmBCertMeteringInfo(_) => Some(DrmBCertMeteringInfo::TAG),
            AttributeInner::DrmBCertExtDataSignKeyInfo(_) => Some(DrmBCertExtDataSignKeyInfo::TAG),
            AttributeInner::BCertExtDataContainer(_) => Some(BCertExtDataContainer::TAG),
            AttributeInner::DrmBCertExtDataSignature(_) => Some(DrmBCertExtDataSignature::TAG),
            AttributeInner::DrmBCertServerInfo(_) => Some(DrmBCertServerInfo::TAG),
            AttributeInner::DrmBcertSecurityVersion(_) => Some(DrmBcertSecurityVersion::TAG),
            AttributeInner::DrmBcertSecurityVersion2(_) => Some(DrmBcertSecurityVersion2::TAG),
            AttributeInner::Unknown(_) => None,
        }
    }
}

#[derive(BinRead, BinWrite, StructRawSize, Debug, Clone, Default)]
#[brw(big)]
pub struct Attribute {
    pub flags: u16,
    pub tag: u16,
    pub length: u32,
    // size of inner in bytes = length of `Attribute` - sizeof(flags) - sizeof(tag) - sizeof(length)
    #[br(args { tag, length: length - 2 - 2 - 4 })]
    pub inner: AttributeInner,
}

impl PreprocessWrite for Attribute {
    fn preprocess_write(&mut self) {
        self.inner.preprocess_write();

        self.length = u32::try_from(self.get_raw_size()).unwrap();
        self.tag = self.inner.get_tag().unwrap_or(self.tag);
    }
}

#[derive(BinRead, BinWrite, Debug, Clone, Default)]
#[brw(big, magic = b"CERT")]
pub struct BCert {
    pub version: u32,
    pub total_length: u32,
    pub certificate_length: u32,
    // attributes size in bytes = total_length - b"CERT".len() - sizeof(version) - sizeof(total_length) - sizeof(certificate_length)
    #[br(parse_with = until_exact_number_of_bytes(u64::from(total_length) - 4 * 4))]
    pub attributes: Vec<Attribute>,
}

impl BCert {
    fn certificate_size(&self) -> Option<usize> {
        match &self.attributes.last() {
            Some(attr) => match &attr.inner {
                AttributeInner::DrmBCertSignatureInfo(_) => Some(attr.get_raw_size()),
                _ => {
                    log::error!("DrmBCertSignatureInfo has to be the last attribute");
                    None
                }
            },
            None => {
                log::error!("Missing attribute");
                None
            }
        }
    }
}

impl PreprocessWrite for BCert {
    fn preprocess_write(&mut self) {
        for attribute in &mut self.attributes {
            attribute.preprocess_write();
        }

        // total_length = attributes size + b"CERT".len() + sizeof(version) + sizeof(total_length) + sizeof(certificate_length)
        self.total_length = self.attributes.iter().map(|a| a.length).sum::<u32>() + 4 * 4;
        self.certificate_length =
            self.total_length - u32::try_from(self.certificate_size().unwrap_or_default()).unwrap();
    }
}

#[derive(BinRead, BinWrite, Debug, Clone, Default)]
#[brw(big, magic = b"CHAI")]
pub struct BCertChain {
    pub version: u32,
    pub total_length: u32,
    pub flags: u32,
    pub certificate_count: u32,
    #[br(count = certificate_count)]
    pub certificates: Vec<ValueAndRaw<BCert>>,
}

impl PreprocessWrite for BCertChain {
    fn preprocess_write(&mut self) {
        for certificate in &mut self.certificates {
            if !certificate.use_raw {
                certificate.val.preprocess_write();
            }
        }

        self.certificate_count = u32::try_from(self.certificates.len()).unwrap();
        // total_length = certificates_length + b"CHAI".len() + sizeof(version) + sizeof(total_length) + sizeof(flags) + sizeof(certificate_count)
        self.total_length = self
            .certificates
            .iter()
            .map(|c| c.total_length)
            .sum::<u32>()
            + 4 * 5;
    }
}
