#![allow(dead_code)]

use super::StructTag;
use binrw::{helpers::until_eof, BinRead};
use playready_macros::StructTag;

#[derive(BinRead, Debug, Clone, Copy, PartialEq)]
#[br(big, repr = u16)]
pub enum CipherType {
    Invalid = 0x0000,
    Rsa1024 = 0x0001,
    ChainedLicense = 0x0002,
    Ecc256 = 0x0003,
    Ecc256WithKZ = 0x0004,
    TeeTransient = 0x0005,
    Ecc256ViaSymmetric = 0x0006,
    Unknown = 0xffff,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0039)]
pub struct PlayEnablerType {
    pub player_enabler_type: [u8; 16],
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0029)]
pub struct DomainRestrictionObject {
    pub account_id: [u8; 16],
    pub revision: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0013)]
pub struct IssueDateObject {
    pub issue_date: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0032)]
pub struct RevInfoVersionObject {
    pub sequence: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0034)]
pub struct SecurityLevelObject {
    pub minimum_security_level: u16,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0033)]
pub struct EmbeddedLicenseSettingsObject {
    pub indicator: u16,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x002a)]
pub struct ECCKeyObject {
    pub curve_type: u16,
    pub key_length: u16,
    #[br(count = key_length)]
    pub key: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x000b)]
pub struct SignatureObject {
    pub signature_type: u16,
    pub signature_data_length: u16,
    #[br(count = signature_data_length)]
    pub signature_data: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x000a)]
pub struct ContentKeyObject {
    pub key_id: [u8; 16],
    pub key_type: u16,
    pub cipher_type: CipherType,
    pub key_length: u16,
    #[br(count = key_length)]
    pub encrypted_key: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x000d)]
pub struct RightsSettingsObject {
    pub rights: u16,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0005)]
pub struct OutputProtectionLevelRestrictionObject {
    pub minimum_compressed_digital_video_opl: u16,
    pub minimum_uncompressed_digital_video_opl: u16,
    pub minimum_analog_video_opl: u16,
    pub minimum_digital_compressed_audio_opl: u16,
    pub minimum_digital_uncompressed_audio_opl: u16,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0012)]
pub struct ExpirationRestrictionObject {
    pub begin_date: u32,
    pub end_date: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0050)]
pub struct RemovalDateObject {
    pub removal_date: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x003b)]
pub struct UplinkKIDObject {
    pub plink_kid: [u8; 16],
    pub chained_checksum_type: u16,
    pub chained_checksum_length: u16,
    #[br(count = chained_checksum_length)]
    pub chained_checksum: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x0008)]
pub struct AnalogVideoOutputConfigurationRestriction {
    pub video_output_protection_id: [u8; 16],
    #[br(count = length - 24)]
    pub binary_configuration_data: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x0059)]
pub struct DigitalVideoOutputRestrictionObject {
    pub video_output_protection_id: [u8; 16],
    #[br(count = length - 24)]
    pub binary_configuration_data: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x0031)]
pub struct DigitalAudioOutputRestrictionObject {
    pub audio_output_protection_id: [u8; 16],
    #[br(count = length - 24)]
    pub binary_configuration_data: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x002c)]
pub struct PolicyMetadataObject {
    pub metadata_type: [u8; 16],
    #[br(count = length - 24)]
    pub policy_data: Vec<u8>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x005a)]
pub struct SecureStopRestrictionObject {
    pub metering_id: [u8; 16],
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0016)]
pub struct MeteringRestrictionObject {
    pub metering_id: [u8; 16],
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0030)]
pub struct ExpirationAfterFirstPlayRestrictionObject {
    pub seconds: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x001a)]
pub struct GracePeriodObject {
    pub grace_period: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0022)]
pub struct SourceIdObject {
    pub source_id: u32,
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct AuxiliaryKey {
    pub location: u32,
    pub key: [u8; 16],
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0051)]
pub struct AuxiliaryKeysObject {
    pub count: u16,
    #[br(count = count)]
    pub auxiliary_keys: Vec<AuxiliaryKey>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0052)]
pub struct UplinkKeyObject3 {
    pub uplink_key_id: [u8; 16],
    pub chained_length: u16,
    #[br(count = chained_length)]
    pub checksum: Vec<u8>,
    pub count: u16,
    #[br(count = count)]
    pub entries: Vec<u32>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x003a)]
pub struct CopyEnablerObject {
    pub copy_enabler_type: [u8; 16],
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x003d)]
pub struct CopyCountRestrictionObject {
    pub count: u32,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big)]
#[struct_tag(0x0037)]
pub struct MoveObject {
    pub minimum_move_protection_level: u32,
}

#[derive(BinRead, Debug, Clone)]
#[br(big, import { type_: u16, length: u32})]
pub enum XmrObjectInner {
    #[br(pre_assert(type_ == OutputProtectionLevelRestrictionObject::tag()))]
    OutputProtectionLevelRestrictionObject(OutputProtectionLevelRestrictionObject),
    #[br(pre_assert(type_ == AnalogVideoOutputConfigurationRestriction::tag()))]
    AnalogVideoOutputConfigurationRestriction(
        #[br(args(length))] AnalogVideoOutputConfigurationRestriction,
    ),
    #[br(pre_assert(type_ == ContentKeyObject::tag()))]
    ContentKeyObject(ContentKeyObject),
    #[br(pre_assert(type_ == SignatureObject::tag()))]
    SignatureObject(SignatureObject),
    #[br(pre_assert(type_ == RightsSettingsObject::tag()))]
    RightsSettingsObject(RightsSettingsObject),
    #[br(pre_assert(type_ == ExpirationRestrictionObject::tag()))]
    ExpirationRestrictionObject(ExpirationRestrictionObject),
    #[br(pre_assert(type_ == IssueDateObject::tag()))]
    IssueDateObject(IssueDateObject),
    #[br(pre_assert(type_ == MeteringRestrictionObject::tag()))]
    MeteringRestrictionObject(MeteringRestrictionObject),
    #[br(pre_assert(type_ == GracePeriodObject::tag()))]
    GracePeriodObject(GracePeriodObject),
    #[br(pre_assert(type_ == SourceIdObject::tag()))]
    SourceIdObject(SourceIdObject),
    #[br(pre_assert(type_ == ECCKeyObject::tag()))]
    ECCKeyObject(ECCKeyObject),
    #[br(pre_assert(type_ == PolicyMetadataObject::tag()))]
    PolicyMetadataObject(#[br(args(length))] PolicyMetadataObject),
    #[br(pre_assert(type_ == DomainRestrictionObject::tag()))]
    DomainRestrictionObject(DomainRestrictionObject),
    #[br(pre_assert(type_ == ExpirationAfterFirstPlayRestrictionObject::tag()))]
    ExpirationAfterFirstPlayRestrictionObject(ExpirationAfterFirstPlayRestrictionObject),
    #[br(pre_assert(type_ == DigitalAudioOutputRestrictionObject::tag()))]
    DigitalAudioOutputRestrictionObject(#[br(args(length))] DigitalAudioOutputRestrictionObject),
    #[br(pre_assert(type_ == RevInfoVersionObject::tag()))]
    RevInfoVersionObject(RevInfoVersionObject),
    #[br(pre_assert(type_ == EmbeddedLicenseSettingsObject::tag()))]
    EmbeddedLicenseSettingsObject(EmbeddedLicenseSettingsObject),
    #[br(pre_assert(type_ == SecurityLevelObject::tag()))]
    SecurityLevelObject(SecurityLevelObject),
    #[br(pre_assert(type_ == MoveObject::tag()))]
    MoveObject(MoveObject),
    #[br(pre_assert(type_ == PlayEnablerType::tag()))]
    PlayEnablerType(PlayEnablerType),
    #[br(pre_assert(type_ == CopyEnablerObject::tag()))]
    CopyEnablerObject(CopyEnablerObject),
    #[br(pre_assert(type_ == UplinkKIDObject::tag()))]
    UplinkKIDObject(UplinkKIDObject),
    #[br(pre_assert(type_ == CopyCountRestrictionObject::tag()))]
    CopyCountRestrictionObject(CopyCountRestrictionObject),
    #[br(pre_assert(type_ == RemovalDateObject::tag()))]
    RemovalDateObject(RemovalDateObject),
    #[br(pre_assert(type_ == AuxiliaryKeysObject::tag()))]
    AuxiliaryKeysObject(AuxiliaryKeysObject),
    #[br(pre_assert(type_ == UplinkKeyObject3::tag()))]
    UplinkKeyObject3(UplinkKeyObject3),
    #[br(pre_assert(type_ == SecureStopRestrictionObject::tag()))]
    SecureStopRestrictionObject(SecureStopRestrictionObject),
    #[br(pre_assert(type_ == DigitalVideoOutputRestrictionObject::tag()))]
    DigitalVideoOutputRestrictionObject(#[br(args(length))] DigitalVideoOutputRestrictionObject),
    Unknown(#[br(count = length)] Vec<u8>),
}

#[derive(BinRead, Debug, Clone)]
#[br(big)]
pub struct XmrObject {
    pub flags: u16,
    pub type_: u16,
    pub length: u32,
    #[br(args { type_, length })]
    pub data: XmrObjectInner,
}

#[derive(BinRead, Debug, Clone)]
#[br(big, magic = b"XMR\x00")]
pub struct XmrLicense {
    pub xmr_version: u32,
    pub rights_id: [u8; 16],
    // pyplayready is missing `unknown` field but somehow Python's construct manages to parse correctly
    pub unknown: [u8; 16],
    #[br(parse_with = until_eof)]
    pub containers: Vec<XmrObject>,
}
