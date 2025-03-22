#![allow(dead_code)]

use super::{until_exact_number_of_bytes, StructTag};
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
#[br(big, import(length: u32))]
#[struct_tag(0x0001)]
pub struct OuterContainer {
    // 8 = sizeof(flags) + sizeof(type_) + sizeof(length)
    #[br(parse_with = until_exact_number_of_bytes(u64::from(length - 8)))]
    pub containers: Vec<XmrObject>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x0002)]
pub struct GlobalPolicyContainer {
    // 8 = sizeof(flags) + sizeof(type_) + sizeof(length)
    #[br(parse_with = until_exact_number_of_bytes(u64::from(length - 8)))]
    pub containers: Vec<XmrObject>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x0004)]
pub struct PlaybackPolicyContainer {
    // 8 = sizeof(flags) + sizeof(type_) + sizeof(length)
    #[br(parse_with = until_exact_number_of_bytes(u64::from(length - 8)))]
    pub containers: Vec<XmrObject>,
}

#[derive(BinRead, StructTag, Debug, Clone)]
#[br(big, import(length: u32))]
#[struct_tag(0x0009)]
pub struct KeyMaterialContainer {
    // 8 = sizeof(flags) + sizeof(type_) + sizeof(length)
    #[br(parse_with = until_exact_number_of_bytes(u64::from(length - 8)))]
    pub containers: Vec<XmrObject>,
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
    #[br(pre_assert(type_ == OuterContainer::TAG))]
    OuterContainer(#[br(args(length))] OuterContainer),
    #[br(pre_assert(type_ == GlobalPolicyContainer::TAG))]
    GlobalPolicyContainer(#[br(args(length))] GlobalPolicyContainer),
    #[br(pre_assert(type_ == PlaybackPolicyContainer::TAG))]
    PlaybackPolicyContainer(#[br(args(length))] PlaybackPolicyContainer),
    #[br(pre_assert(type_ == KeyMaterialContainer::TAG))]
    KeyMaterialContainer(#[br(args(length))] KeyMaterialContainer),
    #[br(pre_assert(type_ == OutputProtectionLevelRestrictionObject::TAG))]
    OutputProtectionLevelRestrictionObject(OutputProtectionLevelRestrictionObject),
    #[br(pre_assert(type_ == AnalogVideoOutputConfigurationRestriction::TAG))]
    AnalogVideoOutputConfigurationRestriction(
        #[br(args(length))] AnalogVideoOutputConfigurationRestriction,
    ),
    #[br(pre_assert(type_ == ContentKeyObject::TAG))]
    ContentKeyObject(ContentKeyObject),
    #[br(pre_assert(type_ == SignatureObject::TAG))]
    SignatureObject(SignatureObject),
    #[br(pre_assert(type_ == RightsSettingsObject::TAG))]
    RightsSettingsObject(RightsSettingsObject),
    #[br(pre_assert(type_ == ExpirationRestrictionObject::TAG))]
    ExpirationRestrictionObject(ExpirationRestrictionObject),
    #[br(pre_assert(type_ == IssueDateObject::TAG))]
    IssueDateObject(IssueDateObject),
    #[br(pre_assert(type_ == MeteringRestrictionObject::TAG))]
    MeteringRestrictionObject(MeteringRestrictionObject),
    #[br(pre_assert(type_ == GracePeriodObject::TAG))]
    GracePeriodObject(GracePeriodObject),
    #[br(pre_assert(type_ == SourceIdObject::TAG))]
    SourceIdObject(SourceIdObject),
    #[br(pre_assert(type_ == ECCKeyObject::TAG))]
    ECCKeyObject(ECCKeyObject),
    #[br(pre_assert(type_ == PolicyMetadataObject::TAG))]
    PolicyMetadataObject(#[br(args(length))] PolicyMetadataObject),
    #[br(pre_assert(type_ == DomainRestrictionObject::TAG))]
    DomainRestrictionObject(DomainRestrictionObject),
    #[br(pre_assert(type_ == ExpirationAfterFirstPlayRestrictionObject::TAG))]
    ExpirationAfterFirstPlayRestrictionObject(ExpirationAfterFirstPlayRestrictionObject),
    #[br(pre_assert(type_ == DigitalAudioOutputRestrictionObject::TAG))]
    DigitalAudioOutputRestrictionObject(#[br(args(length))] DigitalAudioOutputRestrictionObject),
    #[br(pre_assert(type_ == RevInfoVersionObject::TAG))]
    RevInfoVersionObject(RevInfoVersionObject),
    #[br(pre_assert(type_ == EmbeddedLicenseSettingsObject::TAG))]
    EmbeddedLicenseSettingsObject(EmbeddedLicenseSettingsObject),
    #[br(pre_assert(type_ == SecurityLevelObject::TAG))]
    SecurityLevelObject(SecurityLevelObject),
    #[br(pre_assert(type_ == MoveObject::TAG))]
    MoveObject(MoveObject),
    #[br(pre_assert(type_ == PlayEnablerType::TAG))]
    PlayEnablerType(PlayEnablerType),
    #[br(pre_assert(type_ == CopyEnablerObject::TAG))]
    CopyEnablerObject(CopyEnablerObject),
    #[br(pre_assert(type_ == UplinkKIDObject::TAG))]
    UplinkKIDObject(UplinkKIDObject),
    #[br(pre_assert(type_ == CopyCountRestrictionObject::TAG))]
    CopyCountRestrictionObject(CopyCountRestrictionObject),
    #[br(pre_assert(type_ == RemovalDateObject::TAG))]
    RemovalDateObject(RemovalDateObject),
    #[br(pre_assert(type_ == AuxiliaryKeysObject::TAG))]
    AuxiliaryKeysObject(AuxiliaryKeysObject),
    #[br(pre_assert(type_ == UplinkKeyObject3::TAG))]
    UplinkKeyObject3(UplinkKeyObject3),
    #[br(pre_assert(type_ == SecureStopRestrictionObject::TAG))]
    SecureStopRestrictionObject(SecureStopRestrictionObject),
    #[br(pre_assert(type_ == DigitalVideoOutputRestrictionObject::TAG))]
    DigitalVideoOutputRestrictionObject(#[br(args(length))] DigitalVideoOutputRestrictionObject),
    // 8 = sizeof(flags) + sizeof(type_) + sizeof(length)
    Unknown(#[br(count = length - 8)] Vec<u8>),
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
    pub offset: u16,
    pub version: u16,
    pub rights_id: [u8; 16],
    #[br(parse_with = until_eof)]
    pub containers: Vec<XmrObject>,
}
