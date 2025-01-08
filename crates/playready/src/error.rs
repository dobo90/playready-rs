//! Error handling.

#![allow(missing_docs)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Binary object not found {0}")]
    BinaryObjectNotFoundError(&'static str),
    #[error("Certificate verification error in certificate with index {0}")]
    CertificateVerificationError(usize),
    #[error("Public key and signature mismatch of {0}")]
    PublicKeyMismatchError(&'static str),
    #[error("Unsupported cipher type {0:?}")]
    UnsupportedCipherTypeError(crate::binary_format::xmr_license::CipherType),
    #[error("P256 decode error")]
    P256DecodeError,
    #[error("Missing license in challenge response")]
    LicenseMissingError,
    #[error("Missing certificate in BCertChain")]
    CertificateMissingError,
    #[error("Slice out of bounds in {0} at length {1}")]
    SliceOutOfBoundsError(&'static str, usize),
    #[error("Parse error")]
    ParseError(#[from] binrw::Error),
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("Base64 decode error")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Integer conversion error")]
    TryFromIntError(#[from] std::num::TryFromIntError),
    #[error("P256 signature verification error")]
    P256EcdsaError(#[from] p256::ecdsa::Error),
    #[error("XML builder error")]
    XmlBuilderError(#[from] xml_builder::XMLError),
    #[error("XML parser error")]
    XmlParserError(#[from] roxmltree::Error),
    #[error("Utf8 conversion error")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Aes invalid length")]
    AesInvalidLengthError(#[from] aes::cipher::InvalidLength),
}
