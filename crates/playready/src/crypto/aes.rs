use aes::{
    cipher::{
        block_padding::{NoPadding, Pkcs7},
        BlockEncryptMut, KeyInit, KeyIvInit,
    },
    Aes128,
};
use cmac::{CmacCore, Mac};
use sha2::digest::{core_api::CoreWrapper, MacError};

pub fn encrypt_cbc(
    key: &[u8],
    iv: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, aes::cipher::InvalidLength> {
    let encryptor = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(msg))
}

pub fn encrypt_ecb(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, aes::cipher::InvalidLength> {
    let encryptor = <ecb::Encryptor<Aes128> as KeyInit>::new_from_slice(key)?;
    Ok(encryptor.encrypt_padded_vec_mut::<NoPadding>(msg))
}

pub fn verify_cmac(key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), MacError> {
    let mut cmac = <CoreWrapper<CmacCore<Aes128>> as Mac>::new_from_slice(key).or(Err(MacError))?;

    cmac.update(msg);
    cmac.verify_slice(signature)
}
