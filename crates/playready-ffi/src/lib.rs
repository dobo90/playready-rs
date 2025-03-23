use playready::{cdm::Session, pssh::WrmHeader, Cdm, Device, Pssh};
use safer_ffi::prelude::*;

#[derive_ReprC(rename = "playready_cdm")]
#[repr(opaque)]
pub struct FfiCdm {
    inner: Cdm,
}

#[derive_ReprC(rename = "playready_session")]
#[repr(opaque)]
pub struct FfiSession {
    inner: Session,
}

#[derive_ReprC(rename = "playready_pssh")]
#[repr(opaque)]
pub struct FfiPssh {
    inner: Pssh,
}

#[derive_ReprC(rename = "playready_wrm_header")]
#[repr(opaque)]
pub struct FfiWrmHeader {
    inner: WrmHeader,
}

impl From<WrmHeader> for FfiWrmHeader {
    fn from(value: WrmHeader) -> Self {
        Self { inner: value }
    }
}

#[derive_ReprC(rename = "playready_kid_ck")]
#[repr(C)]
pub struct FfiKidCk {
    pub kid: [u8; 16],
    pub ck: repr_c::Box<[u8]>,
}

/// Creates new instance of [`Cdm`] from path to `.prd` file.
///
/// When successful function returns pointer to [`Cdm`] which needs to be deallocated by [`playready_cdm_free()`].
/// Otherwise it returns `NULL` and pointer to `error_msg` that needs to be deallocated by [`playready_error_message_free()`].
#[ffi_export]
pub fn playready_cdm_create_from_prd(
    prd_path: char_p::Ref<'_>,
    error_msg: Out<'_, Option<char_p::Box>>,
) -> Option<repr_c::Box<FfiCdm>> {
    let device = match Device::from_prd(prd_path.to_str()) {
        Ok(device) => device,
        Err(err) => {
            error_msg.write(Some(char_p::new(format!("{err:?}"))));
            return None;
        }
    };

    Some(
        Box::new(FfiCdm {
            inner: Cdm::from_device(device),
        })
        .into(),
    )
}

/// Creates new [`Session`].
///
/// Returned pointer should be deallocated by [`playready_session_free()`].
#[ffi_export]
pub fn playready_cdm_open_session(cdm: &FfiCdm) -> repr_c::Box<FfiSession> {
    Box::new(FfiSession {
        inner: cdm.inner.open_session(),
    })
    .into()
}

/// Creates new instance of [`Pssh`] from bytes.
///
/// When successful it returns a pointer to [`Pssh`] which needs to be deallocated by [`playready_pssh_free()`].
/// If not successful it will return `NULL` and pointer to `error_msg` which needs to be deallocated by [`playready_error_message_free()`].
#[ffi_export]
pub fn playready_pssh_from_bytes(
    bytes: c_slice::Ref<'_, u8>,
    error_msg: Out<'_, Option<char_p::Box>>,
) -> Option<repr_c::Box<FfiPssh>> {
    match Pssh::from_bytes(bytes.as_slice()) {
        Ok(inner) => Some(Box::new(FfiPssh { inner }).into()),
        Err(err) => {
            error_msg.write(Some(char_p::new(format!("{err:?}"))));
            None
        }
    }
}

/// Creates new instance of [`Pssh`] from Base64 string.
///
/// When successful it returns a pointer to [`Pssh`] which needs to be deallocated by [`playready_pssh_free()`].
/// If not successful it will return `NULL` and pointer to `error_msg` which needs to be deallocated by [`playready_error_message_free()`].
#[ffi_export]
pub fn playready_pssh_from_b64(
    b64: char_p::Ref<'_>,
    error_msg: Out<'_, Option<char_p::Box>>,
) -> Option<repr_c::Box<FfiPssh>> {
    match Pssh::from_b64(b64.to_bytes()) {
        Ok(inner) => Some(Box::new(FfiPssh { inner }).into()),
        Err(err) => {
            error_msg.write(Some(char_p::new(format!("{err:?}"))));
            None
        }
    }
}

/// Extracts first wrm header from [`Pssh`].
///
/// Returned pointer should be passed to [`playready_session_get_license_challenge()`] where it will be consumed (and deallocated).
#[ffi_export]
pub fn playready_pssh_get_first_wrm_header(pssh: &FfiPssh) -> Option<repr_c::Box<FfiWrmHeader>> {
    let wrm_headers = pssh.inner.wrm_headers();
    let wrm_header: FfiWrmHeader = wrm_headers.first().cloned()?.into();
    Some(Box::new(wrm_header).into())
}

/// Returns license challenge.
///
/// Function consumes and deallocates `wrm_header`. It's recommended to set `wrm_header` to `NULL` after calling this function.
/// If successful returned pointer should be freed by [`playready_license_challenge_free()`].
/// Otherwise it returns `error_msg` which needs to deallocated by [`playready_error_message_free()`].
#[ffi_export]
pub fn playready_session_get_license_challenge(
    session: &FfiSession,
    wrm_header: repr_c::Box<FfiWrmHeader>,
    error_msg: Out<'_, Option<char_p::Box>>,
) -> Option<char_p::Box> {
    let wrm_header = wrm_header.into();

    match session.inner.get_license_challenge(wrm_header.inner) {
        Ok(s) => Some(char_p::new(s)),
        Err(err) => {
            error_msg.write(Some(char_p::new(format!("{err:?}"))));
            None
        }
    }
}

/// Returns keys from license response.
///
/// If successful (`error_msg` != `NULL`) return value needs to be deallocated by [`playready_keys_free()`].
/// Otherwise it return `error_msg` which needs to be deallocated by [`playready_error_message_free()`].
#[ffi_export]
pub fn playready_session_get_keys_from_challenge_response(
    session: &FfiSession,
    response: char_p::Ref<'_>,
    error_msg: Out<'_, Option<char_p::Box>>,
) -> Option<repr_c::Vec<FfiKidCk>> {
    match session
        .inner
        .get_keys_from_challenge_response(response.to_str())
    {
        Ok(keys) => Some(
            keys.into_iter()
                .map(|kid_ck| FfiKidCk {
                    kid: kid_ck.0.into(),
                    ck: Box::<[u8]>::from(kid_ck.1).into(),
                })
                .collect::<Vec<_>>()
                .into(),
        ),
        Err(err) => {
            error_msg.write(Some(char_p::new(format!("{err:?}"))));
            None
        }
    }
}

/// Deallocates `cdm`. If `NULL` is passed function will do nothing.
#[ffi_export]
pub fn playready_cdm_free(cdm: Option<repr_c::Box<FfiCdm>>) {
    drop(cdm)
}

/// Deallocates `session`. If `NULL` is passed function will do nothing.
#[ffi_export]
pub fn playready_session_free(session: Option<repr_c::Box<FfiSession>>) {
    drop(session)
}

/// Deallocates `pssh`. If `NULL` is passed function will do nothing.
#[ffi_export]
pub fn playready_pssh_free(pssh: Option<repr_c::Box<FfiPssh>>) {
    drop(pssh)
}

/// Deallocates `challenge`. If `NULL` is passed function will do nothing.
#[ffi_export]
pub fn playready_license_challenge_free(challenge: Option<char_p::Box>) {
    drop(challenge)
}

/// Deallocates `keys`. If `NULL` is passed function will do nothing.
#[ffi_export]
pub fn playready_keys_free(keys: repr_c::Vec<FfiKidCk>) {
    drop(keys)
}

/// Deallocates `error_msg`. If `NULL` is passed function will do nothing.
#[ffi_export]
pub fn playready_error_message_free(error_msg: Option<char_p::Box>) {
    drop(error_msg)
}

pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("playready.h")?
        .generate()
}
