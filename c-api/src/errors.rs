use std::ffi::c_char;

use rats_rs::errors::{Error, ErrorKind};

#[allow(non_camel_case_types)]
pub type error_kind_t = ErrorKind;

#[allow(non_camel_case_types)]
pub type error_obj_t = Error;

/// Get error kind of this `error_obj`.
#[no_mangle]
pub extern "C" fn rats_rs_err_get_kind(error_obj: *mut error_obj_t) -> error_kind_t {
    return (unsafe { &mut *error_obj }).get_kind();
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct error_msg_t {
    msg: *const c_char,
    msg_len: usize,
}

/// Get human-readable string for the detailed error message recoreded in this `error_obj`.
/// Caller should not modify the the message content returned by this api, and there is no need to deallocate the msg pointer. This api will not return null pointer in any case.
#[no_mangle]
pub extern "C" fn rats_rs_err_get_msg_ref(error_obj: *mut error_obj_t) -> error_msg_t {
    let msg = (unsafe { &mut *error_obj })
        .get_msg_ref()
        .as_ref()
        .map(|msg| msg.as_str())
        .unwrap_or("unknown");
    error_msg_t {
        msg: msg.as_ptr() as *const c_char,
        msg_len: msg.len(),
    }
}

/// Free the `error_obj` returned by other apis.
#[no_mangle]
pub extern "C" fn rats_rs_err_free(error_obj: *mut error_obj_t) {
    drop(unsafe { Box::from_raw(&mut *error_obj) });
}
