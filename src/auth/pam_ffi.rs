// Minimal PAM FFI bindings.
use std::ffi::{CStr, CString};
use std::ptr;

const PAM_SUCCESS: i32 = 0;
const PAM_AUTH_ERR: i32 = 1;
const PAM_PROMPT_ECHO_OFF: i32 = 1;
const PAM_PROMPT_ECHO_ON: i32 = 2;
#[allow(dead_code)]
const PAM_ERROR_MSG: i32 = 3;
#[allow(dead_code)]
const PAM_TEXT_INFO: i32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct PamMessage {
    msg_style: i32,
    msg: *const libc::c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut libc::c_char,
    resp_retcode: i32,
}

type PamConvFunc = extern "C" fn(
    num_msg: i32,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut libc::c_void,
) -> i32;

#[repr(C)]
struct PamConv {
    conv: PamConvFunc,
    appdata_ptr: *mut libc::c_void,
}

type PamHandle = *mut libc::c_void;

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const libc::c_char,
        user: *const libc::c_char,
        conv: *const PamConv,
        pamh: *mut PamHandle,
    ) -> i32;

    fn pam_authenticate(pamh: PamHandle, flags: i32) -> i32;
    fn pam_end(pamh: PamHandle, status: i32) -> i32;
    fn pam_strerror(pamh: PamHandle, errnum: i32) -> *const libc::c_char;
}

extern "C" fn pam_conv_callback(
    num_msg: i32,
    msgs: *const *const PamMessage,
    resp_out: *mut *mut PamResponse,
    appdata: *mut libc::c_void,
) -> i32 {
    if num_msg <= 0 || msgs.is_null() || resp_out.is_null() {
        return PAM_AUTH_ERR;
    }

    let password_ptr = appdata as *const libc::c_char;
    let password: Option<Vec<u8>> = if password_ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(password_ptr) }.to_bytes().to_vec())
    };

    // Allocate array of PamResponse using libc malloc (PAM will free it)
    let array_size = (num_msg as usize) * std::mem::size_of::<PamResponse>();
    let array_ptr = unsafe { libc::malloc(array_size) as *mut PamResponse };
    if array_ptr.is_null() {
        return PAM_AUTH_ERR;
    }

    // Zero-initialize
    unsafe { libc::memset(array_ptr as *mut libc::c_void, 0, array_size) };

    for i in 0..num_msg as usize {
        let msg = unsafe { (*(*msgs.add(i))).to_owned() };
        match msg.msg_style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => {
                if let Some(ref pwd) = password {
                    unsafe {
                        let cstr = CString::new(pwd.as_slice() as &[u8]).unwrap();
                        let resp_ptr = libc::strdup(cstr.as_ptr());
                        (*array_ptr.add(i)).resp = resp_ptr;
                    }
                }
            }
            _ => {}
        }
    }

    unsafe { *resp_out = array_ptr };
    PAM_SUCCESS
}

pub fn authenticate(service: &str, user: &str, password: &str) -> anyhow::Result<()> {
    let service_c = CString::new(service)?;
    let user_c = CString::new(user)?;
    let password_c = CString::new(password)?;

    let password_ptr = password_c.as_ptr();

    let conv = PamConv {
        conv: pam_conv_callback,
        appdata_ptr: password_ptr as *mut libc::c_void,
    };

    let mut pamh: PamHandle = ptr::null_mut();
    let ret = unsafe { pam_start(service_c.as_ptr(), user_c.as_ptr(), &conv, &mut pamh) };
    if ret != PAM_SUCCESS {
        let err_str = unsafe { CStr::from_ptr(pam_strerror(pamh, ret)) }
            .to_string_lossy()
            .to_string();
        unsafe { pam_end(pamh, ret) };
        anyhow::bail!("pam_start failed ({}): {}", ret, err_str);
    }

    let auth_ret = unsafe { pam_authenticate(pamh, 0) };
    let end_ret = unsafe { pam_end(pamh, auth_ret) };
    if end_ret != PAM_SUCCESS {
        anyhow::bail!("pam_end failed: {}", end_ret);
    }

    if auth_ret != PAM_SUCCESS {
        let err_str = unsafe { CStr::from_ptr(pam_strerror(pamh, auth_ret)) }
            .to_string_lossy()
            .to_string();
        anyhow::bail!("pam_authenticate failed ({}): {}", auth_ret, err_str);
    }

    Ok(())
}
