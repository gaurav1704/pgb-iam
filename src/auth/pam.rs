/// Authenticate a user via PAM using minimal FFI.
pub fn authenticate(service: &str, user: &str, password: &str) -> anyhow::Result<()> {
    crate::auth::pam_ffi::authenticate(service, user, password)
}
