use std::ffi::CString;
use std::ptr;

// The macOS Sandbox Profile (SBPL)
// This is a minimal profile for a network-enabled tool.
const PROFILE: &str = r#"
(version 1)
(deny default) ; Deny everything by default

(allow network*) ; Allow outbound networking for ureq
(allow mach-lookup (global-name "com.apple.dnssd.service")) ; DNS lookup
(allow mach-lookup (global-name "com.apple.system.logger"))

; Allow reading system certificates and basic config
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/share/icu"))
(allow file-read* (subpath "/private/var/db/mds"))

; Allow writing ONLY to our specific download directory
(allow file-write* (subpath "./sandbox_data"))
(allow file-read* (subpath "./sandbox_data"))
"#;

fn main() {
    // 1. Prepare the error pointer
    let mut err_ptr: *mut libc::c_char = ptr::null_mut();
    let c_profile = CString::new(PROFILE).unwrap();

    unsafe {
        // 2. Enter the Sandbox
        // sandbox_init is a macOS-specific libc function
        let result = libc::sandbox_init(
            c_profile.as_ptr(),
            0, // flags
            &mut err_ptr
        );

        if result != 0 {
            if !err_ptr.is_null() {
                let err_msg = CString::from_raw(err_ptr);
                panic!("Sandbox init failed: {:?}", err_msg);
            }
            panic!("Sandbox init failed with unknown error");
        }
    }

    println!("Process is now sandboxed on macOS.");

    // Now ureq can run safely. If it tries to read your SSH keys in ~/.ssh,
    // the macOS kernel will kill the process or return a Permission Denied.
}
