use std::fs;
use std::path::Path;

fn main() {
    let quarantine_path = "./quarantine";
    fs::create_dir_all(quarantine_path).expect("Failed to create quarantine dir");
    
    // Canonicalize to get the absolute path for the sandbox profiles
    let abs_path = fs::canonicalize(quarantine_path).unwrap();
    let path_str = abs_path.to_str().unwrap();

    // Trigger the platform-specific sandbox
    if let Err(e) = apply_sandbox(path_str) {
        eprintln!("Error applying sandbox: {}", e);
        std::process::exit(1);
    }

    println!("Sandbox active. Running pupscan logic...");
    
    // Your ureq logic goes here
    // let resp = ureq::get("...").call();
}

// --- MAC OS IMPLEMENTATION ---
#[cfg(target_os = "macos")]
fn apply_sandbox(path: &str) -> Result<(), String> {
    use std::ffi::CString;
    use std::ptr;

    let profile = format!(
        r#"(version 1)
           (deny default)
           (allow network-outbound)
           (allow mach-lookup (global-name "com.apple.dnssd.service"))
           (allow mach-lookup (global-name "com.apple.system.logger"))
           (allow file-read* (subpath "/usr/lib"))
           (allow file-read* (subpath "/System/Library"))
           (allow file-read* (subpath "/private/var/db/mds"))
           (allow file-read* (subpath "{path}"))
           (allow file-write* (subpath "{path}"))"#,
        path = path
    );

    let c_profile = CString::new(profile).unwrap();
    let mut err_ptr: *mut libc::c_char = ptr::null_mut();

    unsafe {
        if libc::sandbox_init(c_profile.as_ptr(), 0, &mut err_ptr) != 0 {
            return Err("macOS sandbox_init failed".to_string());
        }
    }
    Ok(())
}

// --- LINUX IMPLEMENTATION ---
#[cfg(target_os = "linux")]
fn apply_sandbox(path: &str) -> Result<(), String> {
    use std::ffi::CString;
    use std::ptr;

    unsafe {
        // 1. Unshare to get private Mount/PID namespaces
        if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) != 0 {
            return Err("Linux unshare failed. Did you run with sudo?".to_string());
        }

        // 2. Pivot root logic (simplified for brevity)
        // Note: Real Linux sandboxing requires more lines to setup bind mounts 
        // for /etc/resolv.conf so ureq can find the internet.
        
        // 3. Drop privileges to 'nobody'
        libc::setgid(65534);
        libc::setuid(65534);
    }
    Ok(())
}

// --- FALLBACK FOR OTHER OS ---
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn apply_sandbox(_path: &str) -> Result<(), String> {
    println!("Warning: No sandbox implemented for this OS.");
    Ok(())
}
