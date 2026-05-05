pub fn enter_sandbox() {
    let quarantine_path = "./sandbox";
    std::fs::create_dir_all(quarantine_path).expect("Failed to create sandbox dir");
    
    // Canonicalize to get the absolute path for the sandbox profiles
    let abs_path = std::fs::canonicalize(quarantine_path).unwrap();
    let path_str = abs_path.to_str().unwrap();

    // Trigger the platform-specific sandbox
    if let Err(e) = apply_sandbox(path_str) {
        eprintln!("Error applying sandbox: {}", e);
        std::process::exit(1);
    }

    println!("Sandbox active. Running pupscan logic...");
}

// --- MAC OS IMPLEMENTATION ---
#[cfg(target_os = "macos")]
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u32, errorbuf: *mut *mut libc::c_char) -> libc::c_int;
}

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
        if sandbox_init(c_profile.as_ptr(), 0, &mut err_ptr) != 0 {
            return Err("macOS sandbox_init failed".to_string());
        }
    }
    Ok(())
}

// --- LINUX IMPLEMENTATION ---
#[cfg(target_os = "linux")]
const MS_BIND: u64 = 4096;
#[cfg(target_os = "linux")]
const MS_REC: u64 = 16384;
#[cfg(target_os = "linux")]
const MS_PRIVATE: u64 = 1 << 18;
#[cfg(target_os = "linux")]
const MS_RDONLY: u64 = 1;

#[cfg(target_os = "linux")]
fn apply_sandbox(jail_path: &str) {
    let root = CString::new("/").unwrap();
    let c_jail = CString::new(jail_path).unwrap();
    let old_root_path = format!("{}/old_root", jail_path);
    let c_old_root = CString::new(old_root_path.as_str()).unwrap();

    unsafe {
        // 1. Create new namespaces (Mount & PID)
        if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) != 0 {
            panic!("Failed to unshare. Run as root/sudo.");
        }

        // 2. Make our mounts private
        libc::mount(ptr::null(), root.as_ptr(), ptr::null(), MS_REC | MS_PRIVATE, ptr::null());

        // 3. Bind mount the jail to itself so it's a mount point
        libc::mount(c_jail.as_ptr(), c_jail.as_ptr(), ptr::null(), MS_BIND | MS_REC, ptr::null());

        // 4. PROVIDE NETWORK BASICS: Bind mount DNS and SSL certs (READ ONLY)
        // Without these, ureq cannot resolve hostnames or verify HTTPS
        setup_net_configs(jail_path);

        // 5. Pivot Root
        fs::create_dir_all(&old_root_path).unwrap();
        libc::syscall(libc::SYS_pivot_root, c_jail.as_ptr(), c_old_root.as_ptr());
        
        // 6. Cleanup
        libc::chdir(root.as_ptr());
        libc::umount2(CString::new("/old_root").unwrap().as_ptr(), libc::MNT_DETACH);
        fs::remove_dir("/old_root").ok();

        // 7. DROP PRIVILEGES to 'nobody' (usually UID 65534)
        // This is CRITICAL. It prevents the code from undoing the jail.
        libc::setgid(65534);
        libc::setuid(65534);
    }
}

#[cfg(target_os = "linux")]
unsafe fn setup_net_configs(jail_path: &str) {
    let configs = [
        ("/etc/resolv.conf", "etc/resolv.conf"),
        ("/etc/ssl/certs", "etc/ssl/certs"),
    ];

    for (host, guest) in configs {
        let guest_full = format!("{}/{}", jail_path, guest);
        let _ = fs::create_dir_all(Path::new(&guest_full).parent().unwrap());
        let _ = fs::File::create(&guest_full); // Ensure file exists
        
        let c_host = CString::new(host).unwrap();
        let c_guest = CString::new(guest_full).unwrap();

        // Mount as Read-Only so the compromised code can't change DNS
        libc::mount(c_host.as_ptr(), c_guest.as_ptr(), ptr::null(), MS_BIND | MS_RDONLY, ptr::null());
    }
}

// --- FALLBACK FOR OTHER OS ---
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn apply_sandbox(_path: &str) -> Result<(), String> {
    println!("Warning: No sandbox implemented for this OS.");
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn test_sandbox_enforcement() {
    // 1. Enter sandbox
    enter_sandbox();
    // 2. Try to write to a forbidden path
    let result = std::fs::write("/tmp/malicious.txt", "evil data");
    // 3. Assert it was blocked
    assert!(result.is_err());
}