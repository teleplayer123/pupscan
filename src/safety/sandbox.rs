use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::ptr;

// Minimal constants for syscalls
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 16384;
const MS_PRIVATE: u64 = 1 << 18;
const MS_RDONLY: u64 = 1;

fn enter_sandbox(jail_path: &str) {
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
