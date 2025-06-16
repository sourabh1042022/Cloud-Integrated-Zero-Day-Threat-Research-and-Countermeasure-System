use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::fs::OpenOptions;
use std::io::Write;

#[no_mangle]
pub extern "C" fn execve(pathname: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe {
        let c_path = CString::from_raw(pathname as *mut c_char);
        let log_path = "/tmp/syscall_log.txt";

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            let _ = writeln!(file, "[HOOKED execve] → {:?}", c_path);
        }

        let real_execve: extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int =
            std::mem::transmute(libc::dlsym(libc::RTLD_NEXT, b"execve\0".as_ptr() as *const c_char));
        real_execve(pathname, argv, envp)
    }
}
