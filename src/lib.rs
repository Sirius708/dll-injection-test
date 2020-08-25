use std::ffi::CString;
use std::ptr::null_mut;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};
use winapi::um::winuser::{MessageBoxA, MB_ICONINFORMATION};

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _instance: HINSTANCE,
    call_reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            let caption = CString::new("Hey you!").unwrap();
            let message = CString::new("You're finally awake!").unwrap();
            unsafe {
                MessageBoxA(
                    null_mut(),
                    message.as_ptr(),
                    caption.as_ptr(),
                    MB_ICONINFORMATION,
                );
            }
        }
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    }
    TRUE
}
