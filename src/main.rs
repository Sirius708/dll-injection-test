#![cfg(windows)]

mod proc;

use crate::proc::{
    alloc_process_memory, create_process, create_remote_thread, resume_thread, wait_for_thread,
};
use std::ffi::{CString, OsStr};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use w32_error::W32Error;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};

const APP_PATH: &str = "C:\\Windows\\System32\\calc.exe";
const APP_DIR: &str = "C:\\Windows\\System32";
const DLL_HOOK: &str = "dll_hook_test.dll";

fn main() {
    // when creating the process make sure that the working directory is set to the directory
    // your target app is located in, otherwise you could get startup problems
    // or in the worst case some kind of file corruption or similar, because some files like dlls
    // are not in the directory where your injector is executed or some relative paths of the app
    // are now wreaking havoc on unrelated files, or again just missing files
    println!("Creating process: '{}'", APP_PATH);
    let (proc_handle, proc_thread_handle) = create_process(APP_PATH, APP_DIR)
        .map_err(|err| {
            eprintln!("{}", err);
            err
        })
        .unwrap();

    // as the dll hook needs to be run in the target process, we need to write the dll hook path
    // into the memory of the target process, make sure the path is nul terminated
    println!("Allocating process memory for dll hook path");
    let dll_hook = CString::new(DLL_HOOK).unwrap();
    let mut dll_hook_mem = alloc_process_memory(&proc_handle, DLL_HOOK.len() + 1)
        .map_err(|err| {
            eprintln!("{}", err);
            err
        })
        .unwrap();

    println!("Writing dll hook path into process memory");
    dll_hook_mem
        .write(dll_hook.as_bytes_with_nul())
        .map_err(|err| {
            eprintln!("{}", err);
            err
        })
        .unwrap();

    // we are getting the LoadLibrary function pointer here, because it is the function
    // that gets executed on the process to load our dll hook
    //
    // THIS METHOD OF DLL INJECTION WILL NOT WORK IF YOUR TARGET APPLICATION IS NOT LINKED AGAINST KERNEL32.DLL
    //
    println!("Loading LoadLibraryA from kernel32.dll");
    let load_library_fn = unsafe {
        let dll = OsStr::new("kernel32.dll")
            .encode_wide()
            .chain(once(0))
            .collect::<Vec<_>>();
        let ld_lib = CString::new("LoadLibraryA").unwrap();

        let mod_handle = GetModuleHandleW(dll.as_ptr());
        if mod_handle.is_null() {
            eprintln!("GetModuleHandleW failed");
            panic!("{}", W32Error::last_thread_error());
        }
        GetProcAddress(mod_handle, ld_lib.as_ptr())
    };
    if load_library_fn.is_null() {
        eprintln!("GetProcAddress failed");
        panic!("{}", W32Error::last_thread_error());
    }

    // we pass the LoadLibrary function pointer as our thread start routine
    // and the pointer to the memory that contains the dll hook path is the argument,
    // this will cause LoadLibrary to be executed on the target process with our dll hook path as argument
    // and will thus inject and execute our dll hook on the target process
    println!("Creating a remote thread with dll hook");
    let thread_handle = unsafe {
        create_remote_thread(
            &proc_handle,
            Some(std::mem::transmute(load_library_fn)),
            dll_hook_mem.as_ptr(),
        )
        .map_err(|err| {
            eprintln!("{}", err);
            err
        })
        .unwrap()
    };

    // this timeout is only there toi make sure the dll hook is finished
    // injection code or doing whatever it needs to do
    //
    // WaitForSingleObject has more return values that specify better why it finished waiting
    // I'm just waiting for the thread or timeout, nothing sophisticated here
    println!("Waiting for remote thread to finish");
    wait_for_thread(&thread_handle, 5000)
        .map_err(|err| {
            eprintln!("{}", err);
            err
        })
        .unwrap();

    // if you don't resume the main application thread of the program you injected the dll into,
    // nothing will happen except that you now have a pretty much dead process in the background,
    // so either kill it if something goes wrong or resume it when you're finished with the injection
    println!("Resuming main application thread");
    resume_thread(&proc_thread_handle)
        .map_err(|err| {
            eprintln!("{}", err);
            err
        })
        .unwrap();

    println!("Finished dll hook injection");
}
