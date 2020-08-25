#![cfg(windows)]

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null_mut, NonNull};
use std::rc::Rc;
use w32_error::W32Error;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;
use winapi::um::processthreadsapi::{CreateProcessW, CreateRemoteThread, ResumeThread};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_SUSPENDED, WAIT_FAILED};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE};

// windows handles are just a number,
// but there are intended to be used in the context they are created for,
// like a handle created from create process
// should be used in a context where a handle to a process is required
//
// this encapsulation makes sure that the handle is only used where it fits,
// and also that they only get cleaned up when they are definitely not needed anymore
//
// NonNull is also great here because 0 handles are invalid

#[derive(Clone)]
pub struct ProcessHandle(Rc<Handle>);

impl ProcessHandle {
    fn new(handle: NonNull<c_void>) -> Self {
        Self(Rc::new(Handle(handle)))
    }

    fn as_ptr(&self) -> HANDLE {
        (self.0).0.as_ptr()
    }
}

#[derive(Clone)]
pub struct ThreadHandle(ProcessHandle, Rc<Handle>);

impl ThreadHandle {
    fn new(proc_handle: &ProcessHandle, handle: NonNull<c_void>) -> Self {
        Self(proc_handle.clone(), Rc::new(Handle(handle)))
    }

    fn as_ptr(&self) -> HANDLE {
        (self.1).0.as_ptr()
    }
}

#[repr(transparent)]
struct Handle(NonNull<c_void>);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0.as_ptr());
        }
    }
}

#[derive(Clone)]
pub struct ProcessMemory {
    proc_handle: ProcessHandle,
    size: usize,
    mem_addr: NonNull<c_void>,
}

impl ProcessMemory {
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, W32Error> {
        assert!(
            self.len() >= bytes.len(),
            "bytes to write exceed process memory size"
        );
        let mut bytes_written = std::mem::MaybeUninit::uninit();
        unsafe {
            let res = WriteProcessMemory(
                self.proc_handle.as_ptr(),
                self.mem_addr.as_ptr(),
                bytes.as_ptr() as _,
                self.size.min(bytes.len()),
                bytes_written.as_mut_ptr(),
            );
            if res == FALSE {
                eprintln!("WriteProcessMemory failed");
                Err(W32Error::last_thread_error())
            } else {
                Ok(bytes_written.assume_init())
            }
        }
    }

    pub unsafe fn as_ptr(&self) -> NonNull<c_void> {
        self.mem_addr
    }
}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        unsafe {
            VirtualFreeEx(
                self.proc_handle.as_ptr(),
                self.mem_addr.as_ptr(),
                0,
                MEM_RELEASE,
            );
        }
    }
}

pub fn create_process(
    path: &str,
    working_dir: &str,
) -> Result<(ProcessHandle, ThreadHandle), W32Error> {
    let path = OsStr::new(path)
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let working_dir = OsStr::new(working_dir)
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();

    // it is important that these two structs are initialized to zero,
    // because we can pass stuff to the create process function through at least startup_info
    // and if you don't zero them, garbage gets passed on,
    // likely resulting in a STATUS_ACCESS_VIOLATION (0xC0000005)
    let mut startup_info = std::mem::MaybeUninit::zeroed();
    let mut process_info = std::mem::MaybeUninit::zeroed();

    unsafe {
        if CreateProcessW(
            path.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            FALSE,
            CREATE_SUSPENDED,
            null_mut(),
            working_dir.as_ptr(),
            startup_info.as_mut_ptr(),
            process_info.as_mut_ptr(),
        ) == FALSE
        {
            eprintln!("CreateProcess failed");
            return Err(W32Error::last_thread_error());
        }

        let _startup_info = startup_info.assume_init();
        let process_info = process_info.assume_init();

        let proc_handle = ProcessHandle::new(
            NonNull::new(process_info.hProcess).expect("CreateProcess process handle is invalid"),
        );
        let thread_handle = ThreadHandle::new(
            &proc_handle,
            NonNull::new(process_info.hThread).expect("CreateProcess thread handle is invalid"),
        );
        Ok((proc_handle, thread_handle))
    }
}

pub fn alloc_process_memory(
    proc_handle: &ProcessHandle,
    size: usize,
) -> Result<ProcessMemory, W32Error> {
    unsafe {
        let alloc = VirtualAllocEx(
            proc_handle.as_ptr(),
            null_mut(),
            size,
            MEM_COMMIT,
            PAGE_READWRITE,
        );
        if alloc.is_null() {
            eprintln!("VirtualAllocEx failed");
            return Err(W32Error::last_thread_error());
        }
        Ok(ProcessMemory {
            proc_handle: proc_handle.clone(),
            size,
            mem_addr: NonNull::new_unchecked(alloc),
        })
    }
}

pub type ThreadStartRoutine = LPTHREAD_START_ROUTINE;

pub fn create_remote_thread(
    proc_handle: &ProcessHandle,
    routine: ThreadStartRoutine,
    parameter: NonNull<c_void>,
) -> Result<ThreadHandle, W32Error> {
    unsafe {
        let handle = CreateRemoteThread(
            proc_handle.as_ptr(),
            null_mut(),
            0,
            routine,
            parameter.as_ptr(),
            0,
            null_mut(),
        );
        if handle.is_null() {
            eprintln!("CreateRemoteThread failed");
            return Err(W32Error::last_thread_error());
        }
        Ok(ThreadHandle::new(
            &proc_handle,
            NonNull::new_unchecked(handle),
        ))
    }
}

pub fn wait_for_thread(thread_handle: &ThreadHandle, timeout_milli: u32) -> Result<(), W32Error> {
    unsafe {
        let res = WaitForSingleObject(thread_handle.as_ptr(), timeout_milli);
        if res == WAIT_FAILED {
            eprintln!("WaitForSingleObject failed");
            Err(W32Error::last_thread_error())
        } else {
            Ok(())
        }
    }
}

pub fn resume_thread(thread_handle: &ThreadHandle) -> Result<(), W32Error> {
    unsafe {
        let res = ResumeThread(thread_handle.as_ptr());
        if res == u32::max_value() {
            eprintln!("ResumeThread failed");
            Err(W32Error::last_thread_error())
        } else {
            Ok(())
        }
    }
}
