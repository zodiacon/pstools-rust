use winapi::shared::ntdef::HANDLE;
use winapi::um::handleapi::*;
use winapi::um::errhandlingapi::*;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Debug)]
pub struct KernelHandle(HANDLE);

#[derive(Debug, Clone, Copy)]
pub struct Win32Error(u32);

impl Drop for KernelHandle {
    fn drop(&mut self) {
        if self.0 as isize > 0 {
            unsafe { CloseHandle(self.0); }
        }
    }
}

impl KernelHandle {
    pub fn new(handle: HANDLE) -> Self {
        KernelHandle(handle)
    }

    pub fn close(&mut self) -> Result<(), Win32Error> {
        let success = unsafe { CloseHandle(self.0) };
        if success != 0 {
            Ok(())
        }
        else {
            Err(Win32Error::new())
        }
    }

    pub fn is_valid(&self) -> bool {
        self.0 != null_mut() 
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Win32Error {
    pub fn new() -> Self {
        unsafe { Win32Error(GetLastError()) }
    }

    pub fn from_error(error: u32) -> Self {
        Win32Error(error)
    }

    pub fn from_ntstatus(status: i32) -> Self {
        unsafe {
            Win32Error(ntapi::ntrtl::RtlNtStatusToDosError(status))
        }
    }
}