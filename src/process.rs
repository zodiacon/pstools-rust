use crate::enums;
use crate::core;
use std::time;
use std::ptr::null_mut;
use winapi::um::processthreadsapi::*;
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::*;
use winapi::um::winbase::*;
use winapi::ctypes::c_void;
use ntapi::ntexapi;
use winapi::shared::minwindef::MAX_PATH;

pub struct Process {
    handle: core::KernelHandle,
}

impl Process {
    pub fn current() -> Self {
        Self {
            handle: core::KernelHandle::new( unsafe { GetCurrentProcess() })
        }
    }
    pub fn open(access_mask: enums::ProcessAccessMask, pid: u32) -> Result<Self, core::Win32Error> {
        let handle = unsafe { OpenProcess(access_mask as u32, 0, pid) };
        if handle != null_mut() {
            Ok(Process {
                handle: core::KernelHandle::new(handle)
            })
        }
        else {
            Err(core::Win32Error::new())
        }
    }

    pub fn id(&self) -> u32 {
        unsafe { GetProcessId(self.handle.get()) }
    }

    pub fn full_path(&self) -> Result<String, core::Win32Error> {
        unsafe {
            let mut path = Vec::new();
            path.resize(MAX_PATH, 0u16);
            let mut size = MAX_PATH as u32;
            if QueryFullProcessImageNameW(self.handle.get(), 0, path.as_mut_ptr(), &mut size) == 0 {
                Err(core::Win32Error::new())
            }
            else {
                Ok(String::from_utf16(&path[..size as usize]).unwrap())
            }
        }
    }


}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub id: u32,
    pub parent_id: u32,
    pub thread_count: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ThreadInfoEx {

}

#[derive(Debug, Clone)]
pub struct ProcessInfoEx {
    pub id: u32,
    pub parent_id: u32,
    pub thread_count: u32,
    pub name: String,
    pub handle_count: u32,
    pub priority: i32,
    pub create_time: i64,
    pub user_time: std::time::Duration,
    pub kernel_time: std::time::Duration,
    pub session_id: u32,
    pub virtual_size: usize,
    pub peak_virtual_size: usize,
    pub working_set: usize,
    pub peak_working_set: usize,
    pub page_fault_count: u32,
    pub commit_size: usize,
    pub peak_commit_size: usize,
    pub paged_pool: usize,
    pub non_paged_pool: usize,
    pub peak_paged_pool: usize,
    pub peak_non_paged_pool: usize,
    pub threads: Vec<ThreadInfoEx>,
}

impl ProcessInfoEx {
    unsafe fn from_native(p: ntexapi::PSYSTEM_PROCESS_INFORMATION, name: String, include_threads: bool) -> Self {
        let pp = &*p;
        ProcessInfoEx {
            id: pp.UniqueProcessId as u32,
            parent_id: pp.InheritedFromUniqueProcessId as u32,
            thread_count: pp.NumberOfThreads,
            name: if pp.UniqueProcessId as u32 == 0 { "(Idle)".to_string() } else { String::from_utf16(std::slice::from_raw_parts(pp.ImageName.Buffer, (pp.ImageName.Length / 2) as usize)).unwrap() },
            create_time: *pp.CreateTime.QuadPart(),
            user_time: time::Duration::from_nanos((*pp.UserTime.QuadPart() * 100) as u64),
            kernel_time: time::Duration::from_nanos((*pp.KernelTime.QuadPart() * 100) as u64),
            handle_count: pp.HandleCount,
            priority: pp.BasePriority,
            session_id: pp.SessionId,
            working_set: pp.WorkingSetSize,
            peak_working_set: pp.PeakWorkingSetSize,
            commit_size: pp.PagefileUsage,
            peak_commit_size: pp.PeakPagefileUsage,
            paged_pool: pp.QuotaPagedPoolUsage,
            non_paged_pool: pp.QuotaNonPagedPoolUsage,
            peak_paged_pool: pp.QuotaPeakPagedPoolUsage,
            peak_non_paged_pool: pp.QuotaPeakNonPagedPoolUsage,
            virtual_size: pp.VirtualSize,
            peak_virtual_size: pp.PeakVirtualSize,
            page_fault_count: pp.PageFaultCount,
            threads: if include_threads { enum_threads(pp) } else { Vec::new() },
        }
    }
}

pub fn enum_processes_native_pid(pid: u32, include_threads: bool) -> Option<ProcessInfoEx> {
    let mut result = enum_processes_native_generic(include_threads, pid, "").unwrap();
    if result.is_empty() {
        None
    }
    else {
        Some(result.pop().unwrap())
    }
}

pub fn enum_processes_native_name(name: &str, include_threads: bool) -> Result<Vec<ProcessInfoEx>, core::Win32Error> {
    enum_processes_native_generic(include_threads, std::u32::MAX, &name) 
}

pub fn enum_processes_native(include_threads: bool) -> Result<Vec<ProcessInfoEx>, core::Win32Error> {
    enum_processes_native_generic(include_threads, std::u32::MAX, "") 
}

fn enum_processes_native_generic(include_threads: bool, pid: u32, pname: &str) -> Result<Vec<ProcessInfoEx>, core::Win32Error> {
    unsafe {
        let mut buffer = Vec::new();
        let size: u32 = 1 << 22;
        buffer.resize(size as usize, 0u8);
        let status = ntexapi::NtQuerySystemInformation(ntexapi::SystemExtendedProcessInformation, buffer.as_mut_ptr() as *mut c_void, size, null_mut());
        if status != 0 {
            return Err(core::Win32Error::from_ntstatus(status));
        }

        let mut p = buffer.as_mut_ptr() as ntexapi::PSYSTEM_PROCESS_INFORMATION;
        let mut processes = Vec::with_capacity(512);

        loop {
            let pp = &*p;
            let name = if pp.UniqueProcessId as u32 == 0 { "(Idle)".to_string() } else { String::from_utf16(std::slice::from_raw_parts(pp.ImageName.Buffer, (pp.ImageName.Length / 2) as usize)).unwrap() };
            if (pid == std::u32::MAX || pid == pp.UniqueProcessId as u32) && (pname.len() == 0 || pname == name) {
                let pi = ProcessInfoEx::from_native(p, name, include_threads);
                processes.push(pi);
            }
            if pp.NextEntryOffset == 0 {
                break;
            }
            p = (p as *mut u8).offset((*p).NextEntryOffset as isize) as ntexapi::PSYSTEM_PROCESS_INFORMATION;
        }

        processes.shrink_to_fit();
        Ok(processes)
    }
}

fn enum_threads(pi: &ntexapi::SYSTEM_PROCESS_INFORMATION) -> Vec<ThreadInfoEx> {
    todo!();
}

pub fn enum_processes_toolhelp() -> Result<Vec<ProcessInfo>, core::Win32Error> {
    unsafe {
        let handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // create a KernelHandle that is automatically closed
        let _khandle = core::KernelHandle::new(handle);

        if handle == INVALID_HANDLE_VALUE {
            return Err(core::Win32Error::new())
        }
        let mut processes = Vec::with_capacity(512);

        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(handle, &mut pe) != 0 {
            loop {
                let pi = ProcessInfo {
                    id: pe.th32ProcessID,
                    parent_id: pe.th32ParentProcessID,
                    thread_count: pe.cntThreads,
                    name: String::from_utf16(&pe.szExeFile[..lstrlenW(pe.szExeFile.as_ptr()) as usize]).unwrap()
                };
                processes.push(pi);
                if Process32NextW(handle, &mut pe) == 0 {
                    break;
                }
            }
        }
        else {
            return Err(core::Win32Error::new());        
        }
        processes.shrink_to_fit();
        Ok(processes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locate_process(name: &str) -> u32 {
        for pi in &enum_processes_toolhelp().unwrap() {
            if pi.name == name && pi.thread_count > 0 {
                return pi.id;
            }
        }
        0
    }

    #[test]
    fn open_process() {
        let explorer = locate_process("explorer.exe");
        assert!(explorer != 0);
        let process = Process::open(enums::ProcessAccessMask::QueryLimitedInformation, explorer).unwrap();
        assert_eq!(process.id(), explorer);
        let path = process.full_path().unwrap();
        assert!(path.eq_ignore_ascii_case("c:\\Windows\\explorer.exe"));
    }

    #[test]
    fn enum_processes1() {
        let processes = enum_processes_toolhelp().unwrap();
        for pi in &processes {
            println!("{:?}", pi);
        }
    }

    #[test]
    fn enum_processes2() {
        let processes = enum_processes_native(false).unwrap();
        for pi in &processes {
            println!("{:?}", pi);
        }
    }

    #[test]
    fn current_process() {
        let process = Process::current();
        unsafe {
            assert_eq!(process.id(), GetCurrentProcessId());
        }
        println!("{}", process.full_path().unwrap());
    }
}

