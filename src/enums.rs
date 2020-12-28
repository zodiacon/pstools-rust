use winapi::um::winnt::*;

#[repr(u32)]
pub enum ProcessAccessMask {
    Terminate = PROCESS_TERMINATE,
    CreateThread = PROCESS_CREATE_THREAD,
    SetSessionId = PROCESS_SET_SESSIONID,
    VmOperation = PROCESS_VM_OPERATION,
    VmRead = PROCESS_VM_READ,
    VmWrite = PROCESS_VM_WRITE,
    DupHandle = PROCESS_DUP_HANDLE,
    CreateProcess = PROCESS_CREATE_PROCESS,
    SetQuota = PROCESS_SET_QUOTA,
    SetInformation = PROCESS_SET_INFORMATION,
    QueryInformation = PROCESS_QUERY_INFORMATION,
    SuspendResume = PROCESS_SUSPEND_RESUME,
    QueryLimitedInformation = PROCESS_QUERY_LIMITED_INFORMATION,
    SetLimitedInformation = PROCESS_SET_LIMITED_INFORMATION,
}

