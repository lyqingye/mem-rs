use anyhow::Result;
use windows::Win32::{
    Foundation::{GetLastError, BOOL, FALSE, HANDLE, TRUE, CloseHandle},
    System::{
        Diagnostics::Debug::{
            GetThreadContext, ReadProcessMemory, SetThreadContext, Wow64GetThreadContext,
            Wow64SetThreadContext, WriteProcessMemory, CONTEXT, WOW64_CONTEXT,
        },
        Memory::{
            VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx,
            MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
            VIRTUAL_FREE_TYPE,
        },
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, IsWow64Process, NtQueryInformationProcess,
            OpenProcess, ProcessBasicInformation, ProcessWow64Information, LPTHREAD_START_ROUTINE,
            PROCESSINFOCLASS, PROCESS_ACCESS_RIGHTS, PROCESS_BASIC_INFORMATION,
            THREAD_CREATION_FLAGS,
        },
    },
};

use super::{
    any_as_u8_slice_mut, NtCreateThreadEx, NtResumeProcess, NtResumeThread,
    NtSetInformationProcess, NtSuspendProcess, NtSuspendThread, Runtime, PEB_T,
};

pub struct Native {
}

pub fn new() -> Native {
    Native {  }
}

pub unsafe fn last_error<T: Sized + Default>() -> Result<T> {
    let err = GetLastError();
    if err.is_ok() {
        Ok(T::default())
    } else {
        Err(anyhow::anyhow!("{:?}", err.to_hresult().message()))
    }
}

pub fn map_win32_result<T: Sized>(err: windows::core::Result<T>) -> Result<T> {
    err.map_err(|e| anyhow::anyhow!("code: {} message: {}", e.code(), e.message()))
}

impl Runtime for Native {
    fn open_process(&self, pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<HANDLE> {
        let hprocess;
        unsafe {
            if pid == GetCurrentProcessId() {
                hprocess = GetCurrentProcess();
            } else {
                hprocess = OpenProcess(access, false, pid)?;
            }
        }
        Ok(hprocess)
    }

    fn virtual_alloc(
        &self,
        hprocess: HANDLE,
        address: usize,
        size: usize,
        allocation_type: VIRTUAL_ALLOCATION_TYPE,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<usize> {
        unsafe {
            let result =
                VirtualAllocEx(hprocess, Some(address as _), size, allocation_type, protect);
            if result.is_null() {
                last_error()
            } else {
                Ok(result as _)
            }
        }
    }

    fn virtual_free(
        &self,
        hprocess: HANDLE,
        address: usize,
        free_type: VIRTUAL_FREE_TYPE,
    ) -> Result<()> {
        unsafe {
            if TRUE == VirtualFreeEx(hprocess, address as _, 0 as usize, free_type) {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    fn virtual_query(&self, hprocess: HANDLE, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        unsafe {
            if 0 != VirtualQueryEx(
                hprocess,
                Some(address as _),
                &mut info,
                core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) {
                Ok(info)
            } else {
                last_error()
            }
        }
    }

    fn virtual_protect(
        &self,
        hprocess: HANDLE,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        let mut old = PAGE_PROTECTION_FLAGS::default();
        unsafe {
            if TRUE == VirtualProtectEx(hprocess, address as _, size, protect, &mut old) {
                Ok(old)
            } else {
                last_error()
            }
        }
    }

    fn read_process_meory(
        &self,
        hprocess: HANDLE,
        address: usize,
        buffer: &mut [u8],
        size: usize,
    ) -> Result<usize> {
        assert!(buffer.len() >= size);
        let mut bytes: usize = 0;
        unsafe {
            if TRUE
                == ReadProcessMemory(
                    hprocess,
                    address as _,
                    buffer as *mut [u8] as _,
                    size,
                    Some(&mut bytes as _),
                )
                && bytes != 0
            {
                Ok(bytes)
            } else {
                last_error()
            }
        }
    }

    fn write_process_memory(
        &self,
        hprocess: HANDLE,
        address: usize,
        buffer: &[u8],
        size: usize,
    ) -> Result<usize> {
        assert!(buffer.len() >= size);
        let mut bytes: usize = 0;
        unsafe {
            if TRUE
                == WriteProcessMemory(
                    hprocess,
                    address as _,
                    buffer as *const [u8] as _,
                    size,
                    Some(&mut bytes as _),
                )
                && bytes != 0
            {
                Ok(bytes)
            } else {
                last_error()
            }
        }
    }

    fn query_process_info(
        &self,
        hprocess: HANDLE,
        info_class: PROCESSINFOCLASS,
        buffer: &mut [u8],
    ) -> Result<()> {
        let mut length: u32 = 0;
        unsafe {
            let result = NtQueryInformationProcess(
                hprocess,
                info_class,
                buffer as *mut [u8] as _,
                buffer.len() as u32,
                &mut length as _,
            );
            map_win32_result(result)
        }
    }

    fn set_process_info(
        &self,
        hprocess: HANDLE,
        info_class: PROCESSINFOCLASS,
        buffer: &[u8],
    ) -> Result<()> {
        unsafe {
            if NtSetInformationProcess(
                hprocess,
                info_class as _,
                buffer as *const [u8] as _,
                buffer.len() as u32,
            )
            .is_ok()
            {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    fn create_remote_thread(
        &self,
        hprocess: HANDLE,
        start_routine: LPTHREAD_START_ROUTINE,
        args: Option<*const ::core::ffi::c_void>,
        create_flags: THREAD_CREATION_FLAGS,
        access: u32,
    ) -> Result<HANDLE> {
        let arguments = args.unwrap_or(core::ptr::null());
        let mut hthread = HANDLE::default();
        unsafe {
            if NtCreateThreadEx(
                &mut hthread,
                access,
                core::ptr::null(),
                hprocess,
                start_routine,
                arguments,
                create_flags,
                0,
                0x1000,
                0x100000,
                core::ptr::null(),
            )
            .is_ok()
            {
                Ok(hthread)
            } else {
                last_error()
            }
        }
    }

    fn get_thread_context(&self, hthread: HANDLE) -> Result<CONTEXT> {
        let mut ctx = CONTEXT::default();
        unsafe {
            if TRUE == GetThreadContext(hthread, &mut ctx) {
                Ok(ctx)
            } else {
                last_error()
            }
        }
    }

    fn get_thread_context_wow64(&self, hthread: HANDLE) -> Result<WOW64_CONTEXT> {
        let mut ctx = WOW64_CONTEXT::default();
        unsafe {
            if TRUE == Wow64GetThreadContext(hthread, &mut ctx) {
                Ok(ctx)
            } else {
                last_error()
            }
        }
    }

    fn set_thread_context(&self, hthread: HANDLE, ctx: *const CONTEXT) -> Result<()> {
        unsafe {
            if TRUE == SetThreadContext(hthread, ctx) {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    fn set_thread_context_wow64(&self, hthread: HANDLE, ctx: *const WOW64_CONTEXT) -> Result<()> {
        unsafe {
            if TRUE == Wow64SetThreadContext(hthread, ctx) {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    fn get_peb32(&self, hprocess: HANDLE) -> Result<(PEB_T<u32>, usize)> {
        unsafe {
            let mut peb: PEB_T<u32> = core::mem::zeroed();
            let mut ptr = 064;
            self.query_process_info(
                hprocess,
                ProcessWow64Information,
                any_as_u8_slice_mut(&mut ptr),
            )?;
            self.read_process_meory(
                hprocess,
                ptr,
                any_as_u8_slice_mut(&mut peb),
                core::mem::size_of::<PEB_T<u32>>(),
            )?;
            Ok((peb, ptr))
        }
    }

    fn get_peb64(&self, hprocess: HANDLE) -> Result<(PEB_T<u64>, usize)> {
        unsafe {
            let mut peb: PEB_T<u64> = core::mem::zeroed();
            let mut info: PROCESS_BASIC_INFORMATION = core::mem::zeroed();
            self.query_process_info(
                hprocess,
                ProcessBasicInformation,
                any_as_u8_slice_mut(&mut info),
            )?;
            self.read_process_meory(
                hprocess,
                info.PebBaseAddress as usize,
                any_as_u8_slice_mut(&mut peb),
                core::mem::size_of::<PEB_T<u64>>(),
            )?;
            Ok((peb, info.PebBaseAddress as _))
        }
    }

    fn suspend_process(&self, hprocess: HANDLE) -> Result<()> {
        unsafe {
            if NtSuspendProcess(hprocess).is_ok() {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    fn resume_process(&self, hprocess: HANDLE) -> Result<()> {
        unsafe {
            if NtResumeProcess(hprocess).is_ok() {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    fn suspend_thread(&self, hthread: HANDLE) -> Result<u32> {
        let mut resume_counter: u32 = 0;
        unsafe {
            if NtSuspendThread(hthread, &mut resume_counter).is_ok() {
                Ok(resume_counter)
            } else {
                last_error()
            }
        }
    }

    fn resume_thread(&self, hthread: HANDLE) -> Result<u32> {
        let mut resume_counter: u32 = 0;
        unsafe {
            if NtResumeThread(hthread, &mut resume_counter).is_ok() {
                Ok(resume_counter)
            } else {
                last_error()
            }
        }
    }

    fn close_handle(&self, handle: HANDLE) {
        unsafe {
            CloseHandle(handle);
        }
    }
}

#[cfg(test)]
mod test {
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

    use super::*;
    #[test]
    fn test_memory_operation() {
        let hprocess = unsafe { GetCurrentProcess() };
        let native = new(hprocess, false);
        let size = 0x1000;
        let buffer = native
            .virtual_alloc(hprocess, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
            .unwrap();
        let mut data = 0x100131231usize;
        native
            .write_process_memory(
                hprocess,
                buffer,
                any_as_u8_slice_mut(&mut data),
                std::mem::size_of::<usize>(),
            )
            .unwrap();

        let mut read_data = 0usize;
        native
            .read_process_meory(
                hprocess,
                buffer,
                any_as_u8_slice_mut(&mut read_data) as _,
                std::mem::size_of::<usize>(),
            )
            .unwrap();
        assert_eq!(data, read_data);
        native.virtual_free(hprocess, buffer, MEM_RELEASE).unwrap();

        let (peb, _) = native.get_peb64(hprocess).unwrap();
        println!("{}", peb.ImageBaseAddress);
    }

    #[test]
    fn test_peb() {
        let hprocess = unsafe { GetCurrentProcess() };
        let native = new(hprocess, false);
        let (peb, _) = native.get_peb64(hprocess).unwrap();
        assert_ne!(0, peb.ImageBaseAddress);
        let mut pe_header_magic: u16 = 0;
        native
            .read_process_meory(
                hprocess,
                peb.ImageBaseAddress as usize,
                any_as_u8_slice_mut(&mut pe_header_magic),
                2,
            )
            .unwrap();
        // 'MZ'
        assert_eq!(0x5a4d, pe_header_magic);
    }
}
