use anyhow::Result;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, BOOL, FALSE, HANDLE, NTSTATUS, TRUE},
    System::{
        Diagnostics::Debug::{
            GetThreadContext, ReadProcessMemory, SetThreadContext, Wow64GetThreadContext,
            Wow64SetThreadContext, WriteProcessMemory, CONTEXT, WOW64_CONTEXT,
        },
        Memory::{
            VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx,
            MEMORY_BASIC_INFORMATION, MEMORY_BASIC_INFORMATION64, PAGE_PROTECTION_FLAGS,
            VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE,
        },
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{
            GetCurrentProcess, IsWow64Process, NtQueryInformationProcess, ProcessBasicInformation,
            ProcessWow64Information, LPTHREAD_START_ROUTINE, PROCESSINFOCLASS,
            PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION_CLASS, THREAD_CREATION_FLAGS,
        },
    },
};

use super::{any_as_u8_slice_mut, NtCreateThreadEx, NtSetInformationProcess, PEB_T};

/// Type of barrier
#[derive(Debug)]
pub enum BarrierType {
    WOW32_32 = 0, // Both processes are WoW64
    WOW64_64,     // Both processes are x64
    WOW32_64,     // Managing x64 process from WoW64 process
    WOW64_32,     // Managing WOW64 process from x64 process
}
impl Default for BarrierType {
    fn default() -> Self {
        Self::WOW32_32
    }
}

#[derive(Debug, Default)]
pub struct Wow64Barrier {
    pub barrier: BarrierType,
    pub source_wow64: bool,
    pub target_wow64: bool,
    pub x86_os: bool,
    pub mismatch: bool,
}

pub struct Native {
    hprocess: HANDLE,
    wow_barrier: Wow64Barrier,
    page_size: usize,
    x86os: bool,
}

pub fn new(hprocess: HANDLE, x86os: bool) -> Native {
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut info);
    }

    let mut native = Native {
        hprocess,
        wow_barrier: Wow64Barrier::default(),
        page_size: info.dwPageSize as usize,
        x86os,
    };
    if x86os {
        native.wow_barrier.source_wow64 = true;
        native.wow_barrier.target_wow64 = true;
        native.wow_barrier.barrier = BarrierType::WOW32_32;
    } else {
        unsafe {
            let mut wow_src: BOOL = FALSE;
            let mut wow_tgt: BOOL = FALSE;
            IsWow64Process(GetCurrentProcess(), &mut wow_src);
            IsWow64Process(hprocess, &mut wow_tgt);

            match (wow_src, wow_tgt) {
                (TRUE, FALSE) => {
                    native.wow_barrier.barrier = BarrierType::WOW32_32;
                }
                (FALSE, FALSE) => {
                    native.wow_barrier.barrier = BarrierType::WOW64_64;
                }
                (TRUE, _) => {
                    native.wow_barrier.barrier = BarrierType::WOW32_64;
                    native.wow_barrier.mismatch = true;
                }
                _ => {
                    native.wow_barrier.barrier = BarrierType::WOW64_32;
                    native.wow_barrier.mismatch = true;
                }
            }
        }
    }
    native
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

impl Native {
    pub fn virtual_alloc_ext(
        &self,
        address: usize,
        size: usize,
        allocation_type: VIRTUAL_ALLOCATION_TYPE,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<usize> {
        unsafe {
            let result = VirtualAllocEx(
                self.hprocess,
                Some(address as _),
                size,
                allocation_type,
                protect,
            );
            if result.is_null() {
                last_error()
            } else {
                Ok(result as _)
            }
        }
    }

    pub fn virtual_free_ext(
        &self,
        address: usize,
        free_type: VIRTUAL_FREE_TYPE,
    ) -> Result<()> {
        unsafe {
            if TRUE == VirtualFreeEx(self.hprocess, address as _, 0 as usize, free_type) {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    pub fn virtual_query_ext(&self, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        unsafe {
            if 0 != VirtualQueryEx(
                self.hprocess,
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

    pub fn virtual_protect_ext(
        &self,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        let mut old = PAGE_PROTECTION_FLAGS::default();
        unsafe {
            if TRUE == VirtualProtectEx(self.hprocess, address as _, size, protect, &mut old) {
                Ok(old)
            } else {
                last_error()
            }
        }
    }

    pub fn read_process_meory(
        &self,
        address: usize,
        buffer: &mut [u8],
        size: usize,
    ) -> Result<usize> {
        assert!(buffer.len() >= size);
        let mut bytes: usize = 0;
        unsafe {
            if TRUE
                == ReadProcessMemory(
                    self.hprocess,
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

    pub fn write_process_memory(
        &self,
        address: usize,
        buffer: &[u8],
        size: usize,
    ) -> Result<usize> {
        assert!(buffer.len() >= size);
        let mut bytes: usize = 0;
        unsafe {
            if TRUE
                == WriteProcessMemory(
                    self.hprocess,
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

    pub fn query_process_info<T: Sized + Default>(
        &self,
        info_class: PROCESSINFOCLASS,
        buffer: &mut T,
    ) -> Result<()> {
        let mut length: u32 = 0;
        unsafe {
            let result = NtQueryInformationProcess(
                self.hprocess,
                info_class,
                buffer as *mut T as _,
                core::mem::size_of::<T>() as u32,
                &mut length as _,
            );
            map_win32_result(result)
        }
    }

    pub fn set_process_info<T: Sized + Default>(
        &self,
        info_class: PROCESSINFOCLASS,
        buffer: &T,
    ) -> Result<()> {
        unsafe {
            if NtSetInformationProcess(
                self.hprocess,
                info_class as _,
                buffer as *const T as _,
                core::mem::size_of::<T>() as u32,
            )
            .is_ok()
            {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    pub fn create_remote_thread(
        &self,
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
                self.hprocess,
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

    pub fn get_thread_context(hthread: HANDLE) -> Result<CONTEXT> {
        let mut ctx = CONTEXT::default();
        unsafe {
            if TRUE == GetThreadContext(hthread, &mut ctx) {
                Ok(ctx)
            } else {
                last_error()
            }
        }
    }

    pub fn get_thread_context_wow64(&self, hthread: HANDLE) -> Result<WOW64_CONTEXT> {
        let mut ctx = WOW64_CONTEXT::default();
        if self.wow_barrier.target_wow64 == false {
            Err(anyhow::anyhow!(
                "target process is x64. WOW64 CONTEXT is not available"
            ))
        } else {
            unsafe {
                if TRUE == Wow64GetThreadContext(hthread, &mut ctx) {
                    Ok(ctx)
                } else {
                    last_error()
                }
            }
        }
    }

    pub fn set_thread_context(&self, hthread: HANDLE, ctx: *const CONTEXT) -> Result<()> {
        unsafe {
            if TRUE == SetThreadContext(hthread, ctx) {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    pub fn set_thread_context_wow64(
        &self,
        hthread: HANDLE,
        ctx: *const WOW64_CONTEXT,
    ) -> Result<()> {
        unsafe {
            if TRUE == Wow64SetThreadContext(hthread, ctx) {
                Ok(())
            } else {
                last_error()
            }
        }
    }

    pub fn get_peb32(&self) -> Result<(PEB_T<u32>, usize)> {
        if self.wow_barrier.target_wow64 == false {
            Err(anyhow::anyhow!(
                "Target process is x64. PEB32 is not available"
            ))
        } else {
            unsafe {
                let mut peb: PEB_T<u32> = core::mem::zeroed();
                let mut ptr = 064;
                self.query_process_info::<usize>(ProcessWow64Information, &mut ptr)?;
                self.read_process_meory(
                    ptr,
                    any_as_u8_slice_mut(&mut peb),
                    core::mem::size_of::<PEB_T<u32>>(),
                )?;
                Ok((peb, ptr))
            }
        }
    }

    pub fn get_peb64(&self) -> Result<(PEB_T<u64>, usize)> {
        unsafe {
            let mut peb: PEB_T<u64> = core::mem::zeroed();
            let mut info: PROCESS_BASIC_INFORMATION = core::mem::zeroed();
            self.query_process_info::<PROCESS_BASIC_INFORMATION>(
                ProcessBasicInformation,
                &mut info,
            )?;
            self.read_process_meory(
                info.PebBaseAddress as usize,
                any_as_u8_slice_mut(&mut peb),
                core::mem::size_of::<PEB_T<u64>>(),
            )?;
            Ok((peb, info.PebBaseAddress as _))
        }
    }
}

#[cfg(test)]
mod test {
    use windows::Win32::System::Memory::{PAGE_READWRITE, MEM_RELEASE, MEM_RESERVE, MEM_COMMIT};

    use super::*;
    #[test]
    fn test_memory_operation() {
        let hprocess = unsafe {GetCurrentProcess()};
        let native = new(hprocess, false);
        let size = 0x1000;
        let buffer = native.virtual_alloc_ext(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE).unwrap();
        let mut data = 0x100131231usize;
        native.write_process_memory(buffer, any_as_u8_slice_mut(&mut data), std::mem::size_of::<usize>()).unwrap();

        let mut read_data = 0usize;
        native.read_process_meory(buffer, any_as_u8_slice_mut(&mut read_data), std::mem::size_of::<usize>()).unwrap();
        assert_eq!(data,read_data);
        native.virtual_free_ext(buffer,MEM_RELEASE).unwrap();

        let (peb,_) = native.get_peb64().unwrap();
        println!("{}",peb.ImageBaseAddress);
    }

    #[test]
    fn test_peb() {
        let hprocess = unsafe {GetCurrentProcess()};
        let native = new(hprocess, false);
        let (peb,_) = native.get_peb64().unwrap();
        assert_ne!(0,peb.ImageBaseAddress);
        let mut pe_header_magic: u16 = 0;
        native.read_process_meory(peb.ImageBaseAddress as usize, any_as_u8_slice_mut(&mut pe_header_magic), 2).unwrap();
        // 'MZ'
        assert_eq!(0x5a4d,pe_header_magic);
    }
}