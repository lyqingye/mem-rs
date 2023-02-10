use crate::runtime::u8_slice_as_wstring;
use anyhow::Result;

use std::mem::{size_of, transmute_copy};

use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, TRUE},
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
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, NtQueryInformationProcess, OpenProcess,
            ProcessBasicInformation, ProcessWow64Information, LPTHREAD_START_ROUTINE,
            PROCESSINFOCLASS, PROCESS_ACCESS_RIGHTS, PROCESS_BASIC_INFORMATION,
            THREAD_CREATION_FLAGS,
        },
        WindowsProgramming::{
            NtQuerySystemInformation, SystemProcessInformation, SYSTEM_INFORMATION_CLASS,
            SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use super::{
    any_as_u8_slice_mut, ModuleInfo, NtCreateThreadEx, NtResumeProcess, NtResumeThread,
    NtSetInformationProcess, NtSuspendProcess, NtSuspendThread, ProcessInfo, Runtime,
    LDR_DATA_TABLE_ENTRY_BASE_T, PEB_LDR_DATA_T, PEB_T,
};

pub struct SystemProcessInfoIter {
    ptr: *const u8,
}

impl SystemProcessInfoIter {
    pub fn new(buffer: *const u8) -> SystemProcessInfoIter {
        SystemProcessInfoIter { ptr: buffer }
    }
}

impl Iterator for SystemProcessInfoIter {
    type Item = *const SYSTEM_PROCESS_INFORMATION;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ptr.is_null() {
            None
        } else {
            unsafe {
                let result: Self::Item = core::mem::transmute(self.ptr);
                let next = (*result).NextEntryOffset as usize;
                if next == 0 {
                    self.ptr = core::ptr::null();
                } else {
                    self.ptr = self.ptr.add(next)
                }
                Some(result)
            }
        }
    }
}

pub struct Native {}

pub fn new() -> Native {
    Native {}
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
    fn current_process(&self) -> HANDLE {
        unsafe { GetCurrentProcess() }
    }

    fn enum_process(&self, callback: &mut dyn FnMut(ProcessInfo) -> bool) -> Result<()> {
        let result = self.query_system_info(SystemProcessInformation)?;
        for info_ptr in SystemProcessInfoIter::new(result.as_ptr()) {
            assert!(!info_ptr.is_null());
            let info = unsafe { info_ptr.as_ref().unwrap() };
            let image_name;
            if info.ImageName.Buffer.is_null() {
                image_name = "".to_owned();
            } else {
                image_name = unsafe { info.ImageName.Buffer.to_string()? };
            }
            if (*callback)(ProcessInfo {
                pid: info.UniqueProcessId.0 as _,
                image_name,
                threads: Vec::new(),
            }) {
                break;
            }
        }

        Ok(())
    }

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

    fn read_process_memory(
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
            let result = NtSetInformationProcess(
                hprocess,
                info_class as _,
                buffer as *const [u8] as _,
                buffer.len() as u32,
            )
            .ok();
            map_win32_result(result)
        }
    }

    fn query_system_info(&self, info_class: SYSTEM_INFORMATION_CLASS) -> Result<Vec<u8>> {
        let temp_buf_size: usize = 0x8;
        let mut temp_buf = vec![0u8; temp_buf_size];
        let mut buffer_size: u32 = 0;
        unsafe {
            if NtQuerySystemInformation(
                info_class,
                temp_buf.as_mut_ptr() as _,
                temp_buf_size as u32,
                &mut buffer_size,
            )
            .is_err()
            {
                let mut buffer = Vec::with_capacity(buffer_size as usize);
                buffer.resize(buffer_size as usize, 0);
                let result = NtQuerySystemInformation(
                    info_class,
                    buffer.as_mut_ptr() as _,
                    buffer_size,
                    &mut buffer_size,
                );
                map_win32_result(result)?;
                Ok(buffer)
            } else {
                Ok(temp_buf)
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
            let result = NtCreateThreadEx(
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
            .ok();
            map_win32_result(result)?;
            Ok(hthread)
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
            self.read_process_memory(
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
            self.read_process_memory(
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
            let result = NtSuspendProcess(hprocess).ok();
            map_win32_result(result)
        }
    }

    fn resume_process(&self, hprocess: HANDLE) -> Result<()> {
        unsafe {
            let result = NtResumeProcess(hprocess).ok();
            map_win32_result(result)
        }
    }

    fn suspend_thread(&self, hthread: HANDLE) -> Result<u32> {
        let mut resume_counter: u32 = 0;
        unsafe {
            let result = NtSuspendThread(hthread, &mut resume_counter).ok();
            map_win32_result(result)?;
            Ok(resume_counter)
        }
    }

    fn resume_thread(&self, hthread: HANDLE) -> Result<u32> {
        let mut resume_counter: u32 = 0;
        unsafe {
            let result = NtResumeThread(hthread, &mut resume_counter).ok();
            map_win32_result(result)?;
            Ok(resume_counter)
        }
    }

    fn close_handle(&self, handle: HANDLE) {
        unsafe {
            CloseHandle(handle);
        }
    }

    fn enum_modules32(
        &self,
        hprocess: HANDLE,
        callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()> {
        enum_module_t::<u32>(self, hprocess, callback)
    }

    fn enum_modules64(
        &self,
        hprocess: HANDLE,
        callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()> {
        enum_module_t::<u64>(self, hprocess, callback)
    }
}

fn enum_module_t<T: Copy + Default + Sized>(
    native: &Native,
    hprocess: HANDLE,
    callback: &mut dyn FnMut(ModuleInfo) -> bool,
) -> Result<()> {
    assert!(size_of::<T>() <= size_of::<usize>());
    let (peb, _) = native.get_peb64(hprocess)?;
    let mut ldr = PEB_LDR_DATA_T::<T>::default();

    // read ldr data
    let _ = native.read_process_memory(
        hprocess,
        peb.Ldr as _,
        any_as_u8_slice_mut(&mut ldr),
        core::mem::size_of::<PEB_LDR_DATA_T<T>>(),
    )?;

    // calc offset of InLoadOrderModuleList field of LDR
    let field_offset =
        std::ptr::addr_of!(ldr.InLoadOrderModuleList) as usize - std::ptr::addr_of!(ldr) as usize;

    let mut head = unsafe { transmute_copy(&ldr.InLoadOrderModuleList.Flink) };
    loop {
        if peb.Ldr as usize + field_offset == head {
            break;
        }
        let mut entry = LDR_DATA_TABLE_ENTRY_BASE_T::<T>::default();
        let mut path_buffer = vec![0u8; 512];

        // read entry base info
        let _ = native.read_process_memory(
            hprocess,
            head,
            any_as_u8_slice_mut(&mut entry),
            core::mem::size_of::<LDR_DATA_TABLE_ENTRY_BASE_T<T>>(),
        );

        // read path buffer
        let _ = native.read_process_memory(
            hprocess,
            unsafe { transmute_copy(&entry.FullDllName.Buffer) },
            path_buffer.as_mut(),
            entry.FullDllName.Length as usize,
        );

        let path = unsafe {
            u8_slice_as_wstring(path_buffer.as_slice(), entry.FullDllName.Length as usize)
        };

        let file_name = std::path::PathBuf::from(path.clone())
            .file_name()
            .unwrap_or("unknown".as_ref())
            .to_os_string()
            .to_string_lossy()
            .to_string();

        // callback
        if callback(ModuleInfo {
            base_address: unsafe { transmute_copy(&entry.DllBase) },
            size_of_image: entry.SizeOfImage as _,
            full_path: path,
            name: file_name,
            ldr_ptr: head,
        }) {
            break;
        }

        // read next entry
        if native
            .read_process_memory(
                hprocess,
                head,
                any_as_u8_slice_mut(&mut head),
                core::mem::size_of::<T>(),
            )
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

    use super::*;
    #[test]
    fn test_memory_operation() {
        let hprocess = unsafe { GetCurrentProcess() };
        let native = new();
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
            .read_process_memory(
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
        let native = new();
        let (peb, _) = native.get_peb64(hprocess).unwrap();
        assert_ne!(0, peb.ImageBaseAddress);
        let mut pe_header_magic: u16 = 0;
        native
            .read_process_memory(
                hprocess,
                peb.ImageBaseAddress as usize,
                any_as_u8_slice_mut(&mut pe_header_magic),
                2,
            )
            .unwrap();
        // 'MZ'
        assert_eq!(0x5a4d, pe_header_magic);
    }

    #[test]
    fn test_enum_process() {
        let native = new();
        native
            .enum_process(&mut |info| -> bool {
                println!("{:?} {}", info.pid, info.image_name);
                return false;
            })
            .unwrap();
    }

    #[test]
    fn test_enum_modules() {
        let native = new();
        let hprocess = native.current_process();
        native
            .enum_modules64(hprocess, &mut |module| {
                println!("{:?}", module);
                false
            })
            .unwrap();
    }
}
