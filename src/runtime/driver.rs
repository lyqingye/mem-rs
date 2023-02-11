use core::ffi;

use super::{ModuleInfo, ProcessInfo, Runtime, PEB_T};
use anyhow::Result;
use driver_loader_rs::{
    controller::{self, DriverController},
    loader::DrvLdr,
};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::{CONTEXT, WOW64_CONTEXT},
        Memory::{
            MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
            VIRTUAL_FREE_TYPE,
        },
        Threading::{
            GetCurrentProcess, GetProcessId, LPTHREAD_START_ROUTINE, PROCESSINFOCLASS,
            PROCESS_ACCESS_RIGHTS, THREAD_CREATION_FLAGS,
        },
        WindowsProgramming::SYSTEM_INFORMATION_CLASS,
    },
};

pub struct Driver {
    ldr: DrvLdr,
    ctl: DriverController,
}

impl Driver {
    pub fn new(driver_path: &str) -> Result<Self> {
        let ldr =
            driver_loader_rs::loader::DrvLdr::new("lyqingye", "lyqingye", driver_path, false)?;
        let ctl = controller::new("\\??\\WindowsKernelResearch".to_owned());
        Ok(Self { ldr, ctl })
    }
}

impl Runtime for Driver {
    fn init(&mut self) -> Result<()> {
        self.ldr.install_service()?;
        self.ldr.start_service_and_wait()?;
        self.ctl.conn()?;
        self.ctl.init_global_context()?;
        Ok(())
    }

    fn current_process(&self) -> HANDLE {
        unsafe { GetCurrentProcess() }
    }

    fn enum_process(&self, _callback: &mut dyn FnMut(ProcessInfo) -> bool) -> Result<()> {
        unimplemented!()
    }

    fn open_process(&self, _pid: u32, _access: PROCESS_ACCESS_RIGHTS) -> Result<HANDLE> {
        unimplemented!()
    }

    fn virtual_alloc(
        &self,
        _hprocess: HANDLE,
        _address: usize,
        _size: usize,
        _allocation_type: VIRTUAL_ALLOCATION_TYPE,
        _protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<usize> {
        unimplemented!()
    }

    fn virtual_free(
        &self,
        _hprocess: HANDLE,
        _address: usize,
        _free_type: VIRTUAL_FREE_TYPE,
    ) -> Result<()> {
        unimplemented!()
    }

    fn virtual_query(
        &self,
        _hprocess: HANDLE,
        _address: usize,
    ) -> Result<MEMORY_BASIC_INFORMATION> {
        unimplemented!()
    }

    fn virtual_protect(
        &self,
        _hprocess: HANDLE,
        _address: usize,
        _size: usize,
        _protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        unimplemented!()
    }

    fn read_process_memory(
        &self,
        hprocess: HANDLE,
        address: usize,
        buffer: &mut [u8],
        size: usize,
    ) -> Result<usize> {
        let pid = unsafe { GetProcessId(hprocess) };
        let result = self.ctl.read_proc_mem(HANDLE(pid as _), address, size)?;
        if result.len() == size {
            buffer.copy_from_slice(result.as_slice());
        }
        Ok(result.len())
    }

    fn write_process_memory(
        &self,
        hprocess: HANDLE,
        address: usize,
        buffer: &[u8],
        size: usize,
    ) -> Result<usize> {
        assert_eq!(buffer.len(), size);
        let pid = unsafe { GetProcessId(hprocess) };
        let write_bytes = self.ctl.write_proc_mem(HANDLE(pid as _), buffer, address)?;
        Ok(write_bytes)
    }

    fn physical_alloc(&self, physical_address: usize, size: usize) -> Result<usize> {
        let allocate_address = self.ctl.alloc_physcinal_memory(physical_address, size)?;
        Ok(allocate_address)
    }

    fn physical_free(&self, physical_address: usize) -> Result<()> {
        self.ctl.free_physcinal_memory(physical_address)?;
        Ok(())
    }

    fn physical_write(&self, physical_address: usize, buffer: &[u8], size: usize) -> Result<usize> {
        assert_eq!(buffer.len(), size);
        let bytes_write = self.ctl.write_physical_memory(buffer, physical_address)?;
        Ok(bytes_write)
    }

    fn physical_read(
        &self,
        physical_address: usize,
        buffer: &mut [u8],
        size: usize,
    ) -> Result<usize> {
        let result = self.ctl.read_physical_memory(physical_address, size)?;
        if result.len() == size {
            buffer.copy_from_slice(result.as_slice());
        }
        Ok(result.len())
    }

    fn query_process_info(
        &self,
        _hprocess: HANDLE,
        _info_class: PROCESSINFOCLASS,
        _buffer: &mut [u8],
    ) -> Result<()> {
        unimplemented!()
    }

    fn set_process_info(
        &self,
        _hprocess: HANDLE,
        _info_class: PROCESSINFOCLASS,
        _buffer: &[u8],
    ) -> Result<()> {
        unimplemented!()
    }

    fn query_system_info(&self, _info_class: SYSTEM_INFORMATION_CLASS) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn create_remote_thread(
        &self,
        _hprocess: HANDLE,
        _start_routine: LPTHREAD_START_ROUTINE,
        _args: Option<*const ffi::c_void>,
        _create_flags: THREAD_CREATION_FLAGS,
        _access: u32,
    ) -> Result<HANDLE> {
        unimplemented!()
    }

    fn get_thread_context(&self, _hthread: HANDLE) -> Result<CONTEXT> {
        unimplemented!()
    }

    fn get_thread_context_wow64(&self, _hthread: HANDLE) -> Result<WOW64_CONTEXT> {
        unimplemented!()
    }

    fn set_thread_context(&self, _hthread: HANDLE, _ctx: *const CONTEXT) -> Result<()> {
        unimplemented!()
    }

    fn set_thread_context_wow64(&self, _hthread: HANDLE, _ctx: *const WOW64_CONTEXT) -> Result<()> {
        unimplemented!()
    }

    fn get_peb32(&self, _hprocess: HANDLE) -> Result<(PEB_T<u32>, usize)> {
        unimplemented!()
    }

    fn get_peb64(&self, _hprocess: HANDLE) -> Result<(PEB_T<u64>, usize)> {
        unimplemented!()
    }

    fn suspend_process(&self, _hprocess: HANDLE) -> Result<()> {
        unimplemented!()
    }

    fn resume_process(&self, _hprocess: HANDLE) -> Result<()> {
        unimplemented!()
    }

    fn suspend_thread(&self, _hthread: HANDLE) -> Result<u32> {
        unimplemented!()
    }

    fn resume_thread(&self, _hthread: HANDLE) -> Result<u32> {
        unimplemented!()
    }

    fn close_handle(&self, _handle: HANDLE) {
        unimplemented!()
    }

    fn enum_modules32(
        &self,
        _hprocess: HANDLE,
        _callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()> {
        unimplemented!()
    }

    fn enum_modules64(
        &self,
        _hprocess: HANDLE,
        _callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()> {
        unimplemented!()
    }

    fn enum_pe_headers(
        &self,
        _hprocess: HANDLE,
        _start_address: usize,
        _end_address: usize,
        _callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()> {
        unimplemented!()
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // uninstall driver
    }
}
