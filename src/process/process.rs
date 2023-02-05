use anyhow::Result;
use windows::Win32::{Foundation::{HANDLE, BOOL, FALSE, TRUE}, System::{SystemInformation::{SYSTEM_INFO, GetNativeSystemInfo}, Threading::{GetCurrentProcess, IsWow64Process, PROCESS_ACCESS_RIGHTS, GetProcessId}}};

use crate::runtime::{Runtime, native::{Native, self}, Wow64Barrier, BarrierType};

use super::{memory::{self, ProcessMemory}, modules::{ProcessModule, self}};

pub struct Process {
    wow_barrier: Wow64Barrier,
    page_size: usize,
    x86os: bool,
    pid: u32,
    handle: HANDLE,
    runtime: Box<dyn Runtime>,
}

pub fn process_from_pid(pid: u32,access: PROCESS_ACCESS_RIGHTS) -> Result<Process> {
    let runtime = native::new();
    let hprocess = runtime.open_process(pid, access)?;
    process_from_handle(hprocess, Some(Box::new(runtime)))
}

pub fn process_from_handle(hprocess: HANDLE, runtime_opt: Option<Box<dyn Runtime>>) -> Result<Process> {
    let runtime = runtime_opt.unwrap_or(Box::new(native::new()));

    let pid = unsafe{ GetProcessId(hprocess)};
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut info);
    }

    let mut wow_barrier = Wow64Barrier::default();
    let x86os = false;

    if x86os {
        wow_barrier.source_wow64 = true;
        wow_barrier.target_wow64 = true;
        wow_barrier.barrier = BarrierType::WOW32_32;
    } else {
        unsafe {
            let mut wow_src: BOOL = FALSE;
            let mut wow_tgt: BOOL = FALSE;
            IsWow64Process(GetCurrentProcess(), &mut wow_src);
            IsWow64Process(hprocess, &mut wow_tgt);

            match (wow_src, wow_tgt) {
                (TRUE, FALSE) => {
                    wow_barrier.barrier = BarrierType::WOW32_32;
                }
                (FALSE, FALSE) => {
                    wow_barrier.barrier = BarrierType::WOW64_64;
                }
                (TRUE, _) => {
                    wow_barrier.barrier = BarrierType::WOW32_64;
                    wow_barrier.mismatch = true;
                }
                _ => {
                    wow_barrier.barrier = BarrierType::WOW64_32;
                    wow_barrier.mismatch = true;
                }
            }
        }
    }

    Ok(Process { wow_barrier, page_size: info.dwPageSize as usize, x86os, pid, handle: hprocess, runtime: runtime })
}


impl Process {

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn suspend(&self) -> Result<()> {
        self.runtime.suspend_process(self.handle)
    }

    pub fn resume(&self) -> Result<()> {
        self.runtime.resume_process(self.handle)
    }

    pub fn suspend_thread(&self, hthread: HANDLE) -> Result<()> {
        let _ = self.runtime.suspend_thread(hthread)?;
        Ok(())
    }

    pub fn resume_thread(&self, hthread: HANDLE) -> Result<()> {
        let _ = self.runtime().resume_thread(hthread)?;
        Ok(())
    }

    pub fn runtime(&self) -> &dyn Runtime {
        self.runtime.as_ref()
    }

    pub fn memory<'a>(&'a self) -> ProcessMemory<'a> {
        memory::new(self)
    }

    pub fn modules<'a>(&'a self) -> ProcessModule<'a> {
        modules::new(self)
    }
}


impl Drop for Process {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            self.runtime.close_handle(self.handle)
        }
    }
}

#[cfg(test)]
mod test {}