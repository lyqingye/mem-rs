use anyhow::Result;
use windows::Win32::{
    Foundation::{BOOL, FALSE, HANDLE, TRUE},
    System::{
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{GetCurrentProcess, GetProcessId, IsWow64Process, PROCESS_ACCESS_RIGHTS},
    },
};

use crate::runtime::{
    native::{self},
    BarrierType, Runtime, Wow64Barrier,
};

use super::{memory::ProcessMemory, modules::ProcessModule};

pub struct Process {
    wow_barrier: Wow64Barrier,
    page_size: usize,
    x86os: bool,
    pid: u32,
    handle: HANDLE,
    runtime: Box<dyn Runtime>,
}

impl Process {
    pub fn current_process() -> Result<Process> {
        let runtime = native::new();
        Self::process_from_handle(runtime.current_process(), Some(Box::new(runtime)))
    }

    pub fn process_from_name(name: String, access: PROCESS_ACCESS_RIGHTS) -> Result<Process> {
        let runtime = native::new();
        let mut process_info = None;
        runtime.enum_process(&mut |info| -> bool {
            if info.image_name == name {
                process_info = Some(info);
                true
            } else {
                false
            }
        })?;

        if let Some(info) = process_info {
            Self::process_from_pid(info.pid, access, Some(Box::new(runtime)))
        } else {
            Err(anyhow::anyhow!("process not found! {:?}", name))
        }
    }

    pub fn process_from_pid(
        pid: u32,
        access: PROCESS_ACCESS_RIGHTS,
        runtime_opt: Option<Box<dyn Runtime>>,
    ) -> Result<Process> {
        let runtime = runtime_opt.unwrap_or(Box::new(native::new()));
        let hprocess = runtime.open_process(pid, access)?;
        Self::process_from_handle(hprocess, Some(runtime))
    }

    pub fn process_from_handle(
        hprocess: HANDLE,
        runtime_opt: Option<Box<dyn Runtime>>,
    ) -> Result<Process> {
        let runtime = runtime_opt.unwrap_or(Box::new(native::new()));

        let pid = unsafe { GetProcessId(hprocess) };
        let mut info = SYSTEM_INFO::default();
        unsafe {
            GetNativeSystemInfo(&mut info);
        }

        let mut wow_barrier = Wow64Barrier::default();

        // TODO Get os arch
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

        Ok(Process {
            wow_barrier,
            page_size: info.dwPageSize as usize,
            x86os,
            pid,
            handle: hprocess,
            runtime,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn wow_barrier(&self) -> &Wow64Barrier {
        &self.wow_barrier
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn is_x86os(&self) -> bool {
        self.x86os
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

    pub fn memory(&self) -> ProcessMemory {
        ProcessMemory::new(self)
    }

    pub fn modules(&self) -> ProcessModule {
        ProcessModule::new(self)
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
