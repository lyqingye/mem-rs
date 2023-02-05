use anyhow::Result;
use windows::Win32::{Foundation::HANDLE, System::Threading::PROCESS_ACCESS_RIGHTS};

use super::{
    core::ProcessCore,
    memory::{self, ProcessMemory},
};

pub struct Process {
    core: Option<ProcessCore>,
    pid: u32,
}

impl Process {
    pub fn attach(&mut self, access: PROCESS_ACCESS_RIGHTS) -> Result<()> {
        if self.core.is_none() {
            self.core = Some(super::core::open(self.pid, access)?)
        }
        Ok(())
    }

    pub fn suspend(&self) -> Result<()> {
        self.core().native().suspend_process()
    }

    pub fn resume(&self) -> Result<()> {
        self.core().native().resume_process()
    }

    pub fn suspend_thread(&self, hthread: HANDLE) -> Result<()> {
        let _ = self.core().native().suspend_thread(hthread)?;
        Ok(())
    }

    pub fn resume_thread(&self, hthread: HANDLE) -> Result<()> {
        let _ = self.core().native().resume_thread(hthread)?;
        Ok(())
    }

    pub fn core(&self) -> &ProcessCore {
        if self.core.is_none() {
            panic!("process not attch")
        }
        self.core.as_ref().unwrap()
    }

    pub fn memory<'a>(&'a self) -> ProcessMemory<'a> {
        memory::new(self.core())
    }
}

#[cfg(test)]
mod test {}
