use anyhow::Result;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_ACCESS_RIGHTS},
    },
};

use crate::subsystem::{native, SubSystem};

pub struct ProcessCore {
    hprocess: HANDLE,
    subsystem: Box<dyn SubSystem>,
}

pub fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<ProcessCore> {
    let hprocess;
    unsafe {
        if pid == GetCurrentProcessId() {
            hprocess = GetCurrentProcess();
        } else {
            hprocess = OpenProcess(access, false, pid)?;
        }
    }

    #[cfg(target_arch = "x86_64")]
    let subsystem = native::new(hprocess, false);

    Ok(ProcessCore {
        hprocess,
        subsystem: Box::new(subsystem),
    })
}

impl ProcessCore {
    pub fn native(&self) -> &dyn SubSystem {
        self.subsystem.as_ref()
    }

    pub fn handle(&self) -> HANDLE {
        self.hprocess
    }
}

impl Drop for ProcessCore {
    fn drop(&mut self) {
        if !self.hprocess.is_invalid() {
            unsafe {
                CloseHandle(self.hprocess);
            }
        }
    }
}
