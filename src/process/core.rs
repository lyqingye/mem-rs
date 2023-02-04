use anyhow::Result;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_ACCESS_RIGHTS,
    },
};

#[derive(Debug)]
pub struct ProcessCore {
    hprocess: HANDLE,
}

impl ProcessCore {
    pub fn open(&mut self, pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<()> {
        unsafe {
            if pid == GetCurrentProcessId() {
                self.hprocess = GetCurrentProcess();
            } else {
                self.hprocess = OpenProcess(access, false, pid)?;
            }
            Ok(())
        }
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
