use super::{memory::ProcessMemory, process::Process};
use anyhow::Result;

pub struct MemBlock<'a> {
    pm: &'a ProcessMemory<'a>,
    ptr: *const u8,
    size: usize,
}

impl<'a> MemBlock<'a> {
    pub fn new(pm: &'a ProcessMemory<'a>, ptr: *const u8, size: usize) -> MemBlock<'a> {
        debug_assert!(!ptr.is_null());
        MemBlock { pm, ptr, size }
    }

    pub fn read(&self, offset: usize, buffer: &mut [u8], size: usize) -> Result<()> {
        let _ = self.pm.read(self.ptr as usize + offset, size, buffer)?;
        Ok(())
    }

    pub fn read_t<T>(&self, offset: usize, buffer: &mut T) -> Result<()>
    where
        T: Sized + Copy + Default,
    {
        let _ = self.pm.read_t(self.ptr as usize + offset, buffer)?;
        Ok(())
    }

    pub fn read_copy<T>(&self, offset: usize) -> Result<T>
    where
        T: Sized + Copy + Default,
    {
        self.pm.read_t_copy(self.ptr as usize + offset)
    }

    pub fn write(&self, offset: usize, buffer: &[u8]) -> Result<()> {
        let _ = self
            .pm
            .write(self.ptr as usize + offset, buffer.len(), buffer);
        Ok(())
    }

    pub fn write_t<T>(&self, offset: usize, buffer: &T) -> Result<()>
    where
        T: Sized + Copy + Default,
    {
        let _ = self.pm.write_t(self.ptr as usize + offset, buffer)?;
        Ok(())
    }

    pub fn realloc(&mut self, size: usize) -> Result<()> {
        let info = self.pm.query(self.ptr as _)?;
        self.ptr = self.pm.alloc(self.ptr as _, size, info.AllocationProtect)? as _;
        Ok(())
    }
}

impl Drop for MemBlock<'_> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let _ = self.pm.free(self.ptr as _);
        }
    }
}
