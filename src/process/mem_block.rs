use super::memory::ProcessMemory;
use anyhow::Result;

pub struct MemBlock<'a> {
    pm: &'a ProcessMemory<'a>,
    ptr: *const u8,
    size: usize,
    owner: bool,
}

impl<'a> MemBlock<'a> {
    pub fn new(
        pm: &'a ProcessMemory<'a>,
        ptr: *const u8,
        size: usize,
        owner: bool,
    ) -> MemBlock<'a> {
        debug_assert!(!ptr.is_null());
        MemBlock {
            pm,
            ptr,
            size,
            owner,
        }
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

    pub fn write_copy<T>(&self, offset: usize, buffer: T) -> Result<()>
    where
        T: Sized + Copy + Default,
    {
        self.write_t(offset, &buffer)
    }

    pub fn realloc(&mut self, size: usize) -> Result<()> {
        let info = self.pm.query(self.ptr as _)?;
        self.ptr = self.pm.alloc(self.ptr as _, size, info.AllocationProtect)? as _;
        self.size = size;
        Ok(())
    }
}

impl Drop for MemBlock<'_> {
    fn drop(&mut self) {
        if self.owner && !self.ptr.is_null() {
            let _ = self.pm.free(self.ptr as _);
        }
    }
}
