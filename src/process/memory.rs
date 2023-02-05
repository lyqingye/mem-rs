use crate::subsystem::{any_as_u8_slice, any_as_u8_slice_mut};

use super::core::ProcessCore;
use anyhow::Result;
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_RELEASE, MEM_RESET, PAGE_PROTECTION_FLAGS,
};

pub struct ProcessMemory<'a> {
    core: &'a ProcessCore,
}

pub fn new<'a>(core: &'a ProcessCore) -> ProcessMemory<'a> {
    ProcessMemory { core }
}

impl<'a> ProcessMemory<'a> {
    pub fn allocate(
        &self,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<usize> {
        self.core
            .native()
            .virtual_alloc_ext(address, size, MEM_COMMIT | MEM_RESET, protect)
    }

    pub fn free(&self, address: usize) -> Result<()> {
        self.core.native().virtual_free_ext(address, MEM_RELEASE)
    }

    pub fn query(&self, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
        self.core.native().virtual_query_ext(address)
    }

    pub fn protect(
        &self,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        self.core
            .native()
            .virtual_protect_ext(address, size, protect)
    }

    pub fn read(&self, address: usize, size: usize, buffer: &mut [u8]) -> Result<usize> {
        self.core.native().read_process_meory(address, buffer, size)
    }

    pub fn read_t_copy<T>(&self, address: usize) -> Result<T>
    where
        T: Sized + Copy + Default,
    {
        let mut buffer = T::default();
        let _ = self.core.native().read_process_meory(
            address,
            any_as_u8_slice_mut(&mut buffer),
            core::mem::size_of::<T>(),
        )?;
        Ok(buffer)
    }

    pub fn read_t<T>(&self, address: usize, buffer: &mut T) -> Result<usize>
    where
        T: Sized,
    {
        self.core.native().read_process_meory(
            address,
            any_as_u8_slice_mut(buffer),
            core::mem::size_of::<T>(),
        )
    }

    pub fn write(&self, address: usize, size: usize, buffer: &[u8]) -> Result<usize> {
        self.core
            .native()
            .write_process_memory(address, buffer, size)
    }

    pub fn write_t<T>(&self, address: usize, buffer: &T) -> Result<usize>
    where
        T: Sized,
    {
        self.core.native().write_process_memory(
            address,
            any_as_u8_slice(buffer),
            core::mem::size_of::<T>(),
        )
    }
}

#[cfg(test)]
mod test {
    #[test]
    pub fn test_read_write_process_memory() {}
}
