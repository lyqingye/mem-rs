use crate::runtime::{any_as_u8_slice, any_as_u8_slice_mut};

use super::{mem_block::MemBlock, process::Process};
use anyhow::Result;
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_RELEASE, MEM_RESET, PAGE_PROTECTION_FLAGS,
};

pub struct ProcessMemory<'a> {
    ps: &'a Process,
}

pub fn new<'a>(ps: &'a Process) -> ProcessMemory<'a> {
    ProcessMemory { ps }
}

impl<'a> ProcessMemory<'a> {
    pub fn alloc(
        &self,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<usize> {
        self.ps.runtime().virtual_alloc(
            self.ps.handle(),
            address,
            size,
            MEM_COMMIT | MEM_RESET,
            protect,
        )
    }

    pub fn alloc_block(
        &'a self,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<MemBlock<'a>> {
        let address = self.alloc(address, size, protect)?;
        Ok(MemBlock::new(self, address as _, size))
    }

    pub fn free(&self, address: usize) -> Result<()> {
        self.ps
            .runtime()
            .virtual_free(self.ps.handle(), address, MEM_RELEASE)
    }

    pub fn query(&self, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
        self.ps.runtime().virtual_query(self.ps.handle(), address)
    }

    pub fn protect(
        &self,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        self.ps
            .runtime()
            .virtual_protect(self.ps.handle(), address, size, protect)
    }

    pub fn read(&self, address: usize, size: usize, buffer: &mut [u8]) -> Result<usize> {
        self.ps
            .runtime()
            .read_process_meory(self.ps.handle(), address, buffer, size)
    }

    pub fn read_t_copy<T>(&self, address: usize) -> Result<T>
    where
        T: Sized + Copy + Default,
    {
        let mut buffer = T::default();
        let _ = self.ps.runtime().read_process_meory(
            self.ps.handle(),
            address,
            any_as_u8_slice_mut(&mut buffer),
            core::mem::size_of::<T>(),
        )?;
        Ok(buffer)
    }

    pub fn read_t<T>(&self, address: usize, buffer: &mut T) -> Result<usize>
    where
        T: Sized + Copy + Default,
    {
        self.ps.runtime().read_process_meory(
            self.ps.handle(),
            address,
            any_as_u8_slice_mut(buffer),
            core::mem::size_of::<T>(),
        )
    }

    pub fn write(&self, address: usize, size: usize, buffer: &[u8]) -> Result<usize> {
        self.ps
            .runtime()
            .write_process_memory(self.ps.handle(), address, buffer, size)
    }

    pub fn write_t<T>(&self, address: usize, buffer: &T) -> Result<usize>
    where
        T: Sized + Copy + Default,
    {
        self.ps.runtime().write_process_memory(
            self.ps.handle(),
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
