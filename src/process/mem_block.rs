use super::memory::ProcessMemory;
use anyhow::Result;

pub struct MemBlock<'a> {
    pm: &'a ProcessMemory<'a>,
    ptr: *const u8,
    size: usize,
    owner: bool,
}

impl<'a> MemBlock<'a> {
    pub fn new(pm: &'a ProcessMemory<'a>, ptr: *const u8, size: usize, owner: bool) -> MemBlock<'a> {
        debug_assert!(!ptr.is_null());
        MemBlock { pm, ptr, size, owner}
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

pub struct CopyOnWriteMemBlock<'a> {
    pm: &'a ProcessMemory<'a>,
    ptr: *const u8,
    page_size: usize,
    cached: Vec<u8>,
    dirty: Vec<u8>,
    page_cache: Vec<Option<Box<Vec<u8>>>>,
    max_pages: usize,
}

impl<'a> CopyOnWriteMemBlock<'a> {
    pub fn new(pm: &'a ProcessMemory<'a>, ptr: *const u8, page_size: usize, max_pages: usize) -> CopyOnWriteMemBlock<'a> {
        debug_assert!(!ptr.is_null());
        let mut block = CopyOnWriteMemBlock {
            pm,
            ptr,
            page_size,
            max_pages,
            cached: Vec::with_capacity(max_pages / 8),
            dirty: Vec::with_capacity(max_pages / 8),
            page_cache: Vec::with_capacity(max_pages),
        };

        // allocate
        block.cached.resize(max_pages / 8,0);
        block.dirty.resize(max_pages / 8,0);
        block.page_cache.resize(max_pages,None);
        block
    }

    fn access_page(&mut self, offset: usize, write: bool) -> Result<()> {
        if !Self::read_bit(&self.cached,self.page_size,offset) {
            self.page_fault(offset)?;
        }
        if write {
            let _ = Self::set_bit(&mut self.dirty,self.page_size,offset,true);
        }
        Ok(())
    }

    pub fn commit() -> Result<()> {
        Ok(())
    }

    fn page_fault(&mut self, offset: usize) -> Result<() > {

        Ok(())
    }

    fn self_page_cache(&mut self, offset: usize) {
        let page = self.page_cache.get_mut(offset / self.max_pages).unwrap();
        if page.is_none() {
            let mut new_page = Vec::with_capacity(self.page_size);
            new_page.resize(self.page_size,0);
            *page = Some(Box::new(new_page));
        }else {
        }
    }

    fn read_bit(bitmap: &[u8], page_size: usize, offset: usize) -> bool {
        if bitmap[offset / (page_size << 3)] & (1 << ((offset % (page_size << 3)) / page_size - 1)) == 1 {
            true
        }else {
            false
        }
    }

    fn set_bit(bitmap: &mut [u8], page_size: usize, offset: usize, value: bool) -> bool {
        let world_index = offset / (page_size << 3);
        let world = bitmap[world_index];
        let bit_index = (offset % (page_size << 3)) / page_size - 1;
        let old;
        if world & (1 << bit_index) == 1 {
            old = true
        }else {
            old = false
        }
        if value {
            bitmap[world_index] = world | 1 << bit_index;
        }else {
            bitmap[world_index] = world & (!(1 << bit_index));
        }
        old
    }
}

