use super::process::Process;
use crate::runtime::ModuleInfo;
use anyhow::Result;

pub struct ProcessModule<'a> {
    ps: &'a Process,
}

impl<'a> ProcessModule<'a> {
    pub fn new(ps: &Process) -> ProcessModule {
        ProcessModule { ps }
    }

    pub fn get_module(&self, name: String) -> Result<Option<ModuleInfo>> {
        let mut module = None;
        self.ps
            .runtime()
            .enum_modules64(self.ps.handle(), &mut |module_info| {
                if module_info.name == name {
                    module = Some(module_info);
                    true
                } else {
                    false
                }
            })?;
        Ok(module)
    }

    pub fn get_main_module(&self) -> Result<Option<ModuleInfo>> {
        let (peb, _) = self.ps.runtime().get_peb64(self.ps.handle())?;
        let mut module = None;
        self.ps
            .runtime()
            .enum_modules64(self.ps.handle(), &mut |module_info| {
                if module_info.base_address == peb.ImageBaseAddress as usize {
                    module = Some(module_info);
                    true
                } else {
                    false
                }
            })?;
        Ok(module)
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut modules = Vec::new();
        self.ps
            .runtime()
            .enum_modules64(self.ps.handle(), &mut |module_info| {
                modules.push(module_info);
                false
            })?;
        Ok(modules)
    }
}
