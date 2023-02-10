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
}
