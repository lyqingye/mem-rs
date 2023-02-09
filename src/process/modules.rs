use super::process::Process;
use crate::runtime::ModuleInfo;

pub struct ProcessModule<'a> {
    ps: &'a Process,
}

impl<'a> ProcessModule<'a> {
    pub fn new(ps: &Process) -> ProcessModule {
        ProcessModule { ps }
    }

    pub fn get_module(&self, _name: String) -> Option<ModuleInfo> {
        //
        None
    }
}
