use super::process::Process;

pub struct ProcessModule<'a> {
    ps: &'a Process,
}


impl<'a> ProcessModule<'a> {
    pub fn new(ps: &Process) -> ProcessModule {
        ProcessModule { ps }
    }
}
