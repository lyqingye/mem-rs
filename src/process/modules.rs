use super::process::Process;

pub struct ProcessModule<'a> {
    ps: &'a Process,
}

pub fn new<'a>(ps: &'a Process) -> ProcessModule<'a> {
    ProcessModule { ps }
}

impl<'a> ProcessModule<'a> {}
