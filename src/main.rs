#![feature(pointer_byte_offsets)]

use crate::{process::process::Process, runtime::any_as_u8_slice};
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

use crate::runtime::{any_as_u8_slice_mut, driver::Driver, Runtime};

pub mod process;
pub mod runtime;

fn main() {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format_module_path(true)
        .filter_module("goblin", log::LevelFilter::Error)
        .init();

    let mut runtime = Driver::new("c:\\Users\\ex\\Desktop\\Driver.sys").unwrap();
    runtime.init().unwrap();
    let mut buffer = 0u16;
    let process = Process::process_from_name("notepad.exe".to_owned(), PROCESS_ALL_ACCESS).unwrap();
    let (peb, _) = process.runtime().get_peb64(process.handle()).unwrap();
    let mut bytes_read = runtime
        .read_process_memory(
            process.handle(),
            peb.ImageBaseAddress as _,
            any_as_u8_slice_mut(&mut buffer),
            2,
        )
        .unwrap();
    log::info!("{} {:x}", bytes_read, buffer);

    let physical_address = runtime.physical_alloc( process.page_size()).unwrap();
    log::info!("physical address: {:x}",physical_address);

    bytes_read = runtime.physical_write(physical_address,any_as_u8_slice(&buffer), 2).unwrap();
    assert_eq!(bytes_read,2);
    let mut buffer2 = 0u16;
    let bytes_write = runtime.physical_read(physical_address, any_as_u8_slice_mut(&mut buffer2), 2).unwrap();
    assert_eq!(bytes_write,2);
    runtime.physical_free(physical_address).unwrap();
}
