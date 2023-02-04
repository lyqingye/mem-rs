#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi;

use windows::Win32::{
    Foundation::{HANDLE, NTSTATUS},
    System::{
        Threading::{LPTHREAD_START_ROUTINE, PROCESSINFOCLASS, THREAD_CREATION_FLAGS},
        WindowsProgramming::OBJECT_ATTRIBUTES,
    },
};

pub mod native;

#[repr(C)]
pub union PS_ATTRIBUTE_u {
    pub Value: usize,
    pub ValuePtr: *mut core::ffi::c_void,
}

#[repr(C)]
pub struct PS_ATTRIBUTE {
    pub Attribute: usize,
    pub Size: usize,
    pub u: PS_ATTRIBUTE_u,
    pub ReturnLength: *mut usize,
}

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    pub TotalLength: usize,
    pub Attributes: [PS_ATTRIBUTE; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_u<T: Sized + Default + Copy> {
    pub KernelCallbackTable: T,
    pub UserSharedInfoPtr: T,
}

#[repr(C)]
pub struct UNICODE_STRING_T<T: Sized + Default> {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: T,
}

#[repr(C)]
pub struct LIST_ENTRY_T<T: Sized + Default + Copy> {
    pub Flink: T,
    pub Blink: T,
}

#[repr(C)]
pub struct PEB_T<T: Sized + Default + Copy> {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: T,
    pub ImageBaseAddress: T,
    pub Ldr: T,
    pub ProcessParameters: T,
    pub SubSystemData: T,
    pub ProcessHeap: T,
    pub FastPebLock: T,
    pub AtlThunkSListPtr: T,
    pub IFEOKey: T,
    pub CrossProcessFlags: T,
    pub u: PEB_u<T>,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: T,
    pub TlsExpansionCounter: u32,
    pub TlsBitmap: T,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: T,
    pub HotpatchInformation: T,
    pub ReadOnlyStaticServerData: T,
    pub AnsiCodePageData: T,
    pub OemCodePageData: T,
    pub UnicodeCaseTableData: T,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: ffi::c_longlong,
    pub HeapSegmentReserve: T,
    pub HeapSegmentCommit: T,
    pub HeapDeCommitTotalFreeThreshold: T,
    pub HeapDeCommitFreeBlockThreshold: T,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: T,
    pub GdiSharedHandleTable: T,
    pub ProcessStarterHelper: T,
    pub GdiDCAttributeList: T,
    pub LoaderLock: T,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u16,
    pub OSCSDVersion: u16,
    pub OSPlatformId: u32,
    pub ImageSubsystem: u32,
    pub ImageSubsystemMajorVersion: u32,
    pub ImageSubsystemMinorVersion: T,
    pub ActiveProcessAffinityMask: T,
    pub GdiHandleBuffer: [T; 34],
    pub PostProcessInitRoutine: T,
    pub TlsExpansionBitmap: T,
    pub TlsExpansionBitmapBits: [u32; 32],
    pub SessionId: T,
    pub AppCompatFlags: ffi::c_longlong,
    pub AppCompatFlagsUser: ffi::c_longlong,
    pub pShimData: T,
    pub AppCompatInfo: T,
    pub CSDVersion: UNICODE_STRING_T<T>,
    pub ActivationContextData: T,
    pub ProcessAssemblyStorageMap: T,
    pub SystemDefaultActivationContextData: T,
    pub SystemAssemblyStorageMap: T,
    pub MinimumStackCommit: T,
    pub FlsCallback: T,
    pub FlsListHead: LIST_ENTRY_T<T>,
    pub FlsBitmap: T,
    pub FlsBitmapBits: [u32; 4],
    pub FlsHighIndex: u32,
    pub WerRegistrationData: T,
    pub WerShipAssertPtr: T,
    pub pContextData: T,
    pub pImageHeaderHash: T,
    pub TracingFlags: u64,
    pub CsrServerReadOnlySharedMemoryBase: T,
    pub TppWorkerpListLock: T,
    pub TppWorkerpList: LIST_ENTRY_T<T>,
    pub WaitOnAddressHashTable: [T; 128],
    pub TelemetryCoverageHeader: T,
    pub CloudFileFlags: T,
    pub CloudFileDiagFlags: T,
    pub PlaceholderCompatibilityMode: u8,
    pub PlaceholderCompatibilityModeReserved: [u8; 7],
}

extern "C" {
    pub fn NtSetInformationProcess(
        hprocess: HANDLE,
        info_class: PROCESSINFOCLASS,
        buffer: *const ::core::ffi::c_void,
        size: u32,
    ) -> NTSTATUS;

    pub fn NtCreateThreadEx(
        hthread: *mut HANDLE,
        access: u32,
        attributes: *const OBJECT_ATTRIBUTES,
        hprocess: HANDLE,
        start_routine: LPTHREAD_START_ROUTINE,
        argument: *const ::core::ffi::c_void,
        create_flags: THREAD_CREATION_FLAGS,
        zerobits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        arttribute_list: *const PS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((p as *const T) as *const u8, std::mem::size_of::<T>()) }
}

fn any_as_u8_slice_mut<T: Sized>(p: &mut T) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut((p as *mut T) as *mut u8, std::mem::size_of::<T>()) }
}
