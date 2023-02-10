#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
use anyhow::Result;
use std::ffi;

use windows::Win32::{
    Foundation::{HANDLE, NTSTATUS},
    System::{
        Diagnostics::Debug::{CONTEXT, WOW64_CONTEXT},
        Memory::{
            MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
            VIRTUAL_FREE_TYPE,
        },
        Threading::{
            LPTHREAD_START_ROUTINE, PROCESSINFOCLASS, PROCESS_ACCESS_RIGHTS, THREAD_CREATION_FLAGS,
        },
        WindowsProgramming::{OBJECT_ATTRIBUTES, SYSTEM_INFORMATION_CLASS},
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
#[derive(Default)]
pub struct UNICODE_STRING_T<T: Sized + Default> {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: T,
}

#[repr(C)]
#[derive(Default)]
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

#[repr(C)]
#[derive(Default)]
pub struct PEB_LDR_DATA_T<T: Sized + Default + Copy> {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: T,
    pub InLoadOrderModuleList: LIST_ENTRY_T<T>,
    pub InMemoryOrderModuleList: LIST_ENTRY_T<T>,
    pub InInitializationOrderModuleList: LIST_ENTRY_T<T>,
    pub EntryInProgress: T,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: T,
    pub EntryPoint: T,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING_T<T>,
    pub BaseDllName: UNICODE_STRING_T<T>,
    pub Flags: u32,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY_T<T>,
    pub TimeDateStamp: u32,
    pub EntryPointActivationContext: T,
    pub PatchInformation: T,
}

#[derive(Default)]
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY_BASE_T<T: Sized + Default + Copy> {
    pub InLoadOrderLinks: LIST_ENTRY_T<T>,
    pub InMemoryOrderLinks: LIST_ENTRY_T<T>,
    pub InInitializationOrderLinks: LIST_ENTRY_T<T>,
    pub DllBase: T,
    pub EntryPoint: T,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING_T<T>,
    pub BaseDllName: UNICODE_STRING_T<T>,
    pub Flags: u32,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY_T<T>,
    pub TimeDateStamp: u32,
    pub EntryPointActivationContext: T,
    pub PatchInformation: T,
}

/// Type of barrier
#[derive(Debug)]
pub enum BarrierType {
    WOW32_32 = 0, // Both processes are WoW64
    WOW64_64,     // Both processes are x64
    WOW32_64,     // Managing x64 process from WoW64 process
    WOW64_32,     // Managing WOW64 process from x64 process
}
impl Default for BarrierType {
    fn default() -> Self {
        Self::WOW32_32
    }
}

#[derive(Debug, Default)]
pub struct Wow64Barrier {
    pub barrier: BarrierType,
    pub source_wow64: bool,
    pub target_wow64: bool,
    pub x86_os: bool,
    pub mismatch: bool,
}

pub struct ProcessInfo {
    pub pid: u32,
    pub image_name: String,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Default)]
pub struct ThreadInfo {
    pub tid: HANDLE,
    pub address: usize,
    pub is_main_thread: usize,
}

#[derive(Debug, Default, Clone)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size_of_image: usize,
    pub full_path: String,
    pub name: String,
    pub ldr_ptr: usize,
}

pub const MemoryBasicInformation: i32 = 0;
pub const MemorySectionName: i32 = 2;

#[repr(C)]
pub struct SectionName<T: Sized + Default + Copy> {
    file_name: UNICODE_STRING_T<T>,
    buffer: [u8; 512],
}

impl<T: Sized + Default + Copy> Default for SectionName<T> {
    fn default() -> Self {
        Self {
            file_name: UNICODE_STRING_T::<T>::default(),
            buffer: [0u8; 512],
        }
    }
}

#[link(name = "ntdll")]
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
        attribute_list: *const PS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;

    pub fn NtSuspendProcess(hprocess: HANDLE) -> NTSTATUS;

    pub fn NtResumeProcess(hprocess: HANDLE) -> NTSTATUS;

    pub fn NtSuspendThread(hthread: HANDLE, previous_suspend_count: *const u32) -> NTSTATUS;

    pub fn NtResumeThread(hthread: HANDLE, previous_suspend_count: *const u32) -> NTSTATUS;

    pub fn NtQueryVirtualMemory(
        hprocess: HANDLE,
        address: *const ffi::c_void,
        info_class: i32,
        buffer: *mut ffi::c_void,
        size: usize,
        return_length: *const usize,
    ) -> NTSTATUS;
}

#[inline]
pub fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((p as *const T) as *const u8, std::mem::size_of::<T>()) }
}

#[inline]
pub fn any_as_u8_slice_mut<T: Sized>(p: &mut T) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut((p as *mut T) as *mut u8, std::mem::size_of::<T>()) }
}

#[inline]
pub unsafe fn u8_slice_as_wstring(buffer: &[u8], length: usize) -> String {
    String::from_utf16_lossy(std::slice::from_raw_parts(
        buffer.as_ptr() as *const u16,
        length / 2,
    ))
}

pub trait Runtime {
    fn current_process(&self) -> HANDLE;

    fn enum_process(&self, callback: &mut dyn FnMut(ProcessInfo) -> bool) -> Result<()>;

    fn open_process(&self, pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<HANDLE>;

    fn virtual_alloc(
        &self,
        hprocess: HANDLE,
        address: usize,
        size: usize,
        allocation_type: VIRTUAL_ALLOCATION_TYPE,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<usize>;

    fn virtual_free(
        &self,
        hprocess: HANDLE,
        address: usize,
        free_type: VIRTUAL_FREE_TYPE,
    ) -> Result<()>;

    fn virtual_query(&self, hprocess: HANDLE, address: usize) -> Result<MEMORY_BASIC_INFORMATION>;

    fn virtual_protect(
        &self,
        hprocess: HANDLE,
        address: usize,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS>;

    fn read_process_memory(
        &self,
        hprocess: HANDLE,
        address: usize,
        buffer: &mut [u8],
        size: usize,
    ) -> Result<usize>;

    fn write_process_memory(
        &self,
        hprocess: HANDLE,
        address: usize,
        buffer: &[u8],
        size: usize,
    ) -> Result<usize>;

    fn query_process_info(
        &self,
        hprocess: HANDLE,
        info_class: PROCESSINFOCLASS,
        buffer: &mut [u8],
    ) -> Result<()>;

    fn set_process_info(
        &self,
        hprocess: HANDLE,
        info_class: PROCESSINFOCLASS,
        buffer: &[u8],
    ) -> Result<()>;

    fn query_system_info(&self, info_class: SYSTEM_INFORMATION_CLASS) -> Result<Vec<u8>>;

    fn create_remote_thread(
        &self,
        hprocess: HANDLE,
        start_routine: LPTHREAD_START_ROUTINE,
        args: Option<*const ffi::c_void>,
        create_flags: THREAD_CREATION_FLAGS,
        access: u32,
    ) -> Result<HANDLE>;

    fn get_thread_context(&self, hthread: HANDLE) -> Result<CONTEXT>;

    fn get_thread_context_wow64(&self, hthread: HANDLE) -> Result<WOW64_CONTEXT>;

    fn set_thread_context(&self, hthread: HANDLE, ctx: *const CONTEXT) -> Result<()>;

    fn set_thread_context_wow64(&self, hthread: HANDLE, ctx: *const WOW64_CONTEXT) -> Result<()>;

    fn get_peb32(&self, hprocess: HANDLE) -> Result<(PEB_T<u32>, usize)>;

    fn get_peb64(&self, hprocess: HANDLE) -> Result<(PEB_T<u64>, usize)>;

    fn suspend_process(&self, hprocess: HANDLE) -> Result<()>;

    fn resume_process(&self, hprocess: HANDLE) -> Result<()>;

    fn suspend_thread(&self, hthread: HANDLE) -> Result<u32>;

    fn resume_thread(&self, hthread: HANDLE) -> Result<u32>;

    fn close_handle(&self, handle: HANDLE);

    fn enum_modules32(
        &self,
        hprocess: HANDLE,
        callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()>;

    fn enum_modules64(
        &self,
        hprocess: HANDLE,
        callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()>;

    fn enum_pe_headers(
        &self,
        hprocess: HANDLE,
        start_address: usize,
        end_address: usize,
        callback: &mut dyn FnMut(ModuleInfo) -> bool,
    ) -> Result<()>;
}
