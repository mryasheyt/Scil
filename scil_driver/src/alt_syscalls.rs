//! For enabling / disabling alt syscalls

use core::{arch::asm, ffi::c_void, ptr::null_mut};

use alloc::{boxed::Box, vec::Vec};
use shared::telemetry::{Args, NtFunction, TelemetryEntry};
use wdk::println;
use wdk_sys::{
    _KTRAP_FRAME,
    _MODE::KernelMode,
    DISPATCHER_HEADER, DRIVER_OBJECT, HANDLE, KTRAP_FRAME, OBJ_KERNEL_HANDLE, PETHREAD, PKTHREAD,
    PROCESS_ALL_ACCESS, PsThreadType, THREAD_ALL_ACCESS,
    ntddk::{
        IoCsqRemoveNextIrp, IoGetCurrentProcess, IoThreadToProcess, ObReferenceObjectByHandle,
        ObfDereferenceObject, ZwClose,
    },
};

use crate::{
    ffi::{ZwGetNextProcess, ZwGetNextThread},
    scil_telemetry::{TelemetryCache, TelemetryEntryOrphan},
    utils::{
        DriverError, get_module_base_and_sz, get_process_name_and_pid,
        scan_module_for_byte_pattern, thread_to_process_name,
    },
};

pub const SSN_NT_OPEN_PROCESS: u32 = 0x26;
pub const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
pub const SSN_NT_CREATE_THREAD_EX: u32 = 0x00c9;
pub const SSN_NT_WRITE_VM: u32 = 0x003a;

const NT_OPEN_FILE: u32 = 0x0033;
const NT_CREATE_SECTION: u32 = 0x004a;
const NT_CREATE_SECTION_EX: u32 = 0x00c6;
const NT_DEVICE_IO_CONTROL_FILE: u32 = 0x0007;
const NT_CREATE_FILE_SSN: u32 = 0x0055;
const NT_TRACE_EVENT_SSN: u32 = 0x005e;

/// A local definition of a KTHREAD, seeing as though the WDK doesn't export one for us. If this changes
/// between kernel builds, it will cause problems :E
#[repr(C)]
struct KThreadLocalDef {
    junk: [u8; 0x90],
    k_trap_ptr: *mut KTRAP_FRAME,
}

const SYSCALL_ALLOW: i32 = 1;

/// The callback routine which we control to run when a system call is dispatched via the alt syscall technique.
///
/// # Args:
/// - `p_nt_function`: A function pointer to the real Nt* dispatch function (e.g. NtOpenProcess)
/// - `ssn`: The System Service Number of the syscall
/// - `args_base`: The base address of the args passed into the original syscall rcx, rdx, r8 and r9
/// - `p3_home`: The address of `P3Home` of the _KTRAP_FRAME
///
/// # Safety
/// This function is **NOT** compatible with the `PspSyscallProviderServiceDispatch` branch of alt syscalls, it
/// **WILL** result in a bug check in that instance. This can only be used with
/// `PspSyscallProviderServiceDispatchGeneric`.
pub unsafe extern "system" fn syscall_handler(
    _p_nt_function: c_void,
    ssn: u32,
    _args_base: *const c_void,
    _p3_home: *const c_void,
) -> i32 {
    let process_details = get_process_name_and_pid();
    let proc_name = process_details.0.to_lowercase();
    let pid = process_details.1;

    // We only want to target scil_test.exe as a POC
    if !proc_name.contains("scil_test") {
        return SYSCALL_ALLOW;
    }

    let ktrap_frame = match extract_trap() {
        Some(p) => unsafe { *p },
        None => {
            println!("[-] [scil] Could not get trap for syscall intercept.");
            return SYSCALL_ALLOW;
        }
    };

    match ssn {
        SSN_NT_OPEN_PROCESS
        | SSN_NT_ALLOCATE_VIRTUAL_MEMORY
        | SSN_NT_WRITE_VM
        | SSN_NT_CREATE_THREAD_EX => {
            // TODO from here, grab the list of pending PIRPs and use them to send syscall events to the user app

            // let pirp = unsafe { IoCsqRemoveNextIrp() };

            // println!("[scil] [i] SSN: {:#X}", ssn);
            // if let Err(e) = TelemetryCache::push(TelemetryEntry::new(
            //     NtFunction::NtOpenProcess,
            //     Args {
            //         rcx: Some(ktrap_frame.Rcx as usize),
            //         rdx: Some(ktrap_frame.Rdx as usize),
            //         r8: Some(ktrap_frame.R8 as usize),
            //         r9: Some(ktrap_frame.R9 as usize),
            //         ..Default::default()
            //     },
            //     pid,
            // )) {
            //     println!("[scil] [-] Failed to push syscall object. {e}");
            // };
        }
        _ => (),
    };

    SYSCALL_ALLOW
}

#[inline(always)]
fn extract_trap() -> Option<*const _KTRAP_FRAME> {
    let mut k_thread: *const c_void = null_mut();
    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) k_thread,
        );
    }

    if k_thread.is_null() {
        println!("[-] [scil] No KTHREAD discovered.");
        return None;
    }

    let p_ktrap = unsafe { &*(k_thread as *const KThreadLocalDef) }.k_trap_ptr;

    Some(p_ktrap)
}
