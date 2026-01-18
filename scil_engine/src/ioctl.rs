use std::ffi::c_void;

use shared::{IOCTL_DRAIN_LOG_SNAPSHOT, IOCTL_SNAPSHOT_QUE_LOG, telemetry::TelemetryEntry};
use windows::Win32::{Foundation::HANDLE, System::IO::DeviceIoControl};

/// A public 'class' (lol) for
pub struct Ioctl;

impl Ioctl {
    pub fn ioctl_drain_syscall_log(device: HANDLE) -> Option<Vec<TelemetryEntry>> {
        drain_driver_messages(device, None, None)
    }
}

/// Makes an IOCTL to drain the driver messages. If no buffer is taken by this function, then
/// the function calls to get the count.
fn drain_driver_messages(
    device: HANDLE,
    buf: Option<Vec<TelemetryEntry>>,
    num_elements: Option<usize>,
) -> Option<Vec<TelemetryEntry>> {
    //
    // If the function is called with None, then we need to get the size of the buffer and have the
    // driver create a snapshot of the data.
    // This branch will then recursively call the current function to retrieve the data from the driver.
    //
    let Some(mut buf) = buf else {
        let mut count_items = 0usize;

        if let Err(e) = unsafe {
            DeviceIoControl(
                device,
                IOCTL_SNAPSHOT_QUE_LOG,
                Some(&mut count_items as *mut _ as *const c_void),
                size_of_val(&count_items) as u32,
                None,
                0,
                None,
                None,
            )
        } {
            println!(
                "[-] Failed to make IOCTL for IOCTL_SNAPSHOT_QUE_LOG where buffer was not yet initialised. {e}"
            );
            return None;
        };

        // Nothing queued
        if count_items == 0 {
            return None;
        }

        let buf = Vec::<TelemetryEntry>::with_capacity(count_items);

        drain_driver_messages(device, Some(buf), Some(count_items));
        return None;
    };

    let Some(num_elements) = num_elements else {
        println!("[-] num_elements was empty.");
        return None;
    };

    //
    // Calculate the actual size of the buffer and make the IOCTL again, this time draining the snapshot
    //
    let sz = size_of::<TelemetryEntry>() * num_elements;

    if let Err(e) = unsafe {
        DeviceIoControl(
            device,
            IOCTL_DRAIN_LOG_SNAPSHOT,
            Some(buf.as_mut_ptr() as *mut _ as *const c_void),
            sz as u32,
            None,
            0,
            None,
            None,
        )
    } {
        println!(
            "[-] Failed to make IOCTL for IOCTL_DRAIN_LOG_SNAPSHOT where buffer was initialised with len: {}. {e}",
            buf.len()
        );
        return None;
    };

    Some(buf)
}
