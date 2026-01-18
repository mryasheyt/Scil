use windows::Win32::Foundation::HANDLE;

pub fn ioctl_drain_syscall_log(device: HANDLE) -> Vec<>,