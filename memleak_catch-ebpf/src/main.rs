#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, uretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AllocInfo {
    pub size: usize,
    pub func_type: u8, // 0 = malloc, 1 = calloc, 2 = free, 3 = realloc, 4 = emalloc, 5 = efree
    pub stack_id: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AllocEvent {
    pub address: usize,
    pub size: usize,
    pub func_type: u8, // 0 = malloc, 1 = calloc, 2 = free, 3 = realloc, 4 = emalloc, 5 = efree
    pub stack_id: i64,
    pub pid_tid: u32,
    pub status: u8, // 0 = freed, 1 = leak
    pub _padding: [u8; 2], // for alignment
}

#[map(name = "ALLOC_MAP")]
static mut ALLOC_MAP: HashMap<usize, AllocInfo> = HashMap::<usize, AllocInfo>::with_max_entries(10240, 0);

#[map(name = "TMP_SIZE")]
static mut TMP_SIZE: HashMap<u64, usize> = HashMap::<u64, usize>::with_max_entries(10240, 0);

#[map(name = "EVENTS")]
static mut EVENTS: aya_ebpf::maps::RingBuf = aya_ebpf::maps::RingBuf::with_byte_size(4096, 0);

#[map(name = "STACK_TRACES")]
static mut STACK_TRACES: aya_ebpf::maps::StackTrace = aya_ebpf::maps::StackTrace::with_max_entries(1024, 0);

const BPF_F_USER_STACK: u64 = 256;

#[uprobe]
pub fn malloc_entry(ctx: ProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    if let Some(size) = ctx.arg::<usize>(0) {
        unsafe {
            let _ = TMP_SIZE.insert(&pid_tid, &size, 0);
        }
    }
    0
}

#[uretprobe]
pub fn malloc_exit(ctx: RetProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let stack_id = unsafe {
        aya_ebpf::helpers::bpf_get_stackid(
            ctx.regs as *mut _ as *mut core::ffi::c_void,
            &mut STACK_TRACES as *mut _ as *mut core::ffi::c_void,
            BPF_F_USER_STACK,
        )
    };
    if let Some(address) = ctx.ret::<usize>() {
        unsafe {
            if let Some(size) = TMP_SIZE.get(&pid_tid).copied() {
                let info = AllocInfo { size, func_type: 0, stack_id };
                let _ = ALLOC_MAP.insert(&address, &info, 0);
                let _ = TMP_SIZE.remove(&pid_tid);

                let event = AllocEvent { address, size, func_type: 0, stack_id, pid_tid: pid_tid as u32, status: 1, _padding: [0; 2] };
                let _ = EVENTS.output(&event, 0);
            }
        }
    }
    0
}

#[uprobe]
pub fn calloc_entry(ctx: ProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    if let (Some(nmemb), Some(size)) = (ctx.arg::<usize>(0), ctx.arg::<usize>(1)) {
        let total_size = nmemb * size;
        unsafe {
            let _ = TMP_SIZE.insert(&pid_tid, &total_size, 0);
        }
    }
    0
}

#[uretprobe]
pub fn calloc_exit(ctx: RetProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let stack_id = unsafe {
        aya_ebpf::helpers::bpf_get_stackid(
            ctx.regs as *mut _ as *mut core::ffi::c_void,
            &mut STACK_TRACES as *mut _ as *mut core::ffi::c_void,
            BPF_F_USER_STACK,
        )
    };
    if let Some(address) = ctx.ret::<usize>() {
        unsafe {
            if let Some(size) = TMP_SIZE.get(&pid_tid).copied() {
                let info = AllocInfo { size, func_type: 1, stack_id };
                let _ = ALLOC_MAP.insert(&address, &info, 0);
                let _ = TMP_SIZE.remove(&pid_tid);

                let event = AllocEvent { address, size, func_type: 1, stack_id, pid_tid: pid_tid as u32, status: 1, _padding: [0; 2] };
                let _ = EVENTS.output(&event, 0);
            }
        }
    }
    0
}

#[uprobe]
pub fn realloc_entry(ctx: ProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    if let (Some(ptr), Some(size)) = (ctx.arg::<usize>(0), ctx.arg::<usize>(1)) {
        unsafe {
            if let Some(info_ptr) = ALLOC_MAP.get_ptr(&ptr) {
                let mut info = *info_ptr;
                info.size = size;
                let _ = ALLOC_MAP.insert(&ptr, &info, 0);
                let _ = TMP_SIZE.insert(&pid_tid, &ptr, 0);
            }
        }
    }
    0
}

#[uretprobe]
pub fn realloc_exit(ctx: RetProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let stack_id = unsafe {
        aya_ebpf::helpers::bpf_get_stackid(
            ctx.regs as *mut _ as *mut core::ffi::c_void,
            &mut STACK_TRACES as *mut _ as *mut core::ffi::c_void,
            BPF_F_USER_STACK,
        )
    };
    if let Some(address) = ctx.ret::<usize>() {
        unsafe {
            // Get the old address from TMP_SIZE
            if let Some(old_address_ptr) = TMP_SIZE.get(&pid_tid) {
                let old_address = *old_address_ptr;
                // Retrieve info from ALLOC_MAP using old address
                if let Some(info_ptr) = ALLOC_MAP.get_ptr(&old_address) {
                    let info = *info_ptr;

                    let freed_event = AllocEvent {
                        address: old_address,
                        size: info.size,
                        func_type: 2,
                        stack_id,
                        pid_tid: pid_tid as u32,
                        status: 0, // freed
                        _padding: [0; 2],
                    };
                    let _ = EVENTS.output(&freed_event, 0);

                    // Remove old entry
                    let _ = ALLOC_MAP.remove(&old_address);
                    // Insert info with new address
                    let _ = ALLOC_MAP.insert(&address, &info, 0);
                    // Emit AllocEvent
                    let event = AllocEvent { address, size: info.size, func_type: 3, stack_id, pid_tid: pid_tid as u32, status: 0, _padding: [0; 2] };
                    let _ = EVENTS.output(&event, 0);
                }
                // Remove TMP_SIZE entry
                let _ = TMP_SIZE.remove(&pid_tid);
            }
        }
    }
    0
}

#[uprobe]
pub fn free_entry(ctx: ProbeContext) -> u32 {
    let pid_tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let stack_id = unsafe {
        aya_ebpf::helpers::bpf_get_stackid(
            ctx.regs as *mut _ as *mut core::ffi::c_void,
            &mut STACK_TRACES as *mut _ as *mut core::ffi::c_void,
            BPF_F_USER_STACK,
        )
    };
    if let Some(address) = ctx.arg::<usize>(0) {
        unsafe {
            if let Some(info_ptr) = ALLOC_MAP.get_ptr(&address) {
                let info = *info_ptr;
                let _ = ALLOC_MAP.remove(&address);

                let event = AllocEvent { address, size: info.size, func_type: 2, stack_id, pid_tid: pid_tid as u32, status: 0, _padding: [0; 2] };
                let _ = EVENTS.output(&event, 0);
                let _ = TMP_SIZE.remove(&pid_tid);
            }
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";