#![no_std]
#![no_main]

use aya_ebpf::{
    bpf_printk,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use core::panic::PanicInfo;

#[tracepoint]
pub fn hello(ctx: TracePointContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // offset 16: const char *filename (format dosyasından)
    let ptr = unsafe { ctx.read_at::<u64>(16).map_err(|_| 1u32)? } as *const u8;

    let mut buf = [0u8; 32];
    let name = unsafe { bpf_probe_read_user_str_bytes(ptr, &mut buf).map_err(|_| 2u32)? };

    if basename_eq(name, b"whoami") {
        unsafe { bpf_printk!(c"whoami calistirildi, pid=%d", pid) };
    } else if basename_eq(name, b"date") {
        unsafe { bpf_printk!(c"date calistirildi, pid=%d", pid) };
    } else if basename_eq(name, b"ls") {
        unsafe { bpf_printk!(c"ls calistirildi, pid=%d", pid) };
    }
    Ok(0)
}

#[inline(always)]
fn basename_eq<const N: usize>(path: &[u8], expected: &[u8; N]) -> bool {
    if path.len() < N {
        return false;
    }

    let start = path.len() - N;
    if start != 0 && path[start - 1] != b'/' {
        return false;
    }

    let mut index = 0;
    while index < N {
        if path[start + index] != expected[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
