use core::arch::global_asm;

use crate::fnv1a_hash;

use super::resolve::function::*;

global_asm!(
    "
.global do_syscall

.section .text

do_syscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    mov eax, ecx
    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov  rdx,  [rsp + 0x28]
    mov  r8,   [rsp + 0x30]
    mov  r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:

    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx

"
);
unsafe extern "C" {
    pub fn do_syscall(ssn: u32, syscall_addr: *const u8, n_args: u32, ...) -> i32;
}

#[derive(Default)]
pub struct Syscall {
    function_ptr: *const u8,
}

impl Syscall {
    pub fn new(function_hash: u32) -> Self {
        unsafe {
            let func =
                resolve_function(resolve_module(fnv1a_hash!("ntdll")).unwrap(), function_hash)
                    .unwrap_or(0) as *const u8;
            Self { function_ptr: func }
        }
    }

    pub fn ssn(&self) -> Option<u32> {
        unsafe {
            if self.function_ptr.is_null() {
                return None;
            }

            let mut i = 0;
            while i < 32 {
                if self.function_ptr.add(i).read() == 0xB8 {
                    return Some(*(self.function_ptr.add(i + 1) as *const u32));
                }
                i += 1;
            }

            None
        }
    }

    pub fn syscall_addr(&self) -> Option<*const u8> {
        unsafe {
            if self.function_ptr.is_null() {
                return None;
            }

            let mut i = 0;
            while i < 32 {
                if self.function_ptr.add(i).read() == 0x0F
                    && self.function_ptr.add(i + 1).read() == 0x05
                    && self.function_ptr.add(i + 2).read() == 0xC3
                {
                    return Some(self.function_ptr.add(i));
                }
                i += 1;
            }

            None
        }
    }
}

#[macro_export]
macro_rules! syscall {
    ($function_name:expr) => {{
        let call = $crate::syscalls::Syscall::new($crate::hash::fnv1a_hash!($function_name));
        match (call.ssn(), call.syscall_addr()) {
            (Some(ssn), Some(addr)) => $crate::syscalls::do_syscall(ssn, addr, 0),
            _ => -1,
        }
    }};

    ($function_name:expr, $($y:expr), +) => {{
        let call = $crate::syscalls::Syscall::new($crate::hash::fnv1a_hash!($function_name));
        match (call.ssn(), call.syscall_addr()) {
            (Some(ssn), Some(addr)) => {
                let mut cnt: u32 = 0;
                $(let _ = $y; cnt += 1;)+
                $crate::syscalls::do_syscall(ssn, addr, cnt, $($y),+)
            }
            _ => -1,
        }
    }};
}
