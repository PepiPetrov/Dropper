use ntapi::ntpsapi::NtCurrentPeb;
use crate::call_fn;

struct RtlGlobalAllocator {}

unsafe impl Sync for RtlGlobalAllocator {}
unsafe impl core::alloc::GlobalAlloc for RtlGlobalAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe {
            call_fn!(
                "ntdll",
                "RtlAllocateHeap",
                (*NtCurrentPeb()).ProcessHeap,
                0,
                layout.size()
            ) as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe {
            call_fn!(
                "ntdll",
                "RtlFreeHeap",
                (*NtCurrentPeb()).ProcessHeap,
                0,
                ptr
            );
        }
    }

    unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        // SAFETY: the safety contract for `alloc` must be upheld by the caller.
        let ptr = unsafe { self.alloc(layout) };
        if !ptr.is_null() {
            // SAFETY: as allocation succeeded, the region from `ptr`
            // of size `size` is guaranteed to be valid for writes.
            unsafe { core::ptr::write_bytes(ptr, 0, size) };
        }
        ptr
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        // SAFETY: the caller must ensure that the `new_size` does not overflow.
        // `layout.align()` comes from a `Layout` and is thus guaranteed to be valid.
        let new_layout =
            unsafe { core::alloc::Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: the caller must ensure that `new_layout` is greater than zero.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            // SAFETY: the previously allocated block cannot overlap the newly allocated block.
            // The safety contract for `dealloc` must be upheld by the caller.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    ptr,
                    new_ptr,
                    core::cmp::min(layout.size(), new_size),
                );
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: RtlGlobalAllocator = RtlGlobalAllocator {};

// #[panic_handler]
// fn panic_handler(_panic: &core::panic::PanicInfo) -> ! {
//     //     // let msg = panic.message().as_str().unwrap().as_bytes();
//     //     // unsafe {
//     //     //     windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxA(
//     //     //         0,
//     //     //         msg.as_ptr(),
//     //     //         b"Error\0".as_ptr(),
//     //     //         windows_sys::Win32::UI::WindowsAndMessaging::MB_OK,
//     //     //     );
//     //     // }
//     loop {}
// }
