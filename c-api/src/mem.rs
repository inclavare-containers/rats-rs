/// This function is used to free the buffer pointed by pointers returned by some of the rats-rs APIs, to avoid memory leak. Note that you should not call libc's `free()` function on those pointers, because the allocater is different between C and Rust.
#[no_mangle]
pub extern "C" fn rats_rs_rust_free(data: *mut u8, len: usize) {
    let slice = std::ptr::slice_from_raw_parts_mut(data, len);
    let x = unsafe { Box::from_raw(slice) };
    drop(x)
}
