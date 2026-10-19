//! POSIX C-string and memory manipulation functions.
#![allow(suspicious_runtime_symbol_definitions)]

/// Calculate the length of a null-terminated string.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0;
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

/// Calculate the length of a string up to a maximum length.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const u8, maxlen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0;
    while len < maxlen && unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

/// Compare two null-terminated strings.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strcmp(s1: *const u8, s2: *const u8) -> i32 {
    if s1 == s2 {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }

    let mut i = 0;
    loop {
        let b1 = unsafe { *s1.add(i) };
        let b2 = unsafe { *s2.add(i) };
        if b1 != b2 {
            return (b1 as i32) - (b2 as i32);
        }
        if b1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Compare two strings up to `n` bytes.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strncmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    if n == 0 || s1 == s2 {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }

    for i in 0..n {
        let b1 = unsafe { *s1.add(i) };
        let b2 = unsafe { *s2.add(i) };
        if b1 != b2 {
            return (b1 as i32) - (b2 as i32);
        }
        if b1 == 0 {
            break;
        }
    }
    0
}

/// Copy null-terminated string `src` to `dst`.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let mut i = 0;
    loop {
        let b = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = b };
        if b == 0 {
            break;
        }
        i += 1;
    }
    dst
}

/// Copy up to `n` bytes from `src` to `dst`, padding with zeroes.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }
    let mut i = 0;
    let mut pad = false;
    while i < n {
        if !pad {
            let b = unsafe { *src.add(i) };
            unsafe { *dst.add(i) = b };
            if b == 0 {
                pad = true;
            }
        } else {
            unsafe { *dst.add(i) = 0 };
        }
        i += 1;
    }
    dst
}

/// Concatenate null-terminated string `src` onto `dst`.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let dst_len = unsafe { strlen(dst) };
    unsafe { strcpy(dst.add(dst_len), src) };
    dst
}

/// Locate first occurrence of character `c` in string `s`.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *mut u8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let target = (c as u8) as usize;
    let mut ptr = s;
    loop {
        let b = unsafe { *ptr };
        if b as usize == target {
            return ptr as *mut u8;
        }
        if b == 0 {
            return core::ptr::null_mut();
        }
        ptr = unsafe { ptr.add(1) };
    }
}

/// Copy `n` bytes from non-overlapping `src` to `dst`.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }
    for i in 0..n {
        unsafe { *dst.add(i) = *src.add(i); }
    }
    dst
}

/// Copy `n` bytes from potentially overlapping `src` to `dst`.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }
    if (dst as usize) < (src as usize) {
        for i in 0..n {
            unsafe { *dst.add(i) = *src.add(i); }
        }
    } else {
        for i in (0..n).rev() {
            unsafe { *dst.add(i) = *src.add(i); }
        }
    }
    dst
}

/// Fill `n` bytes of memory with byte value `val`.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    if dst.is_null() || n == 0 {
        return dst;
    }
    let byte_val = val as u8;
    for i in 0..n {
        unsafe { *dst.add(i) = byte_val; }
    }
    dst
}

/// Compare `n` bytes of memory.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    if n == 0 || s1 == s2 {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    for i in 0..n {
        let b1 = unsafe { *s1.add(i) };
        let b2 = unsafe { *s2.add(i) };
        if b1 != b2 {
            return (b1 as i32) - (b2 as i32);
        }
    }
    0
}

/// Locate first occurrence of character `c` within `n` bytes of memory.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    if s.is_null() || n == 0 {
        return core::ptr::null_mut();
    }
    let target = c as u8;
    for i in 0..n {
        let ptr = unsafe { s.add(i) };
        if unsafe { *ptr } == target {
            return ptr as *mut u8;
        }
    }
    core::ptr::null_mut()
}

/// Parse ASCII decimal integer from string.
#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn atoi(s: *const u8) -> i32 {
    if s.is_null() {
        return 0;
    }
    let mut ptr = s;
    // Skip whitespace
    while unsafe { *ptr == b' ' || *ptr == b'\t' || *ptr == b'\n' || *ptr == b'\r' } {
        ptr = unsafe { ptr.add(1) };
    }
    let mut sign = 1;
    if unsafe { *ptr == b'-' } {
        sign = -1;
        ptr = unsafe { ptr.add(1) };
    } else if unsafe { *ptr == b'+' } {
        ptr = unsafe { ptr.add(1) };
    }

    let mut res: i32 = 0;
    while unsafe { *ptr >= b'0' && *ptr <= b'9' } {
        let digit = unsafe { (*ptr - b'0') as i32 };
        res = res.saturating_mul(10).saturating_add(digit);
        ptr = unsafe { ptr.add(1) };
    }
    res * sign
}

/// Convert integer to ASCII decimal string in provided slice.
pub fn itoa(val: i64, buf: &mut [u8]) -> &str {
    if buf.is_empty() {
        return "";
    }
    if val == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("");
    }
    let is_neg = val < 0;
    let mut uval = if is_neg {
        val.unsigned_abs()
    } else {
        val as u64
    };

    let mut temp = [0u8; 32];
    let mut idx = 0;
    while uval > 0 && idx < temp.len() {
        temp[idx] = b'0' + (uval % 10) as u8;
        uval /= 10;
        idx += 1;
    }
    if is_neg && idx < temp.len() {
        temp[idx] = b'-';
        idx += 1;
    }

    let out_len = idx.min(buf.len());
    for i in 0..out_len {
        buf[i] = temp[idx - 1 - i];
    }
    core::str::from_utf8(&buf[..out_len]).unwrap_or("")
}
