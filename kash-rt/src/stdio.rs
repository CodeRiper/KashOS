//! Formatted Standard I/O for User-Space Binaries (`print!`, `println!`).

use core::fmt::{self, Write};
use crate::posix;

pub struct Stdout;
pub struct Stderr;
pub struct Stdin;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let _ = posix::write(1, s.as_bytes());
        Ok(())
    }
}

impl Write for Stderr {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let _ = posix::write(2, s.as_bytes());
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print_stdout(args: fmt::Arguments) {
    let mut out = Stdout;
    let _ = out.write_fmt(args);
}

#[doc(hidden)]
pub fn _print_stderr(args: fmt::Arguments) {
    let mut err = Stderr;
    let _ = err.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::stdio::_print_stdout(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => {
        $crate::print!("{}\n", format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::stdio::_print_stderr(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => {
        $crate::eprint!("{}\n", format_args!($($arg)*))
    };
}
