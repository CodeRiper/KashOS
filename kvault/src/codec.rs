//! Tiny bounds-checked (de)serializer. Every read can fail with `Corrupt`; nothing panics.
use crate::error::{VaultError, VaultResult};
use alloc::{string::String, vec::Vec};

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}
impl Writer {
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    pub fn str8(&mut self, s: &str) {
        self.u8(s.len() as u8);
        self.bytes(s.as_bytes());
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> VaultResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(VaultError::Corrupt)?;
        let s = self.buf.get(self.pos..end).ok_or(VaultError::Corrupt)?;
        self.pos = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> VaultResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> VaultResult<u16> {
        let mut a = [0u8; 2];
        a.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(a))
    }
    pub fn u32(&mut self) -> VaultResult<u32> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    pub fn u64(&mut self) -> VaultResult<u64> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    pub fn arr32(&mut self) -> VaultResult<[u8; 32]> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    pub fn str8(&mut self) -> VaultResult<String> {
        let n = self.u8()? as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| VaultError::Corrupt)
    }
}
