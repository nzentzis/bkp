extern crate ring;

use std::io;
use std::io::{Read, Write};
use ring::digest;

/// A trait to easily convert binary data to hex
pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl<'a> ToHex for &'a [u8] {
    fn to_hex(&self) -> String {
        let mut s = String::new();
        for i in self.iter() {
            s += &format!("{:02x}", i);
        }
        s
    }
}

/// Wraps an underlying reader and hashes the data read/written
pub struct Hasher<'a, S: 'a> {
    ctx: digest::Context,
    strm: &'a mut S
}

impl<'a, S> Hasher<'a, S> {
    /// Create a new Hasher with the given algorithm
    pub fn new(algo: &'static digest::Algorithm, strm: &'a mut S) -> Self {
        Hasher {ctx: digest::Context::new(algo), strm: strm}
    }

    pub fn sha256(strm: &'a mut S) -> Self {
        Hasher::new(&digest::SHA256, strm)
    }

    pub fn finish(self) -> digest::Digest { self.ctx.finish() }
}

impl<'a, R: Read> Read for Hasher<'a, R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let r = self.strm.read(&mut buf);
        if let Ok(n) = r { self.ctx.update(&buf[0..n]); }
        r
    }
}

impl<'a, W: Write> Write for Hasher<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let r = self.strm.write(&buf);
        if let Ok(n) = r { self.ctx.update(&buf[0..n]); }
        r
    }

    fn flush(&mut self) -> io::Result<()> { self.strm.flush() }
}

/// A dummy object which implements Write but discards the written data
pub struct DevNull {}

impl DevNull {
    pub fn new() -> DevNull { DevNull {} }
}

impl Write for DevNull {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { Ok(buf.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn tohex_test() { // make sure the ToHex trait works properly
    let v: Vec<u8> = vec![1,2,3,4,5,6,250,251,252,253];
    let s = v.as_slice().to_hex();
    assert!(s == "010203040506fafbfcfd");
}

#[test]
fn sha256_test() { // make sure the Hasher works properly
    let mut v = Vec::new();
    {
        let mut writer = Hasher::sha256(&mut v);
        writer.write(b"I will not buy this record, it is scratched.\n");
        writer.write(b"My hovercraft is full of eels\n");
        let r = writer.finish();
        let hex = r.as_ref().to_hex();
        assert!(hex ==
            "9242c08a0bbcf5157a9515277b34c16f1939dc723cbae5d0beed129f6ac66622");
    }
    assert!(v.len() == 75);
}
