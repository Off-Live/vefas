use std::io::{Read, Write};
use vefas_core::TlsTee;

/// Simple mock transport that repeats a byte
struct Mock {
    read_src: Vec<u8>,
    write_sink: Vec<u8>,
}

impl Mock {
    fn new(len: usize) -> Self {
        Self {
            read_src: vec![0xaa; len],
            write_sink: Vec::new(),
        }
    }
}

impl Read for Mock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.read_src.len());
        buf[..n].copy_from_slice(&self.read_src[..n]);
        self.read_src.drain(0..n);
        Ok(n)
    }
}
impl Write for Mock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_sink.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn ring_buffer_bounds_inbound_and_outbound() {
    // Cap small to force drops
    let mut tee = TlsTee::with_caps(Mock::new(256 * 1024), 8 * 1024);
    // Read more than cap
    let mut buf = vec![0u8; 32 * 1024];
    let _ = tee.read(&mut buf).unwrap();
    assert!(tee.inbound_len().unwrap() <= 8 * 1024);
    assert!(tee.dropped_inbound().unwrap() > 0);

    // Write more than cap
    let write_data = vec![0xbb; 32 * 1024];
    let _ = tee.write(&write_data).unwrap();
    assert!(tee.outbound_len().unwrap() <= 8 * 1024);
    assert!(tee.dropped_outbound().unwrap() > 0);
}
