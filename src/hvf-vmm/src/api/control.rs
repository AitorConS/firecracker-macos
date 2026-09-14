// SPDX-License-Identifier: Apache-2.0
//! Fixed-size, versioned control frames shared with native/control.h.
use crate::Result;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

#[derive(Debug, PartialEq)]
pub(super) struct Message {
    pub kind: u8,
    pub operation: u64,
}
impl Message {
    pub fn send(&self, stream: &mut UnixStream) -> Result<()> {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(b"HVFC");
        bytes[4] = 1;
        bytes[5] = self.kind;
        bytes[8..].copy_from_slice(&self.operation.to_le_bytes());
        stream.write_all(&bytes)?;
        Ok(())
    }
}
#[derive(Default)]
pub(super) struct Reader {
    bytes: [u8; 16],
    used: usize,
}
impl Reader {
    pub fn receive(&mut self, stream: &mut UnixStream) -> Result<Option<Message>> {
        match stream.read(&mut self.bytes[self.used..]) {
            Ok(0) => return Err("control peer disconnected".into()),
            Ok(n) => self.used += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        if self.used < self.bytes.len() {
            return Ok(None);
        }
        self.used = 0;
        if &self.bytes[..4] != b"HVFC" || self.bytes[4] != 1 || self.bytes[6..8] != [0, 0] {
            return Err("invalid control frame or unsupported version".into());
        }
        Ok(Some(Message {
            kind: self.bytes[5],
            operation: u64::from_le_bytes(self.bytes[8..].try_into().unwrap()),
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_and_coalesced_frames() {
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        let mut reader = Reader::default();
        tx.write_all(b"HVF").unwrap();
        assert!(reader.receive(&mut rx).unwrap().is_none());
        tx.write_all(&[b'C', 1, b'A', 0, 0, 9, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        Message {
            kind: b'A',
            operation: 10,
        }
        .send(&mut tx)
        .unwrap();
        assert_eq!(
            reader.receive(&mut rx).unwrap(),
            Some(Message {
                kind: b'A',
                operation: 9
            })
        );
        assert_eq!(
            reader.receive(&mut rx).unwrap(),
            Some(Message {
                kind: b'A',
                operation: 10
            })
        );
    }
    #[test]
    fn rejects_unknown_version() {
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        tx.write_all(b"HVFC\x02A\0\0\0\0\0\0\0\0\0\0").unwrap();
        assert!(Reader::default().receive(&mut rx).is_err());
    }
}
