// SPDX-License-Identifier: Apache-2.0
//! Bounded HTTP workers keep slow clients out of the lifecycle loop.
use crate::Result;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_CONNECTIONS: usize = 32;
type Reply = (u16, Option<Value>);
type Pending = (Request, SyncSender<Reply>);
pub(super) struct Transport {
    sender: SyncSender<Pending>,
    receiver: Receiver<Pending>,
    workers: Vec<JoinHandle<()>>,
    pub rejected: u64,
    queued: Arc<AtomicUsize>,
}
impl Transport {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(MAX_CONNECTIONS);
        Self {
            sender,
            receiver,
            workers: Vec::new(),
            rejected: 0,
            queued: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub fn accept(&mut self, listener: &UnixListener) -> Result<()> {
        self.workers.retain(|worker| !worker.is_finished());
        // Bound accept work as well as active connections under a connection flood.
        for _ in 0..8 {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };
            if self.workers.len() == MAX_CONNECTIONS {
                self.rejected += 1;
                drop(stream);
                continue;
            }
            let sender = self.sender.clone();
            let queued = self.queued.clone();
            self.workers.push(thread::spawn(move || {
                let mut prometheus = false;
                let reply = match request(&mut stream) {
                    Ok(request) => {
                        prometheus = request.path == "/metrics" && request.prometheus;
                        let (tx, rx) = mpsc::sync_channel(1);
                        queued.fetch_add(1, Ordering::Relaxed);
                        if sender.try_send((request, tx)).is_err() {
                            queued.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                        match rx.recv_timeout(Duration::from_secs(2)) {
                            Ok(reply) => reply,
                            Err(_) => return,
                        }
                    }
                    Err(e) => (400, Some(json!({"fault_message":e.to_string()}))),
                };
                let _ = respond(&mut stream, reply.0, reply.1, prometheus);
            }));
        }
        Ok(())
    }
    pub fn connections(&self) -> usize {
        self.workers.len()
    }
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }
    pub fn next(&self) -> Option<Pending> {
        let pending = self.receiver.try_recv().ok()?;
        self.queued.fetch_sub(1, Ordering::Relaxed);
        Some(pending)
    }
}
fn read_before(stream: &mut UnixStream, bytes: &mut [u8], deadline: Instant) -> Result<usize> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("HTTP read deadline exceeded".into());
    }
    stream.set_read_timeout(Some(remaining))?;
    Ok(stream.read(bytes)?)
}

pub(super) struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    prometheus: bool,
}
fn request(stream: &mut UnixStream) -> Result<Request> {
    // Darwin accept inherits the listener's O_NONBLOCK. Each bounded worker
    // must use blocking I/O with deadlines, otherwise a delayed first byte is
    // incorrectly answered with HTTP 400/EAGAIN before the client sends it.
    stream.set_nonblocking(false)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    let header_end = loop {
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if bytes.len() > 8192 {
            return Err("HTTP headers exceed 8 KiB".into());
        }
        let n = read_before(stream, &mut buf, deadline)?;
        if n == 0 {
            return Err("incomplete HTTP headers".into());
        }
        bytes.extend_from_slice(&buf[..n]);
    };
    if header_end > 8192 {
        return Err("HTTP headers exceed 8 KiB".into());
    }
    let headers = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = headers.split("\r\n");
    let first: Vec<_> = lines
        .next()
        .ok_or("request line missing")?
        .split_whitespace()
        .collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err("expected HTTP/1.1".into());
    }
    let method = first[0].to_owned();
    let path = first[1].to_owned();
    let mut length = None;
    let mut prometheus = false;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        if name.eq_ignore_ascii_case("accept")
            && value.split(',').any(|v| v.trim().starts_with("text/plain"))
        {
            prometheus = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked requests are unsupported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate Content-Length".into());
            }
            let n: usize = value.trim().parse()?;
            if n > 1024 * 1024 {
                return Err("HTTP body exceeds 1 MiB".into());
            }
            length = Some(n);
        }
    }
    let length = length.unwrap_or(0);
    while bytes.len() - header_end < length {
        let need = (length - (bytes.len() - header_end)).min(buf.len());
        let n = read_before(stream, &mut buf[..need], deadline)?;
        if n == 0 {
            return Err("incomplete HTTP body".into());
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    Ok(Request {
        prometheus,
        method,
        path,
        body: bytes[header_end..header_end + length].to_vec(),
    })
}
fn respond(
    stream: &mut UnixStream,
    code: u16,
    value: Option<Value>,
    prometheus: bool,
) -> Result<()> {
    let body = if prometheus {
        value
            .as_ref()
            .and_then(Value::as_object)
            .map(|metrics| {
                metrics
                    .iter()
                    .filter(|(_, v)| v.is_number())
                    .map(|(name, v)| format!("hvf_{name} {v}\n"))
                    .collect::<String>()
            })
            .unwrap_or_default()
    } else {
        value.map(|v| v.to_string()).unwrap_or_default()
    };
    let content_type = if prometheus {
        "text/plain; version=0.0.4"
    } else {
        "application/json"
    };
    let reason = match code {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut remaining = response.as_bytes();
    while !remaining.is_empty() {
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return Err("HTTP write deadline exceeded".into());
        }
        stream.set_write_timeout(Some(budget))?;
        let written = stream.write(remaining)?;
        if written == 0 {
            return Err("HTTP client disconnected".into());
        }
        remaining = &remaining[written..];
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonblocking_accepted_socket_waits_for_delayed_request() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
        });
        assert_eq!(request(&mut server).unwrap().path, "/");
        writer.join().unwrap();
    }
    fn parse(bytes: &[u8]) -> Result<Request> {
        let (mut server, mut client) = UnixStream::pair()?;
        client.write_all(bytes)?;
        client.shutdown(std::net::Shutdown::Write)?;
        request(&mut server)
    }
    #[test]
    fn mutation_campaign_bounded_requests() {
        let cases = std::env::var("HVF_FUZZ_CASES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1000)
            .min(1_000_000);
        let seed =
            b"PUT /snapshot/create HTTP/1.1\r\nContent-Length: 2\r\nAccept: text/plain\r\n\r\n{}";
        let mut random = 0x20260913u64;
        for i in 0..cases {
            let mut bytes = seed.to_vec();
            for _ in 0..(i % 16 + 1) {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                let index = (random as usize) % bytes.len();
                bytes[index] = (random >> 32) as u8;
            }
            if i % 3 == 0 {
                bytes.truncate(i % seed.len());
            }
            if let Ok(request) = parse(&bytes) {
                assert!(request.body.len() <= 1024 * 1024);
                assert!(!request.method.is_empty() && !request.path.is_empty());
            }
        }
    }
    #[test]
    fn valid_body() {
        let r = parse(b"PUT /actions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(r.body, b"{}");
        assert_eq!(r.path, "/actions");
    }
    #[test]
    fn rejects_ambiguous_framing() {
        for b in [
            b"PUT / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(parse(b).is_err());
        }
    }
    #[test]
    fn rejects_truncated_body() {
        assert!(parse(b"PUT / HTTP/1.1\r\nContent-Length: 3\r\n\r\n{}").is_err());
    }
    #[test]
    fn rejects_large_body() {
        assert!(parse(b"PUT / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n").is_err());
    }
}
