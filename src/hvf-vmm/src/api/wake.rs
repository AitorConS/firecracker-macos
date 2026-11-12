// SPDX-License-Identifier: Apache-2.0
//! Wakes the lifecycle loop when there is work, so it need not find it by polling.
use crate::Result;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

const USER: usize = 1;

/// Wakes the loop from another thread.
#[derive(Clone, Copy)]
pub(super) struct Waker(RawFd);
impl Waker {
    pub fn wake(self) {
        let trigger = event(USER, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER);
        // SAFETY: one valid change, no event list. The queue lives as long as
        // the supervisor; a failure only leaves the loop on its timer.
        unsafe { libc::kevent(self.0, &trigger, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    }
}

pub(super) struct Wake(OwnedFd);
impl Wake {
    /// Watches the listener for connections and the process for the signals
    /// that stop it. A signal is seen here as well as by its handler.
    pub fn new(listener: RawFd) -> Result<Self> {
        // SAFETY: kqueue takes no arguments; the descriptor is owned below.
        let queue = unsafe { libc::kqueue() };
        if queue < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: a fresh descriptor nothing else owns.
        let wake = Self(unsafe { OwnedFd::from_raw_fd(queue) });
        wake.add(event(USER, libc::EVFILT_USER, libc::EV_ADD | libc::EV_CLEAR, 0))?;
        wake.add(event(listener as usize, libc::EVFILT_READ, libc::EV_ADD, 0))?;
        for signal in [libc::SIGTERM, libc::SIGINT] {
            wake.add(event(signal as usize, libc::EVFILT_SIGNAL, libc::EV_ADD, 0))?;
        }
        Ok(wake)
    }
    pub fn waker(&self) -> Waker {
        Waker(self.0.as_raw_fd())
    }
    /// Wakes the loop when the process exits. One that is already gone wakes
    /// it at once.
    pub fn watch_exit(&self, pid: u32) {
        let exit = event(
            pid as usize,
            libc::EVFILT_PROC,
            libc::EV_ADD | libc::EV_ONESHOT,
            libc::NOTE_EXIT,
        );
        if self.add(exit).is_err() {
            self.waker().wake();
        }
    }
    /// Returns when something watched happens, or after `limit`: timers and
    /// what is not watched are still found by the loop's regular pass.
    pub fn wait(&self, limit: Duration) {
        let timeout = libc::timespec {
            tv_sec: limit.as_secs() as libc::time_t,
            tv_nsec: limit.subsec_nanos() as libc::c_long,
        };
        let mut events = [event(0, 0, 0, 0); 8];
        // SAFETY: the event list holds eight entries and the timeout is valid.
        let n = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as i32,
                &timeout,
            )
        };
        if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            // Never spin on a queue that fails: keep the loop's old cadence.
            std::thread::sleep(limit);
        }
    }
    fn add(&self, change: libc::kevent) -> Result<()> {
        // SAFETY: one valid change, no event list.
        let n = unsafe {
            libc::kevent(self.0.as_raw_fd(), &change, 1, std::ptr::null_mut(), 0, std::ptr::null())
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}
fn event(ident: usize, filter: i16, flags: u16, fflags: u32) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Instant;
    const LONG: Duration = Duration::from_secs(5);
    fn woke(wake: &Wake) -> bool {
        let start = Instant::now();
        wake.wait(LONG);
        start.elapsed() < LONG / 2
    }
    #[test]
    fn wakes_on_work_and_otherwise_waits() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let wake = Wake::new(listener.as_raw_fd()).unwrap();
        let start = Instant::now();
        wake.wait(Duration::from_millis(20));
        assert!(start.elapsed() >= Duration::from_millis(20));

        let waker = wake.waker();
        std::thread::spawn(move || waker.wake()).join().unwrap();
        assert!(woke(&wake));
        // A wake is consumed by the wait it ends.
        let start = Instant::now();
        wake.wait(Duration::from_millis(20));
        assert!(start.elapsed() >= Duration::from_millis(20));

        let _client = UnixStream::connect(&path).unwrap();
        assert!(woke(&wake));
        listener.accept().unwrap();

        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        wake.watch_exit(child.id());
        assert!(woke(&wake));
        child.wait().unwrap();
        // A process that no longer exists still wakes the loop.
        wake.watch_exit(child.id());
        assert!(woke(&wake));
    }
}
