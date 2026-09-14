#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host storage power-cut probe for DEDICATED hardware (diskchecker-style).

Checks whether a Mac's storage keeps data that F_FULLFSYNC acknowledged when
power is physically cut. The ACK log must live on a SECOND machine (the
observer), because anything logged on the machine being cut can be lost too.

  observer --listen 0.0.0.0:7788 --log acks.log     (on the second machine)
  writer   --file /Volumes/Test/probe.bin --size-mib 1024 \
           --observer 192.0.2.10:7788 [--sync fullfsync|none]  (on the test Mac)
  -> cut power on the test Mac while the writer runs, boot it again
  verify   --file /Volumes/Test/probe.bin --acks acks.log     (copy acks.log over)

Every record is a 4 KiB block at offset counter*4096 with a CRC. The writer
sends "ACK run counter" only after F_FULLFSYNC returned; the observer fsyncs
the line before replying. verify fails if any acknowledged block is missing or
corrupt. --sync none is the negative control and is expected to lose blocks
after a real power cut; if it never loses anything, the cut is not effective.

F_FULLFSYNC failures abort the writer; there is no fallback to fsync().
`selftest` runs all parts locally without any power cut and proves only that
the tool itself detects missing or corrupt blocks.
"""

import argparse
import fcntl
import os
import socket
import struct
import sys
import tempfile
import threading
import uuid
import zlib

BLOCK = 4096
MAGIC = b"JPCPROBE"
HEADER = struct.Struct("<8s16sQI")


def block(run, counter):
    body = bytearray(BLOCK)
    seed = zlib.crc32(run + struct.pack("<Q", counter))
    for i in range(HEADER.size, BLOCK, 4):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        struct.pack_into("<I", body, i, seed)
    crc = zlib.crc32(bytes(body[HEADER.size:]))
    HEADER.pack_into(body, 0, MAGIC, run, counter, crc)
    return bytes(body)


def observer(args, ready=None, stop=None):
    host, port = args.listen.rsplit(":", 1)
    server = socket.create_server((host, int(port)))
    if ready is not None:
        ready.append(server.getsockname()[1])
    log = open(args.log, "a")
    server.settimeout(0.5)
    while not (stop and stop.is_set()):
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        with conn, conn.makefile("rwb") as stream:
            for line in stream:
                log.write(line.decode())
                log.flush()
                os.fsync(log.fileno())
                stream.write(b"OK\n")
                stream.flush()
    log.close()


def writer(args):
    run = uuid.uuid4().bytes
    fd = os.open(args.file, os.O_RDWR | os.O_CREAT, 0o600)
    size = args.size_mib << 20
    os.ftruncate(fd, size)
    fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    host, port = args.observer.rsplit(":", 1)
    conn = socket.create_connection((host, int(port)))
    stream = conn.makefile("rwb")
    print(f"RUN {run.hex()} sync={args.sync}", flush=True)
    for counter in range(size // BLOCK):
        if args.limit and counter >= args.limit:
            break
        os.pwrite(fd, block(run, counter), counter * BLOCK)
        if args.sync == "fullfsync":
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)  # raises OSError; never falls back
        stream.write(f"ACK {run.hex()} {counter}\n".encode())
        stream.flush()
        if stream.readline() != b"OK\n":
            raise SystemExit("observer did not confirm")
    stream.close()
    conn.close()
    os.close(fd)
    print("WRITER_DONE", flush=True)


def verify(args):
    acks = {}
    for line in open(args.acks):
        parts = line.split()
        if len(parts) == 3 and parts[0] == "ACK":
            acks[parts[1]] = max(acks.get(parts[1], -1), int(parts[2]))
    if args.run:
        acks = {args.run: acks[args.run]}
    if len(acks) != 1:
        raise SystemExit(f"expected one run in ACK log, found {sorted(acks)}; pass --run")
    run_hex, last = next(iter(acks.items()))
    run = bytes.fromhex(run_hex)
    bad = []
    with open(args.file, "rb") as f:
        for counter in range(last + 1):
            f.seek(counter * BLOCK)
            if f.read(BLOCK) != block(run, counter):
                bad.append(counter)
    print(f"VERIFY run={run_hex} acknowledged={last + 1} missing_or_corrupt={len(bad)}"
          + (f" first={bad[:10]}" if bad else ""))
    return 1 if bad else 0


def selftest():
    with tempfile.TemporaryDirectory() as tmp:
        stop, ready = threading.Event(), []
        obs = argparse.Namespace(listen="127.0.0.1:0", log=os.path.join(tmp, "acks.log"))
        thread = threading.Thread(target=observer, args=(obs, ready, stop))
        thread.start()
        while not ready:
            pass
        path = os.path.join(tmp, "probe.bin")
        writer(argparse.Namespace(file=path, size_mib=4, observer=f"127.0.0.1:{ready[0]}", sync="fullfsync", limit=256))
        stop.set()
        thread.join()
        check = argparse.Namespace(file=path, acks=obs.log, run=None)
        assert verify(check) == 0, "clean run must verify"
        with open(path, "r+b") as f:
            f.seek(17 * BLOCK)
            f.write(bytes(BLOCK))  # simulate a lost block
        assert verify(check) == 1, "a lost acknowledged block must be detected"
        print("SELFTEST_OK (no power cut performed; tool logic only)")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    o = sub.add_parser("observer")
    o.add_argument("--listen", required=True)
    o.add_argument("--log", required=True)
    w = sub.add_parser("writer")
    w.add_argument("--file", required=True)
    w.add_argument("--size-mib", type=int, default=1024)
    w.add_argument("--observer", required=True)
    w.add_argument("--sync", choices=("fullfsync", "none"), default="fullfsync")
    w.add_argument("--limit", type=int, default=0)
    v = sub.add_parser("verify")
    v.add_argument("--file", required=True)
    v.add_argument("--acks", required=True)
    v.add_argument("--run")
    sub.add_parser("selftest")
    args = parser.parse_args()
    if args.command == "observer":
        observer(args)
    elif args.command == "writer":
        writer(args)
    elif args.command == "verify":
        sys.exit(verify(args))
    else:
        selftest()


if __name__ == "__main__":
    main()
