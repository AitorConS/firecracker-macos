// SPDX-License-Identifier: Apache-2.0
// Guest workload for power-loss simulation on a Nanos TFS volume at /data.
//
// DURA_MODE=write appends fixed 256-byte records with fdatasync, creates a new
// segment every 64 records through create+fsync+rename+directory fsync, and
// rewrites /data/meta in place with fsync. "ACK n" is printed only after every
// sync for record n returned success. DURA_SYNC=0 skips syncs (negative control).
//
// DURA_MODE=verify DURA_ACK=n checks that records 1..n exist intact and that
// /data/meta records at least n.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	recordSize = 256
	perSegment = 64
	dir        = "/data/log"
	meta       = "/data/meta"
)

func record(i int) []byte {
	sum := sha256.Sum256([]byte("jerboa-durability-" + strconv.Itoa(i)))
	line := fmt.Sprintf("%08d:%s", i, hex.EncodeToString(sum[:]))
	b := []byte(line + strings.Repeat(".", recordSize-len(line)-1) + "\n")
	return b
}

func segment(i int) string { return filepath.Join(dir, fmt.Sprintf("seg-%06d", (i-1)/perSegment)) }

func fail(format string, args ...any) {
	fmt.Printf("DURA_FAIL "+format+"\n", args...)
	os.Exit(1)
}

func step(format string, args ...any) {
	if os.Getenv("DURA_TRACE") == "1" {
		fmt.Printf("STEP "+format+"\n", args...)
	}
}

func syncDir(path string, enabled bool) {
	if !enabled {
		return
	}
	step("fsync dir %s", path)
	d, err := os.Open(path)
	if err != nil {
		fail("open dir %s: %v", path, err)
	}
	if err := d.Sync(); err != nil {
		fail("fsync dir %s: %v", path, err)
	}
	d.Close()
}

func write(enabled bool, limit int) {
	step("mkdir %s", dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail("mkdir: %v", err)
	}
	syncDir("/data", enabled)
	m, err := os.OpenFile(meta, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		fail("meta: %v", err)
	}
	var seg *os.File
	big := make([]byte, 64<<10)
	for i := 1; i <= limit; i++ {
		if (i-1)%perSegment == 0 {
			if seg != nil {
				seg.Close()
			}
			tmp := segment(i) + ".tmp"
			f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				fail("create %s: %v", tmp, err)
			}
			if enabled {
				if err := f.Sync(); err != nil {
					fail("fsync %s: %v", tmp, err)
				}
			}
			f.Close()
			if err := os.Rename(tmp, segment(i)); err != nil {
				fail("rename: %v", err)
			}
			syncDir(dir, enabled)
			seg, err = os.OpenFile(segment(i), os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				fail("open segment: %v", err)
			}
			// A large multi-descriptor write that is never acknowledged on its own.
			for j := range big {
				big[j] = byte(i + j)
			}
			if err := os.WriteFile(filepath.Join(dir, "scratch"), big, 0o644); err != nil {
				fail("scratch: %v", err)
			}
		}
		if i <= 2 {
			step("append record %d", i)
		}
		if _, err := seg.Write(record(i)); err != nil {
			fail("append %d: %v", i, err)
		}
		if enabled {
			if err := syscall.Fdatasync(int(seg.Fd())); err != nil {
				fail("fdatasync %d: %v", i, err)
			}
		}
		if _, err := m.WriteAt([]byte(fmt.Sprintf("last=%08d\n", i)), 0); err != nil {
			fail("meta write: %v", err)
		}
		if enabled {
			if err := m.Sync(); err != nil {
				fail("meta fsync: %v", err)
			}
		}
		fmt.Printf("ACK %d\n", i)
	}
	fmt.Println("WRITE_DONE")
}

// verify checks records 1..acked. acked < 0 uses the value in /data/meta: meta
// is fsynced only after its record's fdatasync, so it must never point past an
// intact record at any crash point, even without host-side ACK information.
func verify(acked int) {
	if acked < 0 {
		acked = 0
		if b, err := os.ReadFile(meta); err == nil && len(b) >= 13 && strings.HasPrefix(string(b), "last=") {
			acked, _ = strconv.Atoi(string(b[5:13]))
		}
	}
	for i := 1; i <= acked; i++ {
		f, err := os.Open(segment(i))
		if err != nil {
			fail("record %d: segment missing: %v", i, err)
		}
		got := make([]byte, recordSize)
		_, err = f.ReadAt(got, int64((i-1)%perSegment)*recordSize)
		f.Close()
		if err != nil {
			fail("record %d: short read: %v", i, err)
		}
		if string(got) != string(record(i)) {
			fail("record %d: payload mismatch", i)
		}
	}
	b, err := os.ReadFile(meta)
	if err != nil && acked > 0 {
		fail("meta missing: %v", err)
	}
	last := 0
	if len(b) >= 14 && strings.HasPrefix(string(b), "last=") {
		last, _ = strconv.Atoi(string(b[5:13]))
	}
	if last < acked {
		fail("meta last=%d below acked=%d", last, acked)
	}
	present := acked
	for {
		f, err := os.Open(segment(present + 1))
		if err != nil {
			break
		}
		got := make([]byte, recordSize)
		_, err = f.ReadAt(got, int64(present%perSegment)*recordSize)
		f.Close()
		if err != nil || string(got) != string(record(present+1)) {
			break
		}
		present++
	}
	fmt.Printf("VERIFY_OK acked=%d present=%d meta=%d\n", acked, present, last)
}

func main() {
	fmt.Printf("DURA_START mode=%s sync=%s\n", os.Getenv("DURA_MODE"), os.Getenv("DURA_SYNC"))
	switch os.Getenv("DURA_MODE") {
	case "write":
		limit, err := strconv.Atoi(os.Getenv("DURA_LIMIT"))
		if err != nil || limit <= 0 {
			limit = 1 << 30
		}
		write(os.Getenv("DURA_SYNC") != "0", limit)
	case "verify":
		acked, err := strconv.Atoi(os.Getenv("DURA_ACK"))
		if err != nil {
			fail("DURA_ACK: %v", err)
		}
		verify(acked)
	default:
		fail("unknown DURA_MODE")
	}
}
