#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild the disk image a host power cut could leave, from a crash journal.

The journal comes from a VMM built with -DHVF_CRASH_JOURNAL (crash_journal.h).
Writes are journaled ahead of pwrite(); 'S' records give the bytes a short or
failed write actually applied. Models, for the file with the given inode:
  durable  base image + every write before the last successful F_FULLFSYNC;
           all later writes are lost (host cache fully lost).
  subset   durable + a seeded random, order-preserving subset of later writes
           (partial writeback before the cut).
  full     base + every journaled write.
  boundary base + writes before the --flush k-th successful F_FULLFSYNC, plus a
           seeded order-preserving subset of the writes issued before flush k+1
           (a cut while the next sync was in flight).

--compare KILLED checks journal completeness against the disk the VMM kill
left: the full image may differ only inside the final write intent, which the
kill can interrupt before or during pwrite(). Any other difference means the
journal missed a write and the models are invalid.
"""

import argparse
import json
import random
import shutil
import struct
from pathlib import Path

MAGIC = 0x4A435648
HEADER = struct.Struct("<IB3xQQQQIi")
CHUNK = 1 << 20


def parse(path):
    data = path.read_bytes()
    records, pos = [], 0
    while pos < len(data):
        if len(data) - pos < HEADER.size:
            return records, True
        magic, kind, dev, ino, seq, offset, length, error = HEADER.unpack_from(data, pos)
        if magic != MAGIC:
            raise ValueError(f"{path}: bad magic at {pos}")
        pos += HEADER.size
        payload = b""
        if kind in (ord("W"), ord("P")):
            if len(data) - pos < length:
                return records, True
            payload = data[pos:pos + length]
            pos += length
        records.append({"type": chr(kind), "ino": ino, "seq": seq, "offset": offset,
                        "len": length, "data": payload, "error": error})
    return records, False


def diff_ranges(left, right):
    ranges = []
    with open(left, "rb") as a, open(right, "rb") as b:
        offset = 0
        while True:
            x, y = a.read(CHUNK), b.read(CHUNK)
            if not x and not y:
                break
            if x != y:
                for i in range(max(len(x), len(y))):
                    if i >= len(x) or i >= len(y) or x[i] != y[i]:
                        start = offset + i
                        if ranges and ranges[-1][1] == start:
                            ranges[-1][1] = start + 1
                        else:
                            ranges.append([start, start + 1])
            offset += max(len(x), len(y))
    return ranges


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--journals", type=Path, required=True)
    parser.add_argument("--inode", type=int, required=True)
    parser.add_argument("--mode", choices=("durable", "subset", "full", "boundary"), required=True)
    parser.add_argument("--flush", type=int, default=0, help="1-based flush index for --mode boundary")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compare", type=Path, help="killed disk to check journal completeness against")
    args = parser.parse_args()

    selected, truncated, sources = [], False, []
    for journal in sorted(args.journals.glob("journal-*.bin")):
        records, cut = parse(journal)
        mine = [r for r in records if r["ino"] == args.inode and r["type"] in "WSFE"]
        if any(r["type"] == "W" for r in mine):
            sources.append(journal.name)
            selected, truncated = mine, cut
    if len(sources) > 1:
        raise SystemExit(f"more than one VMM wrote inode {args.inode}: {sources}")
    applied = {r["seq"]: r["len"] for r in selected if r["type"] == "S"}
    writes = [r for r in selected if r["type"] == "W"]
    for w in writes:
        w["data"] = w["data"][:applied.get(w["seq"], len(w["data"]))]
    flushes = [r for r in selected if r["type"] == "F"]
    errors = [r for r in selected if r["type"] == "E"]
    durable_seq = flushes[-1]["seq"] if flushes else 0
    rng = random.Random(args.seed)
    if args.mode == "full":
        chosen = writes
    elif args.mode == "boundary":
        if not 1 <= args.flush <= len(flushes):
            raise SystemExit(f"--flush must be 1..{len(flushes)}")
        point = flushes[args.flush - 1]["seq"]
        following = flushes[args.flush]["seq"] if args.flush < len(flushes) else float("inf")
        chosen = [w for w in writes if w["seq"] < point]
        chosen += [w for w in writes if point < w["seq"] < following and rng.random() < 0.5]
    else:
        chosen = [w for w in writes if w["seq"] < durable_seq]
        if args.mode == "subset":
            chosen += [w for w in writes if w["seq"] > durable_seq and rng.random() < 0.5]
    shutil.copyfile(args.base, args.out)
    size = args.out.stat().st_size
    with args.out.open("r+b") as image:
        for w in chosen:
            if w["offset"] + len(w["data"]) > size:
                raise SystemExit(f"write beyond image end at {w['offset']}")
            image.seek(w["offset"])
            image.write(w["data"])
    summary = {
        "mode": args.mode,
        "seed": args.seed,
        "journal": sources,
        "journal_truncated_tail": truncated,
        "writes": len(writes),
        "short_or_failed_writes": len(applied),
        "flushes": len(flushes),
        "flush_errors": len(errors),
        "durable_seq": durable_seq,
        "boundary_flush": args.flush if args.mode == "boundary" else None,
        # Flush indices k whose following sync interval contains writes: only a
        # boundary cut there drops in-flight writes. Idle flushes add nothing.
        "write_bearing_flushes": [
            k for k in range(1, len(flushes) + 1)
            if any(flushes[k - 1]["seq"] < w["seq"] < (flushes[k]["seq"] if k < len(flushes) else float("inf"))
                   for w in writes)
        ],
        "applied_writes": len(chosen),
        "lost_writes": len(writes) - len(chosen),
        "written_bytes": sum(len(w["data"]) for w in writes),
    }
    if args.compare:
        ranges = diff_ranges(args.out, args.compare)
        last = writes[-1] if writes else None
        inside = bool(last) and all(last["offset"] <= s and e <= last["offset"] + last["len"] for s, e in ranges)
        summary["compare"] = {
            "differing_bytes": sum(e - s for s, e in ranges),
            "ranges": ranges[:32],
            "final_intent": [last["offset"], last["offset"] + last["len"]] if last else None,
            "complete": not ranges or inside,
        }
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
