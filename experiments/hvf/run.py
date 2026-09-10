#!/usr/bin/env python3
"""Create an isolated RAM image and run a bounded HVF bring-up experiment."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile

BASE = 0x40000000
SIZE = 128 << 20
HERE = Path(__file__).resolve().parent

def load_elf(path, ram):
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('expected little-endian ELF64')
    fields = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, _, entry, phoff, _, _, _, phsize, phnum, *_ = fields
    if kind != 2 or machine != 183 or phsize != 56 or phnum == 0 or phoff + phsize * phnum > len(data):
        raise ValueError('expected executable AArch64 ELF with valid program headers')
    executable_entry = False
    ranges = []
    for n in range(phnum):
        typ, flags, off, va, pa, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + n * phsize)
        if typ != 1:
            continue
        if filesz > memsz or off + filesz > len(data) or pa < BASE + 0x200000 or pa + memsz > BASE + SIZE:
            raise ValueError('invalid segment or overlap with reserved DTB/page-table region')
        if any(pa < end and start < pa + memsz for start, end in ranges):
            raise ValueError('overlapping ELF segments')
        ranges.append((pa, pa + memsz))
        if flags & 1 and va <= entry < va + filesz:
            if va != pa:
                raise ValueError('probe requires identity-mapped entry segment')
            executable_entry = True
        ram.seek(pa - BASE)
        ram.write(data[off:off + filesz])
    if not executable_entry or entry & 3:
        raise ValueError('entry is not inside executable file bytes')
    return entry

DTS = '''/dts-v1/;
/ {
    #address-cells = <2>; #size-cells = <2>; compatible = "linux,dummy-virt";
    memory@40000000 { device_type = "memory"; reg = <0 0x40000000 0 0x08000000>; };
    pcie@3f000000 { compatible = "pci-host-ecam-generic"; device_type = "pci";
        #address-cells = <3>; #size-cells = <2>; reg = <0 0x3f000000 0 0x1000000>;
        bus-range = <0 15>; ranges = <0x02000000 0 0x10000000 0 0x10000000 0 0x10000000>;
    };
    cpus { #address-cells = <1>; #size-cells = <0>;
        cpu@0 { device_type = "cpu"; compatible = "arm,arm-v8"; reg = <0>; enable-method = "psci"; };
    };
    psci { compatible = "arm,psci-0.2"; method = "hvc"; };
    intc@8000000 { compatible = "arm,gic-v3"; #interrupt-cells = <3>;
        #address-cells = <2>; #size-cells = <2>; ranges;
        interrupt-controller; reg = <0 0x08000000 0 0x10000>, <0 0x080a0000 0 0x20000>;
        phandle = <1>;
    };
    timer { compatible = "arm,armv8-timer"; interrupt-parent = <1>;
        interrupts = <1 13 4>, <1 14 4>, <1 11 4>, <1 10 4>; };
    pl011@9000000 { compatible = "arm,pl011", "arm,primecell";
        reg = <0 0x09000000 0 0x1000>; };
    chosen { stdout-path = "/pl011@9000000"; };
};
'''

def device_tree(cpus=1):
    if not 1 <= cpus <= 4:
        raise ValueError('supported vCPU range: 1..4')
    extra=''.join(f'cpu@{i} {{ device_type = "cpu"; compatible = "arm,arm-v8"; reg = <{i}>; enable-method = "psci"; }};\n' for i in range(1,cpus))
    return DTS.replace('    psci {', '    psci {').replace('    };\n    psci', extra+'    };\n    psci').replace('0x080a0000 0 0x20000',f'0x080a0000 0 0x{cpus*0x20000:x}')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, help='AArch64 ELF; omitted for synthetic HVF test')
    parser.add_argument("--cpus",type=int,choices=range(1,5),default=1)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vmm-hvf-') as tmp:
        tmp = Path(tmp)
        image = tmp / 'ram.bin'
        with image.open('w+b') as ram:
            ram.truncate(SIZE)
            if args.kernel:
                entry = load_elf(args.kernel, ram)
                dts = tmp / 'guest.dts'
                dts.write_text(device_tree(args.cpus))
                dtb = tmp / 'guest.dtb'
                subprocess.run(['/opt/homebrew/bin/dtc', '-I', 'dts', '-O', 'dtb', '-o', str(dtb), str(dts)], check=True)
                blob = dtb.read_bytes()
                if len(blob) > 0x200000:
                    raise ValueError('DTB exceeds reserved region')
                ram.seek(0)
                ram.write(blob)
            else:
                entry = BASE + 0x400000
                # mov x1, #0x09000000; mov w0, #72; str w0,[x1]
                # mov w0,#8; movk w0,#0x8400,lsl#16; hvc #0
                words = [0xd2a12001, 0x52800900, 0xb9000020, 0x52800100, 0x72b08000, 0xd4000002]
                ram.seek(entry - BASE)
                ram.write(struct.pack('<6I', *words))
        command = [str(HERE / 'build/hvf-probe'), str(image), f'{entry:x}']
        try:
            import os
            result = subprocess.run(command, timeout=15,env={**os.environ,"HVF_CPUS":str(args.cpus)})
        except subprocess.TimeoutExpired:
            print('HVF probe exceeded 15 seconds (guest progress is not a successful boot)', flush=True)
            return 124
        return result.returncode

if __name__ == '__main__':
    raise SystemExit(main())
