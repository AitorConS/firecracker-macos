# SPDX-License-Identifier: Apache-2.0
import io
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import run

class LoaderTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'kernel'
            path.write_bytes(data)
            return run.load_elf(path, io.BytesIO())

    def elf(self, pa=0x40400000, memsz=4, filesz=4):
        ident = b'\x7fELF\x02\x01\x01' + bytes(9)
        header = struct.pack('<HHIQQQIHHHHHH', 2, 183, 1, pa, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        ph = struct.pack('<IIQQQQQQ', 1, 5, 120, pa, pa, filesz, memsz, 4)
        return ident + header + ph + b'\x02\x00\x00\xd4'

    def test_valid_identity_entry(self):
        self.assertEqual(self.load(self.elf()), 0x40400000)

    def test_reject_truncated_and_wrong_arch(self):
        for data in [b'bad', self.elf()[:100], self.elf()[:18] + b'\x3e\x00' + self.elf()[20:]]:
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                self.load(data)

    def test_reject_out_of_ram_and_dtb_overlap(self):
        for pa in [0x80000000, 0x40000000, 0x47fffffc]:
            with self.subTest(pa=pa), self.assertRaises(ValueError):
                self.load(self.elf(pa=pa, memsz=8))

    def test_reject_filesz_larger_than_memsz(self):
        with self.assertRaises(ValueError):
            self.load(self.elf(memsz=1))

class HVFTests(unittest.TestCase):
    def test_native_guest_uart_and_shutdown(self):
        result = subprocess.run(['python3', str(run.HERE / 'run.py')], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'H')
        self.assertIn('PSCI SYSTEM_OFF', result.stderr)

if __name__ == '__main__':
    unittest.main()
