// SPDX-License-Identifier: Apache-2.0
use crate::{RAM_BASE, RAM_SIZE, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
fn field(data: &[u8], offset: usize, size: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset.checked_add(size).ok_or("ELF offset overflow")?)
        .ok_or("truncated ELF field")?;
    let mut value = [0; 8];
    value[..size].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}
pub fn load(path: &Path, ram: &mut File, ram_size: u64) -> Result<u64> {
    let mut data = Vec::new();
    File::open(path)?
        .take(RAM_SIZE + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > RAM_SIZE || data.get(..7) != Some(b"\x7fELF\x02\x01\x01") {
        return Err("expected a bounded little-endian ELF64 image".into());
    }
    if field(&data, 16, 2)? != 2 || field(&data, 18, 2)? != 183 || field(&data, 54, 2)? != 56 {
        return Err("expected executable AArch64 ELF".into());
    }
    let entry = field(&data, 24, 8)?;
    let phoff = field(&data, 32, 8)?;
    let count = field(&data, 56, 2)?;
    if count == 0 || phoff.checked_add(count * 56).ok_or("ELF header overflow")? > data.len() as u64
    {
        return Err("invalid program headers".into());
    }
    let mut executable = false;
    let mut ranges = Vec::new();
    for i in 0..count {
        let p = (phoff + i * 56) as usize;
        if field(&data, p, 4)? != 1 {
            continue;
        }
        let flags = field(&data, p + 4, 4)?;
        let offset = field(&data, p + 8, 8)?;
        let va = field(&data, p + 16, 8)?;
        let pa = field(&data, p + 24, 8)?;
        let filesz = field(&data, p + 32, 8)?;
        let memsz = field(&data, p + 40, 8)?;
        let end = pa.checked_add(memsz).ok_or("segment overflow")?;
        let file_end = offset.checked_add(filesz).ok_or("file offset overflow")?;
        if filesz > memsz
            || file_end > data.len() as u64
            || pa < RAM_BASE + 0x20_0000
            || end > RAM_BASE + ram_size
        {
            return Err("segment outside RAM/file or overlapping reserved DTB region".into());
        }
        if ranges
            .iter()
            .any(|&(start, finish)| pa < finish && start < end)
        {
            return Err("overlapping segments".into());
        }
        ranges.push((pa, end));
        if flags & 1 != 0 && entry >= va && entry - va < filesz {
            if va != pa {
                return Err("entry segment must be identity mapped".into());
            }
            executable = true;
        }
        ram.seek(SeekFrom::Start(pa - RAM_BASE))?;
        ram.write_all(&data[offset as usize..file_end as usize])?;
    }
    if !executable || entry & 3 != 0 {
        return Err("entry outside executable bytes".into());
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn elf(pa: u64, memsz: u64) -> Vec<u8> {
        let mut b = vec![0; 124];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (off, size, val) in [
            (16, 2, 2),
            (18, 2, 183),
            (24, 8, pa),
            (32, 8, 64),
            (54, 2, 56),
            (56, 2, 1),
            (64, 4, 1),
            (68, 4, 5),
            (72, 8, 120),
            (80, 8, pa),
            (88, 8, pa),
            (96, 8, 4),
            (104, 8, memsz),
        ] {
            b[off..off + size].copy_from_slice(&val.to_le_bytes()[..size]);
        }
        b
    }
    fn check(bytes: &[u8]) -> Result<u64> {
        let temp = tempfile::tempdir()?;
        let input = temp.path().join("kernel");
        std::fs::write(&input, bytes)?;
        let mut ram = File::create(temp.path().join("ram"))?;
        ram.set_len(RAM_SIZE)?;
        load(&input, &mut ram, RAM_SIZE)
    }
    #[test]
    fn identity_entry() {
        assert_eq!(
            check(&elf(RAM_BASE + 0x400000, 8)).unwrap(),
            RAM_BASE + 0x400000
        );
    }
    #[test]
    fn rejects_truncation() {
        let image = elf(RAM_BASE + 0x400000, 8);
        for n in [0, 6, 40, 63, 119, 123] {
            assert!(check(&image[..n]).is_err());
        }
    }
    #[test]
    fn rejects_guest_ranges() {
        for pa in [RAM_BASE, RAM_BASE + RAM_SIZE - 4, 0x80000000, u64::MAX - 1] {
            assert!(check(&elf(pa, 8)).is_err());
        }
    }
    #[test]
    fn rejects_sizes() {
        assert!(check(&elf(RAM_BASE + 0x400000, 1)).is_err());
    }
    #[test]
    fn rejects_wrong_arch() {
        let mut b = elf(RAM_BASE + 0x400000, 8);
        b[18] = 62;
        assert!(check(&b).is_err());
    }
}

/// Linux AArch64 Image v3.17+ (uncompressed, little endian), entered at EL1.
pub fn linux(
    path: &Path,
    initrd: Option<&Path>,
    ram: &mut File,
    ram_size: u64,
) -> Result<(u64, Option<(u64, u64)>)> {
    let mut data = Vec::new();
    File::open(path)?
        .take(ram_size + 1)
        .read_to_end(&mut data)?;
    if data.len() < 64 || data.len() as u64 > ram_size || data[56..60] != *b"ARM\x64" {
        return Err("expected uncompressed AArch64 Linux Image".into());
    }
    let offset = field(&data, 8, 8)?;
    let size = field(&data, 16, 8)?;
    let flags = field(&data, 24, 8)?;
    if flags & 1 != 0 || size == 0 || offset > ram_size || size < data.len() as u64 {
        return Err("unsupported Linux Image header".into());
    }
    let address = RAM_BASE
        .checked_add(0x200000)
        .and_then(|a| a.checked_add(offset))
        .ok_or("Image offset overflow")?;
    let end = address.checked_add(size).ok_or("Image size overflow")?;
    if end > RAM_BASE + ram_size || address & 3 != 0 {
        return Err("Linux Image outside RAM".into());
    }
    ram.seek(SeekFrom::Start(address - RAM_BASE))?;
    ram.write_all(&data)?;
    let region = if let Some(path) = initrd {
        let mut data = Vec::new();
        File::open(path)?
            .take(ram_size + 1)
            .read_to_end(&mut data)?;
        let len = data.len() as u64;
        if len == 0 || len > ram_size {
            return Err("invalid initrd length".into());
        }
        let start = (RAM_BASE + ram_size - len) & !4095;
        if start < end {
            return Err("initrd overlaps kernel".into());
        }
        ram.seek(SeekFrom::Start(start - RAM_BASE))?;
        ram.write_all(&data)?;
        Some((start, start + len))
    } else {
        None
    };
    Ok((address, region))
}

#[cfg(test)]
mod linux_tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0; 4096];
        b[8..16].copy_from_slice(&0x80000u64.to_le_bytes());
        b[16..24].copy_from_slice(&0x100000u64.to_le_bytes());
        b[56..60].copy_from_slice(b"ARM\x64");
        b
    }
    #[test]
    fn linux_layout_and_initrd() {
        let t = tempfile::tempdir().unwrap();
        let kernel = t.path().join("Image");
        let initrd = t.path().join("initrd");
        std::fs::write(&kernel, image()).unwrap();
        std::fs::write(&initrd, [1, 2, 3, 4]).unwrap();
        let mut ram = File::create(t.path().join("ram")).unwrap();
        let (entry, region) = linux(&kernel, Some(&initrd), &mut ram, 8 << 20).unwrap();
        assert_eq!(entry, RAM_BASE + 0x280000);
        let (start, end) = region.unwrap();
        assert_eq!(start & 4095, 0);
        assert_eq!(end - start, 4);
        assert!(start >= entry + 0x100000);
    }
    #[test]
    fn rejects_bad_linux_headers_and_overlap() {
        let t = tempfile::tempdir().unwrap();
        let kernel = t.path().join("Image");
        let initrd = t.path().join("initrd");
        let mut ram = File::create(t.path().join("ram")).unwrap();
        for (offset, value) in [(16, 0u64), (8, u64::MAX), (24, 1u64)] {
            let mut b = image();
            b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            std::fs::write(&kernel, b).unwrap();
            assert!(linux(&kernel, None, &mut ram, 8 << 20).is_err());
        }
        std::fs::write(&kernel, image()).unwrap();
        std::fs::write(&initrd, vec![0; 6 << 20]).unwrap();
        assert!(linux(&kernel, Some(&initrd), &mut ram, 8 << 20).is_err());
    }
}
