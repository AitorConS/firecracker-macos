// SPDX-License-Identifier: Apache-2.0
use crate::Result;
use vm_fdt::FdtWriter;
pub fn build(
    cpus: u32,
    memory_mib: u32,
    power_button: bool,
    boot_args: Option<&str>,
    initrd: Option<(u64, u64)>,
) -> Result<Vec<u8>> {
    let mut f = FdtWriter::new()?;
    let root = f.begin_node("")?;
    f.property_u32("#address-cells", 2)?;
    f.property_u32("#size-cells", 2)?;
    f.property_string("compatible", "linux,dummy-virt")?;
    let n = f.begin_node("memory@40000000")?;
    f.property_string("device_type", "memory")?;
    f.property_array_u32("reg", &[0, 0x40000000, 0, memory_mib << 20])?;
    f.end_node(n)?;
    let n = f.begin_node("pcie@3f000000")?;
    f.property_string("compatible", "pci-host-ecam-generic")?;
    f.property_string("device_type", "pci")?;
    f.property_u32("#address-cells", 3)?;
    f.property_u32("#size-cells", 2)?;
    f.property_array_u32("reg", &[0, 0x3f000000, 0, 0x1000000])?;
    f.property_array_u32("bus-range", &[0, 15])?;
    f.property_array_u32(
        "ranges",
        &[0x02000000, 0, 0x10000000, 0, 0x10000000, 0, 0x10000000],
    )?;
    f.property_u32("#interrupt-cells", 1)?;
    f.property_array_u32("interrupt-map-mask", &[0x1800, 0, 0, 7])?;
    let mut map = Vec::new();
    for slot in 0..4 {
        for pin in 1..=4 {
            map.extend_from_slice(&[
                slot << 11,
                0,
                0,
                pin,
                1,
                0,
                0,
                0,
                3 + (slot + pin - 1) % 4,
                4,
            ]);
        }
    }
    f.property_array_u32("interrupt-map", &map)?;
    f.end_node(n)?;
    let n = f.begin_node("cpus")?;
    f.property_u32("#address-cells", 1)?;
    f.property_u32("#size-cells", 0)?;
    for i in 0..cpus {
        let c = f.begin_node(&format!("cpu@{i}"))?;
        f.property_string("device_type", "cpu")?;
        f.property_string("compatible", "arm,arm-v8")?;
        f.property_u32("reg", i)?;
        f.property_string("enable-method", "psci")?;
        f.end_node(c)?;
    }
    f.end_node(n)?;
    let n = f.begin_node("psci")?;
    f.property_string("compatible", "arm,psci-0.2")?;
    f.property_string("method", "hvc")?;
    f.end_node(n)?;
    let n = f.begin_node("intc@8000000")?;
    f.property_string("compatible", "arm,gic-v3")?;
    f.property_u32("#interrupt-cells", 3)?;
    f.property_u32("#address-cells", 2)?;
    f.property_u32("#size-cells", 2)?;
    f.property_null("ranges")?;
    f.property_null("interrupt-controller")?;
    f.property_array_u32(
        "reg",
        &[0, 0x08000000, 0, 0x10000, 0, 0x080a0000, 0, cpus * 0x20000],
    )?;
    f.property_phandle(1)?;
    f.end_node(n)?;
    let n = f.begin_node("timer")?;
    f.property_string("compatible", "arm,armv8-timer")?;
    f.property_u32("interrupt-parent", 1)?;
    f.property_array_u32("interrupts", &[1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4])?;
    f.end_node(n)?;
    let n = f.begin_node("clock")?;
    f.property_string("compatible", "fixed-clock")?;
    f.property_u32("#clock-cells", 0)?;
    f.property_u32("clock-frequency", 24000000)?;
    f.property_phandle(2)?;
    f.end_node(n)?;
    let n = f.begin_node("pl011@9000000")?;
    f.property_string_list(
        "compatible",
        vec!["arm,pl011".into(), "arm,primecell".into()],
    )?;
    f.property_array_u32("reg", &[0, 0x09000000, 0, 0x1000])?;
    f.property_array_u32("clocks", &[2, 2])?;
    f.property_string_list("clock-names", vec!["uartclk".into(), "apb_pclk".into()])?;
    f.property_u32("interrupt-parent", 1)?;
    f.property_array_u32("interrupts", &[0, 1, 4])?;
    f.end_node(n)?;
    let n = f.begin_node("fw-cfg@9020000")?;
    f.property_string("compatible", "qemu,fw-cfg-mmio")?;
    f.property_array_u32("reg", &[0, 0x09020000, 0, 0x18])?;
    f.end_node(n)?;
    if power_button {
        let n = f.begin_node("virtio_mmio@9030000")?;
        f.property_string("compatible", "virtio,mmio")?;
        f.property_array_u32("reg", &[0, 0x09030000, 0, 0x1000])?;
        f.property_u32("interrupt-parent", 1)?;
        f.property_array_u32("interrupts", &[0, 8, 4])?;
        f.end_node(n)?;
    }
    let n = f.begin_node("chosen")?;
    f.property_string("stdout-path", "/pl011@9000000")?;
    if let Some(args) = boot_args {
        f.property_string("bootargs", args)?;
    }
    if let Some((start, end)) = initrd {
        f.property_u64("linux,initrd-start", start)?;
        f.property_u64("linux,initrd-end", end)?;
    }
    f.end_node(n)?;
    f.end_node(root)?;
    Ok(f.finish()?)
}
