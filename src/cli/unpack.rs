// SPDX-License-Identifier: GPL-3.0-or-later
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use bootparse::{
    compress::CompressFormat,
    parse::{Block, BootImage, BootType},
};

#[derive(serde::Serialize)]
struct BootHeaderInfo {
    kind: &'static str,
    version: u32,
    page_size: usize,
    header_size: usize,
    kernel_size: usize,
    ramdisk_size: usize,
    dtb_size: usize,
    kernel_compress: Option<CompressFormat>,
    ramdisk_compress: Option<CompressFormat>,
    dtb_compress: Option<CompressFormat>,
}

#[derive(serde::Serialize)]
struct VendorBootHeaderInfo {
    kind: &'static str,
    version: u32,
    page_size: usize,
    header_size: usize,
    ramdisk_size: usize,
    dtb_size: usize,
    table_entry_num: usize,
    bootconfig_size: usize,
    ramdisk_compress: Option<CompressFormat>,
    dtb_compress: Option<CompressFormat>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vendor_ramdisk_compress: Vec<CompressFormat>,
    bootconfig_compress: Option<CompressFormat>,
}
fn collect_boot_formats(
    img: &BootImage<'_>,
) -> (
    Option<CompressFormat>,
    Option<CompressFormat>,
    Option<CompressFormat>,
) {
    (
        img.kernel().map(|b| b.format()),
        img.ramdisk().map(|b| b.format()),
        img.dtb().map(|b| b.format()),
    )
}

fn collect_vendor_boot_formats(
    img: &BootImage<'_>,
) -> (
    Option<CompressFormat>,
    Option<CompressFormat>,
    Vec<CompressFormat>,
    Option<CompressFormat>,
) {
    let ramdisk = img.ramdisk().map(|b| b.format());
    let dtb = img.dtb().map(|b| b.format());
    let vendor_ramdisk = img
        .ramdisks()
        .map(|rds| rds.iter().map(|rd| Block::new(rd.data).format()).collect())
        .unwrap_or_default();
    let bootconfig = img.bootconfig().map(|b| b.format());
    (ramdisk, dtb, vendor_ramdisk, bootconfig)
}

fn build_boot_header_info(img: &BootImage<'_>) -> BootHeaderInfo {
    let h = &img.boot().unwrap().header;
    let (kernel_c, ramdisk_c, dtb_c) = collect_boot_formats(img);
    BootHeaderInfo {
        kind: "boot",
        version: h.version(),
        page_size: h.page_size(),
        header_size: h.header_size(),
        kernel_size: h.kernel_size(),
        ramdisk_size: h.ramdisk_size(),
        dtb_size: h.dtb_size(),
        kernel_compress: kernel_c,
        ramdisk_compress: ramdisk_c,
        dtb_compress: dtb_c,
    }
}

fn build_vendor_boot_header_info(img: &BootImage<'_>) -> VendorBootHeaderInfo {
    let h = &img.vendor_boot().unwrap().header;
    let (ramdisk_c, dtb_c, vendor_ramdisk_c, bootconfig_c) = collect_vendor_boot_formats(img);
    VendorBootHeaderInfo {
        kind: "vendor_boot",
        version: h.version(),
        page_size: h.page_size(),
        header_size: h.header_size(),
        ramdisk_size: h.ramdisk_size(),
        dtb_size: h.dtb_size(),
        table_entry_num: h.table_entry_num(),
        bootconfig_size: h.bootconfig_size(),
        ramdisk_compress: ramdisk_c,
        dtb_compress: dtb_c,
        vendor_ramdisk_compress: vendor_ramdisk_c,
        bootconfig_compress: bootconfig_c,
    }
}

fn dump_block(dir: &Path, name: &str, block: Block) -> Result<()> {
    if block.is_empty() {
        return Ok(());
    }
    let path = dir.join(name);
    match block.format() {
        CompressFormat::UNKNOWN | CompressFormat::CPIO => {
            fs::write(&path, block.raw()).with_context(|| format!("write {}", path.display()))?;
        }
        _ => {
            let data = block
                .decompress()
                .with_context(|| format!("decompress {name}"))?;
            fs::write(&path, data).with_context(|| format!("write {}", path.display()))?;
        }
    }
    Ok(())
}

fn dump_bytes(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn dump_header_info(img: &BootImage<'_>, dir: &Path) -> Result<()> {
    let bytes = match img.kind() {
        BootType::Boot => serde_json::to_vec_pretty(&build_boot_header_info(img))?,
        BootType::VendorBoot => serde_json::to_vec_pretty(&build_vendor_boot_header_info(img))?,
        BootType::Unknown => unreachable!(),
    };
    dump_bytes(dir, "header.json", &bytes)
}

fn extract_boot(img: &BootImage<'_>, dir: &Path) -> Result<()> {
    if let Some(kernel) = img.kernel() {
        dump_block(dir, "kernel", kernel)?;
    }
    if let Some(ramdisk) = img.ramdisk() {
        dump_block(dir, "ramdisk", ramdisk)?;
    }
    if let Some(dtb) = img.dtb() {
        dump_block(dir, "dtb", dtb)?;
    }
    Ok(())
}

fn extract_vendor_boot(img: &BootImage<'_>, dir: &Path) -> Result<()> {
    if let Some(ramdisks) = img.ramdisks() {
        for rd in ramdisks {
            let file = if rd.name.is_empty() {
                format!("vendor_ramdisk_{}", rd.index)
            } else {
                format!("vendor_ramdisk_{}_{}", rd.index, rd.name)
            };
            dump_block(dir, &file, Block::new(rd.data))?;
        }
    }
    if let Some(dtb) = img.dtb() {
        dump_block(dir, "dtb", dtb)?;
    }
    if let Some(bc) = img.bootconfig() {
        dump_bytes(dir, "bootconfig", bc.raw())?;
    }
    if let Some(vendor) = img.vendor_boot() {
        if let Some(table) = vendor.blocks.table {
            dump_bytes(dir, "vendor_ramdisk_table", table)?;
        }
    }
    Ok(())
}

fn extract_all(img: &BootImage, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    match img.kind() {
        BootType::Boot => extract_boot(img, out_dir),
        BootType::VendorBoot => extract_vendor_boot(img, out_dir),
        BootType::Unknown => unreachable!(),
    }?;

    dump_header_info(img, out_dir)
}

pub fn unpack(path: impl AsRef<Path>, out_dir: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let img =
        BootImage::parse(data.as_ref()).with_context(|| format!("parse {}", path.display()))?;
    extract_all(&img, out_dir.as_ref())
}
