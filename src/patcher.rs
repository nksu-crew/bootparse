// SPDX-License-Identifier: GPL-3.0-or-later
//! Repacking of boot and vendor_boot images with replaced blocks.
//!
//! The replaced sections are re-encoded with the compression they originally
//! used, the header sizes are rewritten and the AVB tail, vbmeta blob and
//! footer are preserved so the flashed image stays structurally valid.  The
//! AVB signature itself cannot survive patching; NekoSU flashes the result
//! without re-signing.

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use zerocopy::IntoBytes;

use crate::bindgen::bindings as boot_head;
use crate::boot::BootVer;
use crate::compress::{CompressFormat, compress, parse_compress_format};
use crate::parse::BootImage;
use crate::utils::{align_to, pad_to, read_struct_at};
use crate::vendor_boot::VendorBootVer;

const AVB_FOOTER_MAGIC: &[u8] = b"AVBf";
const AVB_MAGIC: &[u8] = b"AVB0";
const AVB_FOOTER_SIZE: usize = 64;
const FOOTER_ORIGINAL_IMAGE_SIZE: usize = 12;
const FOOTER_VBMETA_OFFSET: usize = 20;
const FOOTER_VBMETA_SIZE: usize = 28;

struct Avb<'a> {
    tail: Option<&'a [u8]>,
    vbmeta: &'a [u8],
    footer: &'a [u8],
}

/// One patchable block of a boot image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BootBlock {
    Kernel,
    Ramdisk,
    Second,
    RecoveryDtbo,
    Dtb,
    Signature,
}

impl BootBlock {
    fn name(self) -> &'static str {
        match self {
            BootBlock::Kernel => "kernel",
            BootBlock::Ramdisk => "ramdisk",
            BootBlock::Second => "second stage",
            BootBlock::RecoveryDtbo => "recovery dtbo",
            BootBlock::Dtb => "dtb",
            BootBlock::Signature => "signature",
        }
    }

    /// Whether the block exists in the layout of `header`.
    fn is_supported_by(self, header: &BootVer) -> bool {
        match self {
            BootBlock::Kernel | BootBlock::Ramdisk => true,
            BootBlock::Second => !matches!(header, BootVer::V3(_) | BootVer::V4(_)),
            BootBlock::RecoveryDtbo => matches!(header, BootVer::V1(_) | BootVer::V2(_)),
            BootBlock::Dtb => matches!(header, BootVer::V2(_)),
            BootBlock::Signature => matches!(header, BootVer::V4(_)),
        }
    }

    /// Signatures are opaque bytes, everything else keeps its original
    /// compression when replaced.
    fn is_compressed(self) -> bool {
        !matches!(self, BootBlock::Signature)
    }
}

/// Rebuilds a boot image with zero or more blocks replaced.
pub struct BootPatcher<'a> {
    image: &'a BootImage<'a>,
    replacements: HashMap<BootBlock, Vec<u8>>,
}

impl<'a> BootPatcher<'a> {
    pub fn new(image: &'a BootImage<'a>) -> Result<Self> {
        ensure!(
            image.boot().is_some(),
            "only boot images can be patched with BootPatcher"
        );
        Ok(Self {
            image,
            replacements: HashMap::new(),
        })
    }

    /// Replace the kernel with the *uncompressed* payload `data`; the
    /// original compression is reapplied on repack.
    pub fn replace_kernel(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replace_block(BootBlock::Kernel, data)
    }

    /// Replace the ramdisk with the *uncompressed* payload `data`; the
    /// original compression is reapplied on repack.
    pub fn replace_ramdisk(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replace_block(BootBlock::Ramdisk, data)
    }

    /// Replace the second stage bootloader (header v0..v2).
    pub fn replace_second(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replace_block(BootBlock::Second, data)
    }

    /// Replace the recovery DTBO/ACPIO (header v1/v2).
    pub fn replace_recovery_dtbo(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replace_block(BootBlock::RecoveryDtbo, data)
    }

    /// Replace the device tree blob (header v2).
    pub fn replace_dtb(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replace_block(BootBlock::Dtb, data)
    }

    /// Replace the v4 boot signature.  Signatures are stored verbatim, without
    /// compression.
    pub fn replace_signature(&mut self, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replace_block(BootBlock::Signature, data)
    }

    /// Replace any block.  The block must exist in the image's header layout.
    pub fn replace_block(&mut self, block: BootBlock, data: impl Into<Vec<u8>>) -> &mut Self {
        self.replacements.insert(block, data.into());
        self
    }

    /// Repack the image and return the new bytes.
    pub fn patch(&self) -> Result<Vec<u8>> {
        let boot = self.image.boot().context("not a boot image")?;
        let header = boot.header;
        let page = header.page_size();
        let data = self.image.data();
        let header_space = header.header_space();

        for &block in self.replacements.keys() {
            ensure!(
                block.is_supported_by(&header),
                "{} is not present in boot header v{}",
                block.name(),
                header.version()
            );
        }

        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(
            data.get(..header_space)
                .context("truncated boot header")?,
        );

        let replacement = |block: BootBlock| self.replacements.get(&block).map(Vec::as_slice);

        let kernel_size = write_block(
            &mut out,
            page,
            Some(boot.blocks.kernel),
            replacement(BootBlock::Kernel),
            BootBlock::Kernel.is_compressed(),
        )?
        .unwrap_or(0);
        let ramdisk_size = write_block(
            &mut out,
            page,
            Some(boot.blocks.ramdisk),
            replacement(BootBlock::Ramdisk),
            BootBlock::Ramdisk.is_compressed(),
        )?
        .unwrap_or(0);

        let second_size = write_block(
            &mut out,
            page,
            boot.blocks.second,
            replacement(BootBlock::Second),
            BootBlock::Second.is_compressed(),
        )?
        .unwrap_or(0);

        let recovery_dtbo_start = out.len() as u64;
        let recovery_dtbo = write_block(
            &mut out,
            page,
            boot.blocks.recovery_dtbo,
            replacement(BootBlock::RecoveryDtbo),
            BootBlock::RecoveryDtbo.is_compressed(),
        )?;
        let recovery_dtbo_size = recovery_dtbo.unwrap_or(0);

        let dtb_size = write_block(
            &mut out,
            page,
            boot.blocks.dtb,
            replacement(BootBlock::Dtb),
            BootBlock::Dtb.is_compressed(),
        )?
        .unwrap_or(0);

        let signature_size = write_block(
            &mut out,
            page,
            boot.blocks.signature,
            replacement(BootBlock::Signature),
            BootBlock::Signature.is_compressed(),
        )?
        .unwrap_or(0);

        rebuild_avb(&mut out, data, boot_blocks_end(&header), page)?;

        patch_boot_header(
            &mut out,
            &header,
            kernel_size,
            ramdisk_size,
            second_size,
            recovery_dtbo_size,
            recovery_dtbo.is_some(),
            recovery_dtbo_start,
            dtb_size,
            signature_size,
        );

        Ok(out)
    }
}

/// Write one block, re-compressing a replacement with the original format and
/// page-aligning the next block.  `None` means the block is absent.
fn write_block(
    out: &mut Vec<u8>,
    page: usize,
    original: Option<&[u8]>,
    replacement: Option<&[u8]>,
    recompress: bool,
) -> Result<Option<usize>> {
    if original.is_none() && replacement.is_none() {
        return Ok(None);
    }

    let payload: Cow<'_, [u8]> = match replacement {
        Some(data) if recompress => {
            let format = original
                .map(parse_compress_format)
                .unwrap_or(CompressFormat::UNKNOWN);
            Cow::Owned(compress(data, format)?)
        }
        Some(data) => Cow::Borrowed(data),
        None => Cow::Borrowed(original.unwrap_or_default()),
    };

    let size = payload.len();
    out.extend_from_slice(payload.as_ref());
    pad_to(out, page);
    Ok(Some(size))
}

#[allow(clippy::too_many_arguments)]
fn patch_boot_header(
    out: &mut [u8],
    header: &BootVer,
    kernel_size: usize,
    ramdisk_size: usize,
    second_size: usize,
    recovery_dtbo_size: usize,
    recovery_dtbo_present: bool,
    recovery_dtbo_start: u64,
    dtb_size: usize,
    signature_size: usize,
) {
    let mut header = *header;
    match &mut header {
        BootVer::V0(h) => {
            h.kernel_size = kernel_size as u32;
            h.ramdisk_size = ramdisk_size as u32;
            h.second_size = second_size as u32;
        }
        BootVer::V1(h) => {
            h._base.kernel_size = kernel_size as u32;
            h._base.ramdisk_size = ramdisk_size as u32;
            h._base.second_size = second_size as u32;
            h.recovery_dtbo_size = recovery_dtbo_size as u32;
            if recovery_dtbo_present {
                h.recovery_dtbo_offset = recovery_dtbo_start;
            }
        }
        BootVer::V2(h) => {
            h._base._base.kernel_size = kernel_size as u32;
            h._base._base.ramdisk_size = ramdisk_size as u32;
            h._base._base.second_size = second_size as u32;
            h._base.recovery_dtbo_size = recovery_dtbo_size as u32;
            if recovery_dtbo_present {
                h._base.recovery_dtbo_offset = recovery_dtbo_start;
            }
            h.dtb_size = dtb_size as u32;
        }
        BootVer::V3(h) => {
            h.kernel_size = kernel_size as u32;
            h.ramdisk_size = ramdisk_size as u32;
        }
        BootVer::V4(h) => {
            h._base.kernel_size = kernel_size as u32;
            h._base.ramdisk_size = ramdisk_size as u32;
            h.signature_size = signature_size as u32;
        }
    }

    let bytes = match &header {
        BootVer::V0(h) => h.as_bytes(),
        BootVer::V1(h) => h.as_bytes(),
        BootVer::V2(h) => h.as_bytes(),
        BootVer::V3(h) => h.as_bytes(),
        BootVer::V4(h) => h.as_bytes(),
    };
    let end = bytes.len().min(out.len());
    out[..end].copy_from_slice(&bytes[..end]);
}

/// Rebuilds a vendor_boot image with zero or more ramdisks replaced.
pub struct VendorBootPatcher<'a> {
    image: &'a BootImage<'a>,
    replacements: HashMap<usize, Vec<u8>>,
}

impl<'a> VendorBootPatcher<'a> {
    pub fn new(image: &'a BootImage<'a>) -> Result<Self> {
        ensure!(
            image.vendor_boot().is_some(),
            "only vendor_boot images can be patched"
        );
        Ok(Self {
            image,
            replacements: HashMap::new(),
        })
    }

    /// Replace the vendor ramdisk at `index` with the *uncompressed* payload
    /// `data`; the entry's original compression is reapplied on repack.
    pub fn replace_vendor_ramdisk(&mut self, index: usize, data: Vec<u8>) -> &mut Self {
        self.replacements.insert(index, data);
        self
    }

    /// Repack the image and return the new bytes.
    pub fn patch(&self) -> Result<Vec<u8>> {
        let vendor = self
            .image
            .vendor_boot()
            .context("not a vendor_boot image")?;
        let header = vendor.header;
        let page = header.page_size();
        let data = self.image.data();
        let header_space = header.header_space();

        for &index in self.replacements.keys() {
            ensure!(
                index < vendor.ramdisks.len(),
                "invalid vendor ramdisk index {index}"
            );
        }

        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(
            data.get(..header_space)
                .context("truncated vendor_boot header")?,
        );

        // The vendor ramdisk section: keep untouched entries byte-for-byte and
        // recompress the replaced ones with their original format.
        let mut new_entries: Vec<(u32, u32)> = Vec::with_capacity(vendor.ramdisks.len());
        for (index, entry) in vendor.ramdisks.iter().enumerate() {
            let payload = match self.replacements.get(&index) {
                Some(replacement) => compress(replacement, parse_compress_format(entry.data))?,
                None => entry.data.to_vec(),
            };
            new_entries.push(((out.len() - header_space) as u32, payload.len() as u32));
            out.extend_from_slice(&payload);
        }
        let ramdisk_size = (out.len() - header_space) as u32;
        pad_to(&mut out, page);

        out.extend_from_slice(vendor.blocks.dtb);
        pad_to(&mut out, page);

        let mut table_size = 0u32;
        if let Some(table) = vendor.blocks.table {
            let entry_size = header.table_entry_size();
            let table_start = out.len();
            for (index, (offset, size)) in new_entries.iter().enumerate() {
                let mut entry: boot_head::vendor_ramdisk_table_entry_v4 =
                    read_struct_at(table, index * entry_size)
                        .context("truncated vendor ramdisk table")?;
                entry.ramdisk_offset = *offset;
                entry.ramdisk_size = *size;
                out.extend_from_slice(entry.as_bytes());
            }
            table_size = (out.len() - table_start) as u32;
            ensure!(
                table_size == header.table_size() as u32,
                "vendor ramdisk table size changed while repacking"
            );
            pad_to(&mut out, page);
        }

        if let Some(bootconfig) = vendor.blocks.bootconfig {
            out.extend_from_slice(bootconfig);
            pad_to(&mut out, page);
        }

        rebuild_avb(&mut out, data, vendor_blocks_end(&header), page)?;

        // Patch the header's block sizes in place.
        let ramdisk_size_offset =
            core::mem::offset_of!(boot_head::vendor_boot_img_hdr_v3, vendor_ramdisk_size);
        out[ramdisk_size_offset..ramdisk_size_offset + 4]
            .copy_from_slice(&ramdisk_size.to_le_bytes());

        if matches!(header, VendorBootVer::V4(_)) {
            let table_size_offset =
                core::mem::offset_of!(boot_head::vendor_boot_img_hdr_v4, vendor_ramdisk_table_size);
            out[table_size_offset..table_size_offset + 4]
                .copy_from_slice(&table_size.to_le_bytes());
        }

        Ok(out)
    }
}

/// Append the AVB tail, vbmeta blob and footer of the original image to the
/// rebuilt payload, patching the footer's offsets and zero-filling the gap.
fn rebuild_avb(out: &mut Vec<u8>, data: &[u8], blocks_end: usize, page: usize) -> Result<()> {
    let Some(avb) = parse_avb(data, blocks_end) else {
        return Ok(());
    };

    let tail_len = avb.tail.map_or(0, <[u8]>::len);
    let needed = align_to(out.len() + align_to(tail_len, page), 4096)
        + avb.vbmeta.len()
        + AVB_FOOTER_SIZE;
    ensure!(
        needed <= data.len(),
        "no space left for AVB structures (need {needed} bytes, image is {})",
        data.len()
    );

    if let Some(tail) = avb.tail {
        out.extend_from_slice(tail);
        pad_to(out, page);
    }

    let original_image_size = out.len() as u64;
    pad_to(out, 4096);
    let vbmeta_offset = out.len() as u64;
    out.extend_from_slice(avb.vbmeta);

    let zero_end = data.len() - AVB_FOOTER_SIZE;
    let mut footer = avb.footer.to_vec();
    footer[FOOTER_ORIGINAL_IMAGE_SIZE..FOOTER_ORIGINAL_IMAGE_SIZE + 8]
        .copy_from_slice(&original_image_size.to_be_bytes());
    footer[FOOTER_VBMETA_OFFSET..FOOTER_VBMETA_OFFSET + 8]
        .copy_from_slice(&vbmeta_offset.to_be_bytes());

    if out.len() < zero_end {
        out.resize(zero_end, 0);
    }
    ensure!(
        out.len() == zero_end,
        "AVB footer would overlap the patched image"
    );
    out.extend_from_slice(&footer);
    Ok(())
}

/// The offset just past the last block of the original boot image, page-aligned
/// the same way [`BootVer::blocks`] slices them.
fn boot_blocks_end(header: &BootVer) -> usize {
    let page = header.page_size();
    let mut end = header.header_space();
    end = align_to(end + header.kernel_size(), page);
    end = align_to(end + header.ramdisk_size(), page);
    end = align_to(end + header.second_size(), page);
    end = align_to(end + header.recovery_dtbo_size(), page);
    end = align_to(end + header.dtb_size(), page);
    align_to(end + header.signature_size(), page)
}

/// The offset just past the last block of the original image, page-aligned the
/// same way [`VendorBootVer::blocks`] slices them.
fn vendor_blocks_end(header: &VendorBootVer) -> usize {
    let page = header.page_size();
    let mut end = header.header_space();
    end = align_to(end + header.ramdisk_size(), page);
    end = align_to(end + header.dtb_size(), page);
    end = align_to(end + header.table_size(), page);
    align_to(end + header.bootconfig_size(), page)
}

fn parse_avb(data: &[u8], blocks_end: usize) -> Option<Avb<'_>> {
    if data.len() < AVB_FOOTER_SIZE {
        return None;
    }

    let footer = &data[data.len() - AVB_FOOTER_SIZE..];
    if !footer.starts_with(AVB_FOOTER_MAGIC) {
        return None;
    }

    let original_image_size = be_u64(footer, FOOTER_ORIGINAL_IMAGE_SIZE)? as usize;
    let vbmeta_offset = be_u64(footer, FOOTER_VBMETA_OFFSET)? as usize;
    let vbmeta_size = be_u64(footer, FOOTER_VBMETA_SIZE)? as usize;

    let vbmeta = data.get(vbmeta_offset..vbmeta_offset.checked_add(vbmeta_size)?)?;
    if !vbmeta.starts_with(AVB_MAGIC) {
        // Some dumps carry a footer whose vbmeta offset is bogus; leave the
        // AVB metadata alone instead of failing the patch.
        return None;
    }

    let tail = if original_image_size > blocks_end {
        data.get(blocks_end..original_image_size)
    } else {
        None
    };

    Some(Avb {
        tail,
        vbmeta,
        footer,
    })
}

fn be_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}
