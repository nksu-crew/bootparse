// SPDX-License-Identifier: GPL-3.0-or-later
//! Round-trip tests for image parsing, cpio handling and vendor_boot patching.
//!
//! The images are assembled here from the on-disk layout documented in the
//! AOSP `bootimg.h`, independently of the bindgen structs the parser uses.

use bootparse::BootVer;
use bootparse::compress::{CompressFormat, compress, decompress};
use bootparse::cpio::{Cpio, CpioEntry};
use bootparse::parse::BootImage;
use bootparse::patcher::{BootBlock, BootPatcher, VendorBootPatcher};

const PAGE: usize = 4096;

fn pad_to_page(buf: &mut Vec<u8>) {
    while buf.len() % PAGE != 0 {
        buf.push(0);
    }
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn sample_cpio(extra: &str) -> Vec<u8> {
    let mut cpio = Cpio::new();
    cpio.add("init", CpioEntry::regular(0o755, b"init".to_vec()))
        .unwrap();
    cpio.add("lib", CpioEntry::dir(0o755)).unwrap();
    cpio.add("lib/modules", CpioEntry::dir(0o755)).unwrap();
    cpio.add(
        "lib/modules/modules.load",
        CpioEntry::regular(0o644, extra.as_bytes().to_vec()),
    )
    .unwrap();
    cpio.dump()
}

/// v4 vendor_boot image with `ramdisks` as the vendor ramdisk section.
fn build_vendor_boot_v4(ramdisks: &[Vec<u8>], dtb: &[u8], bootconfig: &[u8], avb: bool) -> Vec<u8> {
    let mut section = Vec::new();
    let mut table = Vec::new();

    for (index, ramdisk) in ramdisks.iter().enumerate() {
        table.extend_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        table.extend_from_slice(&(section.len() as u32).to_le_bytes());
        table.extend_from_slice(&1u32.to_le_bytes()); // VENDOR_RAMDISK_TYPE_PLATFORM
        let mut name = [0u8; 32];
        let text = format!("ramdisk{index}");
        name[..text.len()].copy_from_slice(text.as_bytes());
        table.extend_from_slice(&name);
        table.extend_from_slice(&[0u8; 64]); // board_id
        section.extend_from_slice(ramdisk);
    }

    let mut image = vec![0u8; PAGE];
    image.extend_from_slice(&section);
    pad_to_page(&mut image);
    image.extend_from_slice(dtb);
    pad_to_page(&mut image);
    let table_offset = image.len();
    image.extend_from_slice(&table);
    pad_to_page(&mut image);
    let bootconfig_offset = image.len();
    image.extend_from_slice(bootconfig);
    pad_to_page(&mut image);

    image[0..8].copy_from_slice(b"VNDRBOOT");
    put_u32(&mut image, 8, 4); // header_version
    put_u32(&mut image, 12, PAGE as u32); // page_size
    put_u32(&mut image, 16, 0x1000_0000); // kernel_addr
    put_u32(&mut image, 20, 0x1100_0000); // ramdisk_addr
    put_u32(&mut image, 24, section.len() as u32); // vendor_ramdisk_size
    put_u32(&mut image, 2076, 0x1000_1000); // tags_addr
    put_u32(&mut image, 2096, 2128); // header_size
    put_u32(&mut image, 2100, dtb.len() as u32); // dtb_size
    put_u64(&mut image, 2104, 0x1200_0000); // dtb_addr
    put_u32(&mut image, 2112, table.len() as u32); // vendor_ramdisk_table_size
    put_u32(&mut image, 2116, ramdisks.len() as u32); // entry_num
    put_u32(&mut image, 2120, 108); // entry_size
    put_u32(&mut image, 2124, bootconfig.len() as u32); // bootconfig_size

    let _ = table_offset;
    let _ = bootconfig_offset;

    if avb {
        append_avb(&mut image, 256);
    }
    image
}

fn append_avb(image: &mut Vec<u8>, vbmeta_size: usize) {
    let original_image_size = image.len();
    let vbmeta_offset = (image.len() + PAGE - 1) / PAGE * PAGE;

    image.resize(vbmeta_offset, 0);
    image.extend_from_slice(b"AVB0");
    image.resize(vbmeta_offset + vbmeta_size, 0);
    // Slack so the patched payload still fits before the vbmeta blob.
    image.resize(image.len() + 4 * PAGE, 0);

    let mut footer = [0u8; 64];
    footer[0..4].copy_from_slice(b"AVBf");
    footer[12..20].copy_from_slice(&(original_image_size as u64).to_be_bytes());
    footer[20..28].copy_from_slice(&(vbmeta_offset as u64).to_be_bytes());
    footer[28..36].copy_from_slice(&(vbmeta_size as u64).to_be_bytes());
    image.extend_from_slice(&footer);
}

/// v3 vendor_boot image with a single ramdisk.
fn build_vendor_boot_v3(ramdisk: &[u8], dtb: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; PAGE];
    image.extend_from_slice(ramdisk);
    pad_to_page(&mut image);
    image.extend_from_slice(dtb);
    pad_to_page(&mut image);

    image[0..8].copy_from_slice(b"VNDRBOOT");
    put_u32(&mut image, 8, 3);
    put_u32(&mut image, 12, PAGE as u32);
    put_u32(&mut image, 24, ramdisk.len() as u32);
    put_u32(&mut image, 2096, 2112);
    put_u32(&mut image, 2100, dtb.len() as u32);
    put_u64(&mut image, 2104, 0x1200_0000);
    image
}

/// v3 boot image with a gzip kernel and a gzip ramdisk.
fn build_boot_v3(kernel: &[u8], ramdisk: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; PAGE];
    image.extend_from_slice(kernel);
    pad_to_page(&mut image);
    image.extend_from_slice(ramdisk);
    pad_to_page(&mut image);

    image[0..8].copy_from_slice(b"ANDROID!");
    put_u32(&mut image, 8, kernel.len() as u32);
    put_u32(&mut image, 12, ramdisk.len() as u32);
    put_u32(&mut image, 20, 1580); // header_size
    put_u32(&mut image, 40, 3); // header_version
    image
}

fn page_align(n: usize) -> usize {
    (n + PAGE - 1) / PAGE * PAGE
}

/// v4 boot image with an optional AVB tail/vbmeta/footer.
fn build_boot_v4(kernel: &[u8], ramdisk: &[u8], signature: &[u8], avb: bool) -> Vec<u8> {
    let mut image = vec![0u8; PAGE];
    image.extend_from_slice(kernel);
    pad_to_page(&mut image);
    image.extend_from_slice(ramdisk);
    pad_to_page(&mut image);
    image.extend_from_slice(signature);
    pad_to_page(&mut image);

    image[0..8].copy_from_slice(b"ANDROID!");
    put_u32(&mut image, 8, kernel.len() as u32);
    put_u32(&mut image, 12, ramdisk.len() as u32);
    put_u32(&mut image, 20, 1584); // header_size
    put_u32(&mut image, 40, 4); // header_version
    put_u32(&mut image, 1580, signature.len() as u32);

    if avb {
        append_avb(&mut image, 256);
    }
    image
}

/// v2 boot image with every optional block populated.
fn build_boot_v2(
    kernel: &[u8],
    ramdisk: &[u8],
    second: &[u8],
    recovery_dtbo: &[u8],
    dtb: &[u8],
) -> Vec<u8> {
    let mut image = vec![0u8; PAGE];
    image.extend_from_slice(kernel);
    pad_to_page(&mut image);
    image.extend_from_slice(ramdisk);
    pad_to_page(&mut image);
    image.extend_from_slice(second);
    pad_to_page(&mut image);
    let recovery_offset = image.len();
    image.extend_from_slice(recovery_dtbo);
    pad_to_page(&mut image);
    image.extend_from_slice(dtb);
    pad_to_page(&mut image);

    image[0..8].copy_from_slice(b"ANDROID!");
    put_u32(&mut image, 8, kernel.len() as u32);
    put_u32(&mut image, 16, ramdisk.len() as u32);
    put_u32(&mut image, 24, second.len() as u32);
    put_u32(&mut image, 36, PAGE as u32); // page_size
    put_u32(&mut image, 40, 2); // header_version
    put_u32(&mut image, 1632, recovery_dtbo.len() as u32);
    put_u64(&mut image, 1636, recovery_offset as u64);
    put_u32(&mut image, 1644, 1664); // header_size
    put_u32(&mut image, 1648, dtb.len() as u32);
    image
}

/// v1 boot image with a 2048-byte page size.
fn build_boot_v1(
    kernel: &[u8],
    ramdisk: &[u8],
    second: &[u8],
    recovery_dtbo: &[u8],
) -> Vec<u8> {
    const V1_PAGE: usize = 2048;
    fn pad(buf: &mut Vec<u8>) {
        while buf.len() % V1_PAGE != 0 {
            buf.push(0);
        }
    }

    let mut image = vec![0u8; V1_PAGE];
    image.extend_from_slice(kernel);
    pad(&mut image);
    image.extend_from_slice(ramdisk);
    pad(&mut image);
    image.extend_from_slice(second);
    pad(&mut image);
    let recovery_offset = image.len();
    image.extend_from_slice(recovery_dtbo);
    pad(&mut image);

    image[0..8].copy_from_slice(b"ANDROID!");
    put_u32(&mut image, 8, kernel.len() as u32);
    put_u32(&mut image, 16, ramdisk.len() as u32);
    put_u32(&mut image, 24, second.len() as u32);
    put_u32(&mut image, 36, V1_PAGE as u32); // page_size
    put_u32(&mut image, 40, 1); // header_version
    put_u32(&mut image, 1632, recovery_dtbo.len() as u32);
    put_u64(&mut image, 1636, recovery_offset as u64);
    put_u32(&mut image, 1644, 1648); // header_size
    image
}

#[test]
fn cpio_round_trip() {
    let archive = sample_cpio("nksu.ko\n");
    let cpio = Cpio::load_from_data(&archive).unwrap();

    assert!(cpio.exists("lib/modules"));
    assert_eq!(
        cpio.get("lib/modules/modules.load").unwrap().data(),
        Some(b"nksu.ko\n".as_slice())
    );
    assert!(cpio.get("lib/modules").unwrap().is_dir());

    let reparsed = Cpio::load_from_data(&cpio.dump()).unwrap();
    assert_eq!(reparsed.entries().len(), cpio.entries().len());
}

#[test]
fn cpio_concatenated_archives_are_merged() {
    let mut data = sample_cpio("first\n");
    data.extend_from_slice(&sample_cpio("second\n"));

    let cpio = Cpio::load_from_data(&data).unwrap();
    assert_eq!(
        cpio.get("lib/modules/modules.load").unwrap().data(),
        Some(b"second\n".as_slice())
    );
}

#[test]
fn vendor_boot_v4_parses_its_table() {
    let ramdisks = vec![
        compress(&sample_cpio("a\n"), CompressFormat::GZIP).unwrap(),
        b"not-a-cpio".to_vec(),
    ];
    let image = build_vendor_boot_v4(&ramdisks, b"dtb", b"bootconfig", false);

    let parsed = BootImage::parse(&image).unwrap();
    assert_eq!(parsed.vendor_boot_version(), Some(4));

    let entries = parsed.ramdisks().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "ramdisk0");
    assert_eq!(entries[0].format(), CompressFormat::GZIP);
    assert_eq!(entries[0].decompress().unwrap(), sample_cpio("a\n"));
    assert_eq!(entries[1].data, b"not-a-cpio");
}

#[test]
fn vendor_boot_v4_patch_rewrites_table_and_keeps_other_blocks() {
    let original = vec![
        compress(&sample_cpio("a\n"), CompressFormat::GZIP).unwrap(),
        b"second".to_vec(),
    ];
    let image = build_vendor_boot_v4(&original, b"dtb-payload", b"bootconfig", false);

    let replacement = sample_cpio("replaced\n");
    let boot = BootImage::parse(&image).unwrap();
    let mut patcher = VendorBootPatcher::new(&boot).unwrap();
    patcher.replace_vendor_ramdisk(0, replacement.clone());
    let patched = patcher.patch().unwrap();

    let parsed = BootImage::parse(&patched).unwrap();
    let entries = parsed.ramdisks().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].decompress().unwrap(), replacement);
    assert_eq!(entries[1].data, b"second");
    assert_eq!(parsed.dtb().unwrap().raw(), b"dtb-payload");
    assert_eq!(parsed.bootconfig().unwrap().raw(), b"bootconfig");
    // The untouched entry is copied verbatim; the replaced one is recompressed
    // with its original format.
    assert_eq!(entries[0].format(), CompressFormat::GZIP);
}

#[test]
fn vendor_boot_v3_patch_replaces_the_single_ramdisk() {
    let original = compress(&sample_cpio("v3\n"), CompressFormat::GZIP).unwrap();
    let image = build_vendor_boot_v3(&original, b"dtb3");

    let replacement = sample_cpio("v3-replaced\n");
    let boot = BootImage::parse(&image).unwrap();
    let mut patcher = VendorBootPatcher::new(&boot).unwrap();
    patcher.replace_vendor_ramdisk(0, replacement.clone());
    let patched = patcher.patch().unwrap();

    let parsed = BootImage::parse(&patched).unwrap();
    let entries = parsed.ramdisks().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].decompress().unwrap(), replacement);
    assert_eq!(parsed.dtb().unwrap().raw(), b"dtb3");
}

#[test]
fn vendor_boot_patch_preserves_avb_structures() {
    let ramdisk = compress(&sample_cpio("avb\n"), CompressFormat::GZIP).unwrap();
    let image = build_vendor_boot_v4(&[ramdisk], b"dtb", b"", true);

    let replacement = sample_cpio("avb-replaced\n");
    let boot = BootImage::parse(&image).unwrap();
    let mut patcher = VendorBootPatcher::new(&boot).unwrap();
    patcher.replace_vendor_ramdisk(0, replacement.clone());
    let patched = patcher.patch().unwrap();

    assert_eq!(patched.len(), image.len());

    let footer = &patched[patched.len() - 64..];
    assert!(footer.starts_with(b"AVBf"));
    let vbmeta_offset = u64::from_be_bytes(footer[20..28].try_into().unwrap()) as usize;
    assert!(patched[vbmeta_offset..].starts_with(b"AVB0"));
    let original_image_size = u64::from_be_bytes(footer[12..20].try_into().unwrap()) as usize;
    assert!(original_image_size <= vbmeta_offset);

    let parsed = BootImage::parse(&patched).unwrap();
    assert_eq!(
        parsed.ramdisks().unwrap()[0].decompress().unwrap(),
        replacement
    );
}

#[test]
fn boot_image_kernel_is_decompressed() {
    let kernel = b"kernel payload".repeat(64);
    let compressed = compress(&kernel, CompressFormat::GZIP).unwrap();
    let image = build_boot_v3(&compressed, b"ramdisk");

    let parsed = BootImage::parse(&image).unwrap();
    assert_eq!(parsed.boot_version(), Some(3));
    assert_eq!(parsed.kernel().unwrap().format(), CompressFormat::GZIP);
    assert_eq!(parsed.kernel().unwrap().decompress().unwrap(), kernel);
    assert_eq!(decompress(parsed.kernel().unwrap().raw()).unwrap(), kernel);
}

#[test]
fn boot_patcher_replaces_kernel_and_ramdisk() {
    let kernel = b"kernel payload ".repeat(64);
    let ramdisk = sample_cpio("original\n");
    let image = build_boot_v3(
        &compress(&kernel, CompressFormat::GZIP).unwrap(),
        &compress(&ramdisk, CompressFormat::GZIP).unwrap(),
    );

    let replacement_kernel = b"replacement kernel ".repeat(32);
    let replacement_ramdisk = sample_cpio("replacement\n");
    let parsed = BootImage::parse(&image).unwrap();
    let mut patcher = BootPatcher::new(&parsed).unwrap();
    patcher.replace_kernel(replacement_kernel.clone());
    patcher.replace_ramdisk(replacement_ramdisk.clone());
    let patched = patcher.patch().unwrap();

    let parsed = BootImage::parse(&patched).unwrap();
    assert_eq!(parsed.boot_version(), Some(3));
    let kernel = parsed.kernel().unwrap();
    assert_eq!(kernel.format(), CompressFormat::GZIP);
    assert_eq!(kernel.decompress().unwrap(), replacement_kernel);
    let ramdisk = parsed.ramdisk().unwrap();
    assert_eq!(ramdisk.format(), CompressFormat::GZIP);
    assert_eq!(ramdisk.decompress().unwrap(), replacement_ramdisk);
}

#[test]
fn boot_patcher_noop_reproduces_the_image() {
    let image = build_boot_v3(
        &compress(b"kernel", CompressFormat::GZIP).unwrap(),
        &compress(&sample_cpio("noop\n"), CompressFormat::GZIP).unwrap(),
    );
    let parsed = BootImage::parse(&image).unwrap();
    let patched = BootPatcher::new(&parsed).unwrap().patch().unwrap();
    assert_eq!(patched, image);

    let image = build_boot_v4(
        &compress(b"kernel", CompressFormat::GZIP).unwrap(),
        &compress(&sample_cpio("noop avb\n"), CompressFormat::GZIP).unwrap(),
        b"signature",
        true,
    );
    let parsed = BootImage::parse(&image).unwrap();
    let patched = BootPatcher::new(&parsed).unwrap().patch().unwrap();
    assert_eq!(patched, image);
}

#[test]
fn boot_patcher_replaces_v2_optional_blocks() {
    let kernel = b"kernel payload ".repeat(32);
    let ramdisk = sample_cpio("v2\n");
    let image = build_boot_v2(
        &compress(&kernel, CompressFormat::GZIP).unwrap(),
        &compress(&ramdisk, CompressFormat::GZIP).unwrap(),
        &compress(b"second", CompressFormat::GZIP).unwrap(),
        b"recovery-dtbo",
        b"dtb",
    );

    let replacement_kernel = b"replacement kernel ".repeat(20);
    let replacement_second = b"replacement second ".repeat(3);
    let replacement_recovery = b"replacement recovery dtbo ".repeat(2);
    let replacement_dtb = b"replacement dtb ".repeat(2);
    let parsed = BootImage::parse(&image).unwrap();
    let mut patcher = BootPatcher::new(&parsed).unwrap();
    patcher.replace_kernel(replacement_kernel.clone());
    patcher.replace_second(replacement_second.clone());
    patcher.replace_recovery_dtbo(replacement_recovery.clone());
    patcher.replace_dtb(replacement_dtb.clone());
    let patched = patcher.patch().unwrap();

    let parsed = BootImage::parse(&patched).unwrap();
    assert_eq!(parsed.boot_version(), Some(2));
    assert_eq!(
        parsed.kernel().unwrap().decompress().unwrap(),
        replacement_kernel
    );
    let boot = parsed.boot().unwrap();
    let second = boot.blocks.second.unwrap();
    assert_eq!(
        bootparse::compress::parse_compress_format(second),
        CompressFormat::GZIP
    );
    assert_eq!(decompress(second).unwrap(), replacement_second);
    assert_eq!(boot.blocks.recovery_dtbo.unwrap(), replacement_recovery);
    assert_eq!(boot.blocks.dtb.unwrap(), replacement_dtb);

    // The recovery dtbo offset follows the block when earlier sizes change.
    let header = boot.header;
    let expected_offset = header.header_space()
        + page_align(header.kernel_size())
        + page_align(header.ramdisk_size())
        + page_align(header.second_size());
    let BootVer::V2(raw) = header else {
        panic!("expected a v2 header");
    };
    let recovery_dtbo_offset = raw._base.recovery_dtbo_offset;
    assert_eq!(recovery_dtbo_offset, expected_offset as u64);
}

#[test]
fn boot_patcher_handles_v1_headers_and_2048_byte_pages() {
    let image = build_boot_v1(
        &compress(b"kernel v1", CompressFormat::GZIP).unwrap(),
        &compress(&sample_cpio("v1\n"), CompressFormat::GZIP).unwrap(),
        &compress(b"second v1", CompressFormat::GZIP).unwrap(),
        b"recovery v1",
    );

    let replacement_kernel = b"replacement v1 kernel ".repeat(3);
    let replacement_recovery = b"replacement v1 recovery ".repeat(3);
    let parsed = BootImage::parse(&image).unwrap();
    assert_eq!(parsed.boot_version(), Some(1));
    let mut patcher = BootPatcher::new(&parsed).unwrap();
    patcher.replace_kernel(replacement_kernel.clone());
    patcher.replace_recovery_dtbo(replacement_recovery.clone());
    let patched = patcher.patch().unwrap();

    let parsed = BootImage::parse(&patched).unwrap();
    assert_eq!(parsed.boot_version(), Some(1));
    assert_eq!(
        parsed.kernel().unwrap().decompress().unwrap(),
        replacement_kernel
    );
    let boot = parsed.boot().unwrap();
    assert_eq!(boot.blocks.recovery_dtbo.unwrap(), replacement_recovery);
    assert_eq!(boot.header.page_size(), 2048);
}

#[test]
fn boot_patcher_replaces_v4_signature_and_keeps_avb() {
    let image = build_boot_v4(
        &compress(b"kernel", CompressFormat::GZIP).unwrap(),
        &compress(&sample_cpio("v4\n"), CompressFormat::GZIP).unwrap(),
        b"signature-original",
        true,
    );

    let replacement_kernel = b"replacement v4 kernel ".repeat(4);
    let replacement_signature = b"signature-replacement";
    let parsed = BootImage::parse(&image).unwrap();
    let mut patcher = BootPatcher::new(&parsed).unwrap();
    patcher.replace_kernel(replacement_kernel.clone());
    patcher.replace_signature(replacement_signature.to_vec());
    let patched = patcher.patch().unwrap();

    assert_eq!(patched.len(), image.len());
    let footer = &patched[patched.len() - 64..];
    assert!(footer.starts_with(b"AVBf"));
    let vbmeta_offset = u64::from_be_bytes(footer[20..28].try_into().unwrap()) as usize;
    assert!(patched[vbmeta_offset..].starts_with(b"AVB0"));

    let parsed = BootImage::parse(&patched).unwrap();
    assert_eq!(
        parsed.kernel().unwrap().decompress().unwrap(),
        replacement_kernel
    );
    assert_eq!(
        parsed.boot().unwrap().blocks.signature.unwrap(),
        replacement_signature
    );
}

#[test]
fn boot_patcher_rejects_blocks_missing_from_the_header() {
    let image = build_boot_v3(
        &compress(b"kernel", CompressFormat::GZIP).unwrap(),
        &compress(&sample_cpio("reject\n"), CompressFormat::GZIP).unwrap(),
    );
    let parsed = BootImage::parse(&image).unwrap();
    let mut patcher = BootPatcher::new(&parsed).unwrap();
    patcher.replace_dtb(b"not supported in v3".to_vec());
    assert!(patcher.patch().is_err());

    let vendor = build_vendor_boot_v3(b"ramdisk", b"dtb");
    let parsed = BootImage::parse(&vendor).unwrap();
    assert!(BootPatcher::new(&parsed).is_err());

    let parsed = BootImage::parse(&image).unwrap();
    let mut patcher = BootPatcher::new(&parsed).unwrap();
    patcher.replace_block(BootBlock::Second, b"not supported in v3".to_vec());
    assert!(patcher.patch().is_err());
}

#[test]
fn every_supported_format_round_trips() {
    let payload = b"nekosu ramdisk payload".repeat(200);
    let mut formats = vec![
        CompressFormat::GZIP,
        CompressFormat::XZ,
        CompressFormat::LZMA,
        CompressFormat::BZIP2,
        CompressFormat::LZ4,
        CompressFormat::LZ4_LEGACY,
    ];
    #[cfg(feature = "experimental")]
    formats.push(CompressFormat::LZOP);

    for format in formats {
        let compressed = compress(&payload, format).unwrap();
        assert_eq!(
            bootparse::compress::parse_compress_format(&compressed),
            format,
            "detection failed for {format:?}"
        );
        assert_eq!(decompress(&compressed).unwrap(), payload, "{format:?}");
    }
}

#[cfg(feature = "experimental")]
#[test]
fn lzop_round_trips() {
    let payload = b"nekosu lzop payload ".repeat(500);
    let compressed = compress(&payload, CompressFormat::LZOP).unwrap();

    assert_eq!(
        bootparse::compress::parse_compress_format(&compressed),
        CompressFormat::LZOP
    );
    assert!(compressed.starts_with(b"\x89LZO"));
    assert_eq!(decompress(&compressed).unwrap(), payload);
}

/// Cross-checks both directions against the reference `lzop` tool.  Skipped
/// when the tool is not installed (CI only needs the self-contained tests).
#[cfg(feature = "experimental")]
#[test]
fn lzop_interops_with_the_reference_tool() {
    let payload = b"nekosu lzop interop payload ".repeat(2000);
    let compressed = compress(&payload, CompressFormat::LZOP).unwrap();

    let dir = std::env::temp_dir().join(format!("bootparse-lzop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lzo_path = dir.join("ours.lzo");
    let bin_path = dir.join("plain.bin");
    std::fs::write(&lzo_path, &compressed).unwrap();
    std::fs::write(&bin_path, &payload).unwrap();

    // What we write must be readable by the reference decompressor.
    let decoded = match std::process::Command::new("lzop")
        .arg("-d")
        .arg("-c")
        .arg(&lzo_path)
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };
    assert!(
        decoded.status.success(),
        "lzop -d: {}",
        String::from_utf8_lossy(&decoded.stderr)
    );
    assert_eq!(decoded.stdout, payload);

    // What the reference compressor writes must be readable by us.
    let encoded = std::process::Command::new("lzop")
        .arg("-c")
        .arg(&bin_path)
        .output()
        .unwrap();
    assert!(encoded.status.success());
    assert_eq!(decompress(&encoded.stdout).unwrap(), payload);

    let _ = std::fs::remove_dir_all(&dir);
}
