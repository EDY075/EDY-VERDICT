fn main() {
    generate_foundation_icon().expect("Foundation build icon must be generated");
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["foundation_status"])),
    )
    .expect("Foundation Tauri configuration must be valid");
}

// Windows requires an ICO resource even for --no-bundle. Generate a tiny, plain
// technical placeholder from code: no downloaded image or imaging dependency.
fn generate_foundation_icon() -> std::io::Result<()> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".generated");
    let destination = directory.join("foundation.ico");
    let mut bytes = Vec::new();
    // ICONDIR, one 16x16, 32-bit DIB entry, 1128-byte bitmap at offset 22.
    bytes.extend_from_slice(&[0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0]);
    bytes.extend_from_slice(&1128_u32.to_le_bytes());
    bytes.extend_from_slice(&22_u32.to_le_bytes());
    bytes.extend_from_slice(&40_u32.to_le_bytes());
    bytes.extend_from_slice(&16_i32.to_le_bytes());
    bytes.extend_from_slice(&32_i32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&32_u16.to_le_bytes());
    bytes.extend_from_slice(&[0; 24]);
    for _ in 0..256 {
        bytes.extend_from_slice(&[0xc9, 0xd8, 0x91, 0xff]);
    }
    bytes.extend_from_slice(&[0; 64]);
    std::fs::create_dir_all(directory)?;
    if std::fs::read(&destination).ok().as_ref() != Some(&bytes) {
        std::fs::write(destination, bytes)?;
    }
    Ok(())
}
