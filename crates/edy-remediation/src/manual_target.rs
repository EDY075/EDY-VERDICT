//! Read-only identity binding. No create/write/delete/replace rights or operations.
use std::path::Path;
#[cfg(windows)]
pub fn readonly_directory_identity(path: &Path) -> Result<String, &'static str> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| "target_invalid")?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: File owns the live handle; initialized output has the required layout/lifetime.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0
        || info.dwFileAttributes & 0x400 != 0
        || info.dwFileAttributes & 0x10 == 0
    {
        return Err("target_invalid");
    }
    Ok(format!(
        "directory-{:08x}-{:08x}{:08x}",
        info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
    ))
}
#[cfg(not(windows))]
pub fn readonly_directory_identity(path: &Path) -> Result<String, &'static str> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(|_| "target_invalid")?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err("target_invalid");
    }
    Ok(format!("directory-{:x}-{:x}", m.dev(), m.ino()))
}
