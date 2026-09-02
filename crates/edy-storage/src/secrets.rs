//! Native adapter only. No values are logged, serialized, or sent to a WebView.
use std::fmt;
use zeroize::Zeroizing;

pub struct SecretValue(pub Zeroizing<Vec<u8>>);
// Deliberately no Debug/Serialize implementation for SecretValue.
#[derive(Debug)]
pub struct SecretError(pub u32);
impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential Manager operation failed ({})", self.0)
    }
}
impl std::error::Error for SecretError {}

pub struct CredentialStore;
#[cfg(windows)]
impl CredentialStore {
    pub fn read(target: &str) -> Result<Option<SecretValue>, SecretError> {
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_FOUND, GetLastError},
            Security::Credentials::*,
        };
        let target = wide(target)?;
        let mut ptr = std::ptr::null_mut();
        // SAFETY: target is NUL terminated and ptr receives a system-owned allocation.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut ptr) } == 0 {
            let code = unsafe { GetLastError() };
            return if code == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(SecretError(code))
            };
        }
        struct Allocation(*mut CREDENTIALW);
        impl Drop for Allocation {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                // SAFETY: this unique CredReadW allocation is still alive; all
                // borrowed views ended before drop. Wipe the native blob as well.
                unsafe {
                    let credential = &*self.0;
                    if credential.CredentialBlobSize > 0 && !credential.CredentialBlob.is_null() {
                        std::slice::from_raw_parts_mut(
                            credential.CredentialBlob,
                            credential.CredentialBlobSize as usize,
                        )
                        .zeroize();
                    }
                }
                unsafe { CredFree(self.0.cast()) };
            }
        }
        let allocated = Allocation(ptr);
        let credential = unsafe { &*allocated.0 };
        let bytes = if credential.CredentialBlobSize == 0 {
            vec![]
        } else {
            // SAFETY: CredReadW supplies a valid blob with the advertised length.
            unsafe {
                std::slice::from_raw_parts(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
            }
            .to_vec()
        };
        Ok(Some(SecretValue(Zeroizing::new(bytes))))
    }
    pub fn write(target: &str, value: &SecretValue) -> Result<(), SecretError> {
        use windows_sys::Win32::{Foundation::GetLastError, Security::Credentials::*};
        let mut target = wide(target)?;
        if value.0.len() > 2560 {
            return Err(SecretError(87));
        }
        let mut credential: CREDENTIALW = unsafe { std::mem::zeroed() };
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = target.as_mut_ptr();
        credential.CredentialBlobSize = value.0.len() as u32;
        credential.CredentialBlob = value.0.as_ptr().cast_mut();
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        // SAFETY: pointers remain valid for the synchronous call; API copies the blob.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(SecretError(unsafe { GetLastError() }));
        }
        Ok(())
    }
    pub fn delete(target: &str) -> Result<(), SecretError> {
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_FOUND, GetLastError},
            Security::Credentials::*,
        };
        let target = wide(target)?;
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(SecretError(code));
            }
        }
        Ok(())
    }
}
#[cfg(windows)]
fn wide(value: &str) -> Result<Vec<u16>, SecretError> {
    if !value.starts_with("EDY-VERDICT-") || value.contains('\0') || value.len() > 256 {
        return Err(SecretError(87));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    fn isolated_target(case: &str) -> String {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock is valid")
            .as_nanos();
        format!(
            "EDY-VERDICT-LEVEL0-TEST-{case}-{}-{nonce}",
            std::process::id()
        )
    }
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = CredentialStore::delete(&self.0);
        }
    }
    #[test]
    #[ignore = "Explicit user-authorized native credential write/read/delete; no real key"]
    fn credential_manager_fake_roundtrip() {
        let target = isolated_target("ROUNDTRIP");
        assert!(
            CredentialStore::read(&target).unwrap().is_none(),
            "Existing credential preserved; refusing overwrite"
        );
        let _cleanup = Cleanup(target.clone());
        let fake = SecretValue(Zeroizing::new(
            b"discardable-foundation-fixture-not-an-api-key".to_vec(),
        ));
        CredentialStore::write(&target, &fake).unwrap();
        let read = CredentialStore::read(&target)
            .unwrap()
            .expect("Credential missing");
        // Boolean assertion prevents values appearing in failure output.
        assert!(
            read.0.as_slice() == fake.0.as_slice(),
            "Credential comparison failed"
        );
        CredentialStore::delete(&target).unwrap();
        assert!(
            CredentialStore::read(&target).unwrap().is_none(),
            "Cleanup not confirmed"
        );
    }
    #[test]
    #[ignore = "Explicit user-authorized failure cleanup test"]
    fn cleanup_on_unwind() {
        let target = isolated_target("UNWIND");
        assert!(
            CredentialStore::read(&target).unwrap().is_none(),
            "Existing credential preserved"
        );
        let cleanup_target = target.clone();
        let result = std::panic::catch_unwind(|| {
            let _cleanup = Cleanup(cleanup_target.clone());
            CredentialStore::write(&cleanup_target, &SecretValue(Zeroizing::new(vec![42; 16])))
                .unwrap();
            panic!("Synthetic failure without secret value");
        });
        assert!(result.is_err());
        assert!(
            CredentialStore::read(&target).unwrap().is_none(),
            "Failure cleanup not confirmed"
        );
    }
}
