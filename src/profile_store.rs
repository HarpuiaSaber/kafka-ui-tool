use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

use crate::models::PersistedProfile;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("LOCALAPPDATA is unavailable")]
    LocalAppDataUnavailable,
    #[error("Could not {operation} connection store ({kind:?})")]
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
    #[error("Could not serialize connection profiles")]
    Serialize,
    #[error("Could not encrypt connection store")]
    Encrypt,
    #[error("Could not decrypt connection store")]
    Decrypt,
    #[error("Decrypted connection store has an invalid format")]
    Deserialize,
}

pub struct ProfileStore {
    path: PathBuf,
    certificates_dir: PathBuf,
    protector: Box<dyn DataProtector>,
}

trait DataProtector: Send + Sync {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError>;
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, StoreError>;
}

struct WindowsDpapiProtector;

impl DataProtector for WindowsDpapiProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        crypt(plaintext, true)
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, StoreError> {
        crypt(ciphertext, false)
    }
}

impl ProfileStore {
    pub fn open() -> Result<Self, StoreError> {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or(StoreError::LocalAppDataUnavailable)?;
        let local_app_data = PathBuf::from(local_app_data);
        let root = local_app_data.join("Kafka UI Tool");
        migrate_legacy_profile_directory(&local_app_data.join("Kafa UI Tool"), &root)?;
        Self::at_root(root)
    }

    #[cfg(test)]
    pub fn for_test(root: PathBuf) -> Result<Self, StoreError> {
        Self::at_root(root)
    }

    #[cfg(test)]
    pub(crate) fn with_test_protector(root: PathBuf) -> Result<Self, StoreError> {
        let mut store = Self::for_test(root)?;
        store.protector = Box::new(tests::TestProtector);
        Ok(store)
    }

    fn at_root(root: PathBuf) -> Result<Self, StoreError> {
        let certificates_dir = root.join("certificates");
        fs::create_dir_all(&certificates_dir)
            .map_err(|error| io_error("create directories for", error))?;
        Ok(Self {
            path: root.join("connections.dat"),
            certificates_dir,
            protector: Box::new(WindowsDpapiProtector),
        })
    }

    pub fn load(&self) -> Result<Vec<PersistedProfile>, StoreError> {
        let encrypted = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error("read", error)),
        };
        let mut plaintext = self.protector.unprotect(&encrypted)?;
        // Do not retain serde's error: malformed JSON can include payload text.
        let result = serde_json::from_slice(&plaintext).map_err(|_| StoreError::Deserialize);
        plaintext.fill(0);
        result
    }

    pub fn save(&self, profiles: &[PersistedProfile]) -> Result<(), StoreError> {
        let mut plaintext = serde_json::to_vec(profiles).map_err(|_| StoreError::Serialize)?;
        let encrypted = self.protector.protect(&plaintext);
        plaintext.fill(0);
        let encrypted = encrypted?;

        // Recreate parents if the store directory was removed after opening.
        fs::create_dir_all(&self.certificates_dir)
            .map_err(|error| io_error("create directories for", error))?;
        let temporary_path = self
            .path
            .with_file_name(format!(".connections-{}.tmp", uuid::Uuid::new_v4()));
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| io_error("create temporary file for", error))?;
        let result = (|| {
            temporary
                .write_all(&encrypted)
                .map_err(|error| io_error("write", error))?;
            temporary
                .sync_all()
                .map_err(|error| io_error("flush", error))
        })();
        // Windows must release this file handle before moving the file.
        drop(temporary);
        let result = result.and_then(|()| {
            // On Windows std::fs::rename uses MoveFileExW with replacement.
            // Both paths are in the same directory; the old file is never deleted first.
            fs::rename(&temporary_path, &self.path).map_err(|error| io_error("replace", error))
        });
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn certificates_dir(&self) -> &Path {
        &self.certificates_dir
    }
}

/// Move the old application directory only when no directory exists at the new path.
fn migrate_legacy_profile_directory(legacy_root: &Path, root: &Path) -> Result<(), StoreError> {
    if legacy_root.exists() && !root.exists() {
        fs::rename(legacy_root, root).map_err(|error| io_error("migrate legacy", error))?;
    }
    Ok(())
}

fn io_error(operation: &'static str, error: io::Error) -> StoreError {
    StoreError::Io {
        operation,
        kind: error.kind(),
    }
}

/// All DPAPI buffers are owned by Windows and released with LocalFree.
fn crypt(bytes: &[u8], protect: bool) -> Result<Vec<u8>, StoreError> {
    let failure = || {
        if protect {
            StoreError::Encrypt
        } else {
            StoreError::Decrypt
        }
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| failure())?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: DPAPI reads the input for the duration of this call, and initializes
    // the output blob on success. Null optional parameters request no entropy or
    // description. UI_FORBIDDEN prevents prompts; omitting LOCAL_MACHINE binds
    // encryption to the current Windows user's credentials.
    let success = unsafe {
        if protect {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if success == 0 {
        return Err(failure());
    }
    // SAFETY: On success, DPAPI provides cbData initialized bytes in a LocalAlloc
    // buffer. Copy them before clearing and freeing that allocation. Empty blobs
    // do not require dereferencing a potentially null pointer.
    unsafe {
        let result = if output.cbData == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
        };
        if !output.pbData.is_null() {
            ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            LocalFree(output.pbData.cast());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ConnectionProfile;
    use std::fs;

    const PASSWORD: &str = "synthetic-store-password-8e25a1";

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("kafka-profile-store-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn store(&self) -> ProfileStore {
            let mut store = ProfileStore::for_test(self.0.join("isolated")).unwrap();
            // The test seam never replaces the protector used by either public constructor.
            store.protector = Box::new(TestProtector);
            store
        }
    }

    /// Deterministic transform for exercising storage behavior only. This is not
    /// cryptography; production always uses current-user Windows DPAPI.
    pub(super) struct TestProtector;

    impl DataProtector for TestProtector {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
            let mut ciphertext = b"test-protector:".to_vec();
            ciphertext.extend(plaintext.iter().rev().map(|byte| byte ^ 0xa5));
            Ok(ciphertext)
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, StoreError> {
            let payload = ciphertext
                .strip_prefix(b"test-protector:")
                .ok_or(StoreError::Decrypt)?;
            Ok(payload.iter().rev().map(|byte| byte ^ 0xa5).collect())
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            // Only this test's freshly created UUID directory is removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn profiles() -> Vec<PersistedProfile> {
        vec![PersistedProfile::from(&ConnectionProfile::sasl_plain(
            "example.invalid:9093",
            "synthetic-user",
            PASSWORD,
        ))]
    }

    #[test]
    fn isolated_store_round_trips_persisted_profiles() {
        let root = TestRoot::new();
        let store = root.store();
        let expected = profiles();
        store.save(&expected).unwrap();

        let reopened = root.store();
        assert_eq!(reopened.load().unwrap(), expected);
        assert_eq!(store.path(), root.0.join("isolated/connections.dat"));
        assert_eq!(
            store.certificates_dir(),
            root.0.join("isolated/certificates")
        );
        assert!(store.certificates_dir().is_dir());
    }

    #[test]
    fn encrypted_file_contains_no_known_password_or_json_payload() {
        let root = TestRoot::new();
        let store = root.store();
        let expected = profiles();
        store.save(&expected).unwrap();

        let bytes = fs::read(store.path()).unwrap();
        assert!(!bytes.is_empty());
        assert!(!bytes
            .windows(PASSWORD.len())
            .any(|part| part == PASSWORD.as_bytes()));
        assert!(!bytes
            .windows(b"example.invalid".len())
            .any(|part| part == b"example.invalid"));
        assert!(serde_json::from_slice::<Vec<PersistedProfile>>(&bytes).is_err());
    }

    #[test]
    fn missing_store_returns_empty_profiles_without_creating_data_file() {
        let root = TestRoot::new();
        let store = root.store();

        assert!(store.load().unwrap().is_empty());
        assert!(!store.path().exists());
    }

    #[test]
    fn migrates_legacy_profile_directory_when_new_directory_is_absent() {
        let root = TestRoot::new();
        let legacy_root = root.0.join("Kafa UI Tool");
        let new_root = root.0.join("Kafka UI Tool");
        fs::create_dir_all(legacy_root.join("certificates")).unwrap();
        fs::write(legacy_root.join("connections.dat"), b"encrypted-fixture").unwrap();

        migrate_legacy_profile_directory(&legacy_root, &new_root).unwrap();

        assert!(!legacy_root.exists());
        assert_eq!(
            fs::read(new_root.join("connections.dat")).unwrap(),
            b"encrypted-fixture"
        );
        assert!(new_root.join("certificates").is_dir());
    }

    #[test]
    fn invalid_bytes_fail_with_payload_free_decryption_error() {
        let root = TestRoot::new();
        let store = root.store();
        fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        fs::write(store.path(), PASSWORD.as_bytes()).unwrap();

        let error = store.load().unwrap_err();
        assert!(matches!(error, StoreError::Decrypt));
        assert!(!format!("{error:?} {error}").contains(PASSWORD));
        assert_eq!(fs::read(store.path()).unwrap(), PASSWORD.as_bytes());
    }

    #[test]
    fn dpapi_round_trips_or_returns_payload_free_typed_error() {
        let protector = WindowsDpapiProtector;
        match protector.protect(PASSWORD.as_bytes()) {
            Ok(ciphertext) => {
                assert!(!ciphertext
                    .windows(PASSWORD.len())
                    .any(|part| part == PASSWORD.as_bytes()));
                assert_eq!(
                    protector.unprotect(&ciphertext).unwrap(),
                    PASSWORD.as_bytes()
                );
            }
            Err(error) => {
                // The sandbox account can lack a loaded Windows user profile.
                // This verifies the failure contract, not DPAPI availability.
                assert!(matches!(error, StoreError::Encrypt));
                assert!(!format!("{error:?} {error}").contains(PASSWORD));
            }
        }
        let error = protector.unprotect(PASSWORD.as_bytes()).unwrap_err();
        assert!(matches!(error, StoreError::Decrypt));
        assert!(!format!("{error:?} {error}").contains(PASSWORD));
    }

    #[test]
    fn saving_again_replaces_existing_profiles_without_leaving_temporary_files() {
        let root = TestRoot::new();
        let store = root.store();
        store.save(&profiles()).unwrap();
        store.save(&[]).unwrap();

        assert!(store.load().unwrap().is_empty());
        let mut names: Vec<_> = fs::read_dir(store.path().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, vec!["certificates", "connections.dat"]);
    }

    #[test]
    fn failed_replacement_cleans_temporary_file_and_preserves_destination() {
        let root = TestRoot::new();
        let store = root.store();
        fs::create_dir_all(store.path()).unwrap();
        let marker = store.path().join("keep.txt");
        fs::write(&marker, b"keep").unwrap();

        assert!(matches!(
            store.save(&profiles()),
            Err(StoreError::Io {
                operation: "replace",
                ..
            })
        ));
        assert_eq!(fs::read(marker).unwrap(), b"keep");
        assert_eq!(
            fs::read_dir(store.path().parent().unwrap())
                .unwrap()
                .count(),
            2
        );
    }
}
