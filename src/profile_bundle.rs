use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::models::{
    ConnectionProfile, PersistedProfile, PersistedSaslMechanism, PersistedSaslTransport,
    PersistedSecurityMode, SaslMechanism, SaslTransport, Secret, TlsSettings,
};
use crate::profile_store::ProfileStore;

/// Portable JSON contains plaintext credentials and private keys. Treat it as secret data.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableBundle {
    pub version: u32,
    pub profiles: Vec<PortableProfile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableProfile {
    pub id: String,
    pub name: String,
    pub bootstrap_servers: String,
    pub security: PortableSecurity,
    pub tls: Option<PortableTls>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PortableSecurity {
    Plaintext,
    Ssl,
    Sasl {
        transport: PersistedSaslTransport,
        mechanism: PersistedSaslMechanism,
        username: String,
        password: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTls {
    pub ca_certificate: String,
    pub client_certificate: Option<String>,
    pub private_key: Option<String>,
    pub private_key_password: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImportConflict {
    pub incoming_name: String,
    pub existing_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("Portable connection bundle has an invalid schema")]
    InvalidSchema,
    #[error("Portable connection bundle version is unsupported")]
    UnsupportedVersion,
    #[error("Portable connection bundle contains invalid certificate encoding")]
    InvalidBase64,
    #[error("Portable connection bundle contains an invalid profile")]
    InvalidProfile,
    #[error("A connection with this display name already exists")]
    Conflict(ImportConflict),
    #[error("Could not {operation} portable certificate material ({kind:?})")]
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
}

impl std::fmt::Debug for PortableBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PortableBundle([redacted])")
    }
}

/// Reads certificate files. Call from a worker, and warn before saving the returned plaintext JSON.
pub fn export_bundle(profiles: &[ConnectionProfile]) -> Result<String, BundleError> {
    let mut portable = Vec::with_capacity(profiles.len());
    let mut ids = HashSet::new();
    let mut names = HashMap::new();
    for profile in profiles {
        profile
            .validate()
            .map_err(|_| BundleError::InvalidProfile)?;
        if profile.id.trim().is_empty() || !ids.insert(&profile.id) {
            return Err(BundleError::InvalidProfile);
        }
        if let Some(existing_id) = names.insert(&profile.name, &profile.id) {
            return Err(BundleError::Conflict(ImportConflict {
                incoming_name: profile.name.clone(),
                existing_id: existing_id.to_owned(),
            }));
        }
        let security = match PersistedProfile::from(profile).security {
            PersistedSecurityMode::Plaintext => PortableSecurity::Plaintext,
            PersistedSecurityMode::Ssl { .. } => PortableSecurity::Ssl,
            PersistedSecurityMode::Sasl {
                transport,
                mechanism,
                username,
                password,
            } => PortableSecurity::Sasl {
                transport,
                mechanism,
                username,
                password,
            },
        };
        let tls = profile
            .tls()
            .map(|tls| -> Result<_, BundleError> {
                Ok(PortableTls {
                    ca_certificate: encode_file(&tls.ca_path)?,
                    client_certificate: tls
                        .certificate_path
                        .as_deref()
                        .filter(|path| !path.trim().is_empty())
                        .map(encode_file)
                        .transpose()?,
                    private_key: tls
                        .private_key_path
                        .as_deref()
                        .filter(|path| !path.trim().is_empty())
                        .map(encode_file)
                        .transpose()?,
                    private_key_password: tls.private_key_password.expose().to_owned(),
                })
            })
            .transpose()?;
        portable.push(PortableProfile {
            id: profile.id.clone(),
            name: profile.name.clone(),
            bootstrap_servers: profile.bootstrap_servers.clone(),
            security,
            tls,
        });
    }
    serde_json::to_string_pretty(&PortableBundle {
        version: 1,
        profiles: portable,
    })
    .map_err(|_| BundleError::InvalidSchema)
}

/// Validates the entire batch before writing files. Does not save the encrypted profile store.
/// Names use exact display-name equality; conflicts within the batch also identify the prior ID.
pub fn import_bundle(
    json: &str,
    store: &ProfileStore,
    existing: &[ConnectionProfile],
) -> Result<Vec<ConnectionProfile>, BundleError> {
    // serde diagnostics may quote credentials: retain only our payload-free category.
    let bundle: PortableBundle =
        serde_json::from_str(json).map_err(|_| BundleError::InvalidSchema)?;
    if bundle.version != 1 {
        return Err(BundleError::UnsupportedVersion);
    }
    let batch = format!("import-{}", uuid::Uuid::new_v4());
    let final_directory = store.certificates_dir().join(&batch);
    let mut validated = Vec::with_capacity(bundle.profiles.len());
    let mut ids = HashSet::new();
    for portable in bundle.profiles {
        if portable.id.trim().is_empty() || !ids.insert(portable.id.clone()) {
            return Err(BundleError::InvalidProfile);
        }
        let directory_name = uuid::Uuid::new_v4().to_string();
        let directory = final_directory.join(&directory_name);
        let material = portable.tls.as_ref().map(decode_tls).transpose()?;
        let tls = portable
            .tls
            .map(|tls| -> Result<_, BundleError> {
                Ok(TlsSettings {
                    ca_path: path_string(&directory.join("ca.pem"))?,
                    certificate_path: tls
                        .client_certificate
                        .map(|_| path_string(&directory.join("client.pem")))
                        .transpose()?,
                    private_key_path: tls
                        .private_key
                        .map(|_| path_string(&directory.join("client.key")))
                        .transpose()?,
                    private_key_password: Secret::new(tls.private_key_password),
                })
            })
            .transpose()?;
        let mut profile = match portable.security {
            PortableSecurity::Plaintext => {
                if tls.is_some() {
                    return Err(BundleError::InvalidProfile);
                }
                ConnectionProfile::plaintext(portable.bootstrap_servers)
            }
            PortableSecurity::Ssl => ConnectionProfile::ssl(
                portable.bootstrap_servers,
                tls.ok_or(BundleError::InvalidProfile)?,
            ),
            PortableSecurity::Sasl {
                transport,
                mechanism,
                username,
                password,
            } => {
                let transport = match transport {
                    PersistedSaslTransport::Plaintext => {
                        if tls.is_some() {
                            return Err(BundleError::InvalidProfile);
                        }
                        SaslTransport::Plaintext
                    }
                    PersistedSaslTransport::Ssl => {
                        if tls.is_none() {
                            return Err(BundleError::InvalidProfile);
                        }
                        SaslTransport::Ssl
                    }
                };
                let mechanism = match mechanism {
                    PersistedSaslMechanism::Plain => SaslMechanism::Plain,
                    PersistedSaslMechanism::ScramSha256 => SaslMechanism::ScramSha256,
                    PersistedSaslMechanism::ScramSha512 => SaslMechanism::ScramSha512,
                };
                let mut profile = ConnectionProfile::sasl(
                    portable.bootstrap_servers,
                    transport,
                    mechanism,
                    username,
                    password,
                    tls.unwrap_or_default(),
                );
                if transport == SaslTransport::Plaintext {
                    profile.tls = None;
                }
                profile
            }
        };
        profile.id = portable.id;
        profile.name = portable.name;
        profile
            .validate()
            .map_err(|_| BundleError::InvalidProfile)?;
        validated.push((profile, directory_name, material));
    }
    // All schema, encoding, pairing, and profile validation finishes before conflict checking or I/O.
    let mut names: HashMap<&str, &str> = existing
        .iter()
        .map(|profile| (profile.name.as_str(), profile.id.as_str()))
        .collect();
    for (profile, _, _) in &validated {
        if let Some(existing_id) = names.insert(&profile.name, &profile.id) {
            return Err(BundleError::Conflict(ImportConflict {
                incoming_name: profile.name.clone(),
                existing_id: existing_id.to_owned(),
            }));
        }
    }
    if validated.iter().any(|(_, _, material)| material.is_some()) {
        let stage = ImportStage::new(store.certificates_dir())?;
        for (_, directory_name, material) in &validated {
            if let Some(material) = material {
                let directory = stage.path.join(directory_name);
                fs::create_dir(&directory)
                    .map_err(|error| io_error("stage directory for", error))?;
                write_material(&directory.join("ca.pem"), &material.ca)?;
                if let Some(certificate) = &material.certificate {
                    write_material(&directory.join("client.pem"), certificate)?;
                }
                if let Some(key) = &material.key {
                    write_material(&directory.join("client.key"), key)?;
                }
            }
        }
        // One same-volume move publishes the whole batch, avoiding partially moved profiles.
        stage.commit(&final_directory)?;
    }
    Ok(validated
        .into_iter()
        .map(|(profile, _, _)| profile)
        .collect())
}

fn encode_file(path: &str) -> Result<String, BundleError> {
    let bytes = fs::read(path).map_err(|error| io_error("read", error))?;
    if bytes.is_empty() {
        return Err(BundleError::InvalidProfile);
    }
    Ok(STANDARD.encode(bytes))
}

struct CertificateMaterial {
    ca: Vec<u8>,
    certificate: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
}

fn decode_tls(tls: &PortableTls) -> Result<CertificateMaterial, BundleError> {
    fn decode(value: &str) -> Result<Vec<u8>, BundleError> {
        let bytes = STANDARD
            .decode(value)
            .map_err(|_| BundleError::InvalidBase64)?;
        if bytes.is_empty() {
            return Err(BundleError::InvalidProfile);
        }
        Ok(bytes)
    }
    if tls.client_certificate.is_some() != tls.private_key.is_some() {
        return Err(BundleError::InvalidProfile);
    }
    Ok(CertificateMaterial {
        ca: decode(&tls.ca_certificate)?,
        certificate: tls.client_certificate.as_deref().map(decode).transpose()?,
        key: tls.private_key.as_deref().map(decode).transpose()?,
    })
}

fn path_string(path: &Path) -> Result<String, BundleError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(BundleError::InvalidProfile)
}

fn write_material(path: &Path, bytes: &[u8]) -> Result<(), BundleError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("stage file for", error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error("write", error))
}

struct ImportStage {
    path: PathBuf,
}

impl ImportStage {
    fn new(parent: &Path) -> Result<Self, BundleError> {
        let path = parent.join(format!(".import-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).map_err(|error| io_error("stage directory for", error))?;
        Ok(Self { path })
    }

    fn commit(self, destination: &Path) -> Result<(), BundleError> {
        // Never replace even an empty existing destination.
        if destination
            .try_exists()
            .map_err(|error| io_error("inspect destination for", error))?
        {
            return Err(io_error(
                "publish",
                io::Error::from(io::ErrorKind::AlreadyExists),
            ));
        }
        fs::rename(&self.path, destination).map_err(|error| io_error("publish", error))
    }
}

impl Drop for ImportStage {
    fn drop(&mut self) {
        // Only a fresh, generated staging path owned by this import is removed.
        // On success it no longer exists. On failure it contains unpublished material.
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn io_error(operation: &'static str, error: io::Error) -> BundleError {
    BundleError::Io {
        operation,
        kind: error.kind(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SaslMechanism, SaslTransport, Secret, TlsSettings};
    use std::path::{Path, PathBuf};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("kafa-bundle-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn store(&self, name: &str) -> ProfileStore {
            ProfileStore::for_test(self.0.join(name)).unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            // Only this test's freshly allocated UUID directory is removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "profiles": [{
                "id": "incoming-id", "name": "Imported TLS", "bootstrap_servers": "broker.invalid:9093",
                "security": "Ssl",
                "tls": {
                    "ca_certificate": "Y2E=", "client_certificate": "Y2VydA==", "private_key": "a2V5",
                    "private_key_password": "synthetic-key-secret"
                }
            }]
        })
    }

    fn no_artifacts(store: &ProfileStore) {
        assert_eq!(fs::read_dir(store.certificates_dir()).unwrap().count(), 0);
        assert!(!store.path().exists());
    }

    #[test]
    fn portable_bundle_restores_certificates_and_secrets_on_a_new_store() {
        let root = TestRoot::new();
        let source = root.store("source");
        let target = root.store("target");
        let ca = source.certificates_dir().join("source-ca.pem");
        let certificate = source.certificates_dir().join("source-client.pem");
        let key = source.certificates_dir().join("source-client.key");
        fs::write(&ca, [0, 255, 1, 2]).unwrap();
        fs::write(&certificate, b"synthetic-client-certificate").unwrap();
        fs::write(&key, b"synthetic-private-key").unwrap();
        let tls = TlsSettings {
            ca_path: ca.to_str().unwrap().into(),
            certificate_path: Some(certificate.to_str().unwrap().into()),
            private_key_path: Some(key.to_str().unwrap().into()),
            private_key_password: Secret::new("synthetic-key-secret"),
        };
        let mut original = ConnectionProfile::sasl(
            "broker.invalid:9093",
            SaslTransport::Ssl,
            SaslMechanism::ScramSha512,
            "synthetic-user",
            "synthetic-sasl-secret",
            tls,
        );
        original.name = "Portable SASL".into();
        let json = export_bundle(&[original.clone()]).unwrap();
        assert!(json.contains("synthetic-sasl-secret"));
        assert!(json.contains("synthetic-key-secret"));
        assert!(!json.contains("source-ca.pem"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["version"],
            1
        );
        let bundle: PortableBundle = serde_json::from_str(&json).unwrap();
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("synthetic-sasl-secret"));
        assert!(!debug.contains("synthetic-key-secret"));
        assert!(!debug.contains("c3ludGhldGljLXByaXZhdGUta2V5"));
        // Prove the destination does not need the exporting machine's files.
        fs::remove_file(ca).unwrap();
        fs::remove_file(certificate).unwrap();
        fs::remove_file(key).unwrap();
        let imported = import_bundle(&json, &target, &[]).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].id, original.id);
        assert_eq!(imported[0].name, original.name);
        assert_eq!(imported[0].bootstrap_servers, original.bootstrap_servers);
        assert_eq!(imported[0].security, original.security);
        let tls = imported[0].tls().unwrap();
        let paths = [
            &tls.ca_path,
            tls.certificate_path.as_ref().unwrap(),
            tls.private_key_path.as_ref().unwrap(),
        ];
        for path in paths {
            assert!(Path::new(path).starts_with(target.certificates_dir()));
            assert_ne!(Path::new(path).parent().unwrap(), target.certificates_dir());
        }
        assert_eq!(fs::read(&tls.ca_path).unwrap(), [0, 255, 1, 2]);
        assert_eq!(
            fs::read(tls.certificate_path.unwrap()).unwrap(),
            b"synthetic-client-certificate"
        );
        assert_eq!(
            fs::read(tls.private_key_path.unwrap()).unwrap(),
            b"synthetic-private-key"
        );
        assert_eq!(tls.private_key_password.expose(), "synthetic-key-secret");
        assert!(!target.path().exists());
        assert_eq!(fs::read_dir(target.certificates_dir()).unwrap().count(), 1);
    }

    #[test]
    fn invalid_base64_in_later_profile_leaves_no_certificate_artifacts() {
        let root = TestRoot::new();
        let store = root.store("target");
        let mut json = fixture();
        let mut second = json["profiles"][0].clone();
        second["name"] = "Second".into();
        second["id"] = "second-id".into();
        second["tls"]["private_key"] = "!invalid-base64!".into();
        json["profiles"].as_array_mut().unwrap().push(second);
        let error = import_bundle(&json.to_string(), &store, &[]).unwrap_err();
        assert!(matches!(error, BundleError::InvalidBase64));
        assert!(!format!("{error:?} {error}").contains("!invalid-base64!"));
        no_artifacts(&store);
    }

    #[test]
    fn invalid_schema_security_and_version_leave_no_artifacts() {
        let root = TestRoot::new();
        let store = root.store("target");
        let mut wrong_version = fixture();
        wrong_version["version"] = 2.into();
        assert!(matches!(
            import_bundle(&wrong_version.to_string(), &store, &[]),
            Err(BundleError::UnsupportedVersion)
        ));
        for json in [
            "{synthetic-secret",
            "{}",
            r#"{"version":1,"profiles":null}"#,
        ] {
            assert!(matches!(
                import_bundle(json, &store, &[]),
                Err(BundleError::InvalidSchema)
            ));
        }
        for invalid in ["unknown security synthetic-secret", "SASL_SSL"] {
            let mut json = fixture();
            json["profiles"][0]["security"] = invalid.into();
            let error = import_bundle(&json.to_string(), &store, &[]).unwrap_err();
            assert!(matches!(error, BundleError::InvalidSchema));
            assert!(!format!("{error:?} {error}").contains(invalid));
        }
        no_artifacts(&store);
    }

    #[test]
    fn duplicate_display_name_is_reported_before_mutation() {
        let root = TestRoot::new();
        let store = root.store("target");
        let mut existing = ConnectionProfile::plaintext("existing.invalid:9092");
        existing.id = "existing-id".into();
        existing.name = "Imported TLS".into();
        let error = import_bundle(&fixture().to_string(), &store, &[existing]).unwrap_err();
        match error {
            BundleError::Conflict(conflict) => {
                assert_eq!(conflict.incoming_name, "Imported TLS");
                assert_eq!(conflict.existing_id, "existing-id");
            }
            _ => panic!("expected typed conflict"),
        }
        no_artifacts(&store);
    }

    #[test]
    fn duplicate_names_within_bundle_are_rejected_before_mutation() {
        let root = TestRoot::new();
        let store = root.store("target");
        let mut json = fixture();
        let mut second = json["profiles"][0].clone();
        second["id"] = "second-id".into();
        json["profiles"].as_array_mut().unwrap().push(second);
        assert!(matches!(
            import_bundle(&json.to_string(), &store, &[]),
            Err(BundleError::Conflict(_))
        ));
        no_artifacts(&store);
    }

    #[test]
    fn invalid_profiles_and_unpaired_certificate_material_leave_no_artifacts() {
        let root = TestRoot::new();
        let store = root.store("target");
        for field in ["name", "bootstrap_servers", "id"] {
            let mut json = fixture();
            json["profiles"][0][field] = " ".into();
            assert!(matches!(
                import_bundle(&json.to_string(), &store, &[]),
                Err(BundleError::InvalidProfile)
            ));
        }
        for field in ["client_certificate", "private_key", "ca_certificate"] {
            let mut json = fixture();
            json["profiles"][0]["tls"][field] = if field == "ca_certificate" {
                "".into()
            } else {
                serde_json::Value::Null
            };
            assert!(matches!(
                import_bundle(&json.to_string(), &store, &[]),
                Err(BundleError::InvalidProfile)
            ));
        }
        no_artifacts(&store);
    }

    #[test]
    fn export_rejects_duplicate_ids_instead_of_producing_an_unimportable_bundle() {
        let profile = ConnectionProfile::plaintext("broker.invalid:9092");
        let mut duplicate = profile.clone();
        duplicate.name = "Another display name".into();
        assert!(matches!(
            export_bundle(&[profile, duplicate]),
            Err(BundleError::InvalidProfile)
        ));
    }

    #[test]
    fn export_rejects_duplicate_names_instead_of_producing_a_conflicting_bundle() {
        let first = ConnectionProfile::plaintext("first.invalid:9092");
        let second = ConnectionProfile::plaintext("second.invalid:9092");
        assert!(matches!(
            export_bundle(&[first, second]),
            Err(BundleError::Conflict(_))
        ));
    }

    #[test]
    fn failed_publish_removes_staged_private_keys_and_preserves_existing_destination() {
        let root = TestRoot::new();
        let store = root.store("target");
        let destination = store.certificates_dir().join("existing");
        fs::create_dir(&destination).unwrap();
        let marker = destination.join("keep.pem");
        fs::write(&marker, b"keep-existing-certificate").unwrap();
        let stage = ImportStage::new(store.certificates_dir()).unwrap();
        let staging_path = stage.path.clone();
        write_material(&stage.path.join("client.key"), b"synthetic-private-key").unwrap();
        assert!(matches!(
            stage.commit(&destination),
            Err(BundleError::Io {
                operation: "publish",
                ..
            })
        ));
        assert!(!staging_path.exists());
        assert_eq!(fs::read(marker).unwrap(), b"keep-existing-certificate");
        assert_eq!(fs::read_dir(store.certificates_dir()).unwrap().count(), 1);
    }

    #[test]
    fn failed_staging_write_removes_previous_staged_material() {
        let root = TestRoot::new();
        let store = root.store("target");
        let stage = ImportStage::new(store.certificates_dir()).unwrap();
        let staging_path = stage.path.clone();
        let destination = store.certificates_dir().join("published");
        let result = (move || -> Result<(), BundleError> {
            write_material(&stage.path.join("ca.pem"), b"synthetic-ca")?;
            // A real create_new failure after the first material was written.
            write_material(&stage.path.join("ca.pem"), b"should-not-overwrite")?;
            stage.commit(&destination)
        })();
        assert!(matches!(
            result,
            Err(BundleError::Io {
                operation: "stage file for",
                ..
            })
        ));
        assert!(!staging_path.exists());
        no_artifacts(&store);
    }

    #[test]
    fn all_security_modes_round_trip_with_unique_certificate_directories() {
        let root = TestRoot::new();
        let source = root.store("source");
        let destination = root.store("destination");
        let ca = source.certificates_dir().join("ca.pem");
        fs::write(&ca, b"synthetic-ca").unwrap();
        let tls = TlsSettings::with_ca(ca.to_str().unwrap());
        let mut profiles = vec![
            ConnectionProfile::plaintext("broker.invalid:9092"),
            ConnectionProfile::ssl("broker.invalid:9093", tls.clone()),
        ];
        for mechanism in [
            SaslMechanism::Plain,
            SaslMechanism::ScramSha256,
            SaslMechanism::ScramSha512,
        ] {
            for transport in [SaslTransport::Plaintext, SaslTransport::Ssl] {
                profiles.push(ConnectionProfile::sasl(
                    "broker.invalid:9093",
                    transport,
                    mechanism,
                    "synthetic-user",
                    "synthetic-password",
                    tls.clone(),
                ));
            }
        }
        for (index, profile) in profiles.iter_mut().enumerate() {
            profile.name = format!("Connection {index}");
        }
        let json = export_bundle(&profiles).unwrap();
        let imported = import_bundle(&json, &destination, &[]).unwrap();
        assert_eq!(imported.len(), 8);
        assert_eq!(export_bundle(&imported).unwrap(), json);
        let mut paths = std::collections::HashSet::new();
        for profile in imported {
            assert!(profile.validate().is_ok());
            if let Some(tls) = profile.tls() {
                assert_eq!(fs::read(&tls.ca_path).unwrap(), b"synthetic-ca");
                assert!(paths.insert(PathBuf::from(&tls.ca_path)));
                assert!(tls.certificate_path.is_none());
                assert!(tls.private_key_path.is_none());
            }
        }
        assert_eq!(paths.len(), 4);
        assert!(!destination.path().exists());
    }

    #[test]
    fn invalid_sasl_transport_mechanism_credentials_and_tls_combinations_are_rejected() {
        let root = TestRoot::new();
        let store = root.store("target");
        let mut json = fixture();
        json["profiles"][0]["security"] = serde_json::json!({"Sasl": {
            "transport": "Ssl", "mechanism": "Plain", "username": "synthetic-user", "password": "synthetic-password"
        }});
        for field in ["transport", "mechanism"] {
            let mut invalid = json.clone();
            invalid["profiles"][0]["security"]["Sasl"][field] =
                "unsupported-synthetic-secret".into();
            let error = import_bundle(&invalid.to_string(), &store, &[]).unwrap_err();
            assert!(matches!(error, BundleError::InvalidSchema));
            assert!(!format!("{error:?} {error}").contains("unsupported-synthetic-secret"));
        }
        for field in ["username", "password"] {
            let mut invalid = json.clone();
            invalid["profiles"][0]["security"]["Sasl"][field] = "".into();
            assert!(matches!(
                import_bundle(&invalid.to_string(), &store, &[]),
                Err(BundleError::InvalidProfile)
            ));
        }
        json["profiles"][0]["security"]["Sasl"]["transport"] = "Plaintext".into();
        assert!(matches!(
            import_bundle(&json.to_string(), &store, &[]),
            Err(BundleError::InvalidProfile)
        ));
        json["profiles"][0]["security"] = "Plaintext".into();
        assert!(matches!(
            import_bundle(&json.to_string(), &store, &[]),
            Err(BundleError::InvalidProfile)
        ));
        json = fixture();
        json["profiles"][0]["tls"] = serde_json::Value::Null;
        assert!(matches!(
            import_bundle(&json.to_string(), &store, &[]),
            Err(BundleError::InvalidProfile)
        ));
        no_artifacts(&store);
    }
}
