use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    Plaintext,
    Ssl {
        ca_path: String,
        certificate_path: String,
        key_path: String,
        key_password: Secret,
    },
    SaslPlain {
        transport: SaslTransport,
        username: String,
        password: Secret,
    },
    SaslScramSha256 {
        transport: SaslTransport,
        username: String,
        password: Secret,
    },
    SaslScramSha512 {
        transport: SaslTransport,
        username: String,
        password: Secret,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaslTransport {
    Plaintext,
    Ssl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaslMechanism {
    Plain,
    ScramSha256,
    ScramSha512,
}

impl SaslMechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    pub ca_path: String,
    pub certificate_path: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_password: Secret,
}

impl TlsSettings {
    #[cfg(test)]
    pub fn with_ca(path: impl Into<String>) -> Self {
        Self {
            ca_path: path.into(),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionProfile {
    pub id: String,
    pub name: String,
    pub bootstrap_servers: String,
    pub security: SecurityMode,
    /// TLS settings for SASL_SSL. SSL retains its legacy variant fields.
    pub tls: Option<TlsSettings>,
}

impl ConnectionProfile {
    pub fn plaintext(bootstrap_servers: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Kafka connection".into(),
            bootstrap_servers: bootstrap_servers.into(),
            security: SecurityMode::Plaintext,
            tls: None,
        }
    }

    pub fn ssl(bootstrap_servers: impl Into<String>, tls: TlsSettings) -> Self {
        let mut profile = Self::plaintext(bootstrap_servers);
        profile.security = SecurityMode::Ssl {
            ca_path: tls.ca_path,
            certificate_path: tls.certificate_path.unwrap_or_default(),
            key_path: tls.private_key_path.unwrap_or_default(),
            key_password: tls.private_key_password,
        };
        profile
    }

    pub fn sasl(
        bootstrap_servers: impl Into<String>,
        transport: SaslTransport,
        mechanism: SaslMechanism,
        username: impl Into<String>,
        password: impl Into<String>,
        tls: TlsSettings,
    ) -> Self {
        let username = username.into();
        let password = Secret::new(password);
        let mut profile = Self::plaintext(bootstrap_servers);
        profile.security = match mechanism {
            SaslMechanism::Plain => SecurityMode::SaslPlain {
                transport,
                username,
                password,
            },
            SaslMechanism::ScramSha256 => SecurityMode::SaslScramSha256 {
                transport,
                username,
                password,
            },
            SaslMechanism::ScramSha512 => SecurityMode::SaslScramSha512 {
                transport,
                username,
                password,
            },
        };
        profile.tls = Some(tls);
        profile
    }

    #[cfg(test)]
    pub fn sasl_plain(
        bootstrap_servers: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::sasl(
            bootstrap_servers,
            SaslTransport::Ssl,
            SaslMechanism::Plain,
            username,
            password,
            TlsSettings::default(),
        )
    }

    #[cfg(test)]
    pub fn scram_sha256(
        bootstrap_servers: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::sasl(
            bootstrap_servers,
            SaslTransport::Ssl,
            SaslMechanism::ScramSha256,
            username,
            password,
            TlsSettings::default(),
        )
    }

    #[cfg(test)]
    pub fn scram_sha512_plaintext(
        bootstrap_servers: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::scram_sha512(
            bootstrap_servers,
            SaslTransport::Plaintext,
            username,
            password,
        )
    }

    #[cfg(test)]
    pub fn scram_sha512(
        bootstrap_servers: impl Into<String>,
        transport: SaslTransport,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::sasl(
            bootstrap_servers,
            transport,
            SaslMechanism::ScramSha512,
            username,
            password,
            TlsSettings::default(),
        )
    }

    pub fn tls(&self) -> Option<TlsSettings> {
        match &self.security {
            SecurityMode::Ssl {
                ca_path,
                certificate_path,
                key_path,
                key_password,
            } => Some(TlsSettings {
                ca_path: ca_path.clone(),
                certificate_path: nonempty_path(certificate_path),
                private_key_path: nonempty_path(key_path),
                private_key_password: key_password.clone(),
            }),
            SecurityMode::SaslPlain {
                transport: SaslTransport::Ssl,
                ..
            }
            | SecurityMode::SaslScramSha256 {
                transport: SaslTransport::Ssl,
                ..
            }
            | SecurityMode::SaslScramSha512 {
                transport: SaslTransport::Ssl,
                ..
            } => Some(self.tls.clone().unwrap_or_default()),
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<(), Vec<ProfileValidationError>> {
        let mut errors = Vec::new();
        if self.name.trim().is_empty() {
            errors.push(ProfileValidationError::MissingName);
        }
        if self.bootstrap_servers.trim().is_empty() {
            errors.push(ProfileValidationError::MissingBootstrapServers);
        }
        if let Some(tls) = self.tls() {
            if tls.ca_path.trim().is_empty() {
                errors.push(ProfileValidationError::MissingCaCertificate);
            }
            let has_certificate = tls
                .certificate_path
                .as_deref()
                .is_some_and(|path| !path.trim().is_empty());
            let has_key = tls
                .private_key_path
                .as_deref()
                .is_some_and(|path| !path.trim().is_empty());
            if has_key && !has_certificate {
                errors.push(ProfileValidationError::MissingClientCertificate);
            }
            if has_certificate && !has_key {
                errors.push(ProfileValidationError::MissingPrivateKey);
            }
        }
        match &self.security {
            SecurityMode::SaslPlain {
                username, password, ..
            }
            | SecurityMode::SaslScramSha256 {
                username, password, ..
            }
            | SecurityMode::SaslScramSha512 {
                username, password, ..
            } => {
                if username.trim().is_empty() {
                    errors.push(ProfileValidationError::MissingSaslUsername);
                }
                if password.expose().is_empty() {
                    errors.push(ProfileValidationError::MissingSaslPassword);
                }
            }
            _ => {}
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn summary(&self) -> ProfileSummary {
        let security = match &self.security {
            SecurityMode::Plaintext => "PLAINTEXT".into(),
            SecurityMode::Ssl { .. } => "SSL".into(),
            SecurityMode::SaslPlain { transport, .. } => {
                sasl_label(*transport, SaslMechanism::Plain)
            }
            SecurityMode::SaslScramSha256 { transport, .. } => {
                sasl_label(*transport, SaslMechanism::ScramSha256)
            }
            SecurityMode::SaslScramSha512 { transport, .. } => {
                sasl_label(*transport, SaslMechanism::ScramSha512)
            }
        };
        ProfileSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            bootstrap_servers: self.bootstrap_servers.clone(),
            security,
        }
    }
}

fn nonempty_path(path: &str) -> Option<String> {
    if path.trim().is_empty() {
        None
    } else {
        Some(path.to_owned())
    }
}

fn sasl_label(transport: SaslTransport, mechanism: SaslMechanism) -> String {
    let protocol = match transport {
        SaslTransport::Plaintext => "SASL_PLAINTEXT",
        SaslTransport::Ssl => "SASL_SSL",
    };
    format!("{protocol} / {}", mechanism.as_str())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub bootstrap_servers: String,
    pub security: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileValidationError {
    MissingName,
    MissingBootstrapServers,
    MissingCaCertificate,
    MissingSaslUsername,
    MissingSaslPassword,
    MissingClientCertificate,
    MissingPrivateKey,
}

/// Plaintext serialization DTO. Only the store may persist it, after encryption.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedProfile {
    pub id: String,
    pub name: String,
    pub bootstrap_servers: String,
    pub security: PersistedSecurityMode,
    pub tls: Option<PersistedTlsSettings>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedSecurityMode {
    Plaintext,
    Ssl {
        ca_path: String,
        certificate_path: String,
        key_path: String,
        key_password: String,
    },
    Sasl {
        transport: PersistedSaslTransport,
        mechanism: PersistedSaslMechanism,
        username: String,
        password: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedSaslTransport {
    Plaintext,
    Ssl,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedSaslMechanism {
    Plain,
    ScramSha256,
    ScramSha512,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedTlsSettings {
    pub ca_path: String,
    pub certificate_path: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_password: String,
}

impl fmt::Debug for PersistedProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&ConnectionProfile::from(self.clone()), formatter)
    }
}

impl From<&ConnectionProfile> for PersistedProfile {
    fn from(profile: &ConnectionProfile) -> Self {
        let security = match &profile.security {
            SecurityMode::Plaintext => PersistedSecurityMode::Plaintext,
            SecurityMode::Ssl {
                ca_path,
                certificate_path,
                key_path,
                key_password,
            } => PersistedSecurityMode::Ssl {
                ca_path: ca_path.clone(),
                certificate_path: certificate_path.clone(),
                key_path: key_path.clone(),
                key_password: key_password.expose().to_owned(),
            },
            SecurityMode::SaslPlain {
                transport,
                username,
                password,
            }
            | SecurityMode::SaslScramSha256 {
                transport,
                username,
                password,
            }
            | SecurityMode::SaslScramSha512 {
                transport,
                username,
                password,
            } => PersistedSecurityMode::Sasl {
                transport: match transport {
                    SaslTransport::Plaintext => PersistedSaslTransport::Plaintext,
                    SaslTransport::Ssl => PersistedSaslTransport::Ssl,
                },
                mechanism: match &profile.security {
                    SecurityMode::SaslPlain { .. } => PersistedSaslMechanism::Plain,
                    SecurityMode::SaslScramSha256 { .. } => PersistedSaslMechanism::ScramSha256,
                    _ => PersistedSaslMechanism::ScramSha512,
                },
                username: username.clone(),
                password: password.expose().to_owned(),
            },
        };
        Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            bootstrap_servers: profile.bootstrap_servers.clone(),
            security,
            tls: profile.tls.as_ref().map(|tls| PersistedTlsSettings {
                ca_path: tls.ca_path.clone(),
                certificate_path: tls.certificate_path.clone(),
                private_key_path: tls.private_key_path.clone(),
                private_key_password: tls.private_key_password.expose().to_owned(),
            }),
        }
    }
}

impl From<PersistedProfile> for ConnectionProfile {
    fn from(profile: PersistedProfile) -> Self {
        let security = match profile.security {
            PersistedSecurityMode::Plaintext => SecurityMode::Plaintext,
            PersistedSecurityMode::Ssl {
                ca_path,
                certificate_path,
                key_path,
                key_password,
            } => SecurityMode::Ssl {
                ca_path,
                certificate_path,
                key_path,
                key_password: Secret::new(key_password),
            },
            PersistedSecurityMode::Sasl {
                transport,
                mechanism,
                username,
                password,
            } => {
                let transport = match transport {
                    PersistedSaslTransport::Plaintext => SaslTransport::Plaintext,
                    PersistedSaslTransport::Ssl => SaslTransport::Ssl,
                };
                let password = Secret::new(password);
                match mechanism {
                    PersistedSaslMechanism::Plain => SecurityMode::SaslPlain {
                        transport,
                        username,
                        password,
                    },
                    PersistedSaslMechanism::ScramSha256 => SecurityMode::SaslScramSha256 {
                        transport,
                        username,
                        password,
                    },
                    PersistedSaslMechanism::ScramSha512 => SecurityMode::SaslScramSha512 {
                        transport,
                        username,
                        password,
                    },
                }
            }
        };
        Self {
            id: profile.id,
            name: profile.name,
            bootstrap_servers: profile.bootstrap_servers,
            security,
            tls: profile.tls.map(|tls| TlsSettings {
                ca_path: tls.ca_path,
                certificate_path: tls.certificate_path,
                private_key_path: tls.private_key_path,
                private_key_password: Secret::new(tls.private_key_password),
            }),
        }
    }
}

#[cfg(test)]
pub fn filter_topics(query: &str, topics: &[String]) -> Vec<String> {
    let query = query.trim().to_lowercase();

    topics
        .iter()
        .filter(|topic| topic.to_lowercase().contains(&query))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        filter_topics, ConnectionProfile, PersistedProfile, ProfileValidationError, SaslMechanism,
        SaslTransport, Secret, TlsSettings,
    };

    #[test]
    fn filters_topics_case_insensitively() {
        let topics = vec!["orders.created".to_owned(), "audit.log".to_owned()];

        assert_eq!(filter_topics("ORDER", &topics), vec!["orders.created"]);
    }

    #[test]
    fn plain_sasl_requires_credentials() {
        let profile = ConnectionProfile::sasl_plain("localhost:9092", "", "");

        assert!(profile.validate().is_err());
    }

    #[test]
    fn sasl_ssl_requires_ca_certificate() {
        let profile = ConnectionProfile::sasl_plain("broker:9093", "alice", "test-password");

        assert_eq!(
            profile.validate(),
            Err(vec![ProfileValidationError::MissingCaCertificate])
        );
    }

    #[test]
    fn validation_collects_all_applicable_field_errors() {
        let mut profile = ConnectionProfile::sasl(
            " ",
            SaslTransport::Ssl,
            SaslMechanism::ScramSha256,
            " ",
            "",
            TlsSettings {
                private_key_path: Some("client.key".into()),
                ..TlsSettings::default()
            },
        );
        profile.name = " ".into();

        assert_eq!(
            profile.validate(),
            Err(vec![
                ProfileValidationError::MissingName,
                ProfileValidationError::MissingBootstrapServers,
                ProfileValidationError::MissingCaCertificate,
                ProfileValidationError::MissingClientCertificate,
                ProfileValidationError::MissingSaslUsername,
                ProfileValidationError::MissingSaslPassword,
            ])
        );
    }

    #[test]
    fn ssl_requires_ca_certificate() {
        assert_eq!(
            ConnectionProfile::ssl("broker:9093", TlsSettings::default()).validate(),
            Err(vec![ProfileValidationError::MissingCaCertificate])
        );
    }

    #[test]
    fn client_key_requires_client_certificate() {
        let mut tls = TlsSettings::with_ca("ca.pem");
        tls.private_key_path = Some("client.key".into());

        assert_eq!(
            ConnectionProfile::ssl("broker:9093", tls).validate(),
            Err(vec![ProfileValidationError::MissingClientCertificate])
        );
    }

    #[test]
    fn client_certificate_requires_private_key() {
        let mut tls = TlsSettings::with_ca("ca.pem");
        tls.certificate_path = Some("client.pem".into());

        assert_eq!(
            ConnectionProfile::ssl("broker:9093", tls).validate(),
            Err(vec![ProfileValidationError::MissingPrivateKey])
        );
    }

    #[test]
    fn blank_optional_tls_paths_are_absent() {
        let mut tls = TlsSettings::with_ca("ca.pem");
        tls.certificate_path = Some(" ".into());
        tls.private_key_path = Some("".into());
        assert_eq!(
            ConnectionProfile::ssl("broker:9093", tls.clone()).validate(),
            Ok(())
        );
        tls.private_key_path = Some("client.key".into());
        assert_eq!(
            ConnectionProfile::ssl("broker:9093", tls).validate(),
            Err(vec![ProfileValidationError::MissingClientCertificate])
        );
    }

    #[test]
    fn valid_profiles_cover_all_security_mechanisms_and_transports() {
        assert_eq!(
            ConnectionProfile::plaintext("broker:9092").validate(),
            Ok(())
        );
        let mut tls = TlsSettings::with_ca("ca.pem");
        tls.certificate_path = Some("client.pem".into());
        tls.private_key_path = Some("client.key".into());
        assert_eq!(
            ConnectionProfile::ssl("broker:9093", tls.clone()).validate(),
            Ok(())
        );
        for mechanism in [
            SaslMechanism::Plain,
            SaslMechanism::ScramSha256,
            SaslMechanism::ScramSha512,
        ] {
            for transport in [SaslTransport::Plaintext, SaslTransport::Ssl] {
                let settings = if transport == SaslTransport::Ssl {
                    tls.clone()
                } else {
                    TlsSettings::default()
                };
                assert_eq!(
                    ConnectionProfile::sasl(
                        "broker:9093",
                        transport,
                        mechanism,
                        "alice",
                        "test-password",
                        settings
                    )
                    .validate(),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn each_sasl_mechanism_reports_the_missing_credential_field() {
        for mechanism in [
            SaslMechanism::Plain,
            SaslMechanism::ScramSha256,
            SaslMechanism::ScramSha512,
        ] {
            let missing_username = ConnectionProfile::sasl(
                "broker:9092",
                SaslTransport::Plaintext,
                mechanism,
                " ",
                "test-password",
                TlsSettings::default(),
            );
            assert_eq!(
                format!("{:?}", missing_username.validate()),
                "Err([MissingSaslUsername])"
            );

            let missing_password = ConnectionProfile::sasl(
                "broker:9092",
                SaslTransport::Plaintext,
                mechanism,
                "alice",
                "",
                TlsSettings::default(),
            );
            assert_eq!(
                format!("{:?}", missing_password.validate()),
                "Err([MissingSaslPassword])"
            );
        }
    }

    #[test]
    fn summary_is_safe_for_ui_and_preserves_identity() {
        let mut profile = ConnectionProfile::sasl(
            "broker:9093",
            SaslTransport::Ssl,
            SaslMechanism::ScramSha512,
            "alice",
            "test-password",
            TlsSettings::with_ca("ca.pem"),
        );
        profile.name = "production".into();
        let summary = profile.summary();
        assert_eq!(summary.id, profile.id);
        assert_eq!(summary.name, "production");
        assert_eq!(summary.bootstrap_servers, "broker:9093");
        assert_eq!(summary.security, "SASL_SSL / SCRAM-SHA-512");
        assert!(!format!("{summary:?}").contains("test-password"));
    }

    #[test]
    fn persisted_profiles_round_trip_all_security_modes_and_secret_values() {
        let mut tls = TlsSettings::with_ca("ca.pem");
        tls.certificate_path = Some("client.pem".into());
        tls.private_key_path = Some("client.key".into());
        tls.private_key_password = Secret::new("test-key-password");
        let mut profiles = vec![
            ConnectionProfile::plaintext("broker:9092"),
            ConnectionProfile::ssl("broker:9093", tls.clone()),
        ];
        for mechanism in [
            SaslMechanism::Plain,
            SaslMechanism::ScramSha256,
            SaslMechanism::ScramSha512,
        ] {
            for transport in [SaslTransport::Plaintext, SaslTransport::Ssl] {
                profiles.push(ConnectionProfile::sasl(
                    "broker:9093",
                    transport,
                    mechanism,
                    "alice",
                    "test-password",
                    tls.clone(),
                ));
            }
        }
        for profile in profiles {
            let dto = PersistedProfile::from(&profile);
            let serialized = serde_json::to_string(&dto).unwrap();
            let restored: PersistedProfile = serde_json::from_str(&serialized).unwrap();
            assert_eq!(ConnectionProfile::from(restored), profile);
            for debug in [format!("{profile:?}"), format!("{dto:?}")] {
                assert!(!debug.contains("test-password"));
                assert!(!debug.contains("test-key-password"));
            }
        }
    }
}
