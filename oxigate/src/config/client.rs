use std::collections::HashMap;

use reqwest::{Client, ClientBuilder, Identity};
use serde::{Deserialize, Serialize};

use crate::config::route::{HeaderValue as RouteHeaderValue, ResolveContext};

/// Client identity (certificate + private key) used for mutual TLS (mTLS).
///
/// Two formats are supported:
///
/// **PEM** — separate certificate and key files, both PEM-encoded:
/// ```yaml
/// client_identity:
///   type: pem
///   cert: /etc/ssl/client/client.crt
///   key:  /etc/ssl/client/client.key
/// ```
///
/// **PKCS#12** — a single `.p12` / `.pfx` archive, optionally password-protected:
/// ```yaml
/// client_identity:
///   type: pkcs12
///   path: /etc/ssl/client/client.p12
///   password: "{{env:P12_PASSWORD}}"   # or a literal string, or omit for no password
/// ```
///
/// The `password` field in the PKCS#12 variant supports the same
/// `{{access_token}}`, `{{id_token}}`, and `{{env:NAME}}` placeholder
/// interpolation as header values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientIdentity {
    /// Identity supplied as separate PEM certificate and key files.
    Pem {
        /// Path to the PEM-encoded client certificate (may include the full chain).
        cert: String,
        /// Path to the PEM-encoded unencrypted private key for the client certificate.
        key: String,
    },
    /// Identity supplied as a PKCS#12 archive (`.p12` / `.pfx`).
    Pkcs12 {
        /// Path to the PKCS#12 archive.
        path: String,
        /// Optional password protecting the archive.
        /// Supports `{{env:VAR}}` placeholder interpolation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
}

/// TLS configuration for the upstream connection of a route.
///
/// Supports three independent axes:
/// - **Server verification** — `ca_cert` pins a private CA instead of the system store.
/// - **Mutual TLS (mTLS)** — `client_identity` presents a client certificate to the upstream.
/// - **Escape hatch** — `accept_invalid_certs` disables verification entirely (dev/test only).
///
/// # Example (YAML) — mTLS with PEM files
///
/// ```yaml
/// tls:
///   ca_cert: /etc/ssl/certs/my-ca.pem
///   client_identity:
///     type: pem
///     cert: /etc/ssl/client/client.crt
///     key:  /etc/ssl/client/client.key
/// ```
///
/// # Example (YAML) — mTLS with PKCS#12 archive
///
/// ```yaml
/// tls:
///   ca_cert: /etc/ssl/certs/my-ca.pem
///   client_identity:
///     type: pkcs12
///     path: /etc/ssl/client/client.p12
///     password: "{{env:P12_PASSWORD}}"
/// ```
///
/// # Example (YAML) — server CA only
///
/// ```yaml
/// tls:
///   ca_cert: /etc/ssl/certs/my-ca.pem
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to a PEM-encoded CA certificate (or bundle) used to verify the
    /// upstream's TLS certificate.  Useful when the upstream uses a private or
    /// self-signed CA that is not in the system trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,

    /// Client certificate and private key presented to the upstream during the
    /// TLS handshake.  Required when the upstream enforces mutual TLS (mTLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<ClientIdentity>,

    /// When `true`, TLS certificate validation is disabled for this route.
    ///
    /// ⚠️  **Never use in production.**  Intended only for local development
    /// or testing against self-signed certificates when adding the CA is not
    /// practical.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_invalid_certs: bool,
}

/// Error type for client registry operations.
#[derive(Debug)]
pub enum ClientRegistryError {
    /// Two or more clients share the same name.
    DuplicateName(String),
    /// Failed to read a TLS certificate file.
    TlsCertReadError(String, std::io::Error),
    /// Failed to build the reqwest client.
    ClientBuildError(String, reqwest::Error),
}

impl std::fmt::Display for ClientRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientRegistryError::DuplicateName(n) => write!(f, "Duplicate client name: \"{n}\""),
            ClientRegistryError::TlsCertReadError(n, e) => {
                write!(f, "Failed to read TLS cert for client \"{n}\": {e}")
            }
            ClientRegistryError::ClientBuildError(n, e) => {
                write!(f, "Failed to build client \"{n}\": {e}")
            }
        }
    }
}

impl std::error::Error for ClientRegistryError {}

/// Configuration for a single named reqwest HTTP client.
///
/// # YAML
///
/// ```yaml
/// name: backend-mtls
/// tls:
///   ca_cert: /etc/ssl/certs/my-ca.pem
///   client_identity:
///     type: pem
///     cert: /etc/ssl/client/client.crt
///     key:  /etc/ssl/client/client.key
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpClientConfig {
    /// Unique name identifying this client. Referenced by routes via `client_name`.
    pub name: String,

    /// Maximum time (in milliseconds) to wait for the upstream to respond.
    /// `None` means no explicit timeout is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Optional TLS configuration (CA cert, client identity, accept_invalid_certs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

/// A registry of named [`HttpClientConfig`] entries that can be built into
/// a [`HashMap<String, Client>`] for use in [`ProxyState`].
///
/// # Rules
///
/// - Names must be unique; [`HttpClientRegistry::build`] returns
///   [`ClientRegistryError::DuplicateName`] on the first collision.
///
/// # YAML
///
/// ```yaml
/// clients:
///   - name: default-backend
///   - name: secure-backend
///     tls:
///       ca_cert: /etc/ssl/certs/my-ca.pem
///   - name: mtls-backend
///     tls:
///       client_identity:
///         type: pkcs12
///         path: /etc/ssl/client/client.p12
///         password: "{{env:P12_PASSWORD}}"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HttpClientRegistry {
    /// Ordered list of client configurations.
    #[serde(default)]
    pub clients: Vec<HttpClientConfig>,
}

impl HttpClientRegistry {
    /// Build a [`HashMap<String, (HttpClientConfig, Client)>`] from the registry.
    ///
    /// Returns `Err` if:
    /// - Two clients share the same name.
    /// - A TLS certificate file cannot be read or parsed.
    pub fn build(
        &self,
    ) -> Result<HashMap<String, (HttpClientConfig, Client)>, ClientRegistryError> {
        // Check uniqueness first.
        let mut seen: HashMap<&str, ()> = HashMap::new();
        for cfg in &self.clients {
            if seen.insert(cfg.name.as_str(), ()).is_some() {
                return Err(ClientRegistryError::DuplicateName(cfg.name.clone()));
            }
        }

        self.clients
            .iter()
            .map(|cfg| {
                let client = build_client_from_config(cfg)?;
                Ok((cfg.name.clone(), (cfg.clone(), client)))
            })
            .collect()
    }
}

/// Build a reqwest [`Client`] from an [`HttpClientConfig`].
pub(crate) fn build_client_from_config(
    cfg: &HttpClientConfig,
) -> Result<Client, ClientRegistryError> {
    let mut builder = ClientBuilder::new();
    let name = &cfg.name;

    if let Some(tls) = &cfg.tls {
        if tls.accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(cert_path) = &tls.ca_cert {
            let pem = std::fs::read(cert_path)
                .map_err(|e| ClientRegistryError::TlsCertReadError(name.clone(), e))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| ClientRegistryError::ClientBuildError(name.clone(), e))?;
            builder = builder.add_root_certificate(cert);
        }

        if let Some(identity) = &tls.client_identity {
            let id = load_identity(name, identity)?;
            builder = builder.identity(id);
        }
    }

    builder
        .build()
        .map_err(|e| ClientRegistryError::ClientBuildError(name.clone(), e))
}

fn load_identity(name: &str, identity: &ClientIdentity) -> Result<Identity, ClientRegistryError> {
    match identity {
        ClientIdentity::Pem { cert, key } => {
            let cert_pem = std::fs::read(cert)
                .map_err(|e| ClientRegistryError::TlsCertReadError(name.to_string(), e))?;
            let key_pem = std::fs::read(key)
                .map_err(|e| ClientRegistryError::TlsCertReadError(name.to_string(), e))?;
            let mut combined = cert_pem;
            combined.extend_from_slice(&key_pem);
            Identity::from_pem(&combined)
                .map_err(|e| ClientRegistryError::ClientBuildError(name.to_string(), e))
        }
        ClientIdentity::Pkcs12 { path, password } => {
            let der = std::fs::read(path)
                .map_err(|e| ClientRegistryError::TlsCertReadError(name.to_string(), e))?;
            let resolved_password = match password {
                None => String::new(),
                Some(raw) => {
                    let hv: RouteHeaderValue = serde_yaml::from_str(&format!("\"{raw}\""))
                        .unwrap_or(RouteHeaderValue::Literal(raw.clone()));
                    let ctx = ResolveContext::new("", "");
                    hv.resolve(&ctx)
                }
            };
            Identity::from_pkcs12_der(&der, &resolved_password)
                .map_err(|e| ClientRegistryError::ClientBuildError(name.to_string(), e))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cfg(name: &str) -> HttpClientConfig {
        HttpClientConfig {
            name: name.to_string(),
            timeout_ms: None,
            tls: None,
        }
    }

    #[test]
    fn empty_registry_builds_empty_map() {
        let registry = HttpClientRegistry::default();
        let map = registry.build().expect("build");
        assert!(map.is_empty());
    }

    #[test]
    fn unique_names_build_ok() {
        let registry = HttpClientRegistry {
            clients: vec![make_cfg("alpha"), make_cfg("beta")],
        };
        let map = registry.build().expect("build");
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("alpha"));
        assert!(map.contains_key("beta"));
        // Verify the config is stored alongside the client.
        assert_eq!(map["alpha"].0.name, "alpha");
        assert_eq!(map["beta"].0.name, "beta");
    }

    #[test]
    fn duplicate_names_rejected() {
        let registry = HttpClientRegistry {
            clients: vec![make_cfg("alpha"), make_cfg("beta"), make_cfg("alpha")],
        };
        let err = registry.build().unwrap_err();
        assert!(matches!(err, ClientRegistryError::DuplicateName(n) if n == "alpha"));
    }

    #[test]
    fn roundtrip_yaml() {
        let yaml = r#"
clients:
  - name: plain-client
  - name: ca-client
    tls:
      ca_cert: /etc/ssl/certs/ca.pem
"#;
        let registry: HttpClientRegistry = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(registry.clients.len(), 2);
        assert_eq!(registry.clients[0].name, "plain-client");
        assert_eq!(registry.clients[0].timeout_ms, None);
        assert!(registry.clients[0].tls.is_none());
        assert_eq!(registry.clients[1].name, "ca-client");
        assert_eq!(
            registry.clients[1].tls.as_ref().unwrap().ca_cert.as_deref(),
            Some("/etc/ssl/certs/ca.pem")
        );

        let back = serde_yaml::to_string(&registry).expect("serialize");
        let decoded: HttpClientRegistry = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(registry, decoded);
    }

    #[test]
    fn timeout_ms_roundtrip_yaml() {
        let yaml = r#"
clients:
  - name: fast-client
    timeout_ms: 3000
"#;
        let registry: HttpClientRegistry = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(registry.clients[0].timeout_ms, Some(3000));
        let back = serde_yaml::to_string(&registry).expect("serialize");
        let decoded: HttpClientRegistry = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(registry, decoded);
    }
}
