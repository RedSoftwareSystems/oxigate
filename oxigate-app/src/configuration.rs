use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bind address
// ---------------------------------------------------------------------------

/// A TCP bind address (IP + port).
///
/// # YAML
///
/// ```yaml
/// address: 0.0.0.0
/// port: 8080
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindAddress {
    /// IP address to bind to. Defaults to `0.0.0.0` (all interfaces).
    #[serde(default = "BindAddress::default_address")]
    pub address: IpAddr,

    /// TCP port to listen on.
    pub port: u16,
}

impl BindAddress {
    fn default_address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

impl std::fmt::Display for BindAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

// ---------------------------------------------------------------------------
// Server-side TLS identity
// ---------------------------------------------------------------------------

/// Server-side TLS certificate and private key.
///
/// Used to configure the HTTPS listener. Both PEM and PKCS#12 formats are
/// supported.
///
/// # YAML — PEM
///
/// ```yaml
/// server_identity:
///   format: pem
///   cert: /etc/oxigate/tls/server.crt
///   key:  /etc/oxigate/tls/server.key
/// ```
///
/// # YAML — PKCS#12
///
/// ```yaml
/// server_identity:
///   format: pkcs12
///   path:     /etc/oxigate/tls/server.p12
///   password: "{{env:SERVER_P12_PASSWORD}}"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ServerIdentity {
    /// PEM-encoded certificate (chain) + unencrypted private key.
    Pem {
        /// Path to the PEM-encoded server certificate (may include the full
        /// chain up to, but not including, the root CA).
        cert: PathBuf,
        /// Path to the PEM-encoded unencrypted private key.
        key: PathBuf,
    },
    /// PKCS#12 archive bundling the certificate and private key.
    Pkcs12 {
        /// Path to the `.p12` / `.pfx` archive.
        path: PathBuf,
        /// Optional password protecting the archive.
        /// Supports `{{env:VAR}}` placeholder interpolation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Mutual TLS (mTLS) client verification
// ---------------------------------------------------------------------------

/// Controls how the server verifies client certificates in mTLS mode.
///
/// # YAML
///
/// ```yaml
/// client_auth:
///   ca_cert: /etc/oxigate/tls/client-ca.pem
///   require: true
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    /// Path to the PEM-encoded CA certificate (or bundle) used to verify
    /// connecting clients' certificates.
    pub ca_cert: PathBuf,

    /// When `true` (default), the server rejects connections that do not
    /// present a valid client certificate signed by `ca_cert`.
    /// When `false`, client certificates are requested but optional.
    #[serde(default = "ClientAuthConfig::default_require")]
    pub require: bool,
}

impl ClientAuthConfig {
    fn default_require() -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// HTTPS / TLS listener config
// ---------------------------------------------------------------------------

/// Configuration for the HTTPS listener.
///
/// Supports HTTP/1.1 and HTTP/2 (negotiated via ALPN) and optional mutual
/// TLS client authentication.
///
/// # YAML — HTTPS with mTLS and HTTP/2
///
/// ```yaml
/// https:
///   bind:
///     address: 0.0.0.0
///     port: 8443
///   server_identity:
///     format: pem
///     cert: /etc/oxigate/tls/server.crt
///     key:  /etc/oxigate/tls/server.key
///   client_auth:
///     ca_cert: /etc/oxigate/tls/client-ca.pem
///     require: true
///   http2: true
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpsConfig {
    /// Socket address the HTTPS listener binds to.
    pub bind: BindAddress,

    /// Server certificate and private key.
    pub server_identity: ServerIdentity,

    /// Optional mutual TLS (mTLS) client authentication.
    ///
    /// When `None`, no client certificate is requested (standard one-way TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<ClientAuthConfig>,

    /// Enable HTTP/2 negotiation via ALPN.
    ///
    /// When `true` the server advertises `h2` and `http/1.1` in the TLS
    /// handshake and uses HTTP/2 when the client supports it.
    /// Defaults to `true`.
    #[serde(default = "HttpsConfig::default_http2")]
    pub http2: bool,
}

impl HttpsConfig {
    fn default_http2() -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// HTTP (plain) listener config
// ---------------------------------------------------------------------------

/// Configuration for the plain HTTP listener.
///
/// # YAML
///
/// ```yaml
/// http:
///   bind:
///     address: 0.0.0.0
///     port: 8080
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Socket address the HTTP listener binds to.
    pub bind: BindAddress,
}

// ---------------------------------------------------------------------------
// Config file paths
// ---------------------------------------------------------------------------

/// Paths to the YAML configuration files loaded at startup.
///
/// # YAML
///
/// ```yaml
/// config_files:
///   routes:  /etc/oxigate/routes.yaml
///   clients: /etc/oxigate/clients.yaml
///   auth:    /etc/oxigate/auth.yaml     # optional
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFilePaths {
    /// Path to the YAML file containing the list of
    /// [`oxigate::config::route::ReverseProxyRoute`] entries.
    pub routes: PathBuf,

    /// Path to the YAML file containing the
    /// [`oxigate::config::client::HttpClientRegistry`] (named HTTP clients).
    pub clients: PathBuf,

    /// Optional path to the YAML file containing the
    /// [`oxigate::config::auth::AuthConfig`] for the OIDC/OAuth2
    /// `AuthenticationLayer`.  When absent, no authentication layer is added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Logging config
// ---------------------------------------------------------------------------

/// Log level for the gateway.
///
/// Maps directly to the `tracing` crate's level filter.
///
/// # YAML
///
/// ```yaml
/// log_level: info
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// GatewayConfig — top-level
// ---------------------------------------------------------------------------

/// Full configuration for the Oxigate API gateway.
///
/// Deserialise from a YAML file at startup and pass to the server builder.
///
/// # Listener modes
///
/// | `http` | `https` | Result                                       |
/// |:------:|:-------:|----------------------------------------------|
/// | set    | not set | Plain HTTP only                              |
/// | not set| set     | HTTPS only (TLS, optional mTLS, optional H2) |
/// | set    | set     | Both listeners run concurrently              |
///
/// At least one of `http` or `https` must be provided.
///
/// # Full example (YAML)
///
/// ```yaml
/// http:
///   bind:
///     address: 0.0.0.0
///     port: 8080
///
/// https:
///   bind:
///     address: 0.0.0.0
///     port: 8443
///   server_identity:
///     format: pem
///     cert: /etc/oxigate/tls/server.crt
///     key:  /etc/oxigate/tls/server.key
///   client_auth:
///     ca_cert: /etc/oxigate/tls/client-ca.pem
///     require: true
///   http2: true
///
/// config_files:
///   routes:  /etc/oxigate/routes.yaml
///   clients: /etc/oxigate/clients.yaml
///   auth:    /etc/oxigate/auth.yaml
///
/// log_level: info
/// ```
///
/// # Minimal example — HTTP only
///
/// ```yaml
/// http:
///   bind:
///     port: 8080
///
/// config_files:
///   routes:  /etc/oxigate/routes.yaml
///   clients: /etc/oxigate/clients.yaml
/// ```
///
/// # Minimal example — HTTPS only (self-signed, no mTLS)
///
/// ```yaml
/// https:
///   bind:
///     port: 8443
///   server_identity:
///     format: pem
///     cert: /etc/oxigate/tls/server.crt
///     key:  /etc/oxigate/tls/server.key
///
/// config_files:
///   routes:  /etc/oxigate/routes.yaml
///   clients: /etc/oxigate/clients.yaml
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    // ── Listeners ────────────────────────────────────────────────────────────
    /// Plain HTTP listener.  When `None`, no HTTP socket is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,

    /// HTTPS listener with TLS termination, optional mTLS, and optional
    /// HTTP/2.  When `None`, no HTTPS socket is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<HttpsConfig>,

    // ── Config file paths ─────────────────────────────────────────────────────
    /// Paths to the YAML configuration files for routes, clients, and auth.
    pub config_files: ConfigFilePaths,

    // ── Observability ─────────────────────────────────────────────────────────
    /// Minimum log level emitted by the gateway. Defaults to `info`.
    #[serde(default)]
    pub log_level: LogLevel,
}

impl GatewayConfig {
    /// Load a [`GatewayConfig`] from a YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if the YAML is invalid.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        let config = serde_yaml::from_str(&content)
            .map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
        Ok(config)
    }

    /// Returns `true` when at least one listener (HTTP or HTTPS) is configured.
    pub fn has_listener(&self) -> bool {
        self.http.is_some() || self.https.is_some()
    }

    /// Validate that the configuration is self-consistent.
    ///
    /// Returns `Err` when:
    /// - Neither `http` nor `https` is configured.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.has_listener() {
            return Err(ConfigError::NoListener);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ConfigError
// ---------------------------------------------------------------------------

/// Errors that can occur while loading or validating [`GatewayConfig`].
#[derive(Debug)]
pub enum ConfigError {
    /// The configuration file could not be read.
    Io(PathBuf, std::io::Error),
    /// The YAML content could not be parsed into [`GatewayConfig`].
    Parse(PathBuf, serde_yaml::Error),
    /// Neither `http` nor `https` listener is configured.
    NoListener,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(path, e) => {
                write!(f, "Cannot read config file {}: {e}", path.display())
            }
            ConfigError::Parse(path, e) => {
                write!(f, "Cannot parse config file {}: {e}", path.display())
            }
            ConfigError::NoListener => write!(
                f,
                "Invalid configuration: at least one of `http` or `https` must be configured"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn http_only_yaml() -> &'static str {
        r#"
http:
  bind:
    address: "0.0.0.0"
    port: 8080

config_files:
  routes:  /etc/oxigate/routes.yaml
  clients: /etc/oxigate/clients.yaml
"#
    }

    fn https_only_yaml() -> &'static str {
        r#"
https:
  bind:
    address: "0.0.0.0"
    port: 8443
  server_identity:
    format: pem
    cert: /etc/oxigate/tls/server.crt
    key:  /etc/oxigate/tls/server.key
  http2: true

config_files:
  routes:  /etc/oxigate/routes.yaml
  clients: /etc/oxigate/clients.yaml
"#
    }

    fn full_yaml() -> &'static str {
        r#"
http:
  bind:
    address: "127.0.0.1"
    port: 8080

https:
  bind:
    address: "0.0.0.0"
    port: 8443
  server_identity:
    format: pem
    cert: /etc/oxigate/tls/server.crt
    key:  /etc/oxigate/tls/server.key
  client_auth:
    ca_cert: /etc/oxigate/tls/client-ca.pem
    require: true
  http2: true

config_files:
  routes:  /etc/oxigate/routes.yaml
  clients: /etc/oxigate/clients.yaml
  auth:    /etc/oxigate/auth.yaml

log_level: debug
"#
    }

    fn pkcs12_yaml() -> &'static str {
        r#"
https:
  bind:
    port: 8443
  server_identity:
    format: pkcs12
    path: /etc/oxigate/tls/server.p12
    password: "{{env:SERVER_P12_PASSWORD}}"

config_files:
  routes:  /etc/oxigate/routes.yaml
  clients: /etc/oxigate/clients.yaml
"#
    }

    #[test]
    fn http_only_deserializes() {
        let cfg: GatewayConfig = serde_yaml::from_str(http_only_yaml()).expect("deserialize");
        assert!(cfg.http.is_some());
        assert!(cfg.https.is_none());
        let http = cfg.http.unwrap();
        assert_eq!(http.bind.port, 8080);
        assert_eq!(http.bind.address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(cfg.config_files.auth.is_none());
        assert_eq!(cfg.log_level, LogLevel::Info);
    }

    #[test]
    fn https_only_deserializes() {
        let cfg: GatewayConfig = serde_yaml::from_str(https_only_yaml()).expect("deserialize");
        assert!(cfg.http.is_none());
        let https = cfg.https.as_ref().expect("https present");
        assert_eq!(https.bind.port, 8443);
        assert!(https.http2);
        assert!(https.client_auth.is_none());
        assert!(matches!(
            &https.server_identity,
            ServerIdentity::Pem { cert, key }
            if cert == std::path::Path::new("/etc/oxigate/tls/server.crt")
            && key  == std::path::Path::new("/etc/oxigate/tls/server.key")
        ));
    }

    #[test]
    fn full_config_deserializes() {
        let cfg: GatewayConfig = serde_yaml::from_str(full_yaml()).expect("deserialize");

        // HTTP
        let http = cfg.http.as_ref().expect("http present");
        assert_eq!(http.bind.port, 8080);
        assert_eq!(http.bind.address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // HTTPS
        let https = cfg.https.as_ref().expect("https present");
        assert_eq!(https.bind.port, 8443);
        assert!(https.http2);

        // mTLS client auth
        let client_auth = https.client_auth.as_ref().expect("client_auth present");
        assert_eq!(
            client_auth.ca_cert,
            PathBuf::from("/etc/oxigate/tls/client-ca.pem")
        );
        assert!(client_auth.require);

        // Config files
        assert_eq!(
            cfg.config_files.routes,
            PathBuf::from("/etc/oxigate/routes.yaml")
        );
        assert_eq!(
            cfg.config_files.clients,
            PathBuf::from("/etc/oxigate/clients.yaml")
        );
        assert_eq!(
            cfg.config_files.auth,
            Some(PathBuf::from("/etc/oxigate/auth.yaml"))
        );

        // Log level
        assert_eq!(cfg.log_level, LogLevel::Debug);
    }

    #[test]
    fn pkcs12_server_identity_deserializes() {
        let cfg: GatewayConfig = serde_yaml::from_str(pkcs12_yaml()).expect("deserialize");
        let https = cfg.https.as_ref().expect("https present");
        assert!(matches!(
            &https.server_identity,
            ServerIdentity::Pkcs12 { path, password }
            if path == std::path::Path::new("/etc/oxigate/server.p12")
                || password.as_deref() == Some("{{env:SERVER_P12_PASSWORD}}")
        ));
    }

    #[test]
    fn roundtrip_yaml_full() {
        let cfg: GatewayConfig = serde_yaml::from_str(full_yaml()).expect("deserialize");
        let serialized = serde_yaml::to_string(&cfg).expect("serialize");
        let decoded: GatewayConfig = serde_yaml::from_str(&serialized).expect("re-deserialize");
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn validate_no_listener_errors() {
        let yaml = r#"
config_files:
  routes:  /etc/oxigate/routes.yaml
  clients: /etc/oxigate/clients.yaml
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).expect("deserialize");
        assert!(matches!(cfg.validate(), Err(ConfigError::NoListener)));
    }

    #[test]
    fn validate_http_only_ok() {
        let cfg: GatewayConfig = serde_yaml::from_str(http_only_yaml()).expect("deserialize");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_https_only_ok() {
        let cfg: GatewayConfig = serde_yaml::from_str(https_only_yaml()).expect("deserialize");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn client_auth_optional_require_defaults_true() {
        let yaml = r#"
https:
  bind:
    port: 8443
  server_identity:
    format: pem
    cert: /etc/oxigate/tls/server.crt
    key:  /etc/oxigate/tls/server.key
  client_auth:
    ca_cert: /etc/oxigate/tls/client-ca.pem

config_files:
  routes:  /r.yaml
  clients: /c.yaml
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).expect("deserialize");
        let ca = cfg.https.unwrap().client_auth.expect("client_auth present");
        assert!(ca.require, "require should default to true");
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn bind_address_display() {
        let addr = BindAddress {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8080,
        };
        assert_eq!(addr.to_string(), "0.0.0.0:8080");
    }
}
