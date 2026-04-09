use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// HTTP methods supported by the reverse proxy route matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
}

/// Defines how the incoming request path is matched against the route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum PathMatcher {
    /// Exact path match (e.g. `/api/health`).
    Exact(String),
    /// Prefix match — any path starting with the given prefix is accepted
    /// (e.g. `/api/` matches `/api/users`, `/api/orders`, …).
    Prefix(String),
    /// Full regular-expression match against the request path.
    Regex(String),
}

/// Controls how the upstream URL is constructed from the matched request path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteRule {
    /// Forward the path unchanged to the upstream.
    #[default]
    PassThrough,
    /// Strip the matched prefix and forward the remainder.
    /// Only meaningful when used together with `PathMatcher::Prefix`.
    StripPrefix,
    /// Replace the entire path with a fixed string.
    Replace(String),
}

/// A variable that can be interpolated into an upstream request header value.
///
/// | YAML placeholder        | Variant                  | Resolved value                        |
/// |-------------------------|--------------------------|---------------------------------------|
/// | `{{access_token}}`      | `AccessToken`            | Current OAuth2 access token           |
/// | `{{id_token}}`          | `IdToken`                | Current OIDC ID token                 |
/// | `{{env:VAR_NAME}}`      | `Env("VAR_NAME")`        | Value of the `VAR_NAME` env variable  |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderVariable {
    /// The OAuth2 access token for the current session.
    AccessToken,
    /// The OIDC ID token for the current session.
    IdToken,
    /// A system / environment variable identified by name.
    Env(String),
}

/// The value of an injected upstream request header.
///
/// A value is either a plain literal string or a reference to a variable
/// that is resolved at request time.
///
/// # YAML representations
///
/// Plain literal:
/// ```yaml
/// headers:
///   X-Custom-Header: "hello"
/// ```
///
/// Application variable — access token:
/// ```yaml
/// headers:
///   Authorization: "{{access_token}}"
/// ```
///
/// Application variable — ID token:
/// ```yaml
/// headers:
///   X-Id-Token: "{{id_token}}"
/// ```
///
/// System / environment variable:
/// ```yaml
/// headers:
///   X-Api-Key: "{{env:API_KEY}}"
///   X-Region:  "{{env:AWS_REGION}}"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    /// A fixed, literal header value.
    Literal(String),
    /// A variable whose value is substituted when the request is forwarded.
    Variable(HeaderVariable),
}

// ---------------------------------------------------------------------------
// Custom serde for HeaderVariable
//
// Serialised as the inner string of the `{{…}}` placeholder without braces:
//   AccessToken  ->  "access_token"
//   IdToken      ->  "id_token"
//   Env("FOO")   ->  "env:FOO"
//
// This is an internal representation used by HeaderValue's serde impl.
// ---------------------------------------------------------------------------

impl HeaderVariable {
    fn to_placeholder(&self) -> String {
        match self {
            HeaderVariable::AccessToken => "access_token".to_owned(),
            HeaderVariable::IdToken => "id_token".to_owned(),
            HeaderVariable::Env(name) => format!("env:{name}"),
        }
    }

    fn from_placeholder(s: &str) -> Option<Self> {
        match s {
            "access_token" => Some(HeaderVariable::AccessToken),
            "id_token" => Some(HeaderVariable::IdToken),
            other if other.starts_with("env:") => {
                let name = other.trim_start_matches("env:").to_owned();
                if name.is_empty() {
                    None
                } else {
                    Some(HeaderVariable::Env(name))
                }
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Custom serde for HeaderValue
//
// Serialised as a plain string:
//   Literal("hello")              ->  "hello"
//   Variable(AccessToken)         ->  "{{access_token}}"
//   Variable(IdToken)             ->  "{{id_token}}"
//   Variable(Env("API_KEY"))      ->  "{{env:API_KEY}}"
// ---------------------------------------------------------------------------

impl Serialize for HeaderValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let raw = match self {
            HeaderValue::Literal(v) => v.clone(),
            HeaderValue::Variable(var) => {
                let placeholder = var.to_placeholder();
                format!("{{{{{placeholder}}}}}")
            }
        };
        s.serialize_str(&raw)
    }
}

impl<'de> Deserialize<'de> for HeaderValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let trimmed = raw.trim();

        // Match `{{...}}` placeholders.
        if let Some(inner) = trimmed
            .strip_prefix("{{")
            .and_then(|s| s.strip_suffix("}}"))
            && let Some(var) = HeaderVariable::from_placeholder(inner.trim())
        {
            return Ok(HeaderValue::Variable(var));
        }

        Ok(HeaderValue::Literal(raw))
    }
}

// ---------------------------------------------------------------------------
// Resolution context
// ---------------------------------------------------------------------------

/// Runtime context passed to [`HeaderValue::resolve`].
///
/// Carries the session tokens and an optional snapshot of system variables
/// (typically populated from `std::env::vars()` at startup, or from a
/// custom provider).  Using a pre-collected `HashMap` instead of calling
/// `std::env::var` directly makes resolution pure, testable, and immune to
/// TOCTOU races on the environment.
pub struct ResolveContext<'a> {
    /// Current OAuth2 access token.
    pub access_token: &'a str,
    /// Current OIDC ID token.
    pub id_token: &'a str,
    /// System / environment variables keyed by name.
    /// If `None`, resolution of `{{env:…}}` placeholders falls back to
    /// [`std::env::var`] at call time.
    pub env: Option<&'a HashMap<String, String>>,
}

impl<'a> ResolveContext<'a> {
    /// Convenience constructor for contexts without system-variable support.
    pub fn new(access_token: &'a str, id_token: &'a str) -> Self {
        Self {
            access_token,
            id_token,
            env: None,
        }
    }

    /// Constructor with a pre-collected environment snapshot.
    pub fn with_env(
        access_token: &'a str,
        id_token: &'a str,
        env: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            access_token,
            id_token,
            env: Some(env),
        }
    }
}

impl HeaderValue {
    /// Resolve the header value against the given [`ResolveContext`].
    ///
    /// | Variant                 | Result                                                         |
    /// |-------------------------|----------------------------------------------------------------|
    /// | `Literal(s)`            | `s` unchanged                                                  |
    /// | `Variable(AccessToken)` | `ctx.access_token`                                             |
    /// | `Variable(IdToken)`     | `ctx.id_token`                                                 |
    /// | `Variable(Env(name))`   | value from `ctx.env` map, or `std::env::var`, or empty string  |
    pub fn resolve(&self, ctx: &ResolveContext<'_>) -> String {
        match self {
            HeaderValue::Literal(v) => v.clone(),
            HeaderValue::Variable(HeaderVariable::AccessToken) => ctx.access_token.to_string(),
            HeaderValue::Variable(HeaderVariable::IdToken) => ctx.id_token.to_string(),
            HeaderValue::Variable(HeaderVariable::Env(name)) => ctx
                .env
                .and_then(|map| map.get(name).cloned())
                .or_else(|| std::env::var(name).ok())
                .unwrap_or_default(),
        }
    }
}

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

/// Header manipulation rules for one traffic direction (inbound or outbound).
///
/// Header values in `add` may reference runtime variables:
/// - `{{access_token}}` — current OAuth2 access token.
/// - `{{id_token}}`     — current OIDC ID token.
/// - `{{env:NAME}}`     — system environment variable `NAME`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersConfig {
    /// Headers to inject. For request headers these are forwarded to the
    /// upstream; for response headers these are returned to the client.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub add: HashMap<String, HeaderValue>,

    /// Header names to remove before forwarding / returning.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip: Vec<String>,
}

/// A single reverse-proxy routing rule.
///
/// Each `ReverseProxyRoute` maps an incoming request (identified by an
/// optional HTTP method and a path matcher) to an upstream service URL,
/// optionally rewriting the path and injecting extra headers.
///
/// # Example (YAML)
///
/// ```yaml
/// name: api-backend
/// path:
///   type: prefix
///   value: /api/
/// upstream_url: http://backend-service:8080
/// methods:
///   - GET
///   - POST
/// rewrite: strip_prefix
/// request_headers:
///   add:
///     Authorization: "{{access_token}}"
///     X-Id-Token:    "{{id_token}}"
///     X-Api-Key:     "{{env:API_KEY}}"
///     X-Forwarded-Prefix: /api
///   strip:
///     - Cookie
/// response_headers:
///   strip:
///     - X-Internal-Server
/// enabled: true
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReverseProxyRoute {
    /// Human-readable name for this route (used in logs and metrics).
    pub name: String,

    /// Rule used to match the incoming request path.
    pub path: PathMatcher,

    /// Base URL of the upstream service requests are forwarded to
    /// (e.g. `http://backend:8080`). Must **not** contain a trailing slash.
    pub upstream_url: String,

    /// Restrict matching to specific HTTP methods.
    /// When empty all methods are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<HttpMethod>,

    /// Controls how the upstream request path is built from the matched path.
    /// Defaults to `PassThrough` when omitted.
    #[serde(default = "RewriteRule::default")]
    pub rewrite: RewriteRule,

    /// Header manipulation rules applied to the inbound request before it is
    /// forwarded to the upstream (`add` injects headers, `strip` removes them).
    #[serde(default, skip_serializing_if = "HeadersConfig::is_empty")]
    pub request_headers: HeadersConfig,

    /// Header manipulation rules applied to the upstream response before it is
    /// returned to the client (`add` injects headers, `strip` removes them).
    #[serde(default, skip_serializing_if = "HeadersConfig::is_empty")]
    pub response_headers: HeadersConfig,

    /// Maximum time (in milliseconds) to wait for the upstream to respond.
    /// `None` means no explicit timeout is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Optional TLS configuration for the upstream connection.
    /// When `None`, the system trust store is used and certificate validation
    /// is performed normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    /// Whether this route is active. Disabled routes are loaded but never matched.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Default helpers
// ---------------------------------------------------------------------------

impl HeadersConfig {
    /// Returns `true` when both `add` and `strip` are empty, used by serde's
    /// `skip_serializing_if`.
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.strip.is_empty()
    }
}

fn default_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_route() -> ReverseProxyRoute {
        ReverseProxyRoute {
            name: "api-backend".to_string(),
            path: PathMatcher::Prefix("/api/".to_string()),
            upstream_url: "http://backend:8080".to_string(),
            methods: vec![HttpMethod::Get, HttpMethod::Post],
            rewrite: RewriteRule::StripPrefix,
            tls: Some(TlsConfig {
                ca_cert: Some("/etc/ssl/certs/my-ca.pem".to_string()),
                client_identity: Some(ClientIdentity::Pem {
                    cert: "/etc/ssl/client/client.crt".to_string(),
                    key: "/etc/ssl/client/client.key".to_string(),
                }),
                accept_invalid_certs: false,
            }),
            request_headers: HeadersConfig {
                add: [
                    (
                        "Authorization".to_string(),
                        HeaderValue::Variable(HeaderVariable::AccessToken),
                    ),
                    (
                        "X-Id-Token".to_string(),
                        HeaderValue::Variable(HeaderVariable::IdToken),
                    ),
                    (
                        "X-Api-Key".to_string(),
                        HeaderValue::Variable(HeaderVariable::Env("API_KEY".to_string())),
                    ),
                    (
                        "X-Forwarded-Prefix".to_string(),
                        HeaderValue::Literal("/api".to_string()),
                    ),
                ]
                .into_iter()
                .collect(),
                strip: vec!["Cookie".to_string()],
            },
            response_headers: HeadersConfig {
                add: HashMap::new(),
                strip: vec!["X-Internal-Server".to_string()],
            },

            timeout_ms: Some(5000),
            enabled: true,
        }
    }

    #[test]
    fn tls_config_roundtrip_yaml() {
        let yaml = r#"
name: tls-route
path:
  type: exact
  value: /secure
upstream_url: "https://secure-svc:8443"
tls:
  ca_cert: /etc/ssl/certs/my-ca.pem
  accept_invalid_certs: false
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        let tls = route.tls.clone().expect("tls config present");
        assert_eq!(tls.ca_cert.as_deref(), Some("/etc/ssl/certs/my-ca.pem"));
        assert!(tls.client_identity.is_none());
        assert!(!tls.accept_invalid_certs);

        let back = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn tls_accept_invalid_certs_skipped_when_false() {
        // accept_invalid_certs: false must be omitted from the serialized form.
        let route = ReverseProxyRoute {
            name: "r".to_string(),
            path: PathMatcher::Exact("/".to_string()),
            upstream_url: "https://svc".to_string(),
            methods: vec![],
            rewrite: RewriteRule::PassThrough,
            request_headers: Default::default(),
            response_headers: Default::default(),
            timeout_ms: None,
            tls: Some(TlsConfig {
                ca_cert: None,
                client_identity: None,
                accept_invalid_certs: false,
            }),
            enabled: true,
        };
        let yaml = serde_yaml::to_string(&route).expect("serialize");
        assert!(!yaml.contains("accept_invalid_certs"), "should be skipped");
    }

    #[test]
    fn tls_mtls_pem_roundtrip_yaml() {
        let yaml = r#"
name: mtls-route
path:
  type: exact
  value: /mtls
upstream_url: "https://secure-svc:8443"
tls:
  ca_cert: /etc/ssl/certs/my-ca.pem
  client_identity:
    type: pem
    cert: /etc/ssl/client/client.crt
    key: /etc/ssl/client/client.key
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        let tls = route.tls.clone().expect("tls present");
        let identity = tls.client_identity.expect("client_identity present");
        assert!(matches!(identity, ClientIdentity::Pem { cert, key }
                if cert == "/etc/ssl/client/client.crt" && key == "/etc/ssl/client/client.key"));

        // Roundtrip
        let back = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn tls_mtls_pkcs12_roundtrip_yaml() {
        let yaml = r#"
name: mtls-pkcs12-route
path:
  type: exact
  value: /mtls-pkcs12
upstream_url: "https://secure-svc:8443"
tls:
  client_identity:
    type: pkcs12
    path: /etc/ssl/client/client.p12
    password: "{{env:P12_PASSWORD}}"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        let tls = route.tls.clone().expect("tls present");
        let identity = tls.client_identity.expect("client_identity present");
        assert!(
            matches!(&identity, ClientIdentity::Pkcs12 { path, password }
                if path == "/etc/ssl/client/client.p12"
                && password.as_deref() == Some("{{env:P12_PASSWORD}}"))
        );

        // Roundtrip
        let back = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn tls_mtls_pkcs12_no_password_roundtrip_yaml() {
        let yaml = r#"
name: mtls-pkcs12-nopass
path:
  type: exact
  value: /mtls-nopass
upstream_url: "https://secure-svc:8443"
tls:
  client_identity:
    type: pkcs12
    path: /etc/ssl/client/client.p12
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        let tls = route.tls.clone().expect("tls present");
        let identity = tls.client_identity.expect("client_identity present");
        assert!(
            matches!(&identity, ClientIdentity::Pkcs12 { path, password }
                if path == "/etc/ssl/client/client.p12" && password.is_none())
        );

        // password must not appear in the serialized YAML when None
        let yaml_out = serde_yaml::to_string(&route).expect("serialize");
        assert!(!yaml_out.contains("password"), "password should be omitted");
    }

    #[test]
    fn tls_none_when_omitted() {
        let yaml = r#"
name: plain
path:
  type: exact
  value: /plain
upstream_url: "http://svc:8080"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        assert!(route.tls.is_none());
    }

    #[test]
    fn roundtrip_yaml() {
        let route = sample_route();
        let yaml = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn header_variable_placeholders_roundtrip() {
        let yaml = r#"
name: token-route
path:
  type: exact
  value: /secure
upstream_url: "http://svc:9000"
request_headers:
  add:
    Authorization: "{{access_token}}"
    X-Id-Token:    "{{id_token}}"
    X-Api-Key:     "{{env:API_KEY}}"
    X-Static:      "hello"
  strip:
    - Cookie
response_headers:
  strip:
    - X-Internal-Server
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");

        assert_eq!(
            route.request_headers.add["Authorization"],
            HeaderValue::Variable(HeaderVariable::AccessToken),
        );
        assert_eq!(
            route.request_headers.add["X-Id-Token"],
            HeaderValue::Variable(HeaderVariable::IdToken),
        );
        assert_eq!(
            route.request_headers.add["X-Api-Key"],
            HeaderValue::Variable(HeaderVariable::Env("API_KEY".to_string())),
        );
        assert_eq!(
            route.request_headers.add["X-Static"],
            HeaderValue::Literal("hello".to_string()),
        );
        assert_eq!(route.request_headers.strip, vec!["Cookie"]);
        assert_eq!(route.response_headers.strip, vec!["X-Internal-Server"]);
    }

    #[test]
    fn header_value_resolve_with_env_map() {
        let env: HashMap<String, String> = [
            ("API_KEY".to_string(), "secret-key".to_string()),
            ("AWS_REGION".to_string(), "eu-west-1".to_string()),
        ]
        .into_iter()
        .collect();

        let ctx = ResolveContext::with_env("my-access", "my-id", &env);

        assert_eq!(
            HeaderValue::Variable(HeaderVariable::AccessToken).resolve(&ctx),
            "my-access"
        );
        assert_eq!(
            HeaderValue::Variable(HeaderVariable::IdToken).resolve(&ctx),
            "my-id"
        );
        assert_eq!(
            HeaderValue::Variable(HeaderVariable::Env("API_KEY".to_string())).resolve(&ctx),
            "secret-key"
        );
        assert_eq!(
            HeaderValue::Variable(HeaderVariable::Env("AWS_REGION".to_string())).resolve(&ctx),
            "eu-west-1"
        );
        assert_eq!(
            HeaderValue::Literal("fixed".to_string()).resolve(&ctx),
            "fixed"
        );
    }

    #[test]
    fn header_value_resolve_env_fallback_to_std_env() {
        // Set a real env var and verify the fallback path (no map provided).
        // SAFETY: single-threaded test, no other thread reads this variable.
        unsafe { std::env::set_var("OXIGATE_TEST_VAR", "from-std-env") };
        let ctx = ResolveContext::new("tok", "id");
        let result = HeaderValue::Variable(HeaderVariable::Env("OXIGATE_TEST_VAR".to_string()))
            .resolve(&ctx);
        assert_eq!(result, "from-std-env");
        // SAFETY: same reasoning as above.
        unsafe { std::env::remove_var("OXIGATE_TEST_VAR") };
    }

    #[test]
    fn header_value_resolve_missing_env_returns_empty() {
        let env: HashMap<String, String> = HashMap::new();
        let ctx = ResolveContext::with_env("tok", "id", &env);
        let result =
            HeaderValue::Variable(HeaderVariable::Env("DOES_NOT_EXIST".to_string())).resolve(&ctx);
        assert_eq!(result, "");
    }

    #[test]
    fn default_enabled_is_true() {
        let yaml = r#"
name: minimal
path:
  type: exact
  value: /health
upstream_url: "http://svc:9000"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        assert!(route.enabled);
        assert_eq!(route.rewrite, RewriteRule::PassThrough);
        assert!(route.methods.is_empty());
    }
}
