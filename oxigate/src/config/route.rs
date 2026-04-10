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
/// client_name: backend-mtls
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

    /// Name of a pre-configured HTTP client from the [`crate::config::client::HttpClientRegistry`].
    ///
    /// When set, the named client (including its `timeout_ms` and TLS settings)
    /// is used to forward requests for this route. When `None`, a plain default
    /// client with no explicit timeout is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

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
            client_name: None,
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
            enabled: true,
        }
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
