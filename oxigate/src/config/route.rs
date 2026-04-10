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

/// The transport scheme a route is restricted to.
///
/// Scheme-specific routes (`Http` or `Https`) take priority over generic
/// (`Any`) routes when the incoming request's scheme matches. `Any` routes
/// act as a fallback when no scheme-specific route matches.
///
/// # YAML
///
/// ```yaml
/// scheme: http    # only match plain HTTP requests
/// scheme: https   # only match HTTPS requests
/// scheme: any     # match both (default)
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
    #[default]
    Any,
}

impl Scheme {
    /// Returns `true` when the variant is `Any` (used by `skip_serializing_if`).
    pub fn is_any(&self) -> bool {
        matches!(self, Scheme::Any)
    }
}

/// The kind and target URL of a redirect response.
///
/// Supports `{{env:VAR}}` interpolation in the target URL — resolved at
/// startup by [`ReverseProxyRoute::interpolated`].
///
/// # YAML examples
///
/// ```yaml
/// # Temporary redirect (302 Found)
/// redirect:
///   type: temporary
///   url: https://new.example.com/path
///
/// # Permanent redirect (301 Moved Permanently)
/// redirect:
///   type: permanent
///   url: https://new.example.com/path
///
/// # With env-var interpolation
/// redirect:
///   type: permanent
///   url: "{{env:CANONICAL_URL}}/path"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RedirectAction {
    /// HTTP 302 Found — the resource has temporarily moved.
    Temporary {
        /// The URL to redirect to. Supports `{{env:VAR}}` interpolation.
        url: String,
    },
    /// HTTP 301 Moved Permanently — the resource has permanently moved.
    Permanent {
        /// The URL to redirect to. Supports `{{env:VAR}}` interpolation.
        url: String,
    },
}

impl RedirectAction {
    /// Returns the HTTP status code for this redirect type.
    pub fn status_code(&self) -> u16 {
        match self {
            RedirectAction::Temporary { .. } => 302,
            RedirectAction::Permanent { .. } => 301,
        }
    }

    /// Returns the target URL.
    pub fn url(&self) -> &str {
        match self {
            RedirectAction::Temporary { url } | RedirectAction::Permanent { url } => url,
        }
    }
}

/// A single header matching rule used to restrict route selection.
///
/// The `pattern` is a full regular-expression matched against the header
/// value (case-sensitive by default). The match must cover the **entire**
/// value (anchored). If the header is absent the rule does **not** match.
///
/// # YAML examples
///
/// ```yaml
/// match_headers:
///   - name: Content-Type
///     pattern: "application/json(;.*)?"
///   - name: Accept
///     pattern: "text/html.*"
///   - name: X-Custom-Flag
///     pattern: "enabled"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderMatcher {
    /// Name of the request header to inspect (case-insensitive lookup).
    pub name: String,
    /// Regular expression that must fully match the header value.
    pub pattern: String,
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
    /// Required for proxy routes; omitted for redirect-only routes.
    pub upstream_url: Option<String>,

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

    /// Optional list of header matching rules.
    ///
    /// All rules must match for the route to be selected (AND semantics).
    /// If the list is empty the route matches any headers.
    ///
    /// Each rule specifies a header name and a regex pattern. The pattern must
    /// fully match the header value. If the named header is absent the rule
    /// does not match.
    ///
    /// # YAML example
    ///
    /// ```yaml
    /// match_headers:
    ///   - name: Content-Type
    ///     pattern: "application/json(;.*)?"
    ///   - name: X-Api-Version
    ///     pattern: "v[2-9]"
    /// ```
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_headers: Vec<HeaderMatcher>,

    /// Restrict this route to a specific transport scheme.
    ///
    /// Scheme-specific routes (`http` or `https`) are evaluated before `any`
    /// routes, giving them priority. Defaults to `any` when omitted.
    #[serde(default, skip_serializing_if = "Scheme::is_any")]
    pub scheme: Scheme,

    /// Optional hostname (and optional port) this route is restricted to.
    ///
    /// Matched against the `Host` header of the incoming request.
    /// Supports `{{env:VAR}}` interpolation resolved at startup.
    ///
    /// **Matching rules:**
    /// - When `None` (omitted), the route matches any `Host` header — no restriction.
    /// - When set **without a port** (e.g. `api.example.com`), only the hostname is
    ///   compared; any port in the `Host` header is ignored.
    /// - When set **with a port** (e.g. `api.example.com:8443`), both the hostname
    ///   and the port must match the `Host` header exactly.
    ///
    /// Hostname comparison is case-insensitive in all cases.
    ///
    /// # YAML examples
    ///
    /// ```yaml
    /// hostname: api.example.com            # matches any port on this host
    /// hostname: api.example.com:8443       # matches only port 8443
    /// hostname: "{{env:GATEWAY_HOSTNAME}}" # from environment variable
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Optional redirect action.
    ///
    /// When set, the gateway immediately returns an HTTP redirect response
    /// (`301` or `302`) to the client without contacting any upstream.
    /// The `upstream_url` field is not required for redirect routes.
    ///
    /// # YAML examples
    ///
    /// ```yaml
    /// # Redirect HTTP traffic to HTTPS (combine with scheme: http)
    /// redirect:
    ///   type: permanent
    ///   url: "https://{{env:DOMAIN}}{{path}}"
    ///
    /// # Temporary redirect to a maintenance page
    /// redirect:
    ///   type: temporary
    ///   url: https://example.com/maintenance
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectAction>,

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
// Interpolation
// ---------------------------------------------------------------------------

impl ReverseProxyRoute {
    /// Return a clone of this route with all string fields resolved through
    /// `{{env:VAR}}` interpolation.  Call this at startup before inserting
    /// routes into [`crate::handler::proxy_handler::ProxyState`].
    pub fn interpolated(&self) -> Self {
        use crate::config::interpolation::interpolate;

        fn interp_header_value(hv: &HeaderValue) -> HeaderValue {
            match hv {
                HeaderValue::Literal(s) => HeaderValue::Literal(interpolate(s)),
                HeaderValue::Variable(_) => hv.clone(),
            }
        }

        fn interp_headers_config(hc: &HeadersConfig) -> HeadersConfig {
            HeadersConfig {
                add: hc
                    .add
                    .iter()
                    .map(|(k, v)| (interpolate(k), interp_header_value(v)))
                    .collect(),
                strip: hc.strip.iter().map(|s| interpolate(s)).collect(),
            }
        }

        Self {
            name: self.name.clone(),
            path: match &self.path {
                PathMatcher::Exact(s) => PathMatcher::Exact(interpolate(s)),
                PathMatcher::Prefix(s) => PathMatcher::Prefix(interpolate(s)),
                PathMatcher::Regex(s) => PathMatcher::Regex(interpolate(s)),
            },
            upstream_url: self.upstream_url.as_deref().map(interpolate),
            methods: self.methods.clone(),
            rewrite: match &self.rewrite {
                RewriteRule::Replace(s) => RewriteRule::Replace(interpolate(s)),
                other => other.clone(),
            },
            request_headers: interp_headers_config(&self.request_headers),
            response_headers: interp_headers_config(&self.response_headers),
            client_name: self.client_name.as_deref().map(interpolate),
            scheme: self.scheme.clone(),
            hostname: self.hostname.as_deref().map(interpolate),
            redirect: self.redirect.as_ref().map(|r| match r {
                RedirectAction::Temporary { url } => RedirectAction::Temporary {
                    url: interpolate(url),
                },
                RedirectAction::Permanent { url } => RedirectAction::Permanent {
                    url: interpolate(url),
                },
            }),
            match_headers: self
                .match_headers
                .iter()
                .map(|m| HeaderMatcher {
                    name: interpolate(&m.name),
                    pattern: interpolate(&m.pattern),
                })
                .collect(),
            enabled: self.enabled,
        }
    }
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
            upstream_url: Some("http://backend:8080".to_string()),
            methods: vec![HttpMethod::Get, HttpMethod::Post],
            rewrite: RewriteRule::StripPrefix,
            client_name: None,
            match_headers: vec![],
            scheme: Scheme::Any,
            hostname: None,
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
            redirect: None,
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
    fn hostname_field_roundtrip_yaml() {
        let yaml = r#"
name: vhost-route
path:
  type: exact
  value: /
upstream_url: "http://svc:8080"
hostname: api.example.com
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(route.hostname.as_deref(), Some("api.example.com"));

        let back = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn hostname_absent_defaults_to_none() {
        let yaml = r#"
name: no-host
path:
  type: exact
  value: /health
upstream_url: "http://svc:8080"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        assert!(route.hostname.is_none());
    }

    #[test]
    fn redirect_action_roundtrip_yaml() {
        let yaml = r#"
name: http-to-https
scheme: http
path:
  type: prefix
  value: /
upstream_url: "http://unused:9999"
redirect:
  type: permanent
  url: "https://example.com"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        let action = route.redirect.as_ref().expect("redirect present");
        assert_eq!(action.status_code(), 301);
        assert_eq!(action.url(), "https://example.com");

        let back = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn redirect_temporary_roundtrip_yaml() {
        let yaml = r#"
name: temp-redirect
path:
  type: exact
  value: /old
redirect:
  type: temporary
  url: "https://example.com/new"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        let action = route.redirect.expect("redirect present");
        assert_eq!(action.status_code(), 302);
        assert_eq!(action.url(), "https://example.com/new");
        assert!(route.upstream_url.is_none());
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

    #[test]
    fn match_headers_roundtrip_yaml() {
        let yaml = r#"
name: json-api
path:
  type: prefix
  value: /api/
upstream_url: "http://backend:8080"
match_headers:
  - name: Content-Type
    pattern: "application/json(;.*)?"
  - name: X-Api-Version
    pattern: "v[2-9]"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(route.match_headers.len(), 2);
        assert_eq!(route.match_headers[0].name, "Content-Type");
        assert_eq!(route.match_headers[0].pattern, "application/json(;.*)?");
        assert_eq!(route.match_headers[1].name, "X-Api-Version");

        let back = serde_yaml::to_string(&route).expect("serialize");
        let decoded: ReverseProxyRoute = serde_yaml::from_str(&back).expect("re-deserialize");
        assert_eq!(route, decoded);
    }

    #[test]
    fn match_headers_absent_defaults_to_empty() {
        let yaml = r#"
name: no-header-match
path:
  type: exact
  value: /health
upstream_url: "http://svc:8080"
"#;
        let route: ReverseProxyRoute = serde_yaml::from_str(yaml).expect("deserialize");
        assert!(route.match_headers.is_empty());
    }
}
