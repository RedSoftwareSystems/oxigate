use serde::{Deserialize, Serialize};

use axum_oidc_client::{
    auth::CodeChallengeMethod, auth_builder::OAuthConfigurationBuilder,
    authentication::OAuthConfiguration, errors::Error,
};

// ---------------------------------------------------------------------------
// CodeChallengeMethodConfig
// ---------------------------------------------------------------------------

/// PKCE code challenge method, serialisable counterpart of
/// [`axum_oidc_client::auth::CodeChallengeMethod`].
///
/// # YAML
///
/// ```yaml
/// code_challenge_method: s256   # or: plain
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CodeChallengeMethodConfig {
    /// SHA-256 hashing (recommended, default).
    #[default]
    S256,
    /// Plain text — only for legacy providers that do not support S256.
    Plain,
}

impl From<CodeChallengeMethodConfig> for CodeChallengeMethod {
    fn from(c: CodeChallengeMethodConfig) -> Self {
        match c {
            CodeChallengeMethodConfig::S256 => CodeChallengeMethod::S256,
            CodeChallengeMethodConfig::Plain => CodeChallengeMethod::Plain,
        }
    }
}

// ---------------------------------------------------------------------------
// OidcEndpointsConfig
// ---------------------------------------------------------------------------

/// Manual OIDC / OAuth2 endpoint URLs.
///
/// Required when `issuer_url` is **not** set.  When `issuer_url` is set,
/// any field provided here takes precedence over the auto-discovered value.
///
/// # YAML
///
/// ```yaml
/// endpoints:
///   authorization: https://provider.example.com/oauth2/authorize
///   token:         https://provider.example.com/oauth2/token
///   end_session:   https://provider.example.com/oauth2/logout   # optional
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OidcEndpointsConfig {
    /// OAuth2 authorization endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,

    /// OAuth2 token endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Optional OIDC end-session (logout) endpoint URL.
    ///
    /// Only set this when the provider supports RP-Initiated Logout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session: Option<String>,
}

// ---------------------------------------------------------------------------
// SessionConfig
// ---------------------------------------------------------------------------

/// Session and token lifetime settings.
///
/// # YAML
///
/// ```yaml
/// session:
///   max_age_minutes: 30   # required
///   token_max_age_seconds: 300   # optional
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum session duration in **minutes**.  Sessions older than this
    /// require re-authentication.
    pub max_age_minutes: i64,

    /// Optional cap on token lifetime in **seconds**.  Tokens older than this
    /// are treated as expired and refreshed even if the provider's own
    /// expiry is longer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_max_age_seconds: Option<i64>,
}

// ---------------------------------------------------------------------------
// AuthRoutesConfig
// ---------------------------------------------------------------------------

/// Configuration for the authentication route paths added by
/// [`axum_oidc_client::auth::AuthenticationLayer`].
///
/// # YAML
///
/// ```yaml
/// routes:
///   base_path: /auth                     # default
///   post_logout_redirect_uri: /          # required
///   token_request_redirect_uri: true     # default
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRoutesConfig {
    /// Base path under which the auth routes are mounted.
    ///
    /// The following routes are registered automatically:
    /// - `GET <base_path>`           — start OAuth2 flow
    /// - `GET <base_path>/callback`  — OAuth2 callback
    /// - `GET <base_path>/logout`    — logout
    ///
    /// Defaults to `/auth`.  When changed, `client.redirect_uri` must be
    /// updated to match (e.g. `https://app.example.com<base_path>/callback`).
    #[serde(default = "AuthRoutesConfig::default_base_path")]
    pub base_path: String,

    /// URI to redirect users to after logout.
    ///
    /// Typically `/` or the application's home page.
    pub post_logout_redirect_uri: String,

    /// Whether to include `redirect_uri` in the token exchange request
    /// (RFC 6749 §4.1.3).
    ///
    /// Set to `false` when the upstream provider rejects redundant
    /// `redirect_uri` parameters during token exchange (e.g. Okta with a
    /// single registered redirect URI).  Defaults to `true`.
    #[serde(default = "AuthRoutesConfig::default_token_request_redirect_uri")]
    pub token_request_redirect_uri: bool,
}

impl AuthRoutesConfig {
    fn default_base_path() -> String {
        "/auth".to_string()
    }

    fn default_token_request_redirect_uri() -> bool {
        true
    }
}

impl Default for AuthRoutesConfig {
    fn default() -> Self {
        Self {
            base_path: Self::default_base_path(),
            post_logout_redirect_uri: "/".to_string(),
            token_request_redirect_uri: Self::default_token_request_redirect_uri(),
        }
    }
}

// ---------------------------------------------------------------------------
// OidcClientConfig
// ---------------------------------------------------------------------------

/// OAuth2 / OIDC client credentials and redirect URI.
///
/// # YAML
///
/// ```yaml
/// client:
///   id:           my-client-id
///   secret:       my-client-secret
///   redirect_uri: https://app.example.com/auth/callback
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcClientConfig {
    /// OAuth2 client identifier issued by the provider.
    pub id: String,

    /// OAuth2 client secret issued by the provider.
    ///
    /// ⚠️ Never commit this value to source control.  Prefer injecting it at
    /// runtime via an environment variable or a secrets manager and referencing
    /// it with `{{env:CLIENT_SECRET}}` in the configuration file.
    pub secret: String,

    /// Redirect URI registered with the OAuth2 provider.
    ///
    /// Must exactly match one of the redirect URIs configured in the
    /// provider's application settings.
    pub redirect_uri: String,
}

// ---------------------------------------------------------------------------
// TlsClientConfig
// ---------------------------------------------------------------------------

/// TLS options for the HTTP client used by the OIDC layer when communicating
/// with the provider (discovery, token exchange, etc.).
///
/// # YAML
///
/// ```yaml
/// provider_tls:
///   custom_ca_cert: /etc/ssl/certs/my-ca.pem
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProviderTlsConfig {
    /// Path to a PEM-encoded CA certificate (or bundle) used to verify the
    /// provider's TLS certificate.
    ///
    /// Leave unset to use the system trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_ca_cert: Option<String>,
}

// ---------------------------------------------------------------------------
// AuthConfig  (top-level)
// ---------------------------------------------------------------------------

/// Full configuration for the `axum-oidc-client` authentication layer.
///
/// Serialises to / deserialises from YAML (or any other serde format).
/// Call [`AuthConfig::build`] to obtain an [`OAuthConfiguration`] that can be
/// passed directly to
/// [`AuthenticationLayer::new`](axum_oidc_client::auth::AuthenticationLayer::new).
///
/// # Endpoint discovery modes
///
/// | `issuer_url` | `endpoints`               | Behaviour                                      |
/// |:------------:|:-------------------------:|------------------------------------------------|
/// | set          | not set                   | Full OIDC auto-discovery                       |
/// | set          | partially set             | Auto-discovery; explicit fields take precedence |
/// | not set      | fully set                 | Manual endpoint configuration                  |
/// | not set      | partially / not set       | `build()` returns an error                     |
///
/// # Example (YAML) — OIDC auto-discovery
///
/// ```yaml
/// issuer_url: https://accounts.google.com
///
/// client:
///   id:           my-client-id
///   secret:       "{{env:OIDC_CLIENT_SECRET}}"
///   redirect_uri: https://app.example.com/auth/callback
///
/// private_cookie_key: "{{env:COOKIE_KEY}}"
///
/// session:
///   max_age_minutes: 30
///   token_max_age_seconds: 300
///
/// scopes:
///   - openid
///   - email
///   - profile
///
/// routes:
///   base_path: /auth
///   post_logout_redirect_uri: /
/// ```
///
/// # Example (YAML) — manual endpoints
///
/// ```yaml
/// endpoints:
///   authorization: https://provider.example.com/oauth2/authorize
///   token:         https://provider.example.com/oauth2/token
///   end_session:   https://provider.example.com/oauth2/logout
///
/// client:
///   id:           my-client-id
///   secret:       my-client-secret
///   redirect_uri: https://app.example.com/auth/callback
///
/// private_cookie_key: at-least-32-bytes-long-secret-key!!
///
/// session:
///   max_age_minutes: 60
///
/// routes:
///   post_logout_redirect_uri: /
///
/// code_challenge_method: s256
///
/// provider_tls:
///   custom_ca_cert: /etc/ssl/certs/my-ca.pem
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    // ── Endpoint resolution ──────────────────────────────────────────────────
    /// OIDC issuer URL used for auto-discovery.
    ///
    /// When set the layer fetches `<issuer_url>/.well-known/openid-configuration`
    /// and populates any endpoint not explicitly provided in `endpoints`.
    ///
    /// Mutually optional with `endpoints`: provide at least one of the two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,

    /// Manual OAuth2 / OIDC endpoint URLs.
    ///
    /// Any field set here overrides the auto-discovered value when `issuer_url`
    /// is also present.
    #[serde(default, skip_serializing_if = "OidcEndpointsConfig::is_empty")]
    pub endpoints: OidcEndpointsConfig,

    // ── Client credentials ───────────────────────────────────────────────────
    /// OAuth2 client credentials and redirect URI.
    pub client: OidcClientConfig,

    // ── Cookie encryption ────────────────────────────────────────────────────
    /// Secret key used to encrypt the session cookie.
    ///
    /// Must be at least 32 characters long.
    ///
    /// ⚠️ Never commit this value to source control.
    pub private_cookie_key: String,

    // ── Session / token lifetime ─────────────────────────────────────────────
    /// Session and token lifetime settings.
    pub session: SessionConfig,

    // ── Scopes ───────────────────────────────────────────────────────────────
    /// OAuth2 scopes to request.
    ///
    /// Defaults to `["openid", "email", "profile"]` when omitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,

    // ── PKCE ─────────────────────────────────────────────────────────────────
    /// PKCE code challenge method.  Defaults to `s256`.
    #[serde(default)]
    pub code_challenge_method: CodeChallengeMethodConfig,

    // ── Route settings ───────────────────────────────────────────────────────
    /// Auth route paths and redirect configuration.
    #[serde(default)]
    pub routes: AuthRoutesConfig,

    // ── Provider TLS ─────────────────────────────────────────────────────────
    /// TLS settings for the HTTP client that communicates with the OIDC
    /// provider (discovery, token exchange, etc.).
    #[serde(default, skip_serializing_if = "ProviderTlsConfig::is_empty")]
    pub provider_tls: ProviderTlsConfig,
}

// ---------------------------------------------------------------------------
// Helper: emptiness predicates used by skip_serializing_if
// ---------------------------------------------------------------------------

impl OidcEndpointsConfig {
    /// Returns `true` when all endpoint fields are `None`.
    pub fn is_empty(&self) -> bool {
        self.authorization.is_none() && self.token.is_none() && self.end_session.is_none()
    }
}

impl ProviderTlsConfig {
    /// Returns `true` when no TLS overrides are configured.
    pub fn is_empty(&self) -> bool {
        self.custom_ca_cert.is_none()
    }
}

// ---------------------------------------------------------------------------
// AuthConfig::build
// ---------------------------------------------------------------------------

impl AuthConfig {
    /// Build an [`OAuthConfiguration`] from this config.
    ///
    /// When `issuer_url` is set this method performs an **async** HTTP request
    /// to the provider's discovery document before constructing the
    /// configuration.  Call this at application startup and cache the result.
    ///
    /// # Errors
    ///
    /// Returns [`axum_oidc_client::errors::Error`] when:
    /// - A required field is missing and cannot be auto-discovered.
    /// - The discovery request fails (network error, non-200 status, invalid JSON).
    /// - The private cookie key or any other field is invalid.
    pub async fn build(&self) -> Result<OAuthConfiguration, Error> {
        use crate::config::interpolation::{interpolate, interpolate_opt};

        let mut builder = OAuthConfigurationBuilder::default();

        // ── Provider TLS ─────────────────────────────────────────────────────
        if let Some(ca) = interpolate_opt(self.provider_tls.custom_ca_cert.as_deref()) {
            builder = builder.with_custom_ca_cert(&ca);
        }

        // ── OIDC discovery ───────────────────────────────────────────────────
        if let Some(issuer) = interpolate_opt(self.issuer_url.as_deref()) {
            builder = builder.with_issuer(&issuer).await?;
        }

        // ── Manual endpoint overrides (always win over discovery) ────────────
        if let Some(auth) = interpolate_opt(self.endpoints.authorization.as_deref()) {
            builder = builder.with_authorization_endpoint(&auth);
        }
        if let Some(token) = interpolate_opt(self.endpoints.token.as_deref()) {
            builder = builder.with_token_endpoint(&token);
        }
        if let Some(end_session) = interpolate_opt(self.endpoints.end_session.as_deref()) {
            builder = builder.with_end_session_endpoint(&end_session);
        }

        // ── Client credentials ───────────────────────────────────────────────
        builder = builder
            .with_client_id(&interpolate(&self.client.id))
            .with_client_secret(&interpolate(&self.client.secret))
            .with_redirect_uri(&interpolate(&self.client.redirect_uri));

        // ── Cookie key ───────────────────────────────────────────────────────
        builder = builder.with_private_cookie_key(&interpolate(&self.private_cookie_key));

        // ── Session / token lifetime ─────────────────────────────────────────
        builder = builder.with_session_max_age(self.session.max_age_minutes);
        if let Some(token_max_age) = self.session.token_max_age_seconds {
            builder = builder.with_token_max_age(token_max_age);
        }

        // ── Scopes ───────────────────────────────────────────────────────────
        if !self.scopes.is_empty() {
            let interpolated: Vec<String> = self.scopes.iter().map(|s| interpolate(s)).collect();
            let scope_refs: Vec<&str> = interpolated.iter().map(String::as_str).collect();
            builder = builder.with_scopes(scope_refs);
        }

        // ── PKCE ─────────────────────────────────────────────────────────────
        builder = builder.with_code_challenge_method(self.code_challenge_method.clone().into());

        // ── Route configuration ──────────────────────────────────────────────
        builder = builder
            .with_base_path(interpolate(&self.routes.base_path))
            .with_post_logout_redirect_uri(&interpolate(&self.routes.post_logout_redirect_uri))
            .with_token_request_redirect_uri(self.routes.token_request_redirect_uri);

        builder.build()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> &'static str {
        r#"
endpoints:
  authorization: https://provider.example.com/oauth2/authorize
  token:         https://provider.example.com/oauth2/token

client:
  id:           test-client
  secret:       test-secret
  redirect_uri: https://app.example.com/auth/callback

private_cookie_key: "at-least-32-bytes-long-secret-key!!"

session:
  max_age_minutes: 30

routes:
  post_logout_redirect_uri: /
"#
    }

    fn full_yaml() -> &'static str {
        r#"
issuer_url: https://accounts.google.com

endpoints:
  authorization: https://provider.example.com/oauth2/authorize
  token:         https://provider.example.com/oauth2/token
  end_session:   https://provider.example.com/oauth2/logout

client:
  id:           my-client-id
  secret:       my-client-secret
  redirect_uri: https://app.example.com/auth/callback

private_cookie_key: "at-least-32-bytes-long-secret-key!!"

session:
  max_age_minutes: 60
  token_max_age_seconds: 300

scopes:
  - openid
  - email
  - profile

code_challenge_method: s256

routes:
  base_path: /api/auth
  post_logout_redirect_uri: /home
  token_request_redirect_uri: false

provider_tls:
  custom_ca_cert: /etc/ssl/certs/my-ca.pem
"#
    }

    #[test]
    fn minimal_config_deserializes() {
        let cfg: AuthConfig = serde_yaml::from_str(minimal_yaml()).expect("deserialize");
        assert_eq!(cfg.client.id, "test-client");
        assert_eq!(cfg.session.max_age_minutes, 30);
        assert!(cfg.session.token_max_age_seconds.is_none());
        assert!(cfg.scopes.is_empty());
        assert_eq!(cfg.code_challenge_method, CodeChallengeMethodConfig::S256);
        assert_eq!(cfg.routes.base_path, "/auth");
        assert!(cfg.routes.token_request_redirect_uri);
        assert!(cfg.issuer_url.is_none());
        assert!(cfg.provider_tls.custom_ca_cert.is_none());
    }

    #[test]
    fn full_config_deserializes() {
        let cfg: AuthConfig = serde_yaml::from_str(full_yaml()).expect("deserialize");

        assert_eq!(
            cfg.issuer_url.as_deref(),
            Some("https://accounts.google.com")
        );
        assert_eq!(
            cfg.endpoints.authorization.as_deref(),
            Some("https://provider.example.com/oauth2/authorize")
        );
        assert_eq!(
            cfg.endpoints.token.as_deref(),
            Some("https://provider.example.com/oauth2/token")
        );
        assert_eq!(
            cfg.endpoints.end_session.as_deref(),
            Some("https://provider.example.com/oauth2/logout")
        );
        assert_eq!(cfg.client.id, "my-client-id");
        assert_eq!(cfg.client.secret, "my-client-secret");
        assert_eq!(
            cfg.client.redirect_uri,
            "https://app.example.com/auth/callback"
        );
        assert_eq!(cfg.session.max_age_minutes, 60);
        assert_eq!(cfg.session.token_max_age_seconds, Some(300));
        assert_eq!(cfg.scopes, vec!["openid", "email", "profile"]);
        assert_eq!(cfg.code_challenge_method, CodeChallengeMethodConfig::S256);
        assert_eq!(cfg.routes.base_path, "/api/auth");
        assert_eq!(cfg.routes.post_logout_redirect_uri, "/home");
        assert!(!cfg.routes.token_request_redirect_uri);
        assert_eq!(
            cfg.provider_tls.custom_ca_cert.as_deref(),
            Some("/etc/ssl/certs/my-ca.pem")
        );
    }

    #[test]
    fn roundtrip_yaml() {
        let cfg: AuthConfig = serde_yaml::from_str(full_yaml()).expect("deserialize");
        let serialized = serde_yaml::to_string(&cfg).expect("serialize");
        let decoded: AuthConfig = serde_yaml::from_str(&serialized).expect("re-deserialize");
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn code_challenge_method_plain_deserializes() {
        let yaml = r#"
endpoints:
  authorization: https://p.example.com/auth
  token:         https://p.example.com/token
client:
  id: c
  secret: s
  redirect_uri: https://app.example.com/auth/callback
private_cookie_key: "at-least-32-bytes-long-secret-key!!"
session:
  max_age_minutes: 10
routes:
  post_logout_redirect_uri: /
code_challenge_method: plain
"#;
        let cfg: AuthConfig = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(cfg.code_challenge_method, CodeChallengeMethodConfig::Plain);
    }

    #[test]
    fn default_routes_config() {
        let routes = AuthRoutesConfig::default();
        assert_eq!(routes.base_path, "/auth");
        assert_eq!(routes.post_logout_redirect_uri, "/");
        assert!(routes.token_request_redirect_uri);
    }

    #[test]
    fn endpoints_is_empty() {
        assert!(OidcEndpointsConfig::default().is_empty());
        let non_empty = OidcEndpointsConfig {
            authorization: Some("https://x".to_string()),
            ..Default::default()
        };
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn provider_tls_is_empty() {
        assert!(ProviderTlsConfig::default().is_empty());
        let non_empty = ProviderTlsConfig {
            custom_ca_cert: Some("/ca.pem".to_string()),
        };
        assert!(!non_empty.is_empty());
    }

    #[tokio::test]
    async fn build_without_issuer_and_with_manual_endpoints() {
        let cfg: AuthConfig = serde_yaml::from_str(minimal_yaml()).expect("deserialize");
        let result = cfg.build().await;
        assert!(result.is_ok(), "build failed: {:?}", result.err());
        let oauth = result.unwrap();
        assert_eq!(oauth.client_id, "test-client");
        assert_eq!(oauth.session_max_age, 30);
        assert_eq!(oauth.base_path, "/auth");
        assert_eq!(oauth.post_logout_redirect_uri, "/");
        assert!(oauth.token_request_redirect_uri);
    }

    #[tokio::test]
    async fn build_applies_all_fields() {
        // Use a config without issuer_url so no network call is made.
        let yaml = r#"
endpoints:
  authorization: https://p.example.com/auth
  token:         https://p.example.com/token
  end_session:   https://p.example.com/logout
client:
  id:           full-client
  secret:       full-secret
  redirect_uri: https://app.example.com/api/auth/callback
private_cookie_key: "at-least-32-bytes-long-secret-key!!"
session:
  max_age_minutes: 45
  token_max_age_seconds: 120
scopes:
  - openid
  - email
code_challenge_method: plain
routes:
  base_path: /api/auth
  post_logout_redirect_uri: /home
  token_request_redirect_uri: false
"#;
        let cfg: AuthConfig = serde_yaml::from_str(yaml).expect("deserialize");
        let oauth = cfg.build().await.expect("build");

        assert_eq!(oauth.client_id, "full-client");
        assert_eq!(oauth.client_secret, "full-secret");
        assert_eq!(
            oauth.redirect_uri,
            "https://app.example.com/api/auth/callback"
        );
        assert_eq!(oauth.session_max_age, 45);
        assert_eq!(oauth.token_max_age, Some(120));
        assert_eq!(oauth.scopes, "openid email");
        assert_eq!(oauth.base_path, "/api/auth");
        assert_eq!(oauth.post_logout_redirect_uri, "/home");
        assert!(!oauth.token_request_redirect_uri);
        assert_eq!(
            oauth.end_session_endpoint.as_deref(),
            Some("https://p.example.com/logout")
        );
        assert_eq!(oauth.authorization_endpoint, "https://p.example.com/auth");
        assert_eq!(oauth.token_endpoint, "https://p.example.com/token");
    }
}
