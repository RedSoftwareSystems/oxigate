use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_oidc_client::auth_session::AuthSession;
use reqwest::{Client, ClientBuilder, Identity};

use crate::config::route::{
    ClientIdentity, HeaderValue as RouteHeaderValue, HttpMethod, PathMatcher, ResolveContext,
    ReverseProxyRoute, RewriteRule, TlsConfig,
};

// ---------------------------------------------------------------------------
// Per-route entry
// ---------------------------------------------------------------------------

/// A route paired with its own dedicated HTTP client.
///
/// Each route gets an isolated [`Client`] so that connection pools, TLS
/// settings, and timeouts can be tuned independently per upstream without
/// affecting other routes.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// The routing rule and header configuration.
    pub route: ReverseProxyRoute,
    /// Dedicated HTTP client for this route's upstream.
    pub client: Client,
}

impl RouteEntry {
    /// Build a client from an optional [`TlsConfig`].
    ///
    /// - Loads a PEM CA certificate from disk when `tls.ca_cert` is set.
    /// - Loads a PEM client certificate + key for mTLS when `tls.client_identity` is set.
    /// - Disables certificate validation when `tls.accept_invalid_certs` is `true`.
    /// - Falls back to a plain default client when `tls` is `None`.
    fn build_client(name: &str, tls: Option<&TlsConfig>) -> Result<Client, ProxyError> {
        let mut builder = ClientBuilder::new();

        if let Some(tls) = tls {
            if tls.accept_invalid_certs {
                builder = builder.danger_accept_invalid_certs(true);
            }

            if let Some(cert_path) = &tls.ca_cert {
                let pem = std::fs::read(cert_path)
                    .map_err(|e| ProxyError::TlsCertReadError(name.to_string(), e))?;

                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|e| ProxyError::ClientBuildError(name.to_string(), e))?;

                builder = builder.add_root_certificate(cert);
            }

            if let Some(identity) = &tls.client_identity {
                builder = builder.identity(Self::load_identity(name, identity)?);
            }
        }

        builder
            .build()
            .map_err(|e| ProxyError::ClientBuildError(name.to_string(), e))
    }

    /// Load a client identity as a [`reqwest::Identity`], dispatching on the
    /// [`ClientIdentity`] variant:
    ///
    /// - `Pem`    — concatenates cert + key PEM files and parses via
    ///   [`Identity::from_pem`].
    /// - `Pkcs12` — reads the archive and parses via [`Identity::from_pkcs12_der`].
    ///   The optional password field supports `{{env:VAR}}` interpolation
    ///   (resolved against the process environment at client-build time,
    ///   before any request context is available).
    fn load_identity(name: &str, identity: &ClientIdentity) -> Result<Identity, ProxyError> {
        match identity {
            ClientIdentity::Pem { cert, key } => {
                let cert_pem = std::fs::read(cert)
                    .map_err(|e| ProxyError::TlsCertReadError(name.to_string(), e))?;
                let key_pem = std::fs::read(key)
                    .map_err(|e| ProxyError::TlsCertReadError(name.to_string(), e))?;

                // reqwest::Identity::from_pem expects cert + key in one PEM blob.
                let mut combined = cert_pem;
                combined.extend_from_slice(&key_pem);

                Identity::from_pem(&combined)
                    .map_err(|e| ProxyError::ClientBuildError(name.to_string(), e))
            }

            ClientIdentity::Pkcs12 { path, password } => {
                let der = std::fs::read(path)
                    .map_err(|e| ProxyError::TlsCertReadError(name.to_string(), e))?;

                // Resolve the password: support {{env:VAR}} placeholders by
                // deserialising the raw string as a HeaderValue and resolving it
                // against an empty session context (only env vars are meaningful
                // at build time, before any request is in flight).
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
                    .map_err(|e| ProxyError::ClientBuildError(name.to_string(), e))
            }
        }
    }

    /// Build a [`RouteEntry`], applying any TLS configuration declared on the route.
    pub fn new(route: ReverseProxyRoute) -> Result<Self, ProxyError> {
        let client = Self::build_client(&route.name, route.tls.as_ref())?;
        Ok(Self { client, route })
    }

    /// Build a [`RouteEntry`] with a custom [`ClientBuilder`].
    ///
    /// Useful for routes that need custom TLS roots, proxies, or other
    /// per-upstream configuration.
    pub fn with_builder(
        route: ReverseProxyRoute,
        builder: ClientBuilder,
    ) -> Result<Self, ProxyError> {
        let client = builder
            .build()
            .map_err(|e| ProxyError::ClientBuildError(route.name.clone(), e))?;
        Ok(Self { route, client })
    }
}

// ---------------------------------------------------------------------------
// Proxy state
// ---------------------------------------------------------------------------

/// Shared application state for the reverse proxy handler.
///
/// Wrap in [`axum::extract::State`] and register with your `Router`:
///
/// ```ignore
/// let state = Arc::new(ProxyState::new(routes)?);
/// let app = Router::new()
///     .route("/{*path}", any(proxy_handler))
///     .with_state(state);
/// ```
#[derive(Clone, Debug)]
pub struct ProxyState {
    /// Per-route entries, each with its own HTTP client. The first matching
    /// enabled entry wins.
    pub entries: Vec<RouteEntry>,
    /// Optional pre-collected environment snapshot used for `{{env:…}}`
    /// interpolation. When `None` the handler falls back to `std::env::var`.
    pub env: Option<Arc<HashMap<String, String>>>,
}

impl ProxyState {
    /// Validate that all route names are unique.
    fn check_unique_names(routes: &[ReverseProxyRoute]) -> Result<(), ProxyError> {
        let mut seen = HashMap::new();
        for route in routes {
            if seen.insert(route.name.as_str(), ()).is_some() {
                return Err(ProxyError::DuplicateRouteName(route.name.clone()));
            }
        }
        Ok(())
    }

    /// Create a new [`ProxyState`] from a list of routes.
    ///
    /// Each route gets its own [`Client`] built from the route's [`TlsConfig`]
    /// (if any). Returns `Err` if any two routes share the same name or if a
    /// TLS certificate cannot be read or parsed.
    pub fn new(routes: Vec<ReverseProxyRoute>) -> Result<Self, ProxyError> {
        Self::check_unique_names(&routes)?;
        let entries = routes
            .into_iter()
            .map(RouteEntry::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries, env: None })
    }

    /// Create a new [`ProxyState`] from pre-built [`RouteEntry`] values.
    ///
    /// Use this when you need per-route custom clients (e.g. custom CA certs).
    /// Returns `Err` if any two entries share the same route name.
    pub fn from_entries(entries: Vec<RouteEntry>) -> Result<Self, ProxyError> {
        let routes: Vec<&ReverseProxyRoute> = entries.iter().map(|e| &e.route).collect();
        let mut seen = HashMap::new();
        for route in routes {
            if seen.insert(route.name.as_str(), ()).is_some() {
                return Err(ProxyError::DuplicateRouteName(route.name.clone()));
            }
        }
        Ok(Self { entries, env: None })
    }

    /// Attach a pre-collected environment snapshot for `{{env:…}}` resolution.
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = Some(Arc::new(env));
        self
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during proxying.
#[derive(Debug)]
pub enum ProxyError {
    /// No route matched the incoming request.
    NoRouteMatched,
    /// The upstream request failed.
    UpstreamError(reqwest::Error),
    /// An invalid header name or value was produced during header injection.
    InvalidHeader(String),
    /// Two or more routes share the same name, which is not allowed.
    DuplicateRouteName(String),
    /// Failed to build the HTTP client for a route.
    ClientBuildError(String, reqwest::Error),
    /// Failed to read the TLS CA certificate file for a route.
    TlsCertReadError(String, std::io::Error),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
            ProxyError::NoRouteMatched => {
                (StatusCode::NOT_FOUND, "No matching route for this request").into_response()
            }
            ProxyError::UpstreamError(e) => {
                (StatusCode::BAD_GATEWAY, format!("Upstream error: {e}")).into_response()
            }
            ProxyError::InvalidHeader(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Header error: {msg}"),
            )
                .into_response(),
            ProxyError::DuplicateRouteName(name) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Duplicate route name: \"{name}\""),
            )
                .into_response(),
            ProxyError::ClientBuildError(name, e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build client for route \"{name}\": {e}"),
            )
                .into_response(),
            ProxyError::TlsCertReadError(name, e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read TLS certificate for route \"{name}\": {e}"),
            )
                .into_response(),
        }
    }
}

// ---------------------------------------------------------------------------
// Route matching helpers
// ---------------------------------------------------------------------------

/// Returns `true` when the route's method list is empty (any method) or
/// contains the incoming method.
fn method_matches(route: &ReverseProxyRoute, method: &axum::http::Method) -> bool {
    if route.methods.is_empty() {
        return true;
    }
    let incoming = match *method {
        axum::http::Method::GET => Some(HttpMethod::Get),
        axum::http::Method::POST => Some(HttpMethod::Post),
        axum::http::Method::PUT => Some(HttpMethod::Put),
        axum::http::Method::PATCH => Some(HttpMethod::Patch),
        axum::http::Method::DELETE => Some(HttpMethod::Delete),
        axum::http::Method::HEAD => Some(HttpMethod::Head),
        axum::http::Method::OPTIONS => Some(HttpMethod::Options),
        axum::http::Method::TRACE => Some(HttpMethod::Trace),
        axum::http::Method::CONNECT => Some(HttpMethod::Connect),
        _ => None,
    };
    incoming.is_some_and(|m| route.methods.contains(&m))
}

/// Returns `true` when the route's path matcher accepts `path`.
fn path_matches(route: &ReverseProxyRoute, path: &str) -> bool {
    match &route.path {
        PathMatcher::Exact(p) => path == p,
        PathMatcher::Prefix(p) => path.starts_with(p.as_str()),
        PathMatcher::Regex(pattern) => {
            use regex_automata::{Match, meta::Regex};
            Regex::new(pattern)
                .ok()
                .and_then(|re| re.find(path.as_bytes()))
                .map(|m: Match| m.start() == 0 && m.end() == path.len())
                .unwrap_or(false)
        }
    }
}

/// Selects the first enabled entry whose route matches `method` and `path`.
fn select_entry<'a>(
    entries: &'a [RouteEntry],
    method: &axum::http::Method,
    path: &str,
) -> Option<&'a RouteEntry> {
    entries
        .iter()
        .filter(|e| e.route.enabled)
        .find(|e| method_matches(&e.route, method) && path_matches(&e.route, path))
}

// ---------------------------------------------------------------------------
// Path rewriting
// ---------------------------------------------------------------------------

fn rewrite_path(route: &ReverseProxyRoute, original_path: &str) -> String {
    match &route.rewrite {
        RewriteRule::PassThrough => original_path.to_owned(),
        RewriteRule::StripPrefix => {
            if let PathMatcher::Prefix(prefix) = &route.path {
                let stripped = original_path
                    .strip_prefix(prefix.as_str())
                    .unwrap_or(original_path);
                // Ensure the result always starts with '/'.
                if stripped.starts_with('/') {
                    stripped.to_owned()
                } else {
                    format!("/{stripped}")
                }
            } else {
                original_path.to_owned()
            }
        }
        RewriteRule::Replace(fixed) => fixed.clone(),
    }
}

// ---------------------------------------------------------------------------
// Upstream URL construction
// ---------------------------------------------------------------------------

fn build_upstream_url(route: &ReverseProxyRoute, path: &str, query: Option<&str>) -> String {
    let base = route.upstream_url.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    match query {
        Some(q) if !q.is_empty() => format!("{base}{path}?{q}"),
        _ => format!("{base}{path}"),
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Axum handler that matches the incoming request against a [`ProxyState`]
/// route list and forwards it to the appropriate upstream service.
///
/// The handler:
/// 1. Selects the first enabled entry that matches the request method and path.
/// 2. Rewrites the upstream path according to the route's [`RewriteRule`].
/// 3. Strips and injects request headers as configured.
/// 4. Forwards the request (including body) to the upstream via the route's own client.
/// 5. Strips and injects response headers as configured.
/// 6. Streams the upstream response back to the client.
///
/// Authentication tokens (`access_token`, `id_token`) are sourced from the
/// optional [`AuthSession`] extractor when available.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    auth_session: Option<AuthSession>,
    req: Request,
) -> Result<Response, ProxyError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path();
    let query = uri.query();

    // --- 1. Route selection -------------------------------------------------
    let entry = select_entry(&state.entries, &method, path).ok_or(ProxyError::NoRouteMatched)?;
    let route = &entry.route;
    let client = &entry.client;

    // --- 2. Path rewriting --------------------------------------------------
    let upstream_path = rewrite_path(route, path);
    let upstream_url = build_upstream_url(route, &upstream_path, query);

    // --- 3. Build resolve context -------------------------------------------
    let (access_token, id_token) = auth_session
        .as_ref()
        .map(|s| (s.access_token.as_str(), s.id_token.as_str()))
        .unwrap_or(("", ""));

    let ctx = match &state.env {
        Some(env) => ResolveContext::with_env(access_token, id_token, env),
        None => ResolveContext::new(access_token, id_token),
    };

    // --- 4. Build upstream request ------------------------------------------
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);

    let mut upstream_req = client.request(reqwest_method, &upstream_url);

    // Apply timeout if configured.
    if let Some(ms) = route.timeout_ms {
        upstream_req = upstream_req.timeout(Duration::from_millis(ms));
    }

    // Copy inbound headers, skipping stripped ones.
    let (parts, body) = req.into_parts();
    let strip_req: Vec<String> = route
        .request_headers
        .strip
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    for (name, value) in &parts.headers {
        if strip_req.contains(&name.as_str().to_lowercase()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            upstream_req = upstream_req.header(name.as_str(), v);
        }
    }

    // Inject additional request headers.
    for (name, hv) in &route.request_headers.add {
        let resolved = hv.resolve(&ctx);
        upstream_req = upstream_req.header(name.as_str(), resolved);
    }

    // Forward the body.
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }

    // --- 5. Execute upstream request ----------------------------------------
    let upstream_resp = upstream_req
        .send()
        .await
        .map_err(ProxyError::UpstreamError)?;

    // --- 6. Build downstream response ---------------------------------------
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let strip_resp: Vec<String> = route
        .response_headers
        .strip
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    let mut builder = axum::response::Response::builder().status(status);

    // Copy upstream response headers, skipping stripped ones.
    for (name, value) in upstream_resp.headers() {
        if strip_resp.contains(&name.as_str().to_lowercase()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    // Inject additional response headers.
    for (name, hv) in &route.response_headers.add {
        let resolved = hv.resolve(&ctx);
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| ProxyError::InvalidHeader(format!("{name}: {e}")))?;
        let header_value = HeaderValue::from_str(&resolved)
            .map_err(|e| ProxyError::InvalidHeader(format!("{name}: {e}")))?;
        builder = builder.header(header_name, header_value);
    }

    // Stream the response body back.
    let resp_bytes = upstream_resp
        .bytes()
        .await
        .map_err(ProxyError::UpstreamError)?;

    let response = builder
        .body(axum::body::Body::from(resp_bytes))
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build response",
            )
                .into_response()
        });

    Ok(response)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::route::{PathMatcher, ReverseProxyRoute, RewriteRule};

    fn make_route(name: &str) -> ReverseProxyRoute {
        ReverseProxyRoute {
            name: name.to_string(),
            path: PathMatcher::Exact(format!("/{name}")),
            upstream_url: "http://localhost:8080".to_string(),
            methods: vec![],
            rewrite: RewriteRule::PassThrough,
            request_headers: Default::default(),
            response_headers: Default::default(),
            timeout_ms: None,
            tls: None,
            enabled: true,
        }
    }

    #[test]
    fn unique_names_accepted() {
        let routes = vec![make_route("alpha"), make_route("beta"), make_route("gamma")];
        assert!(ProxyState::new(routes).is_ok());
    }

    #[test]
    fn route_without_tls_builds_ok() {
        let route = make_route("no-tls");
        assert!(RouteEntry::new(route).is_ok());
    }

    #[test]
    fn route_with_missing_cert_errors() {
        use crate::config::route::TlsConfig;
        let mut route = make_route("bad-cert");
        route.tls = Some(TlsConfig {
            ca_cert: Some("/nonexistent/path/ca.pem".to_string()),
            client_identity: None,
            accept_invalid_certs: false,
        });
        let err = RouteEntry::new(route).unwrap_err();
        assert!(matches!(err, ProxyError::TlsCertReadError(n, _) if n == "bad-cert"));
    }

    #[test]
    fn duplicate_name_rejected() {
        let routes = vec![make_route("alpha"), make_route("beta"), make_route("alpha")];
        let err = ProxyState::new(routes).unwrap_err();
        assert!(matches!(err, ProxyError::DuplicateRouteName(n) if n == "alpha"));
    }

    #[test]
    fn duplicate_name_rejected_from_entries() {
        let entries = vec![
            RouteEntry::new(make_route("foo")).unwrap(),
            RouteEntry::new(make_route("foo")).unwrap(),
        ];
        let err = ProxyState::from_entries(entries).unwrap_err();
        assert!(matches!(err, ProxyError::DuplicateRouteName(n) if n == "foo"));
    }

    #[test]
    fn first_duplicate_is_reported() {
        // "beta" appears twice; it should be the reported duplicate, not "gamma".
        let routes = vec![
            make_route("alpha"),
            make_route("beta"),
            make_route("gamma"),
            make_route("beta"),
            make_route("gamma"),
        ];
        let err = ProxyState::new(routes).unwrap_err();
        assert!(matches!(err, ProxyError::DuplicateRouteName(n) if n == "beta"));
    }

    #[test]
    fn each_entry_has_its_own_client() {
        let routes = vec![make_route("svc-a"), make_route("svc-b")];
        let state = ProxyState::new(routes).unwrap();
        // Each entry must hold a client; verify by pointer inequality is not
        // possible for reqwest::Client, but we can at least assert one per entry.
        assert_eq!(state.entries.len(), 2);
        assert_eq!(state.entries[0].route.name, "svc-a");
        assert_eq!(state.entries[1].route.name, "svc-b");
    }

    #[test]
    fn custom_entry_accepted() {
        let route = make_route("custom");
        let entry = RouteEntry::with_builder(route, ClientBuilder::new()).unwrap();
        let state = ProxyState::from_entries(vec![entry]).unwrap();
        assert_eq!(state.entries[0].route.name, "custom");
    }
}
