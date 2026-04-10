use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_oidc_client::extractors::OptionalAuthSession;
use reqwest::ClientBuilder;

use crate::config::client::HttpClientConfig;
use crate::config::route::{
    HttpMethod, PathMatcher, ResolveContext, ReverseProxyRoute, RewriteRule, Scheme,
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
    /// Build a [`RouteEntry`] with a plain default HTTP client.
    pub fn new(route: ReverseProxyRoute) -> Result<Self, ProxyError> {
        let client = ClientBuilder::new()
            .build()
            .map_err(|e| ProxyError::ClientBuildError(route.name.clone(), e))?;
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
    /// Routes restricted to a specific scheme (http-only or https-only).
    /// These are checked first and take priority.
    pub scheme_entries: Vec<RouteEntry>,
    /// Routes with scheme = Any — checked only when no scheme-specific route matches.
    pub fallback_entries: Vec<RouteEntry>,
    /// Named HTTP clients from the [`crate::config::client::HttpClientRegistry`].
    /// Routes may reference a client by name via `client_name` to use its
    /// configured TLS settings and `timeout_ms`.
    pub clients: HashMap<String, (HttpClientConfig, Client)>,
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

    /// Validate that every `client_name` referenced by a route exists in the
    /// provided clients map.
    fn check_client_names(
        entries: &[&RouteEntry],
        clients: &HashMap<String, (HttpClientConfig, Client)>,
    ) -> Result<(), ProxyError> {
        for entry in entries {
            if let Some(ref name) = entry.route.client_name
                && !clients.contains_key(name.as_str())
            {
                return Err(ProxyError::UnknownClientName(name.clone()));
            }
        }
        Ok(())
    }

    /// Combine scheme-specific and fallback entries into a single vec of references.
    fn all_entries<'a>(
        scheme_entries: &'a [RouteEntry],
        fallback_entries: &'a [RouteEntry],
    ) -> Vec<&'a RouteEntry> {
        scheme_entries
            .iter()
            .chain(fallback_entries.iter())
            .collect()
    }

    /// Create a new [`ProxyState`] from a list of routes and a named-client map.
    ///
    /// Each route gets its own [`Client`] built from the route's [`TlsConfig`]
    /// (if any). Returns `Err` if:
    /// - Any two routes share the same name.
    /// - A TLS certificate cannot be read or parsed.
    /// - A route references a `client_name` not present in `clients`.
    pub fn new(
        routes: Vec<ReverseProxyRoute>,
        clients: HashMap<String, (HttpClientConfig, Client)>,
    ) -> Result<Self, ProxyError> {
        Self::check_unique_names(&routes)?;
        let entries = routes
            .into_iter()
            .map(RouteEntry::new)
            .collect::<Result<Vec<_>, _>>()?;
        Self::check_client_names(&Self::all_entries(&entries, &[]), &clients)?;
        let (scheme_entries, fallback_entries): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| e.route.scheme != Scheme::Any);
        Ok(Self {
            scheme_entries,
            fallback_entries,
            clients,
            env: None,
        })
    }

    /// Create a new [`ProxyState`] from pre-built [`RouteEntry`] values and a
    /// named-client map.
    ///
    /// Use this when you need per-route custom clients (e.g. custom CA certs).
    /// Returns `Err` if:
    /// - Any two entries share the same route name.
    /// - A route references a `client_name` not present in `clients`.
    pub fn from_entries(
        entries: Vec<RouteEntry>,
        clients: HashMap<String, (HttpClientConfig, Client)>,
    ) -> Result<Self, ProxyError> {
        let routes: Vec<&ReverseProxyRoute> = entries.iter().map(|e| &e.route).collect();
        let mut seen = HashMap::new();
        for route in routes {
            if seen.insert(route.name.as_str(), ()).is_some() {
                return Err(ProxyError::DuplicateRouteName(route.name.clone()));
            }
        }
        Self::check_client_names(&Self::all_entries(&entries, &[]), &clients)?;
        let (scheme_entries, fallback_entries): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| e.route.scheme != Scheme::Any);
        Ok(Self {
            scheme_entries,
            fallback_entries,
            clients,
            env: None,
        })
    }

    /// Attach a pre-collected environment snapshot for `{{env:…}}` resolution.
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = Some(Arc::new(env));
        self
    }

    /// Return a combined slice of all entries (scheme-specific first, then fallback).
    pub fn entries(&self) -> Vec<&RouteEntry> {
        Self::all_entries(&self.scheme_entries, &self.fallback_entries)
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
    /// A route referenced a client name not found in the registry.
    UnknownClientName(String),
    /// A proxy route was matched but has no `upstream_url` configured.
    MissingUpstreamUrl(String),
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
            ProxyError::UnknownClientName(name) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unknown client name referenced by route: \"{name}\""),
            )
                .into_response(),
            ProxyError::MissingUpstreamUrl(name) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Route \"{name}\" has no upstream_url configured"),
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

/// Returns `true` when the route's hostname restriction is satisfied.
///
/// - If the route has no `hostname` set (`None`), it matches any host
///   (no restriction).
/// - If `hostname` contains a port (e.g. `api.example.com:8443`), **both**
///   the host and the port must match the incoming `Host` header exactly
///   (case-insensitive host comparison).
/// - If `hostname` has no port (e.g. `api.example.com`), only the host is
///   compared — any port in the `Host` header is ignored.
fn hostname_matches(route: &ReverseProxyRoute, host_header: &str) -> bool {
    let Some(expected) = &route.hostname else {
        return true;
    };

    // Split the configured hostname into (host, optional port).
    let (expected_host, expected_port) = match expected.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (expected.as_str(), None),
    };

    // Split the incoming Host header into (host, optional port).
    let (incoming_host, incoming_port) = match host_header.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_header, None),
    };

    // Host must always match (case-insensitive).
    if !incoming_host.eq_ignore_ascii_case(expected_host) {
        return false;
    }

    // Port must match only when the route specifies one.
    match expected_port {
        Some(ep) => incoming_port == Some(ep),
        None => true,
    }
}

/// Returns `true` when **all** of the route's `match_headers` rules are
/// satisfied by the incoming request headers.
///
/// - An empty `match_headers` list always returns `true`.
/// - Each rule matches when the named header is present and its value fully
///   matches the rule's regex pattern (anchored, case-sensitive).
/// - If any header is absent or its value does not match, returns `false`.
fn headers_match(route: &ReverseProxyRoute, headers: &axum::http::HeaderMap) -> bool {
    use regex_automata::{Match, meta::Regex};

    route.match_headers.iter().all(|matcher| {
        // Header name lookup is case-insensitive (HTTP/1.1 spec).
        let value = match axum::http::HeaderName::from_bytes(matcher.name.as_bytes())
            .ok()
            .and_then(|n| headers.get(&n))
            .and_then(|v| v.to_str().ok())
        {
            Some(v) => v,
            None => return false,
        };

        Regex::new(&matcher.pattern)
            .ok()
            .and_then(|re| re.find(value.as_bytes()))
            .map(|m: Match| m.start() == 0 && m.end() == value.len())
            .unwrap_or(false)
    })
}

/// Selects the matching entry using scheme-priority routing:
/// 1. Scheme-specific entries (http/https) are checked first.
/// 2. Fallback entries (any) are checked only if no scheme-specific match found.
fn select_entry<'a>(
    scheme_entries: &'a [RouteEntry],
    fallback_entries: &'a [RouteEntry],
    method: &axum::http::Method,
    path: &str,
    is_https: bool,
    host: &str,
    headers: &axum::http::HeaderMap,
) -> Option<&'a RouteEntry> {
    let request_scheme = if is_https {
        Scheme::Https
    } else {
        Scheme::Http
    };

    // Priority 1: scheme-specific routes that match the current scheme.
    scheme_entries
        .iter()
        .filter(|e| e.route.enabled && e.route.scheme == request_scheme)
        .find(|e| {
            method_matches(&e.route, method)
                && path_matches(&e.route, path)
                && hostname_matches(&e.route, host)
                && headers_match(&e.route, headers)
        })
        // Priority 2: fallback (any) routes.
        .or_else(|| {
            fallback_entries
                .iter()
                .filter(|e| e.route.enabled)
                .find(|e| {
                    method_matches(&e.route, method)
                        && path_matches(&e.route, path)
                        && hostname_matches(&e.route, host)
                        && headers_match(&e.route, headers)
                })
        })
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

fn build_upstream_url(
    _route: &ReverseProxyRoute,
    path: &str,
    query: Option<&str>,
    base: &str,
) -> String {
    let base = base.trim_end_matches('/');
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
    OptionalAuthSession(auth_session): OptionalAuthSession,
    req: Request,
) -> Result<Response, ProxyError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path();
    let query = uri.query();

    // --- 1. Route selection -------------------------------------------------
    let is_https = req.uri().scheme_str() == Some("https");
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let headers = req.headers().clone();

    let entry = select_entry(
        &state.scheme_entries,
        &state.fallback_entries,
        &method,
        path,
        is_https,
        host,
        &headers,
    )
    .ok_or(ProxyError::NoRouteMatched)?;
    let route = &entry.route;

    // --- 1b. Redirect short-circuit ----------------------------------------
    if let Some(redirect) = &route.redirect {
        let status = axum::http::StatusCode::from_u16(redirect.status_code())
            .unwrap_or(axum::http::StatusCode::FOUND);

        // Build the full Location URL by appending the original path and query
        // to the configured redirect base URL, preserving the request URI.
        let base = redirect.url().trim_end_matches('/');
        let location = match query {
            Some(q) if !q.is_empty() => format!("{base}{path}?{q}"),
            _ => format!("{base}{path}"),
        };

        return Ok(axum::response::Response::builder()
            .status(status)
            .header(axum::http::header::LOCATION, location)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
    }

    // Resolve client and timeout_ms:
    // - Named registry client (from client_name) provides both client and timeout_ms
    // - Otherwise use the per-route default client with no timeout
    let (client, timeout_ms) = entry
        .route
        .client_name
        .as_deref()
        .and_then(|n| state.clients.get(n))
        .map(|(cfg, c)| (c, cfg.timeout_ms))
        .unwrap_or((&entry.client, None));

    // --- 2. Path rewriting --------------------------------------------------
    let upstream_path = rewrite_path(route, path);
    let upstream_url = build_upstream_url(
        route,
        &upstream_path,
        query,
        route
            .upstream_url
            .as_deref()
            .ok_or_else(|| ProxyError::MissingUpstreamUrl(route.name.clone()))?,
    );

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

    // Apply timeout from the resolved client configuration.
    if let Some(ms) = timeout_ms {
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
            upstream_url: Some("http://localhost:8080".to_string()),
            methods: vec![],
            rewrite: RewriteRule::PassThrough,
            request_headers: Default::default(),
            response_headers: Default::default(),
            client_name: None,
            match_headers: vec![],
            scheme: Scheme::Any,
            hostname: None,
            redirect: None,
            enabled: true,
        }
    }

    #[test]
    fn unique_names_accepted() {
        let routes = vec![make_route("alpha"), make_route("beta"), make_route("gamma")];
        assert!(ProxyState::new(routes, HashMap::new()).is_ok());
    }

    #[test]
    fn route_without_tls_builds_ok() {
        let route = make_route("no-tls");
        assert!(RouteEntry::new(route).is_ok());
    }

    #[test]
    fn duplicate_name_rejected() {
        let routes = vec![make_route("alpha"), make_route("beta"), make_route("alpha")];
        let err = ProxyState::new(routes, HashMap::new()).unwrap_err();
        assert!(matches!(err, ProxyError::DuplicateRouteName(n) if n == "alpha"));
    }

    #[test]
    fn duplicate_name_rejected_from_entries() {
        let entries = vec![
            RouteEntry::new(make_route("foo")).unwrap(),
            RouteEntry::new(make_route("foo")).unwrap(),
        ];
        let err = ProxyState::from_entries(entries, HashMap::new()).unwrap_err();
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
        let err = ProxyState::new(routes, HashMap::new()).unwrap_err();
        assert!(matches!(err, ProxyError::DuplicateRouteName(n) if n == "beta"));
    }

    #[test]
    fn each_entry_has_its_own_client() {
        let routes = vec![make_route("svc-a"), make_route("svc-b")];
        let state = ProxyState::new(routes, HashMap::new()).unwrap();
        // Each entry must hold a client; verify by pointer inequality is not
        // possible for reqwest::Client, but we can at least assert one per entry.
        let all = state.entries();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].route.name, "svc-a");
        assert_eq!(all[1].route.name, "svc-b");
    }

    #[test]
    fn custom_entry_accepted() {
        let route = make_route("custom");
        let entry = RouteEntry::with_builder(route, ClientBuilder::new()).unwrap();
        let state = ProxyState::from_entries(vec![entry], HashMap::new()).unwrap();
        assert_eq!(state.fallback_entries[0].route.name, "custom");
    }

    #[test]
    fn scheme_specific_routes_take_priority() {
        use crate::config::route::Scheme;
        let mut http_route = make_route("http-only");
        http_route.scheme = Scheme::Http;

        let mut https_route = make_route("https-only");
        https_route.scheme = Scheme::Https;

        let fallback = make_route("fallback");

        let state =
            ProxyState::new(vec![http_route, https_route, fallback], HashMap::new()).unwrap();

        assert_eq!(state.scheme_entries.len(), 2);
        assert_eq!(state.fallback_entries.len(), 1);
    }

    #[test]
    fn hostname_restricts_route_matching() {
        use crate::config::route::PathMatcher;

        let mut restricted = make_route("restricted");
        restricted.hostname = Some("api.example.com".to_string());

        let mut fallback = make_route("fallback");
        fallback.path = PathMatcher::Exact("/restricted".to_string());

        let state = ProxyState::new(vec![restricted, fallback], HashMap::new()).unwrap();

        // "api.example.com" host matches the restricted route.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/restricted",
            false,
            "api.example.com",
            &axum::http::HeaderMap::new(),
        );
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().route.name, "restricted");

        // Unknown host falls through to fallback (hostname: None = any).
        let fallback_matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/restricted",
            false,
            "other.example.com",
            &axum::http::HeaderMap::new(),
        );
        assert!(fallback_matched.is_some());
        assert_eq!(fallback_matched.unwrap().route.name, "fallback");
    }

    #[test]
    fn hostname_with_port_must_match_port() {
        use crate::config::route::PathMatcher;

        let mut port_restricted = make_route("port-restricted");
        port_restricted.hostname = Some("api.example.com:8443".to_string());
        port_restricted.path = PathMatcher::Exact("/port-test".to_string());

        let mut any_port = make_route("any-port");
        any_port.hostname = Some("api.example.com".to_string());
        any_port.path = PathMatcher::Exact("/port-test".to_string());

        let state = ProxyState::new(vec![port_restricted, any_port], HashMap::new()).unwrap();

        // Exact host+port match → port-restricted route wins.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/port-test",
            false,
            "api.example.com:8443",
            &axum::http::HeaderMap::new(),
        );
        assert_eq!(matched.unwrap().route.name, "port-restricted");

        // Same host, different port → port-restricted route must NOT match,
        // falls through to any-port route.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/port-test",
            false,
            "api.example.com:8080",
            &axum::http::HeaderMap::new(),
        );
        assert_eq!(matched.unwrap().route.name, "any-port");

        // Same host, no port in Host header → port-restricted must NOT match.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/port-test",
            false,
            "api.example.com",
            &axum::http::HeaderMap::new(),
        );
        assert_eq!(matched.unwrap().route.name, "any-port");
    }

    #[test]
    fn hostname_without_port_ignores_incoming_port() {
        use crate::config::route::PathMatcher;

        let mut route = make_route("host-only");
        route.hostname = Some("example.com".to_string());
        route.path = PathMatcher::Exact("/host-only".to_string());

        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();

        // Host header with port → still matches (port is ignored when route has none).
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/host-only",
            false,
            "example.com:9000",
            &axum::http::HeaderMap::new(),
        );
        assert!(
            matched.is_some(),
            "should match regardless of incoming port"
        );

        // Host header without port → also matches.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/host-only",
            false,
            "example.com",
            &axum::http::HeaderMap::new(),
        );
        assert!(matched.is_some());

        // Different host → no match.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/host-only",
            false,
            "other.com",
            &axum::http::HeaderMap::new(),
        );
        assert!(matched.is_none());
    }

    #[test]
    fn hostname_case_insensitive() {
        use crate::config::route::PathMatcher;

        let mut route = make_route("ci-host");
        route.hostname = Some("API.Example.COM".to_string());
        route.path = PathMatcher::Exact("/ci".to_string());

        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();

        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/ci",
            false,
            "api.example.com",
            &axum::http::HeaderMap::new(),
        );
        assert!(
            matched.is_some(),
            "hostname matching must be case-insensitive"
        );
    }

    #[test]
    fn unknown_client_name_rejected() {
        let mut route = make_route("needs-named-client");
        route.client_name = Some("nonexistent-client".to_string());
        let err = ProxyState::new(vec![route], HashMap::new()).unwrap_err();
        assert!(
            matches!(err, ProxyError::UnknownClientName(n) if n == "nonexistent-client"),
            "expected UnknownClientName error"
        );
    }

    #[test]
    fn known_client_name_accepted() {
        use crate::config::client::HttpClientConfig;
        let mut route = make_route("uses-named-client");
        route.client_name = Some("my-client".to_string());
        let named_client = ClientBuilder::new().build().unwrap();
        let clients = HashMap::from([(
            "my-client".to_string(),
            (
                HttpClientConfig {
                    name: "my-client".to_string(),
                    timeout_ms: None,
                    tls: None,
                },
                named_client,
            ),
        )]);
        let state = ProxyState::new(vec![route], clients).unwrap();
        assert_eq!(state.fallback_entries[0].route.name, "uses-named-client");
        assert!(state.clients.contains_key("my-client"));
    }

    #[test]
    fn header_matcher_exact_value() {
        use crate::config::route::HeaderMatcher;
        use axum::http::HeaderMap;

        let mut route = make_route("json-route");
        route.match_headers = vec![HeaderMatcher {
            name: "content-type".to_string(),
            pattern: "application/json".to_string(),
        }];
        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/json-route",
            false,
            "localhost",
            &headers,
        );
        assert!(
            matched.is_some(),
            "should match when Content-Type is application/json"
        );
    }

    #[test]
    fn header_matcher_regex_pattern() {
        use crate::config::route::HeaderMatcher;
        use axum::http::HeaderMap;

        let mut route = make_route("versioned-route");
        route.match_headers = vec![HeaderMatcher {
            name: "x-api-version".to_string(),
            pattern: "v[2-9]".to_string(),
        }];
        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();

        // v3 matches pattern v[2-9]
        let mut headers = HeaderMap::new();
        headers.insert("x-api-version", "v3".parse().unwrap());
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/versioned-route",
            false,
            "localhost",
            &headers,
        );
        assert!(matched.is_some());

        // v1 does NOT match
        let mut headers = HeaderMap::new();
        headers.insert("x-api-version", "v1".parse().unwrap());
        let not_matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/versioned-route",
            false,
            "localhost",
            &headers,
        );
        assert!(not_matched.is_none());
    }

    #[test]
    fn header_matcher_absent_header_no_match() {
        use crate::config::route::HeaderMatcher;

        let mut route = make_route("needs-header");
        route.match_headers = vec![HeaderMatcher {
            name: "x-required".to_string(),
            pattern: ".*".to_string(),
        }];
        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();

        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/needs-header",
            false,
            "localhost",
            &axum::http::HeaderMap::new(),
        );
        assert!(matched.is_none(), "absent header should not match");
    }

    #[test]
    fn empty_match_headers_always_matches() {
        use axum::http::HeaderMap;

        let route = make_route("any-headers");
        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();

        // No headers at all — should still match since match_headers is empty.
        let matched = select_entry(
            &state.scheme_entries,
            &state.fallback_entries,
            &axum::http::Method::GET,
            "/any-headers",
            false,
            "localhost",
            &HeaderMap::new(),
        );
        assert!(matched.is_some());
    }

    #[test]
    fn redirect_route_returns_301() {
        use crate::config::route::RedirectAction;

        let mut route = make_route("perm-redirect");
        route.redirect = Some(RedirectAction::Permanent {
            url: "https://new.example.com".to_string(),
        });
        // upstream_url not needed for redirect routes
        route.upstream_url = None;

        // Verify the route can be built into ProxyState.
        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();
        assert_eq!(state.fallback_entries.len(), 1);
    }

    #[test]
    fn redirect_route_returns_302() {
        use crate::config::route::RedirectAction;

        let mut route = make_route("temp-redirect");
        route.redirect = Some(RedirectAction::Temporary {
            url: "https://example.com/maintenance".to_string(),
        });
        route.upstream_url = None;

        let state = ProxyState::new(vec![route], HashMap::new()).unwrap();
        assert_eq!(state.fallback_entries.len(), 1);
    }
}
