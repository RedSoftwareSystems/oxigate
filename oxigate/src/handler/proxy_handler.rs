use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_oidc_client::auth_session::AuthSession;
use reqwest::Client;

use crate::config::route::{
    HttpMethod, PathMatcher, ResolveContext, ReverseProxyRoute, RewriteRule,
};

// ---------------------------------------------------------------------------
// Proxy state
// ---------------------------------------------------------------------------

/// Shared application state for the reverse proxy handler.
///
/// Wrap in [`axum::extract::State`] and register with your `Router`:
///
/// ```ignore
/// let state = Arc::new(ProxyState::new(routes));
/// let app = Router::new()
///     .route("/{*path}", any(proxy_handler))
///     .with_state(state);
/// ```
#[derive(Clone)]
pub struct ProxyState {
    /// Ordered list of routing rules. The first matching rule wins.
    pub routes: Vec<ReverseProxyRoute>,
    /// Shared HTTP client reused across requests for connection pooling.
    pub client: Client,
    /// Optional pre-collected environment snapshot used for `{{env:…}}`
    /// interpolation. When `None` the handler falls back to `std::env::var`.
    pub env: Option<Arc<HashMap<String, String>>>,
}

impl ProxyState {
    /// Create a new [`ProxyState`] with a default [`Client`].
    pub fn new(routes: Vec<ReverseProxyRoute>) -> Self {
        Self {
            routes,
            client: Client::new(),
            env: None,
        }
    }

    /// Create a new [`ProxyState`] with a custom [`Client`].
    pub fn with_client(routes: Vec<ReverseProxyRoute>, client: Client) -> Self {
        Self {
            routes,
            client,
            env: None,
        }
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

/// Selects the first enabled route that matches `method` and `path`.
fn select_route<'a>(
    routes: &'a [ReverseProxyRoute],
    method: &axum::http::Method,
    path: &str,
) -> Option<&'a ReverseProxyRoute> {
    routes
        .iter()
        .filter(|r| r.enabled)
        .find(|r| method_matches(r, method) && path_matches(r, path))
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
/// 1. Selects the first enabled route that matches the request method and path.
/// 2. Rewrites the upstream path according to the route's [`RewriteRule`].
/// 3. Strips and injects request headers as configured.
/// 4. Forwards the request (including body) to the upstream.
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
    let route = select_route(&state.routes, &method, path).ok_or(ProxyError::NoRouteMatched)?;

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

    let mut upstream_req = state.client.request(reqwest_method, &upstream_url);

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
