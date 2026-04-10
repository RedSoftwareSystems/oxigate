mod configuration;

use std::{net::SocketAddr, path::Path, sync::Arc};

use axum::{Router, routing::any};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use openssl::{
    pkcs12::Pkcs12,
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::X509,
    x509::store::X509StoreBuilder,
};
use tokio::task::JoinSet;
use tracing::{error, info};

use oxigate::{
    config::{auth::AuthConfig, client::HttpClientRegistry, route::ReverseProxyRoute},
    handler::proxy_handler::{ProxyState, proxy_handler},
};

use configuration::{GatewayConfig, LogLevel, ServerIdentity};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Oxigate — an OIDC-aware reverse proxy / API gateway.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to the gateway configuration file (YAML).
    #[arg(short, long, default_value = "/etc/oxigate/gateway.yaml")]
    config: std::path::PathBuf,

    /// Write example configuration files to a directory and exit.
    ///
    /// If no path is given the current working directory is used.
    /// Creates the following files:
    ///   gateway.yaml  — main gateway configuration
    ///   routes.yaml   — reverse proxy route definitions
    ///   clients.yaml  — named HTTP client registry
    ///   auth.yaml     — OIDC / OAuth2 authentication layer (optional)
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = ".",
    )]
    init: Option<std::path::PathBuf>,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum StartupError {
    Config(configuration::ConfigError),
    Io(std::io::Error),
    Yaml(serde_yaml::Error),
    ClientRegistry(oxigate::config::client::ClientRegistryError),
    Proxy(oxigate::handler::proxy_handler::ProxyError),
    Tls(openssl::error::ErrorStack),
    Auth(axum_oidc_client::errors::Error),
    NoListener,
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupError::Config(e) => write!(f, "Configuration error: {e}"),
            StartupError::Io(e) => write!(f, "I/O error: {e}"),
            StartupError::Yaml(e) => write!(f, "YAML parse error: {e}"),
            StartupError::ClientRegistry(e) => write!(f, "Client registry error: {e}"),
            StartupError::Proxy(e) => write!(f, "Proxy state error: {e:?}"),
            StartupError::Tls(e) => write!(f, "TLS error: {e}"),
            StartupError::Auth(e) => write!(f, "Auth config error: {e}"),
            StartupError::NoListener => {
                write!(f, "No listener configured: set `http` and/or `https`")
            }
        }
    }
}

impl From<configuration::ConfigError> for StartupError {
    fn from(e: configuration::ConfigError) -> Self {
        StartupError::Config(e)
    }
}
impl From<std::io::Error> for StartupError {
    fn from(e: std::io::Error) -> Self {
        StartupError::Io(e)
    }
}
impl From<serde_yaml::Error> for StartupError {
    fn from(e: serde_yaml::Error) -> Self {
        StartupError::Yaml(e)
    }
}
impl From<oxigate::config::client::ClientRegistryError> for StartupError {
    fn from(e: oxigate::config::client::ClientRegistryError) -> Self {
        StartupError::ClientRegistry(e)
    }
}
impl From<oxigate::handler::proxy_handler::ProxyError> for StartupError {
    fn from(e: oxigate::handler::proxy_handler::ProxyError) -> Self {
        StartupError::Proxy(e)
    }
}
impl From<openssl::error::ErrorStack> for StartupError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        StartupError::Tls(e)
    }
}
impl From<axum_oidc_client::errors::Error> for StartupError {
    fn from(e: axum_oidc_client::errors::Error) -> Self {
        StartupError::Auth(e)
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // --init: write example config files and exit.
    if let Some(dest) = cli.init {
        if let Err(e) = write_example_configs(&dest) {
            eprintln!("Failed to write example configs: {e}");
            std::process::exit(1);
        }
        return;
    }

    // Load gateway config first (needed for log level before tracing is init).
    let gateway_cfg = match GatewayConfig::from_file(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load gateway config: {e}");
            std::process::exit(1);
        }
    };

    // Initialise tracing.
    init_tracing(&gateway_cfg.log_level);

    if let Err(e) = run(gateway_cfg).await {
        error!("Fatal startup error: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// --init: example configuration scaffolding
// ---------------------------------------------------------------------------

/// Write a set of well-commented example YAML configuration files to `dest`.
fn write_example_configs(dest: &std::path::Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dest)?;

    let files: &[(&str, &str)] = &[
        ("gateway.yaml", EXAMPLE_GATEWAY),
        ("routes.yaml", EXAMPLE_ROUTES),
        ("clients.yaml", EXAMPLE_CLIENTS),
        ("auth.yaml", EXAMPLE_AUTH),
    ];

    for (name, content) in files {
        let path = dest.join(name);
        if path.exists() {
            eprintln!("Skipping {}: file already exists", path.display());
            continue;
        }
        std::fs::write(&path, content)?;
        println!("Created {}", path.display());
    }

    println!(
        "\nExample configuration written to {}.\n\
         Edit the files to match your environment, then run:\n\
         \n  oxigate --config {}/gateway.yaml\n",
        dest.display(),
        dest.display(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Example file contents
// ---------------------------------------------------------------------------

const EXAMPLE_GATEWAY: &str = r#"# gateway.yaml — Oxigate main configuration
#
# Controls which TCP listeners to open, where to find the route / client /
# auth config files, and the minimum log level.
#
# Listeners
# ---------
# At least one of `http` or `https` must be configured.
# Both can be active at the same time (they run concurrently).

# Plain HTTP listener (optional).
http:
  bind:
    address: "0.0.0.0"
    port: 8080

# HTTPS listener with TLS, optional mTLS, and optional HTTP/2 (optional).
https:
  bind:
    address: "0.0.0.0"
    port: 8443

  # Server certificate and private key — PEM or PKCS#12.
  server_identity:
    format: pem
    cert: /etc/oxigate/tls/server.crt
    key:  /etc/oxigate/tls/server.key

  # Uncomment to enable PKCS#12 instead:
  # server_identity:
  #   format: pkcs12
  #   path:     /etc/oxigate/tls/server.p12
  #   password: "{{env:SERVER_P12_PASSWORD}}"

  # Mutual TLS: uncomment to require client certificates.
  # client_auth:
  #   ca_cert: /etc/oxigate/tls/client-ca.pem
  #   require: true   # false = optional client cert

  # Advertise h2 + http/1.1 via ALPN (default: true).
  http2: true

# Paths to the individual YAML configuration files.
config_files:
  routes:  /etc/oxigate/routes.yaml
  clients: /etc/oxigate/clients.yaml
  # auth:  /etc/oxigate/auth.yaml   # uncomment to enable OIDC layer

# Minimum log level: trace | debug | info | warn | error  (default: info)
log_level: info
"#;

const EXAMPLE_ROUTES: &str = r#"# routes.yaml — Reverse proxy route definitions
#
# Each entry maps an inbound request (matched by path and, optionally, HTTP
# method) to an upstream service URL.
#
# Fields
# ------
# name          (required) Unique identifier used in logs and metrics.
# path          (required) How to match the request path — one of:
#                 type: exact   value: /health
#                 type: prefix  value: /api/
#                 type: regex   value: "^/v[0-9]+/.*"
# upstream_url  (required) Base URL of the upstream service (no trailing slash).
# methods       (optional) Restrict to specific HTTP methods; empty = all.
# rewrite       (optional) How to build the upstream path:
#                 pass_through  — forward unchanged (default)
#                 strip_prefix  — remove the matched prefix
#                 replace: /new-path
# request_headers  (optional) Headers to add/strip before forwarding.
# response_headers (optional) Headers to add/strip before returning.
# client_name   (optional) Name of a client from clients.yaml; if omitted
#               a plain default client is used.
# enabled       (optional, default: true) Set false to disable without removing.

- name: health-check
  path:
    type: exact
    value: /health
  upstream_url: "http://backend:8080"
  enabled: true

- name: api-backend
  path:
    type: prefix
    value: /api/
  upstream_url: "http://backend:8080"
  methods:
    - GET
    - POST
    - PUT
    - DELETE
  rewrite: strip_prefix
  request_headers:
    add:
      Authorization:       "{{access_token}}"   # inject OAuth2 access token
      X-Id-Token:          "{{id_token}}"        # inject OIDC ID token
      X-Api-Key:           "{{env:API_KEY}}"     # inject env variable
      X-Forwarded-Prefix:  /api
    strip:
      - Cookie
  response_headers:
    strip:
      - X-Internal-Server
  # client_name: secure-backend   # reference a named client from clients.yaml
  enabled: true

- name: static-assets
  path:
    type: prefix
    value: /static/
  upstream_url: "http://cdn-service:9000"
  rewrite: pass_through
  enabled: true
"#;

const EXAMPLE_CLIENTS: &str = r#"# clients.yaml — Named HTTP client registry
#
# Defines named reqwest clients that routes can reference via `client_name`.
# Each client has its own connection pool, TLS settings, and optional timeout.
#
# Fields
# ------
# name        (required) Unique identifier referenced by routes.
# timeout_ms  (optional) Request timeout in milliseconds; omit for no timeout.
# tls         (optional) TLS settings for the upstream connection:
#   ca_cert             Path to a PEM CA certificate to verify the upstream.
#   accept_invalid_certs  true/false — disable TLS verification (dev only!).
#   client_identity     Client certificate for mutual TLS (mTLS):
#     type: pem
#       cert  Path to PEM client certificate.
#       key   Path to PEM unencrypted private key.
#     type: pkcs12
#       path      Path to .p12 / .pfx archive.
#       password  Optional password; supports {{env:VAR}} interpolation.

clients:
  # Plain default client — no TLS overrides, no timeout.
  - name: default-backend

  # Client with a custom CA and a 5-second timeout.
  - name: secure-backend
    timeout_ms: 5000
    tls:
      ca_cert: /etc/oxigate/tls/upstream-ca.pem

  # Client with mutual TLS using PEM files.
  - name: mtls-pem-backend
    timeout_ms: 10000
    tls:
      ca_cert: /etc/oxigate/tls/upstream-ca.pem
      client_identity:
        type: pem
        cert: /etc/oxigate/tls/client.crt
        key:  /etc/oxigate/tls/client.key

  # Client with mutual TLS using a PKCS#12 archive.
  # - name: mtls-pkcs12-backend
  #   tls:
  #     ca_cert: /etc/oxigate/tls/upstream-ca.pem
  #     client_identity:
  #       type: pkcs12
  #       path:     /etc/oxigate/tls/client.p12
  #       password: "{{env:P12_PASSWORD}}"
"#;

const EXAMPLE_AUTH: &str = r#"# auth.yaml — OIDC / OAuth2 authentication layer (optional)
#
# When this file is referenced in gateway.yaml under config_files.auth,
# the AuthenticationLayer from axum-oidc-client is added to the server.
# Every incoming request must have a valid session cookie or it is
# redirected to the provider's authorization endpoint.
#
# Endpoint resolution
# -------------------
# Option A — OIDC auto-discovery (recommended):
#   Set `issuer_url`; endpoints are fetched from
#   <issuer_url>/.well-known/openid-configuration automatically.
#   Any field under `endpoints` overrides the discovered value.
#
# Option B — manual endpoints:
#   Leave `issuer_url` unset and fill in all `endpoints.*` fields.

# OIDC issuer URL for auto-discovery (option A).
issuer_url: "https://accounts.google.com"

# Manual endpoint overrides (option B or partial overrides of discovered values).
# endpoints:
#   authorization: "https://provider.example.com/oauth2/authorize"
#   token:         "https://provider.example.com/oauth2/token"
#   end_session:   "https://provider.example.com/oauth2/logout"

# OAuth2 / OIDC client credentials.
client:
  id:           "your-client-id"
  secret:       "{{env:OIDC_CLIENT_SECRET}}"   # never hard-code secrets
  redirect_uri: "https://gateway.example.com/auth/callback"

# Session cookie encryption key — must be at least 32 characters.
# Generate with: openssl rand -base64 48
private_cookie_key: "{{env:COOKIE_ENCRYPTION_KEY}}"

# Session and token lifetime.
session:
  max_age_minutes:      30    # session duration
  token_max_age_seconds: 300  # force refresh after 5 minutes (optional)

# OAuth2 scopes to request (default: openid, email, profile).
scopes:
  - openid
  - email
  - profile

# PKCE code challenge method: s256 (recommended) or plain.
code_challenge_method: s256

# Authentication route configuration.
routes:
  base_path: /auth                    # routes: GET /auth, /auth/callback, /auth/logout
  post_logout_redirect_uri: /         # where to send users after logout
  token_request_redirect_uri: true    # include redirect_uri in token request (RFC 6749)

# TLS for the HTTP client that talks to the OIDC provider (optional).
# provider_tls:
#   custom_ca_cert: /etc/oxigate/tls/provider-ca.pem
"#;

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

async fn run(gateway_cfg: GatewayConfig) -> Result<(), StartupError> {
    gateway_cfg
        .validate()
        .map_err(|_| StartupError::NoListener)?;

    info!(
        "Loading routes from {}",
        gateway_cfg.config_files.routes.display()
    );
    let routes = load_yaml::<Vec<ReverseProxyRoute>>(&gateway_cfg.config_files.routes)?;

    info!(
        "Loading client registry from {}",
        gateway_cfg.config_files.clients.display()
    );
    let registry = load_yaml::<HttpClientRegistry>(&gateway_cfg.config_files.clients)?;
    let clients = registry.build()?;

    info!(
        "Building proxy state ({} routes, {} named clients)",
        routes.len(),
        clients.len()
    );
    let proxy_state = Arc::new(ProxyState::new(routes, clients)?);

    // Optionally build the OIDC authentication layer first.
    let auth_layer = match &gateway_cfg.config_files.auth {
        Some(auth_path) => {
            info!("Loading OIDC auth config from {}", auth_path.display());
            let auth_cfg = load_yaml::<AuthConfig>(auth_path)?;
            let oauth_cfg = Arc::new(auth_cfg.build().await?);

            let cache: Arc<dyn axum_oidc_client::auth_cache::AuthCache + Send + Sync> = Arc::new(
                axum_oidc_client::cache::TwoTierAuthCache::new(
                    None,
                    axum_oidc_client::cache::config::TwoTierCacheConfig::default(),
                )
                .expect("failed to build auth cache"),
            );

            let logout_handler =
                Arc::new(axum_oidc_client::logout::handle_default_logout::DefaultLogoutHandler);

            info!(
                "OIDC authentication layer enabled (base path: {})",
                oauth_cfg.base_path
            );

            Some(axum_oidc_client::auth::AuthenticationLayer::new(
                oauth_cfg,
                cache,
                logout_handler,
            ))
        }
        None => {
            info!("No auth config provided — running without authentication layer");
            None
        }
    };

    // Build the Axum router: state must be set before any layer() call so that
    // the handler's extractor types (State<Arc<ProxyState>>) are resolved first.
    let app = {
        let router = Router::new()
            .route("/{*path}", any(proxy_handler))
            .with_state(proxy_state.clone());

        // Apply the auth layer on top of the fully-typed router.
        match auth_layer {
            Some(layer) => router.layer(layer),
            None => router,
        }
    };

    // Spawn listeners concurrently.
    let mut set = JoinSet::new();

    if let Some(http_cfg) = &gateway_cfg.http {
        let addr: SocketAddr = http_cfg
            .bind
            .to_string()
            .parse()
            .expect("invalid HTTP bind address");
        let app = app.clone();
        info!("Starting HTTP listener on {addr}");
        set.spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("failed to bind HTTP listener");
            axum::serve(listener, app).await.expect("HTTP server error");
        });
    }

    if let Some(https_cfg) = &gateway_cfg.https {
        let addr: SocketAddr = https_cfg
            .bind
            .to_string()
            .parse()
            .expect("invalid HTTPS bind address");
        let openssl_cfg = build_openssl_config(https_cfg)?;
        let app = app.clone();
        info!(
            "Starting HTTPS listener on {addr} (HTTP/2: {}, mTLS: {})",
            https_cfg.http2,
            https_cfg.client_auth.is_some(),
        );
        set.spawn(async move {
            axum_server::bind_openssl(addr, openssl_cfg)
                .serve(app.into_make_service())
                .await
                .expect("HTTPS server error");
        });
    }

    // Wait for all listeners — if any exits, log and abort.
    while let Some(result) = set.join_next().await {
        if let Err(e) = result {
            error!("Listener task panicked: {e}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TLS setup
// ---------------------------------------------------------------------------

/// Build an [`OpenSSLConfig`] from the HTTPS configuration, handling:
/// - PEM and PKCS#12 server identities
/// - Optional mTLS client authentication (required or optional)
/// - HTTP/2 via ALPN (`h2` + `http/1.1`)
fn build_openssl_config(
    https_cfg: &configuration::HttpsConfig,
) -> Result<OpenSSLConfig, StartupError> {
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;

    // -- Server identity (certificate + private key) -------------------------
    match &https_cfg.server_identity {
        ServerIdentity::Pem { cert, key } => {
            builder.set_certificate_chain_file(cert)?;
            builder.set_private_key_file(key, openssl::ssl::SslFiletype::PEM)?;
        }
        ServerIdentity::Pkcs12 { path, password } => {
            let der = std::fs::read(path)?;
            let password = password.as_deref().unwrap_or("");
            let p12 = Pkcs12::from_der(&der)?.parse2(password)?;

            if let Some(cert) = p12.cert {
                builder.set_certificate(&cert)?;
            }
            if let Some(key) = p12.pkey {
                builder.set_private_key(&key)?;
            }
            // Intermediate chain certificates
            if let Some(chain) = p12.ca {
                for ca_cert in &chain {
                    builder.add_extra_chain_cert(ca_cert.to_owned())?;
                }
            }
        }
    }

    builder.check_private_key()?;

    // -- Mutual TLS (mTLS) ---------------------------------------------------
    if let Some(client_auth) = &https_cfg.client_auth {
        let ca_pem = std::fs::read(&client_auth.ca_cert)?;
        let ca_cert = X509::from_pem(&ca_pem)?;

        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(ca_cert)?;
        let store = store_builder.build();

        builder.set_verify_cert_store(store)?;

        let verify_mode = if client_auth.require {
            // Fail the handshake if no valid client certificate is presented.
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        } else {
            // Request a certificate but accept connections without one.
            SslVerifyMode::PEER
        };
        builder.set_verify(verify_mode);
    }

    // -- ALPN (HTTP/2 + HTTP/1.1) --------------------------------------------
    if https_cfg.http2 {
        // Server ALPN callback: prefer h2 when the client supports it.
        builder.set_alpn_select_callback(|_, client_protocols| {
            openssl::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_protocols)
                .ok_or(openssl::ssl::AlpnError::NOACK)
        });
        // Advertise protocols in the TLS ClientHello.
        builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    } else {
        builder.set_alpn_protos(b"\x08http/1.1")?;
    }

    Ok(OpenSSLConfig::try_from(builder)
        .map_err(|_e| StartupError::Tls(openssl::error::ErrorStack::get()))
        .unwrap_or_else(|_| {
            panic!(
                "failed to build OpenSSL config: {}",
                openssl::error::ErrorStack::get()
            )
        }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load and deserialise a YAML file into `T`.
fn load_yaml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, StartupError> {
    let content = std::fs::read_to_string(path)?;
    let value = serde_yaml::from_str(&content)?;
    Ok(value)
}

/// Initialise the `tracing` subscriber using the configured log level.
fn init_tracing(level: &LogLevel) {
    let filter = format!("oxigate={level},oxigate_app={level},tower_http={level}");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(true)
        .with_thread_ids(false)
        .compact()
        .init();
}
