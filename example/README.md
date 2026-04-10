# Oxigate — Docker Compose Example

This directory contains a self-contained Docker Compose environment that demonstrates
Oxigate acting as a reverse proxy in front of two backend services:

| Service       | Description                                     | Internal address       |
|---------------|-------------------------------------------------|------------------------|
| `backend`     | Express REST API + health endpoint              | `http://backend:8080`  |
| `cdn-service` | Express static asset server                     | `http://cdn-service:9000` |
| `gateway`     | Oxigate reverse proxy (HTTP + HTTPS)            | `localhost:8080/8443`  |

## Directory layout

```
example/
├── docker-compose.yml       ← orchestrates all three services
├── gen-certs.sh             ← generates self-signed TLS certificates
├── certs/                   ← created by gen-certs.sh (gitignored)
│   ├── ca.crt
│   ├── server.crt
│   └── server.key
├── gateway/
│   ├── Dockerfile           ← multi-stage Rust build → debian:bookworm-slim
│   ├── gateway.yaml         ← listener config (HTTP :8080, HTTPS :8443)
│   ├── routes.yaml          ← routing rules
│   ├── clients.yaml         ← upstream client settings
│   └── auth.yaml            ← authentication config
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
└── cdn-service/
    ├── Dockerfile
    ├── package.json
    └── server.js
```

## Prerequisites

- Docker Engine ≥ 24 with the Compose plugin (`docker compose`)
- OpenSSL (for `gen-certs.sh`)
- Rust toolchain (only needed if you want to build the gateway image locally)

## Quick start

### 1. Generate TLS certificates

```bash
./gen-certs.sh
```

This creates `./certs/ca.crt`, `./certs/server.crt`, and `./certs/server.key`.
The CA certificate (`ca.crt`) is what you pass to `curl --cacert` or import into
your browser to trust the self-signed server certificate.

### 2. Start everything

```bash
docker compose up --build
```

The first run will:
- Build the `backend` and `cdn-service` Node images (fast, ~30 s).
- Build the `gateway` image by compiling the Oxigate workspace from source using
  a multi-stage Rust build (slower on the first run, ~2–5 min depending on your
  machine; subsequent runs use the Docker layer cache).

### 3. Run the tests

Once the services are up, open a second terminal and try the following:

#### Health check (HTTP)
```bash
curl -i http://localhost:8080/health
```

#### Health check (HTTPS / HTTP2)
```bash
curl -i --cacert certs/ca.crt https://localhost:8443/health
```

#### REST API — list users
```bash
curl -i http://localhost:8080/api/users
```

#### REST API — create a user
```bash
curl -i -X POST http://localhost:8080/api/users \
     -H 'Content-Type: application/json' \
     -d '{"name":"Charlie","email":"charlie@example.com"}'
```

#### REST API — list items
```bash
curl -i http://localhost:8080/api/items
```

#### REST API — update an item
```bash
curl -i -X PUT http://localhost:8080/api/items/item-1 \
     -H 'Content-Type: application/json' \
     -d '{"name":"Widget Alpha","price":12.99}'
```

#### REST API — delete an item
```bash
curl -i -X DELETE http://localhost:8080/api/items/item-2
```

#### Static assets
```bash
curl -i http://localhost:8080/static/logo.svg
curl -i http://localhost:8080/static/styles.css
curl -i http://localhost:8080/static/app.js
```

## What to observe

### Header injection
Routes under `/api/*` add these headers before forwarding to the backend:
- `Authorization` — set from the gateway auth config
- `X-Api-Key` — injected by the gateway
- `X-Id-Token` — injected by the gateway
- `X-Forwarded-Prefix: /api` — the stripped prefix

Check the `backend` container logs to see all received headers:
```bash
docker compose logs -f backend
```

### Header stripping
- **Request**: The `Cookie` header is removed by the gateway before it reaches the backend.
- **Response**: The `X-Internal-Server` header set by the backend (`backend-v1`) is
  removed by the gateway before it reaches the client — verify with:
  ```bash
  curl -si http://localhost:8080/api/users | grep -i x-internal
  # (no output — header was stripped)
  ```

## Stopping the environment

```bash
docker compose down
```

To also remove the built images:
```bash
docker compose down --rmi local
```

## Configuration reference

| File                   | Purpose                                                    |
|------------------------|------------------------------------------------------------|
| `gateway/gateway.yaml` | Listener ports, TLS certificate paths, included config files |
| `gateway/routes.yaml`  | URL routing rules, header manipulation, upstream targets   |
| `gateway/clients.yaml` | HTTP client settings for each upstream (timeouts, etc.)    |
| `gateway/auth.yaml`    | Authentication providers and API key configuration         |
