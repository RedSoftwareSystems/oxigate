# Makefile for the Oxigate example environment
# Run from the example/ directory (same level as docker-compose.yml).
#
# Prerequisites:
#   cp .env.example .env   # then fill in your OAuth2 credentials
#
# Usage:
#   make               → print help (default)
#
#   Setup:
#   make env           → copy .env.example to .env (if .env does not exist)
#   make certs         → generate self-signed TLS certificates into ./certs/
#   make setup         → env + certs + npm install for local dev
#
#   Lifecycle:
#   make up            → check .env, generate certs (if needed), start all services
#   make up-build      → same, but force-rebuild all Docker images first
#   make down          → stop and remove containers (keeps volumes/images)
#   make restart       → down + up
#   make ps            → show running container status
#
#   Individual services:
#   make up-gateway    → (re)start only the gateway container
#   make up-backend    → (re)start only the backend container
#   make up-cdn        → (re)start only the cdn-service container
#   make build-gateway → rebuild gateway image (full Rust compile)
#   make build-backend → rebuild backend image
#   make build-cdn     → rebuild cdn-service image
#
#   Logs:
#   make logs          → tail logs from all services
#   make logs-gateway  → tail gateway logs only
#   make logs-backend  → tail backend logs only
#   make logs-cdn      → tail cdn-service logs only
#
#   Smoke tests:
#   make test          → run all smoke tests against the running stack
#   make test-http     → smoke test HTTP endpoints only
#   make test-https    → smoke test HTTPS endpoints only
#   make test-headers  → verify header injection and stripping
#
#   Cleanup:
#   make clean         → stop containers and remove generated certs
#   make clean-all     → clean + remove built Docker images and volumes

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COMPOSE         := docker compose
COMPOSE_FILE    := docker-compose.yml
ENV_FILE        := .env
ENV_EXAMPLE     := .env.example
CERTS_DIR       := certs
CA_CERT         := $(CERTS_DIR)/ca.crt
SERVER_CERT     := $(CERTS_DIR)/server.crt
SERVER_KEY      := $(CERTS_DIR)/server.key

HTTP_BASE       := http://localhost:8080
HTTPS_BASE      := https://localhost:8443

# Required variables that must be present and non-empty in .env.
REQUIRED_VARS   := OAUTH_ISSUER OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET

# Colour helpers (degrade gracefully when the terminal has no colour support).
BOLD   := $(shell tput bold    2>/dev/null || true)
GREEN  := $(shell tput setaf 2 2>/dev/null || true)
CYAN   := $(shell tput setaf 6 2>/dev/null || true)
YELLOW := $(shell tput setaf 3 2>/dev/null || true)
RED    := $(shell tput setaf 1 2>/dev/null || true)
RESET  := $(shell tput sgr0    2>/dev/null || true)

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: \
  all env certs setup check-env \
  up up-build down restart ps \
  up-gateway up-backend up-cdn \
  build-gateway build-backend build-cdn \
  logs logs-gateway logs-backend logs-cdn \
  test test-http test-https test-headers \
  clean clean-all \
  help

# ---------------------------------------------------------------------------
# .env validation
# ---------------------------------------------------------------------------

# check-env is an order-only prerequisite for all lifecycle targets.
# It aborts with a clear message when .env is missing or incomplete.
check-env:
	@if [ ! -f "$(ENV_FILE)" ]; then \
	  echo "$(RED)$(BOLD)ERROR: $(ENV_FILE) not found.$(RESET)"; \
	  echo ""; \
	  echo "Create it from the example file and fill in your credentials:"; \
	  echo ""; \
	  echo "  cp $(ENV_EXAMPLE) $(ENV_FILE)"; \
	  echo "  $$EDITOR $(ENV_FILE)"; \
	  echo ""; \
	  echo "Required variables: $(REQUIRED_VARS)"; \
	  exit 1; \
	fi
	@MISSING=""; \
	for VAR in $(REQUIRED_VARS); do \
	  VALUE=$$(grep -E "^$${VAR}=" "$(ENV_FILE)" | cut -d= -f2- | tr -d '"' | tr -d "'"); \
	  if [ -z "$$VALUE" ] || \
	     echo "$$VALUE" | grep -qE "^(your-|change-me|<)"; then \
	    MISSING="$$MISSING $$VAR"; \
	  fi; \
	done; \
	if [ -n "$$MISSING" ]; then \
	  echo "$(RED)$(BOLD)ERROR: The following required variables are missing or"; \
	  echo "still contain placeholder values in $(ENV_FILE):$(RESET)"; \
	  for V in $$MISSING; do \
	    echo "  $(YELLOW)$$V$(RESET)"; \
	  done; \
	  echo ""; \
	  echo "Edit $(ENV_FILE) and set real values for each variable."; \
	  echo "See $(ENV_EXAMPLE) for guidance."; \
	  exit 1; \
	fi
	@echo "$(GREEN)$(BOLD)» .env OK$(RESET)  ($(REQUIRED_VARS))"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

## env: Copy .env.example to .env (only if .env does not already exist).
env:
	@if [ -f "$(ENV_FILE)" ]; then \
	  echo "$(YELLOW)$(ENV_FILE) already exists — skipping.$(RESET)"; \
	  echo "  Edit it to set your OAuth2 credentials."; \
	else \
	  cp "$(ENV_EXAMPLE)" "$(ENV_FILE)"; \
	  echo "$(GREEN)$(BOLD)» $(ENV_FILE) created from $(ENV_EXAMPLE).$(RESET)"; \
	  echo "  Edit it and set: $(REQUIRED_VARS)"; \
	fi

## certs: Generate self-signed CA + server TLS certificate into ./certs/.
certs: $(SERVER_CERT)

$(SERVER_CERT): gen-certs.sh
	@echo "$(CYAN)$(BOLD)» Generating TLS certificates…$(RESET)"
	@chmod +x gen-certs.sh
	@./gen-certs.sh

## setup: Create .env, generate certificates, and install Node dependencies.
setup: env certs
	@echo "$(CYAN)$(BOLD)» Installing backend dependencies…$(RESET)"
	cd backend     && npm install
	@echo "$(CYAN)$(BOLD)» Installing cdn-service dependencies…$(RESET)"
	cd cdn-service && npm install
	@echo "$(GREEN)$(BOLD)» Setup complete.$(RESET)"
	@echo "  Edit $(ENV_FILE) and set your OAuth2 credentials, then run: make up"

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

## up: Validate .env, ensure certs exist, then start all services (detached).
up: check-env $(SERVER_CERT)
	@echo "$(CYAN)$(BOLD)» Starting services…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) --env-file $(ENV_FILE) up --detach
	@echo ""
	@echo "$(GREEN)$(BOLD)Services are up.$(RESET)"
	@echo "  HTTP  → $(HTTP_BASE)/health"
	@echo "  HTTPS → $(HTTPS_BASE)/health  (use --cacert $(CA_CERT))"
	@echo "  Login → $(HTTP_BASE)/auth"

## up-build: Validate .env, rebuild all images, then start services (detached).
up-build: check-env $(SERVER_CERT)
	@echo "$(CYAN)$(BOLD)» Rebuilding images and starting services…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) --env-file $(ENV_FILE) up --build --detach
	@echo ""
	@echo "$(GREEN)$(BOLD)Services are up (fresh build).$(RESET)"
	@echo "  HTTP  → $(HTTP_BASE)/health"
	@echo "  HTTPS → $(HTTPS_BASE)/health  (use --cacert $(CA_CERT))"
	@echo "  Login → $(HTTP_BASE)/auth"

## down: Stop and remove all containers (images and volumes are kept).
down:
	@echo "$(CYAN)$(BOLD)» Stopping services…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) down

## restart: Stop then restart all services (re-validates .env).
restart: down up

## ps: Show the status of all containers.
ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

# ---------------------------------------------------------------------------
# Individual service management
# ---------------------------------------------------------------------------

## up-gateway: (Re)start the gateway container only.
up-gateway: check-env
	@echo "$(CYAN)$(BOLD)» Starting gateway…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) --env-file $(ENV_FILE) up --detach gateway

## up-backend: (Re)start the backend container only.
up-backend:
	@echo "$(CYAN)$(BOLD)» Starting backend…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) up --detach backend

## up-cdn: (Re)start the cdn-service container only.
up-cdn:
	@echo "$(CYAN)$(BOLD)» Starting cdn-service…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) up --detach cdn-service

## build-gateway: Rebuild the gateway image (full Rust compile).
build-gateway:
	@echo "$(CYAN)$(BOLD)» Rebuilding gateway image (Rust compile — may take a few minutes)…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) build gateway

## build-backend: Rebuild the backend Node image.
build-backend:
	@echo "$(CYAN)$(BOLD)» Rebuilding backend image…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) build backend

## build-cdn: Rebuild the cdn-service Node image.
build-cdn:
	@echo "$(CYAN)$(BOLD)» Rebuilding cdn-service image…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) build cdn-service

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

## logs: Tail logs from all services (Ctrl-C to stop).
logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs --follow

## logs-gateway: Tail gateway logs only.
logs-gateway:
	$(COMPOSE) -f $(COMPOSE_FILE) logs --follow gateway

## logs-backend: Tail backend logs only.
logs-backend:
	$(COMPOSE) -f $(COMPOSE_FILE) logs --follow backend

## logs-cdn: Tail cdn-service logs only.
logs-cdn:
	$(COMPOSE) -f $(COMPOSE_FILE) logs --follow cdn-service

# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------

# Internal helper — assert that a curl response body/status matches a pattern.
define assert_contains
	@printf "  %-48s" "$(1)"; \
	RESP=$$(curl -sk --cacert "$(CA_CERT)" -o - -w '%{http_code}' "$(2)" 2>/dev/null); \
	CODE=$${RESP: -3}; BODY=$${RESP%???}; \
	if echo "$$BODY$$CODE" | grep -q "$(3)"; then \
	  echo "$(GREEN)OK$(RESET)  [HTTP $$CODE]"; \
	else \
	  echo "$(RED)FAIL$(RESET) [HTTP $$CODE]  expected: $(3)"; \
	  echo "    body: $$BODY" | head -c 200; echo; \
	  exit 1; \
	fi
endef

# Internal helper — assert a response header is absent (stripped by gateway).
define assert_header_absent
	@printf "  %-48s" "$(1)"; \
	HEADERS=$$(curl -sI --cacert "$(CA_CERT)" "$(2)" 2>/dev/null); \
	if echo "$$HEADERS" | grep -qi "$(3)"; then \
	  echo "$(RED)FAIL$(RESET)  '$(3)' should be stripped but is present"; \
	  exit 1; \
	else \
	  echo "$(GREEN)OK$(RESET)  [header absent]"; \
	fi
endef

# Internal helper — assert a response header is present.
define assert_header_present
	@printf "  %-48s" "$(1)"; \
	HEADERS=$$(curl -sI --cacert "$(CA_CERT)" "$(2)" 2>/dev/null); \
	if echo "$$HEADERS" | grep -qi "$(3)"; then \
	  echo "$(GREEN)OK$(RESET)  [header present]"; \
	else \
	  echo "$(RED)FAIL$(RESET)  '$(3)' expected but absent"; \
	  exit 1; \
	fi
endef

## test: Run all smoke tests against the running stack.
test: test-http test-https test-headers
	@echo ""
	@echo "$(GREEN)$(BOLD)All smoke tests passed.$(RESET)"

## test-http: Smoke test HTTP endpoints.
test-http:
	@echo ""
	@echo "$(BOLD)HTTP smoke tests  →  $(HTTP_BASE)$(RESET)"
	$(call assert_contains,GET /health → 200 + status ok,$(HTTP_BASE)/health,ok)
	$(call assert_contains,GET / → 200 + HTML home page,$(HTTP_BASE)/,<!DOCTYPE)
	$(call assert_contains,GET /api/users → 200 + JSON array,$(HTTP_BASE)/api/users,alice)
	$(call assert_contains,GET /api/items → 200 + JSON array,$(HTTP_BASE)/api/items,item-1)
	$(call assert_contains,GET /static/logo.svg → 200 + SVG,$(HTTP_BASE)/static/logo.svg,svg)
	$(call assert_contains,GET /static/styles.css → 200 + CSS,$(HTTP_BASE)/static/styles.css,body)
	$(call assert_contains,GET /static/app.js → 200 + JS,$(HTTP_BASE)/static/app.js,Oxigate)
	@echo ""
	@echo "$(GREEN)HTTP tests passed.$(RESET)"

## test-https: Smoke test HTTPS endpoints (requires ./certs/ca.crt).
test-https: $(CA_CERT)
	@echo ""
	@echo "$(BOLD)HTTPS smoke tests  →  $(HTTPS_BASE)$(RESET)"
	$(call assert_contains,GET /health → 200 + status ok,$(HTTPS_BASE)/health,ok)
	$(call assert_contains,GET / → 200 + HTML home page,$(HTTPS_BASE)/,<!DOCTYPE)
	$(call assert_contains,GET /api/users → 200 + JSON array,$(HTTPS_BASE)/api/users,alice)
	$(call assert_contains,GET /static/logo.svg → 200 + SVG,$(HTTPS_BASE)/static/logo.svg,svg)
	@echo ""
	@echo "$(GREEN)HTTPS tests passed.$(RESET)"

## test-headers: Verify header injection and stripping by the gateway.
test-headers:
	@echo ""
	@echo "$(BOLD)Header tests$(RESET)"
	$(call assert_header_absent,X-Internal-Server stripped on /api/users,$(HTTP_BASE)/api/users,X-Internal-Server)
	$(call assert_header_absent,X-Internal-Server stripped on /static/logo.svg,$(HTTP_BASE)/static/logo.svg,X-Internal-Server)
	$(call assert_header_present,Content-Type present on /api/users,$(HTTP_BASE)/api/users,content-type)
	$(call assert_header_present,Content-Type present on /health,$(HTTP_BASE)/health,content-type)
	@echo ""
	@echo "$(GREEN)Header tests passed.$(RESET)"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

## clean: Stop containers and remove generated certificates.
clean: down
	@echo "$(CYAN)$(BOLD)» Removing generated certificates…$(RESET)"
	rm -rf $(CERTS_DIR)
	@echo "$(GREEN)Clean.$(RESET)"

## clean-all: Stop containers, remove certs, Docker images, and volumes.
clean-all: down
	@echo "$(CYAN)$(BOLD)» Removing containers, images, volumes, and certificates…$(RESET)"
	$(COMPOSE) -f $(COMPOSE_FILE) down --rmi local --volumes --remove-orphans
	rm -rf $(CERTS_DIR)
	@echo "$(GREEN)All clean.$(RESET)"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

## help: Print this help message.
help:
	@echo ""
	@echo "$(BOLD)Oxigate example — available make targets$(RESET)"
	@echo ""
	@echo "$(BOLD)Setup$(RESET)"
	@grep -E '^## (env|certs|setup|check-env):' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-22s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Lifecycle$(RESET)"
	@grep -E '^## (up|up-build|down|restart|ps):' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-22s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Individual services$(RESET)"
	@grep -E '^## (up-gateway|up-backend|up-cdn|build-gateway|build-backend|build-cdn):' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-22s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Logs$(RESET)"
	@grep -E '^## logs' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-22s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Smoke tests$(RESET)"
	@grep -E '^## test' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-22s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Cleanup$(RESET)"
	@grep -E '^## clean' $(MAKEFILE_LIST) \
		| sed 's/^## //' \
		| awk '{ match($$0, /^([^:]+): (.*)/, a); printf "  $(CYAN)%-22s$(RESET) %s\n", a[1], a[2] }'
	@echo ""
	@echo "$(BOLD)Required .env variables$(RESET)"
	@echo "  $(CYAN)OAUTH_ISSUER$(RESET)          OIDC issuer URL  (e.g. https://accounts.google.com)"
	@echo "  $(CYAN)OAUTH_CLIENT_ID$(RESET)       OAuth2 client ID"
	@echo "  $(CYAN)OAUTH_CLIENT_SECRET$(RESET)   OAuth2 client secret"
	@echo "  $(CYAN)COOKIE_ENCRYPTION_KEY$(RESET) Session cookie key (min 32 chars)"
	@echo "  $(CYAN)API_KEY$(RESET)               API key forwarded to the backend"
	@echo ""
	@echo "  Run '$(BOLD)make env$(RESET)' to create .env from .env.example."
	@echo ""
