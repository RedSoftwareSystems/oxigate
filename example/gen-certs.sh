#!/usr/bin/env bash
# gen-certs.sh — Generate self-signed TLS certificates for the Oxigate example.
# Usage: ./gen-certs.sh
# Output: ./certs/ca.crt, ./certs/server.crt, ./certs/server.key

set -euo pipefail

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

echo "Generating CA key and certificate..."
openssl genrsa -out "$CERTS_DIR/ca.key" 4096
openssl req -new -x509 -days 3650 -key "$CERTS_DIR/ca.key" \
  -subj "/CN=Oxigate Example CA/O=Oxigate/C=IT" \
  -out "$CERTS_DIR/ca.crt"

echo "Generating server key..."
openssl genrsa -out "$CERTS_DIR/server.key" 2048

echo "Generating server certificate signing request..."
openssl req -new -key "$CERTS_DIR/server.key" \
  -subj "/CN=gateway/O=Oxigate Example/C=IT" \
  -out "$CERTS_DIR/server.csr"

echo "Signing server certificate..."
openssl x509 -req -days 365 \
  -in "$CERTS_DIR/server.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:gateway,IP:127.0.0.1") \
  -out "$CERTS_DIR/server.crt"

rm "$CERTS_DIR/server.csr"

echo ""
echo "Certificates written to $CERTS_DIR/"
echo "  ca.crt     — CA certificate (trust this in your browser/curl)"
echo "  server.crt — server certificate"
echo "  server.key — server private key"
echo ""
echo "Test HTTPS with:"
echo "  curl --cacert $CERTS_DIR/ca.crt https://localhost:8443/health"
