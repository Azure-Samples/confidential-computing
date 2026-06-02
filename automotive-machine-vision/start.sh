#!/bin/sh
set -eu

CERT_PATH="/etc/ssl/private/server.crt"
KEY_PATH="/etc/ssl/private/server.key"

mkdir -p /etc/ssl/private

if [ -n "${TLS_CERT_PEM:-}" ] && [ -n "${TLS_KEY_PEM:-}" ]; then
    printf '%s\n' "$TLS_CERT_PEM" > "$CERT_PATH"
    printf '%s\n' "$TLS_KEY_PEM" > "$KEY_PATH"
    chmod 644 "$CERT_PATH"
    chmod 600 "$KEY_PATH"
    echo "Using provided TLS certificate and private key."
elif [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo "Using existing TLS certificate files in image."
else
    echo "No TLS cert/key provided. Generating self-signed certificate for demo use only."
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
        -keyout "$KEY_PATH" \
        -out "$CERT_PATH" \
        -subj "/C=US/ST=WA/L=Redmond/O=ConfidentialComputing/CN=localhost"
    chmod 644 "$CERT_PATH"
    chmod 600 "$KEY_PATH"
fi

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
