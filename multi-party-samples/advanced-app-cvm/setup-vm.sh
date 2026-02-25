#!/bin/bash
# ============================================================================
# setup-vm.sh — CVM Bootstrap Script for Multi-Party Confidential Computing
# ============================================================================
#
# Called by Azure CustomScriptExtension after all app files are downloaded.
# Installs system packages, guest attestation client, Python environment,
# TLS certificates, and starts supervisord with company-specific config.
#
# Arguments:
#   $1  COMPANY_NAME               (contoso|fabrikam|woodgrove)
#   $2  SKR_KEY_NAME               (e.g., contoso-secret-key)
#   $3  SKR_AKV_ENDPOINT           (e.g., <name>.vault.azure.net)
#   $4  SKR_MAA_ENDPOINT           (e.g., sharedneu.neu.attest.azure.net)
#   $5  MANAGED_IDENTITY_CLIENT_ID (GUID of user-assigned managed identity)
#   $6  PARTNER_CONTOSO_URL        (https://10.0.1.4 or NONE)
#   $7  PARTNER_FABRIKAM_URL       (https://10.0.1.5 or NONE)
#   $8  PARTNER_CONTOSO_AKV_ENDPOINT  (https://vault.vault.azure.net or NONE)
#   $9  PARTNER_FABRIKAM_AKV_ENDPOINT (https://vault.vault.azure.net or NONE)
#   $10 ENABLE_DEBUG                  (true|false — when false, SSH is disabled)
# ============================================================================

set -euo pipefail

COMPANY_NAME="${1:?Company name required (contoso|fabrikam|woodgrove)}"
SKR_KEY_NAME="${2:?Key name required}"
SKR_AKV_ENDPOINT="${3:?AKV endpoint required}"
SKR_MAA_ENDPOINT="${4:?MAA endpoint required}"
MANAGED_IDENTITY_CLIENT_ID="${5:?Identity client ID required}"
PARTNER_CONTOSO_URL="${6:-}"
PARTNER_FABRIKAM_URL="${7:-}"
PARTNER_CONTOSO_AKV_ENDPOINT="${8:-}"
PARTNER_FABRIKAM_AKV_ENDPOINT="${9:-}"
ENABLE_DEBUG="${10:-false}"

# Treat "NONE" sentinel as empty string (used for companies without partners)
[[ "$PARTNER_CONTOSO_URL" == "NONE" ]] && PARTNER_CONTOSO_URL=""
[[ "$PARTNER_FABRIKAM_URL" == "NONE" ]] && PARTNER_FABRIKAM_URL=""
[[ "$PARTNER_CONTOSO_AKV_ENDPOINT" == "NONE" ]] && PARTNER_CONTOSO_AKV_ENDPOINT=""
[[ "$PARTNER_FABRIKAM_AKV_ENDPOINT" == "NONE" ]] && PARTNER_FABRIKAM_AKV_ENDPOINT=""

LOG_FILE="/var/log/cvm-setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "================================================================"
echo " CVM Multi-Party Demo — VM Setup"
echo "================================================================"
echo " Company:    $COMPANY_NAME"
echo " Key:        $SKR_KEY_NAME"
echo " AKV:        $SKR_AKV_ENDPOINT"
echo " MAA:        $SKR_MAA_ENDPOINT"
echo " Identity:   $MANAGED_IDENTITY_CLIENT_ID"
echo " Debug:      $ENABLE_DEBUG"
echo " Started:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"
echo ""

export DEBIAN_FRONTEND=noninteractive

# ============================================================================
# Phase 1: System packages
# ============================================================================
echo "[Phase 1/6] Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    nginx supervisor \
    curl wget gnupg2 lsb-release git \
    openssl tpm2-tools \
    jq 2>&1 | tail -3
echo "  System packages installed"

# ---- Disable SSH when not in debug mode ----
if [[ "$ENABLE_DEBUG" != "true" ]]; then
    echo "  Disabling SSH (EnableDebug not set)..."
    systemctl stop ssh 2>/dev/null || systemctl stop sshd 2>/dev/null || true
    systemctl disable ssh 2>/dev/null || systemctl disable sshd 2>/dev/null || true
    echo "  [OK] SSH service stopped and disabled"
else
    echo "  SSH remains enabled (EnableDebug mode)"
fi

# ============================================================================
# Phase 2: CVM attestation tools (Python-based vTPM attestation)
# ============================================================================
echo ""
echo "[Phase 2/6] Installing CVM attestation tools..."

# cvm-attestation-tools replaces the deprecated azguestattestation binary.
# It uses Python + TSS_MSR to talk directly to the vTPM — no native binary needed.
# See: https://github.com/Azure/cvm-attestation-tools

CVM_ATTEST_DIR="/opt/cvm-attestation-tools"

if [ -d "$CVM_ATTEST_DIR" ]; then
    echo "  cvm-attestation-tools already present at $CVM_ATTEST_DIR"
else
    echo "  Cloning cvm-attestation-tools..."
    git clone --depth 1 https://github.com/Azure/cvm-attestation-tools.git "$CVM_ATTEST_DIR" 2>&1 | tail -2
    echo "  Cloned cvm-attestation-tools"
fi

# TSS.MSR — Python TPM library (provides Tpm class for vTPM NV index read/write)
TSS_DIR="$CVM_ATTEST_DIR/cvm-attestation/TSS_MSR"
if [ -d "$TSS_DIR" ]; then
    echo "  TSS.MSR already present"
else
    echo "  Cloning TSS.MSR (Python TPM library)..."
    git clone --depth 1 https://github.com/microsoft/TSS.MSR.git "$TSS_DIR" 2>&1 | tail -2
    echo "  Cloned TSS.MSR"
fi

# Verify vTPM availability (required for attestation)
if [ -e "/dev/tpmrm0" ]; then
    echo "  /dev/tpmrm0: PRESENT (vTPM available)"
elif [ -e "/dev/tpm0" ]; then
    echo "  /dev/tpm0: PRESENT (TPM available)"
else
    echo "  WARNING: No TPM device found — attestation may not work"
fi

# Quick tpm2-tools sanity check (installed in Phase 1)
if command -v tpm2_nvreadpublic &>/dev/null; then
    echo "  tpm2-tools: INSTALLED"
    # Try to list NV indices to confirm TPM access
    if tpm2_nvreadpublic 2>/dev/null | grep -q "0x1400001"; then
        echo "  HCL report NV index (0x1400001): PRESENT"
    else
        echo "  HCL report NV index: not confirmed (may still work via TSS_MSR)"
    fi
else
    echo "  WARNING: tpm2-tools not found"
fi

# ============================================================================
# Phase 3: Application files
# ============================================================================
echo ""
echo "[Phase 3/6] Setting up application files..."
mkdir -p /app/templates /app/encrypted-data /var/log/supervisor /var/log/nginx

# Copy app files (CustomScriptExtension downloads them to the current directory)
DOWNLOAD_DIR="$(pwd)"
for f in app.py skr_shim.py nginx.conf; do
    if [ -f "$f" ]; then
        cp -f "$f" /app/
        echo "  Copied $f → /app/"
    else
        echo "  WARNING: $f not found in download directory ($(pwd))"
    fi
done

# Requirements file
if [ -f "requirements.txt" ]; then
    cp -f requirements.txt /app/requirements.txt
    echo "  Copied requirements.txt → /app/"
fi

# CSV data files
for f in contoso-data.csv fabrikam-data.csv; do
    if [ -f "$f" ]; then
        cp -f "$f" /app/
        echo "  Copied $f → /app/"
    fi
done

# HTML templates (downloaded flat by CustomScriptExtension, placed into templates/)
for f in index.html index-woodgrove.html; do
    if [ -f "$f" ]; then
        cp -f "$f" /app/templates/
        echo "  Copied $f → /app/templates/"
    fi
done

# Set ownership
chown -R root:root /app
chmod -R 755 /app

# ============================================================================
# Phase 4: Python virtual environment
# ============================================================================
echo ""
echo "[Phase 4/6] Setting up Python environment..."
cd /app
python3 -m venv /app/venv
source /app/venv/bin/activate
pip install --no-cache-dir --upgrade pip 2>&1 | tail -1
pip install --no-cache-dir -r requirements.txt 2>&1 | tail -5

# Install cvm-attestation-tools Python dependencies (pyjwt, construct, etc.)
CVM_ATTEST_REQS="/opt/cvm-attestation-tools/cvm-attestation/requirements.txt"
if [ -f "$CVM_ATTEST_REQS" ]; then
    echo "  Installing cvm-attestation-tools Python dependencies..."
    pip install --no-cache-dir -r "$CVM_ATTEST_REQS" 2>&1 | tail -5
    echo "  cvm-attestation-tools dependencies installed"
else
    echo "  WARNING: cvm-attestation-tools requirements.txt not found at $CVM_ATTEST_REQS"
fi

echo "  Python venv: /app/venv"
echo "  Python:      $(python3 --version)"

# ============================================================================
# Phase 5: TLS certificates + nginx
# ============================================================================
echo ""
echo "[Phase 5/6] Configuring TLS and nginx..."
mkdir -p /etc/nginx/ssl

# Self-signed cert for inter-VM HTTPS (partner communication)
# SANs include all three VM private IPs for mutual acceptance
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt \
    -subj "/C=US/ST=WA/L=Redmond/O=Confidential Computing CVM Demo/CN=${COMPANY_NAME}.cvm.local" \
    -addext "subjectAltName=DNS:localhost,IP:10.0.1.4,IP:10.0.1.5,IP:10.0.1.6" \
    2>/dev/null

chmod 600 /etc/nginx/ssl/server.key
chmod 644 /etc/nginx/ssl/server.crt
echo "  TLS certificate generated for ${COMPANY_NAME}.cvm.local"

# Remove default site to prevent it overriding our config
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/conf.d/default.conf

if [ -f "nginx.conf" ]; then
    cp -f nginx.conf /etc/nginx/nginx.conf
    echo "  nginx.conf installed"
else
    echo "  ERROR: nginx.conf not found in $(pwd)" >&2
    ls -la >&2
    exit 1
fi

# Validate nginx config before proceeding
nginx -t 2>&1
echo "  nginx config validated"

# ============================================================================
# Phase 6: Supervisord configuration (with environment variables)
# ============================================================================
echo ""
echo "[Phase 6/6] Configuring and starting services..."

# Stop and fully mask default nginx service — supervisor will manage it
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
systemctl mask nginx 2>/dev/null || true

# Generate supervisord config with company-specific environment variables
cat > /etc/supervisor/conf.d/cvm-demo.conf << SUPERVISOREOF
[supervisord]
nodaemon=false
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid
loglevel=info

[program:skr_shim]
command=/app/venv/bin/python3 /app/skr_shim.py
directory=/app
autostart=true
autorestart=true
stdout_logfile=/var/log/supervisor/skr_shim.log
stderr_logfile=/var/log/supervisor/skr_shim_error.log
priority=1
startsecs=2
environment=SKR_MAA_ENDPOINT="${SKR_MAA_ENDPOINT}",SKR_AKV_ENDPOINT="${SKR_AKV_ENDPOINT}",SKR_KEY_NAME="${SKR_KEY_NAME}",COMPANY_NAME="${COMPANY_NAME}",MANAGED_IDENTITY_CLIENT_ID="${MANAGED_IDENTITY_CLIENT_ID}"

[program:flask]
command=/app/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 --threads 4 --timeout 120 --access-logfile - --error-logfile - --forwarded-allow-ips="127.0.0.1" app:app
directory=/app
autostart=true
autorestart=true
stdout_logfile=/var/log/supervisor/flask.log
stderr_logfile=/var/log/supervisor/flask_error.log
priority=10
startsecs=5
environment=SKR_MAA_ENDPOINT="${SKR_MAA_ENDPOINT}",SKR_AKV_ENDPOINT="${SKR_AKV_ENDPOINT}",SKR_KEY_NAME="${SKR_KEY_NAME}",COMPANY_NAME="${COMPANY_NAME}",MANAGED_IDENTITY_CLIENT_ID="${MANAGED_IDENTITY_CLIENT_ID}",PARTNER_CONTOSO_URL="${PARTNER_CONTOSO_URL}",PARTNER_FABRIKAM_URL="${PARTNER_FABRIKAM_URL}",PARTNER_CONTOSO_AKV_ENDPOINT="${PARTNER_CONTOSO_AKV_ENDPOINT}",PARTNER_FABRIKAM_AKV_ENDPOINT="${PARTNER_FABRIKAM_AKV_ENDPOINT}"

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
autostart=true
autorestart=true
stdout_logfile=/var/log/supervisor/nginx.log
stderr_logfile=/var/log/supervisor/nginx_error.log
priority=20
startsecs=2
SUPERVISOREOF

echo "  supervisord config written to /etc/supervisor/conf.d/cvm-demo.conf"

# Enable and restart supervisor
systemctl enable supervisor 2>/dev/null || true
supervisorctl reread 2>/dev/null || true
supervisorctl update 2>/dev/null || true
systemctl restart supervisor

# Wait for services to start (flask has startsecs=5, gunicorn needs time to fork workers)
echo ""
echo "  Waiting for services to start..."
for i in $(seq 1 12); do
    sleep 5
    # Check if any service is still in STARTING state
    if ! supervisorctl status 2>/dev/null | grep -q STARTING; then
        break
    fi
    echo "    Still waiting... (${i}0s)"
done

echo ""
echo "  Service status:"
supervisorctl status 2>/dev/null || echo "  (supervisor not yet reporting status)"

# Verify critical services are running
echo ""
echo "  Verification:"
VERIFY_FAILED=false
for svc in nginx flask skr_shim; do
    status=$(supervisorctl status "$svc" 2>/dev/null | awk '{print $2}')
    if [ "$status" = "RUNNING" ]; then
        echo "  [OK] $svc is RUNNING"
    elif [ "$status" = "STARTING" ]; then
        echo "  [WARN] $svc is still STARTING (may need more time)"
    else
        echo "  [FAIL] $svc status: $status" >&2
        supervisorctl tail "$svc" stderr 2>/dev/null | tail -5 || true
        VERIFY_FAILED=true
    fi
done
if curl -sf -o /dev/null http://127.0.0.1:80/; then
    echo "  [OK] HTTP port 80 responding"
else
    echo "  [WARN] HTTP port 80 not yet responding (may need more startup time)"
fi
if [ "$VERIFY_FAILED" = true ]; then
    echo ""
    echo "  ERROR: Critical services failed to start. Check logs:" >&2
    echo "    /var/log/supervisor/supervisord.log" >&2
    echo "    /var/log/supervisor/nginx_error.log" >&2
    echo "    /var/log/supervisor/flask_error.log" >&2
    exit 1
fi

echo ""
echo "================================================================"
echo " CVM Setup Complete: ${COMPANY_NAME}"
echo "================================================================"
echo "  SKR Shim:    http://localhost:8080/"
echo "  Flask App:   http://localhost:8000/"
echo "  Nginx HTTP:  http://localhost:80/"
echo "  Nginx HTTPS: https://localhost:443/"
echo "  MAA:         ${SKR_MAA_ENDPOINT}"
echo "  AKV:         ${SKR_AKV_ENDPOINT}"
echo "  Key:         ${SKR_KEY_NAME}"
echo "  Finished:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================"
