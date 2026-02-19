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
    curl wget gnupg2 lsb-release \
    openssl tpm2-tools \
    jq 2>&1 | tail -3
echo "  System packages installed"

# ============================================================================
# Phase 2: Azure guest attestation client
# ============================================================================
echo ""
echo "[Phase 2/6] Installing guest attestation client..."
ATTESTATION_INSTALLED=false

# Add Microsoft package repository
curl -sSL https://packages.microsoft.com/keys/microsoft.asc \
    | tee /etc/apt/trusted.gpg.d/microsoft.asc > /dev/null 2>&1 || true

AZ_DIST=$(lsb_release -cs 2>/dev/null || echo "noble")
AZ_VER=$(lsb_release -rs 2>/dev/null || echo "24.04")
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/${AZ_VER}/prod ${AZ_DIST} main" \
    > /etc/apt/sources.list.d/microsoft-prod.list

apt-get update -qq 2>/dev/null || true

# Install guest attestation + DCAP client (for SNP evidence)
if apt-get install -y -qq azguestattestation 2>/dev/null; then
    ATTESTATION_INSTALLED=true
    echo "  Guest attestation client installed from Microsoft repository"
fi

# Also try the DCAP client (provides Azure DCAP quote provider)
apt-get install -y -qq az-dcap-client 2>/dev/null || true

if [ "$ATTESTATION_INSTALLED" = false ]; then
    echo "  WARNING: Guest attestation package not available from repo"
    echo "  Attempting direct download..."
    # Try downloading a .deb directly (fallback)
    wget -q "https://packages.microsoft.com/ubuntu/${AZ_VER}/prod/pool/main/a/azguestattestation/azguestattestation_1.0.5_amd64.deb" \
        -O /tmp/azguestattestation.deb 2>/dev/null && \
        dpkg -i /tmp/azguestattestation.deb 2>/dev/null && \
        ATTESTATION_INSTALLED=true && \
        echo "  Guest attestation client installed from direct download" || \
        echo "  WARNING: Could not install guest attestation client"
fi

# Verify
if [ -x "/opt/azguestattestation/AttestationClient" ]; then
    echo "  AttestationClient binary: /opt/azguestattestation/AttestationClient"
elif [ -x "/usr/bin/AttestationClient" ]; then
    echo "  AttestationClient binary: /usr/bin/AttestationClient"
else
    echo "  WARNING: AttestationClient binary not found — attestation will not work"
fi

# Check for SEV-SNP device
if [ -e "/dev/sev-guest" ]; then
    echo "  /dev/sev-guest: PRESENT (AMD SEV-SNP hardware confirmed)"
elif [ -e "/dev/sev" ]; then
    echo "  /dev/sev: PRESENT (AMD SEV device found)"
else
    echo "  WARNING: No SEV device found — this may not be a Confidential VM"
fi

# Check for vTPM
if [ -e "/dev/tpmrm0" ]; then
    echo "  /dev/tpmrm0: PRESENT (vTPM available)"
else
    echo "  WARNING: /dev/tpmrm0 not found — vTPM may not be available"
fi

# ============================================================================
# Phase 3: Application files
# ============================================================================
echo ""
echo "[Phase 3/6] Setting up application files..."
mkdir -p /app/templates /app/encrypted-data /var/log/supervisor /var/log/nginx

# Copy app files (CustomScriptExtension downloads them to the current directory)
for f in app.py skr_shim.py; do
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

if [ -f "nginx.conf" ]; then
    cp -f nginx.conf /etc/nginx/nginx.conf
    echo "  nginx.conf installed"
fi

# ============================================================================
# Phase 6: Supervisord configuration (with environment variables)
# ============================================================================
echo ""
echo "[Phase 6/6] Configuring and starting services..."

# Stop default nginx service — supervisor will manage it
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

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

# Wait briefly and check services
sleep 3
echo ""
echo "  Service status:"
supervisorctl status 2>/dev/null || echo "  (supervisor not yet reporting status)"

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
