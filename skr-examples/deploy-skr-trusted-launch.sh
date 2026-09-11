#!/usr/bin/env bash
# =============================================================================
# deploy-skr-trusted-launch.sh
#
# Deploy a single Azure Trusted Launch VM and demonstrate Secure Key Release
# (SKR) end-to-end WITHOUT Confidential Computing.
#
# This is the Trusted Launch counterpart to the CVM SKR example. It shows that
# Secure Key Release is a feature of Azure Key Vault Premium / Managed HSM that
# validates a Microsoft Azure Attestation (MAA) token against a key's release
# policy — independent of the compute type. A Trusted Launch VM (Gen2, Secure
# Boot + vTPM) is not a Confidential VM and does not emit SEV-SNP
# (x-ms-isolation-tee.*) claims. Instead its MAA token carries vTPM measured-boot
# claims — 'secureboot' and 'x-ms-azurevm-attested-pcr-values.pcrN' — and a
# release policy can gate on those. See: /azure/key-vault/keys/policy-grammar
#
# The script creates a minimal environment:
#
#   1. Resource Group with random suffix (from --prefix)
#   2. VNet with public IP + NSG (SSH locked to deployer's IP)
#   3. Azure Key Vault Premium with two HSM-backed exportable RSA keys:
#        a. "<prefix>-protected-key"          -> release policy: secureboot == true
#        b. "<prefix>-protected-key-mismatch" -> release policy: bogus pinned PCR
#           (used to demonstrate the AccessDenied / policy-mismatch case)
#   4. User-assigned managed identity for Key Vault access (get + release)
#   5. Ubuntu 24.04 Gen2 TRUSTED LAUNCH VM (Secure Boot + vTPM). Standard SKU —
#      no confidential-computing GPU/quota dependency.
#   6. SSH session into the VM that:
#      a. Builds the canonical AzureAttestSKR tool
#         (Azure/confidential-computing-cvm-guest-attestation -> cvm-securekey-release-app),
#         which already supports Trusted Launch VMs.
#      b. SUCCESS CASE: attests via the vTPM, releases + unwraps the protected key.
#      c. NEGATIVE CASE: attempts release of the mismatch key and shows AccessDenied.
#
#   Trusted Launch release policy (SUCCESS key):
#     {
#       "version": "1.0.0",
#       "anyOf": [{
#         "authority": "https://<maa-endpoint>",
#         "allOf": [ { "claim": "secureboot", "equals": true } ]
#       }]
#     }
#
#   The 'secureboot' claim is issued by MAA only for a genuine Trusted Launch
#   (or Confidential) VM that booted with Secure Boot enabled and whose vTPM
#   quote validated. To additionally pin the exact booted image, add
#   'x-ms-azurevm-attested-pcr-values.pcr4' / 'pcr7' constraints (commonly boot
#   loader/kernel and Secure Boot state) using PCR values read from a known-good
#   attestation. The mismatch key pins a deliberately-wrong PCR to demonstrate
#   the AccessDenied path.
#
# Usage:
#   ./deploy-skr-trusted-launch.sh --prefix skrtl [--location northeurope] [--vm-size Standard_D2s_v5]
#   ./deploy-skr-trusted-launch.sh --cleanup
#
# Prerequisites:
#   - Azure CLI (az)  — logged in:  az login
#   - jq
#   - ssh / ssh-keygen / scp
#   - Azure subscription with quota for a Gen2 general-purpose SKU (e.g. Dsv5)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults + argument parsing
# ---------------------------------------------------------------------------
PREFIX=""
LOCATION="northeurope"
VM_SIZE="Standard_D2s_v5"
CLEANUP=false

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/skr-tl-config.json"

usage() {
    cat <<EOF

=== SKR Example (Trusted Launch) — Secure Key Release without Confidential Computing ===

Usage:
  ./$SCRIPT_NAME --prefix <name>   Deploy Trusted Launch VM + Key Vault + release key
  ./$SCRIPT_NAME --cleanup         Remove all resources

Options:
  --prefix   <name>   3-8 char lowercase alphanumeric prefix for resource names
  --location <region> Azure region (default: northeurope)
  --vm-size  <sku>    Any Gen2 SKU that supports Trusted Launch (default: Standard_D2s_v5)
  --cleanup           Remove all resources from a previous deployment

EOF
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Current deployment:"
        echo "  Resource Group: $(jq -r '.resourceGroup' "$CONFIG_FILE")"
        echo "  Location:       $(jq -r '.location' "$CONFIG_FILE")"
        echo ""
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)   PREFIX="${2:-}"; shift 2 ;;
        --location) LOCATION="${2:-}"; shift 2 ;;
        --vm-size)  VM_SIZE="${2:-}"; shift 2 ;;
        --cleanup)  CLEANUP=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Colors (fall back to no-op if not a TTY)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'; C_GRAY=$'\033[90m'; C_RESET=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_GRAY=""; C_RESET=""
fi
say()   { echo "${C_GREEN}$*${C_RESET}"; }
info()  { echo "${C_CYAN}$*${C_RESET}"; }
warn()  { echo "${C_YELLOW}$*${C_RESET}"; }
gray()  { echo "${C_GRAY}$*${C_RESET}"; }

# ---------------------------------------------------------------------------
# Shared MAA endpoint for a region (bash 3.2-safe: case, not associative array)
# ---------------------------------------------------------------------------
maa_endpoint_for() {
    local loc ep
    loc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$loc" in
        eastus)             ep="sharedeus.eus" ;;
        eastus2)            ep="sharedeus2.eus2" ;;
        westus)             ep="sharedwus.wus" ;;
        westus2)            ep="sharedwus2.wus2" ;;
        westus3)            ep="sharedwus3.wus3" ;;
        centralus)          ep="sharedcus.cus" ;;
        northcentralus)     ep="sharedncus.ncus" ;;
        southcentralus)     ep="sharedscus.scus" ;;
        westcentralus)      ep="sharedwcus.wcus" ;;
        canadacentral)      ep="sharedcac.cac" ;;
        canadaeast)         ep="sharedcae.cae" ;;
        northeurope)        ep="sharedneu.neu" ;;
        westeurope)         ep="sharedweu.weu" ;;
        uksouth)            ep="shareduks.uks" ;;
        ukwest)             ep="sharedukw.ukw" ;;
        francecentral)      ep="sharedfrc.frc" ;;
        germanywestcentral) ep="shareddewc.dewc" ;;
        switzerlandnorth)   ep="sharedswn.swn" ;;
        swedencentral)      ep="sharedsec.sec" ;;
        norwayeast)         ep="sharednoe.noe" ;;
        eastasia)           ep="sharedeasia.easia" ;;
        southeastasia)      ep="sharedsasia.sasia" ;;
        japaneast)          ep="sharedjpe.jpe" ;;
        australiaeast)      ep="sharedeau.eau" ;;
        koreacentral)       ep="sharedkrc.krc" ;;
        centralindia)       ep="sharedcin.cin" ;;
        uaenorth)           ep="shareduaen.uaen" ;;
        brazilsouth)        ep="sharedsbr.sbr" ;;
        *)
            echo "No shared MAA endpoint for region '$1'. Use a region with a shared MAA provider (see script)." >&2
            return 1
            ;;
    esac
    echo "${ep}.attest.azure.net"
}

# Random lowercase string of length $1 (naming suffix — not cryptographic).
# Uses $RANDOM in a loop to avoid the `tr | head` SIGPIPE that trips pipefail.
rand_lc() {
    local n="$1" i s="" chars="abcdefghijklmnopqrstuvwxyz"
    for (( i = 0; i < n; i++ )); do
        s="$s${chars:$((RANDOM % 26)):1}"
    done
    printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# CLEANUP mode
# ---------------------------------------------------------------------------
if [[ "$CLEANUP" == true ]]; then
    echo ""
    warn "=== CLEANUP ==="
    if [[ -f "$CONFIG_FILE" ]]; then
        rg="$(jq -r '.resourceGroup' "$CONFIG_FILE")"
        bn="$(jq -r '.basename' "$CONFIG_FILE")"
        warn "Removing resource group: $rg ..."
        az group delete --name "$rg" --yes --no-wait >/dev/null 2>&1 || true
        rm -f "$CONFIG_FILE"
        if [[ -d "$SCRIPT_DIR/.ssh" ]]; then
            rm -f "$SCRIPT_DIR/.ssh/$bn"* 2>/dev/null || true
            rmdir "$SCRIPT_DIR/.ssh" 2>/dev/null || true
        fi
        say "Cleanup submitted. Deletion continues in the background."
    else
        warn "No config file found. Nothing to clean up."
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# Validate + prerequisites
# ---------------------------------------------------------------------------
if [[ -z "$PREFIX" ]]; then
    usage
    exit 0
fi
if ! [[ "$PREFIX" =~ ^[a-z][a-z0-9]{2,7}$ ]]; then
    echo "ERROR: --prefix must be 3-8 chars, lowercase, starting with a letter." >&2
    exit 1
fi

echo ""
info "Checking prerequisites..."
for tool in az jq ssh ssh-keygen scp curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' not found on PATH." >&2; exit 1; }
done
ACCOUNT_JSON="$(az account show -o json 2>/dev/null)" || { echo "ERROR: Not logged in to Azure. Run: az login" >&2; exit 1; }
say "  Logged in as: $(jq -r '.user.name' <<<"$ACCOUNT_JSON")"
say "  Subscription: $(jq -r '.name' <<<"$ACCOUNT_JSON")"

# ---------------------------------------------------------------------------
# Generate names
# ---------------------------------------------------------------------------
SUFFIX="$(rand_lc 5)"
BASENAME="${PREFIX}${SUFFIX}"
RESGRP="${BASENAME}-skr-tl-rg"
VNET_NAME="${BASENAME}-vnet"
PIP_NAME="${BASENAME}-pip"
NSG_NAME="${BASENAME}-nsg"
VM_NAME="${BASENAME}-tlvm"
KV_NAME="${BASENAME}kv"
IDENTITY_NAME="${BASENAME}-id"
SSH_KEY_DIR="$SCRIPT_DIR/.ssh"
SSH_KEY_PATH="$SSH_KEY_DIR/$BASENAME"
GOOD_KEY_NAME="${BASENAME}-protected-key"
MISMATCH_KEY_NAME="${BASENAME}-protected-key-mismatch"
VM_USER="tlvm$(rand_lc 7)"
MAA_ENDPOINT="$(maa_endpoint_for "$LOCATION")"
MAA_AUTHORITY="https://${MAA_ENDPOINT}"

echo ""
info "================================================================"
info " SKR Example (Trusted Launch) — Secure Key Release, no Confidential Computing"
info "================================================================"
echo "  Basename:       $BASENAME"
echo "  Resource Group: $RESGRP"
echo "  Location:       $LOCATION"
echo "  VM:             $VM_NAME ($VM_SIZE, Trusted Launch)"
echo "  Key Vault:      $KV_NAME"
echo "  Protected Key:  $GOOD_KEY_NAME"
echo "  Mismatch Key:   $MISMATCH_KEY_NAME"
echo "  MAA Endpoint:   $MAA_ENDPOINT"
info "================================================================"
echo ""

START_TIME=$(date +%s)

# ---------------------------------------------------------------------------
# Error handler — offer to clean up on failure
# ---------------------------------------------------------------------------
on_error() {
    local rc=$?
    echo ""
    echo "${C_RED}================================================================${C_RESET}"
    echo "${C_RED} DEPLOYMENT FAILED (exit $rc)${C_RESET}"
    echo "${C_RED}================================================================${C_RESET}"
    # Remove the ephemeral SSH key pair created for this deployment.
    if [[ -d "$SSH_KEY_DIR" ]]; then
        rm -f "$SSH_KEY_DIR/$BASENAME"* 2>/dev/null || true
        rmdir "$SSH_KEY_DIR" 2>/dev/null || true
    fi
    if az group show --name "$RESGRP" >/dev/null 2>&1; then
        if [[ -t 0 ]]; then
            read -r -p "  Delete resource group '$RESGRP'? (y/N) " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
                warn "  Removing resource group (background)..."
                az group delete --name "$RESGRP" --yes --no-wait >/dev/null 2>&1 || true
            else
                warn "  Resources left in place. Clean up with: ./$SCRIPT_NAME --cleanup"
            fi
        else
            warn "  Removing resource group '$RESGRP' (background)..."
            az group delete --name "$RESGRP" --yes --no-wait >/dev/null 2>&1 || true
        fi
    fi
    exit "$rc"
}
trap on_error ERR

# ===========================================================================
# PHASE 1: RESOURCE GROUP + NETWORKING
# ===========================================================================
echo "Phase 1: Creating resource group and networking..."

OWNER="$(jq -r '.user.name' <<<"$ACCOUNT_JSON")"
az group create --name "$RESGRP" --location "$LOCATION" \
    --tags "owner=$OWNER" "BuiltBy=$SCRIPT_NAME" "demo=skr-example-trusted-launch" \
    -o none
say "  Resource group: $RESGRP"

az network vnet create --resource-group "$RESGRP" --name "$VNET_NAME" --location "$LOCATION" \
    --address-prefix "10.0.0.0/16" --subnet-name "VMSubnet" --subnet-prefix "10.0.1.0/24" \
    -o none
say "  VNet: $VNET_NAME (10.0.0.0/16)"

az network public-ip create --resource-group "$RESGRP" --name "$PIP_NAME" --location "$LOCATION" \
    --sku Standard --allocation-method Static --version IPv4 \
    -o none
PIP_ADDR="$(az network public-ip show --resource-group "$RESGRP" --name "$PIP_NAME" --query ipAddress -o tsv)"
say "  Public IP: $PIP_NAME ($PIP_ADDR)"

MY_IP="$(curl -fsS --max-time 10 https://api.ipify.org | tr -d '[:space:]')"
az network nsg create --resource-group "$RESGRP" --name "$NSG_NAME" --location "$LOCATION" -o none
az network nsg rule create --resource-group "$RESGRP" --nsg-name "$NSG_NAME" --name "AllowSSH" \
    --protocol Tcp --direction Inbound --priority 1000 \
    --source-address-prefixes "$MY_IP" --source-port-ranges '*' \
    --destination-address-prefixes '*' --destination-port-ranges 22 --access Allow \
    -o none
say "  NSG: $NSG_NAME (SSH allowed from $MY_IP only)"

mkdir -p "$SSH_KEY_DIR"
rm -f "$SSH_KEY_PATH"* 2>/dev/null || true
ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N "" -q
say "  SSH key pair generated (ephemeral, in .ssh/)"
echo ""

# ===========================================================================
# PHASE 2: KEY VAULT + IDENTITY + KEYS
# ===========================================================================
echo "Phase 2: Creating Key Vault, identity, and keys..."

IDENTITY_JSON="$(az identity create --resource-group "$RESGRP" --name "$IDENTITY_NAME" --location "$LOCATION" -o json)"
IDENTITY_ID="$(jq -r '.id' <<<"$IDENTITY_JSON")"
IDENTITY_PRINCIPAL_ID="$(jq -r '.principalId' <<<"$IDENTITY_JSON")"
IDENTITY_CLIENT_ID="$(jq -r '.clientId' <<<"$IDENTITY_JSON")"
say "  Managed identity: $IDENTITY_NAME"

# Key Vault Premium (HSM-backed keys), access-policy model. No disk-encryption
# enablement — Trusted Launch does not use confidential OS-disk encryption.
az keyvault create --resource-group "$RESGRP" --name "$KV_NAME" --location "$LOCATION" \
    --sku Premium --retention-days 10 --enable-purge-protection true \
    --enable-rbac-authorization false \
    -o none
say "  Key Vault: $KV_NAME (Premium)"

# Grant the managed identity key get/release/wrap/unwrap (retry: vault propagation).
for attempt in 1 2 3 4 5 6; do
    if az keyvault set-policy --name "$KV_NAME" --resource-group "$RESGRP" \
        --object-id "$IDENTITY_PRINCIPAL_ID" \
        --key-permissions get release wrapKey unwrapKey -o none 2>/dev/null; then
        break
    fi
    if [[ $attempt -eq 6 ]]; then
        echo "ERROR: could not set Key Vault access policy after 6 attempts." >&2
        exit 1
    fi
    warn "    Vault not ready (attempt $attempt/6), retrying in 10s..."
    sleep 10
done
say "  Access policy: $IDENTITY_NAME -> get, release, wrapKey, unwrapKey"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---- SUCCESS key: gate on secureboot == true (Trusted Launch vTPM claim) ----
info "  Creating protected key: $GOOD_KEY_NAME (release policy: secureboot == true)"
cat >"$TMP_DIR/good-policy.json" <<EOF
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "$MAA_AUTHORITY",
      "allOf": [
        { "claim": "secureboot", "equals": true }
      ]
    }
  ]
}
EOF
az keyvault key create --vault-name "$KV_NAME" --name "$GOOD_KEY_NAME" \
    --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt \
    --exportable true --policy "$TMP_DIR/good-policy.json" \
    -o none
say "  Key created: $GOOD_KEY_NAME (RSA-HSM 2048, exportable, SKR policy bound)"

# ---- MISMATCH key: pin a deliberately-wrong PCR to demonstrate AccessDenied ----
info "  Creating mismatch key: $MISMATCH_KEY_NAME (release policy pins a bogus PCR4)"
cat >"$TMP_DIR/mismatch-policy.json" <<EOF
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "$MAA_AUTHORITY",
      "allOf": [
        { "claim": "secureboot", "equals": true },
        { "claim": "x-ms-azurevm-attested-pcr-values.pcr4", "equals": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
      ]
    }
  ]
}
EOF
az keyvault key create --vault-name "$KV_NAME" --name "$MISMATCH_KEY_NAME" \
    --kty RSA-HSM --size 2048 --ops wrapKey unwrapKey encrypt decrypt \
    --exportable true --policy "$TMP_DIR/mismatch-policy.json" \
    -o none
say "  Key created: $MISMATCH_KEY_NAME (used to demonstrate the AccessDenied path)"
echo ""

# ===========================================================================
# PHASE 3: DEPLOY TRUSTED LAUNCH VM
# ===========================================================================
echo "Phase 3: Deploying Trusted Launch VM..."
info "  Creating VM: $VM_NAME (Trusted Launch — this takes 2-5 minutes)..."

az vm create --resource-group "$RESGRP" --name "$VM_NAME" --location "$LOCATION" \
    --size "$VM_SIZE" \
    --image "Canonical:ubuntu-24_04-lts:server:latest" \
    --admin-username "$VM_USER" \
    --authentication-type ssh --ssh-key-values "$SSH_KEY_PATH.pub" \
    --assign-identity "$IDENTITY_ID" \
    --vnet-name "$VNET_NAME" --subnet "VMSubnet" \
    --public-ip-address "$PIP_NAME" --nsg "$NSG_NAME" \
    --private-ip-address "10.0.1.4" \
    --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true \
    --storage-sku StandardSSD_LRS \
    --nic-delete-option Delete --os-disk-delete-option Delete \
    -o none
say "  VM created: $VM_NAME"

VM_ID="$(az vm show --resource-group "$RESGRP" --name "$VM_NAME" --query vmId -o tsv)"
gray "  VmId: $VM_ID"
echo ""

# ===========================================================================
# PHASE 4: BOOTSTRAP — BUILD AzureAttestSKR + RUN SKR (success + mismatch)
# ===========================================================================
echo "Phase 4: Running bootstrap via SSH (builds AzureAttestSKR + performs SKR)..."
gray "  SSHing into the Trusted Launch VM to build the canonical AzureAttestSKR"
gray "  tool, attest via the vTPM, and exercise the success and mismatch cases."
echo ""

KV_ENDPOINT="${KV_NAME}.vault.azure.net"

# The bootstrap runs on the VM. Placeholders are substituted below via envsubst.
# shellcheck disable=SC2016  # Single quotes are intentional: this body is expanded on the VM, not here.
BOOTSTRAP_TEMPLATE='#!/bin/bash
set -euo pipefail

echo ""
echo "================================================================"
echo " SKR Example (Trusted Launch) — Bootstrap"
echo "================================================================"
echo " Protected key:  ${GOOD_KEY}"
echo " Mismatch key:   ${MISMATCH_KEY}"
echo " Vault:          ${AKV_ENDPOINT}"
echo " MAA:            ${MAA_AUTHORITY}"
echo " Identity:       ${CLIENT_ID}"
echo " Started:        $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
echo "================================================================"
echo ""

export DEBIAN_FRONTEND=noninteractive
export IMDS_CLIENT_ID="${CLIENT_ID}"

# ---- Verify this is a Trusted Launch VM (vTPM present) ----
if [ -e "/dev/tpmrm0" ]; then
    echo "  vTPM: /dev/tpmrm0 PRESENT (Trusted Launch)"
else
    echo "  ERROR: No vTPM device found at /dev/tpmrm0 — is this a Trusted Launch VM?"
    exit 1
fi

# ---- Build the canonical AzureAttestSKR tool (supports Trusted Launch) ----
echo "[1/3] Installing build dependencies and the guest attestation package..."
apt-get update -qq
apt-get install -y -qq build-essential libssl-dev libcurl4-openssl-dev \
    libjsoncpp-dev libboost-all-dev nlohmann-json3-dev cmake git wget 2>&1 | tail -3

ATTEST_DEB="azguestattestation1_1.1.2_amd64.deb"
wget -q "https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/${ATTEST_DEB}"
dpkg -i "${ATTEST_DEB}" 2>&1 | tail -2

echo "[2/3] Building AzureAttestSKR from cvm-securekey-release-app..."
SRC_DIR="/opt/cvm-guest-attestation"
git clone --depth 1 --recursive https://github.com/Azure/confidential-computing-cvm-guest-attestation.git "$SRC_DIR" 2>&1 | tail -2
cd "$SRC_DIR/cvm-securekey-release-app"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
make 2>&1 | tail -3
SKR_BIN="$SRC_DIR/cvm-securekey-release-app/build/AzureAttestSKR"
if [ ! -x "$SKR_BIN" ]; then
    echo "  ERROR: AzureAttestSKR did not build"
    exit 1
fi
echo "  Built: $SKR_BIN"

MAA="${MAA_AUTHORITY}"
AKV="${AKV_ENDPOINT}"
SECRET="trusted-launch-skr-demo-secret"

echo ""
echo "[3/3] Exercising Secure Key Release..."
echo ""
echo "  -- SUCCESS CASE — key gated on secureboot == true --"
GOOD_KID="https://${AKV}/keys/${GOOD_KEY}"
set +e
WRAPPED=$("$SKR_BIN" -a "$MAA" -k "$GOOD_KID" -c imds -s "$SECRET" -w 2>/tmp/skr_good.err)
GOOD_RC=$?
set -e
if [ $GOOD_RC -eq 0 ] && [ -n "$WRAPPED" ]; then
    echo "  [OK] Wrap succeeded — the key was released to this attested Trusted Launch VM."
    UNWRAPPED=$("$SKR_BIN" -a "$MAA" -k "$GOOD_KID" -c imds -s "$WRAPPED" -u 2>/tmp/skr_good_u.err || true)
    if [ "$UNWRAPPED" = "$SECRET" ]; then
        echo "  [OK] Unwrap round-trip verified (recovered the original secret)."
    else
        echo "  [WARN] Unwrap returned unexpected output (see /tmp/skr_good_u.err)."
    fi
else
    echo "  [FAIL] Unexpected: release FAILED for the success key (rc=$GOOD_RC)."
    echo "     ---- stderr ----"; sed "s/^/     /" /tmp/skr_good.err | tail -20
    echo "     A genuine Trusted Launch VM with Secure Boot should satisfy this policy."
fi

echo ""
echo "  -- NEGATIVE CASE — key pins a bogus PCR4 (expected AccessDenied) --"
BAD_KID="https://${AKV}/keys/${MISMATCH_KEY}"
set +e
"$SKR_BIN" -a "$MAA" -k "$BAD_KID" -c imds -s "$SECRET" -w >/tmp/skr_bad.out 2>/tmp/skr_bad.err
BAD_RC=$?
set -e
if [ $BAD_RC -ne 0 ]; then
    echo "  [OK] Release correctly REJECTED (rc=$BAD_RC) — the pinned PCR did not match."
    grep -iE "denied|forbidden|policy|403" /tmp/skr_bad.err | sed "s/^/     /" | tail -5 || true
else
    echo "  [FAIL] Unexpected: release SUCCEEDED for the mismatch key. Review the policy."
fi

echo ""
echo "================================================================"
echo " SKR (Trusted Launch) demonstration complete"
echo " Done: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
echo "================================================================"
'

# Substitute deployment-specific values into the bootstrap.
export GOOD_KEY="$GOOD_KEY_NAME" MISMATCH_KEY="$MISMATCH_KEY_NAME" \
       AKV_ENDPOINT="$KV_ENDPOINT" MAA_AUTHORITY="$MAA_AUTHORITY" CLIENT_ID="$IDENTITY_CLIENT_ID"
BOOTSTRAP_FILE="$TMP_DIR/skr-tl-bootstrap.sh"
# Only expand our known placeholders; leave the VM-side $(...) and $VARs intact.
# shellcheck disable=SC2016  # Literal ${VAR} names are the envsubst allow-list, not host expansions.
envsubst '${GOOD_KEY} ${MISMATCH_KEY} ${AKV_ENDPOINT} ${MAA_AUTHORITY} ${CLIENT_ID}' \
    <<<"$BOOTSTRAP_TEMPLATE" >"$BOOTSTRAP_FILE"

SSH_OPTS=(-i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

gray "  Waiting for SSH on $PIP_ADDR..."
SSH_READY=false
for _ in $(seq 1 30); do
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 "$VM_USER@$PIP_ADDR" "echo ok" 2>/dev/null | grep -q ok; then
        SSH_READY=true
        break
    fi
    sleep 10
done
if [[ "$SSH_READY" != true ]]; then
    echo "ERROR: SSH not available on $PIP_ADDR after 5 minutes. Check NSG rules and VM status." >&2
    exit 1
fi
say "  SSH connected to $PIP_ADDR"

info "  Uploading bootstrap script to VM..."
scp "${SSH_OPTS[@]}" "$BOOTSTRAP_FILE" "$VM_USER@$PIP_ADDR:/tmp/skr-tl-bootstrap.sh" >/dev/null

info "  Running bootstrap on $VM_NAME via SSH (build + SKR, ~5-8 minutes)..."
echo ""
info "================================================================"
info " VM Bootstrap Output (via SSH)"
info "================================================================"
echo ""
ssh "${SSH_OPTS[@]}" "$VM_USER@$PIP_ADDR" "sudo -E bash /tmp/skr-tl-bootstrap.sh" || true
echo ""
info "================================================================"

# ===========================================================================
# SAVE CONFIG + FINAL OUTPUT
# ===========================================================================
jq -n \
    --arg rg "$RESGRP" --arg bn "$BASENAME" --arg loc "$LOCATION" \
    --arg vm "$VM_NAME" --arg vmsize "$VM_SIZE" --arg vmid "$VM_ID" --arg vmip "$PIP_ADDR" \
    --arg user "$VM_USER" --arg sshkey "$SSH_KEY_PATH" --arg kv "$KV_NAME" \
    --arg good "$GOOD_KEY_NAME" --arg mismatch "$MISMATCH_KEY_NAME" \
    --arg id "$IDENTITY_NAME" --arg cid "$IDENTITY_CLIENT_ID" --arg maa "$MAA_ENDPOINT" \
    '{resourceGroup:$rg, basename:$bn, location:$loc, vmName:$vm, vmSize:$vmsize,
      vmId:$vmid, vmIp:$vmip, sshUser:$user, sshKeyPath:$sshkey, keyVault:$kv,
      goodKeyName:$good, mismatchKeyName:$mismatch, identity:$id,
      identityClientId:$cid, maaEndpoint:$maa}' >"$CONFIG_FILE"

ELAPSED=$(( $(date +%s) - START_TIME ))
echo ""
say "================================================================"
say " DEPLOYMENT COMPLETE"
say "================================================================"
echo ""
echo "  Resource Group:  $RESGRP"
echo "  VM:              $VM_NAME ($PIP_ADDR, Trusted Launch)"
echo "  Key Vault:       $KV_NAME"
echo "  Protected Key:   $GOOD_KEY_NAME"
echo "  MAA Endpoint:    $MAA_ENDPOINT"
echo ""
info "  Secure Key Release succeeded on a Trusted Launch VM — no Confidential"
info "  Computing required. The mismatch key demonstrated the AccessDenied path."
echo ""
gray "  Deployment time: $((ELAPSED / 60)) minutes and $((ELAPSED % 60)) seconds"
say "================================================================"

# ---- Auto-cleanup ----
echo ""
warn "Cleaning up resources..."
az group delete --name "$RESGRP" --yes --no-wait >/dev/null 2>&1 || true
rm -f "$CONFIG_FILE"
if [[ -d "$SSH_KEY_DIR" ]]; then
    rm -f "$SSH_KEY_DIR/$BASENAME"* 2>/dev/null || true
    rmdir "$SSH_KEY_DIR" 2>/dev/null || true
fi
say "  Resource group '$RESGRP' deletion started (runs in background)."
say "  SSH keys removed."

# Deployment succeeded — disable the failure trap so a cleanup hiccup can't misreport.
trap - ERR
