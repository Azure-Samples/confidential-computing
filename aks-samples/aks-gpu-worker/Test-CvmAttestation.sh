#!/usr/bin/env bash
set -euo pipefail
trap 'echo "ERROR: CVM attestation failed at line $LINENO; no success is claimed." >&2' ERR

test -r /sys/kernel/security/tpm0/binary_bios_measurements
test "$(wc -c < /sys/kernel/security/tpm0/binary_bios_measurements)" -gt 0
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends curl ca-certificates
mkdir -p /tmp/signed-attestation
cd /tmp/signed-attestation
curl -fsSL --retry 3 -o azure-guest-attest \
    https://github.com/Azure/azure-guest-attestation-sdk/releases/download/azure-guest-attest-v0.1.0/azure-guest-attest-x86_64-unknown-linux-musl
echo 'c6559e35d588b1dc9074c443beadce395da34b5beba2eb6e276195a694064b43  azure-guest-attest' |
    sha256sum -c -
chmod 755 azure-guest-attest
result=/tmp/signed-attestation/cpu-result.log
if ! timeout 180 ./azure-guest-attest guest-attest --provider maa --decode > "$result" 2>&1; then
    echo "ERROR: MAA request failed; inspect $result inside the probe." >&2
    exit 1
fi
grep -E '"x-ms-attestation-type"[[:space:]]*:[[:space:]]*"sevsnpvm"' "$result"
grep -E '"x-ms-compliance-status"[[:space:]]*:[[:space:]]*"azure-compliant-cvm"' "$result"
echo CVM_ATTESTATION_VALIDATED=1
exit 0
