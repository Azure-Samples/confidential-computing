#!/usr/bin/env bash
set -euo pipefail
trap 'echo "ERROR: GPU attestation failed at line $LINENO; no success is claimed." >&2' ERR

export LD_LIBRARY_PATH=/tmp/signed-driver/root/usr/lib/x86_64-linux-gnu
smi=/tmp/signed-driver/root/usr/bin/nvidia-smi
uuid=$("$smi" --query-gpu=uuid --format=csv,noheader)
[[ "$uuid" =~ ^GPU-[[:xdigit:]-]+$ ]]
"$smi" conf-compute -f | grep -Fx 'CC status: ON'
"$smi" conf-compute -e | grep -Fx 'CC Environment: PRODUCTION'
kill -0 "$(cat /var/run/nvidia-persistenced/nvidia-persistenced.pid)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends curl ca-certificates python3 python3-venv
mkdir -p /tmp/signed-attestation
cd /tmp/signed-attestation
curl -fsSL --retry 3 -o onboarding.tar.gz \
    https://github.com/Azure/az-cgpu-onboarding/releases/download/V4.5.1/cgpu-onboarding-package.tar.gz
echo '075ee785f6d65799d99ae18102fb88bdab4afe31540bf16673a27545c0ba80e8  onboarding.tar.gz' | sha256sum -c -
tar -xzf onboarding.tar.gz
mkdir -p verifier
tar -xf cgpu-onboarding-package/local_gpu_verifier.tar -C verifier
cd verifier
python3 -m venv /tmp/signed-attestation/venv
/tmp/signed-attestation/venv/bin/python -m pip install . > /tmp/signed-attestation/pip-install.log 2>&1 || {
    cat /tmp/signed-attestation/pip-install.log >&2
    exit 1
}
/tmp/signed-attestation/venv/bin/python -m pip show nv-local-gpu-verifier |
    grep -Fx 'Version: 2.3.0'
result=/tmp/signed-attestation/gpu-result.log
status=0
timeout 300 /tmp/signed-attestation/venv/bin/python -m verifier.cc_admin \
    --ocsp_attestation_settings strict > "$result" 2>&1 || status=$?
# Retain the full local evidence without echoing attestation tokens.
sed '/Entity Attestation Token:/,$d' "$result"
test "$status" -eq 0
grep -Fx 'GPU Attestation is Successful.' "$result"
grep -F "GPU 0 with UUID $uuid verified successfully." "$result"
echo GPU_ATTESTATION_VALIDATED=1
exit 0
