#!/usr/bin/env python3
"""
CVM SKR Shim — Confidential VM Secure Key Release Service

Replaces the ACI SKR sidecar (/usr/local/bin/skr) for Confidential Virtual Machines.
Exposes the same localhost:8080 API surface that app.py already expects:

    GET  /           → Health/status check
    POST /attest/maa → Get MAA attestation token via vTPM
    POST /key/release → Release a key from Azure Key Vault using attestation

On a Confidential VM (AMD SEV-SNP), attestation uses the vTPM which contains
the SNP attestation report. The guest attestation client (AttestationClient)
handles the full TPM quote → MAA token flow. Key release uses AKV's REST API
with the MAA token + managed identity authentication.

This shim maintains the localhost:8080 contract so app.py requires ZERO changes
when migrating from ACI confidential containers to Confidential VMs.
"""

from flask import Flask, jsonify, request
import subprocess
import requests as http_requests  # avoid collision with flask.request
import json
import base64
import os
import logging
import time

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SKR-SHIM] %(levelname)s %(message)s'
)
log = logging.getLogger('skr_shim')

# ---------------------------------------------------------------------------
# Guest attestation client binary — installed from azguestattestation package
# ---------------------------------------------------------------------------
ATTESTATION_CLIENT_PATHS = [
    '/opt/azguestattestation/AttestationClient',
    '/usr/bin/AttestationClient',
    '/usr/local/bin/AttestationClient',
]


def find_attestation_client():
    """Find the guest attestation client binary on the filesystem."""
    for path in ATTESTATION_CLIENT_PATHS:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return None


# ---------------------------------------------------------------------------
# Managed Identity token (via IMDS — works on any Azure VM with MI assigned)
# ---------------------------------------------------------------------------
def get_managed_identity_token(resource="https://vault.azure.net", client_id=None):
    """
    Get an access token from the Azure Instance Metadata Service (IMDS).
    For user-assigned managed identity, pass client_id.
    """
    url = "http://169.254.169.254/metadata/identity/oauth2/token"
    params = {
        "api-version": "2018-02-01",
        "resource": resource
    }
    if client_id:
        params["client_id"] = client_id

    headers = {"Metadata": "true"}

    for attempt in range(3):
        try:
            resp = http_requests.get(url, params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            token = resp.json().get("access_token")
            if not token:
                raise RuntimeError("IMDS returned empty access_token")
            return token
        except Exception as e:
            if attempt < 2:
                log.warning(f"IMDS token attempt {attempt + 1} failed: {e}, retrying in 2s...")
                time.sleep(2)
            else:
                raise RuntimeError(f"Failed to get managed identity token after 3 attempts: {e}")


# ---------------------------------------------------------------------------
# MAA attestation token (via guest attestation client + vTPM)
# ---------------------------------------------------------------------------
def get_maa_token(maa_endpoint, nonce=None):
    """
    Get an MAA attestation JWT using the CVM guest attestation client.

    The client:
      1. Reads the vTPM quote (which embeds the AMD SEV-SNP report)
      2. Sends the evidence to the specified MAA endpoint
      3. Returns the signed JWT from MAA

    This is the CVM equivalent of the ACI SKR sidecar's /attest/maa endpoint.
    """
    client_path = find_attestation_client()
    if not client_path:
        raise RuntimeError(
            "Guest attestation client not found. "
            "Install the azguestattestation package: "
            "sudo apt-get install azguestattestation. "
            f"Searched paths: {', '.join(ATTESTATION_CLIENT_PATHS)}"
        )

    if not nonce:
        nonce = base64.b64encode(os.urandom(32)).decode()

    # Strip protocol prefix from endpoint
    maa_clean = maa_endpoint.replace('https://', '').replace('http://', '')

    cmd = [client_path, "-a", maa_clean, "-n", nonce, "-o", "token"]
    log.info(f"Attestation: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            token = result.stdout.strip()
            if token:
                log.info(f"MAA token obtained ({len(token)} chars)")
                return token
            else:
                raise RuntimeError(
                    f"AttestationClient returned empty output. stderr: {result.stderr}"
                )
        else:
            raise RuntimeError(
                f"AttestationClient exit code {result.returncode}: {result.stderr.strip()}"
            )
    except subprocess.TimeoutExpired:
        raise RuntimeError("AttestationClient timed out after 60 seconds")


# ---------------------------------------------------------------------------
# JWS (JSON Web Signature) decoding — for AKV key release response
# ---------------------------------------------------------------------------
def decode_jws_payload(jws_token):
    """
    Decode the payload from a JWS token (header.payload.signature).
    AKV key release returns the key wrapped in a JWS.
    """
    parts = jws_token.split('.')
    if len(parts) != 3:
        raise ValueError(f"Invalid JWS format: expected 3 parts, got {len(parts)}")

    payload_b64 = parts[1]
    # Add base64url padding
    padding_needed = 4 - len(payload_b64) % 4
    if padding_needed != 4:
        payload_b64 += '=' * padding_needed

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


def extract_key_from_release(release_payload):
    """
    Navigate the AKV key release JWS payload to extract the raw JWK.

    The payload structure from AKV is typically:
        { "response": { "key": { "key": { <JWK> } } } }

    We progressively unwrap to get the JWK with kty, n, e, d, p, q, etc.
    """
    data = release_payload

    if isinstance(data, dict):
        if 'response' in data:
            data = data['response']
        if 'key' in data and isinstance(data['key'], dict):
            data = data['key']
            if 'key' in data and isinstance(data['key'], dict):
                data = data['key']

    return data


# ============================================================================
# API ENDPOINTS — matching the ACI SKR sidecar contract
# ============================================================================

@app.route('/', methods=['GET'])
def status():
    """
    Health check endpoint.
    app.py polls GET http://localhost:8080/ to know the sidecar is ready.
    """
    sev_available = os.path.exists('/dev/sev-guest') or os.path.exists('/dev/sev')
    tpm_available = os.path.exists('/dev/tpmrm0') or os.path.exists('/dev/tpm0')
    client_path = find_attestation_client()

    return jsonify({
        'status': 'running',
        'type': 'cvm-skr-shim',
        'version': '1.0.0',
        'platform': 'confidential-vm',
        'sev_snp_available': sev_available,
        'vtpm_available': tpm_available,
        'attestation_client': client_path or 'not found',
        'message': 'CVM SKR Shim ready — AMD SEV-SNP attestation via vTPM'
    })


@app.route('/status', methods=['GET'])
def status_alt():
    """Alternative status path (some callers use /status instead of /)."""
    return status()


@app.route('/attest/maa', methods=['POST'])
def attest_maa():
    """
    Get MAA attestation token — same interface as ACI SKR sidecar.

    Accepts JSON: { "maa_endpoint": "<MAA host>", "runtime_data": "<base64 nonce>" }
    Returns JSON: { "token": "<MAA JWT>" }
    """
    data = request.get_json(silent=True) or {}
    maa_endpoint = data.get('maa_endpoint', os.environ.get('SKR_MAA_ENDPOINT', ''))
    runtime_data = data.get('runtime_data', '')

    if not maa_endpoint:
        return jsonify({'error': 'maa_endpoint is required'}), 400

    try:
        token = get_maa_token(maa_endpoint, nonce=runtime_data if runtime_data else None)
        return jsonify({'token': token})
    except Exception as e:
        log.error(f"Attestation failed: {e}")
        return jsonify({
            'error': str(e),
            'maa_endpoint': maa_endpoint,
            'platform': 'confidential-vm',
            'sev_device': os.path.exists('/dev/sev-guest'),
            'tpm_device': os.path.exists('/dev/tpmrm0')
        }), 500


@app.route('/key/release', methods=['POST'])
def key_release():
    """
    Release a key from Azure Key Vault — same interface as ACI SKR sidecar.

    Accepts JSON: {
        "maa_endpoint": "<MAA host>",
        "akv_endpoint": "<vault>.vault.azure.net",
        "kid": "<key-name>"
    }
    Returns JSON: { "key": { <JWK with private components d,p,q,dp,dq,qi> } }

    Flow:
      1. Get MAA attestation token via vTPM → guest attestation client
      2. Get managed identity token for AKV access via IMDS
      3. Call AKV key release API with MAA token
      4. Decode JWS response → extract JWK → return to caller
    """
    data = request.get_json(silent=True) or {}
    maa_endpoint = data.get('maa_endpoint', os.environ.get('SKR_MAA_ENDPOINT', ''))
    akv_endpoint = data.get('akv_endpoint', os.environ.get('SKR_AKV_ENDPOINT', ''))
    kid = data.get('kid', os.environ.get('SKR_KEY_NAME', ''))

    if not maa_endpoint:
        return jsonify({'error': 'maa_endpoint is required'}), 400
    if not akv_endpoint:
        return jsonify({'error': 'akv_endpoint is required'}), 400
    if not kid:
        return jsonify({'error': 'kid (key name) is required'}), 400

    try:
        log.info(f"Key release request: maa={maa_endpoint}, akv={akv_endpoint}, kid={kid}")

        # ---- Step 1: MAA attestation token via vTPM ----
        log.info("  Step 1/4: Getting MAA attestation token from vTPM...")
        maa_token = get_maa_token(maa_endpoint)
        log.info("  Step 1/4: MAA token obtained")

        # ---- Step 2: Managed identity token for AKV ----
        log.info("  Step 2/4: Getting managed identity token for AKV...")
        client_id = os.environ.get('MANAGED_IDENTITY_CLIENT_ID', None)
        akv_token = get_managed_identity_token(
            resource="https://vault.azure.net",
            client_id=client_id if client_id else None
        )
        log.info("  Step 2/4: AKV access token obtained")

        # ---- Step 3: AKV key release API ----
        log.info("  Step 3/4: Calling AKV key release...")

        # Clean up the AKV endpoint
        akv_host = akv_endpoint.replace('https://', '').replace('http://', '').rstrip('/')

        # Build the key release URL
        # kid can be: just a key name, "name/version", or full URL
        if kid.startswith('https://'):
            key_url = f"{kid}/release"
        else:
            key_url = f"https://{akv_host}/keys/{kid}/release"

        resp = http_requests.post(
            f"{key_url}?api-version=7.4",
            headers={
                "Authorization": f"Bearer {akv_token}",
                "Content-Type": "application/json"
            },
            json={"target": maa_token},
            timeout=60
        )

        if resp.status_code != 200:
            error_text = resp.text[:1000]
            log.error(f"AKV key release failed: HTTP {resp.status_code} - {error_text}")
            return jsonify({
                'error': f'Key release failed with status {resp.status_code}',
                'detail': error_text,
                'key_url': key_url
            }), resp.status_code

        # ---- Step 4: Parse JWS → extract JWK ----
        log.info("  Step 4/4: Parsing released key from JWS...")
        release_response = resp.json()
        jws_value = release_response.get('value', '')

        if not jws_value:
            return jsonify({
                'error': 'AKV returned empty value in key release response'
            }), 500

        # Decode the JWS payload to get the key material
        key_payload = decode_jws_payload(jws_value)
        key_data = extract_key_from_release(key_payload)

        log.info(
            f"Key released successfully: {kid} "
            f"(type={key_data.get('kty', '?')}, ops={key_data.get('key_ops', [])})"
        )

        # Return in the exact format the ACI SKR sidecar uses:
        #   { "key": { <JWK> } }
        # app.py does: result.get('key', response.text)
        return jsonify({'key': key_data})

    except Exception as e:
        log.error(f"Key release error: {e}")
        return jsonify({
            'error': str(e),
            'maa_endpoint': maa_endpoint,
            'akv_endpoint': akv_endpoint,
            'kid': kid
        }), 500


# ============================================================================
# Main
# ============================================================================
if __name__ == '__main__':
    port = int(os.environ.get('SKR_SHIM_PORT', 8080))

    log.info("=" * 60)
    log.info("CVM SKR Shim starting")
    log.info("=" * 60)
    log.info(f"  Port:               {port}")
    log.info(f"  Attestation client: {find_attestation_client() or 'NOT FOUND'}")
    log.info(f"  /dev/sev-guest:     {os.path.exists('/dev/sev-guest')}")
    log.info(f"  /dev/tpmrm0:        {os.path.exists('/dev/tpmrm0')}")
    log.info(f"  MAA endpoint:       {os.environ.get('SKR_MAA_ENDPOINT', '(not set)')}")
    log.info(f"  AKV endpoint:       {os.environ.get('SKR_AKV_ENDPOINT', '(not set)')}")
    log.info(f"  Key name:           {os.environ.get('SKR_KEY_NAME', '(not set)')}")
    log.info(f"  Identity client ID: {os.environ.get('MANAGED_IDENTITY_CLIENT_ID', '(not set)')}")
    log.info("=" * 60)

    app.run(host='0.0.0.0', port=port)
