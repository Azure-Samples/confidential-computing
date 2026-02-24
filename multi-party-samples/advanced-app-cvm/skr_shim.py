#!/usr/bin/env python3
"""
CVM SKR Shim — Confidential VM Secure Key Release Service

Replaces the ACI SKR sidecar (/usr/local/bin/skr) for Confidential Virtual Machines.
Exposes the same localhost:8080 API surface that app.py already expects:

    GET  /           → Health/status check
    POST /attest/maa → Get MAA attestation token via vTPM
    POST /key/release → Release a key from Azure Key Vault using attestation

On a Confidential VM (AMD SEV-SNP), attestation uses the vTPM which contains
the SNP attestation report. The cvm-attestation-tools library
(https://github.com/Azure/cvm-attestation-tools) reads the HCL report from
the vTPM NV index, extracts the SNP report + runtime data, retrieves the
VCEK certificate from IMDS, and submits platform evidence to MAA.

This shim maintains the localhost:8080 contract so app.py requires ZERO changes
when migrating from ACI confidential containers to Confidential VMs.
"""

import sys
import os

# ---------------------------------------------------------------------------
# cvm-attestation-tools path setup — MUST happen before other imports
# The library uses a generic 'src' module name, so we insert its base path
# at position 0 to ensure it takes priority.
# See: https://github.com/Azure/cvm-attestation-tools
# ---------------------------------------------------------------------------
CVM_ATTEST_BASE = '/opt/cvm-attestation-tools/cvm-attestation'
if os.path.isdir(CVM_ATTEST_BASE) and CVM_ATTEST_BASE not in sys.path:
    sys.path.insert(0, CVM_ATTEST_BASE)

from flask import Flask, jsonify, request
import requests as http_requests  # avoid collision with flask.request
import json
import base64
import logging
import time
import struct

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SKR-SHIM] %(levelname)s %(message)s'
)
log = logging.getLogger('skr_shim')

# ---------------------------------------------------------------------------
# cvm-attestation-tools import — Python-native vTPM attestation via TSS_MSR
# Replaces the deprecated azguestattestation binary (unavailable on Ubuntu 24.04)
# ---------------------------------------------------------------------------
_CVM_ATTEST_AVAILABLE = False
_CVM_IMPORT_ERROR = None
try:
    from src.attestation_client import (
        AttestationClient as CvmAttestClient,
        AttestationClientParameters,
        Verifier,
    )
    from src.isolation import IsolationType
    from src.logger import Logger as CvmLogger
    _CVM_ATTEST_AVAILABLE = True
    log.info("cvm-attestation-tools loaded successfully")
except ImportError as e:
    _CVM_IMPORT_ERROR = str(e)
    log.warning(f"cvm-attestation-tools not available: {e}")

# Lower-level TPM wrapper for key_hsm unwrapping.
# tpm_wrapper.py does 'from external.TSS_MSR.src.Tpm import *' which brings
# all TSS.MSR types (Tpm, TPMA_OBJECT, NullPwSession, Session, Owner, etc.)
# into its module namespace.  We import the module so we can reference them
# as _tw.Symbol without fighting TSS.MSR's relative-import structure.
_TPM_UNWRAP_AVAILABLE = False
_tw = None
try:
    from src.tpm_wrapper import TssWrapper
    from src.os_info import OsInfo
    import src.tpm_wrapper as _tw
    _TPM_UNWRAP_AVAILABLE = True
    log.info("TPM unwrap modules loaded successfully")
except ImportError as e:
    log.warning(f"TPM unwrap modules not available: {e}")


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
# MAA attestation token (via cvm-attestation-tools + vTPM)
# ---------------------------------------------------------------------------
def get_maa_token(maa_endpoint, nonce=None):
    """
    Get an MAA attestation JWT using cvm-attestation-tools via the vTPM.

    The flow (all in Python, no binary dependency):
      1. TSS_MSR reads the HCL report from vTPM NV index 0x01400001
      2. OS info, AIK cert, PCR quotes, TCG logs, and isolation evidence are collected
      3. Guest attestation evidence is POSTed to the MAA AzureGuest endpoint
      4. MAA returns an encrypted response; client decrypts via TPM ephemeral key
      5. The decrypted JWT includes x-ms-isolation-tee claims (compliance-status,
         attestation-type) used by AKV release policies, plus vm-configuration.vmUniqueId
         (informational — not usable in release policies, per-VM scoping uses KV access policies)

    Guest attestation (not platform) is required because AKV key release policies
    check claims under x-ms-isolation-tee.*, which only guest attestation provides.
    """
    if not _CVM_ATTEST_AVAILABLE:
        raise RuntimeError(
            "cvm-attestation-tools not available. "
            f"Import error: {_CVM_IMPORT_ERROR}. "
            "Ensure /opt/cvm-attestation-tools is installed with TSS_MSR. "
            "See: https://github.com/Azure/cvm-attestation-tools"
        )

    # Clean the MAA endpoint to just the hostname
    maa_clean = maa_endpoint.replace('https://', '').replace('http://', '').rstrip('/')

    # Use the AzureGuest endpoint — guest attestation produces tokens with
    # x-ms-isolation-tee.x-ms-compliance-status and x-ms-attestation-type claims
    # that AKV key release policies require.
    # Note: vmUniqueId is at x-ms-runtime.vm-configuration.vmUniqueId but AKV
    # does not support x-ms-runtime.* claims in release policies.
    attest_url = f"https://{maa_clean}/attest/AzureGuest?api-version=2020-10-01"

    # Build user claims if nonce was provided
    claims = None
    if nonce:
        claims = {"user-claims": {"nonce": nonce}}

    log.info(f"Attestation: provider=MAA, isolation=SEV_SNP, type=Guest, url={attest_url}")

    try:
        logger = CvmLogger("skr-attest").get_logger()

        # Build proper AttestationClientParameters
        params = AttestationClientParameters(
            endpoint=attest_url,
            verifier=Verifier.MAA,
            isolation_type=IsolationType.SEV_SNP,
            claims=claims,
        )
        client = CvmAttestClient(logger, params)

        # attest_guest() collects OS info + TPM PCR quotes + TCG logs +
        # isolation evidence (SNP report + VCEK cert), sends to MAA, and
        # decrypts the response using a TPM ephemeral key.
        # Returns bytes (the decrypted JWT).
        result = client.attest_guest()

        if not result:
            raise RuntimeError("AttestationClient.attest_guest() returned empty token")

        # attest_guest() returns bytes — decode to string and strip whitespace
        token = result.decode('utf-8').strip() if isinstance(result, bytes) else str(result).strip()

        log.info(f"MAA token obtained ({len(token)} chars)")

        # Decode JWT payload to inspect claims (diagnostic logging)
        token_claims = decode_jwt_payload(token)
        if token_claims:
            iss = token_claims.get('iss', '(missing)')
            log.info(f"  Token issuer (iss): {iss}")
            iso_tee = token_claims.get('x-ms-isolation-tee')
            if iso_tee and isinstance(iso_tee, dict):
                att_type = iso_tee.get('x-ms-attestation-type', '(missing)')
                comp_status = iso_tee.get('x-ms-compliance-status', '(missing)')
                log.info(f"  x-ms-isolation-tee.x-ms-attestation-type: {att_type}")
                log.info(f"  x-ms-isolation-tee.x-ms-compliance-status: {comp_status}")
            else:
                log.warning("  WARNING: x-ms-isolation-tee claim MISSING from token")
                # Check if platform-level claims exist instead (would indicate
                # platform attestation was done instead of guest attestation)
                if 'x-ms-attestation-type' in token_claims:
                    log.warning(f"  Found top-level x-ms-attestation-type: "
                                f"{token_claims['x-ms-attestation-type']}")
                    log.warning("  This suggests PLATFORM attestation — "
                                "AKV default CVM policy requires GUEST attestation")

            # Log runtime keys (needed for AKV to wrap the released key)
            # and vm-configuration.vmUniqueId (informational — AKV does not
            # support x-ms-runtime.* claims in release policies)
            runtime = token_claims.get('x-ms-runtime', {})
            if isinstance(runtime, dict):
                keys = runtime.get('keys', [])
                log.info(f"  x-ms-runtime.keys: {len(keys)} key(s) present")
                for i, k in enumerate(keys):
                    log.info(f"    key[{i}]: kty={k.get('kty')}, "
                             f"key_ops={k.get('key_ops')}, "
                             f"kid={k.get('kid', 'n/a')}")
                # Log vmUniqueId (informational — AKV does not support
                # x-ms-runtime.* claims in release policies)
                vm_config = runtime.get('vm-configuration', {})
                if isinstance(vm_config, dict):
                    vm_unique_id = vm_config.get('vmUniqueId', '(missing)')
                    log.info(f"  x-ms-runtime.vm-configuration.vmUniqueId: {vm_unique_id}")
                else:
                    log.warning("  WARNING: x-ms-runtime.vm-configuration missing")
            else:
                log.warning("  WARNING: x-ms-runtime claim missing or not an object")

        return token

    except Exception as e:
        log.error(f"Attestation failed: {e}")
        # Provide diagnostic info
        tpm_present = os.path.exists('/dev/tpmrm0')
        log.error(f"  vTPM (/dev/tpmrm0): {'PRESENT' if tpm_present else 'MISSING'}")
        log.error(f"  CVM attest base: {CVM_ATTEST_BASE}")
        log.error(f"  TSS_MSR dir exists: {os.path.isdir(os.path.join(CVM_ATTEST_BASE, 'TSS_MSR'))}")
        raise


# ---------------------------------------------------------------------------
# JWT / JWS decoding helpers
# ---------------------------------------------------------------------------
def decode_jwt_payload(token):
    """
    Decode the payload from a JWT token (header.payload.signature) without
    verifying the signature. Used for diagnostic logging of MAA token claims.
    Returns the decoded payload dict or None on failure.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            log.warning(f"JWT decode: expected 3 parts, got {len(parts)}")
            return None
        payload_b64 = parts[1]
        # Add base64url padding
        padding_needed = 4 - len(payload_b64) % 4
        if padding_needed != 4:
            payload_b64 += '=' * padding_needed
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception as e:
        log.warning(f"JWT payload decode failed: {e}")
        return None


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


# ---------------------------------------------------------------------------
# key_hsm JWE Unwrapping — extract private RSA components from TPM-encrypted blob
# ---------------------------------------------------------------------------

# PCR list matching what cvm-attestation-tools uses for the ephemeral key
_LINUX_PCR_LIST = [0, 1, 2, 3, 4, 5, 6, 7]

# Serialize TPM access — the vTPM has limited session slots, and concurrent
# requests (gunicorn threads) can exhaust them.
import threading
_tpm_lock = threading.Lock()


def _tpm_create_primary_and_decrypt(rsa_encrypted_aes_key, use_oaep=True):
    """
    Create the same deterministic TPM primary key that was used during
    MAA attestation and RSA-decrypt the AES key from key_hsm.

    Mirrors get_ephemeral_key() (trial session → CreatePrimary) and
    decrypt_with_ephemeral_key() (policy session → RSA_Decrypt) from
    tpm_wrapper.py but **skips the Certify step** which requires the
    AIK at 0x81000003 and fails outside attestation context.

    The key is deterministic because:
      same Owner hierarchy seed + same template + empty unique = same RSA key

    Returns:
        bytes: The decrypted AES key, or raises on failure
    """
    if not _TPM_UNWRAP_AVAILABLE or _tw is None:
        raise RuntimeError("TPM unwrap modules not available")

    with _tpm_lock:
        os_info = OsInfo()
        tss = TssWrapper(log)
        pcr_list = os_info.pcr_list
        pcr_select = tss.get_pcr_select(pcr_list)
        pcrs = tss.get_pcr_values(pcr_list)        # reads PCRs (own TPM session)

        # Main TPM connection for CreatePrimary + RSA_Decrypt
        tpm = _tw.Tpm()
        tpm.connect()

        try:
            # 1. Trial session → compute PCR policy digest
            #    (identical to get_ephemeral_key lines 249-263)
            nonce = _tw.crypto.randomBytes(20)
            trial_resp = tpm.StartAuthSession(
                None, None, nonce, None,
                _tw.TPM_SE.TRIAL, _tw.NullSymDef, _tw.TPM_ALG_ID.SHA256,
            )
            trial_handle = trial_resp.handle
            log.info(f"key_hsm: trial session handle={trial_handle.handle}")

            pcr_digest = tss.sha256_hash_update(pcrs)       # hex string
            tpm.PolicyPCR(trial_handle, bytes.fromhex(pcr_digest), pcr_select)
            policy_digest = tpm.PolicyGetDigest(trial_handle)
            log.info("key_hsm: trial policy digest computed")

            # 2. CreatePrimary with the EXACT same template as get_ephemeral_key()
            attributes = (
                _tw.TPMA_OBJECT.decrypt
                | _tw.TPMA_OBJECT.fixedTPM
                | _tw.TPMA_OBJECT.fixedParent
                | _tw.TPMA_OBJECT.sensitiveDataOrigin
                | _tw.TPMA_OBJECT.noDA
            )
            parameters = _tw.TPMS_RSA_PARMS(
                _tw.TPMT_SYM_DEF_OBJECT(),        # symmetric = NULL
                _tw.TPMS_NULL_ASYM_SCHEME(),       # scheme = NULL
                2048,                               # keyBits
                0,                                  # exponent (default 65537)
            )
            in_public = _tw.TPMT_PUBLIC(
                _tw.TPM_ALG_ID.SHA256,
                attributes,
                policy_digest,                      # from trial session
                parameters,
                _tw.TPM2B_PUBLIC_KEY_RSA(),         # unique = empty → deterministic
            )

            id_key = tpm.withSession(_tw.NullPwSession).CreatePrimary(
                _tw.Owner, _tw.TPMS_SENSITIVE_CREATE(),
                in_public, None, pcr_select,
            )
            key_handle = id_key.getHandle()
            if not key_handle:
                raise RuntimeError("CreatePrimary returned null handle")
            log.info(f"key_hsm: CreatePrimary OK (handle={key_handle})")

            # 3. Real policy session → RSA_Decrypt
            #    (identical to decrypt_with_ephemeral_key lines 283-303)
            nonce2 = _tw.crypto.randomBytes(20)
            policy_resp = tpm.StartAuthSession(
                None, None, nonce2, None,
                _tw.TPM_SE.POLICY, _tw.NullSymDef, _tw.TPM_ALG_ID.SHA256,
            )
            policy_handle = policy_resp.handle
            policy_sess = _tw.Session(policy_handle, policy_resp.nonceTPM)

            # satisfy the PCR policy
            tpm.PolicyPCR(policy_handle, bytes.fromhex(pcr_digest), pcr_select)

            # RSA decrypt
            if use_oaep:
                scheme = _tw.TPMS_SCHEME_OAEP(_tw.TPM_ALG_ID.SHA1)
            else:
                scheme = _tw.TPMS_SCHEME_RSAES()

            decrypted = tpm.withSession(policy_sess).RSA_Decrypt(
                key_handle, rsa_encrypted_aes_key, scheme, None,
            )
            sname = "OAEP-SHA1" if use_oaep else "RSAES"
            log.info(f"key_hsm: RSA-{sname} decrypt via TPM succeeded")
            return bytes(decrypted)

        finally:
            try:
                tss.cleanSlots(tpm, _tw.TPM_HT.TRANSIENT)
                tss.cleanSlots(tpm, _tw.TPM_HT.LOADED_SESSION)
            except Exception:
                pass
            try:
                tpm.close()
            except Exception:
                pass


def _int_to_b64url(n, length=None):
    """Convert a Python int to a base64url-encoded string (JWK format)."""
    byte_len = length or (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(
        n.to_bytes(byte_len, byteorder='big')
    ).rstrip(b'=').decode('ascii')


def _parse_der_private_key(der_bytes):
    """
    Parse DER-encoded RSA private key material into a JWK dict.

    AKV wraps the private key in DER (PKCS#8 or RSAPrivateKey) format,
    not JSON.  Uses the ``cryptography`` library to load the key and
    extract the private numbers.

    Returns:
        dict: JWK with kty, n, e, d, p, q, dp, dq, qi — or None on failure
    """
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key,
        load_der_public_key,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers

    try:
        # Try PKCS#8 first, then raw RSAPrivateKey
        private_key = None
        for loader in [load_der_private_key]:
            try:
                private_key = loader(der_bytes, password=None)
                break
            except Exception:
                continue

        if private_key is None:
            log.error("key_hsm DER: could not load as private key")
            return None

        pn = private_key.private_numbers()
        pub = pn.public_numbers
        key_size_bytes = (pub.n.bit_length() + 7) // 8

        jwk = {
            'kty': 'RSA',
            'n':  _int_to_b64url(pub.n, key_size_bytes),
            'e':  _int_to_b64url(pub.e),
            'd':  _int_to_b64url(pn.d, key_size_bytes),
            'p':  _int_to_b64url(pn.p),
            'q':  _int_to_b64url(pn.q),
            'dp': _int_to_b64url(pn.dmp1),
            'dq': _int_to_b64url(pn.dmq1),
            'qi': _int_to_b64url(pn.iqmp),
        }
        log.info(f"key_hsm DER: parsed RSA-{pub.n.bit_length()} key, "
                 f"n={len(jwk['n'])}chars, d={len(jwk['d'])}chars")
        return jwk

    except Exception as e:
        log.error(f"key_hsm DER parse failed: {e}", exc_info=True)
        return None


def unwrap_key_hsm(key_hsm_value):
    """
    Unwrap the key_hsm JWE field from an AKV key release response.

    key_hsm contains the RSA private key material encrypted with the TPM
    ephemeral key using CKM_RSA_AES_KEY_WRAP:
      1. A random AES-256 key is RSA-encrypted with the TPM ephemeral RSA public key
      2. The actual RSA private key material is AES Key Wrapped with that AES key
      3. ciphertext = RSA_encrypted_AES_key || AES_wrapped_key_material

    Since TPM primary keys are deterministic (same hierarchy seed + template +
    PCR policy → same key), we recreate the same ephemeral key that was used
    during MAA attestation by calling CreatePrimary() with the identical template.

    Returns:
        dict: JWK with private components (d, p, q, dp, dq, qi) or None on failure
    """
    if not _TPM_UNWRAP_AVAILABLE or _tw is None:
        log.warning("TPM unwrap modules not available — cannot unwrap key_hsm")
        return None

    try:
        # ---- Parse key_hsm ----
        if isinstance(key_hsm_value, str):
            padded = key_hsm_value + '=' * (4 - len(key_hsm_value) % 4)
            hsm_bytes = base64.urlsafe_b64decode(padded)
            hsm_json = json.loads(hsm_bytes)
        elif isinstance(key_hsm_value, dict):
            hsm_json = key_hsm_value
        else:
            log.error(f"key_hsm: unexpected type {type(key_hsm_value)}")
            return None

        header = hsm_json.get('header', {})
        enc = header.get('enc', '')
        ct_b64 = hsm_json.get('ciphertext', '')

        if enc != 'CKM_RSA_AES_KEY_WRAP':
            log.error(f"key_hsm: unsupported enc={enc}")
            return None

        # Decode ciphertext
        try:
            ciphertext = base64.urlsafe_b64decode(ct_b64 + '=' * (4 - len(ct_b64) % 4))
        except Exception:
            ciphertext = base64.b64decode(ct_b64 + '=' * (4 - len(ct_b64) % 4))

        RSA_SIZE = 256  # RSA-2048
        if len(ciphertext) <= RSA_SIZE:
            log.error(f"key_hsm: ciphertext too short ({len(ciphertext)} bytes)")
            return None

        rsa_encrypted_aes_key = ciphertext[:RSA_SIZE]
        aes_wrapped_material = ciphertext[RSA_SIZE:]
        log.info(f"key_hsm: ciphertext total={len(ciphertext)}, "
                 f"RSA part={RSA_SIZE}, AES wrapped={len(aes_wrapped_material)} bytes")

        # ---- RSA decrypt the AES key via TPM ----
        # Try OAEP-SHA1 first (CKM_RSA_AES_KEY_WRAP standard), then RSAES fallback
        aes_key = None
        for use_oaep in [True, False]:
            scheme_name = "OAEP-SHA1" if use_oaep else "RSAES"
            try:
                log.info(f"key_hsm: Trying RSA-{scheme_name} decrypt...")
                aes_key = _tpm_create_primary_and_decrypt(
                    rsa_encrypted_aes_key, use_oaep=use_oaep
                )
                log.info(f"key_hsm: RSA-{scheme_name} succeeded, AES key={len(aes_key)} bytes")
                break
            except Exception as e:
                log.warning(f"key_hsm: RSA-{scheme_name} failed: {e}")
                if not use_oaep:
                    raise  # both OAEP and RSAES failed

        if not aes_key:
            log.error("key_hsm: All RSA decrypt attempts failed")
            return None

        # ---- AES Key Unwrap ----
        from cryptography.hazmat.primitives.keywrap import (
            aes_key_unwrap_with_padding,
            aes_key_unwrap,
        )
        try:
            unwrapped = aes_key_unwrap_with_padding(aes_key, aes_wrapped_material)
        except Exception:
            unwrapped = aes_key_unwrap(aes_key, aes_wrapped_material)

        log.info(f"key_hsm: AES unwrap OK, material={len(unwrapped)} bytes")

        # ---- Parse unwrapped key material ----
        # AKV may encode the private key as JSON (JWK) or as DER (ASN.1).
        # Try JSON first; fall back to DER.
        key_material = None
        try:
            key_material = json.loads(unwrapped)
            log.info(f"key_hsm: parsed as JSON JWK (kty={key_material.get('kty')})")
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.info("key_hsm: material is not JSON — attempting DER parse")
            key_material = _parse_der_private_key(unwrapped)

        if key_material:
            log.info(f"key_hsm: unwrapped key type={key_material.get('kty')}, "
                     f"has_d={'d' in key_material}, has_p={'p' in key_material}")
        return key_material

    except Exception as e:
        log.error(f"key_hsm unwrap failed: {e}", exc_info=True)
        return None


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
    tpm_available = os.path.exists('/dev/tpmrm0') or os.path.exists('/dev/tpm0')
    tss_available = os.path.isdir(os.path.join(CVM_ATTEST_BASE, 'TSS_MSR'))

    return jsonify({
        'status': 'running',
        'type': 'cvm-skr-shim',
        'version': '2.0.0',
        'platform': 'confidential-vm',
        'vtpm_available': tpm_available,
        'cvm_attest_tools': _CVM_ATTEST_AVAILABLE,
        'tss_msr_available': tss_available,
        'message': 'CVM SKR Shim ready — AMD SEV-SNP attestation via vTPM + cvm-attestation-tools'
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
            'tpm_device': os.path.exists('/dev/tpmrm0'),
            'cvm_attest_tools': _CVM_ATTEST_AVAILABLE
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

        # First GET the key to retrieve its version and release policy
        # (versioned URL is required by the AKV release API spec)
        key_info_url = f"https://{akv_host}/keys/{kid}?api-version=7.4"
        log.info(f"    Fetching key metadata: {kid}")
        key_info_resp = http_requests.get(
            key_info_url,
            headers={"Authorization": f"Bearer {akv_token}"},
            timeout=30
        )

        key_version = None
        if key_info_resp.status_code == 200:
            key_info = key_info_resp.json()
            key_kid_url = key_info.get('key', {}).get('kid', '')
            log.info(f"    Key kid: {key_kid_url}")

            # Extract version from kid URL: https://{vault}/keys/{name}/{version}
            if key_kid_url:
                key_version = key_kid_url.rstrip('/').split('/')[-1]
                log.info(f"    Key version: {key_version}")

            # Log the release policy for debugging
            rp = key_info.get('release_policy', {})
            if rp:
                rp_data = rp.get('data', '')
                if rp_data:
                    try:
                        padded = rp_data + '=' * (4 - len(rp_data) % 4)
                        rp_bytes = base64.urlsafe_b64decode(padded)
                        rp_text = rp_bytes.decode('utf-8')
                        log.info(f"    Release policy: {rp_text[:500]}")
                    except Exception as rp_err:
                        log.warning(f"    Failed to decode release policy: {rp_err}")
            else:
                log.warning("    NO RELEASE POLICY on key — release will fail!")

            log.info(f"    Exportable: {key_info.get('attributes', {}).get('exportable')}")
        else:
            log.warning(f"    Failed to get key info: HTTP {key_info_resp.status_code}")

        # Build the key release URL — use versioned URL when available
        # The AKV release API spec requires: /keys/{name}/{version}/release
        if kid.startswith('https://'):
            key_url = f"{kid}/release"
        elif key_version:
            key_url = f"https://{akv_host}/keys/{kid}/{key_version}/release"
        else:
            key_url = f"https://{akv_host}/keys/{kid}/release"

        log.info(f"    Release URL: {key_url}")

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

            # On 403, decode the MAA token to diagnose which claims failed
            diagnostics = {}
            if resp.status_code == 403:
                token_claims = decode_jwt_payload(maa_token)
                if token_claims:
                    diagnostics['token_issuer'] = token_claims.get('iss', '(missing)')
                    diagnostics['token_nbf'] = token_claims.get('nbf')
                    diagnostics['token_exp'] = token_claims.get('exp')
                    iso_tee = token_claims.get('x-ms-isolation-tee')
                    if iso_tee and isinstance(iso_tee, dict):
                        diagnostics['x-ms-isolation-tee.x-ms-attestation-type'] = iso_tee.get('x-ms-attestation-type', '(missing)')
                        diagnostics['x-ms-isolation-tee.x-ms-compliance-status'] = iso_tee.get('x-ms-compliance-status', '(missing)')
                        diagnostics['x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable'] = iso_tee.get('x-ms-sevsnpvm-is-debuggable')
                    else:
                        diagnostics['x-ms-isolation-tee'] = '(MISSING - this is required for default CVM policy)'
                        if 'x-ms-attestation-type' in token_claims:
                            diagnostics['top-level-x-ms-attestation-type'] = token_claims['x-ms-attestation-type']
                            diagnostics['diagnosis'] = 'Token has top-level claims but missing x-ms-isolation-tee — likely platform attestation instead of guest attestation'
                    runtime = token_claims.get('x-ms-runtime', {})
                    if isinstance(runtime, dict):
                        diagnostics['x-ms-runtime.keys_count'] = len(runtime.get('keys', []))
                        vm_config = runtime.get('vm-configuration', {})
                        if isinstance(vm_config, dict):
                            diagnostics['x-ms-runtime.vm-configuration.vmUniqueId'] = vm_config.get('vmUniqueId', '(missing)')
                    # Include all top-level claim keys for debugging
                    diagnostics['all_claim_keys'] = sorted(token_claims.keys())
                else:
                    diagnostics['jwt_decode'] = 'Failed to decode MAA token payload'

                log.error(f"  Token diagnostics: {json.dumps(diagnostics, indent=2, default=str)}")

            return jsonify({
                'error': f'Key release failed with status {resp.status_code}',
                'detail': error_text,
                'key_url': key_url,
                'diagnostics': diagnostics
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
            f"Key released: {kid} "
            f"(type={key_data.get('kty', '?')}, ops={key_data.get('key_ops', [])}, "
            f"has_d={'d' in key_data}, has_key_hsm={'key_hsm' in key_data})"
        )

        # ---- Step 5: Unwrap key_hsm to extract private RSA components ----
        # AKV returns the private key material inside key_hsm, encrypted with
        # the TPM ephemeral key from attestation.  Without unwrapping, we only
        # have public components (n, e) — encryption works but decryption fails.
        if 'key_hsm' in key_data and 'd' not in key_data:
            log.info("  Step 5: Unwrapping key_hsm to extract private key...")
            unwrapped_jwk = unwrap_key_hsm(key_data['key_hsm'])
            if unwrapped_jwk:
                # Merge private components into the key
                private_fields = ['d', 'p', 'q', 'dp', 'dq', 'qi']
                merged = 0
                for field in private_fields:
                    if field in unwrapped_jwk:
                        key_data[field] = unwrapped_jwk[field]
                        merged += 1
                # Also pick up any other fields from the unwrapped key
                for field in unwrapped_jwk:
                    if field not in key_data:
                        key_data[field] = unwrapped_jwk[field]
                log.info(f"  Step 5: Merged {merged} private components into JWK")
                # Remove the encrypted blob — no longer needed
                key_data.pop('key_hsm', None)
            else:
                log.warning("  Step 5: key_hsm unwrap failed — returning public-only key")
        elif 'd' in key_data:
            log.info("  Key already has private component 'd' — no unwrap needed")

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
    log.info(f"  cvm-attest-tools:   {'LOADED' if _CVM_ATTEST_AVAILABLE else 'NOT AVAILABLE'}")
    if _CVM_IMPORT_ERROR:
        log.info(f"  Import error:       {_CVM_IMPORT_ERROR}")
    log.info(f"  CVM attest base:    {CVM_ATTEST_BASE}")
    log.info(f"  TSS_MSR dir:        {os.path.isdir(os.path.join(CVM_ATTEST_BASE, 'TSS_MSR'))}")
    log.info(f"  /dev/tpmrm0:        {os.path.exists('/dev/tpmrm0')}")
    log.info(f"  MAA endpoint:       {os.environ.get('SKR_MAA_ENDPOINT', '(not set)')}")
    log.info(f"  AKV endpoint:       {os.environ.get('SKR_AKV_ENDPOINT', '(not set)')}")
    log.info(f"  Key name:           {os.environ.get('SKR_KEY_NAME', '(not set)')}")
    log.info(f"  Identity client ID: {os.environ.get('MANAGED_IDENTITY_CLIENT_ID', '(not set)')}")
    log.info("=" * 60)

    app.run(host='0.0.0.0', port=port)
