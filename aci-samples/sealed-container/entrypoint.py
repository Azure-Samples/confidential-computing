#!/usr/bin/env python3
"""
sealed-app entrypoint.

This script is PID 1 inside the container. The CCE policy denies
`exec_in_container`, so this is the ONLY process tree the container
ever runs. The script performs three steps before handing off to the
Flask app:

  1. Fetch a fresh MAA SEV-SNP attestation token using the get-snp-report
     binary baked into the image and the THIM cert chain + UVM endorsements
     dropped by the ACI control plane into the security-context-* mount.

  2. Call Azure Key Vault Secure Key Release (SKR) for the AES wrapping key.
     The key's release policy (see policies/skr-release-policy.json) binds:
       - x-ms-isolation-tee.x-ms-attestation-type   == "sevsnpvm"
       - x-ms-isolation-tee.x-ms-compliance-status  == "azure-compliant-uvm"
       - x-ms-sevsnpvm-hostdata                     == <CCE policy SHA-256>
       - x-ms-sevsnpvm-is-debuggable                == false
     so the key only releases inside this exact container, on AMD SEV-SNP,
     when the CCE policy hash matches.

  3. Use the released RSA-HSM key (returned as a JWK inside a JWS) to
     unwrap the AES-256-GCM data-encryption key, then decrypt
     /app/sealed-data.enc into /run/sealed/<name>. /run/sealed is a
     tmpfs mounted by the ACI runtime — it is never persisted, never
     accessible from outside the TEE.

A manifest is written to /run/sealed/manifest.json so the app can prove
in the UI that SKR worked without ever exposing the plaintext bytes.

On any failure the container exits non-zero and the ACI runtime restarts
it. There is no fallback path that runs the app with no key — that is
the whole point.
"""
from __future__ import annotations

import sys
sys.stdout.write("[entrypoint] python interpreter alive\n"); sys.stdout.flush()

import base64
import hashlib
import json
import os
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.write("[entrypoint] stdlib imports ok\n"); sys.stdout.flush()

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_unwrap_with_padding

sys.stdout.write("[entrypoint] third-party imports ok\n"); sys.stdout.flush()


GET_SNP_REPORT  = os.environ.get("GET_SNP_REPORT",  "/usr/local/bin/get-snp-report")
MAA_ENDPOINT    = os.environ["MAA_ENDPOINT"]              # required, pinned in CCE policy
AKV_ENDPOINT    = os.environ["AKV_ENDPOINT"]              # required, pinned in CCE policy
KEY_NAME        = os.environ["SKR_KEY_NAME"]              # required, pinned in CCE policy
SEALED_BUNDLE   = Path(os.environ.get("SEALED_BUNDLE", "/app/sealed-data.enc"))
SEALED_DIR      = Path(os.environ.get("SEALED_DIR",    "/run/sealed"))
APP_CMD         = ["python", "/app/app.py"]

REPORT_LEN = 0x4A0


def log(msg: str) -> None:
    """The CCE policy denies runtime logging back to the ACI control plane,
    but writing to stdout/stderr inside the container is harmless — those
    streams are dropped at the boundary."""
    sys.stdout.write(f"[entrypoint] {msg}\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# MAA attestation
# ---------------------------------------------------------------------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int_to_b64url(i: int) -> str:
    return _b64url(i.to_bytes((i.bit_length() + 7) // 8, "big"))


# Ephemeral RSA wrap key. AKV /release wraps the HSM-released key with this
# key using CKM_RSA_AES_KEY_WRAP, so it never leaves the TEE in the clear.
# Lazy so any failure surfaces *after* main() has logged.
_EPHEMERAL_PRIV = None
EPHEMERAL_JWK_PUB = None


def _ensure_ephemeral_key():
    global _EPHEMERAL_PRIV, EPHEMERAL_JWK_PUB
    if _EPHEMERAL_PRIV is not None:
        return
    _EPHEMERAL_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = _EPHEMERAL_PRIV.public_key().public_numbers()
    EPHEMERAL_JWK_PUB = {
        "kty":     "RSA",
        "kid":     "sealed-app-ephemeral-wrap",
        "key_ops": ["wrapKey", "encrypt"],
        "alg":     "RSA-OAEP-256",
        "n":       _int_to_b64url(pub.n),
        "e":       _int_to_b64url(pub.e),
    }


def fetch_snp_report(report_data: bytes) -> bytes:
    proc = subprocess.run([GET_SNP_REPORT, report_data.hex()],
                          capture_output=True, timeout=15, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"get-snp-report failed: {proc.stderr!r}")
    hex_out = "".join(c for c in proc.stdout.decode("ascii", "replace") if c in "0123456789abcdefABCDEF")
    return bytes.fromhex(hex_out)[:REPORT_LEN]


def load_uvm() -> dict:
    explicit = os.environ.get("UVM_SECURITY_CONTEXT_DIR")
    ctx = explicit if (explicit and os.path.isdir(explicit)) else None
    if not ctx:
        for entry in os.listdir("/"):
            if entry.startswith("security-context-") and os.path.isdir("/" + entry):
                ctx = "/" + entry
                break
    if not ctx:
        raise RuntimeError("UVM_SECURITY_CONTEXT_DIR not found")
    return {
        "host_amd_cert_b64": (Path(ctx) / "host-amd-cert-base64").read_text().strip(),
        "reference_info_b64": (Path(ctx) / "reference-info-base64").read_text().strip(),
    }


def get_maa_token() -> str:
    # The 'keys' claim is REQUIRED for AKV /release. MAA copies runtime data
    # into the issued JWT under x-ms-runtime.keys, and AKV uses one of those
    # public keys as the RSA half of CKM_RSA_AES_KEY_WRAP.
    _ensure_ephemeral_key()
    runtime = {
        "client": "sealed-app-entrypoint",
        "ts":     int(time.time()),
        "keys":   [EPHEMERAL_JWK_PUB],
    }
    runtime_bytes = json.dumps(runtime).encode("utf-8")
    report_data = hashlib.sha256(runtime_bytes).digest() + b"\x00" * 32

    report = fetch_snp_report(report_data)
    uvm = load_uvm()
    thim = json.loads(base64.b64decode(uvm["host_amd_cert_b64"]))
    vcek_chain = (thim.get("vcekCert", "") + thim.get("certificateChain", "")).encode("utf-8")
    endorsements = json.dumps({"Uvm": [_b64url(base64.b64decode(uvm["reference_info_b64"]))]}).encode("utf-8")

    inner = {
        "SnpReport":      _b64url(report),
        "VcekCertChain":  _b64url(vcek_chain),
        "Endorsements":   _b64url(endorsements),
    }
    body = {
        "report":      _b64url(json.dumps(inner).encode("utf-8")),
        "runtimeData": {"data": _b64url(runtime_bytes), "dataType": "JSON"},
    }
    url = f"https://{MAA_ENDPOINT}/attest/SevSnpVm?api-version=2022-08-01"
    r = requests.post(url, json=body, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"MAA returned HTTP {r.status_code}: {r.text[:500]}")
    token = r.json().get("token")
    if not token:
        raise RuntimeError(f"MAA returned no token: {r.text[:500]}")
    return token


# ---------------------------------------------------------------------------
# Managed-identity token for AKV
# ---------------------------------------------------------------------------
def get_akv_token() -> str:
    """The ACI container group runs with a user-assigned managed identity that
    has 'get' + 'release' on the SKR key. IMDS is reachable from inside the
    TEE."""
    r = requests.get(
        "http://169.254.169.254/metadata/identity/oauth2/token",
        params={"api-version": "2018-02-01", "resource": "https://vault.azure.net"},
        headers={"Metadata": "true"},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# SKR + unseal
# ---------------------------------------------------------------------------
def release_key(maa_token: str, akv_token: str):
    """Calls AKV /keys/<name>/release. Returns (rsa_private_key, key_version)."""
    akv_host = AKV_ENDPOINT.replace("https://", "").rstrip("/")
    info = requests.get(
        f"https://{akv_host}/keys/{KEY_NAME}?api-version=7.4",
        headers={"Authorization": f"Bearer {akv_token}"},
        timeout=15,
    ).json()
    kid = info.get("key", {}).get("kid", "")
    key_version = kid.rstrip("/").split("/")[-1]

    resp = requests.post(
        f"https://{akv_host}/keys/{KEY_NAME}/{key_version}/release?api-version=7.4",
        headers={"Authorization": f"Bearer {akv_token}", "Content-Type": "application/json"},
        json={"target": maa_token, "enc": "RSA_AES_KEY_WRAP_256"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"AKV release failed HTTP {resp.status_code}: {resp.text[:600]}")
    jws = resp.json()["value"]
    payload = json.loads(_b64url_decode(jws.split(".")[1]))
    jwk = payload["response"]["key"]["key"]
    log(f"  released JWK kid={jwk.get('kid','?')} kty={jwk.get('kty','?')} fields={sorted(jwk.keys())}")
    if "key_hsm" in jwk:
        rsa_priv = unwrap_ckm_rsa_aes(jwk["key_hsm"])
    else:
        rsa_priv = jwk_to_private_key(jwk)
    return rsa_priv, key_version


def unwrap_ckm_rsa_aes(key_hsm_b64: str):
    """CKM_RSA_AES_KEY_WRAP unwrap of the AKV /release HSM payload.

    The wrapped blob is:
      [0 .. rsa_len)   RSA-OAEP-SHA256(MGF1-SHA256)(AES-256 key)
      [rsa_len .. end) AES Key Wrap with Padding (RFC 5649) of PKCS#8 DER
                       of the RSA private key
    """
    blob = _b64url_decode(key_hsm_b64)
    log(f"  key_hsm blob: {len(blob)} bytes (rsa expects {(_EPHEMERAL_PRIV.key_size+7)//8})")
    log(f"  key_hsm head[0:8]={blob[:8].hex()}  tail[-8:]={blob[-8:].hex()}")
    log(f"  key_hsm printable head: {blob[:80]!r}")
    # AKV BYOK-style envelope: when key_hsm is UTF-8 JSON, unwrap that first.
    if blob[:1] == b"{":
        try:
            env = json.loads(blob)
            log(f"  key_hsm envelope keys: {sorted(env.keys())}")
            ct_b64 = env.get("ciphertext") or env.get("encrypted_key") or env.get("value")
            if ct_b64 is None:
                raise RuntimeError(f"key_hsm envelope has no ciphertext field: {list(env.keys())}")
            blob = _b64url_decode(ct_b64)
            log(f"  key_hsm inner blob: {len(blob)} bytes")
        except json.JSONDecodeError:
            pass
    rsa_len = (_EPHEMERAL_PRIV.key_size + 7) // 8
    wrapped_aes = blob[:rsa_len]
    wrapped_key = blob[rsa_len:]
    aes_key = _EPHEMERAL_PRIV.decrypt(
        wrapped_aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    log(f"  aes_key: {len(aes_key)} bytes; wrapped_key: {len(wrapped_key)} bytes")
    # AKV uses AES-KW (RFC 3394) for the inner wrap, not KWP. Try KW first, fall back to KWP.
    try:
        pkcs8_der = aes_key_unwrap(aes_key, wrapped_key)
    except Exception as e:
        log(f"  aes_key_unwrap failed ({e}); trying aes_key_unwrap_with_padding")
        pkcs8_der = aes_key_unwrap_with_padding(aes_key, wrapped_key)
    log(f"  unwrapped payload: {len(pkcs8_der)} bytes; head[0:4]={pkcs8_der[:4].hex()}")
    return serialization.load_der_private_key(pkcs8_der, password=None)


def jwk_to_private_key(jwk: dict):
    """Reconstruct an RSA private key from the JWK fields released by AKV."""
    def _i(name): return int.from_bytes(_b64url_decode(jwk[name]), "big")
    pub = rsa.RSAPublicNumbers(_i("e"), _i("n"))
    priv = rsa.RSAPrivateNumbers(_i("p"), _i("q"), _i("d"), _i("dp"), _i("dq"), _i("qi"), pub)
    return priv.private_key()


def unseal_bundle(rsa_priv) -> dict:
    """Sealed bundle format (versioned, length-prefixed):

      [ 0..3 ]      magic       b"SEAL"
      [ 4..7 ]      version     uint32 LE  (=1)
      [ 8..11]      wrap_len    uint32 LE
      [12..12+wl]   wrapped_dek RSA-OAEP-SHA256(DEK)   ; DEK is 32 random bytes
      [..]          nonce_len   uint32 LE  (=12)
      [..]          nonce       12-byte AES-GCM IV
      [..]          ct_len      uint32 LE
      [..]          ciphertext  AES-256-GCM(plaintext, aad=b"sealed-app/v1")
    """
    raw = SEALED_BUNDLE.read_bytes()
    ciphertext_sha256 = hashlib.sha256(raw).hexdigest()
    if raw[:4] != b"SEAL":
        raise RuntimeError("Sealed bundle magic mismatch")
    version = struct.unpack_from("<I", raw, 4)[0]
    if version != 1:
        raise RuntimeError(f"Unsupported sealed-bundle version {version}")
    off = 8
    wl  = struct.unpack_from("<I", raw, off)[0]; off += 4
    wrapped = raw[off:off+wl]; off += wl
    nl  = struct.unpack_from("<I", raw, off)[0]; off += 4
    nonce = raw[off:off+nl]; off += nl
    cl  = struct.unpack_from("<I", raw, off)[0]; off += 4
    ct  = raw[off:off+cl]

    dek = rsa_priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    if len(dek) != 32:
        raise RuntimeError("Unwrapped DEK is not 32 bytes")
    plaintext = AESGCM(dek).decrypt(nonce, ct, b"sealed-app/v1")
    bundle = json.loads(plaintext)

    return {
        "bundle": bundle,
        "ciphertext_sha256": ciphertext_sha256,
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "wrap_algorithm": "RSA-OAEP-SHA256 + AES-256-GCM",
    }


def write_unsealed(unsealed: dict, key_version: str) -> None:
    SEALED_DIR.mkdir(parents=True, exist_ok=True)
    bundle = unsealed["bundle"]
    files = bundle.get("files", {})
    for name, content_b64 in files.items():
        # Reject path traversal — names come from the sealed bundle but we
        # treat them as untrusted just in case.
        if "/" in name or name.startswith(".") or name in ("manifest.json",):
            log(f"refusing suspicious filename in sealed bundle: {name!r}")
            continue
        (SEALED_DIR / name).write_bytes(base64.b64decode(content_b64))

    manifest = {
        "sealed_at":               bundle.get("sealed_at"),
        "unsealed_at":             datetime.now(timezone.utc).isoformat(),
        "akv_endpoint":            AKV_ENDPOINT,
        "key_name":                KEY_NAME,
        "key_version":             key_version,
        "ciphertext_sha256":       unsealed["ciphertext_sha256"],
        "plaintext_sha256":        unsealed["plaintext_sha256"],
        "wrap_algorithm":          unsealed["wrap_algorithm"],
    }
    (SEALED_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    log(f"sealed-app starting; MAA={MAA_ENDPOINT} AKV={AKV_ENDPOINT} key={KEY_NAME}")
    try:
        log("Step 1/4 — fetching MAA SEV-SNP token")
        maa_token = get_maa_token()
        log(f"  MAA token: {len(maa_token)} chars")

        log("Step 2/4 — acquiring AKV access token via IMDS")
        akv_token = get_akv_token()

        log("Step 3/4 — calling AKV /release")
        rsa_priv, key_version = release_key(maa_token, akv_token)
        log(f"  released key version: {key_version}")

        log("Step 4/4 — unsealing data bundle into tmpfs")
        unsealed = unseal_bundle(rsa_priv)
        write_unsealed(unsealed, key_version)
        log(f"  unsealed {len(unsealed['bundle'].get('files', {}))} file(s) into {SEALED_DIR}")
    except Exception as exc:
        log(f"FATAL: {exc}")
        # Exit non-zero so the runtime restarts (or, in production, fails the
        # container group). NEVER fall through to the app without sealed data.
        return 2

    log(f"Handing off to: {' '.join(APP_CMD)}")
    os.execvp(APP_CMD[0], APP_CMD)


if __name__ == "__main__":
    sys.exit(main())
