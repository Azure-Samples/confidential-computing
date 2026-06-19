"""
sealed-app — runtime attestation web UI for an ACI Confidential Container
group that is locked down with a CCE policy produced by `az confcom
acipolicygen` and an encrypted "sealed" data bundle that is only unwrapped
after Secure Key Release (SKR) succeeds inside the TEE.

The container has no interactive access:
  * the CCE policy has no exec_processes entries, so `az container exec` is
    rejected by the ACI control plane; the image runs as a non-root user
    with a read-only root filesystem;
  * the only writable surface is an in-memory tmpfs at /run/sealed where the
    SKR-released AES-256-GCM key decrypts the sealed bundle that ships
    alongside the image (artifacts/sealed-data.enc);
  * ingress is restricted at L7 by enforce_firewall() below to the trusted
    source CIDR baked into the CCE policy at build time.

The web app is single-purpose:
  * GET  /            — visual attestation page (Jinja template, no JS deps).
  * POST /api/attest  — fetch a fresh SEV-SNP report via get-snp-report,
                        post it to MAA, and return the JWT claims.
  * GET  /api/sealed  — show the unsealed metadata that proves SKR worked.
  * GET  /healthz     — kubelet/probe liveness (returns 200 OK only).

There is intentionally no /exec, /shell, /eval, /debug, /metrics-with-labels
endpoint, no template rendering of user input, and no upload route.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import struct
import subprocess
import traceback
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, abort, jsonify, render_template, request


# ---------------------------------------------------------------------------
# Configuration (all overridable via env, but every variable is pinned in the
# CCE policy with strategy="string" so an attacker cannot inject new values).
# ---------------------------------------------------------------------------
GET_SNP_REPORT = os.environ.get("GET_SNP_REPORT", "/usr/local/bin/get-snp-report")
MAA_ENDPOINT   = os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
MAA_API        = os.environ.get("MAA_API_VERSION", "2022-08-01")
SEALED_DIR     = Path(os.environ.get("SEALED_DIR", "/run/sealed"))
FIREWALL_POLICY_PATH    = Path(os.environ.get("FIREWALL_POLICY", "/app/firewall-policy.json"))
FIREWALL_POLICY_SHA256  = (os.environ.get("FIREWALL_POLICY_SHA256") or "").lower()
TRUSTED_SOURCE_CIDR     = os.environ.get("TRUSTED_SOURCE_CIDR", "0.0.0.0/0")
APP_NAME       = "sealed-app"
APP_VERSION    = "1.0.0"

# Routes that are reachable from any source IP. /healthz is needed so the
# ACI platform's TCP probe can verify liveness without us knowing its
# source CIDR.
FIREWALL_BYPASS_PATHS = frozenset({"/healthz"})

# Bytes/offsets for the AMD SEV-SNP attestation report layout (see AMD SEV-SNP
# ABI specification, publication 56860, table "ATTESTATION_REPORT structure").
REPORT_LEN = 0x4A0  # 1184 bytes


# ---------------------------------------------------------------------------
# MAA claim explanations (re-used from the visual-attestation-demo-v2 sample).
# ---------------------------------------------------------------------------
CLAIM_EXPLANATIONS = {
    "iss": "Issuer URL of the MAA endpoint that signed this token.",
    "iat": "Issued At (Unix epoch seconds).",
    "exp": "Expiration (Unix epoch seconds).",
    "nbf": "Not Before (Unix epoch seconds).",
    "jti": "JWT ID — unique per token, useful for replay detection.",
    "x-ms-ver": "MAA token schema version.",
    "x-ms-attestation-type": "TEE type ('sevsnpvm' on ACI Confidential).",
    "x-ms-compliance-status": "MAA verdict ('azure-compliant-uvm' on success).",
    "x-ms-policy-hash": "SHA-256 of the MAA policy that evaluated this evidence.",
    "x-ms-runtime": "Caller-supplied runtime data bound into REPORT_DATA.",
    "x-ms-inittime": "Init-time data bound into the report (CCE policy hash on ACI CC).",
    "x-ms-sevsnpvm-hostdata": "Host data the hypervisor injected at launch — on ACI CC this is the SHA-256 of the CCE policy. Pin this in the SKR release policy.",
    "x-ms-sevsnpvm-is-debuggable": "Must be false for production CVMs.",
    "x-ms-sevsnpvm-launchmeasurement": "SHA-384 of the initial guest memory contents — the cryptographic identity of the boot image.",
    "x-ms-sevsnpvm-reportdata": "Hex of REPORT_DATA the guest supplied; MAA sets this to SHA-256(x-ms-runtime).",
    "x-ms-sevsnpvm-vmpl": "Virtual Machine Privilege Level (Azure CVMs report VMPL0).",
}


def _explain(key: str) -> str:
    if key in CLAIM_EXPLANATIONS:
        return CLAIM_EXPLANATIONS[key]
    if key.startswith("x-ms-sevsnpvm-"):
        return "SEV-SNP attestation report field surfaced by MAA. See AMD SEV-SNP ABI spec."
    if key.startswith("x-ms-"):
        return "MAA-issued claim. Refer to Microsoft Azure Attestation documentation."
    return "Standard JWT or caller-supplied claim."


# ---------------------------------------------------------------------------
# JWT helpers (display-only; MAA does the cryptographic verification).
# ---------------------------------------------------------------------------
def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def decode_jwt(token: str):
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Token does not have 3 segments (got {len(parts)})")
    return json.loads(_b64url_decode(parts[0])), json.loads(_b64url_decode(parts[1]))


def _format_timestamp(value):
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except Exception:
        return None


def annotate_claims(payload: dict):
    rows = []
    for key, value in payload.items():
        row = {"key": key, "value": value, "explanation": _explain(key)}
        if key in {"iat", "exp", "nbf"}:
            row["timestamp"] = _format_timestamp(value)
        rows.append(row)
    rows.sort(key=lambda r: (not r["key"].startswith("x-ms-"), r["key"]))
    return rows


# ---------------------------------------------------------------------------
# UVM information injected by the ACI control plane.
# ---------------------------------------------------------------------------
def _find_security_context_dir() -> str | None:
    explicit = os.environ.get("UVM_SECURITY_CONTEXT_DIR")
    if explicit and os.path.isdir(explicit):
        return explicit
    try:
        for entry in os.listdir("/"):
            if entry.startswith("security-context-"):
                full = os.path.join("/", entry)
                if os.path.isdir(full):
                    return full
    except OSError:
        pass
    return None


def load_uvm_information() -> dict:
    ctx_dir = _find_security_context_dir()
    if ctx_dir:
        def _read(name):
            p = Path(ctx_dir) / name
            return p.read_text().strip() if p.exists() else ""
        return {
            "host_amd_cert_b64": _read("host-amd-cert-base64"),
            "reference_info_b64": _read("reference-info-base64"),
            "source": ctx_dir,
        }
    return {
        "host_amd_cert_b64": os.environ.get("UVM_HOST_AMD_CERTIFICATE", ""),
        "reference_info_b64": os.environ.get("UVM_REFERENCE_INFO", ""),
        "source": "env",
    }


def _build_maa_report(snp_report: bytes, vcek_cert_chain: bytes, endorsements_json: bytes | None) -> str:
    inner = {
        "SnpReport": _b64url(snp_report),
        "VcekCertChain": _b64url(vcek_cert_chain),
    }
    if endorsements_json:
        inner["Endorsements"] = _b64url(endorsements_json)
    return _b64url(json.dumps(inner).encode("utf-8"))


# ---------------------------------------------------------------------------
# get-snp-report invocation.
# ---------------------------------------------------------------------------
def fetch_snp_report(report_data: bytes) -> bytes:
    if not (os.path.exists("/dev/sev-guest") or os.path.exists("/dev/sev")):
        raise RuntimeError(
            "Neither /dev/sev-guest nor /dev/sev is present. This container "
            "must run on ACI Confidential SKU (AMD SEV-SNP)."
        )
    proc = subprocess.run(
        [GET_SNP_REPORT, report_data.hex()],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"get-snp-report exited {proc.returncode}. "
            f"stdout: {proc.stdout.decode('utf-8', 'replace')[:500]} "
            f"stderr: {proc.stderr.decode('utf-8', 'replace')[:500]}"
        )
    hex_output = "".join(c for c in proc.stdout.decode("ascii", "replace") if c in "0123456789abcdefABCDEF")
    report = bytes.fromhex(hex_output)
    if len(report) < REPORT_LEN:
        raise RuntimeError(f"SNP report too short: {len(report)} bytes")
    return report[:REPORT_LEN]


def parse_snp_report_summary(buf: bytes) -> dict:
    version = struct.unpack_from("<I", buf, 0x000)[0]
    guest_svn = struct.unpack_from("<I", buf, 0x004)[0]
    vmpl = struct.unpack_from("<I", buf, 0x030)[0]
    measurement = buf[0x090:0x0C0].hex()
    host_data = buf[0x0C0:0x0E0].hex()
    report_data = buf[0x050:0x090].hex()
    chip_id = buf[0x1A0:0x1E0].hex()
    return {
        "version": version,
        "guest_svn": guest_svn,
        "vmpl": vmpl,
        "measurement": measurement,
        "host_data": host_data,
        "report_data": report_data,
        "chip_id": chip_id,
    }


# ---------------------------------------------------------------------------
# Top-level attestation flow.
# ---------------------------------------------------------------------------
def perform_attestation(user_nonce: str | None) -> dict:
    nonce = user_nonce or secrets.token_hex(16)
    runtime_obj = {"nonce": nonce, "client": APP_NAME, "version": APP_VERSION}
    runtime_bytes = json.dumps(runtime_obj).encode("utf-8")
    report_data = hashlib.sha256(runtime_bytes).digest() + b"\x00" * 32

    snp_report = fetch_snp_report(report_data)
    summary = parse_snp_report_summary(snp_report)

    uvm = load_uvm_information()
    if not uvm["host_amd_cert_b64"]:
        raise RuntimeError(
            "UVM host AMD certificate not found. Expected security-context-*/host-amd-cert-base64 "
            "or UVM_HOST_AMD_CERTIFICATE env var. ACI control plane injects this on Confidential SKU."
        )
    thim_certs = json.loads(base64.b64decode(uvm["host_amd_cert_b64"]))
    vcek_chain = (thim_certs.get("vcekCert", "") + thim_certs.get("certificateChain", "")).encode("utf-8")

    endorsements_json = None
    if uvm["reference_info_b64"]:
        ref_info = base64.b64decode(uvm["reference_info_b64"])
        endorsements_json = json.dumps({"Uvm": [_b64url(ref_info)]}).encode("utf-8")

    body = {
        "report": _build_maa_report(snp_report, vcek_chain, endorsements_json),
        "runtimeData": {"data": _b64url(runtime_bytes), "dataType": "JSON"},
        "nonce": secrets.randbits(63),
    }
    url = f"https://{MAA_ENDPOINT}/attest/SevSnpVm?api-version={MAA_API}"
    resp = requests.post(url, json=body, timeout=30, headers={"User-Agent": APP_NAME})
    if resp.status_code != 200:
        raise RuntimeError(f"MAA POST {url} returned HTTP {resp.status_code}: {resp.text[:600]}")
    token = resp.json().get("token")
    if not token:
        raise RuntimeError(f"MAA response missing 'token': {resp.text[:600]}")

    header, payload = decode_jwt(token)

    return {
        "endpoint": f"https://{MAA_ENDPOINT}",
        "region": MAA_ENDPOINT.split(".")[0],
        "isolation_type": "SEV_SNP",
        "nonce": nonce,
        "token": token,
        "header": header,
        "payload": payload,
        "claims": annotate_claims(payload),
        "hardware_evidence": {
            "maa_endpoint": MAA_ENDPOINT,
            "uvm_source": uvm["source"],
            "snp_report_size": len(snp_report),
            "snp_report_hex": snp_report.hex(),
            "snp_summary": summary,
            "runtime_data": runtime_obj,
            "runtime_data_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        },
    }


# ---------------------------------------------------------------------------
# Sealed bundle status — the entrypoint writes /run/sealed/manifest.json after
# SKR succeeds. We never expose the decrypted content itself, only metadata.
# ---------------------------------------------------------------------------
def sealed_status() -> dict:
    manifest = SEALED_DIR / "manifest.json"
    if not manifest.is_file():
        return {
            "unsealed": False,
            "reason": "Sealed bundle manifest not found. SKR may have failed or the "
                      "image was started outside of an ACI Confidential container group.",
        }
    info = json.loads(manifest.read_text())
    decrypted_files = []
    try:
        for p in sorted(SEALED_DIR.iterdir()):
            if p.is_file() and p.name != "manifest.json":
                decrypted_files.append({
                    "name": p.name,
                    "size": p.stat().st_size,
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                })
    except Exception as exc:
        decrypted_files = [{"error": str(exc)}]
    return {
        "unsealed": True,
        "sealed_at": info.get("sealed_at"),
        "unsealed_at": info.get("unsealed_at"),
        "akv_endpoint": info.get("akv_endpoint"),
        "key_name": info.get("key_name"),
        "key_version": info.get("key_version"),
        "ciphertext_sha256": info.get("ciphertext_sha256"),
        "plaintext_sha256": info.get("plaintext_sha256"),
        "wrap_algorithm": info.get("wrap_algorithm"),
        "release_policy_sha256": info.get("release_policy_sha256"),
        "files": decrypted_files,
    }


# ---------------------------------------------------------------------------
# Firewall (L7) — Confidential ACI does not support NSGs without a NAT
# gateway, so the signed artifacts/firewall-policy.json is enforced INSIDE
# the container instead. The policy file's SHA-256 is bound by the CCE
# policy (env var FIREWALL_POLICY_SHA256, baked at policy-gen time), so a
# tampered policy is detected at process start and the container exits.
# ---------------------------------------------------------------------------
def load_and_verify_firewall_policy() -> dict:
    if not FIREWALL_POLICY_PATH.is_file():
        raise RuntimeError(f"Firewall policy not found at {FIREWALL_POLICY_PATH}")
    raw = FIREWALL_POLICY_PATH.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if FIREWALL_POLICY_SHA256 and actual != FIREWALL_POLICY_SHA256:
        raise RuntimeError(
            f"Firewall policy SHA-256 mismatch: expected {FIREWALL_POLICY_SHA256}, got {actual}. "
            "Refusing to start."
        )
    return json.loads(raw)


try:
    FIREWALL_POLICY = load_and_verify_firewall_policy()
    _trusted_net = ipaddress.ip_network(TRUSTED_SOURCE_CIDR, strict=False)
except Exception as exc:
    # Surface the failure to stdout and re-raise so the container exits.
    print(f"[sealed-app] FATAL: {exc}", flush=True)
    raise


def _client_ip() -> str:
    # ACI's public IP routes directly to the container; there is no proxy
    # in front. Trust request.remote_addr only.
    return request.remote_addr or ""


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.before_request
def enforce_firewall():
    if request.path in FIREWALL_BYPASS_PATHS:
        return None
    ip = _client_ip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        abort(403)
    if addr not in _trusted_net:
        abort(403)
    return None


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        maa_endpoint=MAA_ENDPOINT,
    )


@app.route("/healthz", methods=["GET"])
def healthz():
    # No body, no metadata — just liveness.
    return "ok", 200


@app.route("/api/firewall", methods=["GET"])
def api_firewall():
    return jsonify({
        "ok": True,
        "policy_sha256": FIREWALL_POLICY_SHA256,
        "trusted_source_cidr": TRUSTED_SOURCE_CIDR,
        "policy": FIREWALL_POLICY,
    })


@app.route("/api/attest", methods=["POST"])
def api_attest():
    user_nonce = (request.json or {}).get("nonce") if request.is_json else request.form.get("nonce")
    try:
        result = perform_attestation(user_nonce or None)
    except Exception as exc:
        return (
            jsonify({"ok": False, "error": str(exc), "trace": traceback.format_exc()}),
            500,
        )
    return jsonify({"ok": True, **result})


@app.route("/api/sealed", methods=["GET"])
def api_sealed():
    return jsonify({"ok": True, **sealed_status()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8443")))
