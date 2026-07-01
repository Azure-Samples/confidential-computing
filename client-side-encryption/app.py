import base64
import json
import os
import time
import uuid
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from azure.core.exceptions import ResourceExistsError
from azure.data.tables import TableClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.storage.queue import QueueServiceClient
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

app = Flask(__name__)

DEFAULT_MAA_ENDPOINT = os.environ.get("SKR_MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
DEFAULT_AKV_ENDPOINT = os.environ.get("SKR_AKV_ENDPOINT", "")
DEFAULT_KEY_NAME = os.environ.get("SKR_KEY_NAME", "customer-secret-key")
DEFAULT_STORAGE_ACCOUNT = os.environ.get("STORAGE_ACCOUNT", "")
DEFAULT_STORAGE_CONNECTION_STRING = os.environ.get("STORAGE_CONNECTION_STRING", "")
DEFAULT_SECRET_STRING = os.environ.get("SECRET_STRING", "")
DEFAULT_AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
BLOB_CONTAINER = os.environ.get("BLOB_CONTAINER", "secretdata")
TABLE_NAME = os.environ.get("TABLE_NAME", "secretrecords")
QUEUE_NAME = os.environ.get("QUEUE_NAME", "secretrecords")

_released_key = None
_key_metadata = {}
_storage_clients = None
_initial_seed_done = False


def _storage_access_error_message(exc: Exception) -> str:
    detail = str(exc).strip() or exc.__class__.__name__
    return (
        "Storage access failed while reading or writing Blob/Table/Queue data. "
        "This deployment currently depends on network reachability from the confidential container "
        "to the storage account. In this tenant, the storage account may be blocked by network policy. "
        f"Detail: {detail}"
    )


@app.errorhandler(Exception)
def handle_unexpected_exception(exc: Exception):
    if isinstance(exc, HTTPException):
        response = exc.get_response()
        response.data = json.dumps({"ok": False, "error": exc.description})
        response.content_type = "application/json"
        return response

    app.logger.exception("Unhandled application error")
    return (
        jsonify(
            {
                "ok": False,
                "error": str(exc).strip() or "Internal server error.",
            }
        ),
        500,
    )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_endpoint(host: str) -> str:
    if not host:
        return ""
    host = host.strip()
    host = host.replace("https://", "").replace("http://", "")
    return host.strip("/")


def _b64url_decode_to_int(value: str) -> int:
    pad = "=" * ((4 - len(value) % 4) % 4)
    raw = base64.urlsafe_b64decode(value + pad)
    return int.from_bytes(raw, byteorder="big")


def _jwk_to_private_key(jwk: dict):
    required = ["n", "e", "d", "p", "q", "dp", "dq", "qi"]
    if not all(k in jwk for k in required):
        return None

    numbers = rsa.RSAPrivateNumbers(
        p=_b64url_decode_to_int(jwk["p"]),
        q=_b64url_decode_to_int(jwk["q"]),
        d=_b64url_decode_to_int(jwk["d"]),
        dmp1=_b64url_decode_to_int(jwk["dp"]),
        dmq1=_b64url_decode_to_int(jwk["dq"]),
        iqmp=_b64url_decode_to_int(jwk["qi"]),
        public_numbers=rsa.RSAPublicNumbers(
            e=_b64url_decode_to_int(jwk["e"]),
            n=_b64url_decode_to_int(jwk["n"]),
        ),
    )
    return numbers.private_key(default_backend())


def _jwk_to_public_key(jwk: dict):
    if "n" not in jwk or "e" not in jwk:
        return None
    numbers = rsa.RSAPublicNumbers(
        e=_b64url_decode_to_int(jwk["e"]),
        n=_b64url_decode_to_int(jwk["n"]),
    )
    return numbers.public_key(default_backend())


def _release_key(maa_endpoint: str, akv_endpoint: str, key_name: str):
    global _released_key, _key_metadata

    maa_endpoint = _normalize_endpoint(maa_endpoint)
    akv_endpoint = _normalize_endpoint(akv_endpoint)

    start = time.time()
    response = requests.post(
        "http://localhost:8080/key/release",
        json={"maa_endpoint": maa_endpoint, "akv_endpoint": akv_endpoint, "kid": key_name},
        timeout=90,
    )
    elapsed_ms = int((time.time() - start) * 1000)

    if response.status_code != 200:
        detail = response.text[:4000] if response.text else "No response body"
        return None, {
            "ok": False,
            "status_code": response.status_code,
            "elapsed_ms": elapsed_ms,
            "detail": detail,
            "request": {
                "maa_endpoint": maa_endpoint,
                "akv_endpoint": akv_endpoint,
                "kid": key_name,
            },
        }

    payload = response.json()
    key_payload = payload.get("key", payload)
    if isinstance(key_payload, str):
        key_payload = json.loads(key_payload)
    if isinstance(key_payload, dict) and "key" in key_payload:
        key_payload = key_payload["key"]

    _released_key = key_payload
    _key_metadata = {
        "kid": key_payload.get("kid", key_name) if isinstance(key_payload, dict) else key_name,
        "kty": key_payload.get("kty", "unknown") if isinstance(key_payload, dict) else "unknown",
        "released_at": _utc_now_iso(),
        "elapsed_ms": elapsed_ms,
    }

    return key_payload, {
        "ok": True,
        "elapsed_ms": elapsed_ms,
        "request": {
            "maa_endpoint": maa_endpoint,
            "akv_endpoint": akv_endpoint,
            "kid": key_name,
        },
        "key_info": {
            "kid": _key_metadata["kid"],
            "kty": _key_metadata["kty"],
            "has_private_components": all(
                k in key_payload for k in ["d", "p", "q", "dp", "dq", "qi"]
            )
            if isinstance(key_payload, dict)
            else False,
        },
    }


def _encrypt_with_released_key(plaintext: str):
    if not _released_key or not isinstance(_released_key, dict):
        raise RuntimeError("No released key is available.")

    public_key = _jwk_to_public_key(_released_key)
    if not public_key:
        raise RuntimeError("Released key does not contain RSA public components.")

    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "algorithm": "RSA-OAEP-SHA256",
        "key_id": _key_metadata.get("kid", "unknown"),
    }


def _decrypt_with_released_key(ciphertext_b64: str):
    if not _released_key or not isinstance(_released_key, dict):
        return None, "No released key is available."

    private_key = _jwk_to_private_key(_released_key)
    if not private_key:
        return None, "Released key does not include private key material for local decryption."

    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8"), None


def _get_storage_clients():
    global _storage_clients
    if _storage_clients:
        return _storage_clients

    if DEFAULT_STORAGE_CONNECTION_STRING:
        blob_service = BlobServiceClient.from_connection_string(DEFAULT_STORAGE_CONNECTION_STRING)
        queue_service = QueueServiceClient.from_connection_string(DEFAULT_STORAGE_CONNECTION_STRING)
        table_client = TableClient.from_connection_string(
            conn_str=DEFAULT_STORAGE_CONNECTION_STRING,
            table_name=TABLE_NAME,
        )
    else:
        if not DEFAULT_STORAGE_ACCOUNT:
            raise RuntimeError("STORAGE_ACCOUNT is not configured.")

        cred = DefaultAzureCredential(
            managed_identity_client_id=DEFAULT_AZURE_CLIENT_ID or None,
        )
        blob_service = BlobServiceClient(
            account_url=f"https://{DEFAULT_STORAGE_ACCOUNT}.blob.core.windows.net",
            credential=cred,
        )
        queue_service = QueueServiceClient(
            account_url=f"https://{DEFAULT_STORAGE_ACCOUNT}.queue.core.windows.net",
            credential=cred,
        )
        table_client = TableClient(
            endpoint=f"https://{DEFAULT_STORAGE_ACCOUNT}.table.core.windows.net",
            table_name=TABLE_NAME,
            credential=cred,
        )

    _storage_clients = {
        "blob_service": blob_service,
        "queue_service": queue_service,
        "table_client": table_client,
    }
    return _storage_clients


def _ensure_storage_entities():
    clients = _get_storage_clients()

    blob_container = clients["blob_service"].get_container_client(BLOB_CONTAINER)
    try:
        blob_container.create_container()
    except ResourceExistsError:
        pass

    queue_client = clients["queue_service"].get_queue_client(QUEUE_NAME)
    try:
        queue_client.create_queue()
    except ResourceExistsError:
        pass

    try:
        clients["table_client"].create_table()
    except ResourceExistsError:
        pass

    return {
        "blob_container": blob_container,
        "queue_client": queue_client,
        "table_client": clients["table_client"],
    }


def _store_record(plaintext: str):
    stores = _ensure_storage_entities()
    enc = _encrypt_with_released_key(plaintext)

    record_id = str(uuid.uuid4())
    created_at = _utc_now_iso()
    base_record = {
        "id": record_id,
        "createdAt": created_at,
        "ciphertext": enc["ciphertext"],
        "algorithm": enc["algorithm"],
        "keyId": enc["key_id"],
    }

    blob_name = f"record-{record_id}.json"
    stores["blob_container"].upload_blob(blob_name, json.dumps(base_record), overwrite=True)

    entity = {
        "PartitionKey": "records",
        "RowKey": record_id,
        "Ciphertext": enc["ciphertext"],
        "Algorithm": enc["algorithm"],
        "KeyId": enc["key_id"],
        "CreatedAt": created_at,
    }
    stores["table_client"].upsert_entity(entity=entity)

    queue_message = json.dumps(base_record)
    stores["queue_client"].send_message(queue_message)

    return base_record


def _collect_records_for_view():
    stores = _ensure_storage_entities()
    rows = []

    blob_items = stores["blob_container"].list_blobs(name_starts_with="record-")
    for item in blob_items:
        payload = stores["blob_container"].download_blob(item.name).readall().decode("utf-8")
        data = json.loads(payload)
        plain, err = _decrypt_with_released_key(data.get("ciphertext", ""))
        rows.append(
            {
                "store": "blob",
                "id": data.get("id"),
                "createdAt": data.get("createdAt"),
                "encrypted": payload,
                "decrypted": plain,
                "decryptError": err,
                "keyId": data.get("keyId", "unknown"),
            }
        )

    entities = stores["table_client"].query_entities("PartitionKey eq 'records'")
    for ent in entities:
        encrypted_payload = json.dumps(
            {
                "PartitionKey": ent.get("PartitionKey"),
                "RowKey": ent.get("RowKey"),
                "Ciphertext": ent.get("Ciphertext"),
                "Algorithm": ent.get("Algorithm"),
                "KeyId": ent.get("KeyId"),
                "CreatedAt": ent.get("CreatedAt"),
            }
        )
        plain, err = _decrypt_with_released_key(ent.get("Ciphertext", ""))
        rows.append(
            {
                "store": "table",
                "id": ent.get("RowKey"),
                "createdAt": ent.get("CreatedAt"),
                "encrypted": encrypted_payload,
                "decrypted": plain,
                "decryptError": err,
                "keyId": ent.get("KeyId", "unknown"),
            }
        )

    queue_messages = stores["queue_client"].peek_messages(max_messages=32)
    for msg in queue_messages:
        body = msg.content
        decoded = body
        try:
            payload = json.loads(decoded)
        except Exception:
            # Some queue configurations may return base64-encoded content.
            decoded = base64.b64decode(body).decode("utf-8")
            payload = json.loads(decoded)
        plain, err = _decrypt_with_released_key(payload.get("ciphertext", ""))
        rows.append(
            {
                "store": "queue",
                "id": payload.get("id"),
                "createdAt": payload.get("createdAt"),
                "encrypted": decoded,
                "decrypted": plain,
                "decryptError": err,
                "keyId": payload.get("keyId", "unknown"),
            }
        )

    rows.sort(key=lambda r: (r.get("createdAt") or "", r.get("store") or ""), reverse=True)
    return rows


def _seed_initial_record_once(process_log: list):
    global _initial_seed_done
    if _initial_seed_done:
        return
    if not DEFAULT_SECRET_STRING:
        process_log.append({"step": "seed", "status": "skipped", "detail": "No SECRET_STRING configured."})
        _initial_seed_done = True
        return

    rec = _store_record(DEFAULT_SECRET_STRING)
    process_log.append(
        {
            "step": "seed",
            "status": "ok",
            "detail": "Seeded initial command-line secret string.",
            "record": rec,
        }
    )
    _initial_seed_done = True


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/get-secret-data", methods=["POST"])
def api_get_secret_data():
    process = []

    body = request.get_json(silent=True) or {}
    maa = body.get("maa_endpoint", DEFAULT_MAA_ENDPOINT)
    akv = body.get("akv_endpoint", DEFAULT_AKV_ENDPOINT)
    kid = body.get("key_name", DEFAULT_KEY_NAME)

    if not akv:
        return jsonify(
            {
                "ok": False,
                "error": "SKR_AKV_ENDPOINT is not configured.",
                "process": process,
            }
        ), 400

    _, release_info = _release_key(maa, akv, kid)
    process.append({"step": "secure-key-release", **release_info})
    if not release_info.get("ok"):
        return jsonify({"ok": False, "error": "Secure Key Release failed.", "process": process}), 502

    try:
        _seed_initial_record_once(process)
        records = _collect_records_for_view()
    except Exception as exc:
        app.logger.exception("Storage access failed during get-secret-data")
        process.append(
            {
                "step": "storage",
                "status": "error",
                "detail": _storage_access_error_message(exc),
            }
        )
        return jsonify({"ok": False, "error": _storage_access_error_message(exc), "process": process}), 502

    process.append(
        {
            "step": "read-stores",
            "status": "ok",
            "detail": "Read encrypted records from Blob, Table, and Queue stores.",
            "counts": {
                "total": len(records),
                "blob": len([r for r in records if r["store"] == "blob"]),
                "table": len([r for r in records if r["store"] == "table"]),
                "queue": len([r for r in records if r["store"] == "queue"]),
            },
        }
    )

    return jsonify(
        {
            "ok": True,
            "process": process,
            "key": _key_metadata,
            "records": records,
        }
    )


@app.route("/api/add-record", methods=["POST"])
def api_add_record():
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    if not value:
        return jsonify({"ok": False, "error": "value is required."}), 400

    if not _released_key:
        return jsonify(
            {
                "ok": False,
                "error": "No released key available. Click 'get secret data' first.",
            }
        ), 400

    try:
        rec = _store_record(value)
        records = _collect_records_for_view()
    except Exception as exc:
        app.logger.exception("Storage access failed during add-record")
        return jsonify({"ok": False, "error": _storage_access_error_message(exc)}), 502

    return jsonify(
        {
            "ok": True,
            "added": rec,
            "records": records,
            "key": _key_metadata,
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
