import base64
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np
import requests
from flask import Flask, jsonify, render_template, request, send_from_directory, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024

UPLOAD_DIR = Path("/tmp/uploads")
PROCESSED_DIR = Path("/tmp/processed")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"mp4"}
jobs_lock = threading.Lock()
jobs: dict[str, dict] = {}

CLAIM_EXPLANATIONS = {
    "x-ms-attestation-type": "Shows the trusted hardware technology used by the attested workload.",
    "x-ms-compliance-status": "Indicates whether platform compliance checks passed.",
    "x-ms-sevsnpvm-is-debuggable": "False means debug mode is disabled, reducing tamper risk.",
    "x-ms-policy-hash": "Cryptographic hash of the confidential compute enforcement (CCE) policy.",
    "x-ms-runtime": "Runtime measurement proving launched workload and environment details.",
    "iss": "The token issuer; for this app this should be your selected Microsoft Azure Attestation endpoint.",
    "iat": "Token issue time (epoch seconds).",
    "exp": "Token expiry time (epoch seconds).",
}


@dataclass
class Detection:
    label: str
    confidence: float
    x: int
    y: int
    w: int
    h: int


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _claim_summary(claims: dict) -> list[dict]:
    summary = []
    for key, value in claims.items():
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value)
        else:
            rendered = str(value)
        summary.append({
            "claim": key,
            "value": rendered,
            "meaning": CLAIM_EXPLANATIONS.get(key, "Container evidence claim provided by attestation token."),
        })
    return summary


def _secure_request() -> bool:
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    return request.is_secure or forwarded_proto.lower() == "https"


def _classify_vehicle(x: int, y: int, w: int, h: int, frame_area: int) -> Detection:
    area = w * h
    aspect = w / max(h, 1)
    if area > 35000 and aspect > 2.2:
        label = "truck"
    elif area > 18000 and aspect > 1.3:
        label = "car"
    elif area < 12000 and aspect < 1.3:
        label = "motorcycle"
    else:
        label = "cycle"

    confidence = min(0.97, max(0.55, (area / max(frame_area, 1)) * 35))
    return Detection(label=label, confidence=confidence, x=x, y=y, w=w, h=h)


def _detect_vehicle_candidates(frame: np.ndarray) -> list[Detection]:
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blurred, 75, 180)
    kernel = np.ones((3, 3), np.uint8)
    edges = cv2.dilate(edges, kernel, iterations=1)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    detections: list[Detection] = []
    frame_area = frame.shape[0] * frame.shape[1]
    for contour in contours:
        area = cv2.contourArea(contour)
        if area < 1200:
            continue
        x, y, w, h = cv2.boundingRect(contour)
        if w < 30 or h < 20:
            continue
        detections.append(_classify_vehicle(x, y, w, h, frame_area))

    detections.sort(key=lambda d: d.confidence, reverse=True)
    return detections[:12]


def _process_video(job_id: str, input_path: Path, output_path: Path):
    cap = None
    writer = None
    try:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        plate_path = cv2.data.haarcascades + "haarcascade_russian_plate_number.xml"
        plate_cascade = cv2.CascadeClassifier(plate_path) if os.path.exists(plate_path) else None

        cap = cv2.VideoCapture(str(input_path))
        if not cap.isOpened():
            with jobs_lock:
                jobs[job_id].update({"state": "failed", "message": "Unable to open uploaded video file."})
            return

        fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 1280)
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 720)

        writer = cv2.VideoWriter(
            str(output_path),
            cv2.VideoWriter_fourcc(*"mp4v"),
            fps,
            (width, height),
        )

        processed_frames = 0
        last_status_update = 0.0

        while True:
            ok, frame = cap.read()
            if not ok:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            for (x, y, w, h) in faces:
                roi = frame[y:y + h, x:x + w]
                frame[y:y + h, x:x + w] = cv2.GaussianBlur(roi, (41, 41), 30)

            if plate_cascade is not None:
                plates = plate_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(25, 25))
                for (x, y, w, h) in plates:
                    roi = frame[y:y + h, x:x + w]
                    frame[y:y + h, x:x + w] = cv2.GaussianBlur(roi, (31, 31), 25)

            detections = _detect_vehicle_candidates(frame)
            for detection in detections:
                cv2.rectangle(
                    frame,
                    (detection.x, detection.y),
                    (detection.x + detection.w, detection.y + detection.h),
                    (0, 255, 255),
                    2,
                )
                label = f"{detection.label} {detection.confidence:.2f}"
                cv2.putText(
                    frame,
                    label,
                    (detection.x, max(20, detection.y - 8)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.6,
                    (0, 255, 255),
                    2,
                    cv2.LINE_AA,
                )

            writer.write(frame)
            processed_frames += 1

            now = time.time()
            if now - last_status_update >= 5:
                percent = 0 if frame_count == 0 else int((processed_frames / frame_count) * 100)
                with jobs_lock:
                    jobs[job_id].update(
                        {
                            "state": "processing",
                            "progress": min(percent, 99),
                            "processedFrames": processed_frames,
                            "totalFrames": frame_count,
                            "lastUpdated": int(now),
                            "message": f"Processing frame {processed_frames} of {frame_count or '?'}",
                        }
                    )
                last_status_update = now

        with jobs_lock:
            jobs[job_id].update(
                {
                    "state": "completed",
                    "progress": 100,
                    "message": "Processing complete. Video is ready for secure playback.",
                    "outputUrl": f"/processed/{output_path.name}",
                }
            )
    except Exception as exc:
        with jobs_lock:
            jobs[job_id].update({"state": "failed", "message": f"Processing failed: {exc}"})
    finally:
        if cap is not None:
            cap.release()
        if writer is not None:
            writer.release()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/attestation/check")
def attestation_check():
    body = request.get_json(silent=True) or {}
    maa_endpoint = body.get("maaEndpoint", os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net"))
    if maa_endpoint.startswith("https://"):
        maa_endpoint = maa_endpoint.replace("https://", "")

    try:
        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_endpoint, "runtime_data": "upload-gate"},
            timeout=30,
        )
        if response.status_code != 200:
            return jsonify(
                {
                    "status": "failed",
                    "message": "Attestation failed. Upload remains blocked.",
                    "detail": response.text[:1000],
                }
            ), response.status_code

        token = response.text.strip().strip('"')
        claims = _decode_jwt_payload(token)
        summary = _claim_summary(claims)

        session["attested"] = True
        session["attestationDecision"] = "pending"
        session["attestedAt"] = int(time.time())

        return jsonify(
            {
                "status": "ok",
                "token": token,
                "claims": summary,
                "explanation": "Token proves this workload is running in an attested confidential container with policy-backed measurements.",
            }
        )
    except Exception as exc:
        return jsonify({"status": "failed", "message": str(exc)}), 500


@app.post("/api/attestation/decision")
def attestation_decision():
    if not session.get("attested"):
        return jsonify({"status": "failed", "message": "Attestation is required before making this decision."}), 400

    decision = (request.json or {}).get("decision", "").lower()
    if decision not in {"proceed", "abort"}:
        return jsonify({"status": "failed", "message": "Decision must be proceed or abort."}), 400

    session["attestationDecision"] = decision
    if decision == "abort":
        session["attested"] = False

    return jsonify({"status": "ok", "decision": decision})


@app.post("/api/process")
def process_video():
    if not _secure_request():
        return jsonify({"status": "failed", "message": "HTTPS is required for uploads."}), 400

    if not session.get("attested") or session.get("attestationDecision") != "proceed":
        return jsonify({"status": "failed", "message": "Attestation and explicit proceed approval are required."}), 403

    if "video" not in request.files:
        return jsonify({"status": "failed", "message": "No video file provided."}), 400

    file = request.files["video"]
    filename = secure_filename(file.filename or "")
    if not filename or not _allowed_file(filename):
        return jsonify({"status": "failed", "message": "Only .mp4 files are accepted."}), 400

    job_id = uuid.uuid4().hex
    input_path = UPLOAD_DIR / f"{job_id}-{filename}"
    output_path = PROCESSED_DIR / f"processed-{job_id}.mp4"
    file.save(input_path)

    with jobs_lock:
        jobs[job_id] = {
            "state": "queued",
            "progress": 0,
            "message": "Queued for processing inside the confidential container.",
            "processedFrames": 0,
            "totalFrames": 0,
        }

    thread = threading.Thread(target=_process_video, args=(job_id, input_path, output_path), daemon=True)
    thread.start()

    return jsonify({"status": "ok", "jobId": job_id})


@app.get("/api/status/<job_id>")
def job_status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"status": "failed", "message": "Unknown job ID."}), 404
    return jsonify({"status": "ok", "job": job})


@app.get("/processed/<path:filename>")
def get_processed_file(filename: str):
    return send_from_directory(PROCESSED_DIR, filename, as_attachment=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
