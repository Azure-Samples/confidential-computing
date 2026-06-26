import base64
import json
import math
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import cv2
import numpy as np
import requests
from flask import Flask, jsonify, render_template, request, send_from_directory, session
from werkzeug.utils import secure_filename
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024 * 1024

UPLOAD_DIR = Path("/tmp/uploads")
PROCESSED_DIR = Path("/tmp/processed")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"mp4"}
jobs_lock = threading.Lock()
jobs: dict[str, dict] = {}
worker_state = threading.local()
JOB_STATE_DIR = Path("/tmp/job_state")
JOB_STATE_DIR.mkdir(parents=True, exist_ok=True)
INSTANCE_NAME = os.environ.get("INSTANCE_NAME", "automotive-machine-vision")
PEER_ENDPOINTS = [e.strip().rstrip("/") for e in os.environ.get("PEER_ENDPOINTS", "").split(",") if e.strip()]
PROCESSING_PROFILE_PRESETS = {
    "balanced": {"worker_factor": 1.0, "detect_stride": 2},
    "fast": {"worker_factor": 1.25, "detect_stride": 3},
    "max": {"worker_factor": 1.5, "detect_stride": 4},
}
ENABLE_DISTRIBUTED_PROCESSING = os.environ.get("ENABLE_DISTRIBUTED_PROCESSING", "false").lower() == "true"
MAX_DISTRIBUTED_CONTAINERS = max(1, min(10, int(os.environ.get("MAX_DISTRIBUTED_CONTAINERS", "1"))))
MIN_FRAMES_PER_SHARD = max(90, min(2400, int(os.environ.get("MIN_FRAMES_PER_SHARD", "240"))))
REMOTE_SEGMENT_TIMEOUT_SECONDS = max(120, min(7200, int(os.environ.get("REMOTE_SEGMENT_TIMEOUT_SECONDS", "3600"))))
VIDEO_OUTPUT_CODECS = ["avc1", "H264", "X264", "mp4v"]
H264_CODECS = {"avc1", "H264", "X264"}
DISPLAY_CONFIDENCE_THRESHOLD = max(0.0, min(1.0, float(os.environ.get("DISPLAY_CONFIDENCE_THRESHOLD", "0.60"))))
ENABLE_PLATE_CONTOUR_FALLBACK = os.environ.get("ENABLE_PLATE_CONTOUR_FALLBACK", "false").lower() == "true"
ENABLE_VEHICLE_PLATE_INFERENCE = os.environ.get("ENABLE_VEHICLE_PLATE_INFERENCE", "true").lower() == "true"
PLATE_REDACTION_STRATEGY = os.environ.get("PLATE_REDACTION_STRATEGY", "vehicle-first").lower()
FORCE_VEHICLE_REFRESH_EVERY_FRAME = os.environ.get("FORCE_VEHICLE_REFRESH_EVERY_FRAME", "true").lower() == "true"
VEHICLE_TRACK_HOLD_FRAMES = max(1, min(60, int(os.environ.get("VEHICLE_TRACK_HOLD_FRAMES", "24"))))
VEHICLE_TRACK_MATCH_IOU = max(0.05, min(0.9, float(os.environ.get("VEHICLE_TRACK_MATCH_IOU", "0.18"))))
LEAD_VEHICLE_MIN_AREA_RATIO = max(0.001, min(0.08, float(os.environ.get("LEAD_VEHICLE_MIN_AREA_RATIO", "0.003"))))
LEAD_VEHICLE_MAX_CENTER_OFFSET = max(0.10, min(0.90, float(os.environ.get("LEAD_VEHICLE_MAX_CENTER_OFFSET", "0.42"))))
PLATE_TRACK_HOLD_FRAMES = max(0, min(45, int(os.environ.get("PLATE_TRACK_HOLD_FRAMES", "18"))))
PLATE_TRACK_MATCH_IOU = max(0.05, min(0.9, float(os.environ.get("PLATE_TRACK_MATCH_IOU", "0.20"))))
PLATE_RED_GLARE_PIXEL_RATIO = max(0.0, min(1.0, float(os.environ.get("PLATE_RED_GLARE_PIXEL_RATIO", "0.08"))))
PLATE_TRACK_SETTINGS_LOCK = threading.Lock()


def _current_plate_tracking_settings() -> dict:
    with PLATE_TRACK_SETTINGS_LOCK:
        return {
            "holdFrames": int(PLATE_TRACK_HOLD_FRAMES),
            "matchIou": float(PLATE_TRACK_MATCH_IOU),
            "redGlarePixelRatio": float(PLATE_RED_GLARE_PIXEL_RATIO),
        }


def _job_state_path(job_id: str) -> Path:
    return JOB_STATE_DIR / f"{job_id}.json"


def _persist_job_state(job_id: str, job: dict):
    state_file = _job_state_path(job_id)
    temp_file = state_file.with_suffix(".tmp")
    temp_file.write_text(json.dumps(job), encoding="utf-8")
    temp_file.replace(state_file)


def _get_job_state(job_id: str) -> dict | None:
    with jobs_lock:
        cached = jobs.get(job_id)
    if cached is not None:
        return cached

    state_file = _job_state_path(job_id)
    if not state_file.exists():
        return None

    try:
        loaded = json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return None

    with jobs_lock:
        jobs[job_id] = loaded
    return loaded


def _update_job_state(job_id: str, **updates):
    with jobs_lock:
        current = jobs.get(job_id)
        if current is None:
            state_file = _job_state_path(job_id)
            if state_file.exists():
                try:
                    current = json.loads(state_file.read_text(encoding="utf-8"))
                except Exception:
                    current = {}
            else:
                current = {}

        current.update(updates)
        jobs[job_id] = current
        snapshot = dict(current)

    _persist_job_state(job_id, snapshot)
    return snapshot


def _read_all_job_states() -> list[dict]:
    seen = set()
    results: list[dict] = []

    with jobs_lock:
        for jid, job in jobs.items():
            seen.add(jid)
            results.append(dict(job))

    for state_file in JOB_STATE_DIR.glob("*.json"):
        jid = state_file.stem
        if jid in seen:
            continue
        try:
            loaded = json.loads(state_file.read_text(encoding="utf-8"))
            results.append(loaded)
        except Exception:
            continue

    return results


def _local_load_metrics(instance_name: str | None = None) -> dict:
    all_jobs = _read_all_job_states()
    active = [j for j in all_jobs if j.get("state") in {"queued", "processing"}]
    processing = [j for j in active if j.get("state") == "processing"]
    queued = [j for j in active if j.get("state") == "queued"]
    avg_progress = 0.0
    if processing:
        avg_progress = round(sum(float(j.get("progress", 0.0)) for j in processing) / len(processing), 2)

    return {
        "instance": instance_name or INSTANCE_NAME,
        "activeJobs": len(active),
        "queuedJobs": len(queued),
        "processingJobs": len(processing),
        "avgProgress": avg_progress,
        "timestamp": int(time.time()),
    }


def _infer_peer_endpoints(current_base: str, max_instances: int = 10) -> list[str]:
    parsed = urlparse(current_base)
    if not parsed.scheme or not parsed.netloc:
        return []

    host = parsed.netloc.split(":", 1)[0]
    match = re.match(r"^(.*-)(\d+)(\..+)$", host)
    if not match:
        return []

    prefix = match.group(1)
    suffix = match.group(3)
    endpoints = []
    for idx in range(1, max_instances + 1):
        endpoint = f"{parsed.scheme}://{prefix}{idx}{suffix}".rstrip("/")
        if endpoint != current_base:
            endpoints.append(endpoint)
    return endpoints


def _candidate_score(candidate: dict) -> tuple:
    return (
        int(candidate.get("activeJobs", 9999)),
        int(candidate.get("queuedJobs", 9999)),
        float(candidate.get("avgProgress", 0.0)),
    )


def _fetch_remote_load(endpoint: str) -> dict:
    parsed = urlparse(endpoint)
    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else endpoint
    res = requests.get(f"{base}/api/load", timeout=3, verify=False)
    if res.status_code != 200:
        raise RuntimeError(f"Load probe failed ({res.status_code})")
    payload = res.json()
    if payload.get("status") != "ok":
        raise RuntimeError(payload.get("message", "Load probe failed"))
    data = payload.get("load", {})
    data["endpoint"] = base
    return data


def _resolve_available_cluster_endpoints(current_base: str) -> list[str]:
    endpoints = [current_base]

    if PEER_ENDPOINTS:
        for peer in PEER_ENDPOINTS:
            if peer and peer not in endpoints:
                endpoints.append(peer)
    else:
        for peer in _infer_peer_endpoints(current_base, max_instances=MAX_DISTRIBUTED_CONTAINERS):
            if peer not in endpoints:
                endpoints.append(peer)

    candidates = []
    for endpoint in endpoints:
        try:
            if endpoint == current_base:
                local = _local_load_metrics()
                local["endpoint"] = endpoint
                candidates.append(local)
            else:
                candidates.append(_fetch_remote_load(endpoint))
        except Exception:
            continue

    if not candidates:
        return [current_base]

    candidates.sort(key=_candidate_score)
    return [c["endpoint"] for c in candidates if c.get("endpoint")]


def _choose_shard_count(frame_count: int, available_containers: int) -> int:
    if available_containers <= 1:
        return 1
    if frame_count <= 0:
        return 1

    by_workload = max(1, int(np.ceil(frame_count / float(MIN_FRAMES_PER_SHARD))))
    return max(1, min(available_containers, MAX_DISTRIBUTED_CONTAINERS, by_workload))

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
    color: tuple[int, int, int]


def _detection_color(label: str) -> tuple[int, int, int]:
    palette = {
        "car": (0, 220, 255),
        "truck": (0, 140, 255),
        "pedestrian": (0, 255, 120),
        "street sign": (255, 170, 0),
        "motorcycle": (180, 255, 0),
        "cycle": (180, 255, 0),
        "license plate": (255, 255, 255),
    }
    return palette.get(label, (0, 255, 255))


def _expand_rect(x: int, y: int, w: int, h: int, frame_w: int, frame_h: int, pad_x: int, pad_y: int) -> tuple[int, int, int, int]:
    left = max(0, x - pad_x)
    top = max(0, y - pad_y)
    right = min(frame_w, x + w + pad_x)
    bottom = min(frame_h, y + h + pad_y)
    return left, top, max(0, right - left), max(0, bottom - top)


def _rect_iou(first: Detection, second: Detection) -> float:
    first_x2 = first.x + first.w
    first_y2 = first.y + first.h
    second_x2 = second.x + second.w
    second_y2 = second.y + second.h

    inter_left = max(first.x, second.x)
    inter_top = max(first.y, second.y)
    inter_right = min(first_x2, second_x2)
    inter_bottom = min(first_y2, second_y2)
    inter_w = max(0, inter_right - inter_left)
    inter_h = max(0, inter_bottom - inter_top)
    intersection = inter_w * inter_h
    if intersection <= 0:
        return 0.0

    union = (first.w * first.h) + (second.w * second.h) - intersection
    return intersection / max(union, 1)


def _dedupe_detections(detections: list[Detection], iou_threshold: float = 0.35) -> list[Detection]:
    kept: list[Detection] = []
    for detection in sorted(detections, key=lambda item: item.confidence, reverse=True):
        if any(existing.label == detection.label and _rect_iou(existing, detection) >= iou_threshold for existing in kept):
            continue
        kept.append(detection)
    return kept


def _plate_region_has_red_glare(frame: np.ndarray, detection: Detection, red_glare_threshold: float) -> bool:
    frame_h, frame_w = frame.shape[:2]
    x, y, w, h = _expand_rect(detection.x, detection.y, detection.w, detection.h, frame_w, frame_h, 6, 6)
    if w <= 0 or h <= 0:
        return False

    roi = frame[y:y + h, x:x + w]
    if roi.size == 0:
        return False

    b = roi[:, :, 0].astype(np.int16)
    g = roi[:, :, 1].astype(np.int16)
    r = roi[:, :, 2].astype(np.int16)
    bright_red = (r > 150) & (r > (g + 35)) & (r > (b + 35))
    red_ratio = float(np.count_nonzero(bright_red)) / float(bright_red.size)
    return red_ratio >= red_glare_threshold


def _stabilize_plate_detections(detections: list[Detection], frame: np.ndarray) -> list[Detection]:
    settings = _current_plate_tracking_settings()
    hold_frames = int(settings["holdFrames"])
    match_iou = float(settings["matchIou"])
    red_glare_threshold = float(settings["redGlarePixelRatio"])

    if hold_frames <= 0:
        return _dedupe_detections(detections, iou_threshold=0.2)

    frame_h, frame_w = frame.shape[:2]
    current_shape = (frame_h, frame_w)
    if getattr(worker_state, "plate_track_shape", None) != current_shape:
        worker_state.plate_track_shape = current_shape
        worker_state.plate_track_cache = []

    cache = list(getattr(worker_state, "plate_track_cache", []))
    refreshed_cache: list[dict] = []
    stabilized: list[Detection] = []
    matched_indices: set[int] = set()

    for detection in _dedupe_detections(detections, iou_threshold=0.2):
        best_idx = -1
        best_iou = 0.0

        for idx, cached_entry in enumerate(cache):
            if idx in matched_indices:
                continue
            cached_detection = cached_entry.get("detection")
            if not isinstance(cached_detection, Detection):
                continue
            overlap = _rect_iou(cached_detection, detection)
            if overlap > best_iou:
                best_iou = overlap
                best_idx = idx

        if best_idx >= 0 and best_iou >= match_iou:
            cached_detection = cache[best_idx]["detection"]
            blended = Detection(
                label="license plate",
                confidence=max(detection.confidence, cached_detection.confidence * 0.92),
                x=int(round((cached_detection.x * 0.35) + (detection.x * 0.65))),
                y=int(round((cached_detection.y * 0.35) + (detection.y * 0.65))),
                w=int(round((cached_detection.w * 0.35) + (detection.w * 0.65))),
                h=int(round((cached_detection.h * 0.35) + (detection.h * 0.65))),
                color=detection.color,
            )
            matched_indices.add(best_idx)
            stabilized.append(blended)
            refreshed_cache.append({"detection": blended, "ttl": hold_frames})
            continue

        stabilized.append(detection)
        refreshed_cache.append({"detection": detection, "ttl": hold_frames})

    for idx, cached_entry in enumerate(cache):
        if idx in matched_indices:
            continue
        cached_detection = cached_entry.get("detection")
        if not isinstance(cached_detection, Detection):
            continue

        ttl = int(cached_entry.get("ttl", 0)) - 1
        if _plate_region_has_red_glare(frame, cached_detection, red_glare_threshold):
            ttl = max(ttl, int(cached_entry.get("ttl", 0)))
        if ttl <= 0:
            continue

        carried = Detection(
            label="license plate",
            confidence=max(0.5, cached_detection.confidence * 0.9),
            x=cached_detection.x,
            y=cached_detection.y,
            w=cached_detection.w,
            h=cached_detection.h,
            color=cached_detection.color,
        )
        stabilized.append(carried)
        refreshed_cache.append({"detection": carried, "ttl": ttl})

    worker_state.plate_track_cache = refreshed_cache[:32]
    return _dedupe_detections(stabilized, iou_threshold=0.18)


def _stabilize_vehicle_detections(detections: list[Detection], frame_shape: tuple[int, ...]) -> list[Detection]:
    frame_h, frame_w = frame_shape[:2]
    current_shape = (frame_h, frame_w)
    if getattr(worker_state, "vehicle_track_shape", None) != current_shape:
        worker_state.vehicle_track_shape = current_shape
        worker_state.vehicle_track_cache = []

    cache = list(getattr(worker_state, "vehicle_track_cache", []))
    refreshed_cache: list[dict] = []
    stabilized: list[Detection] = []
    matched_indices: set[int] = set()

    vehicle_detections = [d for d in detections if d.label in {"car", "truck"}]
    for detection in _dedupe_detections(vehicle_detections, iou_threshold=0.28):
        best_idx = -1
        best_iou = 0.0

        for idx, cached_entry in enumerate(cache):
            if idx in matched_indices:
                continue
            cached_detection = cached_entry.get("detection")
            if not isinstance(cached_detection, Detection):
                continue
            overlap = _rect_iou(cached_detection, detection)
            if overlap > best_iou:
                best_iou = overlap
                best_idx = idx

        if best_idx >= 0 and best_iou >= VEHICLE_TRACK_MATCH_IOU:
            cached_detection = cache[best_idx]["detection"]
            blended = Detection(
                label=detection.label,
                confidence=max(detection.confidence, cached_detection.confidence * 0.95),
                x=int(round((cached_detection.x * 0.30) + (detection.x * 0.70))),
                y=int(round((cached_detection.y * 0.30) + (detection.y * 0.70))),
                w=int(round((cached_detection.w * 0.30) + (detection.w * 0.70))),
                h=int(round((cached_detection.h * 0.30) + (detection.h * 0.70))),
                color=detection.color,
            )
            matched_indices.add(best_idx)
            stabilized.append(blended)
            refreshed_cache.append({"detection": blended, "ttl": VEHICLE_TRACK_HOLD_FRAMES})
            continue

        stabilized.append(detection)
        refreshed_cache.append({"detection": detection, "ttl": VEHICLE_TRACK_HOLD_FRAMES})

    for idx, cached_entry in enumerate(cache):
        if idx in matched_indices:
            continue
        cached_detection = cached_entry.get("detection")
        if not isinstance(cached_detection, Detection):
            continue

        ttl = int(cached_entry.get("ttl", 0)) - 1
        if ttl <= 0:
            continue

        carried = Detection(
            label=cached_detection.label,
            confidence=max(0.5, cached_detection.confidence * 0.92),
            x=cached_detection.x,
            y=cached_detection.y,
            w=cached_detection.w,
            h=cached_detection.h,
            color=cached_detection.color,
        )
        stabilized.append(carried)
        refreshed_cache.append({"detection": carried, "ttl": ttl})

    worker_state.vehicle_track_cache = refreshed_cache[:24]
    return _dedupe_detections(stabilized, iou_threshold=0.25)


def _filter_plate_detections_near_vehicles(plates: list[Detection], vehicles: list[Detection]) -> list[Detection]:
    if not vehicles:
        return plates

    kept: list[Detection] = []
    for plate in plates:
        plate_cx = plate.x + (plate.w // 2)
        plate_cy = plate.y + (plate.h // 2)
        for vehicle in vehicles:
            vx1 = vehicle.x
            vy1 = vehicle.y
            vx2 = vehicle.x + vehicle.w
            vy2 = vehicle.y + vehicle.h
            if vx1 <= plate_cx <= vx2 and vy1 <= plate_cy <= vy2:
                kept.append(plate)
                break
    return kept


def _select_primary_lead_vehicle(vehicles: list[Detection], frame_shape: tuple[int, ...]) -> Detection | None:
    if not vehicles:
        return None

    frame_h, frame_w = frame_shape[:2]
    frame_area = max(1, frame_h * frame_w)
    center_x = frame_w / 2.0
    max_center_offset_px = frame_w * LEAD_VEHICLE_MAX_CENTER_OFFSET
    best: Detection | None = None
    best_score = -1e9

    for vehicle in vehicles:
        if vehicle.label not in {"car", "truck"}:
            continue

        area_ratio = (vehicle.w * vehicle.h) / frame_area
        if area_ratio < LEAD_VEHICLE_MIN_AREA_RATIO:
            continue

        vehicle_cx = vehicle.x + (vehicle.w / 2.0)
        vehicle_bottom = vehicle.y + vehicle.h
        center_offset = abs(vehicle_cx - center_x)
        if center_offset > max_center_offset_px:
            continue

        if vehicle_bottom < frame_h * 0.45:
            continue

        center_score = 1.0 - min(1.0, center_offset / max_center_offset_px)
        bottom_score = min(1.0, max(0.0, (vehicle_bottom - (frame_h * 0.45)) / (frame_h * 0.55)))
        score = (area_ratio * 10.0) + (center_score * 2.0) + (bottom_score * 1.2) + float(vehicle.confidence)
        if score > best_score:
            best_score = score
            best = vehicle

    return best


def _blur_region(frame: np.ndarray, detection: Detection, pad_scale: float = 0.18, sigma: int = 30) -> None:
    frame_h, frame_w = frame.shape[:2]
    pad_x = max(4, int(detection.w * pad_scale))
    pad_y = max(4, int(detection.h * pad_scale))
    x, y, w, h = _expand_rect(detection.x, detection.y, detection.w, detection.h, frame_w, frame_h, pad_x, pad_y)
    if w <= 0 or h <= 0:
        return

    # Keep blur localized even when an upstream detector returns an oversized box.
    if detection.label in {"license plate", "street sign", "face"}:
        limits = {
            "license plate": (0.25, 0.15, 0.04),
            "street sign": (0.30, 0.25, 0.08),
            "face": (0.45, 0.45, 0.18),
        }
        max_w_ratio, max_h_ratio, max_area_ratio = limits[detection.label]
        max_w = max(24, int(frame_w * max_w_ratio))
        max_h = max(18, int(frame_h * max_h_ratio))
        max_area = max(432, int(frame_w * frame_h * max_area_ratio))

        new_w = min(w, max_w)
        new_h = min(h, max_h)
        current_area = max(1, new_w * new_h)
        if current_area > max_area:
            scale = math.sqrt(max_area / current_area)
            new_w = max(24, int(new_w * scale))
            new_h = max(18, int(new_h * scale))

        if new_w < w or new_h < h:
            center_x = x + (w // 2)
            center_y = y + (h // 2)
            x = max(0, min(frame_w - new_w, center_x - (new_w // 2)))
            y = max(0, min(frame_h - new_h, center_y - (new_h // 2)))
            w = new_w
            h = new_h

    roi = frame[y:y + h, x:x + w]
    kernel_w = max(15, ((w // 3) * 2) + 1)
    kernel_h = max(15, ((h // 3) * 2) + 1)
    roi[:] = cv2.GaussianBlur(roi, (kernel_w, kernel_h), sigma)


def _draw_detection(frame: np.ndarray, detection: Detection) -> None:
    x1 = detection.x
    y1 = detection.y
    x2 = detection.x + detection.w
    y2 = detection.y + detection.h
    radius = max(6, min(detection.w, detection.h) // 7)
    radius = min(radius, max(6, detection.w // 2), max(6, detection.h // 2))
    color = detection.color
    thickness = 2

    if detection.w < 18 or detection.h < 18:
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, thickness)
    else:
        cv2.line(frame, (x1 + radius, y1), (x2 - radius, y1), color, thickness)
        cv2.line(frame, (x1 + radius, y2), (x2 - radius, y2), color, thickness)
        cv2.line(frame, (x1, y1 + radius), (x1, y2 - radius), color, thickness)
        cv2.line(frame, (x2, y1 + radius), (x2, y2 - radius), color, thickness)
        cv2.ellipse(frame, (x1 + radius, y1 + radius), (radius, radius), 180, 0, 90, color, thickness)
        cv2.ellipse(frame, (x2 - radius, y1 + radius), (radius, radius), 270, 0, 90, color, thickness)
        cv2.ellipse(frame, (x1 + radius, y2 - radius), (radius, radius), 90, 0, 90, color, thickness)
        cv2.ellipse(frame, (x2 - radius, y2 - radius), (radius, radius), 0, 0, 90, color, thickness)

    label = f"{detection.label} {detection.confidence:.2f}"
    label_size, baseline = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.58, 2)
    label_left = max(0, x1)
    label_top = max(0, y1 - label_size[1] - baseline - 10)
    label_right = min(frame.shape[1], label_left + label_size[0] + 12)
    label_bottom = min(frame.shape[0], label_top + label_size[1] + baseline + 10)
    cv2.rectangle(frame, (label_left, label_top), (label_right, label_bottom), color, -1)
    cv2.putText(
        frame,
        label,
        (label_left + 6, label_bottom - baseline - 4),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.58,
        (15, 24, 32),
        2,
        cv2.LINE_AA,
    )


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
    if area > 28000 and aspect > 1.8:
        label = "truck"
    elif area > 9000 and 0.9 <= aspect <= 3.2:
        label = "car"
    elif area < 12000 and aspect < 1.25:
        label = "motorcycle"
    else:
        label = "cycle"

    confidence = min(0.97, max(0.5, (area / max(frame_area, 1)) * 42))
    return Detection(label=label, confidence=confidence, x=x, y=y, w=w, h=h, color=_detection_color(label))


def _detect_vehicle_candidates(frame: np.ndarray) -> list[Detection]:
    original_h, original_w = frame.shape[:2]
    work_frame = frame
    scale = 1.0

    # Downscale only very large frames to keep distant vehicle detail.
    if original_w > 1280:
        scale = 1280.0 / original_w
        work_frame = cv2.resize(frame, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    gray = cv2.cvtColor(work_frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    blurred = cv2.GaussianBlur(gray, (7, 7), 0)
    edges = cv2.Canny(blurred, 50, 150)
    kernel = np.ones((3, 3), np.uint8)
    edges = cv2.morphologyEx(edges, cv2.MORPH_CLOSE, kernel, iterations=1)
    edges = cv2.dilate(edges, kernel, iterations=1)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    detections: list[Detection] = []
    frame_area = original_h * original_w
    for contour in contours:
        area = cv2.contourArea(contour)
        if area < 600:
            continue
        x, y, w, h = cv2.boundingRect(contour)
        if w < 24 or h < 16:
            continue
        aspect = w / max(h, 1)
        if not (0.65 <= aspect <= 5.5):
            continue

        if scale != 1.0:
            x = int(x / scale)
            y = int(y / scale)
            w = int(w / scale)
            h = int(h / scale)

        detections.append(_classify_vehicle(x, y, w, h, frame_area))

    detections.sort(key=lambda d: d.confidence, reverse=True)
    return _dedupe_detections(detections[:20], iou_threshold=0.2)


def _detect_pedestrian_candidates(frame: np.ndarray, people_detector: cv2.HOGDescriptor) -> list[Detection]:
    original_h, original_w = frame.shape[:2]
    work_frame = frame
    scale = 1.0

    if original_w > 960:
        scale = 960.0 / original_w
        work_frame = cv2.resize(frame, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    rects, weights = people_detector.detectMultiScale(work_frame, winStride=(8, 8), padding=(8, 8), scale=1.05)
    detections: list[Detection] = []
    flattened_weights = weights.flatten().tolist() if len(weights) else []
    for index, (x, y, w, h) in enumerate(rects):
        if h < int(w * 1.35) or w < 24 or h < 60:
            continue

        confidence = flattened_weights[index] if index < len(flattened_weights) else 0.65
        if scale != 1.0:
            x = int(x / scale)
            y = int(y / scale)
            w = int(w / scale)
            h = int(h / scale)

        detections.append(
            Detection(
                label="pedestrian",
                confidence=min(0.98, max(0.55, float(confidence) / 2.5)),
                x=x,
                y=y,
                w=w,
                h=h,
                color=_detection_color("pedestrian"),
            )
        )

    return _dedupe_detections(detections[:8], iou_threshold=0.32)


def _detect_street_sign_candidates(frame: np.ndarray) -> list[Detection]:
    original_h, original_w = frame.shape[:2]
    work_frame = frame
    scale = 1.0

    if original_w > 960:
        scale = 960.0 / original_w
        work_frame = cv2.resize(frame, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    hsv = cv2.cvtColor(work_frame, cv2.COLOR_BGR2HSV)
    red_mask = cv2.inRange(hsv, (0, 80, 70), (10, 255, 255)) | cv2.inRange(hsv, (170, 80, 70), (180, 255, 255))
    blue_mask = cv2.inRange(hsv, (90, 70, 70), (135, 255, 255))
    yellow_mask = cv2.inRange(hsv, (15, 70, 70), (40, 255, 255))
    mask = red_mask | blue_mask | yellow_mask
    kernel = np.ones((5, 5), np.uint8)
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel, iterations=2)
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel, iterations=1)

    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    detections: list[Detection] = []
    frame_area = original_h * original_w
    max_sign_area = frame_area * 0.12
    for contour in contours:
        area = cv2.contourArea(contour)
        if area < 180:
            continue

        perimeter = cv2.arcLength(contour, True)
        if perimeter <= 0:
            continue

        approx = cv2.approxPolyDP(contour, 0.04 * perimeter, True)
        circularity = float((4 * np.pi * area) / max(perimeter * perimeter, 1.0))
        x, y, w, h = cv2.boundingRect(contour)
        aspect = w / max(h, 1)
        if w < 18 or h < 18 or not (0.65 <= aspect <= 1.35):
            continue
        if (w * h) > max_sign_area:
            continue
        if circularity < 0.42 and not (3 <= len(approx) <= 8):
            continue

        if scale != 1.0:
            x = int(x / scale)
            y = int(y / scale)
            w = int(w / scale)
            h = int(h / scale)
            area = area / (scale * scale)

        confidence = min(0.95, max(0.52, (area / max(frame_area, 1)) * 65))
        detections.append(
            Detection(
                label="street sign",
                confidence=confidence,
                x=x,
                y=y,
                w=w,
                h=h,
                color=_detection_color("street sign"),
            )
        )

    return _dedupe_detections(detections[:10], iou_threshold=0.28)


def _detect_license_plate_candidates(gray: np.ndarray, plate_cascade) -> list[Detection]:
    frame_h, frame_w = gray.shape[:2]
    frame_area = max(1, frame_h * frame_w)
    detections: list[Detection] = []

    if plate_cascade is not False:
        plates = plate_cascade.detectMultiScale(gray, scaleFactor=1.05, minNeighbors=3, minSize=(24, 18))
        for (x, y, w, h) in plates:
            aspect = w / max(h, 1)
            if not (1.7 <= aspect <= 6.4):
                continue
            if w > int(frame_w * 0.20) or h > int(frame_h * 0.10):
                continue
            if (w * h) > int(frame_area * 0.02):
                continue
            if y < int(frame_h * 0.08) or (y + h) > int(frame_h * 0.96):
                continue
            detections.append(
                Detection(
                    label="license plate",
                    confidence=0.84,
                    x=x,
                    y=y,
                    w=w,
                    h=h,
                    color=_detection_color("license plate"),
                )
            )

    if ENABLE_PLATE_CONTOUR_FALLBACK:
        blackhat = cv2.morphologyEx(gray, cv2.MORPH_BLACKHAT, np.ones((5, 17), np.uint8))
        grad_x = cv2.Sobel(blackhat, cv2.CV_32F, 1, 0, ksize=3)
        grad_x = cv2.convertScaleAbs(grad_x)
        grad_x = cv2.GaussianBlur(grad_x, (5, 5), 0)
        _, thresh = cv2.threshold(grad_x, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        thresh = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, np.ones((5, 19), np.uint8), iterations=2)
        thresh = cv2.dilate(thresh, np.ones((3, 3), np.uint8), iterations=1)

        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for contour in contours:
            area = cv2.contourArea(contour)
            if area < 280:
                continue
            x, y, w, h = cv2.boundingRect(contour)
            aspect = w / max(h, 1)
            if w < 34 or h < 12 or y < int(frame_h * 0.08) or not (1.8 <= aspect <= 6.4):
                continue
            if w > int(frame_w * 0.16) or h > int(frame_h * 0.08):
                continue
            if (w * h) > int(frame_area * 0.015):
                continue
            detections.append(
                Detection(
                    label="license plate",
                    confidence=0.72,
                    x=x,
                    y=y,
                    w=w,
                    h=h,
                    color=_detection_color("license plate"),
                )
            )

    return _dedupe_detections(detections, iou_threshold=0.22)


def _infer_plate_regions_from_vehicles(detections: list[Detection], frame_shape: tuple[int, ...]) -> list[Detection]:
    frame_h, frame_w = frame_shape[:2]
    inferred: list[Detection] = []
    for detection in detections:
        if detection.label not in {"car", "truck"}:
            continue
        plate_w = min(max(20, int(detection.w * 0.30)), max(20, int(frame_w * 0.20)))
        plate_h = min(max(12, int(detection.h * 0.11)), max(12, int(frame_h * 0.08)))
        plate_x = detection.x + int((detection.w - plate_w) * 0.5)
        plate_y = detection.y + int(detection.h * 0.70)
        plate_x, plate_y, plate_w, plate_h = _expand_rect(plate_x, plate_y, plate_w, plate_h, frame_w, frame_h, 2, 2)
        inferred.append(
            Detection(
                label="license plate",
                confidence=max(0.66, detection.confidence - 0.05),
                x=plate_x,
                y=plate_y,
                w=plate_w,
                h=plate_h,
                color=_detection_color("license plate"),
            )
        )
    return inferred


def _get_detectors():
    face_cascade = getattr(worker_state, "face_cascade", None)
    plate_cascade = getattr(worker_state, "plate_cascade", None)
    if face_cascade is None:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        worker_state.face_cascade = face_cascade
    if plate_cascade is None:
        plate_path = cv2.data.haarcascades + "haarcascade_russian_plate_number.xml"
        plate_cascade = cv2.CascadeClassifier(plate_path) if os.path.exists(plate_path) else False
        worker_state.plate_cascade = plate_cascade
    return face_cascade, plate_cascade


def _process_frame(frame: np.ndarray, run_vehicle_detection: bool) -> np.ndarray:
    face_cascade, plate_cascade = _get_detectors()
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    dynamic_detections = list(getattr(worker_state, "dynamic_detections", []))

    if ENABLE_VEHICLE_PLATE_INFERENCE:
        should_refresh_vehicle_tracks = FORCE_VEHICLE_REFRESH_EVERY_FRAME or run_vehicle_detection
        if should_refresh_vehicle_tracks:
            detected_vehicles = _detect_vehicle_candidates(frame)
            stabilized_vehicles = _stabilize_vehicle_detections(detected_vehicles, frame.shape)
            primary_vehicle = _select_primary_lead_vehicle(stabilized_vehicles, frame.shape)
            dynamic_detections = [primary_vehicle] if primary_vehicle is not None else []
            worker_state.dynamic_detections = dynamic_detections
    elif not ENABLE_VEHICLE_PLATE_INFERENCE:
        dynamic_detections = []

    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
    for (x, y, w, h) in faces:
        _blur_region(frame, Detection("face", 1.0, x, y, w, h, (255, 255, 255)), pad_scale=0.12, sigma=30)

    direct_plate_detections = _detect_license_plate_candidates(gray, plate_cascade)
    inferred_plate_detections: list[Detection] = []
    if ENABLE_VEHICLE_PLATE_INFERENCE:
        inferred_plate_detections = _infer_plate_regions_from_vehicles(dynamic_detections, frame.shape)
        direct_plate_detections = _filter_plate_detections_near_vehicles(direct_plate_detections, dynamic_detections)

    if PLATE_REDACTION_STRATEGY == "vehicle-first" and ENABLE_VEHICLE_PLATE_INFERENCE:
        plate_detections = inferred_plate_detections + direct_plate_detections
    else:
        plate_detections = direct_plate_detections + inferred_plate_detections

    for detection in _stabilize_plate_detections(plate_detections, frame):
        _blur_region(frame, detection, pad_scale=0.28, sigma=32)

    return frame


def _open_video_writer(path: Path, fps: float, width: int, height: int) -> tuple[cv2.VideoWriter, str]:
    for codec in VIDEO_OUTPUT_CODECS:
        writer = cv2.VideoWriter(
            str(path),
            cv2.VideoWriter_fourcc(*codec),
            fps,
            (width, height),
        )
        if writer.isOpened():
            return writer, codec
        writer.release()

    raise RuntimeError("Unable to initialize a video writer with supported codecs.")


def _normalize_video_for_browser(path: Path) -> tuple[bool, str | None]:
    ffmpeg_path = shutil.which("ffmpeg")
    if ffmpeg_path is None:
        return False, "ffmpeg not available"

    normalized_path = path.with_name(f"{path.stem}-normalized{path.suffix}")
    command = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-i",
        str(path),
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-vf",
        "scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p",
        "-movflags",
        "+faststart",
        "-an",
        str(normalized_path),
    ]

    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        normalized_path.replace(path)
        return True, None
    except subprocess.CalledProcessError as exc:
        try:
            normalized_path.unlink(missing_ok=True)
        except Exception:
            pass
        stderr_text = exc.stderr.decode("utf-8", errors="ignore")
        summary = " | ".join(line.strip() for line in stderr_text.splitlines()[-6:] if line.strip())
        return False, summary[:800]


def _resolve_processing_profile(job_profile: str) -> dict:
    return PROCESSING_PROFILE_PRESETS.get(str(job_profile).lower(), PROCESSING_PROFILE_PRESETS["balanced"])


def _runtime_worker_diagnostics(job_profile: str = "balanced") -> dict:
    profile_settings = _resolve_processing_profile(job_profile)
    raw_configured_workers = os.environ.get("PROCESSING_WORKERS", "0")
    configured_workers = int(raw_configured_workers)
    cpu_count = os.cpu_count() or 2
    default_workers = max(1, min(16, cpu_count))
    base_workers = default_workers if configured_workers <= 0 else max(1, min(16, configured_workers))
    worker_count = max(1, min(16, int(round(base_workers * float(profile_settings["worker_factor"])))) )

    return {
        "instanceName": INSTANCE_NAME,
        "jobProfile": job_profile,
        "profileSettings": profile_settings,
        "processId": os.getpid(),
        "cpuCount": cpu_count,
        "rawProcessingWorkers": raw_configured_workers,
        "configuredWorkers": configured_workers,
        "defaultWorkers": default_workers,
        "baseWorkers": base_workers,
        "workerCount": worker_count,
        "plateTracking": _current_plate_tracking_settings(),
    }


def _parse_plate_tracking_value(payload: dict, key: str, cast_type, min_value, max_value):
    if key not in payload:
        return None
    raw = payload.get(key)
    try:
        value = cast_type(raw)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid value for {key}.")
    if value < min_value or value > max_value:
        raise ValueError(f"{key} must be between {min_value} and {max_value}.")
    return value


def _run_video_processing(input_path: Path, output_path: Path, job_profile: str, progress_callback=None) -> dict:
    cap = None
    writer = None
    try:
        cap = cv2.VideoCapture(str(input_path))
        if not cap.isOpened():
            raise RuntimeError("Unable to open uploaded video file.")

        fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 1280)
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 720)

        writer, output_codec = _open_video_writer(output_path, fps, width, height)

        processed_frames = 0
        profile_settings = _resolve_processing_profile(job_profile)

        frame_index = 0
        configured_detect_stride = int(os.environ.get("DETECT_EVERY_N_FRAMES", "1"))
        detect_every_n_frames = max(1, min(12, min(configured_detect_stride, int(profile_settings["detect_stride"]))))

        configured_workers = int(os.environ.get("PROCESSING_WORKERS", "0"))
        default_workers = max(1, min(16, os.cpu_count() or 2))
        base_workers = default_workers if configured_workers <= 0 else max(1, min(16, configured_workers))
        worker_count = max(1, min(16, int(round(base_workers * float(profile_settings["worker_factor"])))) )
        max_inflight = worker_count * 3
        pending: deque = deque()
        started_at = time.time()
        worker_frames = [0] * worker_count
        thread_slots: dict[int, int] = {}
        thread_slots_lock = threading.Lock()

        def process_frame_task(frame_to_process: np.ndarray, should_run_vehicle_detection: bool):
            thread_id = threading.get_ident()
            with thread_slots_lock:
                worker_slot = thread_slots.get(thread_id)
                if worker_slot is None:
                    worker_slot = len(thread_slots)
                    thread_slots[thread_id] = worker_slot
            return _process_frame(frame_to_process, should_run_vehicle_detection), worker_slot

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            reached_eof = False
            while True:
                while not reached_eof and len(pending) < max_inflight:
                    ok, frame = cap.read()
                    if not ok:
                        reached_eof = True
                        break
                    frame_index += 1
                    run_vehicle_detection = (frame_index % detect_every_n_frames) == 0
                    pending.append(executor.submit(process_frame_task, frame, run_vehicle_detection))

                if not pending and reached_eof:
                    break

                processed, worker_slot = pending.popleft().result()
                writer.write(processed)
                processed_frames += 1
                if 0 <= worker_slot < len(worker_frames):
                    worker_frames[worker_slot] += 1
                if progress_callback:
                    progress_callback(processed_frames, frame_count, worker_count, started_at, False, worker_frames.copy())

        if progress_callback:
            progress_callback(processed_frames, frame_count, worker_count, started_at, True, worker_frames.copy())

        if writer is not None:
            writer.release()
            writer = None

        normalized, normalization_error = _normalize_video_for_browser(output_path)

        elapsed = max(time.time() - started_at, 0.001)
        processing_fps = round(processed_frames / elapsed, 2)
        return {
            "processedFrames": processed_frames,
            "totalFrames": frame_count,
            "workerCount": worker_count,
            "workerProgress": worker_frames,
            "processingFps": processing_fps,
            "fps": fps,
            "width": width,
            "height": height,
            "outputCodec": output_codec,
            "normalizedForBrowser": normalized,
            "normalizationError": normalization_error,
        }
    finally:
        if cap is not None:
            cap.release()
        if writer is not None:
            writer.release()


def _split_video_into_segments(input_path: Path, segment_dir: Path, segment_count: int) -> tuple[list[Path], dict]:
    cap = cv2.VideoCapture(str(input_path))
    if not cap.isOpened():
        raise RuntimeError("Unable to open uploaded video file.")

    fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 1280)
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 720)

    if segment_count <= 1 or frame_count <= 0:
        cap.release()
        return [input_path], {"fps": fps, "width": width, "height": height, "frameCount": frame_count}

    segment_dir.mkdir(parents=True, exist_ok=True)
    base = frame_count // segment_count
    remainder = frame_count % segment_count
    frames_per_segment = [(base + (1 if i < remainder else 0)) for i in range(segment_count)]
    frames_per_segment = [count for count in frames_per_segment if count > 0]

    segments: list[Path] = []
    for idx, target_frames in enumerate(frames_per_segment):
        segment_path = segment_dir / f"segment-{idx:03d}.mp4"
        writer, _ = _open_video_writer(segment_path, fps, width, height)

        written = 0
        while written < target_frames:
            ok, frame = cap.read()
            if not ok:
                break
            writer.write(frame)
            written += 1

        writer.release()
        if written > 0 and segment_path.exists() and segment_path.stat().st_size > 0:
            segments.append(segment_path)

        if written < target_frames:
            break

    cap.release()
    if not segments:
        return [input_path], {"fps": fps, "width": width, "height": height, "frameCount": frame_count}

    return segments, {"fps": fps, "width": width, "height": height, "frameCount": frame_count}


def _read_video_metadata(input_path: Path) -> dict:
    cap = cv2.VideoCapture(str(input_path))
    if not cap.isOpened():
        raise RuntimeError("Unable to open uploaded video file.")
    try:
        return {
            "fps": cap.get(cv2.CAP_PROP_FPS) or 24.0,
            "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 1280),
            "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 720),
            "frameCount": int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0),
        }
    finally:
        cap.release()


def _merge_processed_segments(segment_outputs: list[Path], output_path: Path, fps: float, width: int, height: int):
    writer, _ = _open_video_writer(output_path, fps, width, height)
    try:
        for segment in segment_outputs:
            cap = cv2.VideoCapture(str(segment))
            if not cap.isOpened():
                raise RuntimeError(f"Unable to read processed segment: {segment.name}")

            try:
                while True:
                    ok, frame = cap.read()
                    if not ok:
                        break
                    writer.write(frame)
            finally:
                cap.release()
    finally:
        writer.release()


def _download_processed_segment(endpoint: str, output_url: str, destination: Path):
    target = f"{endpoint}{output_url}"
    response = requests.get(target, stream=True, timeout=REMOTE_SEGMENT_TIMEOUT_SECONDS, verify=False)
    if response.status_code != 200:
        raise RuntimeError(f"Segment download failed ({response.status_code}) from {target}")

    with destination.open("wb") as handle:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                handle.write(chunk)


def _process_segment_remote(endpoint: str, segment_input: Path, segment_output: Path, profile: str) -> dict:
    with segment_input.open("rb") as source:
        response = requests.post(
            f"{endpoint}/api/internal/process-segment",
            headers={"X-AMV-Internal-Request": "1"},
            files={"video": (segment_input.name, source, "video/mp4")},
            data={"profile": profile},
            timeout=REMOTE_SEGMENT_TIMEOUT_SECONDS,
            verify=False,
        )

    if response.status_code != 200:
        raise RuntimeError(f"Remote segment processing failed ({response.status_code}) on {endpoint}")

    payload = response.json()
    if payload.get("status") != "ok":
        raise RuntimeError(payload.get("message", f"Remote segment processing failed on {endpoint}"))

    output_url = payload.get("outputUrl")
    if not output_url:
        raise RuntimeError(f"Remote segment output URL missing from {endpoint}")

    _download_processed_segment(endpoint, output_url, segment_output)
    payload["endpoint"] = endpoint
    return payload


def _process_video_distributed(job_id: str, input_path: Path, output_path: Path, current_base: str):
    if not ENABLE_DISTRIBUTED_PROCESSING:
        return None

    job = _get_job_state(job_id) or {}
    profile = str(job.get("profile", "balanced")).lower()

    available_endpoints = _resolve_available_cluster_endpoints(current_base)
    available_endpoints = available_endpoints[:MAX_DISTRIBUTED_CONTAINERS]
    if not available_endpoints:
        available_endpoints = [current_base]

    segment_dir = PROCESSED_DIR / f"segments-{job_id}"
    meta = _read_video_metadata(input_path)

    shard_count = _choose_shard_count(int(meta.get("frameCount") or 0), len(available_endpoints))
    if shard_count <= 1:
        return None

    segments, meta = _split_video_into_segments(input_path, segment_dir, shard_count)
    if len(segments) <= 1:
        return None

    active_endpoints = available_endpoints[:max(1, min(len(available_endpoints), len(segments)))]
    assignments = [active_endpoints[idx % len(active_endpoints)] for idx in range(len(segments))]
    output_segments = [segment_dir / f"processed-{idx:03d}.mp4" for idx in range(len(segments))]

    _update_job_state(
        job_id,
        state="processing",
        distributed=True,
        shardCount=len(segments),
        containerCount=len(set(assignments)),
        progress=2.0,
        message=f"Distributed processing started across {len(set(assignments))} containers for {len(segments)} segments.",
    )

    worker_total = 0
    completed = 0
    with ThreadPoolExecutor(max_workers=len(segments)) as executor:
        futures = {}
        for idx, segment_path in enumerate(segments):
            endpoint = assignments[idx]
            destination = output_segments[idx]
            if endpoint == current_base:
                futures[executor.submit(_run_video_processing, segment_path, destination, profile, None)] = idx
            else:
                futures[executor.submit(_process_segment_remote, endpoint, segment_path, destination, profile)] = idx

        for future in as_completed(futures):
            result = future.result()
            if isinstance(result, dict):
                worker_total += int(result.get("workerCount") or result.get("worker_count") or 0)
            completed += 1
            progress = min(95.0, round((completed / len(segments)) * 93.0 + 2.0, 2))
            _update_job_state(
                job_id,
                state="processing",
                progress=progress,
                message=f"Distributed processing completed {completed}/{len(segments)} segments.",
                shardCount=len(segments),
                containerCount=len(set(assignments)),
            )

    _merge_processed_segments(
        output_segments,
        output_path,
        float(meta.get("fps") or 24.0),
        int(meta.get("width") or 1280),
        int(meta.get("height") or 720),
    )

    _update_job_state(
        job_id,
        state="completed",
        progress=100,
        message=f"Distributed processing complete across {len(set(assignments))} containers.",
        outputUrl=f"/processed/{output_path.name}",
        processingWorkers=worker_total,
        distributed=True,
    )

    for segment_path in segments:
        try:
            segment_path.unlink(missing_ok=True)
        except Exception:
            pass
    for segment_path in output_segments:
        try:
            segment_path.unlink(missing_ok=True)
        except Exception:
            pass
    try:
        segment_dir.rmdir()
    except Exception:
        pass
    return True


def _process_video(job_id: str, input_path: Path, output_path: Path, current_base: str):
    last_status_update = 0.0
    job_profile = str((_get_job_state(job_id) or {}).get("profile", "balanced")).lower()

    try:
        def _update_progress(
            processed_frames: int,
            frame_count: int,
            worker_count: int,
            started_at: float,
            force: bool,
            worker_progress: list[int] | None = None,
        ):
            nonlocal last_status_update
            now = time.time()
            if not force and now - last_status_update < 5:
                return

            percent = 0.0 if frame_count == 0 else round((processed_frames / frame_count) * 100.0, 2)
            elapsed = max(now - started_at, 0.001)
            processing_fps = round(processed_frames / elapsed, 2)
            eta_seconds = None
            if frame_count > 0 and processed_frames > 0 and processing_fps > 0:
                eta_seconds = int(max((frame_count - processed_frames) / processing_fps, 0))

            eta_message = ""
            if eta_seconds is not None:
                eta_message = f" | ETA {eta_seconds // 60:02d}:{eta_seconds % 60:02d}"

            _update_job_state(
                job_id,
                state="processing",
                progress=min(percent, 99.99),
                processedFrames=processed_frames,
                totalFrames=frame_count,
                lastUpdated=int(now),
                processingWorkers=worker_count,
                workerProgress=worker_progress or [0] * max(worker_count, 1),
                processingFps=processing_fps,
                etaSeconds=eta_seconds,
                message=f"Processing frame {processed_frames} of {frame_count or '?'} using {worker_count} workers{eta_message}",
            )
            last_status_update = now

        stats = _run_video_processing(input_path, output_path, job_profile, progress_callback=_update_progress)
        _update_job_state(
            job_id,
            state="completed",
            progress=100,
            message="Processing complete. Video is ready for secure playback.",
            outputUrl=f"/processed/{output_path.name}",
            outputCodec=stats.get("outputCodec"),
            normalizedForBrowser=bool(stats.get("normalizedForBrowser")),
            normalizationError=stats.get("normalizationError"),
            workerProgress=stats.get("workerProgress", []),
            distributed=False,
        )
    except Exception as exc:
        _update_job_state(job_id, state="failed", message=f"Processing failed: {exc}")


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/attestation/check")
def attestation_check():
    body = request.get_json(silent=True) or {}
    maa_endpoint = body.get("maaEndpoint", os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net"))
    if maa_endpoint.startswith("https://"):
        maa_endpoint = maa_endpoint.replace("https://", "")

    # SKR expects runtime_data as base64-encoded content.
    runtime_payload = base64.b64encode(json.dumps({"source": "upload-gate"}).encode("utf-8")).decode("ascii")

    try:
        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_endpoint, "runtime_data": runtime_payload},
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
    except Exception:
        app.logger.exception("Attestation check failed")
        return jsonify({"status": "failed", "message": "Attestation check could not be completed."}), 500


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


@app.post("/api/internal/process-segment")
def process_segment_internal():
    if request.headers.get("X-AMV-Internal-Request") != "1":
        return jsonify({"status": "failed", "message": "Internal endpoint requires X-AMV-Internal-Request header."}), 403

    if not _secure_request():
        return jsonify({"status": "failed", "message": "HTTPS is required for internal segment processing."}), 400

    if "video" not in request.files:
        return jsonify({"status": "failed", "message": "No segment file provided."}), 400

    segment_file = request.files["video"]
    filename = secure_filename(segment_file.filename or "segment.mp4")
    if not filename.lower().endswith(".mp4"):
        return jsonify({"status": "failed", "message": "Only .mp4 segment files are accepted."}), 400

    profile = str(request.form.get("profile", "balanced")).lower()
    if profile not in PROCESSING_PROFILE_PRESETS:
        profile = "balanced"

    segment_id = uuid.uuid4().hex
    input_path = UPLOAD_DIR / f"segment-in-{segment_id}-{filename}"
    output_path = PROCESSED_DIR / f"segment-out-{segment_id}.mp4"
    segment_file.save(input_path)

    try:
        stats = _run_video_processing(input_path, output_path, profile, progress_callback=None)
        return jsonify(
            {
                "status": "ok",
                "outputUrl": f"/processed/{output_path.name}",
                "workerCount": stats.get("workerCount", 0),
                "processedFrames": stats.get("processedFrames", 0),
            }
        )
    except Exception as exc:
        return jsonify({"status": "failed", "message": f"Segment processing failed: {exc}"}), 500
    finally:
        try:
            input_path.unlink(missing_ok=True)
        except Exception:
            pass


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

    requested_profile = str(request.form.get("profile", "balanced")).lower()
    if requested_profile not in PROCESSING_PROFILE_PRESETS:
        requested_profile = "balanced"

    job_id = uuid.uuid4().hex
    input_path = UPLOAD_DIR / f"{job_id}-{filename}"
    output_path = PROCESSED_DIR / f"processed-{job_id}.mp4"
    file.save(input_path)

    _update_job_state(
        job_id,
        state="queued",
        progress=0,
        message="Queued for processing inside the confidential container.",
        processedFrames=0,
        totalFrames=0,
        workerProgress=[],
        profile=requested_profile,
    )

    current_base = request.url_root.rstrip("/")
    thread = threading.Thread(target=_process_video, args=(job_id, input_path, output_path, current_base), daemon=True)
    thread.start()

    return jsonify({"status": "ok", "jobId": job_id})


@app.get("/api/status/<job_id>")
def job_status(job_id: str):
    job = _get_job_state(job_id)
    if not job:
        return jsonify({"status": "failed", "message": "Unknown job ID."}), 404
    return jsonify({"status": "ok", "job": job})


@app.get("/api/load")
def api_load():
    instance = request.host.split(":", 1)[0] if request.host else INSTANCE_NAME
    return jsonify({"status": "ok", "load": _local_load_metrics(instance_name=instance)})


@app.get("/api/debug/runtime")
def api_debug_runtime():
    profile = str(request.args.get("profile", "balanced")).lower()
    if profile not in PROCESSING_PROFILE_PRESETS:
        profile = "balanced"
    return jsonify({"status": "ok", "runtime": _runtime_worker_diagnostics(profile)})


@app.get("/api/settings/plate-tracking")
def api_get_plate_tracking_settings():
    return jsonify({"status": "ok", "settings": _current_plate_tracking_settings()})


@app.post("/api/settings/plate-tracking")
def api_update_plate_tracking_settings():
    payload = request.get_json(silent=True) or {}

    try:
        hold_frames = _parse_plate_tracking_value(payload, "holdFrames", int, 0, 45)
        match_iou = _parse_plate_tracking_value(payload, "matchIou", float, 0.05, 0.9)
    except ValueError as exc:
        return jsonify({"status": "failed", "message": str(exc)}), 400

    global PLATE_TRACK_HOLD_FRAMES, PLATE_TRACK_MATCH_IOU
    with PLATE_TRACK_SETTINGS_LOCK:
        if hold_frames is not None:
            PLATE_TRACK_HOLD_FRAMES = hold_frames
        if match_iou is not None:
            PLATE_TRACK_MATCH_IOU = match_iou

    return jsonify({"status": "ok", "settings": _current_plate_tracking_settings()})


@app.get("/processed/<path:filename>")
def get_processed_file(filename: str):
    response = send_from_directory(
        PROCESSED_DIR,
        filename,
        as_attachment=False,
        mimetype="video/mp4",
        conditional=True,
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Accept-Ranges"] = "bytes"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
