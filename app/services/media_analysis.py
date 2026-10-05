import base64
import json
import os
import struct
import uuid
from datetime import datetime
from pathlib import Path

from app.database import calculate_sha256

UPLOAD_DIR = Path("data") / "evidence_uploads"


def _safe_filename(filename):
    base = os.path.basename(filename or "evidence-upload")
    cleaned = "".join(
        char if char.isalnum() or char in {".", "-", "_"} else "_"
        for char in base
    ).strip("._")
    return cleaned or "evidence-upload"


def save_base64_upload(filename, content_type, data_base64):
    if not data_base64:
        return None

    if "," in data_base64 and data_base64.split(",", 1)[0].startswith("data:"):
        data_base64 = data_base64.split(",", 1)[1]

    payload = base64.b64decode(data_base64, validate=False)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    safe_name = _safe_filename(filename)
    stored_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}-{safe_name}"
    stored_path = UPLOAD_DIR / stored_name

    with open(stored_path, "wb") as handle:
        handle.write(payload)

    metadata = analyse_media_file(stored_path, content_type)

    return {
        "stored_filename": stored_name,
        "stored_path": str(stored_path),
        "original_filename": filename,
        "content_type": content_type,
        "file_size": len(payload),
        "sha256_hash": calculate_sha256(stored_path),
        "metadata": metadata,
    }


def analyse_media_file(path, content_type=None):
    path = Path(path)
    metadata = {
        "file_size": path.stat().st_size if path.exists() else None,
        "content_type": content_type,
        "image": {},
        "video": {},
        "location": None,
        "face_engine": {
            "enabled": False,
            "identity_recognition": False,
            "message": (
                "Face identity recognition is not enabled. "
                "This build preserves media and metadata for authorised review."
            ),
        },
    }

    try:
        with open(path, "rb") as handle:
            header = handle.read(512 * 1024)
    except OSError as error:
        metadata["error"] = str(error)
        return metadata

    dimensions = _read_image_dimensions(header)
    if dimensions:
        metadata["image"] = dimensions

    gps = _read_jpeg_gps(header)
    if gps:
        metadata["location"] = gps

    if content_type and content_type.startswith("video/"):
        metadata["video"] = {
            "stored_for_review": True,
            "frame_analysis": "not_available_without_video_decoder",
        }

    return metadata


def metadata_to_json(metadata):
    if metadata is None:
        return None
    return json.dumps(metadata, sort_keys=True)


def _read_image_dimensions(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24])
        return {
            "format": "PNG",
            "width": width,
            "height": height,
        }

    if data.startswith(b"\xff\xd8"):
        index = 2
        while index + 9 < len(data):
            if data[index] != 0xFF:
                index += 1
                continue
            marker = data[index + 1]
            index += 2
            if marker in {0xD8, 0xD9}:
                continue
            if index + 2 > len(data):
                break
            segment_length = struct.unpack(">H", data[index:index + 2])[0]
            if marker in range(0xC0, 0xC4) and index + 7 < len(data):
                height, width = struct.unpack(">HH", data[index + 3:index + 7])
                return {
                    "format": "JPEG",
                    "width": width,
                    "height": height,
                }
            index += segment_length

    if data[:6] in {b"GIF87a", b"GIF89a"} and len(data) >= 10:
        width, height = struct.unpack("<HH", data[6:10])
        return {
            "format": "GIF",
            "width": width,
            "height": height,
        }

    return None


def _read_jpeg_gps(data):
    if not data.startswith(b"\xff\xd8"):
        return None

    index = 2
    while index + 4 < len(data):
        if data[index] != 0xFF:
            index += 1
            continue

        marker = data[index + 1]
        index += 2

        if marker == 0xE1 and index + 2 <= len(data):
            length = struct.unpack(">H", data[index:index + 2])[0]
            segment = data[index + 2:index + length]
            if segment.startswith(b"Exif\x00\x00"):
                return _parse_exif_gps(segment[6:])
            index += length
        else:
            if index + 2 > len(data):
                break
            length = struct.unpack(">H", data[index:index + 2])[0]
            index += length

    return None


def _parse_exif_gps(tiff):
    try:
        endian = tiff[:2]
        if endian == b"II":
            order = "<"
        elif endian == b"MM":
            order = ">"
        else:
            return None

        first_ifd = struct.unpack(order + "I", tiff[4:8])[0]
        gps_ifd = None

        for tag, value_type, count, value in _read_ifd_entries(tiff, first_ifd, order):
            if tag == 0x8825:
                gps_ifd = value
                break

        if gps_ifd is None:
            return None

        gps = {}
        for tag, value_type, count, value in _read_ifd_entries(tiff, gps_ifd, order):
            gps[tag] = _read_exif_value(tiff, order, value_type, count, value)

        lat = _gps_coordinate(gps.get(2), gps.get(1))
        lon = _gps_coordinate(gps.get(4), gps.get(3))

        if lat is None or lon is None:
            return None

        return {
            "latitude": lat,
            "longitude": lon,
            "source": "jpeg_exif_gps",
        }
    except Exception:
        return None


def _read_ifd_entries(tiff, offset, order):
    if offset + 2 > len(tiff):
        return []

    total = struct.unpack(order + "H", tiff[offset:offset + 2])[0]
    entries = []
    start = offset + 2

    for i in range(total):
        entry = start + (i * 12)
        if entry + 12 > len(tiff):
            break
        tag, value_type, count, value = struct.unpack(order + "HHII", tiff[entry:entry + 12])
        entries.append((tag, value_type, count, value))

    return entries


def _read_exif_value(tiff, order, value_type, count, value):
    type_sizes = {
        1: 1,
        2: 1,
        3: 2,
        4: 4,
        5: 8,
    }
    size = type_sizes.get(value_type, 1) * count
    raw = value.to_bytes(4, "little" if order == "<" else "big") if size <= 4 else tiff[value:value + size]

    if value_type == 2:
        return raw.rstrip(b"\x00").decode("ascii", errors="ignore")
    if value_type == 5:
        values = []
        for i in range(count):
            chunk = raw[i * 8:(i + 1) * 8]
            numerator, denominator = struct.unpack(order + "II", chunk)
            values.append(numerator / denominator if denominator else 0)
        return values
    return value


def _gps_coordinate(parts, reference):
    if not parts or len(parts) != 3:
        return None
    degrees, minutes, seconds = parts
    value = degrees + (minutes / 60) + (seconds / 3600)
    if reference in {"S", "W"}:
        value = -value
    return round(value, 7)