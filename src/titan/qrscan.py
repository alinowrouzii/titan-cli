"""Read a QR image. zbarimg if present, otherwise the macOS scanner."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from titan.auth import AuthError
from titan.config import INSTALL_HINT

_SWIFT = Path(__file__).with_name("qrscan.swift")


def read_qr_payload(path: Path) -> str:
    raw = path.read_bytes()
    if not _is_image(path, raw):
        return raw.decode("utf-8")
    if shutil.which("zbarimg"):
        return _run(["zbarimg", "-q", "--raw", str(path)])
    if sys.platform == "darwin" and _SWIFT.is_file():
        return _run([str(_scanner_bin()), str(path)])
    raise AuthError("cannot scan that image.\n" + INSTALL_HINT)


def _scanner_bin() -> Path:
    cache = Path.home() / ".cache" / "titan"
    cache.mkdir(parents=True, exist_ok=True)
    binary = cache / "qrscan"
    source_time = _SWIFT.stat().st_mtime
    if binary.is_file() and binary.stat().st_mtime >= source_time:
        return binary
    result = subprocess.run(
        ["swiftc", "-O", "-o", str(binary), str(_SWIFT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AuthError((detail or "could not build the QR scanner") + "\n" + INSTALL_HINT)
    return binary


def _is_image(path: Path, raw: bytes) -> bool:
    if raw.startswith(b"\x89PNG") or raw.startswith(b"\xff\xd8") or raw.startswith(b"GIF8"):
        return True
    return path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".heic", ".gif"}


def _run(command: list) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except subprocess.TimeoutExpired as exc:
        raise AuthError("QR scan timed out") from exc
    if result.returncode != 0 or not result.stdout.strip():
        detail = (result.stderr or result.stdout).strip()
        raise AuthError((detail or "could not read QR") + "\n" + INSTALL_HINT)
    return result.stdout.strip()
