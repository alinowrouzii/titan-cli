"""Local TOTP secret and RFC 6238 codes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from titan.auth import AuthError, load_private, save_private


def normalize_secret(text: str) -> str:
    raw = text.strip().strip('"').strip("'")
    if raw.lower().startswith("otpauth://"):
        secret = parse_qs(urlparse(raw).query).get("secret")
        if not secret:
            raise AuthError("otpauth URI has no secret")
        raw = secret[0]
    cleaned = "".join(raw.split()).replace("-", "").upper()
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        base64.b32decode(cleaned + pad, casefold=True)
    except Exception as exc:
        raise AuthError("TOTP secret is not base32") from exc
    if not cleaned:
        raise AuthError("TOTP secret is empty")
    return cleaned


def totp_code(secret: str, when: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = _b32(secret)
    moment = time.time() if when is None else when
    counter = int(moment // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def totp_candidates(secret: str, when: float | None = None) -> list[str]:
    moment = time.time() if when is None else when
    codes = []
    for delta in (0, -30, 30):
        code = totp_code(secret, moment + delta)
        if code not in codes:
            codes.append(code)
    return codes


def save_totp(path: Path, secret: str) -> None:
    save_private(path, (normalize_secret(secret) + "\n").encode("utf-8"))


def load_totp(path: Path) -> str:
    try:
        raw = load_private(path)
    except FileNotFoundError as exc:
        raise AuthError("no TOTP secret. run titan totp set") from exc
    return normalize_secret(raw.decode("utf-8"))


def _b32(secret: str) -> bytes:
    cleaned = normalize_secret(secret)
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + pad, casefold=True)
