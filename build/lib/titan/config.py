"""Host and session location."""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_URL = "https://titan.efarda.ir"

INSTALL_HINT = "\n".join(
    [
        "Mac also needs Xcode command line tools for the QR scanner.",
        "Linux needs zbar-tools (sudo apt install zbar-tools).",
        "Python 3.9 or newer.",
    ]
)


def base_url() -> str:
    return os.environ.get("TITAN_URL", DEFAULT_URL).rstrip("/")


def session_path() -> Path:
    return Path.home() / ".config" / "titan" / "session.json"


def totp_path() -> Path:
    return Path.home() / ".config" / "titan" / "totp"
