"""Login session file and ef.net provider pick."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping


class AuthError(Exception):
    pass


class LdapProvider:
    def __init__(self, provider_id: str, name: str) -> None:
        self.id = provider_id
        self.name = name


def pick_efnet(providers: Iterable[LdapProvider]) -> LdapProvider:
    found = list(providers)
    for provider in found:
        if provider.name == "ef.net":
            return provider
    names = ", ".join(provider.name for provider in found) or "(none)"
    raise AuthError("no LDAP provider named ef.net. providers: %s" % names)


def save_private(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def load_private(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read()


def save_session(path: Path, payload: Mapping[str, Any]) -> None:
    save_private(path, json.dumps(payload).encode("utf-8"))


def delete_paths(paths) -> list:
    removed = []
    parents = []
    for path in paths:
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(path)
            parents.append(path.parent)
    for parent in parents:
        if parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
    return removed


def load_session(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or "token" not in data:
        raise AuthError("session file has no token. run titan login")
    return data
