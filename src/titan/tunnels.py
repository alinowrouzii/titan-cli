"""Named tunnel aliases stored under ~/.config/titan/tunnels.json."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Mapping, Sequence, Tuple

from titan.forward import parse_local_forward, parse_port_pair

ALIAS_RE = re.compile(r"^[a-z0-9_-]+$")
ForwardSpec = Tuple[str, str]


def validate_alias(name: str) -> str:
    if not ALIAS_RE.match(name or ""):
        raise RuntimeError(
            "bad tunnel name: use lowercase letters, digits, _ or -"
        )
    return name


def load_tunnels(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("tunnel file is not readable") from exc
    if not isinstance(data, dict):
        raise RuntimeError("tunnel file is not readable")
    cleaned = {}
    for name, entry in data.items():
        cleaned[validate_alias(str(name))] = _clean_entry(entry)
    return cleaned


def save_tunnels(path: Path, store: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {}
    for name, entry in store.items():
        payload[validate_alias(str(name))] = {
            "target": entry["target"],
            "forwards": [list(pair) for pair in entry["forwards"]],
        }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def get_tunnel(store: Mapping, name: str) -> dict:
    alias = validate_alias(name)
    found = store.get(alias)
    if found is None:
        raise RuntimeError("no tunnel %s" % alias)
    return dict(found)


def set_tunnel(
    store: Mapping,
    name: str,
    target: str,
    forwards: Sequence[ForwardSpec],
) -> dict:
    alias = validate_alias(name)
    target = (target or "").strip()
    if not target:
        raise RuntimeError("tunnel target is empty")
    if not forwards:
        raise RuntimeError("tunnel needs at least one -L or -R")
    cleaned: List[List[str]] = []
    for kind, text in forwards:
        flag = "-L" if kind in ("L", "-L") else "-R"
        _check_forward(flag, text)
        cleaned.append(["L" if flag == "-L" else "R", text])
    copied = dict(store)
    copied[alias] = {"target": target, "forwards": cleaned}
    return copied


def delete_tunnel(store: Mapping, name: str) -> dict:
    alias = validate_alias(name)
    if alias not in store:
        raise RuntimeError("no tunnel %s" % alias)
    copied = dict(store)
    del copied[alias]
    return copied


def to_cli_forwards(entry: Mapping) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for kind, text in entry["forwards"]:
        out.append(("-L" if kind == "L" else "-R", text))
    return out


def format_list(store: Mapping) -> str:
    if not store:
        return "(no tunnels)"
    lines = []
    for name in sorted(store):
        entry = store[name]
        specs = " ".join(
            "%s %s" % ("-L" if kind == "L" else "-R", text)
            for kind, text in entry["forwards"]
        )
        lines.append("%s  %s  %s" % (name, entry["target"], specs))
    return "\n".join(lines)


def format_show(name: str, entry: Mapping) -> str:
    lines = ["name  %s" % name, "target  %s" % entry["target"]]
    for kind, text in entry["forwards"]:
        lines.append("%s  %s" % ("-L" if kind == "L" else "-R", text))
    return "\n".join(lines)


def _clean_entry(entry) -> dict:
    if not isinstance(entry, dict):
        raise RuntimeError("tunnel file is not readable")
    target = entry.get("target")
    forwards = entry.get("forwards")
    if not isinstance(target, str) or not target.strip():
        raise RuntimeError("tunnel file is not readable")
    if not isinstance(forwards, list) or not forwards:
        raise RuntimeError("tunnel file is not readable")
    cleaned: List[List[str]] = []
    for item in forwards:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise RuntimeError("tunnel file is not readable")
        kind, text = item
        if kind not in ("L", "R") or not isinstance(text, str):
            raise RuntimeError("tunnel file is not readable")
        _check_forward("-L" if kind == "L" else "-R", text)
        cleaned.append([kind, text])
    return {"target": target.strip(), "forwards": cleaned}


def _check_forward(flag: str, text: str) -> None:
    try:
        if flag == "-L":
            parse_local_forward(text)
        else:
            parse_port_pair(text)
    except ValueError as exc:
        raise RuntimeError("bad forward spec: %s %s" % (flag, text)) from exc
