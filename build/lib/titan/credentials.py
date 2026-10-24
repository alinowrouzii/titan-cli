"""VM username and password store. Logout does not remove this file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence

from titan.auth import AuthError, load_private, save_private


def empty_store() -> dict:
    return {"default": None, "by_id": {}}


def load_credentials(path: Path) -> dict:
    if not path.is_file():
        return empty_store()
    try:
        data = json.loads(load_private(path).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthError("credential file is not readable") from exc
    if not isinstance(data, dict):
        raise AuthError("credential file is not readable")
    default = data.get("default")
    by_id = data.get("by_id") or {}
    if default is not None and not _pair(default):
        raise AuthError("credential file is not readable")
    if not isinstance(by_id, dict):
        raise AuthError("credential file is not readable")
    cleaned = {}
    for access_id, pair in by_id.items():
        if not _pair(pair):
            raise AuthError("credential file is not readable")
        cleaned[str(access_id)] = {
            "username": pair["username"],
            "password": pair["password"],
        }
    return {
        "default": None
        if default is None
        else {"username": default["username"], "password": default["password"]},
        "by_id": cleaned,
    }


def save_credentials(path: Path, store: Mapping) -> None:
    payload = {
        "default": store["default"],
        "by_id": store["by_id"],
    }
    save_private(path, (json.dumps(payload) + "\n").encode("utf-8"))


def credential_for(store: Mapping, access_id: str) -> Optional[dict]:
    found = store["by_id"].get(access_id)
    if found:
        return dict(found)
    default = store["default"]
    if default:
        return dict(default)
    return None


def set_server(store: Mapping, access_id: str, username: str, password: str) -> dict:
    username, password = _require(username, password)
    copied = _copy(store)
    copied["by_id"][access_id] = {"username": username, "password": password}
    return copied


def set_default(store: Mapping, username: str, password: str) -> dict:
    username, password = _require(username, password)
    copied = _copy(store)
    copied["default"] = {"username": username, "password": password}
    return copied


def delete_server(store: Mapping, access_id: str) -> dict:
    copied = _copy(store)
    copied["by_id"].pop(access_id, None)
    return copied


def delete_default(store: Mapping) -> dict:
    copied = _copy(store)
    copied["default"] = None
    return copied


def format_menu(accesses: Sequence, store: Mapping, include_default: bool = True) -> str:
    lines = []
    saved = store["by_id"]
    for index, access in enumerate(accesses, start=1):
        mark = "*" if access.id in saved else " "
        lines.append(
            "%s  %d  %s  %s  %s"
            % (mark, index, access.resource_name, access.resource_ip, access.id)
        )
    if include_default:
        mark = "*" if store["default"] else " "
        lines.append("%s  0  default for every server with no own password" % mark)
    return "\n".join(lines)


def parse_picks(text: str, server_count: int) -> List[int]:
    picks: List[int] = []
    for item in text.replace(",", " ").split():
        if not item.isdigit():
            raise AuthError("type numbers from the list, for example 1,3 or 0")
        number = int(item)
        if number != 0 and not 1 <= number <= server_count:
            raise AuthError("type numbers from the list, for example 1,3 or 0")
        if number not in picks:
            picks.append(number)
    if not picks:
        raise AuthError("type numbers from the list, for example 1,3 or 0")
    return picks


def parse_one_server(text: str, server_count: int) -> int:
    picks = parse_picks(text, server_count)
    if picks != [picks[0]] or picks[0] == 0:
        raise AuthError("type one server number from the list")
    return picks[0]


def apply_picks(
    store: Mapping,
    accesses: Sequence,
    picks: Iterable[int],
    values: Mapping[int, tuple],
) -> dict:
    copied = _copy(store)
    for pick in picks:
        username, password = values[pick]
        if pick == 0:
            copied = set_default(copied, username, password)
        else:
            copied = set_server(copied, accesses[pick - 1].id, username, password)
    return copied


def _require(username: str, password: str) -> tuple:
    username = username.strip()
    if not username or password == "":
        raise AuthError("username and password are both required")
    return username, password


def _pair(value) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("username"), str)
        and isinstance(value.get("password"), str)
        and value["username"] != ""
        and value["password"] != ""
    )


def _copy(store: Mapping) -> dict:
    default = store["default"]
    return {
        "default": None
        if not default
        else {"username": default["username"], "password": default["password"]},
        "by_id": {
            access_id: {"username": pair["username"], "password": pair["password"]}
            for access_id, pair in store["by_id"].items()
        },
    }
