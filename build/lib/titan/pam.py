"""PAM Thrift calls: providers, login, SSH access list."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from titan.accesses import Access
from titan.auth import LdapProvider
from titan.tls import unverified_context
from titan.thriftbin import (
    BOOL,
    CALL,
    EXCEPTION,
    I32,
    LIST,
    STRING,
    STRUCT,
    Reader,
    ThriftError,
    Writer,
    field_map,
)


class PamError(Exception):
    pass


class SessionExpired(PamError):
    pass


AUTHENTICATED = 1

_STATE_NAMES = {
    1: "AUTHENTICATED",
    2: "GENERATE_OTP",
    3: "VERIFY_OTP",
    4: "CHANGE_PASSWORD",
}


def _open_unverified(request, timeout):
    return urllib.request.urlopen(
        request, timeout=timeout, context=unverified_context()
    )


def post_thrift(
    url: str,
    body: bytes,
    token: Optional[str] = None,
    opener=_open_unverified,
) -> bytes:
    headers = {"Content-Type": "application/octet-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise SessionExpired("session dead. run titan login")
        detail = exc.read()[:200]
        raise PamError("HTTP %s: %r" % (exc.code, detail)) from exc
    except urllib.error.URLError as exc:
        raise PamError(_reach_line(url, exc)) from exc
    except OSError as exc:
        raise PamError(_reach_line(url, exc)) from exc


def _reach_line(url: str, exc: BaseException) -> str:
    host = urlparse(url).hostname or url
    return "cannot reach %s: %s" % (host, _network_reason(exc))


def _network_reason(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    if isinstance(exc, urllib.error.URLError) and reason is not None:
        exc = reason
    if isinstance(exc, socket.gaierror):
        return "name not found"
    text = getattr(exc, "strerror", None) or str(exc)
    text = " ".join(str(text).split()).lower()
    if not text:
        return "network error"
    if (
        "nodename" in text
        or "name or service not known" in text
        or "name resolution" in text
    ):
        return "name not found"
    if "timed out" in text:
        return "timed out"
    if "connection refused" in text:
        return "connection refused"
    if "network is unreachable" in text or "no route to host" in text:
        return "network unreachable"
    if "connection reset" in text:
        return "connection reset"
    if "certificate" in text or "ssl" in text:
        return "tls failed"
    return text


def encode_logout() -> bytes:
    writer = Writer()
    writer.message("logout", CALL, 1)
    writer.stop()
    return writer.bytes()


def encode_providers() -> bytes:
    writer = Writer()
    writer.message("externalProviders", CALL, 1)
    writer.stop()
    return writer.bytes()


def decode_providers(data: bytes) -> List[LdapProvider]:
    fields = field_map(_success_struct(data, "externalProviders"))
    ldap = fields.get(1) or []
    providers: List[LdapProvider] = []
    for item in ldap:
        row = field_map(item)
        providers.append(LdapProvider(str(row[1]), str(row[2])))
    return providers


def encode_login(username: str, password: str, federation_id: str) -> bytes:
    writer = Writer()
    writer.message("login", CALL, 1)
    writer.field(STRUCT, 1)
    writer.field(STRING, 1)
    writer.string(username)
    writer.field(STRING, 2)
    writer.string(password)
    writer.field(STRING, 3)
    writer.string(federation_id)
    writer.stop()
    writer.stop()
    return writer.bytes()


VERIFY_OTP = 3


def decode_login(data: bytes, method: str = "login") -> dict:
    fields = field_map(_reply_struct(data, method))
    if 0 not in fields:
        if method == "login" and 1 in fields:
            raise PamError("invalid credentials")
        if 1 in fields:
            raise PamError("OTP rejected")
        if 2 in fields:
            raise PamError("OTP already enabled")
        raise PamError("login returned no session")
    response = field_map(fields[0])
    return {
        "token": str(response[4]),
        "state": int(response[6]),
        "sessionId": str(response[8]),
    }


def require_authenticated(payload: dict) -> None:
    state = int(payload["state"])
    if state == AUTHENTICATED:
        return
    name = _STATE_NAMES.get(state, str(state))
    raise PamError("PAM state %s. finish that in the browser" % name)


def encode_verify_otp(otp: str, is_validate: bool) -> bytes:
    writer = Writer()
    writer.message("verifyOtpAuth", CALL, 1)
    writer.field(STRING, 1)
    writer.string(otp)
    writer.field(BOOL, 2)
    writer.boolean(is_validate)
    writer.stop()
    return writer.bytes()


def encode_list_ssh(skip: int, limit: int) -> bytes:
    writer = Writer()
    writer.message("getSelfAllowedAccess", CALL, 1)
    writer.field(STRUCT, 1)
    writer.field(STRUCT, 1)
    writer.field(LIST, 1)
    writer.list(STRUCT, 1)
    writer.field(I32, 1)
    writer.i32(1)
    writer.stop()
    writer.field(LIST, 7)
    writer.list(STRUCT, 1)
    writer.field(LIST, 3)
    writer.list(I32, 3)
    writer.i32(1)
    writer.i32(2)
    writer.i32(3)
    writer.stop()
    writer.stop()
    writer.field(I32, 2)
    writer.i32(skip)
    writer.field(I32, 3)
    writer.i32(limit)
    writer.stop()
    writer.stop()
    return writer.bytes()


def decode_access_list(data: bytes) -> Tuple[int, List[Access]]:
    fields = field_map(_success_struct(data, "getSelfAllowedAccess"))
    total = int(fields[1])
    hits: List[Access] = []
    for item in fields[2]:
        row = field_map(item)
        hits.append(
            Access(
                id=str(row[1]),
                name=str(row[2]),
                resource_name=str(row[3]),
                resource_ip=str(row[4]),
            )
        )
    return total, hits


def _reply_struct(data: bytes, method: str):
    reader = Reader(data)
    try:
        name, mtype, _seq = reader.message()
    except ThriftError as exc:
        raise PamError(str(exc)) from exc
    if mtype == EXCEPTION:
        fields = field_map(reader.read_value(STRUCT))
        raise PamError(str(fields.get(1, "thrift exception")))
    if name != method:
        raise PamError("unexpected method %s" % name)
    return reader.read_value(STRUCT)


def _success_struct(data: bytes, method: str):
    fields = field_map(_reply_struct(data, method))
    if 0 not in fields:
        raise PamError("%s returned no success" % method)
    return fields[0]
