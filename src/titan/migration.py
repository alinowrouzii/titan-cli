"""Google Authenticator export QR payload.

The export screen encodes otpauth-migration://offline?data=<protobuf>.
"""

from __future__ import annotations

import base64
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

from titan.auth import AuthError


class MigrationAccount:
    def __init__(
        self,
        secret: bytes,
        name: str,
        issuer: str,
        algorithm: int,
        digits: int,
        otp_type: int,
    ) -> None:
        self.secret = secret
        self.name = name
        self.issuer = issuer
        self.algorithm = algorithm
        self.digits = digits
        self.otp_type = otp_type

    def label(self) -> str:
        if self.issuer and self.name:
            return "%s / %s" % (self.issuer, self.name)
        return self.issuer or self.name or "(unnamed)"


def accounts_in_text(text: str) -> List[MigrationAccount]:
    found: List[MigrationAccount] = []
    for line in text.splitlines() or [text]:
        lowered = line.lower()
        marker = "otpauth-migration://"
        start = lowered.find(marker)
        if start < 0:
            continue
        found.extend(parse_migration_uri(line[start:].strip()))
    return found


def parse_migration_uri(uri: str) -> List[MigrationAccount]:
    parsed = urlparse(uri.strip())
    if parsed.scheme.lower() != "otpauth-migration":
        raise AuthError("not a Google Authenticator export QR")
    data = parse_qs(parsed.query).get("data")
    if not data or not data[0]:
        raise AuthError("export QR has no data")
    payload = _b64(data[0])
    accounts: List[MigrationAccount] = []
    for field_id, wire, value in _fields(payload):
        if field_id == 1 and wire == 2:
            accounts.append(_otp(value))
    if not accounts:
        raise AuthError("export QR has no accounts")
    return accounts


def choose_account(accounts: List[MigrationAccount], query: Optional[str]) -> MigrationAccount:
    totp = [account for account in accounts if account.otp_type in (0, 2)]
    if query:
        folded = query.casefold()
        totp = [
            account
            for account in totp
            if folded in account.name.casefold() or folded in account.issuer.casefold()
        ]
    if len(totp) == 1:
        _require_supported(totp[0])
        return totp[0]
    if not totp:
        raise AuthError("no TOTP account in that export")
    labels = "\n".join(account.label() for account in totp)
    raise AuthError("more than one account. pass --account NAME\n" + labels)


def secret_base32(account: MigrationAccount) -> str:
    if not account.secret:
        raise AuthError("export account %s has no secret" % account.label())
    return base64.b32encode(account.secret).decode("ascii").rstrip("=")


def _require_supported(account: MigrationAccount) -> None:
    if account.otp_type not in (0, 2):
        raise AuthError("%s is HOTP. this CLI only stores TOTP" % account.label())
    if account.algorithm not in (0, 1):
        raise AuthError("%s is not SHA1. this CLI only stores SHA1" % account.label())
    if account.digits not in (0, 1):
        raise AuthError("%s is not a 6-digit code" % account.label())


def _otp(payload: bytes) -> MigrationAccount:
    secret = b""
    name = ""
    issuer = ""
    algorithm = 0
    digits = 0
    otp_type = 0
    for field_id, wire, value in _fields(payload):
        if field_id == 1 and wire == 2:
            secret = value
        elif field_id == 2 and wire == 2:
            name = value.decode("utf-8")
        elif field_id == 3 and wire == 2:
            issuer = value.decode("utf-8")
        elif field_id == 4 and wire == 0:
            algorithm = value
        elif field_id == 5 and wire == 0:
            digits = value
        elif field_id == 6 and wire == 0:
            otp_type = value
    return MigrationAccount(secret, name, issuer, algorithm, digits, otp_type)


def _fields(payload: bytes):
    index = 0
    found = []
    while index < len(payload):
        key, index = _varint(payload, index)
        field_id = key >> 3
        wire = key & 7
        if wire == 0:
            value, index = _varint(payload, index)
        elif wire == 2:
            length, index = _varint(payload, index)
            value = payload[index : index + length]
            index += length
        elif wire == 5:
            value = payload[index : index + 4]
            index += 4
        elif wire == 1:
            value = payload[index : index + 8]
            index += 8
        else:
            raise AuthError("bad export payload")
        found.append((field_id, wire, value))
    return found


def _varint(payload: bytes, index: int):
    shift = 0
    number = 0
    while index < len(payload):
        byte = payload[index]
        index += 1
        number |= (byte & 0x7F) << shift
        if byte < 128:
            return number, index
        shift += 7
        if shift > 63:
            break
    raise AuthError("bad export payload")


def _b64(data: str) -> bytes:
    padded = data.strip()
    padded += "=" * ((4 - len(padded) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise AuthError("export QR data is not base64") from exc
