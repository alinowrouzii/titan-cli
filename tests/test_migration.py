import base64

import pytest

from titan.auth import AuthError
from titan.migration import accounts_in_text, choose_account, secret_base32


def _varint(number: int) -> bytes:
    out = bytearray()
    while True:
        piece = number & 0x7F
        number >>= 7
        if number:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def _bytes_field(field_id: int, payload: bytes) -> bytes:
    return _varint((field_id << 3) | 2) + _varint(len(payload)) + payload


def _varint_field(field_id: int, number: int) -> bytes:
    return _varint((field_id << 3) | 0) + _varint(number)


def _account(secret: bytes, name: str, issuer: str, otp_type: int = 2) -> bytes:
    body = (
        _bytes_field(1, secret)
        + _bytes_field(2, name.encode())
        + _bytes_field(3, issuer.encode())
        + _varint_field(4, 1)
        + _varint_field(5, 1)
        + _varint_field(6, otp_type)
    )
    payload = _bytes_field(1, body)
    data = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return ("otpauth-migration://offline?data=%s" % data).encode()


def test_export_uri_yields_base32_secret():
    secret = b"12345678901234567890"
    text = _account(secret, "a.nowrouzi", "EFARDA").decode()
    accounts = accounts_in_text(text)
    assert len(accounts) == 1
    assert secret_base32(accounts[0]) == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert accounts[0].label() == "EFARDA / a.nowrouzi"


def test_many_accounts_ask_for_a_name_and_hide_secrets():
    text = (
        _account(b"one-secret", "a.nowrouzi", "EFARDA").decode()
        + "\n"
        + _account(b"two-secret", "other", "LAB").decode()
    )
    accounts = accounts_in_text(text)
    with pytest.raises(AuthError) as caught:
        choose_account(accounts, None)
    message = str(caught.value)
    assert "EFARDA / a.nowrouzi" in message
    assert "LAB / other" in message
    assert b"one-secret".decode() not in message
    assert "--account" in message
    chosen = choose_account(accounts, "efarda")
    assert chosen.name == "a.nowrouzi"


def test_hotp_is_not_saved():
    text = _account(b"counter", "a", "EFARDA", otp_type=1).decode()
    accounts = accounts_in_text(text)
    with pytest.raises(AuthError) as caught:
        choose_account(accounts, None)
    assert "no TOTP" in str(caught.value)
