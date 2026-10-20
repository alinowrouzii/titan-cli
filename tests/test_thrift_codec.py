import struct

from titan.pam import decode_login, encode_login
from titan.thriftbin import CALL, Reader


def _string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack(">i", len(raw)) + raw


def _field_string(fid: int, text: str) -> bytes:
    return bytes([11]) + struct.pack(">h", fid) + _string(text)


def _field_i32(fid: int, value: int) -> bytes:
    return bytes([8]) + struct.pack(">h", fid) + struct.pack(">i", value)


def _field_struct(fid: int, body: bytes) -> bytes:
    return bytes([12]) + struct.pack(">h", fid) + body + bytes([0])


def test_login_call_matches_hand_built_bytes():
    body = _field_struct(
        1,
        _field_string(1, "bob")
        + _field_string(2, "secret")
        + _field_string(3, "fed"),
    )
    expected = (
        struct.pack(">I", 0x80010000 | CALL)
        + _string("login")
        + struct.pack(">i", 1)
        + body
        + bytes([0])
    )
    assert encode_login("bob", "secret", "fed") == expected


def test_decode_login_reply_token_and_state():
    response = (
        _field_string(4, "tok")
        + _field_i32(6, 1)
        + _field_string(8, "sid")
    )
    result = _field_struct(0, response)
    message = (
        struct.pack(">I", 0x80010000 | 2)
        + _string("login")
        + struct.pack(">i", 1)
        + result
        + bytes([0])
    )
    payload = decode_login(message)
    assert payload["token"] == "tok"
    assert payload["state"] == 1
    assert payload["sessionId"] == "sid"


def test_reader_rejects_non_strict_header():
    reader = Reader(struct.pack(">i", 4) + b"nope")
    try:
        reader.message()
    except Exception as exc:
        assert "strict" in str(exc)
    else:
        raise AssertionError("expected a strict-header error")
