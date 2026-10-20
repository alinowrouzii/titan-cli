import io
import socket
import ssl
import urllib.error

import pytest

from titan.pam import PamError, SessionExpired, decode_login, post_thrift, require_authenticated
from titan.thriftbin import Writer
from titan.tls import unverified_context


class _Boom:
    def __init__(self, code: int) -> None:
        self.code = code

    def __call__(self, request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, self.code, "no", hdrs=None, fp=io.BytesIO(b"")
        )


def test_tls_verification_is_off():
    context = unverified_context()
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def _raise(exc):
    def opener(request, timeout):
        raise exc

    return opener


def test_dns_failure_is_one_line():
    exc = urllib.error.URLError(
        socket.gaierror(8, "nodename nor servname provided, or not known")
    )
    with pytest.raises(PamError) as caught:
        post_thrift(
            "https://titan.efarda.ir/api/identity/accesses",
            b"",
            opener=_raise(exc),
        )
    assert str(caught.value) == "cannot reach titan.efarda.ir: name not found"


def test_timeout_and_refused_are_one_line():
    timeout = urllib.error.URLError(TimeoutError("timed out"))
    refused = urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
    with pytest.raises(PamError) as caught:
        post_thrift("https://titan.efarda.ir/api/auth/auth", b"", opener=_raise(timeout))
    assert str(caught.value) == "cannot reach titan.efarda.ir: timed out"
    with pytest.raises(PamError) as caught:
        post_thrift("https://titan.efarda.ir/api/auth/auth", b"", opener=_raise(refused))
    assert str(caught.value) == "cannot reach titan.efarda.ir: connection refused"


def test_http_403_is_session_expired():
    with pytest.raises(SessionExpired):
        post_thrift("https://titan.efarda.ir/api/auth/auth", b"", opener=_Boom(403))


def test_login_otp_state_does_not_count_as_success():
    writer = Writer()
    writer.message("login", 2, 1)
    writer.field(12, 0)
    writer.field(11, 4)
    writer.string("tok")
    writer.field(8, 6)
    writer.i32(2)
    writer.field(11, 8)
    writer.string("sid")
    writer.stop()
    writer.stop()
    payload = decode_login(writer.bytes())
    assert payload["state"] == 2
    with pytest.raises(PamError) as caught:
        require_authenticated(payload)
    assert "GENERATE_OTP" in str(caught.value)
