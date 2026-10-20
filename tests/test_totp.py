import os
import stat

from titan.pam import encode_verify_otp
from titan.totp import normalize_secret, save_totp, totp_code


# RFC 6238 SHA1, secret ASCII "12345678901234567890" as base32.
_RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc6238_sha1_at_59_seconds():
    assert totp_code(_RFC_SECRET, when=59) == "287082"


def test_otpauth_uri_keeps_secret():
    uri = "otpauth://totp/EFARDA:a?secret=gezd%20gnbv&issuer=EFARDA"
    assert normalize_secret(uri) == "GEZDGNBV"


def test_totp_file_mode_is_0600(tmp_path):
    path = tmp_path / "titan" / "totp"
    save_totp(path, _RFC_SECRET)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_verify_otp_call_is_not_the_enable_flag():
    body = encode_verify_otp("287082", False)
    assert b"verifyOtpAuth" in body
    assert b"287082" in body
    assert body.endswith(bytes([2, 0, 2, 0, 0]))
