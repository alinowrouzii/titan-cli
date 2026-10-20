from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets.frames import Close

from titan.shell import disconnect_ok, format_disconnect


def test_keepalive_timeout_is_one_line():
    exc = ConnectionClosedError(None, Close(1011, "keepalive ping timeout"))
    text = format_disconnect(exc)
    assert text == "connection closed: server stopped answering"
    assert "Traceback" not in text
    assert "\n" not in text


def test_normal_close_has_no_reason():
    exc = ConnectionClosedOK(Close(1000, ""), Close(1000, ""), True)
    assert format_disconnect(exc) == "connection closed"
    assert disconnect_ok(exc)


def test_peer_reason_is_kept():
    exc = ConnectionClosedError(Close(1008, "no session"), Close(1008, ""), True)
    assert format_disconnect(exc) == "connection closed: no session"
    assert not disconnect_ok(exc)


def test_going_away_without_reason():
    exc = ConnectionClosedOK(Close(1001, ""), None)
    assert format_disconnect(exc) == "connection closed: server going away"
    assert disconnect_ok(exc)


def test_reset_is_one_line():
    exc = ConnectionResetError(104, "Connection reset by peer")
    assert format_disconnect(exc) == "connection closed: Connection reset by peer"
    assert not disconnect_ok(exc)
