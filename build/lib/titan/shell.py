"""Browser SSH websocket, attached to the local terminal."""

from __future__ import annotations

import logging
import os
import re
import select
import sys
import termios
import threading
import tty
from typing import List, Optional, Tuple
from urllib.parse import urlencode, urlparse

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_USER_PROMPT = re.compile(
    r"(?i)(?:(?:^|[\r\n])(?:login(?:\s+as)?|user\s*name|user)|username)\s*:\s*"
)
_PASS_PROMPT = re.compile(r"(?i)password\s*:\s*$")
_AUTOFILL_SECONDS = 15.0


def ssh_proxy_url(
    base_url: str,
    token: str,
    access_id: str,
    cols: int,
    rows: int,
    session_cookie: str,
) -> str:
    parsed = urlparse(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    query = urlencode(
        {
            "cols": cols,
            "rows": rows,
            "token": token,
            "sessionCookie": session_cookie,
            "destination": access_id,
            "protocol": "ssh",
        }
    )
    return "%s://%s/ssh-proxy?%s" % (scheme, parsed.netloc, query)


def terminal_size() -> tuple:
    try:
        size = os.get_terminal_size()
    except OSError:
        return (80, 24)
    return (size.columns, size.lines)


class LoginFeeder:
    """Type a saved VM username and password when those prompts appear."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.done = False
        self._stage = "user"
        self._buf = ""

    def cancel(self) -> None:
        self.done = True
        self._stage = "done"

    def feed(self, text: str) -> List[str]:
        if self.done:
            return []
        self._buf = (self._buf + _visible(text))[-400:]
        out: List[str] = []
        if self._stage == "user":
            match = _USER_PROMPT.search(self._buf)
            if match:
                out.append(self.username + "\r")
                self._stage = "password"
                self._buf = self._buf[match.end() :]
        if self._stage == "password":
            match = _PASS_PROMPT.search(self._buf)
            if match:
                out.append(self.password + "\r")
                self._stage = "done"
                self.done = True
                self._buf = ""
        return out


def _visible(text: str) -> str:
    return _ANSI.sub("", text).replace("\x1b", "")


_CLOSE_CODE = {
    1001: "server going away",
    1002: "protocol error",
    1003: "unsupported data",
    1006: "connection dropped",
    1007: "bad data",
    1008: "policy violation",
    1009: "message too big",
    1010: "missing extension",
    1011: "internal error",
    1012: "server restarting",
    1013: "try again later",
    1014: "bad gateway",
    1015: "tls failed",
}

_CLOSE_REASON = {
    "keepalive ping timeout": "server stopped answering",
}


def format_disconnect(exc: BaseException) -> str:
    """One line for a dead socket. No traceback."""
    from websockets.exceptions import ConnectionClosed

    if isinstance(exc, ConnectionClosed):
        detail = _close_detail(exc)
    else:
        detail = _os_detail(exc)
    if not detail:
        return "connection closed"
    return "connection closed: %s" % detail


def disconnect_ok(exc: BaseException) -> bool:
    from websockets.exceptions import ConnectionClosedOK

    return isinstance(exc, ConnectionClosedOK)


def _close_detail(exc: BaseException) -> str:
    detail = _frame_detail(getattr(exc, "rcvd", None)) or _frame_detail(
        getattr(exc, "sent", None)
    )
    return _CLOSE_REASON.get(detail, detail)


def _frame_detail(frame: object) -> str:
    if frame is None:
        return ""
    reason = getattr(frame, "reason", "") or ""
    reason = " ".join(reason.split())
    if reason:
        return reason
    code = getattr(frame, "code", None)
    if code is None:
        return ""
    return _CLOSE_CODE.get(int(code), "")


def _os_detail(exc: BaseException) -> str:
    text = getattr(exc, "strerror", None) or str(exc)
    return " ".join(text.split())


def _quiet_socket_logs() -> List[Tuple[logging.Logger, int]]:
    saved = []
    for name in ("websockets", "websockets.client"):
        log = logging.getLogger(name)
        saved.append((log, log.level))
        log.setLevel(logging.CRITICAL)
    return saved


def _restore_socket_logs(saved: List[Tuple[logging.Logger, int]]) -> None:
    for log, level in saved:
        log.setLevel(level)


def run_shell(url: str, origin: str, credential: Optional[dict] = None) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("titan ssh needs a terminal")
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    outcome = None
    try:
        tty.setraw(fd)
        outcome = _bridge(url, origin, fd, credential)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if outcome is None:
        return
    message, ok = outcome
    # Cooked mode is back, so this line starts at column 0.
    if ok:
        print("\n" + message, file=sys.stderr)
        return
    raise RuntimeError("\n" + message)


def _bridge(url: str, origin: str, fd: int, credential: Optional[dict] = None):
    from websockets.sync.client import connect

    from titan.tls import unverified_context

    stop = threading.Event()
    feeder = None
    if credential:
        feeder = LoginFeeder(credential["username"], credential["password"])
    send_lock = threading.Lock()
    closed: List[BaseException] = []
    local_exit = False
    thread = None
    saved_logs = _quiet_socket_logs()
    try:
        try:
            with connect(
                url,
                origin=origin,
                ssl=unverified_context(),
                max_size=None,
                open_timeout=20,
            ) as ws:
                def reader() -> None:
                    try:
                        while True:
                            try:
                                message = ws.recv()
                            except Exception as exc:
                                closed.append(exc)
                                break
                            if isinstance(message, str):
                                raw = message.encode("utf-8")
                            else:
                                raw = message
                            os.write(sys.stdout.fileno(), raw)
                            if feeder is None:
                                continue
                            with send_lock:
                                replies = feeder.feed(raw.decode("utf-8", "replace"))
                            failed = False
                            for reply in replies:
                                try:
                                    ws.send(reply)
                                except Exception as exc:
                                    if not closed:
                                        closed.append(exc)
                                    failed = True
                                    break
                            if failed:
                                break
                    finally:
                        stop.set()

                thread = threading.Thread(target=reader, name="reader", daemon=True)
                thread.start()
                timer = None
                if feeder is not None:
                    timer = threading.Timer(
                        _AUTOFILL_SECONDS,
                        _cancel_feeder,
                        args=(send_lock, feeder),
                    )
                    timer.daemon = True
                    timer.start()
                try:
                    while not stop.is_set():
                        ready, _, _ = select.select([fd], [], [], 0.2)
                        if fd not in ready:
                            continue
                        data = os.read(fd, 1024)
                        if not data:
                            local_exit = True
                            break
                        if feeder is not None:
                            with send_lock:
                                feeder.cancel()
                            if timer is not None:
                                timer.cancel()
                        try:
                            ws.send(data.decode("utf-8"))
                        except UnicodeDecodeError:
                            try:
                                ws.send(data)
                            except Exception as exc:
                                if not closed:
                                    closed.append(exc)
                                break
                        except Exception as exc:
                            if not closed:
                                closed.append(exc)
                            break
                finally:
                    if timer is not None:
                        timer.cancel()
        except Exception as exc:
            if not closed:
                closed.append(exc)
        if thread is not None:
            thread.join(timeout=1)
    finally:
        _restore_socket_logs(saved_logs)
    if not closed:
        return None
    if local_exit and disconnect_ok(closed[0]):
        return None
    exc = closed[0]
    from websockets.exceptions import ConnectionClosed

    if isinstance(exc, (ConnectionClosed, ConnectionError)):
        return format_disconnect(exc), disconnect_ok(exc)
    text = str(exc).splitlines()
    return (text[0] if text else exc.__class__.__name__), False


def _cancel_feeder(lock: threading.Lock, feeder: LoginFeeder) -> None:
    with lock:
        feeder.cancel()
