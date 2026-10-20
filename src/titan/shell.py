"""Browser SSH websocket, attached to the local terminal."""

from __future__ import annotations

import os
import re
import select
import sys
import termios
import threading
import tty
from typing import List, Optional
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


def run_shell(url: str, origin: str, credential: Optional[dict] = None) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("titan ssh needs a terminal")
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    error = None
    try:
        tty.setraw(fd)
        error = _bridge(url, origin, fd, credential)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if error is not None:
        raise RuntimeError(error)


def _bridge(url: str, origin: str, fd: int, credential: Optional[dict] = None):
    from websockets.sync.client import connect

    from titan.tls import unverified_context

    stop = threading.Event()
    feeder = None
    if credential:
        feeder = LoginFeeder(credential["username"], credential["password"])
    send_lock = threading.Lock()
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
                    for message in ws:
                        if isinstance(message, str):
                            raw = message.encode("utf-8")
                        else:
                            raw = message
                        os.write(sys.stdout.fileno(), raw)
                        if feeder is None:
                            continue
                        with send_lock:
                            replies = feeder.feed(raw.decode("utf-8", "replace"))
                        for reply in replies:
                            ws.send(reply)
                finally:
                    stop.set()

            thread = threading.Thread(target=reader, daemon=True)
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
                        break
                    if feeder is not None:
                        with send_lock:
                            feeder.cancel()
                        if timer is not None:
                            timer.cancel()
                    try:
                        ws.send(data.decode("utf-8"))
                    except UnicodeDecodeError:
                        ws.send(data)
            finally:
                if timer is not None:
                    timer.cancel()
    except Exception as exc:
        return str(exc)
    return None


def _cancel_feeder(lock: threading.Lock, feeder: LoginFeeder) -> None:
    with lock:
        feeder.cancel()
