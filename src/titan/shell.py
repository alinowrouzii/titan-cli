"""Browser SSH websocket, attached to the local terminal."""

from __future__ import annotations

import os
import select
import sys
import termios
import threading
import tty
from urllib.parse import urlencode, urlparse


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


def run_shell(url: str, origin: str) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("titan ssh needs a terminal")
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    error = None
    try:
        tty.setraw(fd)
        error = _bridge(url, origin, fd)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if error is not None:
        raise RuntimeError(error)


def _bridge(url: str, origin: str, fd: int):
    from websockets.sync.client import connect

    from titan.tls import unverified_context

    stop = threading.Event()
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
                            os.write(sys.stdout.fileno(), message.encode("utf-8"))
                        else:
                            os.write(sys.stdout.fileno(), message)
                finally:
                    stop.set()

            thread = threading.Thread(target=reader, daemon=True)
            thread.start()
            while not stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.2)
                if fd not in ready:
                    continue
                data = os.read(fd, 1024)
                if not data:
                    break
                try:
                    ws.send(data.decode("utf-8"))
                except UnicodeDecodeError:
                    ws.send(data)
    except Exception as exc:
        return str(exc)
    return None
