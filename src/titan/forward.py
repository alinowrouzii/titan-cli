"""TCP publish over the PAM SSH websocket."""

from __future__ import annotations

import base64
import os
import queue
import re
import select
import signal
import socket
import struct
import sys
import termios
import threading
import time
import tty
import uuid
from typing import Callable, List, Optional, Tuple

from titan.shell import LoginFeeder, format_disconnect

HELLO = 1
BIND = 2
BOUND = 3
BIND_FAIL = 4
OPEN = 5
OPENED = 6
OPEN_FAIL = 7
DATA = 8
CLOSE = 9
DROP = 10

KIND_L = 1
KIND_R = 2
MAX_FRAME = 65536
MAX_DATA = 32768
HIGH = 1024 * 1024
HELLO_FRAME = bytes.fromhex("000000020131")

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PROMPT = re.compile(r"^[^\r\n]*[#$%]\s*$")


def parse_port_pair(text: str) -> Tuple[int, int]:
    parts = text.split(":")
    if len(parts) != 2 or any(not part.isdigit() for part in parts):
        raise ValueError(text)
    ports = (int(parts[0]), int(parts[1]))
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError(text)
    return ports


def _port_token(text: str) -> Optional[int]:
    if not text.isdigit():
        return None
    port = int(text)
    if port < 1 or port > 65535:
        return None
    return port


def _host_ok(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if all(label.isdigit() for label in labels):
        if len(labels) != 4:
            return False
        return all(int(label) <= 255 for label in labels)
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if any(not (ch.isalnum() or ch == "-") for ch in label):
            return False
    return True


def parse_local_forward(text: str) -> Tuple[int, str, int]:
    parts = text.split(":")
    if len(parts) == 2:
        listen, dial = parse_port_pair(text)
        return listen, "127.0.0.1", dial
    if len(parts) != 3 or not _host_ok(parts[1]):
        raise ValueError(text)
    listen = _port_token(parts[0])
    dial = _port_token(parts[2])
    if listen is None or dial is None:
        raise ValueError(text)
    return listen, parts[1], dial


def encode_frame(frame_type: int, payload: bytes) -> bytes:
    body = bytes((frame_type,)) + payload
    if len(body) > MAX_FRAME:
        raise ValueError("bad frame")
    return struct.pack(">I", len(body)) + body


def decode_frames(buffer: bytes) -> Tuple[List[Tuple[int, bytes]], bytes]:
    frames = []
    while len(buffer) >= 4:
        (length,) = struct.unpack(">I", buffer[:4])
        if length == 0 or length > MAX_FRAME:
            raise ValueError("bad frame")
        if len(buffer) < 4 + length:
            break
        body = buffer[4 : 4 + length]
        frames.append((body[0], bytes(body[1:])))
        buffer = buffer[4 + length :]
    return frames, buffer


def chunk_script(source: str, dest_b64: str) -> List[str]:
    import base64

    raw = base64.b64encode(source.encode("utf-8")).decode("ascii")
    prefix = "printf '%s' '"
    suffix = "' >> %s && echo TITAN_OK" % dest_b64
    room = 3000 - len(prefix) - len(suffix)
    if room < 1:
        raise ValueError("dest path too long")
    if not raw:
        raw = ""
    lines = []
    while raw or not lines:
        take = raw[:room]
        raw = raw[room:]
        line = prefix + take + suffix
        if len(line) > 3000:
            raise ValueError("chunk too long")
        lines.append(line)
        if not raw:
            break
    return lines


def exec_line(dest_b64: str, dest_py: str) -> str:
    return (
        "base64 -d %s > %s && rm -f %s && echo TITAN_EXEC && "
        "stty -echo -icanon raw && exec python3 -u %s"
        % (dest_b64, dest_py, dest_b64, dest_py)
    )


def _visible(text: str) -> str:
    return _ANSI.sub("", text).replace("\x1b", "")


def last_line_is_prompt(visible: str) -> bool:
    text = visible.replace("\r", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    if not text:
        return False
    return _PROMPT.match(text.split("\n")[-1]) is not None


def remote_tool_error(visible: str) -> str:
    if "python3: not found" in visible or "python3: command not found" in visible:
        return "vm has no python3"
    if "base64: not found" in visible or "base64: command not found" in visible:
        return "vm has no base64"
    return ""


def wire_line(frame: bytes) -> bytes:
    # The PAM proxy delivers client text to the PTY the same way as a key.
    # Shell lines end with CR. A bare LF never reaches the VM program.
    return b"TITAN1 " + base64.b64encode(frame) + b"\r"


def unwrap_wire(buffer: bytes) -> Tuple[List[bytes], bytes]:
    frames: List[bytes] = []
    while buffer:
        cut = None
        for index, byte in enumerate(buffer):
            if byte in (10, 13):
                cut = index
                break
        if cut is None:
            break
        line = buffer[:cut]
        drop = 2 if buffer[cut : cut + 2] == b"\r\n" else 1
        buffer = buffer[cut + drop :]
        if not line.startswith(b"TITAN1 "):
            continue
        try:
            raw = base64.b64decode(line[7:], validate=True)
        except Exception as exc:
            raise ValueError("bad frame") from exc
        got, rest = decode_frames(raw)
        if rest or len(got) != 1:
            raise ValueError("bad frame")
        frames.append(raw)
    return frames, buffer


def after_hello(buffer: bytes) -> Optional[bytes]:
    token = b"TITAN1 " + base64.b64encode(HELLO_FRAME)
    start = 0
    while True:
        index = buffer.find(token, start)
        if index < 0:
            return None
        after = index + len(token)
        if after >= len(buffer):
            return None
        if buffer[after : after + 1] not in (b"\r", b"\n"):
            start = index + 1
            continue
        if buffer[after : after + 2] == b"\r\n":
            after += 2
        else:
            after += 1
        return buffer[after:]


def _pack_err(ident: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack(">IH", ident, len(raw)) + raw


def _unpack_err(payload: bytes) -> Tuple[int, str]:
    ident, size = struct.unpack(">IH", payload[:6])
    return ident, payload[6 : 6 + size].decode("utf-8", "replace")


class Tunnel(object):
    def __init__(
        self, tid: int, kind: str, listen_port: int, dial_port: int, dial_host: str = "127.0.0.1"
    ) -> None:
        self.id = tid
        self.kind = kind
        self.listen_port = listen_port
        self.dial_port = dial_port
        self.dial_host = dial_host
        self.status = "wait"
        self.reason = ""
        self.conns = 0


class TunnelTable(object):
    def __init__(self) -> None:
        self.rows: List[Tunnel] = []

    def add(
        self, kind: str, listen_port: int, dial_port: int, dial_host: str = "127.0.0.1"
    ) -> Tunnel:
        row = Tunnel(len(self.rows) + 1, kind, listen_port, dial_port, dial_host)
        self.rows.append(row)
        return row

    def get(self, tid: int) -> Optional[Tunnel]:
        if tid < 1 or tid > len(self.rows):
            return None
        return self.rows[tid - 1]

    def mark_fail(self, tid: int, reason: str) -> None:
        row = self.get(tid)
        if row is None or row.status == "dead":
            return
        row.status = "fail"
        row.reason = reason

    def mark_up(self, tid: int) -> None:
        row = self.get(tid)
        if row is None or row.status in ("dead", "fail"):
            return
        row.status = "conns"
        row.conns = 0

    def mark_dead(self, tid: int) -> None:
        row = self.get(tid)
        if row is None:
            return
        row.status = "dead"

    def add_conn(self, tid: int) -> None:
        row = self.get(tid)
        if row is None or row.status in ("dead", "fail"):
            return
        row.status = "conns"
        row.conns += 1

    def sub_conn(self, tid: int) -> None:
        row = self.get(tid)
        if row is None or row.status != "conns" or row.conns < 1:
            return
        row.conns -= 1

    def kill(self, text: str) -> Optional[str]:
        value = text.strip()
        row = self.get(int(value)) if value.isdigit() else None
        if row is None or row.status not in ("wait", "conns"):
            return "no tunnel %s" % value
        row.status = "dead"
        return None

    def render(self) -> str:
        lines = []
        for row in self.rows:
            if row.kind == "L":
                listen_side, dial_side = "laptop", "vm"
            else:
                listen_side, dial_side = "vm", "laptop"
            if row.status == "conns":
                status = "conns %d" % row.conns
            elif row.status == "fail":
                status = "fail: %s" % row.reason
            else:
                status = row.status
            lines.append(
                "%d  %s  %s 127.0.0.1:%d  dial %s %s:%d  %s"
                % (
                    row.id,
                    row.kind,
                    listen_side,
                    row.listen_port,
                    dial_side,
                    row.dial_host,
                    row.dial_port,
                    status,
                )
            )
        lines.append("type a number to kill that tunnel")
        return "\n".join(lines)


class Bootstrap(object):
    def __init__(
        self,
        script: str,
        dest_b64: str,
        dest_py: str,
        clock: Callable[[], float],
        credential: Optional[dict] = None,
    ) -> None:
        self.clock = clock
        self.started = clock()
        self.lines = chunk_script(script, dest_b64)
        self.exec = exec_line(dest_b64, dest_py)
        self.buf = b""
        self.visible = ""
        self.last_change = self.started
        self.phase = "login" if credential else "prompt"
        self.feeder = None
        if credential:
            self.feeder = LoginFeeder(credential["username"], credential["password"])
        self.line_i = 0
        self.ok_mark = 0
        self.line_sent_at = None
        self.exec_sent_at = None
        self.out = bytearray()
        self.rest = b""

    def take(self) -> bytes:
        data = bytes(self.out)
        self.out.clear()
        return data

    def push(self, data: bytes) -> None:
        if not data:
            self.poll()
            return
        self.buf += data
        piece = _visible(data.decode("utf-8", "replace"))
        self.visible = _visible(self.buf.decode("utf-8", "replace"))
        self.last_change = self.clock()
        err = remote_tool_error(self.visible)
        if err:
            raise RuntimeError(err)
        if self.feeder is not None and not self.feeder.done:
            for reply in self.feeder.feed(piece):
                self.out += reply.encode("utf-8")
            if not self.feeder.done:
                return
            self.phase = "prompt"
        if self.phase == "hello":
            rest = after_hello(self.buf)
            if rest is not None:
                self.rest = rest
                self.phase = "done"
                return
        self._advance()

    def poll(self) -> None:
        now = self.clock()
        if self.phase in ("login", "prompt") and now - self.started >= 60:
            raise RuntimeError("no shell prompt")
        if (
            self.phase == "ack"
            and self.line_sent_at is not None
            and now - self.line_sent_at >= 5
        ):
            raise RuntimeError("forwarder did not start")
        if (
            self.phase == "hello"
            and self.exec_sent_at is not None
            and now - self.exec_sent_at >= 20
        ):
            raise RuntimeError("forwarder did not start")
        if self.phase == "hello":
            rest = after_hello(self.buf)
            if rest is not None:
                self.rest = rest
                self.phase = "done"
                return
        self._advance()

    def _advance(self) -> None:
        now = self.clock()
        quiet = now - self.last_change >= 0.3
        if self.phase == "prompt":
            if quiet and last_line_is_prompt(self.visible):
                self._send_chunk()
            return
        if self.phase != "ack" or not quiet:
            return
        if self.visible.count("TITAN_OK") <= self.ok_mark:
            return
        if not last_line_is_prompt(self.visible):
            return
        if self.line_i < len(self.lines):
            self._send_chunk()
            return
        self.out += (self.exec + "\r").encode("utf-8")
        self.phase = "hello"
        self.exec_sent_at = now

    def _send_chunk(self) -> None:
        self.out += (self.lines[self.line_i] + "\r").encode("utf-8")
        self.line_i += 1
        self.ok_mark = self.visible.count("TITAN_OK")
        self.line_sent_at = self.clock()
        self.phase = "ack"


def _listen(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(128)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


def _dial(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setblocking(False)
    return sock


class Link(object):
    def __init__(self, specs: List[tuple]) -> None:
        self.table = TunnelTable()
        for spec in specs:
            kind, listen_port, dial_port = spec[0], spec[1], spec[2]
            dial_host = spec[3] if len(spec) > 3 else "127.0.0.1"
            self.table.add(kind, listen_port, dial_port, dial_host)
        self.listeners = {}
        self.chans = {}
        self.next_odd = 1
        self.pending = bytearray()
        self.buf = b""

    def start(self) -> int:
        for row in self.table.rows:
            if row.kind == "L":
                try:
                    self.listeners[row.id] = _listen(row.listen_port)
                except OSError as exc:
                    self.table.mark_fail(row.id, str(exc))
                    continue
                payload = struct.pack(">IBH", row.id, KIND_L, row.dial_port)
                if row.dial_host != "127.0.0.1":
                    raw = row.dial_host.encode("utf-8")
                    payload += struct.pack(">H", len(raw)) + raw
                self._send(BIND, payload)
            else:
                self._send(BIND, struct.pack(">IBH", row.id, KIND_R, row.listen_port))
        return 1 if self.all_failed() else 0

    def all_failed(self) -> bool:
        return bool(self.table.rows) and all(
            row.status == "fail" for row in self.table.rows
        )

    def take_send(self) -> bytes:
        data = bytes(self.pending)
        self.pending.clear()
        for item in self.chans.values():
            item["unsent"] = 0
        return data

    def push(self, data: bytes) -> None:
        self.buf += data
        try:
            frames, self.buf = decode_frames(self.buf)
        except ValueError as exc:
            raise RuntimeError("bad frame") from exc
        for frame_type, payload in frames:
            self._on(frame_type, payload)

    def kill(self, text: str) -> Optional[str]:
        value = text.strip()
        message = self.table.kill(value)
        if message:
            return message
        tid = int(value)
        self._drop_local(tid)
        self._send(DROP, struct.pack(">I", tid))
        return None

    def drop_all(self) -> None:
        for row in list(self.table.rows):
            if row.status in ("wait", "conns"):
                self.kill(str(row.id))

    def poll(self, timeout: float) -> None:
        self._flush_held()
        read_set = list(self.listeners.values())
        for item in self.chans.values():
            if self._want_read(item):
                read_set.append(item["sock"])
        write_set = [item["sock"] for item in self.chans.values() if item["out"]]
        if not read_set and not write_set:
            if timeout:
                time.sleep(timeout)
            self._flush_held()
            return
        try:
            ready_r, ready_w, _ = select.select(read_set, write_set, [], timeout)
        except (OSError, ValueError):
            return
        for tid, listener in list(self.listeners.items()):
            if listener in ready_r:
                self._accept(tid, listener)
        for chan, item in list(self.chans.items()):
            if item["sock"] in ready_r:
                self._read_sock(chan, item)
            if item["sock"] in ready_w:
                self._write_sock(chan, item)
        self._flush_held()

    def _want_read(self, item: dict) -> bool:
        return item["up"] and len(item["held"]) < HIGH and item["unsent"] < HIGH

    def _item(self, sock: socket.socket, tid: int, up: bool) -> dict:
        return {"sock": sock, "tid": tid, "out": bytearray(), "held": bytearray(), "unsent": 0, "up": up}

    def _send(self, frame_type: int, payload: bytes) -> None:
        self.pending += encode_frame(frame_type, payload)

    def _on(self, frame_type: int, payload: bytes) -> None:
        if frame_type == BOUND and len(payload) >= 4:
            (tid,) = struct.unpack(">I", payload[:4])
            self.table.mark_up(tid)
        elif frame_type == BIND_FAIL and len(payload) >= 6:
            tid, reason = _unpack_err(payload)
            listener = self.listeners.pop(tid, None)
            if listener is not None:
                listener.close()
            self.table.mark_fail(tid, reason)
        elif frame_type == OPEN and len(payload) >= 8:
            chan, tid = struct.unpack(">II", payload[:8])
            self._on_open(chan, tid)
        elif frame_type == OPENED and len(payload) >= 4:
            (chan,) = struct.unpack(">I", payload[:4])
            self._on_opened(chan)
        elif frame_type == OPEN_FAIL and len(payload) >= 6:
            chan, _reason = _unpack_err(payload)
            self._close(chan, notify=False)
        elif frame_type == DATA and len(payload) >= 4:
            (chan,) = struct.unpack(">I", payload[:4])
            item = self.chans.get(chan)
            if item is not None:
                item["out"] += payload[4:]
        elif frame_type == CLOSE and len(payload) >= 4:
            (chan,) = struct.unpack(">I", payload[:4])
            item = self.chans.get(chan)
            was = bool(item and item["up"])
            tid = item["tid"] if item else None
            self._close(chan, notify=False)
            if was and tid is not None:
                self.table.sub_conn(tid)

    def _on_open(self, chan: int, tid: int) -> None:
        if chan in self.chans:
            self._send(OPEN_FAIL, _pack_err(chan, "channel in use"))
            return
        row = self.table.get(tid)
        if row is None or row.kind != "R" or row.status != "conns":
            self._send(OPEN_FAIL, _pack_err(chan, "unknown tunnel"))
            return
        try:
            sock = _dial(row.dial_port)
        except OSError as exc:
            self._send(OPEN_FAIL, _pack_err(chan, str(exc)))
            return
        self.chans[chan] = self._item(sock, tid, True)
        self.table.add_conn(tid)
        self._send(OPENED, struct.pack(">I", chan))

    def _on_opened(self, chan: int) -> None:
        item = self.chans.get(chan)
        if item is None or item["up"]:
            return
        item["up"] = True
        self.table.add_conn(item["tid"])

    def _accept(self, tid: int, listener: socket.socket) -> None:
        try:
            conn, _addr = listener.accept()
        except BlockingIOError:
            return
        except OSError:
            return
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.setblocking(False)
        chan = self.next_odd
        self.next_odd += 2
        self.chans[chan] = self._item(conn, tid, False)
        self._send(OPEN, struct.pack(">II", chan, tid))

    def _read_sock(self, chan: int, item: dict) -> None:
        if not self._want_read(item):
            return
        try:
            data = item["sock"].recv(MAX_DATA)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            was = item["up"]
            tid = item["tid"]
            self._close(chan, notify=True)
            if was:
                self.table.sub_conn(tid)
            return
        item["held"] += data

    def _write_sock(self, chan: int, item: dict) -> None:
        if not item["out"]:
            return
        try:
            sent = item["sock"].send(item["out"])
        except BlockingIOError:
            return
        except OSError:
            was = item["up"]
            tid = item["tid"]
            self._close(chan, notify=True)
            if was:
                self.table.sub_conn(tid)
            return
        del item["out"][:sent]

    def _flush_held(self) -> None:
        for chan, item in list(self.chans.items()):
            if not item["held"] or item["unsent"] >= HIGH:
                continue
            room = min(MAX_DATA, HIGH - item["unsent"], len(item["held"]))
            take = bytes(item["held"][:room])
            del item["held"][:room]
            self._send(DATA, struct.pack(">I", chan) + take)
            item["unsent"] += len(take)

    def _close(self, chan: int, notify: bool) -> None:
        item = self.chans.pop(chan, None)
        if item is None:
            return
        try:
            item["sock"].close()
        except OSError:
            pass
        if notify:
            self._send(CLOSE, struct.pack(">I", chan))

    def _drop_local(self, tid: int) -> None:
        listener = self.listeners.pop(tid, None)
        if listener is not None:
            listener.close()
        for chan, item in list(self.chans.items()):
            if item["tid"] == tid:
                self._close(chan, notify=True)


def paint(stream, previous: int, text: str) -> int:
    lines = text.split("\n")
    parts = []
    tty = bool(stream.isatty())
    if tty and previous:
        parts.append("\x1b[%dA" % previous)
    for line in lines:
        if tty:
            parts.append("\x1b[2K")
        parts.append(line + "\n")
    stream.write("".join(parts))
    stream.flush()
    return len(lines)


REMOTE_SOURCE = r'''
import base64
import os
import select
import socket
import struct
import sys
import time

MAX_FRAME = 65536
MAX_DATA = 32768
HIGH = 1024 * 1024
HELLO = 1
BIND = 2
BOUND = 3
BIND_FAIL = 4
OPEN = 5
OPENED = 6
OPEN_FAIL = 7
DATA = 8
CLOSE = 9
DROP = 10
KIND_L = 1
KIND_R = 2


def enc(ftype, payload):
    body = bytes((ftype,)) + payload
    return struct.pack(">I", len(body)) + body


def dec(buf):
    frames = []
    while len(buf) >= 4:
        (length,) = struct.unpack(">I", buf[:4])
        if length == 0 or length > MAX_FRAME:
            raise ValueError("bad frame")
        if len(buf) < 4 + length:
            break
        body = buf[4 : 4 + length]
        frames.append((body[0], body[1:]))
        buf = buf[4 + length :]
    return frames, buf


def pack_err(ident, text):
    raw = text.encode("utf-8")
    return struct.pack(">IH", ident, len(raw)) + raw


def unlink_self():
    if len(sys.argv) < 2:
        return
    base = os.path.basename(sys.argv[1])
    if not (base.startswith("titan-fwd-") and base.endswith(".py")):
        return
    try:
        os.unlink(sys.argv[1])
    except OSError:
        pass


class Fwd(object):
    def __init__(self, read, write, fd, flush):
        self.read = read
        self.write = write
        self.fd = fd
        self.flush = flush
        self.buf = b""
        self.dials = {}
        self.listeners = {}
        self.chans = {}
        self.meta = {}
        self.held = {}
        self.outs = {}
        self.next_even = 2
        self.alive = True

    def send(self, ftype, payload):
        raw = enc(ftype, payload)
        self.write(b"TITAN1 " + base64.b64encode(raw) + b"\n")
        self.flush()

    def serve(self):
        unlink_self()
        self.send(HELLO, b"1")
        while self.alive:
            try:
                self.step()
            except (OSError, ValueError):
                self.alive = False

    def step(self):
        watch_r = []
        if not any(len(buf) >= HIGH for buf in self.outs.values()):
            watch_r.append(self.fd)
        for sock in self.listeners.values():
            watch_r.append(sock)
        for chan, sock in self.chans.items():
            if len(self.held.get(chan, b"")) < HIGH:
                watch_r.append(sock)
        watch_w = [sock for chan, sock in self.chans.items() if self.outs.get(chan)]
        if not watch_r and not watch_w:
            time.sleep(0.5)
            return
        ready_r, ready_w, _ = select.select(watch_r, watch_w, [], 0.5)
        if self.fd in ready_r:
            chunk = self.read(65536)
            if not chunk:
                self.alive = False
                return
            self.buf += chunk
            frames = self.pull_frames()
            for ftype, payload in frames:
                self.frame(ftype, payload)
        for tid, sock in list(self.listeners.items()):
            if sock in ready_r:
                self.accept(tid, sock)
        for chan, sock in list(self.chans.items()):
            if sock in ready_r:
                self.read_sock(chan, sock)
            if sock in ready_w:
                self.write_sock(chan, sock)

    def pull_frames(self):
        frames = []
        while self.buf:
            cut = None
            for index, byte in enumerate(self.buf):
                if byte in (10, 13):
                    cut = index
                    break
            if cut is None:
                break
            line = self.buf[:cut]
            drop = 2 if self.buf[cut : cut + 2] == b"\r\n" else 1
            self.buf = self.buf[cut + drop :]
            if not line.startswith(b"TITAN1 "):
                continue
            raw = base64.b64decode(line[7:])
            got, rest = dec(raw)
            if rest:
                raise ValueError("bad frame")
            frames.extend(got)
        return frames

    def frame(self, ftype, payload):
        if ftype == BIND and len(payload) >= 7:
            tid, kind, port = struct.unpack(">IBH", payload[:7])
            host = "127.0.0.1"
            if len(payload) >= 9:
                (n,) = struct.unpack(">H", payload[7:9])
                if len(payload) < 9 + n:
                    return
                host = payload[9 : 9 + n].decode("utf-8")
            self.bind(tid, kind, port, host)
        elif ftype == OPEN and len(payload) >= 8:
            chan, tid = struct.unpack(">II", payload[:8])
            self.open(chan, tid)
        elif ftype == OPEN_FAIL and len(payload) >= 4:
            (chan,) = struct.unpack(">I", payload[:4])
            self.close_chan(chan, False)
        elif ftype == DATA and len(payload) >= 4:
            (chan,) = struct.unpack(">I", payload[:4])
            self.data(chan, payload[4:])
        elif ftype == CLOSE and len(payload) >= 4:
            (chan,) = struct.unpack(">I", payload[:4])
            self.close_chan(chan, False)
        elif ftype == DROP and len(payload) >= 4:
            (tid,) = struct.unpack(">I", payload[:4])
            self.drop(tid)

    def bind(self, tid, kind, port, host="127.0.0.1"):
        if tid in self.dials or tid in self.listeners:
            self.send(BIND_FAIL, pack_err(tid, "duplicate tunnel"))
            return
        if kind == KIND_L:
            self.dials[tid] = (host, port)
            self.send(BOUND, struct.pack(">I", tid))
            return
        if kind != KIND_R:
            self.send(BIND_FAIL, pack_err(tid, "bad kind"))
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(128)
            sock.setblocking(False)
        except OSError as exc:
            self.send(BIND_FAIL, pack_err(tid, str(exc)))
            return
        self.listeners[tid] = sock
        self.send(BOUND, struct.pack(">I", tid))

    def open(self, chan, tid):
        if chan in self.chans:
            self.send(OPEN_FAIL, pack_err(chan, "channel in use"))
            return
        target = self.dials.get(tid)
        if target is None:
            self.send(OPEN_FAIL, pack_err(chan, "unknown tunnel"))
            return
        host, port = target
        try:
            sock = socket.create_connection((host, port), timeout=10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setblocking(False)
        except OSError as exc:
            self.send(OPEN_FAIL, pack_err(chan, str(exc)))
            return
        self.chans[chan] = sock
        self.meta[chan] = tid
        self.held[chan] = bytearray()
        self.outs.setdefault(chan, bytearray())
        self.send(OPENED, struct.pack(">I", chan))

    def accept(self, tid, sock):
        try:
            conn, _addr = sock.accept()
        except OSError:
            return
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.setblocking(False)
        chan = self.next_even
        self.next_even += 2
        self.chans[chan] = conn
        self.meta[chan] = tid
        self.held[chan] = bytearray()
        self.outs.setdefault(chan, bytearray())
        self.send(OPEN, struct.pack(">II", chan, tid))

    def read_sock(self, chan, sock):
        held = self.held.setdefault(chan, bytearray())
        if len(held) >= HIGH:
            return
        try:
            data = sock.recv(min(MAX_DATA, HIGH - len(held)))
        except OSError:
            data = b""
        if not data:
            self.close_chan(chan, True)
            return
        held += data
        self.flush_held(chan)

    def flush_held(self, chan):
        held = self.held.get(chan)
        if not held:
            return
        take = bytes(held[:MAX_DATA])
        del held[: len(take)]
        self.send(DATA, struct.pack(">I", chan) + take)

    def write_sock(self, chan, sock):
        pending = self.outs.get(chan)
        if not pending:
            return
        try:
            sent = sock.send(pending)
        except OSError:
            self.close_chan(chan, True)
            return
        del pending[:sent]

    def data(self, chan, blob):
        if chan not in self.chans:
            return
        pending = self.outs.setdefault(chan, bytearray())
        pending += blob

    def close_chan(self, chan, notify):
        sock = self.chans.pop(chan, None)
        self.meta.pop(chan, None)
        self.held.pop(chan, None)
        self.outs.pop(chan, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if notify and sock is not None:
            self.send(CLOSE, struct.pack(">I", chan))

    def drop(self, tid):
        self.dials.pop(tid, None)
        sock = self.listeners.pop(tid, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        for chan in [c for c, owner in self.meta.items() if owner == tid]:
            self.close_chan(chan, True)


def main():
    # BufferedReader.read(n) keeps reading until n bytes. On this PTY that
    # blocks forever after the first short line, so BIND never gets parsed.
    infd = sys.stdin.fileno()
    outfd = sys.stdout.fileno()

    def read(n):
        return os.read(infd, n)

    def write(data):
        view = data
        while view:
            sent = os.write(outfd, view)
            view = view[sent:]

    fwd = Fwd(read, write, infd, lambda: None)
    fwd.serve()


if __name__ == "__main__":
    main()
'''


def load_remote():
    namespace = {"__name__": "titan_remote"}
    exec(REMOTE_SOURCE, namespace)
    return namespace["Fwd"]


def _as_bytes(message) -> bytes:
    if isinstance(message, str):
        return message.encode("utf-8")
    return message


def _ws_send(ws, data: bytes) -> None:
    if not data:
        return
    try:
        ws.send(data.decode("utf-8"))
    except UnicodeDecodeError:
        ws.send(data)


def _send_wire(ws, blob: bytes) -> None:
    if not blob:
        return
    frames, rest = decode_frames(blob)
    if rest:
        raise RuntimeError("bad frame")
    for frame_type, payload in frames:
        ws.send(wire_line(encode_frame(frame_type, payload)).decode("ascii"))


def _feed_link(link: Link, pending: bytes, data: bytes) -> bytes:
    pending += data
    try:
        raws, pending = unwrap_wire(pending)
    except ValueError as exc:
        raise RuntimeError("bad frame") from exc
    for raw in raws:
        link.push(raw)
    return pending


def _fail_text(exc: BaseException) -> str:
    from websockets.exceptions import ConnectionClosed

    if isinstance(exc, (ConnectionClosed, ConnectionError, OSError)):
        return format_disconnect(exc)
    text = str(exc).splitlines()
    return text[0] if text else exc.__class__.__name__


def _mirror_stdin(fd: int, ws) -> None:
    ready, _, _ = select.select([fd], [], [], 0)
    if fd not in ready:
        return
    data = os.read(fd, 1024)
    if data:
        _ws_send(ws, data)


def _take_lines(fd: int, buf: bytes) -> Tuple[bytes, List[str]]:
    ready, _, _ = select.select([fd], [], [], 0)
    if fd in ready:
        chunk = os.read(fd, 1024)
        if chunk:
            buf += chunk
    buf = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    messages = []
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        messages.append(line.decode("utf-8", "replace").strip())
    return buf, messages


def run_forward(url: str, origin: str, credential: Optional[dict], specs) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("titan ssh needs a terminal")
    from websockets.sync.client import connect

    from titan.tls import unverified_context

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        try:
            with connect(
                url,
                origin=origin,
                ssl=unverified_context(),
                max_size=None,
                open_timeout=20,
            ) as ws:
                return _session(ws, fd, old, credential, specs)
        except KeyboardInterrupt:
            return 0
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(_fail_text(exc)) from exc
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _session(ws, fd: int, old, credential: Optional[dict], specs) -> int:
    incoming: queue.Queue = queue.Queue()

    def reader() -> None:
        try:
            while True:
                incoming.put(ws.recv())
        except Exception as exc:
            incoming.put(exc)

    thread = threading.Thread(target=reader, name="forward-read", daemon=True)
    thread.start()
    stop = {"hit": False}

    def on_int(_signum, _frame) -> None:
        stop["hit"] = True

    previous = signal.signal(signal.SIGINT, on_int)
    raw = False
    painted = 0
    line_buf = b""
    shown = None
    try:
        if credential is None:
            tty.setraw(fd)
            raw = True
        dest = "/tmp/titan-fwd-%s" % uuid.uuid4().hex
        boot = Bootstrap(
            REMOTE_SOURCE,
            dest + ".b64",
            dest + ".py",
            time.monotonic,
            credential,
        )
        link = None
        while True:
            if stop["hit"]:
                if link is not None:
                    link.drop_all()
                    _send_wire(ws, link.take_send())
                return 0
            if link is None:
                show = credential is None and boot.phase in ("login", "prompt")
                if show:
                    _mirror_stdin(fd, ws)
                try:
                    item = incoming.get(timeout=0.1)
                except queue.Empty:
                    item = None
                if isinstance(item, BaseException):
                    raise RuntimeError(_fail_text(item))
                if item:
                    data = _as_bytes(item)
                    if show:
                        os.write(sys.stdout.fileno(), data)
                    boot.push(data)
                else:
                    boot.poll()
                _ws_send(ws, boot.take())
                if boot.phase != "done":
                    continue
                if raw:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                    raw = False
                link = Link(list(specs))
                wire_buf = _feed_link(link, b"", boot.rest)
                link.start()
                _send_wire(ws, link.take_send())
                shown = link.table.render()
                painted = paint(sys.stdout, 0, shown)
                if link.all_failed():
                    return 1
                continue
            link.poll(0.05)
            line_buf, messages = _take_lines(fd, line_buf)
            for message in messages:
                if not message:
                    continue
                note = link.kill(message)
                if note:
                    print(note, file=sys.stderr)
            _send_wire(ws, link.take_send())
            while True:
                try:
                    item = incoming.get_nowait()
                except queue.Empty:
                    break
                if isinstance(item, BaseException):
                    raise RuntimeError(_fail_text(item))
                wire_buf = _feed_link(link, wire_buf, _as_bytes(item))
                _send_wire(ws, link.take_send())
            block = link.table.render()
            if block != shown:
                painted = paint(sys.stdout, painted, block)
                shown = block
            if link.all_failed():
                return 1
    finally:
        signal.signal(signal.SIGINT, previous)
        if raw:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
