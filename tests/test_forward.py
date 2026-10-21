import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from titan.accesses import Access
from titan.cli import main
from titan.forward import (
    BIND,
    BOUND,
    CLOSE,
    DATA,
    DROP,
    HELLO,
    HELLO_FRAME,
    KIND_L,
    KIND_R,
    OPEN,
    OPENED,
    Bootstrap,
    Link,
    TunnelTable,
    _dial,
    _listen,
    chunk_script,
    decode_frames,
    encode_frame,
    load_remote,
    parse_port_pair,
    run_forward,
)


class Clock(object):
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _paths():
    return "/tmp/titan-fwd-abc.b64", "/tmp/titan-fwd-abc.py"


def _boot(clock, credential=None, script="print(1)\n"):
    b64, py = _paths()
    return Bootstrap(script, b64, py, clock, credential)


def _free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _read_frames(sock, count, timeout=2):
    sock.settimeout(timeout)
    buf = b""
    found = []
    while len(found) < count:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        frames, buf = decode_frames(buf)
        found.extend(frames)
    return found


def test_parse_port_pair_accepts_bounds():
    assert parse_port_pair("27017:27017") == (27017, 27017)
    assert parse_port_pair("1:65535") == (1, 65535)


@pytest.mark.parametrize("text", ["0:1", "1:0", "65536:1", "1:65536", "1:2:3", "foo", "", "27017: 27017", " 1:2"])
def test_parse_port_pair_rejects(text):
    with pytest.raises(ValueError):
        parse_port_pair(text)


def test_frame_round_trip_keeps_nul_and_partial_tail():
    frame = encode_frame(DATA, struct.pack(">I", 7) + b"a\x00b")
    frames, rest = decode_frames(frame + b"\x01\x02")
    assert frames == [(DATA, struct.pack(">I", 7) + b"a\x00b")]
    assert rest == b"\x01\x02"
    assert encode_frame(HELLO, b"1") == HELLO_FRAME
    frames, rest = decode_frames(frame[:3])
    assert frames == []
    assert rest == frame[:3]


def test_decode_rejects_bad_lengths():
    with pytest.raises(ValueError):
        decode_frames(struct.pack(">I", 0))
    with pytest.raises(ValueError):
        decode_frames(struct.pack(">I", 65537) + b"\x00")


def test_chunk_script_round_trip_under_3000():
    import base64

    source = "print('x')\n" * 400
    dest = "/tmp/titan-fwd-abc.b64"
    lines = chunk_script(source, dest)
    assert len(lines) > 1
    assert all(len(line) <= 3000 for line in lines)
    assert all("exec python3" not in line for line in lines)
    parts = []
    marker = "printf '%s' '"
    for line in lines:
        assert line.startswith(marker)
        parts.append(line[len(marker) :].split("' >>", 1)[0])
    assert base64.b64decode("".join(parts)) == source.encode("utf-8")


def test_tunnel_table_kill_render_and_stable_ids():
    table = TunnelTable()
    table.add("L", 27017, 27017)
    table.add("R", 9000, 3000)
    table.mark_up(1)
    table.add_conn(1)
    text = table.render()
    assert "1  L  laptop 127.0.0.1:27017  dial vm 127.0.0.1:27017  conns 1" in text
    assert "2  R  vm 127.0.0.1:9000  dial laptop 127.0.0.1:3000  wait" in text
    assert text.endswith("type a number to kill that tunnel")
    assert table.kill("1") is None
    assert table.get(1).status == "dead"
    assert table.get(2).id == 2
    assert table.kill("1") == "no tunnel 1"
    assert table.kill("nope") == "no tunnel nope"
    assert table.kill("9") == "no tunnel 9"
    table.mark_fail(2, "busy")
    assert "fail: busy" in table.render()
    assert table.kill("2") == "no tunnel 2"


def test_bootstrap_waits_then_sends_one_chunk():
    clock = Clock()
    boot = _boot(clock)
    boot.push(b"user@host:~$ ")
    assert boot.take() == b""
    clock.advance(0.3)
    boot.poll()
    sent = boot.take()
    assert sent.endswith(b"\r")
    assert b"TITAN_OK" in sent
    assert b"exec python3" not in sent
    assert boot.phase == "ack"


def test_bootstrap_ignores_echo_until_prompt_returns():
    clock = Clock()
    boot = _boot(clock)
    boot.push(b"user@host:~$ ")
    clock.advance(0.3)
    boot.poll()
    boot.take()
    boot.push(b"printf '%s' 'xx' && echo TITAN_OK")
    clock.advance(0.3)
    boot.poll()
    assert boot.phase == "ack"
    assert boot.take() == b""


def test_bootstrap_hello_and_timeouts():
    clock = Clock()
    boot = _boot(clock)
    boot.push(b"user@host:~$ ")
    clock.advance(0.3)
    boot.poll()
    boot.take()
    boot.push(b"\r\nTITAN_OK\r\nuser@host:~$ ")
    clock.advance(0.3)
    boot.poll()
    sent = boot.take()
    assert b"TITAN_EXEC" in sent
    assert boot.phase == "hello"
    boot.push(HELLO_FRAME + b"left")
    assert boot.phase == "done"
    assert boot.rest == b"left"

    clock = Clock()
    boot = _boot(clock)
    clock.advance(60)
    with pytest.raises(RuntimeError, match="no shell prompt"):
        boot.poll()

    clock = Clock()
    boot = _boot(clock)
    boot.push(b"user@host:~$ ")
    clock.advance(0.3)
    boot.poll()
    clock.advance(5)
    with pytest.raises(RuntimeError, match="forwarder did not start"):
        boot.poll()

    clock = Clock()
    boot = _boot(clock)
    boot.push(b"user@host:~$ ")
    clock.advance(0.3)
    boot.poll()
    boot.take()
    boot.push(b"\r\nTITAN_OK\r\nuser@host:~$ ")
    clock.advance(0.3)
    boot.poll()
    boot.take()
    clock.advance(20)
    with pytest.raises(RuntimeError, match="forwarder did not start"):
        boot.poll()


def test_bootstrap_reports_missing_tools_and_types_password():
    clock = Clock()
    boot = _boot(clock)
    with pytest.raises(RuntimeError, match="vm has no python3"):
        boot.push(b"python3: not found\n")
    boot = _boot(clock)
    with pytest.raises(RuntimeError, match="vm has no base64"):
        boot.push(b"base64: command not found\n")
    clock = Clock()
    boot = _boot(clock, {"username": "root", "password": "s3cret"})
    boot.push(b"login: ")
    assert boot.take() == b"root\r"
    boot.push(b"\r\nPassword:")
    assert boot.take() == b"s3cret\r"


def test_listen_sets_reuseaddr_and_dial_sets_nodelay():
    listener = _listen(0)
    port = listener.getsockname()[1]
    try:
        assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
        sock = _dial(port)
        try:
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0
        finally:
            sock.close()
    finally:
        listener.close()


def test_link_local_forward_and_kill():
    port = _free_port()
    link = Link([("L", port, 9)])
    assert link.start() == 0
    frames, _rest = decode_frames(link.take_send())
    assert frames[0][0] == BIND
    assert struct.unpack(">IBH", frames[0][1]) == (1, KIND_L, 9)
    link.push(encode_frame(BOUND, struct.pack(">I", 1)))
    assert "conns 0" in link.table.render()
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        link.poll(0.5)
        frames, _rest = decode_frames(link.take_send())
        assert frames[0][0] == OPEN
        chan, tid = struct.unpack(">II", frames[0][1])
        assert tid == 1
        link.push(encode_frame(OPENED, struct.pack(">I", chan)))
        assert "conns 1" in link.table.render()
        client.sendall(b"hi")
        link.poll(0.5)
        frames, _rest = decode_frames(link.take_send())
        assert frames[0][0] == DATA
        assert frames[0][1][4:] == b"hi"
        link.push(encode_frame(DATA, struct.pack(">I", chan) + b"yo"))
        link.poll(0.5)
        client.settimeout(1)
        assert client.recv(8) == b"yo"
    finally:
        client.close()
    assert link.kill("1") is None
    assert "dead" in link.table.render()
    frames, _rest = decode_frames(link.take_send())
    assert frames[-1][0] == DROP
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.5)


def test_link_remote_forward_dials_laptop():
    service = _listen(0)
    port = service.getsockname()[1]
    service.settimeout(2)
    link = Link([("R", 9000, port)])
    link.start()
    link.take_send()
    link.push(encode_frame(BOUND, struct.pack(">I", 1)))
    link.push(encode_frame(OPEN, struct.pack(">II", 2, 1)))
    frames, _rest = decode_frames(link.take_send())
    assert frames[0][0] == OPENED
    try:
        conn, _addr = service.accept()
        try:
            link.push(encode_frame(DATA, struct.pack(">I", 2) + b"zz"))
            link.poll(0.5)
            conn.settimeout(1)
            assert conn.recv(8) == b"zz"
        finally:
            conn.close()
    finally:
        service.close()
        link.drop_all()


def test_link_all_listen_fail(monkeypatch):
    def boom(_port):
        raise OSError("busy")

    monkeypatch.setattr("titan.forward._listen", boom)
    link = Link([("L", 20000, 9)])
    assert link.start() == 1
    assert "fail: busy" in link.table.render()


def test_remote_dials_and_drop_closes_listen():
    left, right = socket.socketpair()
    Fwd = load_remote()
    fwd = Fwd(right.recv, right.sendall, right.fileno(), lambda: None)
    thread = threading.Thread(target=fwd.serve, daemon=True)
    thread.start()
    service = socket.socket()
    service.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    service.bind(("127.0.0.1", 0))
    service.listen(1)
    service.settimeout(2)
    port = service.getsockname()[1]
    try:
        hello = _read_frames(left, 1)[0]
        assert hello == (HELLO, b"1")
        left.sendall(encode_frame(BIND, struct.pack(">IBH", 1, KIND_L, port)))
        bound = _read_frames(left, 1)[0]
        assert bound[0] == BOUND
        left.sendall(encode_frame(OPEN, struct.pack(">II", 1, 1)))
        opened = _read_frames(left, 1)[0]
        assert opened[0] == OPENED
        conn, _addr = service.accept()
        try:
            left.sendall(encode_frame(DATA, struct.pack(">I", 1) + b"ab"))
            conn.settimeout(2)
            assert conn.recv(8) == b"ab"
            conn.sendall(b"AB")
            data = _read_frames(left, 1)[0]
            assert data[0] == DATA
            assert data[1][4:] == b"AB"
        finally:
            conn.close()
        assert _read_frames(left, 1)[0][0] == CLOSE
        listen_port = _free_port()
        left.sendall(encode_frame(BIND, struct.pack(">IBH", 2, KIND_R, listen_port)))
        assert _read_frames(left, 1)[0][0] == BOUND
        left.sendall(encode_frame(DROP, struct.pack(">I", 2)))
        time.sleep(0.3)
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", listen_port), timeout=0.5)
    finally:
        fwd.alive = False
        left.close()
        right.close()
        service.close()
        thread.join(1)


def _rows():
    return [
        Access("id-1", "web", "vm-a", "10.0.0.1"),
        Access("id-2", "db", "vm-b", "10.0.0.2"),
    ]


def test_ssh_flags_call_forward_in_order(monkeypatch):
    seen = {}

    def fake_run(url, origin, credential, specs):
        seen["url"] = url
        seen["origin"] = origin
        seen["credential"] = credential
        seen["specs"] = specs
        return 0

    monkeypatch.setattr("titan.cli._load_accesses", _rows)
    monkeypatch.setattr("titan.cli._token", lambda: "tok")
    monkeypatch.setattr("titan.cli.credentials_path", lambda: Path("/nope/credentials.json"))
    monkeypatch.setattr("titan.cli.run_shell", lambda *args: (_ for _ in ()).throw(AssertionError("shell")))
    monkeypatch.setattr("titan.cli.run_forward", fake_run)
    assert main(["ssh", "2", "-L", "27017:27017", "-R", "9000:3000", "-L", "80:8080"]) == 0
    assert seen["specs"] == [("L", 27017, 27017), ("R", 9000, 3000), ("L", 80, 8080)]
    assert seen["origin"] == "https://titan.efarda.ir"
    assert "/ssh-proxy?" in seen["url"]
    assert seen["credential"] is None


def test_ssh_without_ports_still_opens_shell(monkeypatch):
    opened = []
    monkeypatch.setattr("titan.cli._load_accesses", _rows)
    monkeypatch.setattr("titan.cli._open_shell", lambda access: opened.append(access.id) or 0)
    monkeypatch.setattr("titan.cli.run_forward", lambda *args: (_ for _ in ()).throw(AssertionError("forward")))
    assert main(["ssh", "2"]) == 0
    assert opened == ["id-2"]


def test_bad_forward_spec_exits_before_session(capsys):
    assert main(["ssh", "vm", "-L", "nope"]) == 2
    assert capsys.readouterr().err.strip() == "bad forward spec: -L nope"


def test_run_forward_needs_terminal(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(RuntimeError, match="titan ssh needs a terminal"):
        run_forward("ws://x", "http://x", None, [("L", 1, 2)])
