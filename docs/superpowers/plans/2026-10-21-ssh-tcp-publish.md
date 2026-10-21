# SSH TCP publish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** `titan ssh -L LOCAL:REMOTE` and `-R REMOTE:LOCAL` publish TCP through the existing PAM websocket, with a foreground list the user can kill by number.

**Architecture:** One websocket. After VM login, a Python 3 forwarder on the VM speaks length-prefixed frames. The laptop binds `-L`, the VM binds `-R`, both sides dial only `127.0.0.1`. Plain `titan ssh` stays the shell.

**Tech Stack:** Python 3.9+, stdlib `socket`/`select`/`struct`, existing `websockets` sync client, pytest.

**Spec:** `docs/superpowers/specs/2026-10-21-ssh-tcp-publish-design.md`

## Global Constraints

- Hosts are always `127.0.0.1`. Ports are integers 1 through 65535. No host, no spaces.
- `-L LOCAL:REMOTE` listens on the laptop and dials the VM. `-R REMOTE:LOCAL` listens on the VM and dials the laptop.
- Flag order is tunnel id order, starting at 1. Ids are not reused.
- VM needs `python3` and `base64`. Temp files are `/tmp/titan-fwd-<uuid>.b64` and `.py`. The program unlinks the `.py`.
- Shell lines are at most 3000 bytes and end with `\r`. Chunk ack is a new `TITAN_OK` plus a shell prompt, so command echo is not treated as completion.
- Prompt regex: `^[^\r\n]*[#$%]\s*$` on the last line, plus 300ms of quiet. Deadline 60s from websocket open.
- Per chunk line deadline 5s. Hello deadline 20s after the exec line. Hello bytes `00 00 00 02 01 31`.
- Frame: big-endian `uint32` length, then that many bytes, first byte is the type. Reject length 0 or length above 65536. DATA payload at most 32768.
- Kind 1 is `-L` (VM dials). Kind 2 is `-R` (VM listens). Laptop channels are odd from 1. VM channels are even from 2.
- Listen backlog 128, `SO_REUSEADDR`, dialed sockets `TCP_NODELAY`, dial timeout 10s.
- Per channel, stop reading a socket when 1MB of data from it is not yet written onward. Read again when that buffer is under 1MB.
- Saved password does not mirror stdin. No saved password: raw tty until hello, then cooked. Always restore the tty.
- Ctrl-C exits 0. Every tunnel `fail` exits 1. Bad spec exits 2 with `bad forward spec: ...`.
- Disconnect text reuses `format_disconnect`. No live PAM calls in tests.

## File map

- Create: `src/titan/forward.py` — parse, frames, chunks, tunnel table, bootstrap, remote program, local link, `run_forward`
- Modify: `src/titan/cli.py` — `-L` and `-R`, call `run_forward`
- Modify: `README.md` — TCP ports section
- Test: `tests/test_forward.py`

---

### Task 1: Port pairs, frames, chunks, tunnel table

**Files:**
- Create: `src/titan/forward.py`
- Test: `tests/test_forward.py`

**Interfaces:**
- Produces: `parse_port_pair(text) -> tuple`, `encode_frame(frame_type, payload) -> bytes`, `decode_frames(buffer) -> tuple`, `chunk_script(source, dest_b64) -> list`, `exec_line(dest_b64, dest_py) -> str`, `TunnelTable`

- [x] **Step 1: Write failing tests** for parse rejects, frame round-trip and partial buffers, chunk size and base64 join, table kill and render.

- [x] **Step 2: Run** `pytest tests/test_forward.py -v` and confirm fail.

- [x] **Step 3: Implement** those functions. `TunnelTable.add(kind, listen_port, dial_port)` assigns the next id. `kill(text)` returns `no tunnel VALUE` or `None`. `render()` matches the spec row and footer.

- [x] **Step 4: Re-run the tests.** Expected: pass.

- [x] **Step 5: Commit** `feat: add forward codec and tunnel list`

### Task 2: Bootstrap markers

**Files:**
- Modify: `src/titan/forward.py`
- Test: `tests/test_forward.py`

**Interfaces:**
- Consumes: `chunk_script`, `exec_line`, `LoginFeeder`
- Produces: `last_line_is_prompt(visible) -> bool`, `remote_tool_error(visible) -> str`, `Bootstrap`

- [x] **Step 1: Tests** for prompt, `vm has no python3`, `vm has no base64`, quiet 300ms before the first chunk, ack waits for prompt after `TITAN_OK`, hello split, 60s and 5s and 20s errors.

- [x] **Step 2: Implement `Bootstrap`.** `push(data)` and `poll()` and `take() -> bytes`. Feeder replies are queued while a credential exists. Phase `done` exposes `rest` bytes after the hello frame.

- [x] **Step 3: Tests pass. Commit** `feat: add forwarder bootstrap`

### Task 3: Remote program and local link

**Files:**
- Modify: `src/titan/forward.py`
- Test: `tests/test_forward.py`

**Interfaces:**
- Consumes: frame codec, `TunnelTable`
- Produces: `REMOTE_SOURCE`, `load_remote()`, `Link`

- [x] **Step 1: Test** the remote `Fwd` over a `socketpair`: hello, BIND kind L, OPEN dials a local server, DATA both ways, DROP closes a kind R listen.

- [x] **Step 2: Test** `Link` for `-L` accept/OPEN/DATA and `-R` dial, kill sends DROP, `SO_REUSEADDR` on the listener, all-fail returns 1.

- [x] **Step 3: Implement** `REMOTE_SOURCE` and `Link`. Unlink only a path whose basename starts with `titan-fwd-` and ends with `.py`.

- [x] **Step 4: Tests pass. Commit** `feat: forward TCP in both directions`

### Task 4: CLI, tty gate, README

**Files:**
- Modify: `src/titan/cli.py`
- Modify: `src/titan/forward.py` (`run_forward`)
- Modify: `README.md`
- Test: `tests/test_forward.py`

**Interfaces:**
- Consumes: `parse_port_pair`, `run_forward`, `Bootstrap`, `Link`, `format_disconnect`
- Produces: `titan ssh` accepts repeated `-L` and `-R` in argv order

- [x] **Step 1: Tests.** `-L -R -L` calls `run_forward` with `[("L", 27017, 27017), ("R", 9000, 3000), ("L", 80, 8080)]`. No flags still open the shell. `bad forward spec: -L nope` exits 2. Non-tty `run_forward` raises `titan ssh needs a terminal`.

- [x] **Step 2: Implement CLI and `run_forward`.** Parse specs before loading accesses. Reader thread on the websocket. Saved password: no stdin mirror. No password: raw until hello. Then cooked list. Ctrl-C returns 0. Websocket failure raises `RuntimeError` with `format_disconnect` when that helper applies.

- [x] **Step 3: README section** `TCP ports` with the flag table, the kill line, and Ctrl-C.

- [x] **Step 4: `pytest tests -v` pass. Commit** `feat: publish TCP ports from titan ssh`

## Self-review notes

- Spec row text, exit codes, frame types, and deadlines are tasks 1–4.
- Shell session behavior stays in `shell.py`.
- Out of scope stays out: no background tunnels, no extra bind address, no shell mixed into the forward session.
