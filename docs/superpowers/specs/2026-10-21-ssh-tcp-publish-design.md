# SSH TCP publish

Date: 2026-10-21

`titan ssh` can publish TCP ports through the same PAM websocket it already uses for a shell. The laptop cannot open a real SSH port-forward to the VM. The websocket is one PTY byte stream, so publish mode starts a small Python 3 forwarder on the VM and speaks frames on that stream.

The 2026-10-20 CLI spec left TCP out of scope. This spec adds it. Plain `titan ssh` with no port flag stays the interactive shell.

## Command

```bash
titan ssh 7 -L 27017:27017 -R 9000:3000
```

No `-L` and no `-R`: current shell. No change.

One or more port flags: forward only. No interactive shell.

| Flag | Listen | Dial |
| --- | --- | --- |
| `-L LOCAL:REMOTE` | laptop `127.0.0.1:LOCAL` | VM `127.0.0.1:REMOTE` |
| `-R REMOTE:LOCAL` | VM `127.0.0.1:REMOTE` | laptop `127.0.0.1:LOCAL` |

- Repeat flags. One command, one VM.
- Order of flags is the tunnel list order. `-L`, then `-R`, then `-L` is tunnels 1, 2, 3.
- No target still prints the server list and asks for one number, then forwards.
- Both ports are decimal integers from 1 to 65535. No host, no bind address, no spaces.
- A bad spec exits 2 and names the flag text. Example: `bad forward spec: -L 27017`.
- Hosts are always `127.0.0.1`.
- The VM needs `python3` and `base64`.

## Screen

Stdout is a terminal. If it is not, exit 1 with `titan ssh needs a terminal`.

The list redraws in place when a row changes or a connection count changes. Each row:

```text
{id}  {L|R}  {listen side} 127.0.0.1:{listen}  dial {dial side} 127.0.0.1:{dial}  {status}
```

Listen side and dial side are `laptop` or `vm`. Status is one of:

- `wait`
- `conns N`
- `dead`
- `fail: REASON`

Footer, always the last line of the block:

```text
type a number to kill that tunnel
```

Ids start at 1 and do not get reused. `conns` counts channels that finished the dial. A dial still in progress does not count.

Stdin stays in cooked mode after the forwarder starts. The user types a number and Enter.

- That id is `wait` or `conns`: the listen closes, its connections close, the row becomes `dead`.
- That id is missing, `fail`, or already `dead`: stderr `no tunnel VALUE`. The process stays up.
- Empty line: ignore.

Ctrl-C closes every tunnel and exits 0.

A bind failure marks that row `fail` and leaves the other rows running. When every tunnel has finished its bind attempt and none shows `conns`, print the list and exit 1.

## Data path

Same websocket URL as the shell. Saved VM username and password still go through `LoginFeeder`.

No saved password: until hello, the terminal is raw and bytes copy both ways, same as the shell, so the user can type the VM login. A saved password does not mirror stdin. Keystrokes wait until the tunnel list. Any exit restores the local tty.

Prompt detection starts after the feeder finishes, or immediately when there is no saved password. Strip ANSI the same way `LoginFeeder` does. A prompt is the last line matching:

```text
^[^\r\n]*[#$%]\s*$
```

and 300ms with no more remote bytes. Deadline is 60s from websocket open. On miss, raise `no shell prompt`.

Then the laptop writes the forwarder to the VM:

1. Build a temp name `/tmp/titan-fwd-<uuid>`.
2. Send the Python source as base64 chunks. Each shell line is at most 3000 bytes and ends with `\r`:

```text
printf '%s' 'CHUNK' >> /tmp/titan-fwd-<uuid>.b64 && echo TITAN_OK
```

3. Wait until visible output contains `TITAN_OK` before the next line. Per-line deadline 5s.
4. Last line:

```text
base64 -d /tmp/titan-fwd-<uuid>.b64 > /tmp/titan-fwd-<uuid>.py && rm -f /tmp/titan-fwd-<uuid>.b64 && echo TITAN_EXEC && stty -echo -icanon raw && exec python3 -u /tmp/titan-fwd-<uuid>.py
```

5. Wait until visible output contains `TITAN_EXEC`. Keep every socket byte. The text scan and the hello scan share that buffer.
6. The Python program unlinks its own `.py` path, then sends hello.
7. Search the same buffer for the hello frame. Deadline 20s after the exec line is sent.

If those 20s expire, raise `forwarder did not start`.

If remote text contains `python3: not found` or `python3: command not found`, raise `vm has no python3`.

If remote text contains `base64: not found` or `base64: command not found`, raise `vm has no base64`.

After hello, stop mirroring. The socket carries frames only. The screen is the tunnel list. Local listens for `-L` are created after hello, with `SO_REUSEADDR`. Dialed sockets set `TCP_NODELAY`. Listen backlog is 128. Dial timeout is 10s.

Then the laptop sends one bind frame per tunnel that still needs the VM:

- `-L` whose local listen succeeded: kind dial, port is the VM port.
- `-R`: kind listen, port is the VM port.
- `-L` whose local listen failed: no bind frame. Row is `fail` with the OS error.

A bind success row becomes `conns 0`. A bind failure row becomes `fail` with the remote error text.

Websocket drop: close every socket, exit 1, print the same disconnect line the shell uses.

## Frames

Big-endian. A frame is `uint32` length, then that many bytes. The first of those bytes is the type. Length counts the type byte plus the payload. Reject a length of 0 or a length above 65536. A bad frame closes the websocket and exits 1.

Data payloads are at most 32768 bytes. Larger reads split into more frames.

| Type | Id | Payload | Direction |
| --- | --- | --- | --- |
| HELLO | 1 | utf-8 `1` | VM to laptop, once |
| BIND | 2 | `uint32` id, `uint8` kind, `uint16` port | laptop to VM |
| BOUND | 3 | `uint32` id | VM to laptop |
| BIND_FAIL | 4 | `uint32` id, `uint16` n, n utf-8 bytes | VM to laptop |
| OPEN | 5 | `uint32` channel, `uint32` id | either way |
| OPENED | 6 | `uint32` channel | the dialer |
| OPEN_FAIL | 7 | `uint32` channel, `uint16` n, n utf-8 bytes | the dialer |
| DATA | 8 | `uint32` channel, then bytes | either way |
| CLOSE | 9 | `uint32` channel | either way |
| DROP | 10 | `uint32` id | laptop to VM |

Kind 1 means `-L`: the VM dials `127.0.0.1:port`. Kind 2 means `-R`: the VM listens on `127.0.0.1:port`.

The side that accepted the TCP connection allocates the channel and sends OPEN. Laptop channels are odd, starting at 1. VM channels are even, starting at 2.

OPEN for a known `-L` id makes the VM dial. OPEN for a known `-R` id makes the laptop dial. The dialer replies OPENED or OPEN_FAIL. OPEN for an unknown id gets OPEN_FAIL. A second OPEN for a live channel gets OPEN_FAIL.

CLOSE is idempotent. DATA or CLOSE for an unknown channel is ignored. On DROP, the VM closes that listen if it is `-R`, forgets a `-L` dial port, and closes that tunnel's sockets. The laptop has already closed its side.

Each channel buffers at most 1MB of unread outbound bytes. At that mark, stop reading that socket. Read again when the buffer is under 1MB.

Hello bytes are exactly `00 00 00 02 01 31`.

## Modules

| Unit | Job |
| --- | --- |
| `src/titan/cli.py` | Accept repeated `-L` and `-R` on one list, in argv order. Port flags call the forwarder. No port flags call the shell. |
| `src/titan/forward.py` | Parse pairs, frames, chunk the remote script, tunnel list, binds, kill, websocket loop. |
| `src/titan/shell.py` | Shell behavior stays. Forward mode reuses `LoginFeeder`, `ssh_proxy_url`, and `format_disconnect`. |
| `tests/test_forward.py` | Unit tests below. No live PAM. |
| `README.md` | One section for the flags, the screen, and Ctrl-C. |

`forward.py` exposes:

- `parse_port_pair(text) -> tuple[int, int]`
- `encode_frame(type, payload) -> bytes`
- `decode_frames(buffer) -> tuple[list[tuple[int, bytes]], bytes]`. A partial tail is returned, not parsed. A complete frame with length 0 or length above 65536 raises `ValueError`.
- `chunk_script(source: str, dest_b64: str) -> list[str]`. Only the `printf` lines. The exec line is not included.
- `TunnelTable` with add, mark, kill, connection count, and render
- `run_forward(...) -> int`

`run_forward` returns 0 on Ctrl-C and 1 when every tunnel failed to bind. Prompt, hello, missing `python3`, missing `base64`, a bad frame, and a dropped websocket raise `RuntimeError` with the text in this spec. The CLI already prints that and returns 1.

## Errors

| Case | Result |
| --- | --- |
| Bad port spec | Exit 2. `bad forward spec: ...` |
| Not a terminal | Exit 1. `titan ssh needs a terminal` |
| No session, bad target, PAM login failure | Same as `titan ssh` today |
| No shell prompt in 60s | Exit 1. `no shell prompt` |
| Chunk line gets no `TITAN_OK` in 5s | Exit 1. `forwarder did not start` |
| No hello in 20s | Exit 1. `forwarder did not start` |
| VM has no `python3` | Exit 1. `vm has no python3` |
| VM has no `base64` | Exit 1. `vm has no base64` |
| One bind fails | That row `fail`. Others stay. |
| Every bind fails | Print the list. Exit 1. |
| One dial fails | That connection closes. Tunnel stays. |
| Websocket drops | Exit 1. Shell disconnect line. |
| Bad frame | Exit 1. `bad frame` |
| Ctrl-C | Close all. Exit 0. |
| Kill a live number | Row `dead`. Process stays. |
| Kill anything else | stderr `no tunnel VALUE`. Process stays. |

## Tests

Unit tests only. No live PAM call.

- `parse_port_pair` accepts `27017:27017` and rejects `0`, `65536`, `1:2:3`, `foo`, empty, and embedded spaces.
- `-L`, `-R`, `-L` on `main` produce ids 1, 2, 3 in that kind order, and call `run_forward` instead of the shell.
- `main(["ssh", "2"])` with no port flags still calls the shell path.
- Frame encode and decode round-trip, including a DATA payload with a NUL byte. A partial buffer returns no frame and keeps the tail.
- Length 0 and length above 65536 are errors.
- `chunk_script` lines are each at most 3000 bytes, and joining the chunks base64-decodes to the source.
- `TunnelTable` kill leaves the id dead, does not renumber, tracks connection count, and render includes the ports. Killing a dead or unknown id is the `no tunnel` message.

Manual check, on a logged-in machine, after implementation: `titan ssh <name> -L <local>:<remote>` against a VM port that accepts TCP, connect to the local port, type that tunnel's number and confirm the listen dies, then Ctrl-C and confirm the local terminal is usable. Run plain `titan ssh <name>` and confirm it is still a shell.

## Out of scope

- A shell in the same session as the ports
- Tunnels that stay up after the process exits
- Adding a tunnel after start
- Bind addresses other than `127.0.0.1`
- Host names in `-L` or `-R`
- A native PAM TCP proxy
