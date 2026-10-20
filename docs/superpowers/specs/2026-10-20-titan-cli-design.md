# Titan CLI design

Date: 2026-10-20

Local CLI for EFARDA PAM at `https://titan.efarda.ir` (SPARA XDR). The browser already opens a VM shell. This CLI opens that same shell in the local terminal.

## Goal

From a laptop that cannot SSH to the VM directly:

1. Log in with the ef.net account (username and password sent to PAM).
2. List SSH accesses.
3. Open an interactive shell on one access.

## Out of scope

- RDP and Guacamole
- App-log shells (`app:`)
- TCP and transparent troubleshoot shells
- Telnet and PowerShell connects
- Saving the password
- One-shot remote commands (`titan run`)

## Commands

| Command | Behavior |
| --- | --- |
| `titan login` | Prompt for username and password. Resolve the LDAP provider whose name is `ef.net`. Log in. Write the token. |
| `titan ls` | Print SSH accesses: resource name, access name, IP, id. |
| `titan ssh <name-or-id>` | Interactive local shell for that access. |

Host defaults to `https://titan.efarda.ir`. Override with `TITAN_URL`.

## Session file

Path: `~/.config/titan/session.json`

Mode: `0600`

Contents: the JSON object returned by login, stored as-is. The password is never written.

If the file is missing, `ls` and `ssh` exit 1 and tell the user to run `titan login`.

## Login

PAM login is Thrift over HTTP, not JSON.

1. Call external providers on `/api/auth/auth`.
2. From `ldap`, pick the provider whose name is `ef.net`. If none, exit 1 and list the provider names that exist.
3. Call login with `username`, `password`, and `federationId` set to that provider's `id`.
4. On success, write `session.json`.
5. On failure, print the PAM error and do not write a file.

## List

Same set as the browser page "SSH Accesses": containers whose protocol is SSH and whose resource type is workstation, server, or network device. Service path: `/api/identity/containers`.

`titan ls` prints one row per access: resource name, access name, resource IP, access id.

`titan ssh` treats the argument as a hit when it equals the access id, or when it equals the access name (`name`) or resource name (`resource_name`) with case ignored. Hits are the union. Zero hits: exit 1. More than one hit: print those rows, do not connect, exit 1.

## Shell

The browser Connect button opens `/{protocol}?id=<access id>`, then a websocket.

For SSH:

```
wss://<host>/ssh-proxy?cols=<cols>&rows=<rows>&token=<token>&sessionCookie=<uuid>&destination=<access id>&protocol=ssh
```

`sessionCookie` is a new UUID per connection, hyphens removed, matching the browser.

`titan ssh`:

1. Load the token. On HTTP 403, say the session is dead and tell the user to log in again. Exit 1.
2. Resolve `<name-or-id>` with the rules in List. One hit: use that access id.
3. Read the local terminal size for `cols` and `rows`.
4. Open the websocket.
5. Put the local tty in raw mode. Copy bytes both ways.
6. On resize, if the live socket has no resize message, keep the size from connect.
7. On socket close, error, or Ctrl-C, restore the tty and exit.

## Components

| Unit | Job |
| --- | --- |
| `cli` | Parse `login`, `ls`, `ssh`. |
| `config` | `TITAN_URL` and the session path. |
| `thrift` | Minimal Thrift binary HTTP client for the calls above. |
| `auth` | External providers, login, read and write the session file. |
| `accesses` | List SSH accesses and resolve a name or id. |
| `shell` | Build the websocket URL, raw tty, byte bridge. |

Python package in this repo. Console script name: `titan`.

## Errors

| Case | Result |
| --- | --- |
| No session file | Exit 1. Say run `titan login`. |
| Bad password | Print PAM error. No token file. |
| ef.net provider missing | Exit 1. Print LDAP provider names. |
| Token rejected (403) | Exit 1. Say run `titan login`. |
| Name matches nothing | Exit 1. |
| Name matches many | Print matches. Exit 1. Do not connect. |
| Websocket fails | Print the reason. Restore the tty. |
| Ctrl-C | Close the socket. Restore the tty. |

## Tests

Unit tests only. No live call to PAM.

- Websocket URL contains cols, rows, token, session cookie, destination, and `protocol=ssh`.
- Name resolve: exact one, many, none.
- Session file is created with mode `0600`.

Manual check after implementation, on the user's machine: `titan login`, `titan ls`, `titan ssh <name>`, type a command, exit, confirm the local terminal is usable again.
