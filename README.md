# titan

Command-line client for the EFARDA PAM at [titan.efarda.ir](https://titan.efarda.ir). It logs in with an ef.net account, lists the SSH accesses you can open, and attaches your local terminal to the same shell the browser uses.

The VMs are not reachable by SSH from a laptop. `titan ssh` opens the PAM websocket, then the PAM proxy connects to the VM.

## Install

Python 3.9 or newer. [pipx](https://pipx.pypa.io/) puts `titan` on `PATH`.

```bash
pipx install 'git+https://github.com/alinowrouzii/titan-cli.git'
```

If the shell cannot find `titan`, run `pipx ensurepath` and open a new terminal.

After the repo changes:

```bash
pipx reinstall titan-cli
```

### QR scanner

| System | Extra install |
| --- | --- |
| Mac | Xcode command line tools (`xcode-select --install`). The first `titan totp set --qr` compiles a small scanner. |
| Linux | `sudo apt install zbar-tools` |

`login`, `ls`, `ssh`, and `logout` do not need the scanner. Typing the 6-digit code at login works without it.

## Login

```bash
titan login
```

The command asks for your ef.net username and password. PAM then requires a TOTP code.

- If `~/.config/titan/totp` exists, `titan` sends the current code itself.
- If it does not, type the 6 digits from Google Authenticator.

The ef.net password is not saved. The session token is written to `~/.config/titan/session.json` with mode `0600`.

After login, titan asks `save VM passwords now? [y/N]`. Yes shows the server list. The same list is `titan cred set`, which works any time you are logged in.

Another PAM host:

```bash
TITAN_URL=https://titan.example.ir titan login
```

Certificate verification is off. `titan.efarda.ir` sends only the leaf certificate, and Python cannot complete the chain. A host on the network path can pretend to be the PAM.

## Accesses

```bash
titan ls
titan ssh
titan ssh 7
titan ssh Finnotech-DB-Mongo-4
titan ssh 828-651
```

`titan ssh` with no name prints the server list. `*` means that server has its own saved password. Type one number to connect.

`titan ssh 7` opens that same list row. Numbers start at 1. A number past the list stops. A bare number is always a list row, so an access id that is only digits is reached by its name.

`ls` prints resource name, access name, IP, and access id.

`ssh` matches the access id exactly, or the access name or resource name with case ignored. Zero matches stops. More than one match prints the rows and does not connect. Pass the access id when two rows share a name.

The PAM proxy then asks for the VM username and password. If that server has a saved password, or a default password is set, titan types them when it sees `login:` / `username:` and then `Password:`. Otherwise you type them. Ctrl-C goes to that remote shell. Leave with `exit`. If the prompt never returns, stop the process from another terminal:

```bash
pkill -f "titan ssh"
```

`error: connect EHOSTUNREACH <ip>:22` means the PAM server cannot route to that VM. The same Connect button in the browser fails the same way.

## TCP ports

The VM is still not reachable as an SSH server. These flags ride the same websocket and publish TCP. The VM needs `python3` and `base64`. There is no shell in this mode.

```bash
titan ssh 7 -L 27017:27017 -R 9000:3000
```

| Flag | What listens | What gets dialed |
| --- | --- | --- |
| `-L LOCAL:REMOTE` | your laptop `127.0.0.1:LOCAL` | the VM `127.0.0.1:REMOTE` |
| `-R REMOTE:LOCAL` | the VM `127.0.0.1:REMOTE` | your laptop `127.0.0.1:LOCAL` |

Repeat either flag. The list is numbered in the order you wrote the flags. Both ends stay on `127.0.0.1`.

```text
1  L  laptop 127.0.0.1:27017  dial vm 127.0.0.1:27017  conns 0
2  R  vm 127.0.0.1:9000  dial laptop 127.0.0.1:3000  conns 1
type a number to kill that tunnel
```

Type a number and Enter to close that listen and its connections. Ctrl-C closes every tunnel and returns the terminal. A saved VM password is typed for you. Without one, you log in at the VM prompt, then the list replaces the shell.

## TOTP secret

Save the Google Authenticator export QR so later logins do not ask for the code. On the phone: Transfer accounts, Export accounts. Screenshot the QR.

```bash
titan totp set --qr ~/Desktop/export.png
```

Several accounts in one QR: the command prints the names and stops. It does not print secrets. Pick one:

```bash
titan totp set --qr ~/Desktop/export.png --account EFARDA
```

Only SHA1 6-digit TOTP accounts are stored. The secret is written to `~/.config/titan/totp` with mode `0600`.

You can also type a base32 secret or an `otpauth://` URI:

```bash
titan totp set
```

Remove only the secret:

```bash
titan totp delete
```

## VM passwords

```bash
titan cred set
titan cred default
titan cred delete
```

`titan cred set` prints every server. `*` means that row already has its own password. `0` is the default username and password, used for every server that has no own password. Type numbers such as `1,3` or `0`.

`titan cred default` sets only that default.

`titan cred delete` uses the same list and removes the rows you pick.

Passwords are written to `~/.config/titan/credentials.json` with mode `0600`. `titan logout` does not delete this file.

## Logout

```bash
titan logout
```

This tells PAM to drop the session and deletes `~/.config/titan/session.json`. The TOTP secret stays. VM passwords stay. The next `titan login` still sends the code when the TOTP file is present, and `titan ssh` still uses saved VM passwords.

## Files

| Path | Contents |
| --- | --- |
| `~/.config/titan/session.json` | PAM token. Removed by `titan logout`. |
| `~/.config/titan/totp` | TOTP secret. Removed by `titan totp delete`. |
| `~/.config/titan/credentials.json` | VM usernames and passwords. Not removed by `titan logout`. Removed only by `titan cred delete`. |
| `~/.cache/titan/qrscan` | Mac QR scanner binary. No secret. |
