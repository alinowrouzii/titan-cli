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

The password is not saved. The session token is written to `~/.config/titan/session.json` with mode `0600`.

Another PAM host:

```bash
TITAN_URL=https://titan.example.ir titan login
```

Certificate verification is off. `titan.efarda.ir` sends only the leaf certificate, and Python cannot complete the chain. A host on the network path can pretend to be the PAM.

## Accesses

```bash
titan ls
titan ssh Finnotech-DB-Mongo-4
titan ssh 828-651
```

`ls` prints resource name, access name, IP, and access id.

`ssh` matches the access id exactly, or the access name or resource name with case ignored. Zero matches stops. More than one match prints the rows and does not connect. Pass the access id when two rows share a name.

The PAM proxy then asks for the VM username and password. Ctrl-C goes to that remote shell. Leave with `exit`. If the prompt never returns, stop the process from another terminal:

```bash
pkill -f "titan ssh"
```

`error: connect EHOSTUNREACH <ip>:22` means the PAM server cannot route to that VM. The same Connect button in the browser fails the same way.

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

## Logout

```bash
titan logout
```

This tells PAM to drop the session and deletes `~/.config/titan/session.json`. The TOTP secret stays. The next `titan login` still sends the code when that file is present.

## Files

| Path | Contents |
| --- | --- |
| `~/.config/titan/session.json` | PAM token. Removed by `titan logout`. |
| `~/.config/titan/totp` | TOTP secret. Removed by `titan totp delete`. |
| `~/.cache/titan/qrscan` | Mac QR scanner binary. No secret. |
