"""titan login, titan ls, titan ssh, titan cred."""

from __future__ import annotations

import argparse
import getpass
import sys
import urllib.error
import uuid
from pathlib import Path
from typing import List, Optional, Sequence

from titan.accesses import Access, format_row, resolve
from titan.auth import AuthError, delete_paths, load_session, pick_efnet, save_session
from titan.config import INSTALL_HINT, base_url, credentials_path, session_path, totp_path
from titan.credentials import (
    apply_picks,
    credential_for,
    delete_default,
    delete_server,
    format_menu,
    load_credentials,
    parse_one_server,
    parse_picks,
    save_credentials,
    set_default,
)
from titan.pam import (
    VERIFY_OTP,
    PamError,
    SessionExpired,
    decode_access_list,
    decode_login,
    decode_providers,
    encode_list_ssh,
    encode_login,
    encode_logout,
    encode_providers,
    encode_verify_otp,
    post_thrift,
    require_authenticated,
)
from titan.migration import accounts_in_text, choose_account, secret_base32
from titan.qrscan import read_qr_payload
from titan.totp import load_totp, save_totp, totp_candidates
from titan.shell import run_shell, ssh_proxy_url, terminal_size

PAGE = 100


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="titan",
        epilog=INSTALL_HINT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("login")
    sub.add_parser("logout")
    sub.add_parser("ls")
    totp = sub.add_parser("totp")
    totp_sub = totp.add_subparsers(dest="totp_cmd", required=True)
    totp_set = totp_sub.add_parser(
        "set",
        epilog=INSTALL_HINT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    totp_set.add_argument(
        "--qr",
        help="Google Authenticator export QR image, or an otpauth text file",
    )
    totp_set.add_argument(
        "--account",
        help="issuer or account name when the export QR holds more than one",
    )
    totp_sub.add_parser("delete")
    cred = sub.add_parser("cred")
    cred_sub = cred.add_subparsers(dest="cred_cmd", required=True)
    cred_sub.add_parser(
        "set",
        help="Save VM username and password for chosen servers",
        description="Save VM username and password for chosen servers",
    )
    cred_sub.add_parser("default", help="Save one VM username and password for every server")
    cred_sub.add_parser("delete", help="Delete saved VM passwords")
    ssh = sub.add_parser("ssh")
    ssh.add_argument(
        "target",
        nargs="?",
        help="server number, access id, or name. omit to pick from the list",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.cmd == "login":
            return cmd_login()
        if args.cmd == "logout":
            return cmd_logout()
        if args.cmd == "ls":
            return cmd_ls()
        if args.cmd == "totp":
            if args.totp_cmd == "delete":
                return cmd_totp_delete()
            return cmd_totp_set(args.qr, args.account)
        if args.cmd == "cred":
            if args.cred_cmd == "default":
                return cmd_cred_default()
            if args.cred_cmd == "delete":
                return cmd_cred_delete()
            return cmd_cred_set()
        return cmd_ssh(args.target)
    except SessionExpired as exc:
        print(exc, file=sys.stderr)
        return 1
    except (AuthError, PamError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        return 1


def cmd_login() -> int:
    username = input("username: ")
    password = getpass.getpass("password: ")
    host = base_url()
    providers = decode_providers(
        post_thrift(host + "/api/auth/auth", encode_providers())
    )
    provider = pick_efnet(providers)
    payload = decode_login(
        post_thrift(
            host + "/api/auth/auth",
            encode_login(username, password, provider.id),
        )
    )
    if payload["state"] == VERIFY_OTP:
        payload = _verify_otp(host, payload["token"])
    require_authenticated(payload)
    path = session_path()
    save_session(path, payload)
    print("logged in. session %s" % path)
    answer = input("save VM passwords now? [y/N] ").strip().lower()
    if answer in ("y", "yes"):
        return cmd_cred_set()
    return 0


def cmd_logout() -> int:
    token = _saved_token()
    if token:
        try:
            post_thrift(
                base_url() + "/api/auth/auth",
                encode_logout(),
                token=token,
            )
        except (PamError, urllib.error.URLError, OSError):
            pass
    # Session only. VM passwords live in credentials.json and stay after logout.
    removed = delete_paths([session_path()])
    for path in removed:
        print("deleted %s" % path)
    kept = credentials_path()
    if kept.is_file():
        print("VM passwords kept %s" % kept)
    elif not removed:
        print("nothing saved")
    return 0


def _saved_token() -> str:
    try:
        return str(load_session(session_path()).get("token") or "")
    except (AuthError, OSError, ValueError):
        return ""


def cmd_totp_delete() -> int:
    removed = delete_paths([totp_path()])
    if not removed:
        print("no totp secret")
        return 0
    print("deleted %s" % removed[0])
    return 0


def cmd_totp_set(qr: Optional[str], account: Optional[str]) -> int:
    label = ""
    if qr:
        secret, label = _secret_from_qr(qr, account)
    else:
        if account:
            raise AuthError("--account needs --qr")
        secret = getpass.getpass("totp secret: ")
    path = totp_path()
    save_totp(path, secret)
    if label:
        print("totp secret saved for %s. %s" % (label, path))
    else:
        print("totp secret saved. %s" % path)
    return 0


def _verify_otp(host: str, token: str) -> dict:
    try:
        secret = load_totp(totp_path())
    except AuthError:
        secret = ""
    if not secret:
        code = input("google authenticator code: ").strip().replace(" ", "")
        if not code.isdigit() or len(code) < 4:
            raise AuthError("type the digits from Google Authenticator")
        return _submit_otp(host, token, code)
    last = PamError("OTP rejected")
    for code in totp_candidates(secret):
        try:
            payload = _submit_otp(host, token, code)
        except PamError as exc:
            last = exc
            continue
        if payload["state"] != VERIFY_OTP:
            return payload
        last = PamError("OTP did not finish login")
    raise last


def _submit_otp(host: str, token: str, code: str) -> dict:
    return decode_login(
        post_thrift(
            host + "/api/auth/users",
            encode_verify_otp(code, False),
            token=token,
        ),
        method="verifyOtpAuth",
    )


def _secret_from_qr(path: str, account: Optional[str]) -> tuple:
    text = read_qr_payload(Path(path))
    exported = accounts_in_text(text)
    if exported:
        chosen = choose_account(exported, account)
        return secret_base32(chosen), chosen.label()
    if account:
        raise AuthError("--account is for a Google Authenticator export QR")
    return text, ""


def cmd_ls() -> int:
    rows = _load_accesses()
    print("resource\taccess\tip\tid")
    for access in rows:
        print(format_row(access))
    return 0


def cmd_ssh(target: Optional[str]) -> int:
    rows = _load_accesses()
    if not target:
        store = load_credentials(credentials_path())
        print(format_menu(rows, store, include_default=False))
        print("type one server number")
        number = parse_one_server(input("server: "), len(rows))
        return _open_shell(rows[number - 1])
    if target.isdigit():
        number = int(target)
        if number < 1 or number > len(rows):
            print(
                "server %s is outside 1-%d" % (target, len(rows)),
                file=sys.stderr,
            )
            return 1
        return _open_shell(rows[number - 1])
    hits = resolve(rows, target)
    if not hits:
        print("no access matches %s" % target, file=sys.stderr)
        return 1
    if len(hits) > 1:
        print("more than one match:", file=sys.stderr)
        for access in hits:
            print(format_row(access), file=sys.stderr)
        return 1
    return _open_shell(hits[0])


def _open_shell(access: Access) -> int:
    token = _token()
    cols, rows_n = terminal_size()
    host = base_url()
    url = ssh_proxy_url(
        host,
        token,
        access.id,
        cols,
        rows_n,
        uuid.uuid4().hex,
    )
    run_shell(url, host, credential_for(load_credentials(credentials_path()), access.id))
    return 0


def cmd_cred_set() -> int:
    rows = _load_accesses()
    path = credentials_path()
    store = load_credentials(path)
    print(format_menu(rows, store))
    print("type numbers, for example 1,3 or 0")
    picks = parse_picks(input("servers: "), len(rows))
    values = {}
    for pick in picks:
        if pick == 0:
            values[0] = (
                input("default username: "),
                getpass.getpass("default password: "),
            )
        else:
            access = rows[pick - 1]
            values[pick] = (
                input("username for %s: " % access.resource_name),
                getpass.getpass("password for %s: " % access.resource_name),
            )
    save_credentials(path, apply_picks(store, rows, picks, values))
    print("saved %s" % path)
    return 0


def cmd_cred_default() -> int:
    path = credentials_path()
    store = set_default(
        load_credentials(path),
        input("default username: "),
        getpass.getpass("default password: "),
    )
    save_credentials(path, store)
    print("saved %s" % path)
    return 0


def cmd_cred_delete() -> int:
    rows = _load_accesses()
    path = credentials_path()
    store = load_credentials(path)
    print(format_menu(rows, store))
    print("type numbers to delete, for example 1,3 or 0")
    picks = parse_picks(input("servers: "), len(rows))
    for pick in picks:
        if pick == 0:
            store = delete_default(store)
        else:
            store = delete_server(store, rows[pick - 1].id)
    save_credentials(path, store)
    print("saved %s" % path)
    return 0


def _token() -> str:
    try:
        session = load_session(session_path())
    except FileNotFoundError:
        raise AuthError("no session. run titan login")
    return str(session["token"])


def _load_accesses() -> List[Access]:
    token = _token()
    host = base_url() + "/api/identity/accesses"
    skip = 0
    found: List[Access] = []
    total = None
    while total is None or len(found) < total:
        page_total, hits = decode_access_list(
            post_thrift(host, encode_list_ssh(skip, PAGE), token=token)
        )
        total = page_total
        if not hits:
            break
        found.extend(hits)
        skip += len(hits)
    return found


if __name__ == "__main__":
    sys.exit(main())
