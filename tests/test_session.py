import os
import stat

import pytest

from titan.auth import (
    AuthError,
    LdapProvider,
    delete_paths,
    load_session,
    pick_efnet,
    save_session,
)
from titan.cli import main
from titan.pam import encode_logout


def test_session_file_mode_is_0600(tmp_path):
    path = tmp_path / "titan" / "session.json"
    save_session(path, {"token": "abc", "state": 1, "sessionId": "sid"})
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    assert load_session(path)["token"] == "abc"


def test_missing_session_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_session(tmp_path / "missing.json")


def test_pick_efnet_by_exact_name():
    providers = [
        LdapProvider("local", "local"),
        LdapProvider("fed-1", "ef.net"),
    ]
    assert pick_efnet(providers).id == "fed-1"


def test_delete_paths_removes_session_and_totp(tmp_path):
    session = tmp_path / "titan" / "session.json"
    secret = tmp_path / "titan" / "totp"
    save_session(session, {"token": "abc", "state": 1, "sessionId": "sid"})
    secret.write_text("SECRET\n")
    removed = delete_paths([session, secret])
    assert not session.exists()
    assert not secret.exists()
    assert not session.parent.exists()
    assert len(removed) == 2


def test_delete_session_leaves_totp(tmp_path):
    session = tmp_path / "titan" / "session.json"
    secret = tmp_path / "titan" / "totp"
    save_session(session, {"token": "abc", "state": 1, "sessionId": "sid"})
    secret.write_text("SECRET\n")
    delete_paths([session])
    assert not session.exists()
    assert secret.exists()
    assert secret.parent.exists()


def test_logout_leaves_vm_credentials(tmp_path, monkeypatch):
    from titan.credentials import load_credentials, save_credentials, set_server

    session = tmp_path / "session.json"
    creds = tmp_path / "credentials.json"
    save_session(session, {"token": "abc", "state": 1, "sessionId": "sid"})
    save_credentials(creds, set_server(load_credentials(creds), "828-651", "mongo", "secret"))
    monkeypatch.setattr("titan.cli.session_path", lambda: session)
    monkeypatch.setattr("titan.cli.credentials_path", lambda: creds)
    monkeypatch.setattr("titan.cli._saved_token", lambda: "")
    assert main(["logout"]) == 0
    assert not session.exists()
    assert load_credentials(creds)["by_id"]["828-651"]["password"] == "secret"


def test_cred_set_is_its_own_command(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["cred", "set", "--help"])
    assert caught.value.code == 0
    text = capsys.readouterr().out
    assert "save" in text.lower() or "password" in text.lower()


def test_help_shows_install_hint(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    text = capsys.readouterr().out
    assert "zbar-tools" in text
    assert "Xcode command line tools" in text
    assert "Python 3.9 or newer." in text


def test_logout_call_name():
    assert b"logout" in encode_logout()


def test_pick_efnet_lists_other_names():
    providers = [LdapProvider("a", "corp"), LdapProvider("b", "lab")]
    with pytest.raises(AuthError) as caught:
        pick_efnet(providers)
    assert "corp" in str(caught.value)
    assert "lab" in str(caught.value)
