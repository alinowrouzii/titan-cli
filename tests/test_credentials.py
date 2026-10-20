import os
import stat

import pytest

from titan.accesses import Access
from titan.auth import AuthError
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
    set_server,
)


def _server(access_id: str, name: str = "box") -> Access:
    return Access(access_id, "Finnotech SRV", name, "192.168.0.1")


def test_credentials_file_mode_is_0600(tmp_path):
    path = tmp_path / "titan" / "credentials.json"
    save_credentials(path, set_server(load_credentials(path), "828-651", "mongo", "secret"))
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    store = load_credentials(path)
    assert credential_for(store, "828-651") == {"username": "mongo", "password": "secret"}


def test_missing_credentials_file_is_empty(tmp_path):
    store = load_credentials(tmp_path / "missing.json")
    assert credential_for(store, "828-651") is None


def test_server_password_wins_over_default(tmp_path):
    path = tmp_path / "credentials.json"
    store = set_default(load_credentials(path), "root", "default-pass")
    store = set_server(store, "828-651", "mongo", "mongo-pass")
    save_credentials(path, store)
    store = load_credentials(path)
    assert credential_for(store, "828-651")["password"] == "mongo-pass"
    assert credential_for(store, "828-1")["password"] == "default-pass"


def test_delete_server_keeps_default_and_other_servers(tmp_path):
    path = tmp_path / "credentials.json"
    store = set_default(load_credentials(path), "root", "default-pass")
    store = set_server(store, "828-651", "mongo", "mongo-pass")
    store = set_server(store, "828-645", "app", "app-pass")
    store = delete_server(store, "828-651")
    save_credentials(path, store)
    store = load_credentials(path)
    assert credential_for(store, "828-651")["password"] == "default-pass"
    assert credential_for(store, "828-645")["password"] == "app-pass"


def test_delete_default_keeps_server_password(tmp_path):
    store = set_default(load_credentials(tmp_path / "x"), "root", "default-pass")
    store = set_server(store, "828-651", "mongo", "mongo-pass")
    store = delete_default(store)
    assert credential_for(store, "828-651")["password"] == "mongo-pass"
    assert credential_for(store, "828-1") is None


def test_empty_username_or_password_rejected():
    with pytest.raises(AuthError):
        set_server(load_credentials(__import__("pathlib").Path("/nope")), "828-651", "  ", "secret")
    with pytest.raises(AuthError):
        set_default(load_credentials(__import__("pathlib").Path("/nope")), "root", "")


def test_menu_marks_saved_servers_and_default():
    rows = [_server("828-651", "Finnotech-DB-Mongo-4"), _server("828-645", "Finnotech-App-0")]
    store = set_server(load_credentials(__import__("pathlib").Path("/nope")), "828-651", "mongo", "s")
    store = set_default(store, "root", "d")
    text = format_menu(rows, store)
    assert "*  1  Finnotech-DB-Mongo-4  192.168.0.1  828-651" in text
    assert "   2  Finnotech-App-0  192.168.0.1  828-645" in text
    assert "*  0  default for every server with no own password" in text


def test_ssh_menu_lists_servers_without_default_row():
    rows = [_server("828-651", "Finnotech-DB-Mongo-4"), _server("828-645", "Finnotech-App-0")]
    store = set_server(load_credentials(__import__("pathlib").Path("/nope")), "828-651", "mongo", "s")
    text = format_menu(rows, store, include_default=False)
    assert "*  1  Finnotech-DB-Mongo-4  192.168.0.1  828-651" in text
    assert "   2  Finnotech-App-0  192.168.0.1  828-645" in text
    assert "default for every server" not in text


def test_parse_one_server():
    assert parse_one_server("2", 4) == 2
    with pytest.raises(AuthError):
        parse_one_server("0", 4)
    with pytest.raises(AuthError):
        parse_one_server("1,2", 4)


def test_parse_picks_accepts_servers_and_default():
    assert parse_picks("1,3 0", 4) == [1, 3, 0]


def test_parse_picks_rejects_unknown_number():
    with pytest.raises(AuthError):
        parse_picks("9", 2)


def test_apply_picks_sets_server_and_default():
    rows = [_server("828-651", "mongo"), _server("828-645", "app")]
    store = apply_picks(
        load_credentials(__import__("pathlib").Path("/nope")),
        rows,
        [1, 0],
        {1: ("mongo", "mongo-pass"), 0: ("root", "default-pass")},
    )
    assert credential_for(store, "828-651")["username"] == "mongo"
    assert credential_for(store, "828-645")["password"] == "default-pass"
