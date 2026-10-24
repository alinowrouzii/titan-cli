from titan.accesses import Access
from titan.cli import main


def _rows():
    return [
        Access("id-1", "web", "vm-a", "10.0.0.1"),
        Access("id-2", "db", "vm-b", "10.0.0.2"),
        Access("7", "seven", "vm-c", "10.0.0.3"),
    ]


def test_ssh_number_opens_that_menu_row(monkeypatch):
    rows = _rows()
    opened = []
    monkeypatch.setattr("titan.cli._load_accesses", lambda: rows)
    monkeypatch.setattr("titan.cli._open_shell", lambda access: opened.append(access) or 0)
    assert main(["ssh", "2"]) == 0
    assert opened == [rows[1]]


def test_ssh_number_wins_over_access_id(monkeypatch):
    rows = _rows()
    opened = []
    monkeypatch.setattr("titan.cli._load_accesses", lambda: rows)
    monkeypatch.setattr("titan.cli._open_shell", lambda access: opened.append(access) or 0)
    assert main(["ssh", "7"]) == 1
    assert opened == []
    assert main(["ssh", "3"]) == 0
    assert opened == [rows[2]]


def test_ssh_number_out_of_range(monkeypatch, capsys):
    monkeypatch.setattr("titan.cli._load_accesses", _rows)
    monkeypatch.setattr("titan.cli._open_shell", lambda access: 0)
    assert main(["ssh", "9"]) == 1
    err = capsys.readouterr().err
    assert "9" in err
    assert "3" in err


def test_ssh_menu_cancel_is_quiet(monkeypatch):
    monkeypatch.setattr("titan.cli._load_accesses", _rows)
    monkeypatch.setattr("titan.cli.load_credentials", lambda _path: {"default": None, "by_id": {}})

    def eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert main(["ssh"]) == 130

    def interrupt(_prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt)
    assert main(["ssh"]) == 130


def test_ssh_name_still_resolves(monkeypatch):
    rows = _rows()
    opened = []
    monkeypatch.setattr("titan.cli._load_accesses", lambda: rows)
    monkeypatch.setattr("titan.cli._open_shell", lambda access: opened.append(access) or 0)
    assert main(["ssh", "vm-b"]) == 0
    assert opened == [rows[1]]


def test_ssh_ip_opens_that_server(monkeypatch):
    rows = [
        Access("id-1", "web", "vm-a", "192.168.105.226"),
        Access("id-2", "db", "vm-b", "10.1.105.10"),
    ]
    opened = []
    monkeypatch.setattr("titan.cli._load_accesses", lambda: rows)
    monkeypatch.setattr("titan.cli._open_shell", lambda access: opened.append(access) or 0)
    assert main(["ssh", "192.168.105.226"]) == 0
    assert opened == [rows[0]]
    assert main(["ssh", "105.226"]) == 0
    assert opened == [rows[0], rows[0]]
