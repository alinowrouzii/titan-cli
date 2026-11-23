from titan.cli import main
from titan.complete import candidates
from titan.tunnels import load_tunnels, save_tunnels, set_tunnel


def test_tunnel_save_writes_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / "tunnels.json"
    monkeypatch.setattr("titan.cli.tunnels_path", lambda: path)
    assert (
        main(
            [
                "tunnel",
                "save",
                "mongo",
                "112.113",
                "-L",
                "27017:mongo1.db.finnotech.ir:27017",
                "-L",
                "27018:27018",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert str(path) in out
    store = load_tunnels(path)
    assert store["mongo"]["target"] == "112.113"
    assert store["mongo"]["forwards"] == [
        ["L", "27017:mongo1.db.finnotech.ir:27017"],
        ["L", "27018:27018"],
    ]


def test_tunnel_save_bad_forward(tmp_path, monkeypatch, capsys):
    path = tmp_path / "tunnels.json"
    monkeypatch.setattr("titan.cli.tunnels_path", lambda: path)
    assert main(["tunnel", "save", "mongo", "112.113", "-L", "nope"]) == 1
    assert "bad forward spec" in capsys.readouterr().err


def test_tunnel_ls_and_show(tmp_path, monkeypatch, capsys):
    path = tmp_path / "tunnels.json"
    save_tunnels(
        path,
        set_tunnel({}, "mongo", "112.113", [("L", "27017:27017")]),
    )
    monkeypatch.setattr("titan.cli.tunnels_path", lambda: path)
    assert main(["tunnel", "ls"]) == 0
    assert "mongo" in capsys.readouterr().out
    assert main(["tunnel", "show", "mongo"]) == 0
    shown = capsys.readouterr().out
    assert "112.113" in shown
    assert "27017:27017" in shown


def test_tunnel_rm(tmp_path, monkeypatch, capsys):
    path = tmp_path / "tunnels.json"
    save_tunnels(
        path,
        set_tunnel({}, "mongo", "112.113", [("L", "27017:27017")]),
    )
    monkeypatch.setattr("titan.cli.tunnels_path", lambda: path)
    assert main(["tunnel", "rm", "mongo"]) == 0
    assert load_tunnels(path) == {}
    assert main(["tunnel", "rm", "mongo"]) == 1
    assert "no tunnel mongo" in capsys.readouterr().err


def test_tunnel_run_calls_ssh(tmp_path, monkeypatch):
    path = tmp_path / "tunnels.json"
    save_tunnels(
        path,
        set_tunnel(
            {},
            "mongo",
            "112.113",
            [("L", "27017:mongo1.db.finnotech.ir:27017"), ("R", "9000:3000")],
        ),
    )
    monkeypatch.setattr("titan.cli.tunnels_path", lambda: path)
    seen = []

    def fake_ssh(target, forwards):
        seen.append((target, list(forwards)))
        return 0

    monkeypatch.setattr("titan.cli.cmd_ssh", fake_ssh)
    assert main(["tunnel", "run", "mongo"]) == 0
    assert seen == [
        (
            "112.113",
            [
                ("-L", "27017:mongo1.db.finnotech.ir:27017"),
                ("-R", "9000:3000"),
            ],
        )
    ]


def test_tunnel_run_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("titan.cli.tunnels_path", lambda: tmp_path / "missing.json")
    assert main(["tunnel", "run", "mongo"]) == 1
    assert "no tunnel mongo" in capsys.readouterr().err


def test_tunnel_completion_lists_subcommands():
    assert candidates(["titan", "tunnel", ""], 2, lambda: []) == [
        "run",
        "save",
        "ls",
        "show",
        "rm",
    ]


def test_tunnel_completion_offers_alias_names(tmp_path, monkeypatch):
    path = tmp_path / "tunnels.json"
    save_tunnels(
        path,
        set_tunnel({}, "mongo", "112.113", [("L", "27017:27017")]),
    )
    monkeypatch.setattr("titan.complete.tunnels_path", lambda: path)
    assert candidates(["titan", "tunnel", "run", ""], 3, lambda: []) == ["mongo"]
    assert candidates(["titan", "tunnel", "show", "mo"], 3, lambda: []) == ["mongo"]
    assert candidates(["titan", "tunnel", "rm", ""], 3, lambda: []) == ["mongo"]


def test_titan_tab_includes_tunnel():
    assert "tunnel" in candidates(["titan", ""], 1, lambda: [])
