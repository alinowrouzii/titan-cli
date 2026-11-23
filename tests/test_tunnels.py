import json

import pytest

from titan.tunnels import (
    delete_tunnel,
    format_list,
    format_show,
    get_tunnel,
    load_tunnels,
    save_tunnels,
    set_tunnel,
    to_cli_forwards,
    validate_alias,
)


def test_missing_file_is_empty(tmp_path):
    assert load_tunnels(tmp_path / "missing.json") == {}


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "tunnels.json"
    store = set_tunnel(
        {},
        "mongo",
        "112.113",
        [("L", "27017:mongo1.db.finnotech.ir:27017"), ("L", "27018:27018")],
    )
    save_tunnels(path, store)
    loaded = load_tunnels(path)
    assert loaded["mongo"]["target"] == "112.113"
    assert loaded["mongo"]["forwards"] == [
        ["L", "27017:mongo1.db.finnotech.ir:27017"],
        ["L", "27018:27018"],
    ]


def test_set_tunnel_overwrites_same_name():
    store = set_tunnel({}, "mongo", "112.113", [("L", "27017:27017")])
    store = set_tunnel(store, "mongo", "113.14", [("L", "27017:27017"), ("R", "9000:3000")])
    assert store["mongo"]["target"] == "113.14"
    assert store["mongo"]["forwards"] == [["L", "27017:27017"], ["R", "9000:3000"]]


def test_delete_tunnel_removes_one():
    store = set_tunnel({}, "mongo", "112.113", [("L", "27017:27017")])
    store = set_tunnel(store, "elastic", "105.226", [("L", "9200:9200")])
    store = delete_tunnel(store, "mongo")
    assert "mongo" not in store
    assert "elastic" in store


def test_delete_missing_raises():
    with pytest.raises(RuntimeError, match="no tunnel mongo"):
        delete_tunnel({}, "mongo")


def test_get_tunnel_missing_raises():
    with pytest.raises(RuntimeError, match="no tunnel mongo"):
        get_tunnel({}, "mongo")


def test_validate_alias():
    assert validate_alias("mongo") == "mongo"
    assert validate_alias("mongo-1") == "mongo-1"
    assert validate_alias("db_2") == "db_2"
    with pytest.raises(RuntimeError, match="bad tunnel name"):
        validate_alias("Mongo")
    with pytest.raises(RuntimeError, match="bad tunnel name"):
        validate_alias("mongo.db")
    with pytest.raises(RuntimeError, match="bad tunnel name"):
        validate_alias("")


def test_set_tunnel_rejects_bad_forward():
    with pytest.raises(RuntimeError, match="bad forward spec"):
        set_tunnel({}, "mongo", "112.113", [("L", "nope")])


def test_set_tunnel_rejects_empty_forwards():
    with pytest.raises(RuntimeError, match="at least one"):
        set_tunnel({}, "mongo", "112.113", [])


def test_set_tunnel_rejects_blank_target():
    with pytest.raises(RuntimeError, match="target"):
        set_tunnel({}, "mongo", "  ", [("L", "27017:27017")])


def test_to_cli_forwards():
    entry = {
        "target": "112.113",
        "forwards": [["L", "27017:host:27017"], ["R", "9000:3000"]],
    }
    assert to_cli_forwards(entry) == [
        ("-L", "27017:host:27017"),
        ("-R", "9000:3000"),
    ]


def test_format_list_and_show():
    store = set_tunnel({}, "mongo", "112.113", [("L", "27017:27017")])
    store = set_tunnel(store, "elastic", "105.226", [("L", "9200:9200")])
    text = format_list(store)
    assert "mongo" in text
    assert "112.113" in text
    assert "elastic" in text
    assert "27017:27017" in format_show("mongo", store["mongo"])


def test_bad_json_raises(tmp_path):
    path = tmp_path / "tunnels.json"
    path.write_text("{nope")
    with pytest.raises(RuntimeError, match="tunnel file is not readable"):
        load_tunnels(path)


def test_hand_edited_file_loads(tmp_path):
    path = tmp_path / "tunnels.json"
    path.write_text(
        json.dumps(
            {
                "sepah": {
                    "target": "112.113",
                    "forwards": [["L", "40013:81.12.47.113:40013"]],
                }
            }
        )
        + "\n"
    )
    store = load_tunnels(path)
    assert store["sepah"]["target"] == "112.113"
