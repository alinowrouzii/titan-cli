import subprocess

from titan.accesses import Access
from titan.cli import main
from titan.complete import bash_script, candidates
from titan.pam import SessionExpired


def _boom():
    raise AssertionError("access list should stay unread")


def test_ssh_tab_offers_name_resource_and_full_ip():
    rows = [Access("828-651", "web", "vm-a", "192.168.105.226")]
    assert candidates(["titan", "ssh", ""], 2, lambda: rows) == [
        "web",
        "vm-a",
        "192.168.105.226",
    ]


def test_ssh_tab_skips_blank_ip():
    rows = [Access("id-1", "web", "vm-a", "")]
    assert candidates(["titan", "ssh", ""], 2, lambda: rows) == ["web", "vm-a"]


def test_ssh_tab_offers_a_repeated_word_once():
    rows = [
        Access("id-1", "web", "vm-a", "10.0.0.1"),
        Access("id-2", "web", "vm-a", "10.0.0.1"),
    ]
    assert candidates(["titan", "ssh", ""], 2, lambda: rows) == [
        "web",
        "vm-a",
        "10.0.0.1",
    ]


def test_ssh_prefix_is_case_insensitive():
    rows = [Access("id-1", "Finnotech-DB", "vm-a", "10.0.0.1")]
    assert candidates(["titan", "ssh", "fin"], 2, lambda: rows) == ["Finnotech-DB"]


def test_ssh_dash_offers_forward_flags_without_listing_servers():
    assert candidates(["titan", "ssh", "-"], 2, _boom) == ["-L", "-R"]


def test_ssh_flag_value_offers_nothing():
    assert candidates(["titan", "ssh", "-L", ""], 3, _boom) == []


def test_ssh_after_forward_still_offers_servers():
    rows = [Access("id-1", "web", "vm-a", "10.0.0.1")]
    assert candidates(["titan", "ssh", "-L", "27017:27017", ""], 4, lambda: rows) == [
        "web",
        "vm-a",
        "10.0.0.1",
    ]


def test_ssh_second_word_offers_nothing():
    assert candidates(["titan", "ssh", "web", ""], 3, _boom) == []


def test_titan_tab_lists_commands_without_listing_servers():
    assert candidates(["titan", ""], 1, _boom) == [
        "login",
        "logout",
        "ls",
        "ssh",
        "totp",
        "cred",
    ]


def test_command_prefix_filters():
    assert candidates(["titan", "ss"], 1, _boom) == ["ssh"]


def test_totp_and_cred_list_their_commands():
    assert candidates(["titan", "totp", ""], 2, _boom) == ["set", "delete"]
    assert candidates(["titan", "cred", "d"], 2, _boom) == ["default", "delete"]


def test_bash_hook_keeps_a_spaced_name_as_one_word(tmp_path):
    fake = tmp_path / "titan"
    fake.write_text(
        "#!/bin/bash\nprintf '%s\\n' 'my server'\n",
    )
    fake.chmod(0o755)
    words = " ".join("'%s'" % word for word in ["titan", "ssh", ""])
    program = (
        bash_script()
        + """
export PATH='%s':"$PATH"
COMP_WORDS=(%s)
COMP_CWORD=2
_titan_complete
printf '%%s\\n' "${#COMPREPLY[@]}"
printf '%%s\\n' "${COMPREPLY[@]}"
complete -p titan
"""
        % (tmp_path, words)
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", program],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "1"
    assert lines[1] == "my server"
    assert "nospace" not in lines[2]
    assert "_titan_complete" in lines[2]


def test_bash_hook_hides_titan_failure(tmp_path):
    fake = tmp_path / "titan"
    fake.write_text("#!/bin/bash\necho boom >&2\nexit 1\n")
    fake.chmod(0o755)
    program = (
        bash_script()
        + """
export PATH='%s':"$PATH"
COMP_WORDS=('titan' 'ssh' '')
COMP_CWORD=2
_titan_complete
printf '%%s\\n' "${#COMPREPLY[@]}"
"""
        % tmp_path
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", program],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0"
    assert "boom" not in result.stdout
    assert "boom" not in result.stderr


def test_bash_hook_passes_flag_words(tmp_path):
    seen = tmp_path / "args"
    fake = tmp_path / "titan"
    fake.write_text(
        "#!/bin/bash\nprintf '%%s\\n' \"$@\" > '%s'\n" % seen,
    )
    fake.chmod(0o755)
    program = (
        bash_script()
        + """
export PATH='%s':"$PATH"
COMP_WORDS=('titan' 'ssh' '-L' '')
COMP_CWORD=3
_titan_complete
"""
        % tmp_path
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", program],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert seen.read_text().splitlines() == [
        "completion",
        "candidates",
        "--",
        "3",
        "titan",
        "ssh",
        "-L",
        "",
    ]


def test_completion_bash_prints_the_hook(capsys):
    assert main(["completion", "bash"]) == 0
    assert capsys.readouterr().out == bash_script()


def test_completion_candidates_prints_matching_server(monkeypatch, capsys):
    rows = [Access("id-1", "Finnotech-DB", "vm-a", "10.0.0.1")]
    monkeypatch.setattr("titan.cli._load_accesses", lambda: rows)
    code = main(["completion", "candidates", "--", "2", "titan", "ssh", "fin"])
    assert code == 0
    assert capsys.readouterr().out.splitlines() == ["Finnotech-DB"]


def test_completion_candidates_quiet_when_list_fails(monkeypatch, capsys):
    def boom():
        raise SessionExpired("nope")

    monkeypatch.setattr("titan.cli._load_accesses", boom)
    assert main(["completion", "candidates", "--", "2", "titan", "ssh", ""]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_completion_command_tab_does_not_load_servers(monkeypatch, capsys):
    def boom():
        raise AssertionError("loaded")

    monkeypatch.setattr("titan.cli._load_accesses", boom)
    assert main(["completion", "candidates", "--", "1", "titan", "ss"]) == 0
    assert capsys.readouterr().out.splitlines() == ["ssh"]


def test_completion_candidates_keeps_forward_flag(monkeypatch, capsys):
    def boom():
        raise AssertionError("loaded")

    monkeypatch.setattr("titan.cli._load_accesses", boom)
    assert main(["completion", "candidates", "--", "3", "titan", "ssh", "-L", ""]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
