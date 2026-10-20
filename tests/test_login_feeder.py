from titan.shell import LoginFeeder


def test_feeder_sends_user_then_password():
    feeder = LoginFeeder("mongo", "secret")
    assert feeder.feed("\r\nlogin: ") == ["mongo\r"]
    assert feeder.feed("mongo\r\nPassword: ") == ["secret\r"]
    assert feeder.feed("$ ") == []


def test_feeder_handles_both_prompts_in_one_chunk():
    feeder = LoginFeeder("root", "pw")
    assert feeder.feed("login as: \r\nPassword: ") == ["root\r", "pw\r"]


def test_feeder_ignores_last_login_banner():
    feeder = LoginFeeder("root", "pw")
    assert feeder.feed("Last login: Mon Oct 20\r\n") == []


def test_feeder_cancel_sends_nothing():
    feeder = LoginFeeder("root", "pw")
    feeder.cancel()
    assert feeder.feed("login: \r\nPassword: ") == []


def test_feeder_types_pam_question_prompts():
    feeder = LoginFeeder("nowrouzi", "secret")
    banner = "Please enter login details for 192.168.112.114 :\r\n? Enter your username: "
    assert feeder.feed(banner) == ["nowrouzi\r"]
    assert feeder.feed("nowrouzi\r\n? Enter your password: ") == ["secret\r"]


def test_feeder_strips_ansi_before_match():
    feeder = LoginFeeder("root", "pw")
    assert feeder.feed("\x1b[32musername:\x1b[0m ") == ["root\r"]
