from urllib.parse import parse_qs, urlparse

from titan.shell import ssh_proxy_url


def test_ssh_proxy_url_carries_terminal_fields():
    url = ssh_proxy_url(
        "https://titan.efarda.ir",
        token="tok",
        access_id="acc-1",
        cols=80,
        rows=24,
        session_cookie="abc123",
    )
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert parsed.scheme == "wss"
    assert parsed.netloc == "titan.efarda.ir"
    assert parsed.path == "/ssh-proxy"
    assert query["cols"] == ["80"]
    assert query["rows"] == ["24"]
    assert query["token"] == ["tok"]
    assert query["sessionCookie"] == ["abc123"]
    assert query["destination"] == ["acc-1"]
    assert query["protocol"] == ["ssh"]
    assert "-" not in query["sessionCookie"][0]
