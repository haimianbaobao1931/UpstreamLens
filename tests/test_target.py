import pytest

from upstreamlens.target import InvalidTarget, parse_target


@pytest.mark.parametrize(
    "value",
    [
        "site.example",
        "ftp://site.example",
        "http://site.example:",
        "http://site.example:0",
        "http://site.example:65536",
        "http://site.example:+80",
        "http://[::1]junk:80",
        "http://[fe80::1%25zone]",
        "http://user:password@site.example",
        "http://site.example/\r\nCookie: hidden",
        "http://site.example\\other.example",
    ],
)
def test_rejects_invalid_or_unsafe_targets(value):
    with pytest.raises(InvalidTarget):
        parse_target(value)


def test_parses_ipv6_and_explicit_port():
    target = parse_target("https://[0:0:0:0:0:0:0:1]:9443")
    assert target.host == "::1"
    assert target.port == 9443
    assert target.origin == "https://[::1]:9443"
    assert target.request_target == "/"


def test_international_host_path_and_query():
    target = parse_target("https://例子.example/测试?值=%2F#片段")
    assert target.host == "xn--fsqu00a.example"
    assert target.port == 443
    assert target.request_target == "/%E6%B5%8B%E8%AF%95?%E5%80%BC=%2F"
    assert target.origin == "https://xn--fsqu00a.example"
