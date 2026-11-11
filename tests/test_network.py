import json
import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Queue
from threading import Event, Thread
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from upstreamlens.cli import app
from upstreamlens.network import Address, SocketProbe, certificate_days_remaining
from upstreamlens.target import parse_target


def test_dns_deadline_does_not_wait_for_system_resolver(monkeypatch):
    release = Event()

    def delayed_resolver(*args, **kwargs):
        release.wait(2)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", delayed_resolver)
    start = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            SocketProbe().resolve(parse_target("https://site.example"), 0.02)
        assert time.monotonic() - start < 1
    finally:
        release.set()


def test_tcp_fallback_uses_only_supplied_addresses(monkeypatch):
    first = Mock()
    first.connect.side_effect = ConnectionRefusedError
    second = Mock()
    factory = Mock(side_effect=[first, second])
    monkeypatch.setattr(socket, "socket", factory)
    addresses = [
        Address(socket.AF_INET6, ("2001:db8::1", 9443, 0, 0)),
        Address(socket.AF_INET, ("192.0.2.10", 9443)),
    ]

    connection, peer = SocketProbe().connect(addresses, 1)

    assert connection is second
    assert peer == "192.0.2.10"
    first.connect.assert_called_once_with(addresses[0].endpoint)
    first.close.assert_called_once()
    second.connect.assert_called_once_with(addresses[1].endpoint)


def test_loopback_redirect_reports_status_without_following_or_leaking(monkeypatch):
    requests = Queue()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.put((self.path, self.headers.get("Authorization"), self.headers.get("Cookie")))
            self.send_response(302)
            self.send_header("Location", "https://outside.example/secret-location")
            self.send_header("Set-Cookie", "secret-response-cookie")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    def unexpected_dns(*args, **kwargs):
        raise AssertionError("回环 IP 和重定向不得触发解析")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_dns)
    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/secret-path?token=secret-query"
            result = CliRunner().invoke(app, ["diagnose", url, "--format", "json", "--timeout", "1"])
        finally:
            server.shutdown()
            thread.join()

    assert result.exit_code == 0
    assert requests.get_nowait() == ("/secret-path?token=secret-query", None, None)
    assert requests.empty()
    assert "secret" not in result.output
    report = json.loads(result.stdout)
    http_check = report["checks"][-1]
    assert http_check["name"] == "HTTP"
    assert http_check["status"] == "PASS"
    assert http_check["evidence"]["status_code"] == 302
    assert http_check["evidence"]["detail"] == "未跟随重定向"
    assert isinstance(http_check["evidence"]["duration_ms"], int)
    assert http_check["evidence"]["duration_ms"] >= 0


def test_loopback_unlistened_port_is_a_diagnostic_failure():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{reserved.getsockname()[1]}"
        result = CliRunner().invoke(app, ["diagnose", url, "--format", "json", "--timeout", "3"])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["checks"][2]["status"] == "FAIL"
    assert report["checks"][2]["evidence"]["detail"] == "连接被拒绝"
    assert report["checks"][-1]["status"] == "UNKNOWN"


RELEASE = 1767225600  # 2026-01-01T00:00:00Z


@pytest.mark.parametrize(
    ("not_after", "now", "expected"),
    [
        ("Jan  1 00:00:00 2026 GMT", RELEASE, 0),
        ("Jan 15 00:00:00 2026 GMT", RELEASE, 14),
        ("Jan 15 00:00:00 2026 GMT", RELEASE - 86399, 14),
        ("Jan 15 00:00:00 2026 GMT", RELEASE + 86400, 13),
        ("Dec 31 00:00:00 2025 GMT", RELEASE, -1),
    ],
)
def test_certificate_days_remaining_rounds_down(not_after, now, expected):
    assert certificate_days_remaining(not_after, now=now) == expected


@pytest.mark.parametrize("not_after", ["", "not a date", "Jan 15 2026 GMT"])
def test_certificate_days_remaining_returns_none_for_unparsable_value(not_after):
    assert certificate_days_remaining(not_after, now=RELEASE) is None


def test_tls_probe_records_certificate_expiry(monkeypatch):
    certificate = {
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan 15 00:00:00 2026 GMT",
    }
    secured = Mock()
    secured.version.return_value = "TLSv1.3"
    secured.getpeercert.return_value = certificate
    context = Mock()
    context.wrap_socket.return_value = secured
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(time, "time", lambda: RELEASE)

    connection = Mock()
    _, evidence = SocketProbe().tls(connection, parse_target("https://site.example"), 1)

    assert evidence["valid_until"] == "Jan 15 00:00:00 2026 GMT"
    assert evidence["expires_in_days"] == 14
    secured.do_handshake.assert_called_once_with()
