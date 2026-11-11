import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Queue
from threading import Event, Thread
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from upstreamlens.cli import app
from upstreamlens.network import Address, SocketProbe
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
            requests.put((self.path, self.headers.get("Authorization"), self.headers.get("Cookie"), self.headers.get("User-Agent")))
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
    assert requests.get_nowait() == ("/secret-path?token=secret-query", None, None, "UpstreamLens/0.5.0")
    assert requests.empty()
    assert "secret" not in result.output
    report = json.loads(result.stdout)
    assert report["checks"][-1] == {
        "name": "HTTP",
        "status": "PASS",
        "evidence": {"status_code": 302, "detail": "未跟随重定向"},
    }


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
