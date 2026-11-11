import http.client
import socket
import ssl
from unittest.mock import Mock

import pytest

from upstreamlens.diagnostic import diagnose
from upstreamlens.network import Address, Probe
from upstreamlens.target import parse_target


@pytest.fixture
def probe():
    fake = Mock(spec=Probe)
    fake.resolve.return_value = [Address(socket.AF_INET, ("192.0.2.10", 443))]
    fake.connect.return_value = (Mock(spec=socket.socket), "192.0.2.10")
    fake.tls.return_value = (Mock(spec=socket.socket), {"version": "TLSv1.3"})
    fake.http.return_value = 200
    return fake


def test_https_success_uses_secured_connection(probe):
    target = parse_target("https://site.example/health")
    report = diagnose(target, probe=probe, timeout=2)

    assert report.source == "live"
    assert report.target == "https://site.example"
    assert [check.name for check in report.checks] == ["URL", "DNS", "TCP", "TLS", "HTTP"]
    assert [check.status for check in report.checks] == ["PASS"] * 5
    secured = probe.tls.return_value[0]
    probe.http.assert_called_once_with(secured, target, 2)
    probe.connect.return_value[0].close.assert_called_once()
    secured.close.assert_called_once()


def test_dns_failure_skips_later_checks(probe):
    probe.resolve.side_effect = socket.gaierror(11001, "内部地址")
    report = diagnose(parse_target("https://site.example"), probe=probe)

    assert report.checks[1].evidence == {"detail": "解析失败", "error_code": 11001}
    assert [check.status for check in report.checks] == ["PASS", "FAIL", "UNKNOWN", "UNKNOWN", "UNKNOWN"]
    probe.connect.assert_not_called()
    probe.tls.assert_not_called()
    probe.http.assert_not_called()


def test_refused_connection_to_literal_skips_dns(probe):
    probe.connect.side_effect = ConnectionRefusedError(10061, "拒绝")
    target = parse_target("http://127.0.0.1:51234")
    report = diagnose(target, probe=probe)

    assert report.checks[1].status == "UNKNOWN"
    assert report.checks[2].status == "FAIL"
    assert report.checks[2].evidence["detail"] == "连接被拒绝"
    probe.resolve.assert_not_called()
    probe.connect.assert_called_once_with([Address(socket.AF_INET, ("127.0.0.1", 51234))], 5.0)
    probe.http.assert_not_called()


def test_http_timeout_closes_connection(probe):
    probe.http.side_effect = TimeoutError("内部地址")
    report = diagnose(parse_target("http://site.example"), probe=probe)

    assert report.checks[3].evidence == {"detail": "目标使用 HTTP，无需 TLS"}
    assert report.checks[-1].status == "FAIL"
    assert report.checks[-1].evidence == {"detail": "操作超时"}
    probe.connect.return_value[0].close.assert_called_once()
    probe.tls.assert_not_called()


def test_tls_certificate_failure_skips_http(probe):
    error = ssl.SSLCertVerificationError(1, "私有证书标识")
    error.verify_code = 62
    probe.tls.side_effect = error
    report = diagnose(parse_target("https://site.example"), probe=probe)

    assert report.checks[3].status == "FAIL"
    assert report.checks[3].evidence == {"detail": "证书校验失败", "error_code": 62}
    assert report.checks[4].status == "UNKNOWN"
    probe.http.assert_not_called()
    probe.connect.return_value[0].close.assert_called_once()


def test_live_502_preserves_uncertainty(probe):
    probe.http.return_value = 502
    report = diagnose(parse_target("https://site.example"), probe=probe)

    assert report.checks[-1].status == "FAIL"
    assert report.checks[-1].evidence == {"status_code": 502}
    assert "可能" in report.summary
    assert report.possible_causes
    assert "端口" in report.unconfirmed[0]
    assert "8080" not in str(report)
    assert "连接被拒绝" not in str(report)


def test_malformed_http_does_not_expose_raw_error(probe):
    probe.http.side_effect = http.client.BadStatusLine("secret-cookie")
    report = diagnose(parse_target("http://site.example/private-path?token=secret-query"), probe=probe)

    assert report.checks[-1].status == "FAIL"
    assert "secret" not in str(report)
    assert "private-path" not in str(report)
