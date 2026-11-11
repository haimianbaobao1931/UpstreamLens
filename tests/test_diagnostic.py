import http.client
import socket
import ssl
from unittest.mock import Mock

import pytest

from upstreamlens.diagnostic import diagnose
from upstreamlens.network import Address, Probe
from upstreamlens.target import parse_target


class FakeClock:
    """每次读取推进固定步长，让阶段耗时在测试中可预期。"""

    def __init__(self, step: float = 0.1) -> None:
        self.value = 0.0
        self.step = step

    def __call__(self) -> float:
        current = self.value
        self.value += self.step
        return current


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
    report = diagnose(target, probe=probe, timeout=2, clock=FakeClock())

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
    report = diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock())

    assert report.checks[1].evidence == {"detail": "解析失败", "error_code": 11001, "duration_ms": 100}
    assert [check.status for check in report.checks] == ["PASS", "FAIL", "UNKNOWN", "UNKNOWN", "UNKNOWN"]
    probe.connect.assert_not_called()
    probe.tls.assert_not_called()
    probe.http.assert_not_called()


def test_refused_connection_to_literal_skips_dns(probe):
    probe.connect.side_effect = ConnectionRefusedError(10061, "拒绝")
    target = parse_target("http://127.0.0.1:51234")
    report = diagnose(target, probe=probe, clock=FakeClock())

    assert report.checks[1].status == "UNKNOWN"
    assert report.checks[2].status == "FAIL"
    assert report.checks[2].evidence["detail"] == "连接被拒绝"
    probe.resolve.assert_not_called()
    probe.connect.assert_called_once_with([Address(socket.AF_INET, ("127.0.0.1", 51234))], 5.0)
    probe.http.assert_not_called()


def test_http_timeout_closes_connection(probe):
    probe.http.side_effect = TimeoutError("内部地址")
    report = diagnose(parse_target("http://site.example"), probe=probe, clock=FakeClock())

    assert report.checks[3].evidence == {"detail": "目标使用 HTTP，无需 TLS"}
    assert report.checks[-1].status == "FAIL"
    assert report.checks[-1].evidence == {"detail": "操作超时", "duration_ms": 100}
    probe.connect.return_value[0].close.assert_called_once()
    probe.tls.assert_not_called()


def test_tls_certificate_failure_skips_http(probe):
    error = ssl.SSLCertVerificationError(1, "私有证书标识")
    error.verify_code = 62
    probe.tls.side_effect = error
    report = diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock())

    assert report.checks[3].status == "FAIL"
    assert report.checks[3].evidence == {"detail": "证书校验失败", "error_code": 62, "duration_ms": 100}
    assert report.checks[4].status == "UNKNOWN"
    probe.http.assert_not_called()
    probe.connect.return_value[0].close.assert_called_once()


def test_live_502_preserves_uncertainty(probe):
    probe.http.return_value = 502
    report = diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock())

    assert report.checks[-1].status == "FAIL"
    assert report.checks[-1].evidence == {"status_code": 502, "duration_ms": 100}
    assert "可能" in report.summary
    assert report.possible_causes
    assert "端口" in report.unconfirmed[0]
    assert "8080" not in str(report)
    assert "连接被拒绝" not in str(report)


def test_malformed_http_does_not_expose_raw_error(probe):
    probe.http.side_effect = http.client.BadStatusLine("secret-cookie")
    report = diagnose(parse_target("http://site.example/private-path?token=secret-query"), probe=probe, clock=FakeClock())

    assert report.checks[-1].status == "FAIL"
    assert "secret" not in str(report)
    assert "private-path" not in str(report)


def test_each_completed_phase_reports_its_duration(probe):
    report = diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock())

    durations = {check.name: check.evidence.get("duration_ms") for check in report.checks}
    assert durations == {"URL": None, "DNS": 100, "TCP": 100, "TLS": 100, "HTTP": 100}


def test_failed_phase_reports_its_duration_and_skipped_checks_do_not(probe):
    probe.resolve.side_effect = socket.gaierror(11001, "内部地址")
    report = diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock(0.25))

    assert report.checks[1].evidence["duration_ms"] == 250
    for check in report.checks[2:]:
        assert check.status == "UNKNOWN"
        assert "duration_ms" not in check.evidence


def test_durations_are_unaffected_by_literal_targets(probe):
    probe.connect.side_effect = ConnectionRefusedError(10061, "拒绝")
    report = diagnose(parse_target("http://127.0.0.1:51234"), probe=probe, clock=FakeClock())

    assert "duration_ms" not in report.checks[1].evidence
    assert report.checks[2].evidence["duration_ms"] == 100


def expiring_probe(probe, days):
    evidence = {"version": "TLSv1.3", "certificate": "证书链、有效期和主机名校验通过",
                "expires_in_days": days}
    probe.tls.return_value = (Mock(spec=socket.socket), evidence)
    return diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock())


@pytest.mark.parametrize("days", [0, 3, 14])
def test_certificate_expiring_soon_is_listed_as_a_possible_cause(probe, days):
    report = expiring_probe(probe, days)

    assert any(f"{days} 天" in cause for cause in report.possible_causes)
    assert any("续期" in suggestion for suggestion in report.suggestions)


@pytest.mark.parametrize("days", [15, 400])
def test_certificate_with_distant_expiry_adds_no_cause(probe, days):
    report = expiring_probe(probe, days)

    assert not any("证书剩余有效天数" in cause for cause in report.possible_causes)


def test_certificate_without_expiry_evidence_adds_no_cause(probe):
    report = diagnose(parse_target("https://site.example"), probe=probe, clock=FakeClock())

    assert not any("证书剩余有效天数" in cause for cause in report.possible_causes)
