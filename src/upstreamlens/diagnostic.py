import http.client
import ssl
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from typing import Callable

from .models import Check, Evidence, Report
from .network import Probe, SocketProbe, literal_address
from .rules import analyze
from .target import Target


def _milliseconds(started: float, clock: Callable[[], float]) -> int:
    """返回从 started 到现在的毫秒数，供报告显示各阶段耗时。"""
    return max(0, int(round((clock() - started) * 1000)))


def _failure(name: str, error: Exception, duration_ms: int) -> Check:
    if isinstance(error, TimeoutError):
        message = "操作超时"
    elif isinstance(error, ConnectionRefusedError):
        message = "连接被拒绝"
    elif isinstance(error, ssl.SSLCertVerificationError):
        message = "证书校验失败"
    elif isinstance(error, ssl.SSLError):
        message = "TLS 握手失败"
    else:
        message = {
            "DNS": "解析失败",
            "TCP": "连接失败",
            "TLS": "握手失败",
            "HTTP": "请求或响应读取失败",
        }[name]

    # 原始异常可能携带请求地址或响应内容，报告仅保留安全字段。
    evidence: Evidence = {"detail": message, "duration_ms": duration_ms}
    code = getattr(error, "verify_code", None) if isinstance(
        error, ssl.SSLCertVerificationError
    ) else getattr(error, "errno", None)
    if isinstance(code, int):
        evidence["error_code"] = code
    return Check(name, "FAIL", evidence)


def _probe(
    target: Target, probe: Probe, timeout: float, checks: list[Check],
    clock: Callable[[], float],
) -> None:
    ip = literal_address(target)
    if ip is not None:
        addresses = [ip]
        checks.append(Check("DNS", "UNKNOWN", {"detail": "目标为 IP 地址，无需 DNS 解析"}))
    else:
        started = clock()
        try:
            addresses = probe.resolve(target, timeout)
        except OSError as error:
            checks.append(_failure("DNS", error, _milliseconds(started, clock)))
            return
        checks.append(Check("DNS", "PASS", {
            "addresses": [address.ip for address in addresses],
            "duration_ms": _milliseconds(started, clock),
        }))

    with ExitStack() as resources:
        started = clock()
        try:
            connection, peer = probe.connect(addresses, timeout)
        except OSError as error:
            checks.append(_failure("TCP", error, _milliseconds(started, clock)))
            return
        resources.callback(connection.close)
        checks.append(Check("TCP", "PASS", {
            "address": peer,
            "port": target.port,
            "duration_ms": _milliseconds(started, clock),
        }))

        if target.scheme == "https":
            started = clock()
            try:
                secured, evidence = probe.tls(connection, target, timeout)
            except OSError as error:
                checks.append(_failure("TLS", error, _milliseconds(started, clock)))
                return
            if secured is not connection:
                resources.callback(secured.close)
            connection = secured
            checks.append(Check("TLS", "PASS", {
                **evidence, "duration_ms": _milliseconds(started, clock),
            }))

        started = clock()
        try:
            status = probe.http(connection, target, timeout)
        except (OSError, http.client.HTTPException) as error:
            checks.append(_failure("HTTP", error, _milliseconds(started, clock)))
            return
        evidence = {"status_code": status, "duration_ms": _milliseconds(started, clock)}
        if 200 <= status < 400:
            if status >= 300:
                evidence["detail"] = "未跟随重定向"
            checks.append(Check("HTTP", "PASS", evidence))
        elif 400 <= status < 600:
            checks.append(Check("HTTP", "FAIL", evidence))
        else:
            checks.append(Check("HTTP", "UNKNOWN", evidence))


def diagnose(
    target: Target, *, probe: Probe | None = None, timeout: float = 5.0,
    clock: Callable[[], float] = time.monotonic,
) -> Report:
    checks = [Check("URL", "PASS", {"host": target.host, "port": target.port})]
    report = Report(
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
        target.origin, "live", checks, "", [], [], [],
    )
    _probe(target, SocketProbe() if probe is None else probe, timeout, checks, clock)
    names = {check.name for check in checks}
    for name in ("TCP", "TLS", "HTTP"):
        if name not in names:
            detail = "前置检测失败，未执行"
            if name == "TLS" and target.scheme == "http":
                detail = "目标使用 HTTP，无需 TLS"
            checks.append(Check(name, "UNKNOWN", {"detail": detail}))
    checks.sort(key=lambda check: ("URL", "DNS", "TCP", "TLS", "HTTP").index(check.name))
    analyze(report)
    return report
