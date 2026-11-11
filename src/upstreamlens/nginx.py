"""对用户指定的 Nginx 文本日志进行有界、离线分析。"""

import ipaddress
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .models import NginxEvidence, NginxReport
from .rules import analyze_nginx
from .target import InvalidTarget, parse_target

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_LINES = 100_000
MAX_SAMPLES_PER_GROUP = 3

_HEADER = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(debug|info|notice|warn|error|crit|alert|emerg)\] "
    r"\d+#\d+: (?:\*\d+ )?(.*)$"
)
_FIELDS_START = re.compile(r", (?:client|server|request|upstream|host|referrer): ")
_FIELD = re.compile(r', (client|server|request|upstream|host|referrer): (?:("(?:[^"\\]|\\.)*")|([^,]*))')
_REQUEST = re.compile(r"([A-Z]+) (/[^\s]*) HTTP/\d(?:\.\d)?")
_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
_ERRORS = {
    "connection_refused": (re.compile(r"^(connect\(\) failed \(\d{1,6}: Connection refused\))(?:\s|$)"), ""),
    "upstream_timed_out": (re.compile(r"^upstream timed out(?:\s|\(|$)"), "upstream timed out"),
    "prematurely_closed": (re.compile(r"^upstream prematurely closed connection(?:\s|$)"), "upstream prematurely closed connection"),
    "no_live_upstreams": (re.compile(r"^no live upstreams(?:\s|$)"), "no live upstreams"),
}


class NginxInputError(ValueError):
    pass


def _host(value: str) -> str | None:
    if not value or any(char in value for char in "/?#@\\ "):
        return None
    try:
        target = parse_target("http://" + value)
        return str(ipaddress.ip_address(target.host)) if ":" in target.host else target.host.rstrip(".")
    except (InvalidTarget, ValueError):
        return None


def _fields(text: str) -> dict[str, str | None]:
    fields: dict[str, str | None] = {}
    position = 0
    while position < len(text):
        match = _FIELD.match(text, position)
        if not match:
            break
        key, quoted, unquoted = match.groups()
        value = quoted[1:-1] if quoted is not None else unquoted.strip()
        # 重复字段或转义内容无法可靠归属于单一请求。
        if key in fields or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            fields[key] = None
        else:
            fields[key] = value
        position = match.end()
    return fields


def _upstream(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme in {"http", "https"} and parts.hostname:
            port = f":{parts.port}" if parts.port is not None else ""
            return f"{parts.scheme}://[已隐藏]{port}"
    except ValueError:
        pass
    return "[已隐藏]"


def _event(line: str, line_number: int) -> tuple[NginxEvidence, str | None, str | None] | None:
    header = _HEADER.fullmatch(line)
    if not header:
        return None
    timestamp, severity, body = header.groups()
    try:
        datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    start = _FIELDS_START.search(body)
    message = body[:start.start()] if start else body
    fields = _fields(body[start.start():]) if start else {}
    for kind, (pattern, observed) in _ERRORS.items():
        match = pattern.match(message)
        if match:
            if kind == "connection_refused":
                observed = match.group(1)
            break
    else:
        return None

    request = _REQUEST.fullmatch(fields.get("request") or "")
    method = request.group(1) if request and request.group(1) in _METHODS else None
    request_path = request.group(2).split("?", 1)[0] if request else None
    if request_path and ("#" in request_path or "\\" in request_path):
        request_path = None
    host = _host(fields.get("host") or "")
    server = "[已隐藏]" if fields.get("server") else None
    upstream = _upstream(fields.get("upstream"))
    evidence = NginxEvidence(
        line_number, timestamp, "unknown", severity, kind, observed,
        method, "[已隐藏]" if request_path else None, server, upstream, "matched",
    )
    return evidence, host, request_path


def analyze_nginx_file(path: Path, *, host: str | None = None, request_path: str | None = None) -> NginxReport:
    if host is not None:
        # 筛选仅比较主机名，不接受端口或网址。
        normalized_host = _host(host)
        if not normalized_host or (":" in host and not (host.startswith("[") and host.endswith("]"))):
            raise NginxInputError("主机筛选参数无效，请提供不带端口的主机名或方括号括起的 IPv6 地址。")
        host = normalized_host
    if request_path is not None and (
        not request_path.startswith("/") or any(c in request_path for c in "?#\\")
        or any(ord(c) < 33 or ord(c) == 127 for c in request_path)
    ):
        raise NginxInputError("请求路径筛选参数无效，请提供不含查询参数的绝对路径。")

    report = NginxReport(
        "2.0", "user_supplied_log", 0, 0, 0, None, 0, 0, 0,
        {kind: 0 for kind in _ERRORS}, [], "", "unknown", [], [], [], [],
    )
    samples: dict[tuple[str, str], int] = {}
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise NginxInputError("日志必须是普通本地文件。")
        with path.open("rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise NginxInputError("日志必须是普通本地文件。")
            if info.st_size > MAX_FILE_BYTES:
                raise NginxInputError("日志超过 10 MiB 限制。")
            size = 0
            while True:
                raw = file.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    break
                size += len(raw)
                if size > MAX_FILE_BYTES:
                    raise NginxInputError("日志超过 10 MiB 限制。")
                if len(raw) > MAX_LINE_BYTES:
                    raise NginxInputError("日志行超过 64 KiB 限制。")
                report.total_lines += 1
                if report.total_lines > MAX_LINES:
                    raise NginxInputError("日志超过 100000 行限制。")
                line = raw.decode("utf-8").rstrip("\r\n")
                parsed = _event(line, report.total_lines)
                if parsed is None:
                    report.unrecognized_lines += 1
                    continue
                evidence, event_host, event_path = parsed
                report.valid_events += 1
                comparisons = []
                if host is not None:
                    comparisons.append(None if event_host is None else event_host == host)
                if request_path is not None:
                    comparisons.append(None if event_path is None else event_path == request_path)
                if False in comparisons:
                    report.unmatched_events += 1
                    continue
                if None in comparisons:
                    evidence.correlation = "unconfirmed"
                    report.unconfirmed_events += 1
                else:
                    report.matched_events += 1
                    report.fault_counts[evidence.error_type] += 1
                group = (evidence.correlation, evidence.error_type)
                if samples.get(group, 0) < MAX_SAMPLES_PER_GROUP:
                    report.evidence.append(evidence)
                    samples[group] = samples.get(group, 0) + 1
    except UnicodeDecodeError:
        raise NginxInputError("日志不是有效的 UTF-8 编码。") from None
    except OSError:
        raise NginxInputError("无法读取日志文件，请检查文件是否存在及读取权限。") from None
    if report.total_lines == 0:
        raise NginxInputError("日志文件为空。")
    analyze_nginx(report)
    return report
