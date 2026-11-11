"""对用户指定的 Nginx 文本日志进行有界、离线分析。"""

import ipaddress
import os
import re
import stat
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .models import NginxEvidence, NginxFileEvidence, NginxFileStats, NginxMultiReport, NginxReport
from .rules import analyze_nginx
from .target import InvalidTarget, parse_target

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_LINES = 100_000
MAX_SAMPLES_PER_GROUP = 3
MAX_FILES = 20
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_TOTAL_LINES = 200_000

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


@dataclass
class _Budget:
    bytes_read: int = 0
    lines_read: int = 0


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


def analyze_nginx_file(
    path: Path, *, host: str | None = None, request_path: str | None = None,
    _budget: _Budget | None = None, _identity: tuple[int, int] | None = None,
) -> NginxReport:
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
            if path.suffix.lower() == ".gz" or file.read(2) == b"\x1f\x8b":
                raise NginxInputError("不支持压缩日志。")
            file.seek(0)
            if _identity is not None and (info.st_dev, info.st_ino) != _identity:
                raise NginxInputError("文件在检查后发生变化。")
            if info.st_size > MAX_FILE_BYTES:
                raise NginxInputError("日志超过 10 MiB 限制。")
            size = 0
            while True:
                raw = file.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    break
                size += len(raw)
                if _budget is not None:
                    _budget.bytes_read += len(raw)
                    _budget.lines_read += 1
                    if _budget.bytes_read > MAX_TOTAL_BYTES:
                        raise NginxInputError("多文件总大小超过 30 MiB 限制。")
                    if _budget.lines_read > MAX_TOTAL_LINES:
                        raise NginxInputError("多文件总行数超过 200000 行限制。")
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


def analyze_nginx_files(
    paths: list[Path], *, host: str | None = None, request_path: str | None = None,
) -> NginxReport:
    if not paths:
        raise NginxInputError("请指定日志文件。")
    if len(paths) == 1:
        return analyze_nginx_file(paths[0], host=host, request_path=request_path)
    if len(paths) > MAX_FILES:
        raise NginxInputError("最多只能提供 20 个日志文件。")

    identities: set[tuple[int, int]] = set()
    checked: list[tuple[int, int]] = []
    total_bytes = 0
    total_lines = 0
    for index, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() == ".gz":
                raise NginxInputError("不支持压缩日志。")
            if not stat.S_ISREG(path.stat().st_mode):
                raise NginxInputError("日志必须是普通本地文件。")
            with path.open("rb") as file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise NginxInputError("日志必须是普通本地文件。")
                if file.read(2) == b"\x1f\x8b":
                    raise NginxInputError("不支持压缩日志。")
                if info.st_size == 0:
                    raise NginxInputError("日志文件为空。")
                if info.st_size > MAX_FILE_BYTES:
                    raise NginxInputError("日志超过 10 MiB 限制。")
                identity = (info.st_dev, info.st_ino)
                if not info.st_ino:
                    raise NginxInputError("无法验证文件身份。")
                if identity in identities:
                    raise NginxInputError("与之前的输入是同一个文件。")
                file.seek(0)
                file_bytes = 0
                file_lines = 0
                while True:
                    raw = file.readline(MAX_LINE_BYTES + 1)
                    if not raw:
                        break
                    file_bytes += len(raw)
                    file_lines += 1
                    total_bytes += len(raw)
                    total_lines += 1
                    if file_bytes > MAX_FILE_BYTES:
                        raise NginxInputError("日志超过 10 MiB 限制。")
                    if len(raw) > MAX_LINE_BYTES:
                        raise NginxInputError("日志行超过 64 KiB 限制。")
                    if file_lines > MAX_LINES:
                        raise NginxInputError("日志超过 100000 行限制。")
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise NginxInputError("多文件总大小超过 30 MiB 限制。")
                    if total_lines > MAX_TOTAL_LINES:
                        raise NginxInputError("多文件总行数超过 200000 行限制。")
                    raw.decode("utf-8")
                if not file_lines:
                    raise NginxInputError("日志文件为空。")
            identities.add(identity)
            checked.append(identity)
        except UnicodeDecodeError:
            raise NginxInputError(f"输入文件 {index}：日志不是有效的 UTF-8 编码。") from None
        except OSError:
            raise NginxInputError(f"输入文件 {index} 无法读取，请检查文件和权限。") from None
        except NginxInputError as error:
            raise NginxInputError(f"输入文件 {index}：{error}") from None

    reports: list[NginxReport] = []
    budget = _Budget()
    for index, (path, identity) in enumerate(zip(paths, checked), 1):
        try:
            reports.append(analyze_nginx_file(
                path, host=host, request_path=request_path, _budget=budget, _identity=identity,
            ))
        except NginxInputError as error:
            raise NginxInputError(f"输入文件 {index}：{error}") from None

    result = NginxMultiReport(
        "3.0", "user_supplied_log", 0, 0, 0, None, 0, 0, 0,
        {kind: 0 for kind in _ERRORS}, [], "", "unknown", [], [], [], [], [],
    )
    samples: dict[tuple[str, str], int] = {}
    for index, report in enumerate(reports, 1):
        source = f"file-{index}"
        result.files.append(NginxFileStats(
            source, report.total_lines, report.valid_events, report.unrecognized_lines,
            report.matched_events, report.unmatched_events, report.unconfirmed_events,
            report.fault_counts.copy(),
        ))
        result.total_lines += report.total_lines
        result.valid_events += report.valid_events
        result.unrecognized_lines += report.unrecognized_lines
        result.matched_events += report.matched_events
        result.unmatched_events += report.unmatched_events
        result.unconfirmed_events += report.unconfirmed_events
        for kind, count in report.fault_counts.items():
            result.fault_counts[kind] += count
        for evidence in report.evidence:
            group = (evidence.correlation, evidence.error_type)
            if samples.get(group, 0) < MAX_SAMPLES_PER_GROUP:
                result.evidence.append(NginxFileEvidence(**asdict(evidence), source_file=source))
                samples[group] = samples.get(group, 0) + 1
    analyze_nginx(result)
    result.unconfirmed.append("不同文件可能包含重叠记录，汇总可能重复计算。")
    return result
