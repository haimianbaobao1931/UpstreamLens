import json
import os
import re
from dataclasses import asdict

import pytest
from typer.testing import CliRunner

from upstreamlens import nginx
from upstreamlens.cli import app


PREFIX = "2026/01/02 03:04:05 [error] 101#101: *1 "
REFUSED = "connect() failed (111: Connection refused) while connecting to upstream"
TIMEOUT = "upstream timed out (110: Connection timed out) while reading response header"
NO_LIVE = "no live upstreams while connecting to upstream"
FIELDS = ', client: 192.0.2.1, server: gateway.example, request: "GET /api/health?token=secret HTTP/1.1", upstream: "http://192.0.2.10:8080/api/health", host: "gateway.example"'


@pytest.fixture
def logs(tmp_path):
    folder = tmp_path / "私密目录"
    folder.mkdir()
    paths = [folder / "secret.log", folder / "secret.log.1", folder / "secret.log.2"]
    lines = [PREFIX + REFUSED + FIELDS, PREFIX + TIMEOUT + FIELDS, PREFIX + NO_LIVE + FIELDS]
    for path, line in zip(paths, lines):
        path.write_text(line + "\n", encoding="utf-8")
    return paths


def test_single_file_schema_and_output_are_unchanged(logs):
    expected = asdict(nginx.analyze_nginx_file(logs[0]))
    result = CliRunner().invoke(app, ["analyze-nginx", str(logs[0]), "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == expected
    assert expected["schema_version"] == "2.0"
    assert "files" not in expected
    assert "source_file" not in expected["evidence"][0]


@pytest.mark.parametrize("number", [2, 3])
def test_aggregate_and_per_file_counts_are_consistent(logs, number):
    report = nginx.analyze_nginx_files(logs[:number])
    assert report.schema_version == "3.0"
    assert report.total_lines == report.valid_events == report.matched_events == number
    assert report.unrecognized_lines == report.unmatched_events == report.unconfirmed_events == 0
    assert sum(report.fault_counts.values()) == number
    assert report.total_lines == sum(file.total_lines for file in report.files)
    assert report.valid_events == sum(file.valid_events for file in report.files)
    assert report.matched_events == sum(file.matched_events for file in report.files)
    for kind in report.fault_counts:
        assert report.fault_counts[kind] == sum(file.fault_counts[kind] for file in report.files)
    assert [file.source_file for file in report.files] == [f"file-{i}" for i in range(1, number + 1)]
    assert [item.source_file for item in report.evidence] == [f"file-{i}" for i in range(1, number + 1)]
    assert all(item.line == 1 for item in report.evidence)


def test_same_content_in_distinct_files_is_counted(logs):
    logs[1].write_bytes(logs[0].read_bytes())
    report = nginx.analyze_nginx_files(logs[:2])
    assert report.valid_events == report.matched_events == 2
    assert report.fault_counts["connection_refused"] == 2
    assert [item.source_file for item in report.evidence] == ["file-1", "file-2"]
    assert any("重叠记录" in item for item in report.unconfirmed)


def test_input_order_is_preserved_without_time_sorting(logs):
    logs[0].write_text((PREFIX + REFUSED + FIELDS).replace("2026/01/02", "2026/01/03"), encoding="utf-8")
    logs[1].write_text((PREFIX + TIMEOUT + FIELDS).replace("2026/01/02", "2025/01/01"), encoding="utf-8")
    report = nginx.analyze_nginx_files(logs[:2])
    assert [(item.source_file, item.timestamp) for item in report.evidence] == [
        ("file-1", "2026/01/03 03:04:05"), ("file-2", "2025/01/01 03:04:05")
    ]


def test_same_file_relative_and_absolute_alias_are_rejected(logs, monkeypatch):
    monkeypatch.chdir(logs[0].parent)
    with pytest.raises(nginx.NginxInputError, match="输入文件 2.*同一个文件"):
        nginx.analyze_nginx_files([logs[0], logs[0].parent / "." / logs[0].name])
    result = CliRunner().invoke(app, ["analyze-nginx", logs[0].name, str(logs[0].resolve())])
    assert result.exit_code == 2
    assert "输入文件 2" in result.output


def test_hard_link_alias_is_rejected(logs, tmp_path):
    alias = tmp_path / "alias.log"
    os.link(logs[0], alias)
    with pytest.raises(nginx.NginxInputError, match="输入文件 2.*同一个文件"):
        nginx.analyze_nginx_files([logs[0], alias])


def test_host_and_path_filters_apply_per_file(logs):
    logs[1].write_text(PREFIX + TIMEOUT + FIELDS.replace('host: "gateway.example"', 'host: "other.example"'), encoding="utf-8")
    logs[2].write_text(PREFIX + NO_LIVE, encoding="utf-8")
    report = nginx.analyze_nginx_files(logs, host="gateway.example", request_path="/api/health")
    assert (report.valid_events, report.matched_events, report.unmatched_events, report.unconfirmed_events) == (3, 1, 1, 1)
    assert [(f.matched_events, f.unmatched_events, f.unconfirmed_events) for f in report.files] == [(1, 0, 0), (0, 1, 0), (0, 0, 1)]
    assert [(item.source_file, item.correlation) for item in report.evidence] == [("file-1", "matched"), ("file-3", "unconfirmed")]


@pytest.mark.parametrize("problem", ["missing", "empty", "directory", "invalid_utf8", "gzip", "too_large"])
def test_any_invalid_input_fails_without_partial_report_or_output(logs, tmp_path, problem):
    bad = logs[1]
    if problem == "missing":
        bad = tmp_path / "missing-sensitive.log"
    elif problem == "empty":
        bad.write_bytes(b"")
    elif problem == "directory":
        bad = tmp_path
    elif problem == "invalid_utf8":
        bad.write_bytes(b"\xffprivate")
    elif problem == "gzip":
        bad.write_bytes(b"\x1f\x8bprivate")
    else:
        with bad.open("wb") as file:
            file.seek(nginx.MAX_FILE_BYTES)
            file.write(b"x")
    output = tmp_path / "result.json"
    result = CliRunner().invoke(app, ["analyze-nginx", str(logs[0]), str(bad), "--format", "json", "--output", str(output)])
    assert result.exit_code == 2
    assert "输入文件 2" in result.output
    assert "private" not in result.output and "sensitive" not in result.output
    assert "schema_version" not in result.output
    assert not output.exists()


def test_gzip_suffix_is_rejected_for_one_and_multiple_files(logs, tmp_path):
    compressed = tmp_path / "archive.gz"
    compressed.write_bytes(b"\x1f\x8bdata")
    for paths in ([compressed], [logs[0], compressed]):
        with pytest.raises(nginx.NginxInputError, match="不支持压缩"):
            nginx.analyze_nginx_files(paths)


def test_total_size_limit_rejects_before_parsing(logs, monkeypatch):
    monkeypatch.setattr(nginx, "MAX_TOTAL_BYTES", sum(path.stat().st_size for path in logs[:2]) - 1)
    monkeypatch.setattr(nginx, "analyze_nginx_file", lambda *args, **kwargs: pytest.fail("不应生成部分报告"))
    with pytest.raises(nginx.NginxInputError, match="输入文件 2.*总大小"):
        nginx.analyze_nginx_files(logs[:2])


def test_later_invalid_encoding_is_checked_before_any_report(logs, monkeypatch):
    logs[1].write_bytes(b"\xff")
    monkeypatch.setattr(nginx, "analyze_nginx_file", lambda *args, **kwargs: pytest.fail("不应生成部分报告"))
    with pytest.raises(nginx.NginxInputError, match="输入文件 2.*UTF-8"):
        nginx.analyze_nginx_files(logs[:2])


def test_total_line_limit_rejects_before_parsing(logs, monkeypatch):
    monkeypatch.setattr(nginx, "MAX_TOTAL_LINES", 2)
    monkeypatch.setattr(nginx, "analyze_nginx_file", lambda *args, **kwargs: pytest.fail("不应生成部分报告"))
    with pytest.raises(nginx.NginxInputError, match="输入文件 3.*总行数"):
        nginx.analyze_nginx_files(logs)


def test_unreadable_second_file_identifies_input_and_leaks_no_path(logs, monkeypatch):
    original = type(logs[1]).open

    def denied(path, *args, **kwargs):
        if path == logs[1]:
            raise PermissionError("private-error")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(type(logs[1]), "open", denied)
    result = CliRunner().invoke(app, ["analyze-nginx", str(logs[0]), str(logs[1]), "--format", "json"])
    assert result.exit_code == 2
    assert "输入文件 2" in result.output
    assert "private-error" not in result.output and "私密目录" not in result.output
    assert "schema_version" not in result.output


def test_file_growth_after_preflight_still_enforces_total_limit(logs, monkeypatch):
    limit = sum(path.stat().st_size for path in logs[:2])
    monkeypatch.setattr(nginx, "MAX_TOTAL_BYTES", limit)
    original = nginx.analyze_nginx_file

    def grow_before_read(path, **kwargs):
        if path == logs[1]:
            with path.open("ab") as file:
                file.write(b"extra\n")
        return original(path, **kwargs)

    monkeypatch.setattr(nginx, "analyze_nginx_file", grow_before_read)
    with pytest.raises(nginx.NginxInputError, match="输入文件 2.*总大小"):
        nginx.analyze_nginx_files(logs[:2])


def test_file_replacement_after_preflight_is_rejected(logs, tmp_path, monkeypatch):
    replacement = tmp_path / "replacement.log"
    replacement.write_text(PREFIX + NO_LIVE, encoding="utf-8")
    original = nginx.analyze_nginx_file

    def replace_before_read(path, **kwargs):
        if path == logs[1]:
            os.replace(replacement, path)
        return original(path, **kwargs)

    monkeypatch.setattr(nginx, "analyze_nginx_file", replace_before_read)
    with pytest.raises(nginx.NginxInputError, match="输入文件 2.*发生变化"):
        nginx.analyze_nginx_files(logs[:2])


def test_global_sampling_is_bounded_and_retains_source(logs):
    logs[0].write_text((PREFIX + REFUSED + FIELDS + "\n") * 2, encoding="utf-8")
    logs[1].write_text((PREFIX + REFUSED + FIELDS + "\n") * 2, encoding="utf-8")
    report = nginx.analyze_nginx_files(logs[:2])
    assert report.fault_counts["connection_refused"] == 4
    assert [(item.source_file, item.line) for item in report.evidence] == [
        ("file-1", 1), ("file-1", 2), ("file-2", 1)
    ]


def test_max_file_count_is_bounded(logs):
    with pytest.raises(nginx.NginxInputError, match="20"):
        nginx.analyze_nginx_files([logs[0]] * (nginx.MAX_FILES + 1))


def test_sources_are_anonymous_and_text_matches_json(logs):
    runner = CliRunner()
    args = ["analyze-nginx", *(str(path) for path in logs)]
    text = runner.invoke(app, args)
    structured = runner.invoke(app, [*args, "--format", "json"])
    assert text.exit_code == structured.exit_code == 0
    data = json.loads(structured.stdout)
    assert data["schema_version"] == "3.0"
    assert data["source"] == "user_supplied_log"
    assert data["duplicate_lines"] is None
    assert f"总行数 {data['total_lines']}" in text.stdout
    assert f"有效记录 {data['valid_events']}" in text.stdout
    for file in data["files"]:
        assert file["source_file"] in text.stdout
        assert file["total_lines"] == 1
    for kind, count in data["fault_counts"].items():
        assert re.search(rf"\b{re.escape(kind)}\s+│\s+{count}\s+│", text.stdout)
    for output in (text.output, structured.output):
        for secret in ("私密目录", "secret", "192.0.2.1", "gateway.example", str(logs[0].parent)):
            assert secret not in output
        assert "\x1b" not in output


def test_cannot_overwrite_any_input_or_existing_output(logs, tmp_path):
    originals = [path.read_bytes() for path in logs]
    existing = tmp_path / "existing.json"
    existing.write_text("keep", encoding="utf-8")
    for output in [*logs, existing]:
        result = CliRunner().invoke(app, ["analyze-nginx", *(str(path) for path in logs), "--output", str(output)])
        assert result.exit_code == 2
    assert [path.read_bytes() for path in logs] == originals
    assert existing.read_text(encoding="utf-8") == "keep"


def test_multi_json_output_file_matches_stdout(logs, tmp_path):
    output = tmp_path / "报告.json"
    args = ["analyze-nginx", *(str(path) for path in logs), "--format", "json", "--output", str(output)]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(result.stdout)


def line(timestamp, message, fields=FIELDS):
    return f"{timestamp} [error] 101#101: *1 {message}{fields}"


@pytest.mark.parametrize("terminator", [b"\n", b"\r\n"])
def test_line_limit_counts_content_not_the_terminator(logs, terminator):
    head = (PREFIX + REFUSED).encode("utf-8")
    line_bytes = head + b" " + b"y" * (nginx.MAX_LINE_BYTES - len(head) - 1)
    assert len(line_bytes) == nginx.MAX_LINE_BYTES
    logs[0].write_bytes(line_bytes + terminator)
    report = nginx.analyze_nginx_files(logs[:2])

    assert report.files[0].valid_events == 1
    assert report.fault_counts["connection_refused"] == 1
    assert report.files[1].fault_counts["upstream_timed_out"] == 1


def test_line_above_limit_is_rejected_in_multi_mode(logs):
    head = (PREFIX + REFUSED).encode("utf-8")
    logs[1].write_bytes(head + b" " + b"y" * (nginx.MAX_LINE_BYTES - len(head)))
    with pytest.raises(nginx.NginxInputError, match="输入文件 2：日志行超过 64 KiB"):
        nginx.analyze_nginx_files(logs[:2])


def test_multi_fault_window_is_aggregate_and_per_file(logs):
    logs[0].write_text(line("2026/01/02 05:00:00", NO_LIVE) + "\n", encoding="utf-8")
    logs[1].write_text(line("2026/01/01 23:00:00", NO_LIVE) + "\n", encoding="utf-8")
    report = nginx.analyze_nginx_files(logs[:2])

    assert report.first_fault_timestamp == "2026/01/01 23:00:00"
    assert report.last_fault_timestamp == "2026/01/02 05:00:00"
    assert report.fault_span_seconds == 6 * 3600
    assert [(file.first_fault_timestamp, file.last_fault_timestamp, file.fault_span_seconds)
            for file in report.files] == [
        ("2026/01/02 05:00:00", "2026/01/02 05:00:00", 0),
        ("2026/01/01 23:00:00", "2026/01/01 23:00:00", 0),
    ]


def test_multi_fault_window_is_absent_when_nothing_matches(logs):
    report = nginx.analyze_nginx_files(logs[:2], host="missing.example")

    assert report.matched_events == 0
    assert report.first_fault_timestamp is None
    assert report.fault_span_seconds is None
    assert all(file.first_fault_timestamp is None for file in report.files)
