import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from upstreamlens.cli import app
from upstreamlens.nginx import MAX_FILE_BYTES, MAX_LINE_BYTES, NginxInputError, analyze_nginx_file


PREFIX = "2026/01/02 03:04:05 [error] 101#101: *1 "
REFUSED = "connect() failed (111: Connection refused) while connecting to upstream"
TIMEOUT = "upstream timed out (110: Connection timed out) while reading response header"
CLOSED = "upstream prematurely closed connection while reading response header"
NO_LIVE = "no live upstreams while connecting to upstream"
FIELDS = ', client: 192.0.2.1, server: gateway.example, request: "GET /api/health?token=secret HTTP/1.1", upstream: "http://192.0.2.10:8080/api/health?token=secret", host: "gateway.example"'


def write_log(tmp_path, text):
    path = tmp_path / "错误日志.log"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("message", "kind"),
    [(REFUSED, "connection_refused"), (TIMEOUT, "upstream_timed_out"),
     (CLOSED, "prematurely_closed"), (NO_LIVE, "no_live_upstreams")],
)
def test_recognizes_four_error_types(tmp_path, message, kind):
    report = analyze_nginx_file(write_log(tmp_path, PREFIX + message + FIELDS + "\n"))
    assert report.valid_events == report.matched_events == 1
    assert report.fault_counts[kind] == 1
    assert sum(report.fault_counts.values()) == 1
    evidence = report.evidence[0]
    assert evidence.timestamp == "2026/01/02 03:04:05"
    assert evidence.timezone == "unknown"
    assert evidence.request_method == "GET"
    assert evidence.request_path == evidence.server == "[已隐藏]"
    assert evidence.upstream == "http://[已隐藏]:8080"
    assert evidence.correlation == "matched"


def test_connection_refusal_is_not_claimed_to_be_stopped_process(tmp_path):
    report = analyze_nginx_file(write_log(tmp_path, PREFIX + REFUSED))
    assert "进程停止" not in str(report)
    assert report.evidence[0].observed == "connect() failed (111: Connection refused)"
    assert any("进程状态" in item for item in report.unconfirmed)


def test_deduplicates_exact_lines_and_counts_other_events(tmp_path):
    first = PREFIX + REFUSED + FIELDS
    second = PREFIX.replace("*1", "*2") + TIMEOUT + FIELDS
    report = analyze_nginx_file(write_log(tmp_path, first + "\n" + first + "\n" + second + "\n"))
    assert (report.total_lines, report.valid_events, report.duplicate_lines) == (3, 2, 1)
    assert report.fault_counts["connection_refused"] == 1
    assert report.fault_counts["upstream_timed_out"] == 1


def test_filter_matches_host_case_port_and_path_without_query(tmp_path):
    report = analyze_nginx_file(
        write_log(tmp_path, PREFIX + REFUSED + FIELDS.replace('host: "gateway.example"', 'host: "GATEWAY.EXAMPLE:443"')),
        host="gateway.example", request_path="/api/health",
    )
    assert report.matched_events == 1
    assert report.unconfirmed_events == report.unmatched_events == 0


def test_filter_nonmatching_host_and_path_are_excluded(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED + FIELDS)
    for options in ({"host": "other.example"}, {"request_path": "/other"}):
        report = analyze_nginx_file(path, **options)
        assert report.unmatched_events == 1
        assert report.matched_events == report.unconfirmed_events == 0
        assert not report.evidence


def test_filter_missing_fields_are_unconfirmed(tmp_path):
    report = analyze_nginx_file(write_log(tmp_path, PREFIX + REFUSED), host="gateway.example", request_path="/api/health")
    assert report.valid_events == report.unconfirmed_events == 1
    assert report.matched_events == 0
    assert report.evidence[0].correlation == "unconfirmed"
    assert not any(report.fault_counts.values())


def test_known_mismatch_takes_precedence_over_missing_field(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED + ', host: "other.example"')
    report = analyze_nginx_file(path, host="gateway.example", request_path="/api")
    assert report.unmatched_events == 1
    assert report.unconfirmed_events == 0


def test_server_alone_is_not_used_as_request_host(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED + ', server: gateway.example')
    report = analyze_nginx_file(path, host="gateway.example")
    assert report.unconfirmed_events == 1


def test_duplicate_host_fields_are_ambiguous(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED + ', host: "gateway.example", host: "other.example"')
    report = analyze_nginx_file(path, host="gateway.example")
    assert report.unconfirmed_events == 1


def test_quoted_request_cannot_inject_host_field(tmp_path):
    line = PREFIX + REFUSED + ', request: "GET /x, host: fake.example HTTP/1.1", host: "real.example"'
    report = analyze_nginx_file(write_log(tmp_path, line), host="fake.example")
    assert report.unmatched_events == 1


def test_incomplete_invalid_and_normal_lines(tmp_path):
    data = "\n".join([
        PREFIX + NO_LIVE,
        "2026/01/02 03:04:05 [notice] 1#1: signal process started",
        "2026/99/02 03:04:05 [error] 1#1: " + REFUSED,
        "random upstream timed out",
        PREFIX + "unrelated connect() failed (111: Connection refused)",
        "2026/01/02 03:04:05 [error] broken",
    ])
    report = analyze_nginx_file(write_log(tmp_path, data))
    assert report.total_lines == 6
    assert report.valid_events == 1
    assert report.unrecognized_lines == 5
    assert report.evidence[0].request_method is None


@pytest.mark.parametrize("level", ["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"])
def test_severity_levels(tmp_path, level):
    report = analyze_nginx_file(write_log(tmp_path, PREFIX.replace("[error]", f"[{level}]") + NO_LIVE))
    assert report.evidence[0].severity == level


def test_empty_file_is_an_error(tmp_path):
    with pytest.raises(NginxInputError, match="为空"):
        analyze_nginx_file(write_log(tmp_path, ""))


def test_invalid_path_and_directory_are_errors(tmp_path):
    with pytest.raises(NginxInputError, match="无法读取"):
        analyze_nginx_file(tmp_path / "missing.log")
    with pytest.raises(NginxInputError, match="普通本地文件"):
        analyze_nginx_file(tmp_path)


def test_unreadable_file_is_an_error(tmp_path, monkeypatch):
    path = write_log(tmp_path, PREFIX + REFUSED)
    original = Path.open

    def denied(self, *args, **kwargs):
        if self == path:
            raise PermissionError("private-data")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(NginxInputError, match="无法读取") as error:
        analyze_nginx_file(path)
    assert "private-data" not in str(error.value)


def test_file_size_limit(tmp_path):
    path = tmp_path / "large.log"
    with path.open("wb") as file:
        file.seek(MAX_FILE_BYTES)
        file.write(b"x")
    with pytest.raises(NginxInputError, match="10 MiB"):
        analyze_nginx_file(path)


def test_line_size_limit(tmp_path):
    path = tmp_path / "long.log"
    path.write_bytes(b"x" * (MAX_LINE_BYTES + 1))
    with pytest.raises(NginxInputError, match="64 KiB"):
        analyze_nginx_file(path)


def test_utf8_and_invalid_encoding(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED + ', server: 示例.example')
    assert analyze_nginx_file(path).valid_events == 1
    path.write_bytes(b"\xff\xfeprivate")
    with pytest.raises(NginxInputError, match="UTF-8") as error:
        analyze_nginx_file(path)
    assert "private" not in str(error.value)


def test_sensitive_fields_and_terminal_controls_are_hidden(tmp_path):
    line = PREFIX + REFUSED + FIELDS + ', referrer: "https://user:password@site.example/?cookie=secret"\x1b[31m'
    path = write_log(tmp_path, line)
    for output_format in ("text", "json"):
        result = CliRunner().invoke(app, ["analyze-nginx", str(path), "--format", output_format])
        assert result.exit_code == 0
        for secret in ("192.0.2.1", "192.0.2.10", "secret", "password", "cookie", "\x1b", "/api/health", "gateway.example"):
            assert secret not in result.output


def test_json_schema_and_unconfirmed_examples(tmp_path):
    path = write_log(tmp_path, PREFIX + TIMEOUT + "\n" + PREFIX.replace("*1", "*2") + REFUSED + FIELDS)
    result = CliRunner().invoke(app, ["analyze-nginx", str(path), "--format", "json", "--host", "gateway.example"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["schema_version"] == "1.0"
    assert data["source"] == "user_supplied_log"
    assert data["total_lines"] == data["valid_events"] == 2
    assert data["matched_events"] == data["unconfirmed_events"] == 1
    assert data["fault_counts"]["connection_refused"] == 1
    assert data["fault_counts"]["upstream_timed_out"] == 0
    assert {sample["correlation"] for sample in data["evidence"]} == {"matched", "unconfirmed"}
    assert data["confidence"] == "medium"
    assert data["confidence_basis"] and data["possible_causes"] and data["unconfirmed"] and data["suggestions"]


@pytest.mark.parametrize("options", [["--host", "https://invalid"], ["--host", "gateway.example:443"], ["--request-path", "/x?token=secret"], ["--request-path", "relative"]])
def test_invalid_filter_is_rejected_without_echo(tmp_path, options):
    path = write_log(tmp_path, PREFIX + REFUSED)
    result = CliRunner().invoke(app, ["analyze-nginx", str(path), *options])
    assert result.exit_code == 2
    assert "secret" not in result.output


def test_output_cannot_overwrite_input_or_existing_file(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED)
    original = path.read_bytes()
    output = tmp_path / "report.json"
    output.write_text("existing", encoding="utf-8")
    for destination in (path, output):
        result = CliRunner().invoke(app, ["analyze-nginx", str(path), "--output", str(destination)])
        assert result.exit_code == 2
    assert path.read_bytes() == original
    assert output.read_text(encoding="utf-8") == "existing"


def test_real_cli_process_and_json_output(tmp_path):
    path = write_log(tmp_path, PREFIX + REFUSED + FIELDS)
    output = tmp_path / "报告.json"
    command = [sys.executable, "-c", "from upstreamlens.cli import main; raise SystemExit(main())"]
    result = subprocess.run(
        [*command, "analyze-nginx", str(path), "--format", "json", "--output", str(output)],
        capture_output=True, env={**os.environ, "PYTHONIOENCODING": "ascii"},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout.decode("utf-8")) == json.loads(output.read_text(encoding="utf-8"))


def test_legacy_demo_json_remains_unchanged():
    result = CliRunner().invoke(app, ["demo", "--format", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0
    assert data["source"] == "simulated"
    assert "schema_version" not in data
    assert data["checks"][-2]["evidence"]["status_code"] == 502
