import hashlib
import html
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest
from typer.testing import CliRunner

from upstreamlens import cli
from upstreamlens.demo import load_demo
from upstreamlens.html_report import render_html
from upstreamlens.models import Check, NginxFileEvidence
from upstreamlens.nginx import analyze_nginx_files
from upstreamlens.render import render_json


PREFIX = "2026/01/02 03:04:05 [error] 101#101: *1 "
FAULT = "connect() failed (111: Connection refused) while connecting to upstream"
FIELDS = ', client: 192.0.2.1, server: gateway.example, request: "GET /api?token=private-token HTTP/1.1", upstream: "http://192.0.2.10:8080/api?secret=private-secret", host: "gateway.example"'


@pytest.fixture
def logs(tmp_path):
    directory = tmp_path / "隐私目录"
    directory.mkdir()
    paths = [directory / "secret.log", directory / "secret.log.1"]
    for path in paths:
        path.write_text(PREFIX + FAULT + FIELDS + "\n", encoding="utf-8")
    return paths


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.meters = []
        self.ids = []
        self.policy = ""
        self.style = ""
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "meter":
            self.meters.append(attrs)
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.policy = attrs["content"]
        if tag == "style":
            self.in_style = True

    def handle_data(self, data):
        if self.in_style:
            self.style += data

    def handle_endtag(self, tag):
        if tag == "style":
            self.in_style = False


def parse(document):
    parser = Document()
    parser.feed(document)
    parser.close()
    return parser


@pytest.mark.parametrize("args", [
    ["demo"],
    ["diagnose", "https://site.example"],
    ["analyze-nginx", "missing.log"],
])
def test_html_requires_output_before_diagnostic_operations(monkeypatch, args):
    def unexpected(*args, **kwargs):
        pytest.fail("缺少输出路径时不应执行诊断或读取日志")

    monkeypatch.setattr(cli, "diagnose", unexpected)
    monkeypatch.setattr(cli, "analyze_nginx_files", unexpected)
    result = CliRunner().invoke(cli.app, [*args, "--format", "html"])
    assert result.exit_code == 2
    assert "必须使用 --output" in result.output


def test_demo_html_marks_simulation_and_preserves_evidence(tmp_path):
    output = tmp_path / "演示.html"
    result = CliRunner().invoke(cli.app, ["demo", "--format", "html", "--output", str(output)])
    assert result.exit_code == 0
    doc = output.read_text(encoding="utf-8")
    assert doc.lower().startswith("<!doctype html>")
    assert "SIMULATED / 模拟数据" in doc
    assert "模拟网关" in doc and "502" in doc
    assert "后端连接" in doc and "连接被拒绝" in doc
    assert "HTML 报告已保存" in result.stdout


def test_simulation_time_and_generation_time_are_distinct():
    generated = datetime(2026, 11, 12, 8, 30, tzinfo=timezone.utc)
    doc = render_html(load_demo(), generated_at=generated)
    assert "模拟场景时间</span><strong>2026-01-01T00:00:00+00:00" in doc
    assert "报告生成时间（UTC）</span><strong>2026-11-12T08:30:00+00:00" in doc
    assert "本报告中的检测项" in doc


def test_live_diagnostic_time_retains_its_meaning():
    report = load_demo()
    report.source = "live"
    report.timestamp = "2026-11-11T10:20:30+00:00"
    doc = render_html(report)
    assert "分析时间</span><strong>2026-11-11T10:20:30+00:00" in doc
    assert "模拟场景时间" not in doc
    assert "报告生成时间（UTC）" not in doc
    assert "本报告中的检测项" in doc


def test_diagnose_html_preserves_actual_statuses_and_uncertainty(monkeypatch, tmp_path):
    report = deepcopy(load_demo())
    report.source = "live"
    report.target = "https://service.example"
    report.checks = [
        Check("DNS", "PASS", {"addresses": ["192.0.2.9"]}),
        Check("TCP", "PASS", {"port": 443}),
        Check("TLS", "UNKNOWN", {"detail": "未执行"}),
        Check("HTTP", "FAIL", {"status_code": 502}),
    ]
    report.unconfirmed = ["实际后端地址和端口未知"]
    monkeypatch.setattr(cli, "diagnose", lambda *args, **kwargs: report)
    output = tmp_path / "网络.html"
    result = CliRunner().invoke(cli.app, ["diagnose", "https://service.example", "--format", "html", "--output", str(output)])
    assert result.exit_code == 1
    doc = output.read_text(encoding="utf-8")
    for value in ("实际网络探测", "DNS", "TCP", "TLS", "HTTP", "PASS", "FAIL", "UNKNOWN", "502", "实际后端地址和端口未知"):
        assert value in doc
    assert "SIMULATED / 模拟数据" not in doc
    assert "故障类型" not in doc


@pytest.mark.parametrize("number", [1, 2])
def test_nginx_html_counts_and_sources(logs, tmp_path, number):
    output = tmp_path / "日志.html"
    args = ["analyze-nginx", *(str(path) for path in logs[:number]), "--format", "html", "--output", str(output)]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0
    doc = output.read_text(encoding="utf-8")
    assert "用户提供的日志" in doc
    assert "原报告未记录分析时间" in doc
    assert "日志记录数不等于独立请求数" in doc
    assert "http://[已隐藏]:8080" in doc
    parser = parse(doc)
    assert int(parser.meters[0]["value"]) == number
    if number == 1:
        assert "文件统计" not in doc and "单文件" in doc
    else:
        assert "文件统计" in doc and "file-1" in doc and "file-2" in doc
        assert "重叠记录" in doc


def test_multi_html_exposes_unconfirmed_counts_and_samples(logs, tmp_path):
    logs[1].write_text(PREFIX + FAULT, encoding="utf-8")
    output = tmp_path / "筛选.html"
    args = ["analyze-nginx", *(str(path) for path in logs), "--host", "gateway.example", "--format", "html", "--output", str(output)]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0
    doc = output.read_text(encoding="utf-8")
    assert "关联未确认 1" in doc and "unconfirmed" in doc
    assert "file-2" in doc


def test_document_is_self_contained_and_csp_hash_matches_style():
    document = render_html(load_demo())
    parser = parse(document)
    assert len(parser.ids) == len(set(parser.ids))
    assert "default-src 'none'" in parser.policy
    assert "object-src 'none'" in parser.policy
    assert "@import" not in parser.style.lower()
    assert "url(" not in parser.style.lower()
    import base64
    digest = base64.b64encode(hashlib.sha256(parser.style.encode("utf-8")).digest()).decode("ascii")
    assert f"'sha256-{digest}'" in parser.policy
    for tag, attrs in parser.tags:
        assert tag not in {"script", "link", "iframe", "object", "embed", "img"}
        assert "src" not in attrs
        assert not any(key.startswith("on") for key in attrs)
        if "href" in attrs:
            assert attrs["href"].startswith("#")


@pytest.mark.parametrize("payload", [
    '<script>alert("x")</script>',
    '<img src=x onerror=alert(1)>',
    '</style><script>alert(1)</script>',
    '中文 & "特殊" <内容>',
])
def test_dynamic_text_is_escaped(payload):
    report = load_demo()
    report.summary = payload
    report.possible_causes = [payload]
    report.suggestions = [payload]
    report.checks[0].name = payload
    document = render_html(report)
    assert payload not in document
    assert html.escape(payload, quote=True) in document
    assert all(tag not in {"script", "img"} for tag, _ in parse(document).tags)


def test_untrusted_evidence_fields_and_source_are_escaped(logs):
    report = analyze_nginx_files(logs)
    payload = '<script>alert("source")</script>'
    evidence = report.evidence[0]
    assert isinstance(evidence, NginxFileEvidence)
    evidence.source_file = payload
    evidence.observed = payload
    report.files[0].source_file = payload
    document = render_html(report)
    assert payload not in document
    assert html.escape(payload, quote=True) in document
    assert all(tag != "script" for tag, _ in parse(document).tags)


def test_sensitive_values_and_local_paths_are_redacted(logs, tmp_path):
    output = tmp_path / "report.html"
    result = CliRunner().invoke(cli.app, ["analyze-nginx", *(str(path) for path in logs), "--format", "html", "--output", str(output)])
    assert result.exit_code == 0
    document = output.read_text(encoding="utf-8")
    for secret in ("private-token", "private-secret", "192.0.2.1", "192.0.2.10", "隐私目录", "secret.log", str(tmp_path)):
        assert secret not in document
    report = load_demo()
    report.summary = "Cookie: session=hunter2"
    report.checks[0].evidence = {"url": "https://user:password@example.com/private?token=topsecret", "path": "/home/user/private.log", "detail": "Bearer bearer-secret"}
    doc = render_html(report)
    for secret in ("hunter2", "password", "topsecret", "/home/user/private.log", "bearer-secret"):
        assert secret not in doc


@pytest.mark.parametrize("command", ["demo", "analyze-nginx"])
def test_existing_output_is_preserved(logs, tmp_path, command):
    output = tmp_path / "existing.html"
    output.write_text("原有内容", encoding="utf-8")
    args = [command, *(str(path) for path in logs)] if command == "analyze-nginx" else [command]
    result = CliRunner().invoke(cli.app, [*args, "--format", "html", "--output", str(output)])
    assert result.exit_code == 2
    assert output.read_text(encoding="utf-8") == "原有内容"


def test_html_output_cannot_overwrite_input(logs):
    originals = [path.read_bytes() for path in logs]
    for output in logs:
        result = CliRunner().invoke(cli.app, ["analyze-nginx", *(str(path) for path in logs), "--format", "html", "--output", str(output)])
        assert result.exit_code == 2
    assert [path.read_bytes() for path in logs] == originals


def test_html_invalid_output_directory(tmp_path):
    output = tmp_path / "missing" / "report.html"
    result = CliRunner().invoke(cli.app, ["demo", "--format", "html", "--output", str(output)])
    assert result.exit_code == 2
    assert not output.exists()


def test_original_json_output_and_schema_are_preserved(logs, tmp_path):
    report = analyze_nginx_files(logs)
    baseline = asdict(report)
    render_html(report)
    assert asdict(report) == baseline
    assert baseline["schema_version"] == "3.0"
    output = tmp_path / "report.json"
    result = CliRunner().invoke(cli.app, ["demo", "--format", "text", "--output", str(output)])
    assert result.exit_code == 0
    assert output.read_text(encoding="utf-8").strip() == render_json(load_demo())


@pytest.mark.parametrize("schema", ["1.0", "2.0", "3.0"])
def test_html_preserves_each_nginx_json_schema(logs, schema):
    report = analyze_nginx_files(logs if schema == "3.0" else logs[:1])
    report.schema_version = schema
    if schema == "1.0":
        report.duplicate_lines = 1
    original = render_json(report)
    document = render_html(report)
    assert render_json(report) == original
    assert ("旧版去重统计，可能少计" in document) == (schema == "1.0")


def test_wheel_install_generates_html_without_network(tmp_path):
    root = Path(__file__).resolve().parents[1]
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    env = {**os.environ, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    build = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels), str(root)],
        capture_output=True, env=env,
    )
    assert build.returncode == 0, build.stderr.decode("utf-8", "replace")
    wheel, = wheels.glob("upstreamlens-*.whl")
    site = tmp_path / "installed"
    installed = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(site), str(wheel)],
        capture_output=True, env=env,
    )
    assert installed.returncode == 0, installed.stderr.decode("utf-8", "replace")
    output = tmp_path / "wheel.html"
    script = (
        "import sys; from pathlib import Path; "
        "site = Path(sys.argv.pop(1)); sys.path.insert(0, str(site)); "
        "import upstreamlens; assert Path(upstreamlens.__file__).is_relative_to(site); "
        "from upstreamlens.cli import main; raise SystemExit(main())"
    )
    run = subprocess.run(
        [sys.executable, "-c", script, str(site), "demo", "--format", "html", "--output", str(output)],
        cwd=tmp_path, capture_output=True, env=env,
    )
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
    assert "SIMULATED / 模拟数据" in output.read_text(encoding="utf-8")
