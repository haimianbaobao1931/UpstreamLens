import json
import os
import subprocess
import sys

from typer.testing import CliRunner

from upstreamlens import cli

runner = CliRunner()


def test_process_output_is_utf8_and_usage_errors_omit_input():
    command = [sys.executable, "-c", "from upstreamlens.cli import main; raise SystemExit(main())"]
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}
    demo = subprocess.run([*command, "demo", "--format", "json"], capture_output=True, env=env)
    assert demo.returncode == 0
    assert "模拟网关" in json.loads(demo.stdout.decode("utf-8"))["summary"]

    invalid = subprocess.run(
        [*command, "diagnose", "http://127.0.0.1:1234", "https://user:secret@site.example"],
        capture_output=True,
        env=env,
    )
    assert invalid.returncode == 2
    assert "命令参数无效" in invalid.stderr.decode("utf-8")
    assert b"secret" not in invalid.stderr + invalid.stdout


def test_help_lists_commands_and_options():
    help_result = runner.invoke(cli.app, ["--help"])
    assert help_result.exit_code == 0
    assert "diagnose" in help_result.stdout
    assert "demo" in help_result.stdout
    detail = runner.invoke(cli.app, ["diagnose", "--help"], env={"NO_COLOR": "1"})
    assert detail.exit_code == 0
    assert all(option in detail.stdout for option in ("--format", "--output", "--timeout"))


def test_invalid_credentials_never_echoed(monkeypatch):
    def unexpected_diagnose(*args, **kwargs):
        raise AssertionError("无效输入不得触发探测")

    monkeypatch.setattr(cli, "diagnose", unexpected_diagnose)
    result = runner.invoke(cli.app, ["diagnose", "https://private-user:private-pass@site.example"])
    assert result.exit_code == 2
    assert "用户名或密码" in result.stderr
    assert "private-" not in result.output


def test_rejects_nan_timeout():
    result = runner.invoke(cli.app, ["diagnose", "https://site.example", "--timeout", "nan"])
    assert result.exit_code == 2
    assert "超时必须" in result.stderr


def test_demo_is_offline_and_marks_simulated_data(monkeypatch):
    def unexpected_diagnose(*args, **kwargs):
        raise AssertionError("演示不得触发探测")

    monkeypatch.setattr(cli, "diagnose", unexpected_diagnose)
    text_result = runner.invoke(cli.app, ["demo"])
    assert text_result.exit_code == 0
    assert "模拟数据" in text_result.stdout
    assert "后端连接" in text_result.stdout

    result = runner.invoke(cli.app, ["demo", "--format", "json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["source"] == "simulated"
    assert report["checks"][1]["status"] == "PASS"
    assert report["checks"][-2]["evidence"]["status_code"] == 502
    assert report["checks"][-1]["evidence"]["port"] == 8080
    assert "连接被拒绝" in report["checks"][-1]["evidence"]["detail"]


def test_json_file_matches_stdout_and_preserves_existing_file(tmp_path):
    output = tmp_path / "报告.json"
    args = ["demo", "--format", "json", "--output", str(output)]
    result = runner.invoke(cli.app, args)
    assert result.exit_code == 0
    content = output.read_text(encoding="utf-8")
    assert json.loads(content) == json.loads(result.stdout)

    duplicate = runner.invoke(cli.app, args)
    assert duplicate.exit_code == 2
    assert "文件已存在" in duplicate.stderr
    assert output.read_text(encoding="utf-8") == content
