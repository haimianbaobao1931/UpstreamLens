import math
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from .demo import load_demo
from .diagnostic import diagnose
from .html_report import render_html
from .models import NginxReport, Report
from .nginx import NginxInputError, analyze_nginx_files
from .render import render_json, render_nginx, render_text
from .target import InvalidTarget, parse_target

app = typer.Typer(
    help="诊断单个 HTTP 或 HTTPS 部署目标。",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


class ReportFormat(str, Enum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"


FormatOption = Annotated[ReportFormat, typer.Option("--format", help="报告显示格式。")]
OutputOption = Annotated[Path | None, typer.Option("--output", help="将报告另存为新的 JSON 或 HTML 文件。")]


def _validate_output(output_format: ReportFormat, output: Path | None) -> None:
    if output_format == ReportFormat.HTML and output is None:
        typer.echo("HTML 格式必须使用 --output 指定新文件。", err=True)
        raise typer.Exit(2)


def _emit(report: Report | NginxReport, output_format: ReportFormat, output: Path | None) -> None:
    if output is not None:
        try:
            with output.open("x", encoding="utf-8", newline="\n") as file:
                content = render_html(report) if output_format == ReportFormat.HTML else render_json(report)
                file.write(content + "\n")
        except FileExistsError:
            typer.echo("输出文件已存在，请指定新路径。", err=True)
            raise typer.Exit(2) from None
        except OSError:
            typer.echo("无法写入报告，请检查目录和写入权限。", err=True)
            raise typer.Exit(2) from None

    if output_format == ReportFormat.HTML:
        typer.echo("HTML 报告已保存。")
    elif output_format == ReportFormat.JSON:
        typer.echo(render_json(report))
    elif isinstance(report, NginxReport):
        render_nginx(report, Console(highlight=False, soft_wrap=True))
    else:
        render_text(report, Console(highlight=False, soft_wrap=True))


@app.command("diagnose")
def diagnose_command(
    url: Annotated[str, typer.Argument(help="要探测的 HTTP 或 HTTPS 网址。")],
    output_format: FormatOption = ReportFormat.TEXT,
    output: OutputOption = None,
    timeout: Annotated[float, typer.Option("--timeout", help="每项检测的超时秒数（0 至 60）。")] = 5.0,
) -> None:
    """探测一个网址并输出诊断报告。"""
    _validate_output(output_format, output)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        typer.echo("超时必须大于 0 且不超过 60 秒。", err=True)
        raise typer.Exit(2)
    try:
        target = parse_target(url)
    except InvalidTarget as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(2) from None
    report = diagnose(target, timeout=timeout)
    _emit(report, output_format, output)
    if any(check.status == "FAIL" for check in report.checks):
        raise typer.Exit(1)


@app.command("demo")
def demo_command(
    output_format: FormatOption = ReportFormat.TEXT,
    output: OutputOption = None,
) -> None:
    """离线展示内置的模拟故障报告。"""
    _validate_output(output_format, output)
    _emit(load_demo(), output_format, output)


@app.command("analyze-nginx")
def analyze_nginx_command(
    path: Annotated[list[Path], typer.Argument(help="按顺序提供一个或多个本地 Nginx 错误日志。")],
    output_format: FormatOption = ReportFormat.TEXT,
    output: OutputOption = None,
    host: Annotated[str | None, typer.Option("--host", help="按日志中的请求主机精确筛选。 ")] = None,
    request_path: Annotated[str | None, typer.Option("--request-path", help="按不含查询参数的请求路径精确筛选。 ")] = None,
) -> None:
    """离线分析本地 Nginx 错误日志。"""
    _validate_output(output_format, output)
    try:
        report = analyze_nginx_files(path, host=host, request_path=request_path)
    except NginxInputError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(2) from None
    _emit(report, output_format, output)


def main() -> int:
    # 保证 Windows 重定向输出仍使用 UTF-8，避免随系统代码页变化。
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    try:
        return app(args=sys.argv[1:] or ["--help"], standalone_mode=False) or 0
    except Exception as error:
        if getattr(error, "exit_code", None) != 2:
            raise
        # 参数解析器的默认报错可能回显用户输入的完整网址。
        typer.echo("命令参数无效，请通过 --help 查看用法。", err=True)
        return 2
