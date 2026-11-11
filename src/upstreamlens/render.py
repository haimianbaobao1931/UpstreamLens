import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from .models import NginxReport, Report

_STATUS_COLORS = {"PASS": "green", "FAIL": "red", "UNKNOWN": "yellow"}


def render_json(report: Report | NginxReport) -> str:
    return json.dumps(asdict(report), ensure_ascii=False, indent=2)


def render_nginx(report: NginxReport, console: Console) -> None:
    console.print("用户提供的 Nginx 日志", markup=False)
    console.print(
        f"总行数 {report.total_lines}  有效记录 {report.valid_events}  "
        f"未识别 {report.unrecognized_lines}",
        markup=False,
    )
    console.print(
        f"符合筛选 {report.matched_events}  不匹配 {report.unmatched_events}  "
        f"关联未确认 {report.unconfirmed_events}", markup=False,
    )
    table = Table(show_lines=True)
    table.add_column("故障类型")
    table.add_column("数量")
    for kind, count in report.fault_counts.items():
        table.add_row(kind, str(count))
    console.print(table)
    for item in report.evidence:
        console.print(
            f"证据 第 {item.line} 行  {item.timestamp}（时区未知）  "
            f"{item.severity}  {item.observed}  关联 {item.correlation}", markup=False,
        )
        console.print(
            f"方法 {item.request_method or '未知'}  请求路径 {item.request_path or '未知'}  "
            f"服务器 {item.server or '未知'}  上游 {item.upstream or '未知'}", markup=False,
        )
    console.print(f"结论  {report.summary}  置信度 {report.confidence}", markup=False)
    for title, items in (
        ("置信度依据", report.confidence_basis),
        ("可能原因", report.possible_causes),
        ("待确认", report.unconfirmed),
        ("排查建议", report.suggestions),
    ):
        for item in items:
            console.print(f"{title}  {item}", markup=False)


def render_text(report: Report, console: Console) -> None:
    source = "模拟数据（离线演示）" if report.source == "simulated" else "实际探测"
    console.print(f"{source}  {report.target}")
    console.print(f"时间（协调世界时） {report.timestamp}")
    table = Table(show_lines=True)
    table.add_column("检测项")
    table.add_column("状态")
    table.add_column("证据")
    labels = {
        "host": "主机",
        "port": "端口",
        "addresses": "解析地址",
        "address": "地址",
        "version": "版本",
        "certificate": "证书",
        "valid_from": "证书生效",
        "valid_until": "证书到期",
        "status_code": "状态码",
        "detail": "说明",
        "error_code": "错误码",
    }
    for check in report.checks:
        fields = []
        for key, value in check.evidence.items():
            displayed = "、".join(value) if isinstance(value, list) else str(value)
            fields.append(f"{labels.get(key, key)} {displayed}")
        table.add_row(
            check.name,
            f"[{_STATUS_COLORS[check.status]}]{check.status}[/]",
            "\n".join(fields),
        )
    console.print(table)
    console.print(f"结论  {report.summary}")
    for title, items in (
        ("可能原因", report.possible_causes),
        ("待确认", report.unconfirmed),
        ("排查建议", report.suggestions),
    ):
        for item in items:
            console.print(f"{title}  {item}")
