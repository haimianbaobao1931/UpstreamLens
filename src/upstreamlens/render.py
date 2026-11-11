import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from .models import Report

_STATUS_COLORS = {"PASS": "green", "FAIL": "red", "UNKNOWN": "yellow"}


def render_json(report: Report) -> str:
    return json.dumps(asdict(report), ensure_ascii=False, indent=2)


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
