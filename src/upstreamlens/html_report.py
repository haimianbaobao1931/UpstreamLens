"""将现有诊断结果渲染为无需网络和脚本的独立报告。"""

import base64
import hashlib
import html
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .models import NginxFileEvidence, NginxMultiReport, NginxReport, Report

_CSS = """
:root{color-scheme:light;--ink:#172b38;--muted:#5a707c;--line:#dbe5e8;--paper:#fff;--canvas:#f1f5f5;--nav:#122d3a;--teal:#166e69;--red:#a5332d;--amber:#946200}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;line-height:1.55}
.layout{display:grid;grid-template-columns:235px minmax(0,1fr);min-height:100vh}.rail{background:var(--nav);color:#d0e3e4;padding:30px 22px}.brand{font-size:20px;font-weight:750;letter-spacing:-.04em;color:#fff}.brand-mark{display:inline-grid;place-items:center;background:#8fd2c8;color:#12383c;border-radius:7px;width:30px;height:30px;margin-right:9px;font-weight:850}.rail-label{margin:31px 0 12px;color:#93b4b9;font-size:12px;font-weight:700;letter-spacing:.1em}.rail a{display:block;color:#d0e3e4;text-decoration:none;padding:8px 10px;border-radius:7px;font-size:14px}.rail a:hover{background:#20434e;color:white}.rail-note{margin-top:32px;padding-top:17px;border-top:1px solid #35515a;font-size:12px;color:#a9c2c5}
main{min-width:0;max-width:1440px;width:100%;margin:auto;padding:32px 42px 64px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;color:var(--muted);font-size:12px}.top strong{color:var(--teal);letter-spacing:.08em}.top span{overflow-wrap:anywhere}.hero{padding:34px 0 25px}.eyebrow{font-size:12px;font-weight:800;letter-spacing:.11em;color:var(--teal);text-transform:uppercase}h1{font-size:clamp(27px,3.2vw,42px);line-height:1.18;letter-spacing:-.035em;margin:10px 0 14px}.lead{font-size:16px;color:#425a64;max-width:850px;margin:0;overflow-wrap:anywhere}.badges{display:flex;flex-wrap:wrap;gap:9px;margin:20px 0 0}.badge{display:inline-flex;align-items:center;border:1px solid #c7dcdb;border-radius:5px;background:#e6f3f1;color:#245c59;font-size:12px;font-weight:750;padding:5px 9px}.badge.fail,.badge.simulated{background:#fff1eb;color:#983d2d;border-color:#f0c7b8}.badge.unknown{background:#fff7df;color:#7b5900;border-color:#ead99e}.badge.pass{background:#e6f3e9;color:#226947;border-color:#c1dfca}
.meta{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden}.meta>div{background:var(--paper);padding:15px 18px;min-width:0}.meta span,.label{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}.meta strong{font-size:14px;overflow-wrap:anywhere}.section{margin-top:24px;background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:24px;min-width:0}.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:18px}.section-head h2{margin:0;font-size:18px;letter-spacing:-.02em}.section-head span{color:var(--muted);font-size:12px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metric{background:#f6f9f9;border:1px solid #e6eeee;border-radius:8px;padding:15px;min-width:0}.metric strong{display:block;font-size:27px;line-height:1.1;color:var(--ink);overflow-wrap:anywhere}.metric small{display:block;font-size:12px;color:var(--muted);margin-top:8px}.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.check,.evidence{border:1px solid var(--line);border-radius:8px;padding:15px;min-width:0}.check-head,.evidence-head{display:flex;justify-content:space-between;align-items:start;gap:12px}.check h3,.evidence h3{font-size:15px;margin:0;overflow-wrap:anywhere}.evidence-list{display:grid;gap:11px}.detail{display:grid;grid-template-columns:105px minmax(0,1fr);gap:6px 12px;margin:13px 0 0;font-size:13px}.detail dt{color:var(--muted)}.detail dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}.empty{color:var(--muted);font-size:14px;margin:0}.bars{display:grid;gap:14px}.bar-row{display:grid;grid-template-columns:minmax(130px,220px) minmax(80px,1fr) 45px;gap:12px;align-items:center;font-size:13px}.bar-row span{overflow-wrap:anywhere}.bar-row strong{text-align:right;font-size:14px}meter{width:100%;height:10px;accent-color:var(--teal)}meter::-webkit-meter-bar{background:#e5eeee;border:0;border-radius:8px;height:8px}meter::-webkit-meter-optimum-value{background:#3a9188;border-radius:8px}meter::-moz-meter-bar{background:#3a9188;border-radius:8px}.grid-two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.box{background:#f6f9f9;border:1px solid #e5eeee;border-radius:8px;padding:17px;min-width:0}.box h3{font-size:14px;margin:0 0 10px}.box ul,.box ol,.plain-list{padding-left:20px;margin:0;color:#364f5a;font-size:14px}.box li,.plain-list li{margin:7px 0;overflow-wrap:anywhere}.files{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px;min-width:650px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #e8eeee}th{color:var(--muted);font-weight:650}td:first-child{font-weight:700}.foot{color:var(--muted);font-size:12px;margin-top:24px;line-height:1.7}
@media(max-width:850px){.layout{display:block}.rail{padding:17px 20px}.rail-label,.rail nav,.rail-note{display:none}main{padding:24px 20px 48px}.hero{padding:27px 0 20px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:500px){.top{display:block}.top span{display:block;margin-top:5px}.meta,.checks,.grid-two{grid-template-columns:1fr}.section{padding:18px}.bar-row{grid-template-columns:minmax(105px,1fr) minmax(65px,1fr) 30px;gap:8px}.detail{grid-template-columns:85px minmax(0,1fr)}}
"""

_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_HEADERS = re.compile(r"(?i)\b(?:authorization|cookie|set-cookie)\s*[:=][^\r\n]*")
_BEARER = re.compile(r"(?i)\bbearer\s+[^\s,;<>\"']+")
_SECRET = re.compile(r"(?i)\b(?:access[_-]?token|token|api[_-]?key|password|passwd|secret)\s*[:=]\s*[^\s,;<>\"']+")
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_QUERY = re.compile(r"\?[^\s<>\"']*")
_LOCAL_PATH = re.compile(r"(?i)(?:\b[a-z]:[\\/]|(?<![\w:/<])/(?!/))[^\s<>\"']+")
_EVIDENCE_LABELS = {
    "host": "主机", "port": "端口", "addresses": "解析地址", "address": "地址",
    "version": "版本", "certificate": "证书", "valid_from": "证书生效",
    "valid_until": "证书到期", "status_code": "状态码", "detail": "说明", "error_code": "错误码",
}


def _url_origin(match: re.Match[str]) -> str:
    try:
        if re.fullmatch(r"https?://\[已隐藏\](?::\d{1,5})?", match.group(), re.IGNORECASE):
            return match.group()
        parts = urlsplit(match.group())
        if not parts.hostname:
            return "[地址已隐藏]"
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        port = f":{parts.port}" if parts.port is not None else ""
        return f"{parts.scheme}://{host}{port}"
    except ValueError:
        return "[地址已隐藏]"


def _safe(value: object) -> str:
    text = _CONTROLS.sub("", _ANSI.sub("", str(value)))
    text = _HEADERS.sub("[敏感信息已隐藏]", text)
    text = _BEARER.sub("[敏感信息已隐藏]", text)
    text = _SECRET.sub("[敏感信息已隐藏]", text)
    text = _URL.sub(_url_origin, text)
    text = _QUERY.sub("?[已隐藏]", text)
    text = _LOCAL_PATH.sub("[本地路径已隐藏]", text)
    return html.escape(text, quote=True)


def _items(items: list[str], empty: str) -> str:
    if not items:
        return f'<p class="empty">{_safe(empty)}</p>'
    return '<ul class="plain-list">' + "".join(f"<li>{_safe(item)}</li>" for item in items) + "</ul>"


def _section(title: str, subtitle: str, content: str, section_id: str) -> str:
    return f'<section class="section" id="{section_id}"><div class="section-head"><h2>{title}</h2><span>{subtitle}</span></div>{content}</section>'


def _metrics(values: list[tuple[str, object]]) -> str:
    return '<div class="metrics">' + "".join(
        f'<div class="metric"><strong>{_safe(value)}</strong><small>{_safe(label)}</small></div>'
        for label, value in values
    ) + "</div>"


def _details(values: list[tuple[str, object]]) -> str:
    if not values:
        return '<p class="empty">暂无证据字段</p>'
    rows = "".join(f"<dt>{_safe(key)}</dt><dd>{_safe(value)}</dd>" for key, value in values)
    return f'<dl class="detail">{rows}</dl>'


def _explanations(report: Report | NginxReport) -> str:
    basis = report.confidence_basis if isinstance(report, NginxReport) else []
    boxes = (
        '<div class="grid-two"><div class="box"><h3>可能原因</h3>'
        + _items(report.possible_causes, "报告未提供可能原因。")
        + '</div><div class="box"><h3>证据依据</h3>'
        + _items(basis, "请结合上方检测结果和证据查看。") + "</div></div>"
    )
    result = _section("分析依据", "观察与推断", boxes, "analysis")
    result += _section("尚未确认", "需要进一步证据", _items(report.unconfirmed, "报告未列出待确认事项。"), "unknown")
    if report.suggestions:
        steps = '<ol class="plain-list">' + "".join(f"<li>{_safe(item)}</li>" for item in report.suggestions) + "</ol>"
    else:
        steps = '<p class="empty">报告未提供排查建议。</p>'
    return result + _section("排查建议", "按报告顺序", steps, "actions")


def _network(report: Report) -> tuple[str, str, str, str, str]:
    simulated = report.source == "simulated"
    source = "模拟数据" if simulated else "实际网络探测"
    badge = '<span class="badge simulated">SIMULATED / 模拟数据</span>' if simulated else '<span class="badge">LIVE / 实际探测</span>'
    statuses = [check.status for check in report.checks]
    if not statuses:
        status, style = "尚无检测结果", "unknown"
    elif "FAIL" in statuses:
        status, style = "存在失败检测", "fail"
    elif "UNKNOWN" in statuses:
        status, style = "部分检测未确认", "unknown"
    else:
        status, style = "检测已完成", "pass"
    badge += f'<span class="badge {style}">{status}</span>'
    cards = []
    for check in report.checks:
        status_class = {"PASS": "pass", "FAIL": "fail", "UNKNOWN": "unknown"}.get(check.status, "unknown")
        values = [(_EVIDENCE_LABELS.get(key, key), "、".join(str(item) for item in value) if isinstance(value, list) else value) for key, value in check.evidence.items()]
        cards.append(
            f'<article class="check"><div class="check-head"><h3>{_safe(check.name)}</h3>'
            f'<span class="badge {status_class}">{_safe(check.status)}</span></div>{_details(values)}</article>'
        )
    content = _section("检测与证据", "实际报告中的检测项", '<div class="checks">' + "".join(cards) + "</div>", "evidence")
    content += _explanations(report)
    content += _section("能力范围与限制", "报告解释", '<p class="empty">网络探测仅反映指定目标与端口的检测结果。服务端内部状态需要其他证据确认。</p>', "limits")
    return "网络诊断报告", source, badge, _safe(report.timestamp), content


_FAULT_NAMES = {
    "connection_refused": "上游连接拒绝",
    "upstream_timed_out": "上游超时",
    "prematurely_closed": "上游提前关闭",
    "no_live_upstreams": "无可用上游",
}


def _nginx(report: NginxReport) -> tuple[str, str, str, str, str]:
    badge = '<span class="badge">用户提供的日志</span>'
    badge += f'<span class="badge unknown">关联未确认 {_safe(report.unconfirmed_events)}</span>'
    badge += f'<span class="badge">置信度 {_safe(report.confidence)}</span>'
    count_basis = "旧版去重统计，可能少计" if report.schema_version == "1.0" else "按物理日志记录统计"
    content = _section("记录概览", count_basis, _metrics([
        ("总行数", report.total_lines), ("有效记录", report.valid_events),
        ("符合筛选", report.matched_events), ("不匹配", report.unmatched_events),
        ("关联未确认", report.unconfirmed_events), ("未识别行", report.unrecognized_lines),
    ]), "records")
    maximum = max(report.fault_counts.values(), default=0) or 1
    rows = []
    for kind, count in report.fault_counts.items():
        rows.append(
            f'<div class="bar-row"><span>{_safe(_FAULT_NAMES.get(kind, kind))}</span>'
            f'<meter min="0" max="{_safe(maximum)}" value="{_safe(count)}">{_safe(count)}</meter>'
            f'<strong>{_safe(count)}</strong></div>'
        )
    content += _section("故障类型", "符合筛选的记录", '<div class="bars">' + "".join(rows) + "</div>", "faults")
    if isinstance(report, NginxMultiReport):
        rows = []
        for file in report.files:
            counts = "、".join(f"{_FAULT_NAMES.get(kind, kind)} {count}" for kind, count in file.fault_counts.items())
            rows.append(
                f'<tr><td>{_safe(file.source_file)}</td><td>{_safe(file.total_lines)}</td>'
                f'<td>{_safe(file.valid_events)}</td><td>{_safe(file.matched_events)}</td>'
                f'<td>{_safe(file.unmatched_events)}</td><td>{_safe(file.unconfirmed_events)}</td>'
                f'<td>{_safe(file.unrecognized_lines)}</td><td>{_safe(counts)}</td></tr>'
            )
        table = '<div class="files"><table><thead><tr><th>来源</th><th>总行数</th><th>有效</th><th>匹配</th><th>不匹配</th><th>未确认</th><th>未识别</th><th>故障类型数量</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
        content += _section("文件统计", "按输入顺序", table, "files")
    cards = []
    for evidence in report.evidence:
        source = evidence.source_file if isinstance(evidence, NginxFileEvidence) else "单文件"
        values = [("日志时间", f"{evidence.timestamp}（时区未知）"), ("级别", evidence.severity),
                  ("请求方法", evidence.request_method or "未知"), ("请求路径", evidence.request_path or "未知"),
                  ("服务器", evidence.server or "未知"), ("上游", evidence.upstream or "未知")]
        cards.append(
            f'<article class="evidence"><div class="evidence-head"><h3>{_safe(evidence.observed)}</h3>'
            f'<span class="badge">{_safe(source)} · 第 {_safe(evidence.line)} 行</span></div>'
            f'{_details(values)}<p class="empty">关联状态 {_safe(evidence.correlation)}</p></article>'
        )
    samples = '<div class="evidence-list">' + "".join(cards) + "</div>" if cards else '<p class="empty">没有可展示的代表性证据。</p>'
    content += _section("代表性证据", "脱敏样本，数量有上限", samples, "evidence")
    content += _explanations(report)
    content += _section("能力范围与限制", "报告解释", '<p class="empty">原报告未记录分析时间。日志记录数不等于独立请求数，日志时间未提供时区，文件内容重叠时可能重复计算。</p>', "limits")
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return "Nginx 日志诊断报告", "用户提供的日志", badge, _safe(generated), content


def render_html(report: Report | NginxReport) -> str:
    """只使用转义后的报告字段生成完整 HTML 文档。"""
    if isinstance(report, NginxReport):
        title, source, badges, time_value, content = _nginx(report)
        time_label = "报告生成时间（UTC）"
        target = "本地日志 / 已脱敏"
    else:
        title, source, badges, time_value, content = _network(report)
        time_label = "分析时间"
        target = report.target
    digest = base64.b64encode(hashlib.sha256(_CSS.encode("utf-8")).digest()).decode("ascii")
    policy = f"default-src 'none'; style-src 'sha256-{digest}'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{html.escape(policy, quote=True)}">
<title>UpstreamLens · {_safe(title)}</title><style>{_CSS}</style></head>
<body><div class="layout"><aside class="rail"><div class="brand"><span class="brand-mark">U</span>UpstreamLens</div>
<div class="rail-label">报告导航</div><nav aria-label="报告导航"><a href="#overview">报告概览</a><a href="#evidence">检测与证据</a><a href="#analysis">分析依据</a><a href="#unknown">尚未确认</a><a href="#actions">排查建议</a><a href="#limits">能力范围</a></nav>
<div class="rail-note">离线诊断报告<br>基于已提供的证据生成</div></aside>
<main><div class="top"><strong>UPSTREAMLENS / DIAGNOSTIC REPORT</strong><span>独立文件 · 离线查看</span></div>
<header class="hero" id="overview"><div class="eyebrow">Evidence-based diagnostics</div><h1>{_safe(title)}</h1>
<p class="lead">{_safe(report.summary)}</p><div class="badges">{badges}</div></header>
<div class="meta"><div><span>{time_label}</span><strong>{time_value}</strong></div><div><span>数据来源</span><strong>{source}</strong></div><div><span>分析目标</span><strong>{_safe(target)}</strong></div></div>
{content}<footer class="foot">UpstreamLens · 此报告根据现有证据生成，具体原因需结合其他信息确认。</footer></main></div></body></html>'''
