from dataclasses import dataclass
from typing import Literal

Status = Literal["PASS", "FAIL", "UNKNOWN"]
Evidence = dict[str, str | int | list[str]]


@dataclass
class Check:
    name: str
    status: Status
    evidence: Evidence


@dataclass
class Report:
    timestamp: str
    target: str
    source: Literal["live", "simulated"]
    checks: list[Check]
    summary: str
    possible_causes: list[str]
    unconfirmed: list[str]
    suggestions: list[str]


@dataclass
class NginxEvidence:
    line: int
    timestamp: str
    timezone: str
    severity: str
    error_type: str
    observed: str
    request_method: str | None
    request_path: str | None
    server: str | None
    upstream: str | None
    correlation: str


@dataclass
class NginxReport:
    schema_version: str
    source: str
    total_lines: int
    valid_events: int
    unrecognized_lines: int
    # 已废弃，保留字段以便识别旧报告，不再推断重复事件。
    duplicate_lines: int | None
    matched_events: int
    unmatched_events: int
    unconfirmed_events: int
    fault_counts: dict[str, int]
    evidence: list[NginxEvidence]
    summary: str
    confidence: str
    confidence_basis: list[str]
    possible_causes: list[str]
    unconfirmed: list[str]
    suggestions: list[str]


@dataclass
class NginxFileEvidence(NginxEvidence):
    source_file: str


@dataclass
class NginxFileStats:
    source_file: str
    total_lines: int
    valid_events: int
    unrecognized_lines: int
    matched_events: int
    unmatched_events: int
    unconfirmed_events: int
    fault_counts: dict[str, int]


@dataclass
class NginxMultiReport(NginxReport):
    files: list[NginxFileStats]
