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
