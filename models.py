from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


Severity = str


@dataclass(frozen=True)
class CommandAction:
    """A remediation command that can be planned or executed."""

    action_id: str
    category: str
    description: str
    command: list[str]
    rationale: str
    severity: Severity = "medium"
    requires_root: bool = True
    automatic: bool = True
    check_command: list[str] | None = None


@dataclass
class CommandResult:
    action_id: str
    status: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    note: str = ""


@dataclass
class Finding:
    finding_id: str
    category: str
    title: str
    severity: Severity
    description: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    actions: list[CommandAction] = field(default_factory=list)


@dataclass
class TimelineEvent:
    timestamp: datetime | None
    event_type: str
    description: str
    source_ip: str | None = None
    username: str | None = None
    raw: str | None = None
    severity: Severity = "info"


@dataclass
class AttackFinding:
    source_ip: str
    first_seen: datetime | None
    last_seen: datetime | None
    failure_count: int
    usernames: list[str]
    sample_lines: list[str]
    severity: Severity = "high"
    blocked: bool = False


@dataclass
class AnalysisBundle:
    account_findings: list[Finding]
    permission_findings: list[Finding]
    firewall_actions: list[CommandAction]
    attack_findings: list[AttackFinding]
    timeline: list[TimelineEvent]
    command_results: list[CommandResult]
    inputs: dict[str, Any]

