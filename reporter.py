from __future__ import annotations

import json
import shlex
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import AnalysisBundle, AttackFinding, CommandAction, Finding, TimelineEvent


def format_time(value: datetime | None) -> str:
    if value is None:
        return "unknown time"
    return value.strftime("%Y-%m-%d %H:%M:%S")



def format_command(command: list[str]) -> str:
    return shlex.join(command)


class ReportRenderer:
    def __init__(self, bundle: AnalysisBundle) -> None:
        self.bundle = bundle

    def render_markdown(self) -> str:
        lines: list[str] = []
        account_count = len(self.bundle.account_findings)
        permission_count = len(self.bundle.permission_findings)
        attack_count = len(self.bundle.attack_findings)
        planned_count = len(self.bundle.command_results)

        lines.extend(
            [
                "# Combined System Hardening + Incident Timeline Report",
                "",
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "## Executive Summary",
                "",
                f"- Account findings: {account_count}",
                f"- Permission findings: {permission_count}",
                f"- Brute-force source IPs detected: {attack_count}",
                f"- Remediation commands planned/applied: {planned_count}",
                "",
            ]
        )

        lines.extend(self._inputs_section())
        lines.extend(self._findings_section("Account Audit", self.bundle.account_findings))
        lines.extend(
            self._findings_section("Permission Hardening", self.bundle.permission_findings)
        )
        lines.extend(self._attacks_section(self.bundle.attack_findings))
        lines.extend(self._firewall_section(self.bundle.firewall_actions))
        lines.extend(self._timeline_section(self.bundle.timeline))
        lines.extend(self._command_results_section())
        lines.extend(self._next_steps_section())
        return "\n".join(lines).rstrip() + "\n"

    def _inputs_section(self) -> list[str]:
        lines = ["## Inputs", ""]
        for key, value in self.bundle.inputs.items():
            lines.append(f"- {key}: `{value}`")
        lines.append("")
        return lines

    def _findings_section(self, title: str, findings: list[Finding]) -> list[str]:
        lines = [f"## {title}", ""]
        if not findings:
            lines.extend(["No findings.", ""])
            return lines

        for finding in findings:
            lines.extend(
                [
                    f"### [{finding.severity.upper()}] {finding.title}",
                    "",
                    finding.description,
                    "",
                ]
            )
            if finding.evidence:
                lines.append("Evidence:")
                for item in finding.evidence:
                    lines.append(f"- {item}")
                lines.append("")
            if finding.recommendation:
                lines.extend(["Recommendation:", f"- {finding.recommendation}", ""])
            if finding.actions:
                lines.append("Related commands:")
                for action in finding.actions:
                    lines.append(f"- `{format_command(action.command)}`")
                lines.append("")
        return lines

    def _attacks_section(self, attacks: list[AttackFinding]) -> list[str]:
        lines = ["## SOC Log Analysis: Brute-Force Detections", ""]
        if not attacks:
            lines.extend(["No brute-force activity crossed the configured threshold.", ""])
            return lines

        for attack in attacks:
            users = ", ".join(attack.usernames) if attack.usernames else "unknown"
            lines.extend(
                [
                    f"### [{attack.severity.upper()}] Source IP {attack.source_ip}",
                    "",
                    f"- First seen: {format_time(attack.first_seen)}",
                    f"- Last seen: {format_time(attack.last_seen)}",
                    f"- Failures in detection window: {attack.failure_count}",
                    f"- Usernames attempted: {users}",
                    "",
                    "Sample log lines:",
                ]
            )
            for raw in attack.sample_lines:
                lines.append(f"- `{raw}`")
            lines.append("")
        return lines

    def _firewall_section(self, actions: list[CommandAction]) -> list[str]:
        lines = ["## Firewall and IP Blocking Plan", ""]
        if not actions:
            lines.extend(["No firewall actions generated.", ""])
            return lines

        for action in actions:
            lines.append(f"- {action.description}: `{format_command(action.command)}`")
            if action.check_command:
                lines.append(f"  Check first: `{format_command(action.check_command)}`")
        lines.append("")
        return lines

    def _timeline_section(self, timeline: list[TimelineEvent]) -> list[str]:
        lines = ["## Incident Timeline", ""]
        if not timeline:
            lines.extend(["No auth events parsed.", ""])
            return lines

        lines.append("| Time | Severity | Event | Source | User |")
        lines.append("| --- | --- | --- | --- | --- |")
        for event in timeline:
            lines.append(
                "| "
                + " | ".join(
                    [
                        format_time(event.timestamp),
                        event.severity,
                        event.description.replace("|", "\\|"),
                        event.source_ip or "",
                        event.username or "",
                    ]
                )
                + " |"
            )
        lines.append("")
        return lines

    def _command_results_section(self) -> list[str]:
        lines = ["## Remediation Command Results", ""]
        if not self.bundle.command_results:
            lines.extend(["No commands were planned or executed.", ""])
            return lines

        lines.append("| Status | Action | Command | Note |")
        lines.append("| --- | --- | --- | --- |")
        for result in self.bundle.command_results:
            note = result.note or ""
            if result.returncode is not None:
                note = (note + f" returncode={result.returncode}").strip()
            lines.append(
                f"| {result.status} | {result.action_id} | "
                f"`{format_command(result.command)}` | {note} |"
            )
        lines.append("")
        return lines

    def _next_steps_section(self) -> list[str]:
        return [
            "## Recommended Next Steps",
            "",
            "- Review all UID 0 and empty-password account findings before unlocking any service.",
            "- Preserve auth logs and relevant shell history for forensic retention.",
            "- Rotate credentials for administrator and SSH users.",
            "- Confirm the UFW allow-list matches required production services.",
            "- Persist iptables blocks with the host's approved firewall persistence method.",
            "- Re-run this tool after remediation to confirm findings are cleared.",
            "",
        ]


def write_markdown_report(bundle: AnalysisBundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ReportRenderer(bundle).render_markdown(), encoding="utf-8")


def write_json_report(bundle: AnalysisBundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = asdict(bundle)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

