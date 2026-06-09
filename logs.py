from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .models import AttackFinding, TimelineEvent


IP_PATTERN = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})"
FAILED_RE = re.compile(
    rf"Failed password for (?:invalid user )?(?P<user>[^\s]+) from {IP_PATTERN}"
)
INVALID_RE = re.compile(rf"Invalid user (?P<user>[^\s]+) from {IP_PATTERN}")
ACCEPTED_RE = re.compile(
    rf"Accepted \S+ for (?P<user>[^\s]+) from {IP_PATTERN}"
)
PAM_FAILURE_RE = re.compile(
    rf"authentication failure;.*rhost={IP_PATTERN}(?:.*user=(?P<user>[^\s]+))?"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime | None
    event_type: str
    source_ip: str | None
    username: str | None
    raw: str


def valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip("[];,.")
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def parse_syslog_timestamp(line: str, year: int | None = None) -> datetime | None:
    parts = line.split(maxsplit=3)
    if len(parts) < 3:
        return None
    stamp = " ".join(parts[:3])
    parse_year = year or datetime.now().year
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(stamp, fmt)
            return parsed.replace(year=parse_year)
        except ValueError:
            continue
    return None


class AuthLogAnalyzer:
    def __init__(
        self,
        auth_log_path: Path,
        threshold: int = 5,
        window_minutes: int = 10,
        log_year: int | None = None,
    ) -> None:
        self.auth_log_path = auth_log_path
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.log_year = log_year

    def analyze(self) -> tuple[list[AttackFinding], list[TimelineEvent]]:
        events = self.parse_events()
        attacks = self.detect_brute_force(events)
        timeline = self.build_timeline(events, attacks)
        return attacks, timeline

    def parse_events(self) -> list[AuthEvent]:
        events: list[AuthEvent] = []
        if not self.auth_log_path.exists():
            return events

        for raw_line in self.auth_log_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            event = self.parse_line(raw_line)
            if event:
                events.append(event)
        return events

    def parse_line(self, raw_line: str) -> AuthEvent | None:
        timestamp = parse_syslog_timestamp(raw_line, self.log_year)

        for event_type, pattern in (
            ("failed_password", FAILED_RE),
            ("invalid_user", INVALID_RE),
            ("accepted_login", ACCEPTED_RE),
            ("pam_failure", PAM_FAILURE_RE),
        ):
            match = pattern.search(raw_line)
            if not match:
                continue
            ip = valid_ip(match.groupdict().get("ip"))
            if not ip:
                continue
            user = match.groupdict().get("user")
            return AuthEvent(
                timestamp=timestamp,
                event_type=event_type,
                source_ip=ip,
                username=user,
                raw=raw_line,
            )
        return None

    def detect_brute_force(self, events: list[AuthEvent]) -> list[AttackFinding]:
        failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.event_type in {"failed_password", "invalid_user", "pam_failure"}:
                if event.source_ip:
                    failures_by_ip[event.source_ip].append(event)

        attacks: list[AttackFinding] = []
        for ip, failures in failures_by_ip.items():
            failures.sort(key=lambda item: item.timestamp or datetime.min)
            if len(failures) < self.threshold:
                continue

            window_events = self._largest_failure_window(failures)
            if len(window_events) < self.threshold:
                continue

            usernames = sorted(
                {event.username for event in window_events if event.username}
            )
            attacks.append(
                AttackFinding(
                    source_ip=ip,
                    first_seen=window_events[0].timestamp,
                    last_seen=window_events[-1].timestamp,
                    failure_count=len(window_events),
                    usernames=usernames,
                    sample_lines=[event.raw for event in window_events[:5]],
                    severity="critical" if len(window_events) >= self.threshold * 2 else "high",
                )
            )

        return sorted(
            attacks,
            key=lambda attack: (
                attack.last_seen or datetime.min,
                attack.failure_count,
            ),
            reverse=True,
        )

    def _largest_failure_window(self, failures: list[AuthEvent]) -> list[AuthEvent]:
        if any(event.timestamp is None for event in failures):
            return failures

        best: list[AuthEvent] = []
        window: deque[AuthEvent] = deque()
        for event in failures:
            window.append(event)
            while window and event.timestamp and window[0].timestamp:
                if event.timestamp - window[0].timestamp <= self.window:
                    break
                window.popleft()
            if len(window) > len(best):
                best = list(window)
        return best

    def build_timeline(
        self, events: list[AuthEvent], attacks: list[AttackFinding]
    ) -> list[TimelineEvent]:
        timeline: list[TimelineEvent] = []
        for event in events:
            if event.event_type == "accepted_login":
                severity = "medium"
                description = (
                    f"Accepted SSH login for {event.username} from {event.source_ip}"
                )
            elif event.event_type == "invalid_user":
                severity = "medium"
                description = (
                    f"Invalid SSH username {event.username} attempted from {event.source_ip}"
                )
            else:
                severity = "low"
                description = (
                    f"SSH authentication failure for {event.username or 'unknown'} "
                    f"from {event.source_ip}"
                )
            timeline.append(
                TimelineEvent(
                    timestamp=event.timestamp,
                    event_type=event.event_type,
                    description=description,
                    source_ip=event.source_ip,
                    username=event.username,
                    raw=event.raw,
                    severity=severity,
                )
            )

        for attack in attacks:
            timeline.append(
                TimelineEvent(
                    timestamp=attack.last_seen,
                    event_type="brute_force_detected",
                    description=(
                        f"Brute-force threshold crossed by {attack.source_ip}: "
                        f"{attack.failure_count} failures"
                    ),
                    source_ip=attack.source_ip,
                    severity=attack.severity,
                )
            )

        return sorted(timeline, key=lambda item: item.timestamp or datetime.min)

