from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import CommandAction, Finding


LOGIN_SHELL_DENYLIST = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "false",
    "nologin",
}


@dataclass(frozen=True)
class PasswdEntry:
    username: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str


@dataclass(frozen=True)
class ShadowEntry:
    username: str
    password_hash: str


@dataclass(frozen=True)
class GroupEntry:
    name: str
    gid: int
    members: list[str]


def is_login_shell(shell: str) -> bool:
    shell = shell.strip()
    if not shell:
        return False
    return shell not in LOGIN_SHELL_DENYLIST


def parse_passwd(text: str) -> list[PasswdEntry]:
    entries: list[PasswdEntry] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            raise ValueError(f"Invalid passwd line {line_no}: expected 7 fields")
        entries.append(
            PasswdEntry(
                username=parts[0],
                uid=int(parts[2]),
                gid=int(parts[3]),
                gecos=parts[4],
                home=parts[5],
                shell=parts[6],
            )
        )
    return entries


def parse_shadow(text: str) -> dict[str, ShadowEntry]:
    entries: dict[str, ShadowEntry] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            raise ValueError(f"Invalid shadow line {line_no}: expected fields")
        entries[parts[0]] = ShadowEntry(username=parts[0], password_hash=parts[1])
    return entries


def parse_group(text: str) -> dict[str, GroupEntry]:
    entries: dict[str, GroupEntry] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            raise ValueError(f"Invalid group line {line_no}: expected 4 fields")
        members = [member for member in parts[3].split(",") if member]
        entries[parts[0]] = GroupEntry(name=parts[0], gid=int(parts[2]), members=members)
    return entries


class AccountAuditor:
    def __init__(
        self,
        passwd_path: Path,
        shadow_path: Path | None = None,
        group_path: Path | None = None,
        allowed_uid0: set[str] | None = None,
        privileged_groups: tuple[str, ...] = ("sudo", "wheel"),
    ) -> None:
        self.passwd_path = passwd_path
        self.shadow_path = shadow_path
        self.group_path = group_path
        self.allowed_uid0 = allowed_uid0 or {"root"}
        self.privileged_groups = privileged_groups

    def audit(self) -> list[Finding]:
        passwd_entries = parse_passwd(self.passwd_path.read_text(encoding="utf-8"))
        shadow_entries: dict[str, ShadowEntry] = {}
        group_entries: dict[str, GroupEntry] = {}

        if self.shadow_path and self.shadow_path.exists():
            shadow_entries = parse_shadow(self.shadow_path.read_text(encoding="utf-8"))
        if self.group_path and self.group_path.exists():
            group_entries = parse_group(self.group_path.read_text(encoding="utf-8"))

        findings: list[Finding] = []
        findings.extend(self._audit_uid_zero(passwd_entries))
        findings.extend(self._audit_empty_passwords(passwd_entries, shadow_entries))
        findings.extend(self._audit_interactive_system_accounts(passwd_entries))
        findings.extend(self._audit_privileged_groups(group_entries))
        return findings

    def _audit_uid_zero(self, entries: list[PasswdEntry]) -> list[Finding]:
        findings: list[Finding] = []
        for entry in entries:
            if entry.uid == 0 and entry.username not in self.allowed_uid0:
                action = CommandAction(
                    action_id=f"lock-uid0-{entry.username}",
                    category="accounts",
                    description=f"Lock suspicious UID 0 account {entry.username}",
                    command=["passwd", "-l", entry.username],
                    rationale="Only root should have UID 0 on a hardened Linux host.",
                    severity="critical",
                    automatic=False,
                )
                findings.append(
                    Finding(
                        finding_id=f"acct.uid0.{entry.username}",
                        category="accounts",
                        title="Non-root account has UID 0",
                        severity="critical",
                        description=(
                            f"Account {entry.username!r} has UID 0 and therefore has "
                            "root-equivalent privileges."
                        ),
                        evidence=[
                            f"{entry.username}: uid={entry.uid}, gid={entry.gid}, "
                            f"home={entry.home}, shell={entry.shell}"
                        ],
                        recommendation=(
                            "Investigate immediately. Lock or remove the account after "
                            "confirming it is unauthorized."
                        ),
                        actions=[action],
                    )
                )
        return findings

    def _audit_empty_passwords(
        self, passwd_entries: list[PasswdEntry], shadow_entries: dict[str, ShadowEntry]
    ) -> list[Finding]:
        findings: list[Finding] = []
        passwd_by_name = {entry.username: entry for entry in passwd_entries}
        for username, shadow in shadow_entries.items():
            if shadow.password_hash != "":
                continue
            passwd_entry = passwd_by_name.get(username)
            action = CommandAction(
                action_id=f"lock-empty-password-{username}",
                category="accounts",
                description=f"Lock account with empty password: {username}",
                command=["passwd", "-l", username],
                rationale="Accounts with empty password hashes permit trivial compromise.",
                severity="critical",
                automatic=False,
            )
            evidence = [f"{username}: empty password hash in shadow"]
            if passwd_entry:
                evidence.append(f"shell={passwd_entry.shell}, home={passwd_entry.home}")
            findings.append(
                Finding(
                    finding_id=f"acct.empty_password.{username}",
                    category="accounts",
                    title="Account has empty password hash",
                    severity="critical",
                    description=(
                        f"Account {username!r} has an empty password hash in shadow data."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Lock the account and rotate credentials for any related service."
                    ),
                    actions=[action],
                )
            )
        return findings

    def _audit_interactive_system_accounts(
        self, entries: list[PasswdEntry]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for entry in entries:
            if entry.username == "root":
                continue
            if entry.uid < 1000 and is_login_shell(entry.shell):
                findings.append(
                    Finding(
                        finding_id=f"acct.system_shell.{entry.username}",
                        category="accounts",
                        title="System account has an interactive shell",
                        severity="medium",
                        description=(
                            f"System account {entry.username!r} has login shell "
                            f"{entry.shell!r}."
                        ),
                        evidence=[f"uid={entry.uid}, home={entry.home}, shell={entry.shell}"],
                        recommendation=(
                            "Set service accounts to /usr/sbin/nologin unless interactive "
                            "login is explicitly required."
                        ),
                    )
                )
        return findings

    def _audit_privileged_groups(
        self, group_entries: dict[str, GroupEntry]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for group_name in self.privileged_groups:
            group = group_entries.get(group_name)
            if not group or not group.members:
                continue
            findings.append(
                Finding(
                    finding_id=f"acct.privileged_group.{group_name}",
                    category="accounts",
                    title=f"Privileged group {group_name} has members",
                    severity="info",
                    description=(
                        f"Group {group_name!r} grants elevated privileges and should be "
                        "reviewed during incident response."
                    ),
                    evidence=[f"members={', '.join(group.members)}"],
                    recommendation=(
                        "Confirm each member has a current business need and rotate "
                        "credentials for administrators."
                    ),
                )
            )
        return findings

