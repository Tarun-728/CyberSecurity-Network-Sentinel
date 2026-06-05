from __future__ import annotations

import fnmatch
import glob
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .models import CommandAction, Finding


@dataclass(frozen=True)
class PermissionRule:
    path: str
    mode: str
    owner: str
    group: str
    glob_pattern: bool = False
    required: bool = True


@dataclass(frozen=True)
class FileMetadata:
    path: str
    exists: bool
    mode: str | None = None
    owner: str | None = None
    group: str | None = None


class MetadataProvider(Protocol):
    def resolve(self, rule: PermissionRule) -> list[FileMetadata]:
        ...


def normalize_mode(mode: str | int | None) -> str | None:
    if mode is None:
        return None
    if isinstance(mode, int):
        return f"{mode:04o}"
    return mode.strip().removeprefix("0o").zfill(4)


def load_permission_rules(policy: dict) -> list[PermissionRule]:
    rules: list[PermissionRule] = []
    for raw in policy.get("permission_rules", []):
        rules.append(
            PermissionRule(
                path=raw["path"],
                mode=normalize_mode(raw["mode"]) or "0000",
                owner=raw.get("owner", "root"),
                group=raw.get("group", "root"),
                glob_pattern=bool(raw.get("glob", False)),
                required=bool(raw.get("required", True)),
            )
        )
    return rules


def load_snapshot(path: Path) -> dict[str, FileMetadata]:
    data = json.loads(path.read_text(encoding="utf-8"))
    snapshot: dict[str, FileMetadata] = {}
    for raw in data.get("files", []):
        metadata = FileMetadata(
            path=raw["path"],
            exists=bool(raw.get("exists", True)),
            mode=normalize_mode(raw.get("mode")),
            owner=raw.get("owner"),
            group=raw.get("group"),
        )
        snapshot[metadata.path] = metadata
    return snapshot


def infer_home_user(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    if len(parts) >= 3 and parts[1] == "home" and parts[2]:
        return parts[2]
    return None


def resolve_expected_identity(value: str, path: str) -> str:
    if value == "{user}":
        return infer_home_user(path) or value
    return value


class SnapshotMetadataProvider:
    def __init__(self, snapshot: dict[str, FileMetadata]) -> None:
        self.snapshot = snapshot

    def resolve(self, rule: PermissionRule) -> list[FileMetadata]:
        if rule.glob_pattern:
            matches = [
                metadata
                for path, metadata in self.snapshot.items()
                if fnmatch.fnmatch(path, rule.path)
            ]
            if matches:
                return sorted(matches, key=lambda item: item.path)
            return [FileMetadata(path=rule.path, exists=False)]
        return [self.snapshot.get(rule.path, FileMetadata(path=rule.path, exists=False))]


class LiveMetadataProvider:
    def resolve(self, rule: PermissionRule) -> list[FileMetadata]:
        paths: list[str]
        if rule.glob_pattern:
            paths = sorted(glob.glob(rule.path))
            if not paths:
                return [FileMetadata(path=rule.path, exists=False)]
        else:
            paths = [rule.path]

        return [self._stat_path(path) for path in paths]

    def _stat_path(self, path: str) -> FileMetadata:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return FileMetadata(path=path, exists=False)

        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        owner = str(st.st_uid)
        group = str(st.st_gid)
        try:
            import pwd

            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            pass
        try:
            import grp

            group = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            pass
        return FileMetadata(path=path, exists=True, mode=mode, owner=owner, group=group)


class PermissionAuditor:
    def __init__(self, rules: list[PermissionRule], provider: MetadataProvider) -> None:
        self.rules = rules
        self.provider = provider

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            for metadata in self.provider.resolve(rule):
                finding = self._evaluate(rule, metadata)
                if finding:
                    findings.append(finding)
        return findings

    def _evaluate(
        self, rule: PermissionRule, metadata: FileMetadata
    ) -> Finding | None:
        expected_owner = resolve_expected_identity(rule.owner, metadata.path)
        expected_group = resolve_expected_identity(rule.group, metadata.path)

        if not metadata.exists:
            if not rule.required:
                return None
            return Finding(
                finding_id=f"perm.missing.{metadata.path}",
                category="permissions",
                title="Required security-sensitive path is missing",
                severity="low",
                description=f"Expected path {metadata.path!r} was not found.",
                evidence=[
                    f"expected mode={rule.mode} owner={expected_owner} group={expected_group}"
                ],
                recommendation="Confirm whether the package/service is installed.",
            )

        mismatches: list[str] = []
        actions: list[CommandAction] = []
        actual_mode = normalize_mode(metadata.mode)
        expected_mode = normalize_mode(rule.mode)

        if actual_mode != expected_mode:
            mismatches.append(f"mode {actual_mode} != {expected_mode}")
            actions.append(
                CommandAction(
                    action_id=f"chmod-{metadata.path}",
                    category="permissions",
                    description=f"Set {metadata.path} mode to {expected_mode}",
                    command=["chmod", expected_mode or rule.mode, metadata.path],
                    rationale="Restrictive file modes reduce credential and config exposure.",
                    severity="high",
                )
            )

        if metadata.owner != expected_owner or metadata.group != expected_group:
            mismatches.append(
                f"owner/group {metadata.owner}:{metadata.group} != "
                f"{expected_owner}:{expected_group}"
            )
            actions.append(
                CommandAction(
                    action_id=f"chown-{metadata.path}",
                    category="permissions",
                    description=(
                        f"Set {metadata.path} owner/group to "
                        f"{expected_owner}:{expected_group}"
                    ),
                    command=["chown", f"{expected_owner}:{expected_group}", metadata.path],
                    rationale="Sensitive files should be owned by expected privileged accounts.",
                    severity="high",
                )
            )

        if not mismatches:
            return None

        return Finding(
            finding_id=f"perm.mismatch.{metadata.path}",
            category="permissions",
            title="Security-sensitive path has weak ownership or permissions",
            severity="high",
            description=f"{metadata.path} does not match the hardening baseline.",
            evidence=[
                f"actual mode={actual_mode} owner={metadata.owner} group={metadata.group}",
                f"expected mode={expected_mode} owner={expected_owner} group={expected_group}",
                *mismatches,
            ],
            recommendation="Apply the generated chmod/chown remediation commands.",
            actions=actions,
        )
