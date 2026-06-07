from __future__ import annotations

import platform
import subprocess

from .models import CommandAction, CommandResult


class RemediationError(RuntimeError):
    pass


class CommandExecutor:
    def __init__(self, apply: bool = False, yes: bool = False) -> None:
        self.apply = apply
        self.yes = yes

    def execute(self, actions: list[CommandAction]) -> list[CommandResult]:
        if not self.apply:
            return [
                CommandResult(
                    action_id=action.action_id,
                    status="planned",
                    command=action.command,
                    note="dry-run mode; command was not executed",
                )
                for action in actions
            ]

        if platform.system().lower() != "linux":
            raise RemediationError("--apply is only supported on Linux hosts")
        if not self.yes:
            raise RemediationError("--apply requires --yes")

        results: list[CommandResult] = []
        for action in actions:
            if action.check_command:
                check = subprocess.run(
                    action.check_command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if check.returncode == 0:
                    results.append(
                        CommandResult(
                            action_id=action.action_id,
                            status="skipped",
                            command=action.command,
                            stdout=check.stdout,
                            stderr=check.stderr,
                            returncode=check.returncode,
                            note="already applied",
                        )
                    )
                    continue

            completed = subprocess.run(
                action.command,
                capture_output=True,
                text=True,
                check=False,
            )
            results.append(
                CommandResult(
                    action_id=action.action_id,
                    status="applied" if completed.returncode == 0 else "failed",
                    command=action.command,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    returncode=completed.returncode,
                )
            )
        return results

