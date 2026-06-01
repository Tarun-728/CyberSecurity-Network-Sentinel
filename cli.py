from __future__ import annotations

import argparse
import importlib.resources as resources
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from .accounts import AccountAuditor
from .firewall import FirewallPlanner, load_firewall_policy
from .logs import AuthLogAnalyzer
from .models import AnalysisBundle, CommandAction, CommandResult, TimelineEvent
from .permissions import (
    LiveMetadataProvider,
    PermissionAuditor,
    SnapshotMetadataProvider,
    load_permission_rules,
    load_snapshot,
)
from .remediation import CommandExecutor, RemediationError
from .reporter import write_json_report, write_markdown_report


def data_path(*parts: str) -> Path:
    return Path(str(resources.files("linux_sentinel.data").joinpath(*parts)))


def load_policy(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-sentinel",
        description="Linux hardening plus SOC auth.log incident timeline toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run full hardening and incident workflow")
    add_common_run_args(run)
    run.set_defaults(func=run_command)

    monitor = subparsers.add_parser("monitor", help="poll auth.log for brute-force attacks")
    monitor.add_argument("--auth-log", type=Path, default=Path("/var/log/auth.log"))
    monitor.add_argument("--policy", type=Path, default=data_path("default_policy.json"))
    monitor.add_argument("--threshold", type=int, default=3)
    monitor.add_argument("--window-minutes", type=int, default=10)
    monitor.add_argument("--interval", type=int, default=10)
    monitor.add_argument("--log-year", type=int, default=datetime.now().year)
    monitor.add_argument("--apply", action="store_true")
    monitor.add_argument("--yes", action="store_true")
    monitor.set_defaults(func=monitor_command)
    return parser


def add_common_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--demo", action="store_true", help="use bundled compromised sample data")
    parser.add_argument("--passwd", type=Path, default=Path("/etc/passwd"))
    parser.add_argument("--shadow", type=Path, default=Path("/etc/shadow"))
    parser.add_argument("--group", type=Path, default=Path("/etc/group"))
    parser.add_argument("--auth-log", type=Path, default=Path("/var/log/auth.log"))
    parser.add_argument("--fs-snapshot", type=Path, default=None)
    parser.add_argument("--policy", type=Path, default=data_path("default_policy.json"))
    parser.add_argument("--out", type=Path, default=Path("reports/incident_report.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/incident_report.json"))
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--log-year", type=int, default=datetime.now().year)
    parser.add_argument("--apply", action="store_true", help="execute automatic remediation")
    parser.add_argument("--yes", action="store_true", help="confirm apply mode")
    parser.add_argument(
        "--apply-users",
        action="store_true",
        help="include account lock actions during apply mode",
    )
    parser.add_argument("--no-firewall", action="store_true")
    parser.add_argument("--no-permissions", action="store_true")


def apply_demo_defaults(args: argparse.Namespace) -> None:
    if not args.demo:
        return
    args.passwd = data_path("samples", "etc", "passwd")
    args.shadow = data_path("samples", "etc", "shadow")
    args.group = data_path("samples", "etc", "group")
    args.auth_log = data_path("samples", "var", "log", "auth.log")
    args.fs_snapshot = data_path("samples", "fs_snapshot.json")
    args.policy = data_path("default_policy.json")


def run_command(args: argparse.Namespace) -> int:
    apply_demo_defaults(args)
    try:
        bundle = run_pipeline(args)
    except RemediationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    write_markdown_report(bundle, args.out)
    if args.json_out:
        write_json_report(bundle, args.json_out)

    print(f"Report written: {args.out}")
    if args.json_out:
        print(f"JSON written: {args.json_out}")
    print(
        "Summary: "
        f"{len(bundle.account_findings)} account findings, "
        f"{len(bundle.permission_findings)} permission findings, "
        f"{len(bundle.attack_findings)} brute-force IPs, "
        f"{len(bundle.command_results)} commands planned/applied"
    )
    return 0


def run_pipeline(args: argparse.Namespace) -> AnalysisBundle:
    policy = load_policy(args.policy)

    account_findings = AccountAuditor(
        passwd_path=args.passwd,
        shadow_path=args.shadow,
        group_path=args.group,
    ).audit()

    permission_findings = []
    if not args.no_permissions:
        rules = load_permission_rules(policy)
        if args.fs_snapshot:
            provider = SnapshotMetadataProvider(load_snapshot(args.fs_snapshot))
        else:
            provider = LiveMetadataProvider()
        permission_findings = PermissionAuditor(rules, provider).audit()

    attacks, timeline = AuthLogAnalyzer(
        args.auth_log,
        threshold=args.threshold,
        window_minutes=args.window_minutes,
        log_year=args.log_year,
    ).analyze()

    firewall_actions: list[CommandAction] = []
    if not args.no_firewall:
        planner = FirewallPlanner(load_firewall_policy(policy))
        firewall_actions.extend(planner.ufw_actions())
        firewall_actions.extend(
            planner.block_ip_actions([attack.source_ip for attack in attacks])
        )
        timeline.extend(
            TimelineEvent(
                timestamp=attack.last_seen,
                event_type="ip_block_planned",
                description=f"iptables block planned for {attack.source_ip}",
                source_ip=attack.source_ip,
                severity="high",
            )
            for attack in attacks
        )
        timeline.sort(key=lambda item: item.timestamp or datetime.min)

    actions_to_execute = collect_actions(
        account_findings=account_findings,
        permission_findings=permission_findings,
        firewall_actions=firewall_actions,
        include_user_actions=args.apply_users,
    )
    command_results = CommandExecutor(apply=args.apply, yes=args.yes).execute(actions_to_execute)

    return AnalysisBundle(
        account_findings=account_findings,
        permission_findings=permission_findings,
        firewall_actions=firewall_actions,
        attack_findings=attacks,
        timeline=timeline,
        command_results=command_results,
        inputs={
            "passwd": args.passwd,
            "shadow": args.shadow,
            "group": args.group,
            "auth_log": args.auth_log,
            "policy": args.policy,
            "fs_snapshot": args.fs_snapshot or "live filesystem",
            "threshold": args.threshold,
            "window_minutes": args.window_minutes,
            "mode": "apply" if args.apply else "dry-run",
        },
    )


def collect_actions(
    account_findings,
    permission_findings,
    firewall_actions: list[CommandAction],
    include_user_actions: bool = False,
) -> list[CommandAction]:
    actions: list[CommandAction] = []
    if include_user_actions:
        for finding in account_findings:
            actions.extend(finding.actions)
    for finding in permission_findings:
        actions.extend(action for action in finding.actions if action.automatic)
    actions.extend(action for action in firewall_actions if action.automatic)
    return actions


def monitor_command(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    planner = FirewallPlanner(load_firewall_policy(policy))
    executor = CommandExecutor(apply=args.apply, yes=args.yes)
    blocked_or_planned: set[str] = set()

    print(
        f"Live monitoring {args.auth_log}; alerting after "
        f"{args.threshold} failed SSH logins within {args.window_minutes} minutes. "
        "Press Ctrl+C to stop."
    )
    try:
        while True:
            attacks, _timeline = AuthLogAnalyzer(
                args.auth_log,
                threshold=args.threshold,
                window_minutes=args.window_minutes,
                log_year=args.log_year,
            ).analyze()
            new_attacks = [
                attack
                for attack in attacks
                if attack.source_ip not in blocked_or_planned
            ]
            if new_attacks:
                actions = planner.block_ip_actions(
                    [attack.source_ip for attack in new_attacks]
                )
                results: list[CommandResult] = executor.execute(actions)
                results_by_ip = {result.command[4]: result for result in results}
                for attack in new_attacks:
                    result = results_by_ip.get(attack.source_ip)
                    users = ", ".join(attack.usernames) if attack.usernames else "unknown"
                    print(
                        "\n[BRUTE FORCE DETECTED]\n"
                        "Alert: One brute-force attack detected after "
                        f"{attack.failure_count} wrong SSH password failures.\n"
                        f"Source IP: {attack.source_ip}\n"
                        f"Usernames tried: {users}\n"
                        f"First seen: {attack.first_seen or 'unknown'}\n"
                        f"Last seen: {attack.last_seen or 'unknown'}\n"
                        f"Response: {result.status if result else 'planned'} "
                        f"firewall block for {attack.source_ip}\n"
                    )
                    if result is None:
                        blocked_or_planned.add(attack.source_ip)
                        continue
                    blocked_or_planned.add(result.command[4])
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped monitoring")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
