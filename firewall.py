from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import CommandAction, Finding


@dataclass(frozen=True)
class FirewallPolicy:
    default_incoming: str
    default_outgoing: str
    allow_tcp_ports: list[int]
    enable_ufw: bool = True


def load_firewall_policy(policy: dict) -> FirewallPolicy:
    raw = policy.get("firewall", {})
    return FirewallPolicy(
        default_incoming=raw.get("default_incoming", "deny"),
        default_outgoing=raw.get("default_outgoing", "allow"),
        allow_tcp_ports=[int(port) for port in raw.get("allow_tcp_ports", [22])],
        enable_ufw=bool(raw.get("enable_ufw", True)),
    )


class FirewallPlanner:
    def __init__(self, policy: FirewallPolicy) -> None:
        self.policy = policy

    def ufw_actions(self) -> list[CommandAction]:
        actions = [
            CommandAction(
                action_id="ufw-default-incoming",
                category="firewall",
                description=f"Set UFW default incoming policy to {self.policy.default_incoming}",
                command=["ufw", "default", self.policy.default_incoming, "incoming"],
                rationale="Denying inbound traffic by default reduces exposed services.",
                severity="high",
            ),
            CommandAction(
                action_id="ufw-default-outgoing",
                category="firewall",
                description=f"Set UFW default outgoing policy to {self.policy.default_outgoing}",
                command=["ufw", "default", self.policy.default_outgoing, "outgoing"],
                rationale="Explicit outbound policy keeps host behavior predictable.",
                severity="medium",
            ),
        ]
        for port in self.policy.allow_tcp_ports:
            actions.append(
                CommandAction(
                    action_id=f"ufw-allow-{port}-tcp",
                    category="firewall",
                    description=f"Allow TCP/{port} through UFW",
                    command=["ufw", "allow", f"{port}/tcp"],
                    rationale="Allow only approved management and application ports.",
                    severity="medium",
                )
            )
        if self.policy.enable_ufw:
            actions.append(
                CommandAction(
                    action_id="ufw-enable",
                    category="firewall",
                    description="Enable UFW firewall",
                    command=["ufw", "--force", "enable"],
                    rationale="Firewall policy must be active to protect the host.",
                    severity="high",
                )
            )
        return actions

    def block_ip_actions(self, ips: list[str]) -> list[CommandAction]:
        actions: list[CommandAction] = []
        for ip in sorted(set(ips)):
            try:
                clean_ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            actions.append(
                CommandAction(
                    action_id=f"iptables-block-{clean_ip}",
                    category="firewall",
                    description=f"Block malicious source IP {clean_ip}",
                    command=["iptables", "-I", "INPUT", "-s", clean_ip, "-j", "DROP"],
                    check_command=["iptables", "-C", "INPUT", "-s", clean_ip, "-j", "DROP"],
                    rationale="Drop inbound traffic from source IPs actively brute-forcing SSH.",
                    severity="critical",
                )
            )
        return actions

    def firewall_baseline_finding(self) -> Finding:
        return Finding(
            finding_id="firewall.ufw.baseline",
            category="firewall",
            title="UFW firewall baseline should be enforced",
            severity="high",
            description="Host firewall should deny unexpected inbound access and allow approved ports only.",
            evidence=[
                f"default incoming={self.policy.default_incoming}",
                f"default outgoing={self.policy.default_outgoing}",
                "allowed tcp ports=" + ", ".join(map(str, self.policy.allow_tcp_ports)),
            ],
            recommendation="Apply the generated UFW commands after confirming required service ports.",
            actions=self.ufw_actions(),
        )

