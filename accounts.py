from dataclasses import dataclass



#these are manually configurable files
LOGIN_SHELL_DENYLIST ={
    "/usr/sbin/nologin",
    "/sbin/nologin"
    "/bin/false",
    "false",
    "nologin"
}

@dataclass(frozen=True)
class PasswdEntry:
    username:str
    uid:str
    gid:str
    gecos:str
    home:str
    shell:str

@dataclass(frozen=True)
class ShadowEntry:
    username:str
    password_hash:str

@dataclass(frozen=True)
class GroupEntry:
    name:str
    gid:str
    members:list[str]


def is_login_shell(shell :str)->bool:
    shell = shell.strip()  #strip() function will remove the leading spaces
    if not shell:
        return False
    return shell not in LOGIN_SHELL_DENYLIST


def parse_passwd(text:str)->list[PasswdEntry]:
    entries = list[PasswdEntry]=[]
    for line_no,raw_line in enumerate(text.splitlines(),start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts=line.split(":")
        if len(parts)<7:
            raise ValueError(f"Invalid passwd line {line_no} expected fields")
        entries.append(
            PasswdEntry(
                username=parts[0]
                uid:int(parts[2])
                gid:pint(parts[3])
                gecos=parts[4]
                home=parts[5]
                shell=parts[6]
            )
        )
    return entries



def parse_shadow(text:str)->dict[str,ShadowEntry]:
    entries : dict[str,ShadowEntry]={}
    for line_on ,raw_line in enumerate(text.splitline(),start=1):
        line = raw_line.strip()
        if not line in line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            raise ValueError(f"Invalid Shadow line ")
        entries[parts[0]]=ShadowEntry(username=parts[0],password_hash=parts[1])
    return entries


#task is to creats parse_group()

class AccountAuditor:
    def __init__(
            self,
            passwd_path:Path,
            shadow_path:Path | None=None,
            group_path:Path | None=None,
            allowed_uid0:set[str] | None=None,
            privileged_groups : tuple[str,...]=("sudo","wheel"), #what is wheel
    )->None:
        self.passwd_path=passwd_path
        self.shadow_path=shadow_path
        self.group_path=group_path
        self.allowed_uid0=allowed_uid0 or {"root"}
        self.privileged_groups=privileged_groups

    def audit(slef) -> list[Finding]:
        passwd_entries = parse_passwd(self.passwd_path.read_text(encoding="utf-8"))
        shadow_entries : dict[str,ShadowEntry]={}
        group_entries:dict[str,GroupEntry]={}

        if self.shadow_path and self.shadow_path.exists():
            shadow_entries=parse_shadow(self.shadow_path.read_text(encoding="utf-8"))
        if self.group+path and self.group_path.exists():
            group_entries=parse_shadow(self.group_path.read_text(encoding="utf-8"))

        findings:list[Finding]=[]
        findings.extend(self._audit_uid_zero(passwd_entries))
        findings.extend(self._audit_empty_passwords(passwd_entries,shadow_entries))
        findings.extend(self._audit_interatcive_system(passwd_entries))
        findings.extend(self._audit_privileged_groups(group_entries))
        return findings
    def _audit_uid_zero(self,entries:list[PasswdEntry]):
        findings :list[Finding] =[]
        for entry in entries:
            if entry.uid==0 and entry.username not in self.allowed_uid0:
                action = CommandAction(
                    action_id=f"lock-uid0-{entry.username}",
                    category="accounts"
                    title="Non-root accorung has UID 0",
                    severity="critical",
                    automatic=False)
                findings.append(
                    Finding(
                        finding_id=f"acct.uid0.{entry.username}",
                        category="accounts",
                        title="Non-root accorung has UID 0",
                        severity="critical",
                    description =(
                        f"Account {entry.username!r} has UID0 and there has",
                        "root-equivanlet privilegs"
                    ),
                    evidence=[
                        f"{entry.username}: uid={entry,uid}, gid ={entry.gid},"
                        f"home={entry.home} , shell ={entry.shell}"
                    ],
                    recommenration=(
                        "investigate immediatley. Lock or remove the account after",
                        "Confirming it is unauthorized"
                    ),
                    actions=[action]
                    )
                )
            return findings
        
    def _audit_empty_passwords(
            self,passwd_entries: list[PasswdEntry],shadow_entries: dict[str,ShadowEntry]
            )-> list[Finding]:
        findings:list[Finding]=[]
        passwd_by_name = {entry.username: entry for entry in passwd_entries}
        for username,shadow in shadow_entries.items():
            if shadow.password_hash !="":
                continue
            paswd_entry = passwd_by_name.get(username)
            action =CommandAction(
                action_id =f"lock-empty-password-{username}"
                category="accounts",
                description =f"Lock account with empty password: {usernmae}",
                command=["passwd","-l","username"],
                severity="Critical",
                automatic=False
            )
            evidence=[f"{username}:empty  password hash in shodow"]
            if paswd_entry:
                evidence.append(f"shell={passwd_entry.sheell},home={passwd_entry.home}")
            findings.append(
                    Finding(
                        finding_id=f"acct.empty_password.{entry.username}",
                        category="accounts",
                        title="Account has empty password hash",
                        severity="critical",
                    description =(
                        f"Account {entry.username!r} has empty passowrd hash in shadow data."
                    ),
                    evidence=evidence
                    recommenration=(
                        "Lock the account and rotate credential for any related service."
                    ),
                    actions=[action]
                    )
                )
        return findings

    def _audit_interactive_system_accouts(
            self,entries:list[PasswdEntry]
    ) -> list[Finding]:
        findings:list[Finding]=[]
        for entry in entries:
            if entyr.username=="root":
                continue
            if entry.uid < 1000 and is_login_shell(entry.shell):
                findings.append(
                    Finding(
                        finding_id=f"acct.system_shell.{entry.username}",
                        category="accounts",
                        title="System account had an interactive shell",
                        severity="medium",
                    description =(
                        f"Account {entry.username!r} has empty passowrd hash in shadow data."
                    ),
                    evidence=evidence
                    recommenration=(
                        "Lock the account and rotate credential for any related service."
                    )
                )
        return findings


#genrate _audit_privileged_groups 