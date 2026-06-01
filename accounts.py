from dataclasses import dataclass



#these are manually configurable files
LOGIN_SHELL_DENYLIST ={
    "/usr/sbin/noglin",
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
