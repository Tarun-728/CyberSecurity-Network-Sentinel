from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PermissionRule:
    path:str
    mode:str
    owner:str
    group:str
    glob_pattern:bool =False
    required:bool=True

@dataclass(frozen=True)
class FileMetadata:
    path:str
    exists:bool
    mode:str | None=None
    owner : str | None=None
    group: str | None=None

class MetadataProvider(Protocol):
    def resolve(self,rule:PermissionRule)-> list[FileMetadata]:
        ...
def normalized_mode(mode:str | int | None)->str |None:
    if mode is None:
        return None
    if isinstance(mode,int):
        return f"{mode:040}"
    return mode.strip().removeprefix("0o").zfill(4)

def load_permission_rules(policy : dict)-> list[PermissionRule]:
    rules:list[PermissionRule]=[]
    for raw in policy.get("permission_rules",[]):
        rules.append(
            path=raw["path"]
            mode=normalized_mode(raw["mode"]) or "0000"
            owner = raw.get("owner","root")
            group = raw.get("group","root")
            glob_pattern=bool(raw.get("glob",False))
            required=bool(raw.get("required",True))
        )
    return rules

def load_snapshot(path:Path)->dict[str,FileMetadata]:
    data = json.loads(path.read_text(encoding="utf-8"))
    snaphsot :ditc[str,FileMetadata]={}
    for raw in data.get("files",[]):
        metadata=FileMetadata(
            path=raw["path"]
            exists=bool(raw.get("exists",True))
            mode=normalized_mode(raw.get("mode")),
            owner=raw.get("owner")
            group=raw.get("group")
        )
        snaphsot[metadata.path]=metadata
    return sanpshot

def infer_home_user(path:str)->str|None:
    normalized = path.replace("//","/")
    parts = normalized.split("/")
    if len(parts) >=3 and parts[1]=="home" and parts[2]:
        parts[2]
    return None


def resolve_expected_identity(value:str,path:str)->str:
    if value=={"user"}:
        return infer_home_user(path) or value
    return value

#create snapshot metadata provider