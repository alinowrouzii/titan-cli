"""SSH access rows and name or IP matching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class Access:
    id: str
    name: str
    resource_name: str
    resource_ip: str


def _ip_tail(resource_ip: str, arg: str) -> bool:
    ip_parts = resource_ip.split(".")
    arg_parts = arg.split(".")
    if not arg_parts or len(arg_parts) > len(ip_parts):
        return False
    if any(not part.isdigit() for part in arg_parts):
        return False
    return ip_parts[-len(arg_parts) :] == arg_parts


def resolve(accesses: Iterable[Access], arg: str) -> List[Access]:
    folded = arg.casefold()
    hits: List[Access] = []
    for access in accesses:
        if (
            access.id == arg
            or access.name.casefold() == folded
            or access.resource_name.casefold() == folded
            or _ip_tail(access.resource_ip, arg)
        ):
            hits.append(access)
    return hits


def format_row(access: Access) -> str:
    return "%s\t%s\t%s\t%s" % (
        access.resource_name,
        access.name,
        access.resource_ip,
        access.id,
    )
