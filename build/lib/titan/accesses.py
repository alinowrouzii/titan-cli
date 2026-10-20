"""SSH access rows and name matching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class Access:
    id: str
    name: str
    resource_name: str
    resource_ip: str


def resolve(accesses: Iterable[Access], arg: str) -> List[Access]:
    folded = arg.casefold()
    hits: List[Access] = []
    for access in accesses:
        if (
            access.id == arg
            or access.name.casefold() == folded
            or access.resource_name.casefold() == folded
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
