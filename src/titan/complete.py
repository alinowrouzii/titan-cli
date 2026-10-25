"""Bash completion for titan commands and ssh targets."""

from __future__ import annotations

from typing import Callable, List, Sequence

from titan.accesses import Access

COMMANDS = ("login", "logout", "ls", "ssh", "totp", "cred")
TOTP_COMMANDS = ("set", "delete")
CRED_COMMANDS = ("set", "default", "delete")
SSH_FLAGS = ("-L", "-R")

Loader = Callable[[], Sequence[Access]]


def bash_script() -> str:
    return """_titan_complete() {
  local line
  COMPREPLY=()
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    COMPREPLY+=("$line")
  done < <(titan completion candidates -- "$COMP_CWORD" "${COMP_WORDS[@]}" 2>/dev/null)
}
complete -F _titan_complete titan
"""


def candidates(words: Sequence[str], cword: int, load_rows: Loader) -> List[str]:
    if cword <= 0:
        return []
    if cword == 1:
        current = words[1] if len(words) > 1 else ""
        return _prefix(COMMANDS, current)
    command = words[1] if len(words) > 1 else ""
    if command == "ssh":
        return _ssh_candidates(words, cword, load_rows)
    if command == "totp" and cword == 2:
        current = words[2] if len(words) > 2 else ""
        return _prefix(TOTP_COMMANDS, current)
    if command == "cred" and cword == 2:
        current = words[2] if len(words) > 2 else ""
        return _prefix(CRED_COMMANDS, current)
    return []


def _ssh_candidates(words: Sequence[str], cword: int, load_rows: Loader) -> List[str]:
    current = words[cword] if cword < len(words) else ""
    before = list(words[2:cword])
    if current.startswith("-"):
        return _prefix(SSH_FLAGS, current)
    if before and before[-1] in SSH_FLAGS:
        return []
    if _target_present(before):
        return []
    return _prefix(_server_words(load_rows()), current)


def _target_present(before: Sequence[str]) -> bool:
    index = 0
    while index < len(before):
        token = before[index]
        if token in SSH_FLAGS:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return True
    return False


def _server_words(rows: Sequence[Access]) -> List[str]:
    seen = set()
    words: List[str] = []
    for access in rows:
        for word in (access.name, access.resource_name, access.resource_ip):
            if not word or word in seen:
                continue
            seen.add(word)
            words.append(word)
    return words


def _prefix(words: Sequence[str], prefix: str) -> List[str]:
    folded = prefix.casefold()
    return [word for word in words if word.casefold().startswith(folded)]
