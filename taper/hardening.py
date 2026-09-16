"""Configuration the agent can write is not configuration.

DESIGN.md §9 listed it as a deployment gap: the policy file and, since
v0.3.0, the declared-operations directory sat in the repository, owned by
whoever checked it out - which on a laptop is the same user the agent runs
as. Inert while minting needs the root key, but a grant minted from a
policy the agent edited is a grant the agent wrote, and a declaration the
agent edited is refused by the broker only *after* the grant was minted
against it. The correct home was always `/etc/taper`, root-owned; this
module makes the broker and the mint refuse anything else.

The rule, for a policy file, an ops directory and every file in it: not a
symlink, not writable by group or world, and not owned by a uid the agent
runs as. The agent's uids are whatever `taper broker --allow-uid/--allow-user`
names, or `taper doctor --agent-user`; where no agent is named - `taper
grant` on a laptop - the mode checks still apply, and ownership is the
operator's to get right, which `doctor` will say.

`--allow-writable-config` turns a refusal into a warning, for a checkout on
a laptop. It prints every time. There is no environment variable for it,
so a unit file cannot set it quietly.

verified-by: tests/test_integration.py::TestConfigOwnership::test_a_world_writable_policy_is_refused_at_mint
verified-by: tests/test_integration.py::TestConfigOwnership::test_an_ops_directory_the_agent_owns_stops_the_broker
verified-by: tests/test_integration.py::TestConfigOwnership::test_root_owned_read_only_configuration_passes
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Optional


class WritableConfig(Exception):
    """The path can be changed by a uid that must not change it."""


def _describe(path: Path, st: os.stat_result) -> str:
    return f"{path} (owner uid {st.st_uid}, mode {stat.filemode(st.st_mode)})"


def check_path(path: Path, agent_uids: Optional[Iterable[int]] = None) -> list[str]:
    """Reasons `path` is agent-writable, or an empty list. One path only."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return []
    reasons = []
    if stat.S_ISLNK(st.st_mode):
        reasons.append(f"{path} is a symlink; configuration is a real file or directory")
        return reasons
    if st.st_mode & stat.S_IWOTH:
        reasons.append(f"{_describe(path, st)} is world-writable")
    if st.st_mode & stat.S_IWGRP and st.st_gid != 0:
        reasons.append(f"{_describe(path, st)} is group-writable")
    agents = set(agent_uids or ())
    if st.st_uid in agents and st.st_uid != 0:
        reasons.append(f"{_describe(path, st)} is owned by the agent's uid; it belongs "
                       f"to root under /etc/taper")
    return reasons


def check_tree(root: Path, agent_uids: Optional[Iterable[int]] = None) -> list[str]:
    """`check_path` on a directory, its parent (a writable parent is a
    renameable directory), and every file directly in it."""
    reasons = check_path(root, agent_uids)
    if root.is_dir():
        reasons += [r for r in check_path(root.parent, agent_uids) if "world-writable" in r]
        for child in sorted(root.iterdir()):
            reasons += check_path(child, agent_uids)
    return reasons


def require(paths: Iterable[Path], agent_uids: Optional[Iterable[int]], *,
            allow_writable: bool, what: str, warn) -> None:
    """Refuse (raise WritableConfig) or, with allow_writable, warn loudly."""
    reasons: list[str] = []
    for p in paths:
        p = Path(p)
        reasons += check_tree(p, agent_uids) if p.is_dir() else check_path(p, agent_uids)
    if not reasons:
        return
    text = "\n  ".join(reasons)
    if allow_writable:
        warn(f"{what} is writable by the agent (--allow-writable-config given, "
             f"continuing):\n  {text}")
        return
    raise WritableConfig(
        f"{what} is writable by the agent, and a grant minted from configuration the "
        f"agent can edit is a grant the agent wrote. Move it to /etc/taper, root-owned, "
        f"mode 0644 (files) / 0755 (directories); or pass --allow-writable-config on a "
        f"development checkout.\n  {text}")
