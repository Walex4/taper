"""HTTP adapter — credential injection on egress.

This is the crowded part of the market (Infisical Agent Vault/Proxy, Solo's
agentgateway, Alter, Authsome all do HTTP egress injection). It is included
because a developer should not have to install four tools, not because it is
where the differentiation is.

One thing done differently and worth keeping: the credential is attached to a
resolved (host, path) pair AFTER policy has approved it, so a policy bug cannot
result in the right credential going to the wrong host. The secret is referenced
by name in the plan and resolved at the last moment, which means plans are safe
to log verbatim.
"""

from __future__ import annotations

import posixpath
from urllib.parse import unquote

from .base import Adapter, ExecPlan


def normalize_path(path: str) -> str:
    """Resolve traversal BEFORE policy sees the path.

    `/v1/../../admin` starts with `/v1/` and therefore satisfies a
    `Prefix("/v1/")` constraint while actually addressing `/admin`. The red-team
    suite caught exactly this. Decode percent-encoding first, because `%2e%2e%2f`
    is the same attack wearing a hat, then normalize, then match.
    """
    decoded = unquote(unquote(path))          # twice: double-encoding is standard
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized.lstrip("./")
    # normpath collapses a trailing slash; keep it, since prefix rules care.
    if decoded.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    return normalized


class HTTPAdapter(Adapter):
    operation = "http.request"

    def __init__(self, credentials: dict[str, str] | None = None):
        # host -> secret ref. Explicit mapping; no wildcards, no fallback.
        self.credentials = credentials or {}

    def derive(self, request: dict) -> dict:
        return {
            "method": request["method"],
            "host": request["host"],
            # Policy always sees the NORMALIZED path, and so does the executor.
            "path": normalize_path(request["path"]),
        }

    def plan(self, request: dict, grant: dict) -> ExecPlan:
        host = request["host"]
        path = normalize_path(request["path"])
        ref = self.credentials.get(host)

        return ExecPlan(
            kind="http",
            secret_refs={"authorization": ref} if ref else {},
            detail={
                "method": request["method"],
                "url": f"https://{host}{path}",
                "has_body": "body" in request,
                # If no credential is mapped for this host the request still
                # proceeds unauthenticated rather than borrowing another host's
                # credential. Never fall back.
                "credential_bound_to_host": host if ref else None,
            },
        )
