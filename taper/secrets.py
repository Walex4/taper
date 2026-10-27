"""Secret providers.

The broker resolves a secret reference to a value at the last possible moment,
after the decision is made and immediately before execution. Plans carry
references, never values, which is what makes plans safe to log verbatim.

Ordering matters in `ChainProvider`: the first provider that has the reference
wins, so put the most secure store first and the development fallback last.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, Protocol


class SecretNotFound(KeyError):
    """A secret reference could not be resolved to a value.

    Carries the bare `ref` separately from the message. The message names vault
    paths and is for the operator's own log; the ref is the only part safe to
    put on the wire. `reason` is what a caller may be told: the agent already
    knows the reference name — it is in the policy it was granted — so naming
    it discloses nothing and turns an afternoon of tracing into a one-line fix.
    """

    prefix = "secret not provisioned"

    def __init__(self, message: str, ref: str | None = None):
        super().__init__(message)
        self.ref = ref

    @property
    def reason(self) -> str:
        return f"{self.prefix}: {self.ref}" if self.ref else self.prefix


class SecretUnreadable(SecretNotFound):
    """The secret exists but cannot be used — wrong mode, unreadable file.

    Distinct from missing: telling an operator a secret is "not provisioned"
    when it is sitting there at mode 644 sends them to the wrong fix.
    """

    prefix = "secret unusable"


# `<ref>.oauth2` in the vault configures an exchange for `<ref>`.
EXCHANGE_SUFFIX = ".oauth2"
EXCHANGE_SKEW = 120.0
EXCHANGE_GRANTS = ("refresh_token", "client_credentials")


def _exchange_config(ref: str, text: str) -> dict:
    """Parse and check `<ref>.oauth2`. Refused rather than guessed at: an
    issuer that is not HTTPS would receive a client secret in clear."""
    try:
        config = json.loads(text)
    except ValueError:
        raise SecretUnreadable(f"{ref}{EXCHANGE_SUFFIX} is not JSON", ref=ref) from None
    if not isinstance(config, dict):
        raise SecretUnreadable(f"{ref}{EXCHANGE_SUFFIX} is not a JSON object", ref=ref)
    url = config.get("token_url")
    parsed = urlparse(url) if isinstance(url, str) else None
    if parsed is None or parsed.scheme != "https" or not parsed.hostname:
        raise SecretUnreadable(f"{ref}{EXCHANGE_SUFFIX}: token_url must be an https URL",
                               ref=ref)
    grant = config.get("grant_type", "refresh_token")
    if grant not in EXCHANGE_GRANTS:
        raise SecretUnreadable(f"{ref}{EXCHANGE_SUFFIX}: grant_type is one of "
                               f"{', '.join(EXCHANGE_GRANTS)}", ref=ref)
    needed = ["client_id", "client_secret"] + (["refresh_token"] if grant == "refresh_token" else [])
    missing = [k for k in needed if not isinstance(config.get(k), str) or not config[k]]
    if missing:
        raise SecretUnreadable(f"{ref}{EXCHANGE_SUFFIX} lacks {', '.join(missing)}", ref=ref)
    if config.get("style", "form") not in ("form", "json"):
        raise SecretUnreadable(f"{ref}{EXCHANGE_SUFFIX}: style is form or json", ref=ref)
    config["grant_type"] = grant
    return config


def _https_post(url: str, fields: dict, style: str) -> tuple[int, str]:
    """POST a token request. No redirect is followed: a Location header would
    otherwise receive the client secret on a second request."""
    import urllib.error
    import urllib.parse
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    if style == "json":
        data, ctype = json.dumps(fields).encode(), "application/json"
    else:
        data, ctype = urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": ctype,
                                              "Accept": "application/json",
                                              "User-Agent": "taper/0.1"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536).decode("utf-8", "replace")


class Provider(Protocol):
    def get(self, ref: str) -> Optional[str]: ...


class EnvProvider:
    """Development only. `ssh.identity` -> TAPER_SSH_IDENTITY.

    Deliberately noisy about being insecure: environment variables are visible
    in /proc on Linux and inherited by every child process, which is precisely
    the exposure this project exists to remove.
    """

    def __init__(self, prefix: str = "TAPER_"):
        self.prefix = prefix

    def _name(self, ref: str) -> str:
        return self.prefix + ref.upper().replace(".", "_").replace("-", "_")

    def get(self, ref: str) -> Optional[str]:
        return os.environ.get(self._name(ref))


class FileProvider:
    """One file per secret under a 0700 directory. Good enough for a laptop.

    Refuses to read a secret whose file is group- or world-readable, because a
    mode-644 private key is the failure this whole design is meant to prevent.
    """

    def __init__(self, directory: str | Path = "~/.taper/secrets"):
        self.dir = Path(str(directory)).expanduser()

    def get(self, ref: str) -> Optional[str]:
        # Reference names are used as filenames — reject anything that could
        # escape the directory before touching the filesystem.
        if "/" in ref or ".." in ref or ref.startswith("."):
            raise SecretNotFound(f"unsafe secret reference: {ref!r}", ref=ref)
        path = self.dir / ref
        if not path.is_file():
            return None
        mode = path.stat().st_mode & 0o077
        if mode:
            raise SecretUnreadable(
                f"{path} is readable by others (mode {oct(path.stat().st_mode & 0o777)}); "
                f"run: chmod 600 {path}",
                ref=ref,
            )
        return path.read_text().strip()


class KeychainProvider:
    """macOS Keychain / Linux secret-tool. The right answer on a real machine.

    Shells out to the platform tool with an argv array — never a string, and
    never a shell, for the same reason the adapters don't.
    """

    def __init__(self, service: str = "taper"):
        self.service = service

    def get(self, ref: str) -> Optional[str]:
        import shutil

        if shutil.which("security"):                      # macOS
            argv = ["security", "find-generic-password",
                    "-s", self.service, "-a", ref, "-w"]
        elif shutil.which("secret-tool"):                 # freedesktop
            argv = ["secret-tool", "lookup", "service", self.service, "account", ref]
        else:
            return None

        result = subprocess.run(argv, capture_output=True, text=True, shell=False)
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None


class ChainProvider:
    def __init__(self, *providers: Provider, clock=time.time, post=None):
        self.providers = providers
        self.clock = clock
        # How a token exchange reaches the issuer. Injected for tests; the
        # default is a plain HTTPS POST that follows no redirect.
        self._post = post or _https_post
        self._minted: dict[str, tuple[str, float]] = {}

    def get(self, ref: str) -> Optional[str]:
        for provider in self.providers:
            value = provider.get(ref)
            if value is not None:
                return value
        return None

    def has(self, ref: str) -> bool:
        """Whether `ref` can be resolved, without resolving it: a stored
        value, or an exchange configured for it. Never contacts an issuer,
        so `taper doctor` can ask it."""
        return self.get(ref) is not None or self.get(ref + EXCHANGE_SUFFIX) is not None

    def require(self, ref: str) -> str:
        value = self.get(ref)
        if value is None:
            exchange = self.get(ref + EXCHANGE_SUFFIX)
            if exchange is not None:
                return self._exchange(ref, exchange)
            raise SecretNotFound(
                f"no secret for {ref!r}; add it with "
                f"`taper secret set {ref}` or place it in ~/.taper/secrets/{ref}",
                ref=ref,
            )
        return value

    def _exchange(self, ref: str, config_text: str) -> str:
        """A short-lived access token, minted from what the vault holds.

        Some services issue no long-lived credential worth storing: Google
        hands out hour-long access tokens against a refresh token, a Shopify
        app gets a day-long token from its client credentials. The vault
        holds `<ref>.oauth2` - the issuer, the grant and its secrets - and the
        token is minted here, in the broker's process, at the moment of use,
        and cached until shortly before it expires. The agent never sees
        either half; the plan names `<ref>`, as it would a stored secret.

        verified-by: tests/test_taper.py::TestTokenExchange::test_a_refresh_grant_is_exchanged_once_and_cached
        verified-by: tests/test_taper.py::TestTokenExchange::test_an_exchange_config_must_name_an_https_issuer
        """
        now = self.clock()
        cached = self._minted.get(ref)
        if cached is not None and cached[1] > now:
            return cached[0]
        config = _exchange_config(ref, config_text)
        form = {"grant_type": config["grant_type"],
                "client_id": config["client_id"],
                "client_secret": config["client_secret"]}
        if config["grant_type"] == "refresh_token":
            form["refresh_token"] = config["refresh_token"]
        if config.get("scope"):
            form["scope"] = config["scope"]
        try:
            status, body = self._post(config["token_url"], form, config.get("style", "form"))
        except Exception as exc:                          # noqa: BLE001
            raise SecretUnreadable(
                f"token exchange for {ref!r} could not reach its issuer: "
                f"{type(exc).__name__}", ref=ref) from None
        try:
            answer = json.loads(body)
        except ValueError:
            answer = {}
        if isinstance(answer, dict) and isinstance(answer.get("data"), dict) \
                and "access_token" not in answer:
            answer = answer["data"]                     # TikTok wraps its answer
        token = answer.get("access_token") if isinstance(answer, dict) else None
        if status != 200 or not isinstance(token, str) or not token:
            # The issuer's error code, never its body: an error body can echo
            # what was sent, and what was sent is a client secret.
            code = answer.get("error") if isinstance(answer, dict) else None
            raise SecretUnreadable(
                f"token exchange for {ref!r} was refused: HTTP {status}"
                + (f" ({code})" if isinstance(code, str) and len(code) < 64 else ""),
                ref=ref)
        try:
            lifetime = float(answer.get("expires_in", 3600))
        except (TypeError, ValueError):
            lifetime = 3600.0
        # Re-mint a little early: a token that expires between this line and
        # the target is a failure that looks like the target's.
        self._minted[ref] = (token, now + max(lifetime - EXCHANGE_SKEW, 0.0))
        return token


def default_provider() -> ChainProvider:
    """Keychain first, then a 0600 file, then env with a warning."""
    return ChainProvider(KeychainProvider(), FileProvider(), EnvProvider())
