"""Secret providers.

The broker resolves a secret reference to a value at the last possible moment,
after the decision is made and immediately before execution. Plans carry
references, never values, which is what makes plans safe to log verbatim.

Ordering matters in `ChainProvider`: the first provider that has the reference
wins, so put the most secure store first and the development fallback last.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
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
EXCHANGE_RETRY = 60.0            # a failed exchange is not retried for this long
EXCHANGE_MAX_LIFETIME = 86400.0  # whatever expires_in says
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
    def __init__(self, *providers: Provider, clock=time.time, post=None, persist=None):
        self.providers = providers
        self.clock = clock
        # How a token exchange reaches the issuer. Injected for tests; the
        # default is a plain HTTPS POST that follows no redirect.
        self._post = post or _https_post
        # Where a rotated refresh token is written back: (ref, text) -> None.
        # None keeps the rotation in memory only, which survives until the
        # broker restarts and says so.
        self._persist = persist
        # ref -> (token or None, good until, sha256 of the config it came from,
        # failure message or None). A failure is remembered briefly too, so an
        # unreachable issuer costs one timeout a minute rather than one a call.
        self._minted: dict[str, tuple[Optional[str], float, str, Optional[str]]] = {}
        # ref -> (sha256 of the STORED config it replaces, the rotated config).
        # Keyed to the stored copy, so a second rotation before the first is
        # written back still replaces what the vault holds, never resurrects it.
        self._rotated: dict[str, tuple[str, str]] = {}
        # ref -> why a rotated refresh token could not be written back. The
        # live process keeps working from memory; has() reports it, so
        # `taper doctor` shows it before a restart would lose the token.
        self.unsaved: dict[str, str] = {}

    def get(self, ref: str) -> Optional[str]:
        for provider in self.providers:
            value = provider.get(ref)
            if value is not None:
                return value
        return None

    def has(self, ref: str) -> bool:
        """Whether `ref` can be resolved, without resolving it: a stored
        value, or a well-formed exchange configured for it. Never contacts an
        issuer, so `taper doctor` can ask it; a malformed `.oauth2` raises
        SecretUnreadable rather than counting as present.
        verified-by: tests/test_taper.py::TestTokenExchange::test_has_checks_the_config_without_contacting_the_issuer
        """
        if self.get(ref) is not None:
            return True
        found = self._config_text(ref)
        if found is None:
            return False
        _exchange_config(ref, found[0])
        if ref in self.unsaved:
            raise SecretUnreadable(self.unsaved[ref], ref=ref)
        return True

    def forget(self, ref: str) -> None:
        """Drop a minted token, e.g. after the target answered 401 to it."""
        self._minted.pop(ref, None)

    def require(self, ref: str) -> str:
        value = self.get(ref)
        if value is None:
            found = self._config_text(ref)
            if found is not None:
                return self._exchange(ref, *found)
            raise SecretNotFound(
                f"no secret for {ref!r}; add it with "
                f"`taper secret set {ref}` or place it in ~/.taper/secrets/{ref}",
                ref=ref,
            )
        return value

    def _config_text(self, ref: str) -> Optional[tuple[str, str]]:
        """(the config to use, sha256 of the stored copy), or None.

        A rotation this process saw but could not write back wins over the
        stored copy only while the stored copy is the one it rotated from;
        once someone stores a different config, theirs wins."""
        stored = self.get(ref + EXCHANGE_SUFFIX)
        if stored is None:
            return None
        stored_digest = _digest(stored)
        rotated = self._rotated.get(ref)
        if rotated is not None and rotated[0] == stored_digest:
            return rotated[1], stored_digest
        if rotated is not None:
            self._rotated.pop(ref, None)                 # replaced or written back
            self.unsaved.pop(ref, None)
        return stored, stored_digest

    def _exchange(self, ref: str, config_text: str, stored_digest: Optional[str] = None) -> str:
        """A short-lived access token, minted from what the vault holds.

        Some services issue no long-lived credential worth storing: Google
        hands out hour-long access tokens against a refresh token, a Shopify
        app gets a day-long token from its client credentials. The vault
        holds `<ref>.oauth2` - the issuer, the grant and its long-lived half
        (a refresh token or a client secret) - and the access token is minted
        here, in the broker's process, at the moment of use, and cached until
        shortly before it expires. The agent never sees either half; the plan
        names `<ref>`, as it would a stored secret.

        verified-by: tests/test_taper.py::TestTokenExchange::test_a_refresh_grant_is_exchanged_once_and_cached
        verified-by: tests/test_taper.py::TestTokenExchange::test_an_exchange_config_must_name_an_https_issuer
        verified-by: tests/test_taper.py::TestTokenExchange::test_a_rotated_refresh_token_is_kept
        verified-by: tests/test_taper.py::TestTokenExchange::test_the_cache_follows_the_config_and_forgets_on_request
        verified-by: tests/test_taper.py::TestTokenExchange::test_a_second_rotation_before_write_back_never_replays_a_spent_token
        verified-by: tests/test_taper.py::TestTokenExchange::test_a_write_back_that_does_not_take_effect_is_reported
        """
        if stored_digest is None:
            stored_digest = _digest(config_text)
        now = self.clock()
        digest = _digest(config_text)
        cached = self._minted.get(ref)
        if cached is not None and cached[2] == digest and cached[1] > now:
            if cached[0] is None:
                raise SecretUnreadable(cached[3] or f"token exchange for {ref!r} failed",
                                       ref=ref)
            return cached[0]
        config = _exchange_config(ref, config_text)
        try:
            token, lifetime, rotated = self._ask_issuer(ref, config)
        except SecretUnreadable as exc:
            self._minted[ref] = (None, now + EXCHANGE_RETRY, digest, str(exc))
            raise
        if rotated and rotated != config.get("refresh_token"):
            # The issuer rotated the refresh token: the old one is spent. Keep
            # the new one, in the vault when it can be written.
            updated = json.dumps({**json.loads(config_text), "refresh_token": rotated})
            self._rotated[ref] = (stored_digest, updated)
            self._write_back(ref, updated)
            digest = _digest(updated)
        # Re-mint a little early: a token that expires between this line and
        # the target is a failure that looks like the target's.
        self._minted[ref] = (token, now + max(lifetime - EXCHANGE_SKEW, 0.0), digest, None)
        return token

    def _write_back(self, ref: str, updated: str) -> None:
        """Store a rotated config, and check that the store now returns it:
        a write the chain does not read back (a Keychain entry shadowing the
        file, a read-only vault) is as good as no write after a restart."""
        problem = None
        if self._persist is None:
            problem = "no writable vault is configured"
        else:
            try:
                self._persist(ref + EXCHANGE_SUFFIX, updated)
            except OSError as exc:
                problem = f"the write failed ({type(exc).__name__})"
            else:
                if self.get(ref + EXCHANGE_SUFFIX) != updated:
                    problem = "the vault still returns the old copy (another store shadows it)"
        if problem is None:
            self._rotated.pop(ref, None)
            self.unsaved.pop(ref, None)
            return
        self.unsaved[ref] = (
            f"{ref!r}: the issuer rotated its refresh token and {problem}. It is kept in "
            f"memory until the broker stops; store {ref + EXCHANGE_SUFFIX} again before "
            f"restarting, or re-authorize")
        print(f"taper: warning: {self.unsaved[ref]}", file=sys.stderr)

    def _ask_issuer(self, ref: str, config: dict) -> tuple[str, float, Optional[str]]:
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
        # No expires_in: the common hour. A value that is not a positive
        # number: no caching at all, since the issuer said nothing usable
        # about how long the token lasts.
        raw = answer.get("expires_in", 3600)
        try:
            lifetime = float(raw)
        except (TypeError, ValueError):
            lifetime = 0.0
        if not math.isfinite(lifetime) or lifetime <= 0:
            lifetime = 0.0
        lifetime = min(lifetime, EXCHANGE_MAX_LIFETIME)
        rotated = answer.get("refresh_token") if isinstance(answer, dict) else None
        return token, lifetime, rotated if isinstance(rotated, str) and rotated else None


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def write_secret(directory: Path, ref: str, value: str) -> None:
    """Replace one vault file atomically, 0600 from the first byte."""
    if "/" in ref or ".." in ref or ref.startswith("."):
        raise OSError(f"unsafe secret reference: {ref!r}")
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / f".{ref}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, directory / ref)
    # The rename itself is durable only once the directory is.
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def default_provider() -> ChainProvider:
    """Keychain first, then a 0600 file, then env with a warning.

    The file store is the one `taper secret set` writes: under $TAPER_HOME
    when it is set. It used to be ~/.taper regardless, so a broker started
    with TAPER_HOME pointing anywhere but its own home read a different vault
    from the one its operator had just filled, and reported every secret as
    not provisioned.
    verified-by: tests/test_taper.py::TestDeclaredExecution::test_the_broker_reads_the_vault_secret_set_writes
    """
    home = Path(os.environ.get("TAPER_HOME", "~/.taper")).expanduser()
    secrets_dir = home / "secrets"
    return ChainProvider(KeychainProvider(), FileProvider(secrets_dir), EnvProvider(),
                         persist=lambda ref, text: write_secret(secrets_dir, ref, text))
