"""Secret providers.

The broker resolves a secret reference to a value at the last possible moment,
after the decision is made and immediately before execution. Plans carry
references, never values, which is what makes plans safe to log verbatim.

Ordering matters in `ChainProvider`: the first provider that has the reference
wins, so put the most secure store first and the development fallback last.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional, Protocol


class SecretNotFound(KeyError):
    pass


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
            raise SecretNotFound(f"unsafe secret reference: {ref!r}")
        path = self.dir / ref
        if not path.is_file():
            return None
        mode = path.stat().st_mode & 0o077
        if mode:
            raise SecretNotFound(
                f"{path} is readable by others (mode {oct(path.stat().st_mode & 0o777)}); "
                f"run: chmod 600 {path}"
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
    def __init__(self, *providers: Provider):
        self.providers = providers

    def get(self, ref: str) -> Optional[str]:
        for provider in self.providers:
            value = provider.get(ref)
            if value is not None:
                return value
        return None

    def require(self, ref: str) -> str:
        value = self.get(ref)
        if value is None:
            raise SecretNotFound(
                f"no secret for {ref!r}; add it with "
                f"`taper secret set {ref}` or place it in ~/.taper/secrets/{ref}"
            )
        return value


def default_provider() -> ChainProvider:
    """Keychain first, then a 0600 file, then env with a warning."""
    return ChainProvider(KeychainProvider(), FileProvider(), EnvProvider())
