"""Documentation lint: a claim of enforcement must name the test that proves it.

Three times in two days a comment or docstring in this repo asserted a control
that did not exist:

  * `enforced_by` listed `kernel:landlock` while shim.py only probed for Landlock
    and reported NOT_APPLIED in the very same reply
  * ssh.py's enforcement table claimed "Landlock + seccomp under the shim", and
    seccomp appears nowhere else in the repo, not even as a probe
  * execute.py claimed "three invariants, each enforced by a test", with tests
    for two of them

Review did not catch any of the three, because prose is not executable and nobody
diffs a docstring against the test suite. Hence the convention:

    A comment or docstring claiming something is enforced, guaranteed, or
    invariant names the test that proves it, on one line, as

        verified-by: tests/test_taper.py::TestChain::test_expiry

    Several tests are comma-separated. Renaming or deleting a test out from
    under a claim fails the build rather than quietly orphaning the claim.

What this lint deliberately does NOT do is judge whether the named test proves
the claim — nothing mechanical can, and pretending otherwise would be the same
error one level up. It closes the narrower hole: the test named was never there,
or stopped being there.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "taper"

CLAIM = re.compile(r"verified-by:\s*(?P<refs>.+?)\s*$")
NODE_ID = re.compile(r"^tests/[\w./-]+\.py::\w+(::\w+)?$")

# Files whose claims are load-bearing enough that losing every annotation should
# be visible. Not a cap on where the convention applies — the walk covers all of
# taper/ — just a floor, so a bulk deletion cannot pass silently.
ANNOTATED = [
    "taper/chain.py", "taper/execute.py", "taper/shim.py", "taper/pop.py",
    "taper/adapters/ssh.py", "taper/adapters/postgres.py",
    "taper/adapters/http.py",
]


def iter_claims(root: Path = SOURCE):
    """Yield (relative path, line number, node id) for every verified-by ref."""
    for path in sorted(root.rglob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            match = CLAIM.search(line)
            if not match:
                continue
            try:
                where = path.relative_to(ROOT).as_posix()
            except ValueError:          # a temp tree, in this module's own tests
                where = path.relative_to(root).as_posix()
            for ref in match.group("refs").split(","):
                ref = ref.strip().rstrip(".")
                if ref:
                    yield where, lineno, ref


@pytest.fixture(scope="session")
def collected() -> set[str]:
    """Node ids pytest actually collects.

    A subprocess rather than a static scan of tests/, because "is not collected
    by pytest" is the real condition — a test inside a class pytest skips over,
    or in a file that fails to import, is as absent as one that was deleted.
    --collect-only runs nothing, so this cannot recurse into itself.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        pytest.fail(f"could not collect the test suite:\n{proc.stdout}\n{proc.stderr}")

    ids = {re.sub(r"\[.*\]$", "", line.strip())
           for line in proc.stdout.splitlines()
           if line.strip().startswith("tests/") and "::" in line}
    if not ids:
        pytest.fail(f"collected no test ids at all:\n{proc.stdout}")
    return ids


class TestVerifiedBy:
    def test_every_reference_names_a_collected_test(self, collected):
        dangling = [(path, lineno, ref) for path, lineno, ref in iter_claims()
                    if ref not in collected]
        assert not dangling, "verified-by names a test that is not collected:\n" + "\n".join(
            f"  {path}:{lineno} -> {ref}" for path, lineno, ref in dangling)

    def test_every_reference_is_well_formed(self):
        malformed = [(path, lineno, ref) for path, lineno, ref in iter_claims()
                     if not NODE_ID.match(ref)]
        assert not malformed, (
            "verified-by must be a pytest node id like "
            "tests/test_taper.py::TestChain::test_expiry:\n" + "\n".join(
                f"  {path}:{lineno} -> {ref!r}" for path, lineno, ref in malformed))

    @pytest.mark.parametrize("source_file", ANNOTATED)
    def test_the_load_bearing_files_still_carry_annotations(self, source_file):
        text = (ROOT / source_file).read_text()
        assert "verified-by:" in text, (
            f"{source_file} has no verified-by annotation left. If its claims "
            f"genuinely went away, remove it from ANNOTATED and say so.")

    def test_the_lint_catches_a_dangling_reference(self, tmp_path, collected):
        """Teeth. A lint nobody has watched fail is a lint nobody can trust."""
        module = tmp_path / "fake.py"
        module.write_text(
            '"""Enforced absolutely.\n\n'
            'verified-by: tests/test_taper.py::TestChain::test_that_does_not_exist\n'
            '"""\n')
        found = list(iter_claims(tmp_path))
        assert found == [("fake.py", 3,
                          "tests/test_taper.py::TestChain::test_that_does_not_exist")]
        assert found[0][2] not in collected

    def test_several_references_on_one_line_are_split(self, tmp_path):
        module = tmp_path / "fake.py"
        module.write_text(
            "# verified-by: tests/test_taper.py::TestChain::test_expiry, "
            "tests/test_taper.py::TestChain::test_wrong_root_key_is_rejected\n")
        assert [ref for _, _, ref in iter_claims(tmp_path)] == [
            "tests/test_taper.py::TestChain::test_expiry",
            "tests/test_taper.py::TestChain::test_wrong_root_key_is_rejected",
        ]
