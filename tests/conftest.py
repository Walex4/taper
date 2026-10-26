"""Suite-wide setup. The umask is the whole of it, and it is not a detail.

taper refuses to mint from a policy file the agent's uid can edit: group- or
world-writable configuration is configuration the agent wrote. That check is
correct, it is the point of `hardening.check_path`, and it has tests of its own
which set their modes explicitly.

What it also catches is this suite. A test that writes a policy with
`Path.write_text` gets whatever the ambient umask allows. On Ubuntu - and on
GitHub's runners - a user whose uid equals their gid gets umask 002, so the file
lands 0664, and every mint in the suite is refused. Under umask 022 the same
commit passes. That is why it went unnoticed until CI: it failed only for people
whose umask differed from the author's, and the author's is 022.

Three call sites had already been given an explicit `chmod(0o644)`, one at a
time, as somebody hit them. This sets it once for the twelve that had not been,
and for the next one anybody writes.

Set in `pytest_configure` rather than a fixture so it is in force before
`tmp_path_factory` builds the session's base directory, and so no ordering
between fixtures can decide whether the suite passes.

Tests that deliberately create writable configuration in order to assert the
refusal call `chmod` themselves and are unaffected.

verified-by: tests/test_integration.py::TestSuiteUmask
"""

import os


def pytest_configure(config):
    os.umask(0o022)
