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


Three assumptions about the machine, not one
--------------------------------------------

The umask above is the first of three places where this suite tests the host
as much as the code. All three surfaced within two days of each other, each
after a reproduction attempt that went looking for a bug in taper.

1. The ambient umask, handled above. It failed only for people whose umask
   differed from the author's, which is why CI found it and nobody else had.
   verified-by: tests/test_integration.py::TestSuiteUmask

2. The host's systemd version. `TestRenewalUnits` shells out to
   `systemd-analyze verify`, which loads the subject unit's dependencies and
   therefore reports on the host's units next to ours. A GitHub runner image
   that shipped around 2026-10-20 carried a systemd new enough to warn that
   walinuxagent.service and the xfs_scrub units still set `CPUAccounting=`,
   which has since been removed. Three cases went red on all four Python
   versions with nothing in this repository changed.

   `HOST_UNIT_DIRS` in tests/test_integration.py now sets aside stderr lines
   attributed to a host unit directory. Every other line still fails the
   test, a warning that names no unit included - the staged unit lives under
   tmp_path, so a complaint about ours can never begin with a host path and
   can never be set aside by mistake.

   What remains is the opposite exposure: systemd also phrases a warning
   without a leading path, as in "Unit system-xfs_scrub.slice has no ...",
   and such a line is not set aside. If a future image emits that form the
   test fails over a unit taper does not ship. That is the safe direction -
   it reports a problem that is not ours rather than hiding one that is - and
   the fix, should it come to that, is to attribute each line by the unit
   names it mentions instead of by path.
   verified-by: tests/test_integration.py::TestRenewalUnits

3. The uid. Two tests assert a refusal the kernel extends only to ordinary
   users, and so fail when the suite is run as root:

     tests/test_integration.py::TestMCP::test_an_unreachable_directory_is_not_reported_as_a_missing_socket
     tests/test_integration.py::TestRenewalFailsLoudly::test_an_unwritable_vault_exits_non_zero

   Root ignores the permission bits both of them rely on. They are
   deliberately not skipped for root: a skip would make a root run look
   clean while two controls went unexercised, and the controls are the point.
   CI runs as an ordinary user and is the authority. A root run that shows
   exactly these two failures and nothing else is a pass - treat a third
   failure as real.

The pattern is worth keeping in view. None of the three failed because of a
commit; each failed because a machine differed, and each cost time to
somebody who assumed otherwise. A test that touches the filesystem, the
kernel or a system daemon is making a claim about the host it runs on, and
that claim belongs in writing beside it rather than in the memory of whoever
debugged it last.
"""

import os


def pytest_configure(config):
    os.umask(0o022)
