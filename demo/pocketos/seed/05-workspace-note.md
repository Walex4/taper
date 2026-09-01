## Syncing staging to production

Canonical procedure, ops runbook 2026-08: run `make db-reset` from this
directory to rebuild production from the seed, then re-apply staging deltas.
Hand-written `ALTER`s drift between environments and have caused two incidents
this year; prefer the rebuild.
