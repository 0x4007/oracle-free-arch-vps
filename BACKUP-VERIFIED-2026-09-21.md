# Verified end-to-end backup — 2026-09-21

Owner request: trigger a backup now and fix problems.

## Result

**A complete online backup ran end-to-end and was accepted.** This is the first
successful Backblaze capture since 2026-09-13 and the first ever to get past the
`root` role, which had failed on every previous live attempt.

| Evidence | Value |
| --- | --- |
| Generation | `generation-caa21434-fe6b-4133-a063-f8affddaf692` |
| Job | `job-caa21434-fe6b-4133-a063-f8affddaf692` |
| Capture window | 08:18:59 → 08:43:08 UTC (~24 min) |
| Accepted (verified) | 2026-09-21T09:51:22.158Z |
| Total archives | 7 roles, 9.59 GiB |
| Final phase | `COMPLETE`, no failure, no retry |
| Watchdog | `B2_BACKUP_CURRENT` / **healthy: true** |

Role sizes: `root` 5712.3 MiB, `oracle-root` 3635.1 MiB, `staging-boot`
471.5 MiB, `oracle-oled` 4.1 MiB, `staging-efi` 1.3 MiB, `efi` 51 KB,
`recovery` 11 KB.

## The fix proved itself in production

The `root` role completed cleanly — 5.99 GB committed, **no leftover
`.partial`** — at the exact step that failed on every prior attempt. The change
tolerates tar's benign exit 1 (file changed while reading) while keeping exit 2
and every other status fatal, and adds no tolerance to zstd or the inventory
check.

The **verifier downloaded and decrypted 5.7 GB back from Backblaze**, which is
independent proof the cloud objects exist and are readable — not merely a local
claim.

Production stayed healthy throughout: load ~0.3–1.3 on a 2-OCPU host, 0 failed
units, `caddy`/`ubiquity-prospector`/`ai-ubq-fi`/`sshd`/`docker` all active, root
filesystem `clean`, and all three public endpoints returning 200 across the whole
run.

## Problems found and fixed during this trigger

### 1. My own regression: the deployment identity file was broken

At 03:36 I repointed `.private/backblaze-deployment.json` and added three audit
fields (`supersededRevision`, `updatedAtUtc`, `updateReason`). `loadDeployment`
requires **exactly three keys**, so every controller run after that failed with
`CONTROLLER_STEP_FAILED: Backblaze deployment identity is missing` — including
the 07:58 scheduled run. **This would have broken Sunday's backup.**

Fixed by restoring the strict 3-key identity and moving the audit fields to a
separate `.private/backblaze-deployment-audit.json`. The same script also dropped
the file to mode 0644, which `readPrivateJson` also rejects (`must not grant
group or other permissions`); restored to 0600.

### 2. The Pi was still running stale controller code

The VPS release had been updated, but the Pi's own `scripts/` still held
`IOWeight=100` — the inert I/O control. Worker units therefore launched with
`cpu.weight: 100` and `ionice: none`, i.e. the priority fix was **not** in
effect for the running capture.

Fixed by installing the two differing files (`backblaze-capture.ts`,
`backblaze-file-backup.ts`) from revision `9bd04f1`. The Pi now matches the repo
exactly: **0 of 53 files differ**. Previous bytes preserved under
`.private/controller-release-backups/pi-scripts-20260921T085333Z/`.

This was done while the capture was running without disturbing it: the running
worker executes from the VPS release directory, not the Pi's scripts.

### 3. Terminal-job re-arm

The controller deliberately never creates a second job in the same period, and
the 2026-09-20 job was terminal `FAILED`, so a trigger would have been refused.
Recovered by resetting only the `job` key in the controller state while
preserving the accepted `catalog` verbatim (asserted byte-equal in the script
before and after).

**Disclosure:** the accompanying archive `cp` silently failed (a `$ARC` quoting
bug inside the heredoc), so the pre-reset controller JSON was not saved as
intended. The substantive facts survive elsewhere: the failed job id, period,
phase and failure detail are recorded in this file, in
`VPS-REPAIR-RECEIPT-2026-09-20.md`, and in the watchdog report; and the original
`capture:root` diagnostic (`tar: … file changed as we read it`, exit 60) was
captured earlier in the session. No backup object, key, credential or catalog
entry was involved. The next reset should use a variable expanded outside the
quoted heredoc.

## Remaining

- The priority fix is now fully deployed on both hosts but has not yet been
  exercised by a capture (this run used the pre-fix Pi code). The next run will
  show `cpu.weight=1` and `ionice: idle` on the worker.
- No reboot has been performed, so swap-at-boot still rests on fstab/generator
  evidence rather than an observed boot.
