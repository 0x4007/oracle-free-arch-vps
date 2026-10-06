# Guarded backup scratch sweep — deployed 2026-10-06

## Failure this fixes

The 2026-10-04 weekly capture failed before writing anything (job-69557c9a…, phase FAILED, errorCode CAPTURE_FAILED):

    operation=capture:root
    staging space insufficient selected=26924441600 avail=58015784960

The capture check requires `avail - 2 * selected >= 5 GiB + 512 MiB` on the staging filesystem (scripts/backblaze-capture.ts); the run required 59,754,463,232 B and had 58,015,784,960 B available, short by ~1.7 GB. Nothing ever removed abandoned generation scratch: the controller cleanup only removes the CURRENT generation after a completed cycle, so every failed or interrupted cycle leaked its working copies forever, and enough leaks make every later run fail the same check.

Live confirmation of the leak class: ~23.5 GB of month-old scratch from generation 681c4067 (Sep 5–6, three copies across arch-vps-file-backup, arch-vps-file-recovery and arch-vps-file-verification-attempt2) was still present on 2026-10-06. Manual reclaim that day restored the headroom for the next run.

## The fix (revision 5e34bdf…, main)

- `fix(backup): reclaim stale generation scratch before capture` (b09782b): new `buildScratchSweepScript()` runs from the controller's REQUESTED phase before the transport install and worker launch. It holds the source lock (never racing an active unit), keeps the active generation and anything younger than a 48 h grace period, re-checks canonical root-owned 0700 bases and generation directories, rejects mounts at or below a target, validates the same producer-output whitelist as the cleanup, skips (never fails) anything it cannot prove, and always exits 0 so maintenance cannot block a capture; the capture's own staging-space check remains the gate.
- `fix(backup-progress): raise the cleanup failure after the finally block` (04607b8) and `style: apply deno fmt to pi recovery sources` (6a10784): the pre-existing lint/fmt drift that would otherwise make the release gates red.
- `fix(backup): accept capture step stderr logs in scratch cleanup` (5e34bdf): `capture-<role>.stderr.log` is written only when a capture step fails, so failed-cycle leftovers carried a name the cleanup whitelist rejected and the sweep correctly skipped them; the whitelist addition lets both accept that exact producer output.

## Gates on 5e34bdf

- `deno task check` (98 files), `deno task lint` (98), `deno task fmt` (102): clean.
- `deno task test`: 568 passed / 0 failed / 172 ignored; `deno test -A tests`: 739 passed / 0 failed / 1 ignored.
- New tests: sweep script contract, a stubbed execution of the exact emitted script (active kept, stale removed, fresh kept, unexpected preserved), REQUESTED-phase ordering, transient sweep-failure retry.

## Deployment

- VPS release `5e34bdf…` installed additively at `/var/tmp/arch-vps-file-backup-runtime/releases/5e34bdf…/` — root-owned 0700, release.json manifest, all 55 files hash-verified twice, staged `deno check` passed. Prior releases `6a10784…` and `88e24662…` remain untouched as rollback targets.
- Pi controller `/home/pi/ops/weekly-backup-controller` updated to the same 55-file revision (hash-checked); `.private/backblaze-deployment.json` repointed to `5e34bdf…` with the previous value preserved at `.private/backblaze-deployment.before-5e34bdf-20261006T0237….json`.

## Live acceptance (2026-10-06, deployed 5e34bdf…)

- Sweep executed as root on the VPS from the deployed release: reclaimed `generation-c8123c86…` (file-backup), `generation-bd69c92b…` (recovery), `generation-681c4067…` (verification), and — after the whitelist fix — `generation-a4590a93…` (file-backup). The active generation and sub-48 h directories were preserved; exit 0.
- `cleanupAllowedName("capture-root.stderr.log")` reads true from the deployed release.
- Space preflight of the exact capture check (same exclusions, root filesystem): selected 28,577,755,136 B; avail 76,635,738,112 B; required 63,061,090,304 B; PASS with 13,574,647,808 B (~12.6 GiB) margin.

## Next

- The next scheduled weekly run (Sunday 2026-10-11 00:05 America/New_York) uses revision `5e34bdf…` and runs the sweep before its capture; that sweep also reclaims the two mtime-refreshed `681c4067` record directories and the 2026-10-04 failed job's generation once older than 48 h.
- `/var/tmp/arch-vps-file-verification-attempt2` (72 MB) predates the tooling bases, is referenced by no code, and was left in place.
