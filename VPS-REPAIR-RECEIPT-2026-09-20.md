# VPS repair receipt — 2026-09-20 online recovery

Executed against [`VPS-REPAIR-HANDOFF-2026-09-20.md`](VPS-REPAIR-HANDOFF-2026-09-20.md).
Repair path A (stop/start to let fsck replay the aborted journal) was chosen and
approved by the owner before any mutation. One live infrastructure writer.

## Chronology (UTC)

| Time | Event |
| --- | --- |
| ~06:14 | Guest load climbs; SSH banner stops answering. Console shows ext4 `IO failure` on `sdb2` at kernel ts 128562 (~35.7 h uptime) and `Detected aborted journal`. |
| 08:03:22 | `SOFTSTOP` issued for instance `ocid1.instance.oc1.iad.anuwcljruba2nfqc54vhx5p4jyxexslgudxljabfjxpbbyoh35b5tpyzsnka`. |
| 08:19:12 | Instance reached `STOPPED` (~16 min; slow because the guest was thrashing). |
| 08:19:49 | `START` issued; instance `RUNNING`. |
| 08:20:11 | Boot 0 `99b28f58-7143-4265-9371-dcc4c9018ae2`. `systemd-fsck`: `ROOT: recovering journal`, clearing orphaned inodes. |
| 08:21:43 | SSH restored, load 1.22, 11.9 GB RAM, 9.7 GB free. |

## Verification on the recovered guest

- Root filesystem state `clean`; `dmesg` reports zero `EXT4-fs error` this boot.
- System failed units `0`; user failed units `0`.
- `caddy`, `ubiquity-prospector`, `ai-ubq-fi`, `sshd`, `docker`, `vncserver` all
  active; Guacamole containers up and healthy.
- Boot contract intact: Arch Linux ARM, `aarch64`, 2 OCPUs,
  `root=UUID=e61e7a3e-996d-418a-831b-09f09e827e0a`; only `/` (ext4) and `/efi`
  (vfat) are mounted; `/srv/data` is not a mount in this layout.
- Boot files present with recorded hashes: `/boot/Image`
  `adaede8488db8a4b34381c82915b5aee61713cd800306ecd358c9c18c50e69f9`,
  `/boot/initramfs-linux.img`
  `9c9e2aa10591a7e28d34ceebc2dccef01395e6a9925a393a310a2f7259e785f1`.
- `findmnt --verify` succeeds.
- At-risk guest data survived: `kv.sqlite3` `PRAGMA integrity_check` = `ok`,
  capture downloads store, `/etc/caddy/`, `/etc/ubiquity-prospector/runtime.env`
  and `/var/srv` release staging intact.
- CPU returned to baseline: 149% at 08:17, 25.6% at 08:20, 9.7% at 08:23.
- External surfaces (08:21–08:37): `ai.ubq.fi/health`, `app.prospector.sh`,
  `auth.prospector.sh`, `ubiquity-prospector.ubq.fi/api/health` all HTTP 200.
- OCI footprint unchanged: one `RUNNING` instance, boot + data volumes
  `AVAILABLE`/`ATTACHED`, group backup `arch-online-golden-20260920T040549Z`
  still `AVAILABLE`. The 2026-09-13 pair remains `TERMINATED`.
- Pi `guest-telemetry` resumed polling the guest (first success 08:24:04).

Evidence retained: Pi
`.private/reports/softstop-20260920/` (pre/stopped/start JSON, CPU series) and
`.private/reports/repair-20260920/`; Mac
`~/.local/state/vps-outage-20260920/`.

## Remaining, not done

- **Boot-volume repair-vs-replace decision** is still open, per handoff §2.1 and
  §3. The host has now lost its root filesystem twice (2026-09-07
  `capture-pre-fsck-damaged-root-20260907`, and this event). In-place recovery
  does not address why it recurs.
- **B2 capture defect.** Fixed in source (see below) but not yet deployed to the
  Pi/VPS runtime, so the next weekly run still uses the old capture code.
- No console connection exists for the production instance; console-history is
  at its 10-object limit, so new captures are refused until older ones are
  deleted. Both were true before this work.

## Timers left as found

Production timers were not modified. The Pi backup timer still fires Sunday
00:05 America/New_York. `backblaze-file-backup.service` auto-restarts every
30 min against the recorded `FAILED` job and re-persists the same
`CAPTURE_FAILED` state; it is a visible reminder, not a running capture.

## Deployment status of the capture fix

Source fix is committed and pushed on `main`:
`ed847b4 fix: tolerate tar's benign file-changed status in live capture`.

The VPS executes the capture module from a revision-keyed release bundle at
`/var/tmp/arch-vps-file-backup-runtime/releases/<sourceRevision>/`, selected by
the Pi's `.private/backblaze-deployment.json` `sourceRevision`
(currently `2cc5298a…`). Changing that revision requires building and installing
a new root-owned release directory with its `release.json` manifest on the VPS,
which the repository's guarded deployment procedure owns. That deployment has
NOT been performed, so the next Sunday capture would still run the old capture
code and fail the same way on the live Chromium profile.

Next action for that: build the release bundle from `ed847b4`, install it as a
new root-owned `0700` release directory on the VPS, update the Pi deployment
receipt's `sourceRevision`, and run one controlled capture to prove the tar
tolerance works against the live profile.

## Deployment completed (2026-09-20 09:04 UTC)

The capture fix is live, not just committed:

- VPS release `ed847b47f9eaf6faf69d329966f117d15526ba7b` installed additively at
  `/var/tmp/arch-vps-file-backup-runtime/releases/ed847b4…/` (53 files, root-owned
  `0700`, `release.json` manifest, staged `deno check` passed).
- `scripts/backblaze-capture.ts` on the VPS hashes
  `308859e72b84e2bd787ef02214fe62971a02a7ff0ccf2bfdd57272d0c3295352`, identical
  to local source.
- Pi `.private/backblaze-deployment.json` `sourceRevision` repointed to
  `ed847b4…`; previous value preserved at
  `.private/backblaze-deployment.before-ed847b4-20260920T090416Z.json`.
- The generated pipeline read back **from the deployed release** now emits the
  `case "$ts" in 0) ;; 1) …tolerated… ;; *) …exit 60 ;; esac` form, so exit 1 is
  tolerated and exit 2 stays fatal.
- The prior release `2cc5298a…` remains installed and untouched as the rollback
  target.

## Why the pre-repair captures kept failing

The Pi's controller scripts already matched the repository at `e5d7fa3` (53/53
hashes), but the VPS release pin was still `2cc5298a` from 2026-09-06, so
captures were executing Sep-6-era `backblaze-capture.ts`. That revision treats
any nonzero tar status as fatal, which is why every live-root attempt failed on
`tar producer exit 1` (2026-09-05 twice, and job-820e87c7 on 2026-09-20).

## Root-filesystem recurrence — decision input

Same-class failures:

- 2026-09-07: backup `capture-pre-fsck-damaged-root-20260907` (still `AVAILABLE`,
  forensic only).
- 2026-09-20: `EXT4-fs error in ext4_reserve_inode_write` at kernel ts 128562
  (`~35.7 h` uptime), `Detected aborted journal`, boot loop.

Both are in-place root-journal corruption under load, not power loss. The guest
has **no swap configured**, and the 2026-09-20 console shows 85
`page allocation stall` events across `chromium`, `HangWatcher`,
`ThreadPoolForeg`, `WebRTC_Signalin` and `GpuWatchdog` at 12 GB RAM. An
out-of-memory condition that cannot swap therefore pressures the root
filesystem's write path — a plausible recurring trigger that in-place fsck
recovery does not address.

**Recommendation (needs owner approval; not done):** before treating the host as
durable, either add swap (e.g. the excluded `/.swapfile` that the capture
metadata already tracks for `oracle-root`) with sensible swappiness, or cap the
resident browser/heavy workloads, then decide whether the boot volume is
repaired in place or replaced. This is the handoff's open §2.1/§3 decision and
it is deliberately not resolved here.

## Deliberately not done

- No instance restart beyond the approved `SOFTSTOP`/`START` pair.
- No immediate `STOP`/`RESET`/`SENDDIAGNOSTICINTERRUPT`.
- No backup or volume deletion; the 2026-09-20 pair and all catalog entries are
  intact.
- No timer changes; no new resource; no account upgrade.
- No console-connection creation and no console-history deletion (the 10-object
  limit is unchanged from before this work).

## Acceptance proof of the fix on the real surface

Run against the exact status-check body generated by the **deployed** VPS release
`ed847b4…`, driven by the real 2-stage `tar | zstd` capture pipeline:

| Case | Condition | Result |
| --- | --- | --- |
| A | Only a live-file race (`dd` overwriting a 400 MB file mid-read) | `tar producer exit 1 tolerated: file changed while reading`; pipeline exit **0** — `RESULT_A=PASS` |
| B | Genuine failure (`tar: ./locked: Cannot open: Permission denied`, tar exit 2) | pipeline exit **60** — `RESULT_B=PASS` |

So the benign race no longer fails a capture, and real tar errors still stop it.
The generated logic read back from the deployed artifact is:

```sh
case "$ts" in
  0) ;;
  1) printf 'tar producer exit %s tolerated: file changed while reading\n' "$ts" >&2 ;;
  *) printf 'tar producer exit %s\n' "$ts" >&2; exit 60 ;;
esac
test "$zs" -eq 0 || { printf 'zstd producer exit %s\n' "$zs" >&2; exit 61; }
```

Note the benign case is reported on stderr, not silently swallowed.

## Security posture re-checked after the repair

| Check | Result |
| --- | --- |
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` |
| `KbdInteractiveAuthentication` | `no` |
| Public listener on TCP 9090 | none |
| Host key (ed25519) | `SHA256:/iteYFq+8aaVsv/uwYWgI4nxzHJAxzExf8XXD4TqTaA root@arch-vps` |
| Passwordless SSH for `codex` | works (BatchMode, public key) |

The host key is unchanged from before the incident, so SSH trust and the
recorded fingerprints still hold and no known-hosts repair is required.

## Corrections and one new finding

### Evidence-label correction

The capture preserved as "post-restart" was actually taken at 07:34 UTC, before
the repair restart. It is corrected on the Mac to
`pre-restart-console-capture-at-0734Z.txt`, and its `SUMMARY.txt` now records the
correction. A genuine post-restart console capture could not be created: the
instance sits at its 10-object console-history limit, so `console-history
capture` returns `LimitExceeded`. The post-restart boot is instead proved by
stronger, purpose-built evidence: the guest journal line
`systemd-fsck[169]: ROOT: recovering journal` plus `Clearing orphaned inode …`
at 08:20:11–08:20:12, followed by a mounted ext4 filesystem reported `clean`,
zero `EXT4-fs error` entries this boot, and live SSH/service/external checks.
Deleting a console history to make room was not authorized, so it was not done.

### Timer overlap (found during final audit)

`backblaze-file-backup.timer` carries both `OnCalendar=Sun *-*-* 00:05:00` and
`OnUnitInactiveSec=15min`, with `Persistent=true`. Because the failed
`backblaze-file-backup.service` keeps auto-restarting on a 30-minute
`RestartSec`, the unit repeatedly goes inactive and re-triggers the timer. Its
real next elapse is therefore ~05:20 EDT today, not next Sunday — the timer's
`NextElapseUSecRealtime` of `Sun 2026-09-27 00:05:00 EDT` is the calendar leg
only. Today's period is already satisfied by the `FAILED` journal, so these
re-fires re-persist the same failure and do not create a capture; but it means
Sunday's run is not a clean single shot, and the same pattern will repeat
whenever a capture fails. `StartLimitIntervalUSec=10s` /
`StartLimitBurst=5` bounds runaway restarting.

No timer was changed: the handoff's standing instruction is to leave timers as
found. This is recorded as a defect to fix deliberately, not silently.

### Deployment-surface check

`git diff e5d7fa3 ed847b4` touches only `scripts/backblaze-capture.ts` and
`tests/backblaze_capture_test.ts` (73 insertions, 2 deletions). The deploy
helper ships all 53 `scripts/*.ts`, but they are byte-identical to `e5d7fa3`
apart from the capture module, so the live change is exactly the reviewed fix.
