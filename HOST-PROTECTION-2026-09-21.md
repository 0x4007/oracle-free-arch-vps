# Host protection changes — 2026-09-21

Follow-up to [`VPS-REPAIR-RECEIPT-2026-09-20.md`](VPS-REPAIR-RECEIPT-2026-09-20.md).
Requested by the owner: cap the backup so it cannot bog the machine down.

## What was actually wrong

The backup was **not** unlimited, but its limits did nothing useful:

| Control | Old value | Reality on this host |
| --- | --- | --- |
| `MemoryMax` | `1G` | Working, but irrelevant — the backup is not the big memory consumer. |
| `CPUQuota` | `100%` | Working (one of two cores). |
| `Nice` | `10` | Working but mild. |
| `IOWeight` | `100` | **Inert.** The root volume runs the `none` I/O scheduler, so weight-based I/O control has nothing to act on. |
| `IOSchedulingClass` | unset | **Missing.** This is the control that actually works here. |

Measured on the live host with `dd iflag=direct` against the root volume:

| Condition | 128 MiB read | Effective rate |
| --- | --- | --- |
| baseline | 0.33 s | 412 MB/s (page cache) |
| `ionice -c 3` (idle) alone | 1.81 s | 74 MB/s |
| idle class against a competing reader | 3.67 s | 36 MB/s |

So an idle I/O class does throttle, and it yields correctly under contention.

Correction to the earlier receipt: the "2,800–9,300 MB/s" figures quoted there
were an aggregation error and are not physically possible on this volume.
Direct measurement gives ~63 MB/s read and ~70 MB/s write. The real load was
roughly 16 GB of reads plus 5–8 GB of compressed writes over ~20 minutes,
performed with no effective I/O priority — which is worth fixing, and also
makes that figure a non-issue in the earlier narrative.

## Changes made

### 1. Worker priority (`scripts/backblaze-file-backup.ts`)

The capture worker is launched by the controller through `systemd-run`. Its
properties are now:

    MemoryMax=1G
    CPUQuota=100%
    CPUWeight=1
    Nice=19
    IOSchedulingClass=idle
    IOSchedulingPriority=7

`CPUWeight=1` and `Nice=19` are the floors (0 is not a valid value for either).
Both only take effect under contention, so an idle host still runs the backup
at full speed while production always wins. The previous `IOWeight=100` was
removed because it enforced nothing.

### 2. Service restart loop (`config/backblaze-file-backup.service`)

`Restart=on-failure` / `RestartSec=30min` was removed in favour of `Restart=no`.

The controller already owns a durable exponential backoff
(`ONLINE_RETRY_POLICY`: 15 min initial, 60 min max, six attempts, then a 24 h
cooldown), and `UNATTENDED-BACKUP-CONTRACT.md` mandates that the scheduler timer
recheck due work every 15 minutes. The systemd restart was a **third**,
backoff-blind schedule layered on top: around the 2026-09-20 failure it looped
the unit 45 times and defeated the recorded `nextAttemptAtUtc`.

The contract-mandated 15-minute timer recheck was left untouched.

### 3. Swap (`/.swapfile`, 4 GiB)

The repository already defines this exact file for swap recreation
(`backblaze-machine-restore.ts` requires `present: true`, `path: "/.swapfile"`,
`bytes: 4294967296`) and the same path is in `REQUIRED_EXCLUSIONS`, so it is
excluded from every backup role by design. The host had no swap at all.

Created, enabled, and made persistent:

    fallocate -l 4G /.swapfile && chmod 600 && mkswap && swapon
    /.swapfile none swap defaults 0 0      # /etc/fstab
    vm.swappiness=10                        # /etc/sysctl.d/90-vps-swap.conf

On-disk identity matches the captured design exactly:
`4294967296 600 0 0`.

**Bug caught before it mattered:** the first fstab attempt used
`UUID=<swap-uuid>`. `blkid` reports a UUID for a swap *file*, but the kernel and
systemd resolve `UUID=` through `/dev/disk/by-uuid/`, which has no entry for a
file — so that line would have failed at the next boot. Rewritten to the correct
path form. `findmnt --verify` now reports `0 errors`, and systemd derives the
correct `.swapfile.swap` unit under `swap.target`, which is the boot-activation
path. No reboot was performed to prove this; a reboot is a production outage and
was not authorized.

### 4. Disk pressure

Removed 13 GB of failed/partial capture scratch
(`generation-a3fd3f9f…`, `generation-ecd4cd2f…`, `generation-820e87c7…`) from
`/var/tmp/arch-vps-file-backup/`. Free space went from 71 GB to 84 GB. The
accepted 2026-09-06 generation was left in place.

## Verification

Applied to the real worker path, not just source:

- VPS release `df6a68b6a11de52617afb769b333cb6df3aadada` deployed (53 files,
  staged `deno check` passed); its `backblaze-file-backup.ts` carries the new
  properties.
- Pi `.private/backblaze-deployment.json` repointed to that revision; previous
  value preserved as
  `.private/backblaze-deployment.before-df6a68b-20260921T033630Z.json`.
- Corrected service unit installed and `daemon-reload`ed; `Restart=no` is the
  effective value and the unit settled to `failed` instead of looping.
- A live `systemd-run` worker with the exact new property set measured:
  `cpu.weight=1`, `cpu.max=100000 100000` (one core), `memory.max=1073741824`,
  `ionice: idle`, `nice: 19`.
- Repo `config/backblaze-file-backup.service` is byte-identical to the installed
  unit.
- Swap active at 4 GiB with the intended swappiness.
- 691 tests passed, 0 failed; `deno fmt` and `deno lint` clean.

## Not done

- No reboot, so swap activation at boot rests on the fstab/generator evidence
  above rather than an observed boot.
- The failed 2026-09-20 job is still `FAILED` in the controller journal. The
  next Sunday run allocates the next period normally; its 15-minute rechecks
  will simply re-report the existing failure until then.
