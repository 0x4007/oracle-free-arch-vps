# Online backups and tested independent recovery

Canonical lane: `weekly-backup-restore-cycle-g2f1e8856a4`, branch
`codex/weekly-backup-restore-cycle-g2f1e8856a4`. The controlling handoff is
`ONLINE-BACKUP-RECOVERY-HANDOFF-2026-09-06.md` in the repository root.

## Running Oracle path

The Pi runs `backup-scheduled.ts` through the existing weekly service. Its normal
schedule remains Sunday 00:00 America/New_York. The shared controller lock also
serializes Backblaze work. The obsolete recovery timer is removed, with its
previous definition and runtime preserved privately. `backup-recovery.ts` only
reports legacy state; it cannot restart production.

The normal capture path has no guest stop, start, reboot, freeze or process-idle
operation. One FULL volume-group backup captures the existing 50 GB staging boot
and 150 GB Arch root volumes. Exact source, group and member identities establish
the recovery unit; matching display names do not. Provider-native capture is
crash-consistent, not proof of application transaction consistency.

Creation intent and the returned group ID are saved before waiting. The waiter
allows `COMMITTED` while continuing to require `AVAILABLE` for acceptance. An
ambiguous create never authorizes a second request. Failed runs require explicit
reconciliation of the recorded object and journal. Complete legacy journals are
archived before conversion to online state, preserving the standing approval.

A separately approved one-time scheduler window permits live acceptance without
changing the weekly schedule or fabricating the clock. Its claim prevents a
second capture. Retention checks the accepted replacement before each deletion;
`retainPreviousPair` prohibits all previous-pair deletion.

## Live Oracle evidence, 2026-09-06

The approved scheduler capture completed at 17:07:41 UTC. The deployed runtime
files match source revision `63fe190e0b9d0d11742b3e3fca151cff9021c989`.
The service exited successfully and its scheduler claim is complete.

- One FULL group and its two members are AVAILABLE, totaling 200 GB.
- The live free-backup counter reports five used and zero available. The wrapper
  does not consume a sixth slot. All three previous backups remain intact.
- Production remains one instance, 2 OCPUs, 12 GB RAM, 200 GB live volumes and
  one public IP. Account and current official free-limit checks passed.
- Complete Object Storage accounting is 1,453,785,088 bytes, with
  18,546,214,912 bytes of headroom under the conservative 20 GB bound.
- All 186 SSH, served-page and VNC probes passed between 16:37:03 and 17:09:42
  UTC. The boot ID and seven monitored service invocation IDs stayed unchanged.
  An owned workload advanced throughout; the live desktop was inspected.

The first waiter stopped on the previously unhandled `COMMITTED` state. After a
focused correction and regression test, the same backup ID was resumed through
the scheduler. No second backup was created and no source recovery was needed.

Exact identifiers and receipts remain under `.private/reports/`, including
`online-complete-runtime.json`, `online-scheduler-acceptance.txt`,
`online-continuity-summary.json`, `online-post-capture-inventory.json`, and
`online-final-runtime-deployment.json`.

## Independent Backblaze boot proof

Generation `generation-681c4067-aec2-45d5-9afb-77ee530e3a97` was reconstructed
from exact B2 versions and the off-source recovery kit. The approved Mac download
was about 8.42 GB of encrypted data, plus disposable rescue tools. No production
filesystem path supplied recovery data and no private decryption key went to
the VPS.

Two initially empty sparse disks were rebuilt in an AArch64 QEMU guest: 50 GiB
staging and 150 GiB root, with 4 GiB guest RAM and two vCPUs. All six filesystem
archives, GPT layout, UUIDs, LVM metadata and fallback swap were restored.
Filesystem reconstruction ran from 16:53:24 to approximately 17:02:30 UTC.

The corrected disks booted the retained EFI/shim/GRUB staging chain into Arch
Linux ARM at 17:15:23 UTC. SSH, root and EFI mounts, staged kernel/initramfs
parity, fallback metadata/swap, preserved Codex configuration, Docker containers,
Guacamole markup and a visually inspected Xfce desktop passed. Restricted QEMU
networking and a guest firewall blocked Internet and cloud metadata access.
Copied agents and sync jobs were masked; the rescue share was absent.

Live testing found three reconstruction corrections now in the module:

- Read full SCSI hardware serials through udev when Alpine's lsblk omits them.
- Recreate excluded runtime directories and temporary-directory permissions.
- Explicitly select XFS features compatible with the retained GRUB 2.06 and
  Oracle fallback kernel. Current mkfs.xfs defaults were not boot-compatible.

The clone also needed a new X11 cookie after its hostname changed. This is an
isolation preparation step. The drill required these operator corrections; it
is not evidence of a zero-intervention restore. The dated proof is separate
from each generation's archive verification.

The guest shut down cleanly. Temporary disks, downloaded/decrypted payloads and
the drill SSH key were removed. Small reports, the desktop image, executed
procedure and hashed source files remain in the private recovery kit. B2 objects
and both accepted generations were preserved.

## Reproduction and remaining boundaries

Use `backblaze-machine-restore.ts` with the existing private JSON input convention:
selected index and digest, matching metadata, verified plaintext descriptors,
and an approved serial-bound target. It returns `FILESYSTEMS_REBUILT`, never a
boot claim. Before boot, set clone identities, mask outbound jobs, isolate the
network, refresh hostname-bound X11 authentication, and remove the rescue share.
Then run the SSH, filesystem, data, application and desktop acceptance checks.
The private kit retains the exact tested host/rescue commands and library hashes.

The Oracle group members pass live identity and restore-validator checks, but the
new Oracle point has not been restored and booted. Historical stopped-pair boot
proof and the independent B2 boot proof do not establish that result. The two
approved requests excluded a new OCI clone. Production already uses the full
200 GB live-storage allowance, so a separate Oracle boot target needs a new
scope/resource decision.

`retainPreviousPair` remains true. All five backup slots are occupied; another
capture cannot proceed until an approved retention action frees two slots.
Neither existing-backup deletion nor a new Oracle clone was included in this
acceptance run. Do not describe recurring rotation or the entire handoff as
complete while these boundaries remain unresolved.

The three permitted local review rounds were used before live acceptance. The
live corrections received focused tests and actual runtime checks; no fourth
review was run. PR #9 remains draft pending the remaining acceptance decision.
