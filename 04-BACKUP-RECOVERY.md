# Backup and Recovery Contract

## Core rule

The staging boot volume and Arch root volume are one machine. A backup of only
one volume is not a complete recovery point.

Routine weekly backups are online group captures: the instance stays `RUNNING`
and is never stopped, rebooted, or frozen, and no required service is stopped.
Only the procedures marked as offline below (the historical build golden pair,
or a separately approved disaster-recovery or drill capture) stop the instance
first. The current online operation and acceptance contract is
`ONLINE-BACKUP-CONTRACT.md` with the owner-controlled charter
`/Users/nv/repos/0x4007/oracle-free-arch-vps/PROJECT-VISION.md`.

## Backup-slot plan

Oracle's Always Free page stated a combined maximum of five boot-volume and
block-volume backup objects when this kit was written. Verify the current rule.

Recommended steady-state use:

| Slot | Object                                          |
| ---: | ----------------------------------------------- |
|    1 | Accepted staging boot backup                    |
|    2 | Accepted Arch root backup with the same suffix  |
|    3 | Free for the next staging backup                |
|    4 | Free for the next root backup                   |
|    5 | Unused; not a complete recovery point by itself |

During rotation, the accepted and replacement pairs briefly use four slots. Keep
the fifth slot unused unless the owner explicitly accepts a volume-only backup
for a change that affects only that volume. Such an object is not a complete
machine recovery point.

## Create the golden pair (offline build or disaster-recovery capture)

This stopped procedure applies to the historical build golden pair and to a
separately approved disaster-recovery point. Routine online weekly pairs do not
use it: they are captured by the online scheduler while the instance stays
`RUNNING`, so no outage approval or `SOFTSTOP` applies.

1. Reconcile all backup objects and confirm a pair can be created without
   exceeding the current limit.
2. Confirm zero failed units and quiesce stateful applications.
3. Run `sync`.
4. Obtain approval for the outage.
5. Request an approved OCI `SOFTSTOP` from the operator system while the guest
   remains running.
6. Wait up to 1,200 seconds for OCI `STOPPED`. On timeout or error, reread state
   and fail closed. Never chain immediate `STOP` or `RESET` automatically.
7. Generate one UTC suffix, for example `20260903T191507Z`.
8. Create both backups:

   ```bash
   oci bv boot-volume-backup create \
     --boot-volume-id '<STAGING_BOOT_VOLUME_OCID>' \
     --display-name 'arch-stage-golden-<UTC_SUFFIX>' \
     --type FULL

   oci bv backup create \
     --volume-id '<ARCH_ROOT_VOLUME_OCID>' \
     --display-name 'arch-root-golden-<UTC_SUFFIX>' \
     --type FULL
   ```

   Replace placeholders before execution. Check the installed CLI help because
   waiter and confirmation flags differ by version.

9. Wait until both objects are `AVAILABLE`.
10. Verify for each object:
    - Exact name and shared suffix.
    - `FULL` type.
    - `AVAILABLE` lifecycle state.
    - Correct source OCID.
    - Correct 50 GB or 150 GB source size.
    - Home region.
    - Creation timestamp.
    - No retention lock or paid cross-region copy.
11. Start the same instance and complete live acceptance.

## Rotation

Routine rotation runs automatically and online through the scheduler; it never
stops the instance and it captures the pair as one OCI volume-group backup (see
`ONLINE-BACKUP-CONTRACT.md`). The manual procedure below is the historical
offline alternative, still valid for a separately approved rotation or recovery
point that requires the instance stopped.

1. Reconcile all existing objects and verify that at least two slots are free.
2. If two accepted pairs already consume four slots, choose one complete pair as
   the retained recovery point. Obtain exact approval to delete the other
   complete pair, delete both of its members, and confirm their terminal states.
   Never delete the last accepted pair.
3. Create a new matched incremental pair with one new suffix:

   ```text
   arch-stage-latest-<UTC_SUFFIX>
   arch-root-latest-<UTC_SUFFIX>
   ```

4. Wait for and validate both objects.
5. Start or keep the instance running as the planned workflow requires.
6. Complete the relevant live checks.
7. Obtain exact approval to delete the older retained pair.
8. Delete both older members and confirm their terminal states. The new pair is
   now the sole accepted steady-state pair, and two slots are free for the next
   rotation.

Never rotate one side independently. Never delete the last accepted pair to make
space for an unverified replacement.

## Restore from OCI backups

Use `scripts/oci-restore.ts` as described in `07-OPERATIONS-AND-DRILLS.md`. Keep
`action` set to `plan` until the private ledger contains the exact approved pair
and operation.

Accepted routine pairs are members of one online volume-group capture, created
while the source instance stayed `RUNNING`; before any restore, the tool queries
the live volume-group backup and proves that the selected pair consists of
exactly those two member backups. The bootable recovery target then materializes
the same exact member backups as one boot volume plus one block volume on the
replacement A1 instance. OCI volume-group create-from-backup, which restores the
group as a unit, is a supported alternative that this boot-target path
intentionally does not use. Record the accepted capture in the optional
`volumeGroupId` and `volumeGroupBackupId` restore-configuration fields. When
those two fields are populated, add the same two keys with the exact values to
`approval.approvedTargets`; for the historical golden pair, leave the optional
top-level fields empty and omit both approval keys. Until a live Oracle restore
drill boots a replacement from the capture and passes the full acceptance
checklist, the online group's restore and boot status is `METADATA_PROVED`, not
`RESTORE_DRILL_PROVED`.

The isolated volume-group restore drill has a source-only plan gate in
`scripts/oci-group-restore-drill.ts`. It validates the exact bound plan, the
reviewed one-hour approval over the plan digest (including typed
`FREE_AND_TRIAL`/`FREE_TRIAL` trial evidence: a positive spending cap, an
estimated cost at or below the cap, available trial credits that cover the cap,
a trial expiry past the whole `maxDurationHours` window, and account evidence
observed at most 15 minutes before use; every approval timestamp must be strict
canonical UTC), the live group-capture member metadata, the distinct restored
targets and the durable journal, then builds the deterministic OCI CLI requests
and the journal-guarded cleanup order. It never issues a provider call and never
claims live recovery: its states are `PLAN_VALID`, `METADATA_PROVED` and the
`RUN_READY` run guard, each with `restoreDrillProved` false.

Live execution belongs to `scripts/oci-group-restore-run.ts`
(`deno task
group-restore`) over the journaled state machine in
`scripts/oci-group-restore-executor.ts`. It reads only the explicit private JSON
inputs (`--plan`, `--approval`, `--evidence`, `--runner`, plus the
operator-supplied `--acceptance` for accept/cleanup), refuses missing,
placeholder or ambiguous state, and persists only the lifetime, journal and
result. Every input path and every persisted path must be a relative path rooted
exactly at `.private` with no `.`/`..`/empty segments and no absolute path, so
no input or state write can escape the private directory. The single `--action`
gate is `create` (stops at a durable `CREATED` result), `accept` (a separate
typed acceptance receipt only, whose observation must fall inside the durably
recorded drill window) and `cleanup` (allowed after the durably recorded
lifetime deadline, reporting `deadlineExceeded` instead of extending the
window). Every create boundary re-checks the durably recorded lifetime against
the current adapter clock, so a long provider create that crosses the deadline
cannot hide behind a stale run-start timestamp. The injected production verifier
runs before the first create and after all deletes and reconciles the reviewed
source: `RUNNING` in the plan's availability domain, exactly 2 OCPU/12 GB, 200
GB live storage, one public IP (the read-only probe is region-scoped and limited
to RESERVED addresses; ephemeral clone IPs are availability-domain scoped),
exact source IDs/attachments and volume-group accounting from the group object's
`volume-ids` list.

The group path intentionally uses an **ephemeral** public IP: the clone is
launched with `--assign-public-ip true` in the isolated subnet/VCN and the
production reserved IP and DNS are never moved, reassigned or referenced by this
code. The isolated network must block egress and instance metadata
(`169.254.169.254`) and the clone's duplicate sync jobs must be masked before
its first boot; reach the clone through the isolated network, never by opening
the production network. The independent encrypted Backblaze generations remain
the direct fallback recovery path (see `ONLINE-BACKUP-CONTRACT.md`). This source
change provides no new live proof: until a real operator boot and acceptance
drill runs against the capture, the online group's restore status is
`METADATA_PROVED`, not `RESTORE_DRILL_PROVED`.

The executor also requires the injected `verifyPreBootIsolation` gate after the
two restored volumes are identified and before it launches the clone. That gate
must prove the isolated subnet, egress and metadata controls and prepare the
copied volumes so duplicate timers, agents and sync jobs are masked before the
first boot. The default OCI adapter has no such proof and fails closed; an
acceptance receipt cannot substitute for this pre-boot gate. Create and cleanup
journals are persisted around every provider mutation so a controller crash
leaves an exact resumable intent instead of silently issuing a duplicate.

1. Confirm both backup names share the intended suffix.
2. Restore the staging backup as a boot volume in the tenancy home region.
3. Restore the root backup as a block volume in the same availability domain.
4. Confirm the restored root partition still has `<ARCH_ROOT_UUID>`.
5. Launch `VM.Standard.A1.Flex` with the current free-safe OCPU/RAM allocation
   from the restored staging volume.
6. Attach the restored root volume paravirtualized.
7. The group restore drill launches the clone with an **ephemeral** public IP in
   the isolated subnet/VCN and never assigns the production reserved IP or
   changes production DNS. Only the separate legacy `oci-restore.ts` path
   assigns the reserved IP, and only with exact approval.
8. Verify UEFI -> GRUB -> staged kernel/initramfs -> UUID root boot.
9. Verify SSH host-key expectations. A restored image may intentionally have the
   old host key; a rebuilt machine should have a newly recorded key.
10. Confirm staged kernel and initramfs parity before normal operation.
11. Prove the clone's isolation: no production route, blocked instance metadata,
    masked duplicate sync/job copies before first boot.
12. Supply the typed acceptance receipt (all `GroupRestoreAcceptanceChecks`
    true, exact UUIDs and SHA-256 values bound to the reviewed plan) as a
    separate operator action before recording `RESTORE_DRILL_PROVED`.
13. After cleanup, run the production verifier again and prove the tenancy
    returned to the original footprint (2 OCPU/12 GB, 200 GB live storage, one
    public IP, exact source IDs and volume-group accounting).

A backup does not reserve A1 capacity. If no A1 capacity is available, try
another availability domain in the home region or retry later. Do not create a
duplicate restore that would exceed the live-volume allowance.

The tool checks all configured domains before it restores volumes. If launch
still fails after restoration, it stops and retains the candidate identifiers
for an approved cleanup. It never creates a second candidate pair automatically.

Backup metadata validation is not a restore drill. Record `RESTORE_DRILL_PROVED`
only after a replacement instance boots and passes the full live checklist.

## Optional Object Storage safety image

A tested QCOW2 can be retained in Object Storage as an additional recovery
artifact if the object and all other objects fit the current free allowance. It
is not a substitute for the paired volume backups.

Before sharing or uploading a QCOW2:

- Stop the source filesystem or create it from a clean clone.
- Remove credentials, machine identity, logs, cloud-init state, and private
  application data unless the image is encrypted and access-controlled.
- Verify its digest.
- Record format, virtual size, partition table, firmware assumptions, and
  supported launch mode.
- Test import and isolated boot before calling it recoverable.

Oracle's Linux import requirements currently describe VMDK or QCOW2, one boot
disk, DHCP networking, no hard-coded MAC address, and paravirtualized mode for
Arm shapes. Verify the current requirements before import.

## Restore from a local file archive

A local `rootfs` archive is independent of OCI volume backups. Restore in this
order:

1. Extract the base root archive to a mounted target root.
2. Extract the EFI archive to the target EFI filesystem.
3. Apply only the accepted repair overlay over the root.
4. Preserve numeric owners, ACLs, extended attributes, hard links, and sparse
   files.
5. Recreate runtime mounts, swap, machine identity, network identity, `fstab`,
   and boot-loader metadata.
6. Keep the restored system isolated until SSH, services, mounts, and
   application data are verified.

A live file archive is not a point-in-time database snapshot. Restore databases
from application-native dumps or replication evidence.

## Disaster evidence to retain

- Pair names, OCIDs, suffix, source OCIDs, sizes, type, state, and timestamps.
- Root UUID and partition start sector.
- Staged kernel and initramfs hashes.
- GRUB entry and boot-sync procedure.
- Reserved-IP OCID and DNS names.
- SSH host-key policy.
- Object or archive digests.
- A redacted recovery report and a private identifier ledger.
- Tenancy-wide Object Storage totals and multipart-upload state.
- External encrypted-copy ciphertext hash and isolated decrypt-test evidence.

## Backblaze file-backup exclusion policy

`config/restic-excludes.txt` is the version-controlled exclusion list for the
planned restic file backup to Backblaze B2. It does not affect OCI volume
snapshots. The file is prepared policy only: the B2 backup job and restore path
are not configured or accepted yet.

Pass this file to restic's existing `--exclude-file` option when backing up the
VPS filesystem at `/`. Its paths are anchored to that root. Do not use the list
unchanged against a recovery filesystem mounted under another directory.
Do not pass an excluded directory as a separate backup source: restic does not
apply exclusions to explicitly named source paths.

The initial list excludes GitHub-recoverable repositories, downloaded Codex
executables, known caches, logs, temporary directories and virtual filesystems.
The owner has elected to exclude the whole repository directory, including
local-only files and `.env` files, whose primary copies are on the Mac. There
is no `.env` exception in this policy.

Keep the installed operating system, `/etc`, `/boot`, `/efi`, user configuration,
Codex sessions and authentication, and the package database. Do not exclude
`.codex`, `.config`, `/var/lib`, `/mnt`, or all files above a size threshold.
Container storage remains included until image sources/build instructions and
persistent data coverage have been verified. Container bind mounts outside the
repository directory need normal backup coverage.

Before the first B2 run:

1. Inventory root, EFI and staging filesystems and include their required files.
   Do not let a filesystem-boundary option silently omit EFI or staging content.
2. Preserve package versions, the Codex installation procedure, repository sync
   setup, and the two-disk partition/UUID/boot manifest in the recovery kit.
3. Preview the selected paths with this list. Confirm that excluded data is
   omitted and configuration, user data and boot files remain selected.
4. Measure actual encrypted repository bytes; directory usage is not a storage
   bill. Retain four complete accepted weekly recovery points.
5. Prove a restore that recreates excluded software and boots the two-disk system.
   A file-selection preview alone does not prove a usable backup.

Add exclusions only for a specific replaceable path, with a comment explaining
how it is recreated. Review large contributors when usage grows. Do not expand
exclusions automatically based on process names, file extensions or directory
size. Restic syntax is documented in
[Excluding files](https://restic.readthedocs.io/en/stable/040_backup.html#excluding-files).
