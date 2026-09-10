# Troubleshooting

Use read-only checks first. Record the observed state, expected state, and exact
resource alias before changing anything. Do not use a forced action unless the
owner approves that exact action and target.

## A1 capacity is unavailable

- Confirm that the selected region is the tenancy home region.
- Check each availability domain in that region.
- Retry later if the service reports temporary capacity exhaustion.
- Do not create a paid shape, upgrade the account, or reduce recovery storage
  without an explicit design change and approval.

A volume backup does not reserve future compute capacity.

## OCI still reports RUNNING after guest poweroff

This is expected OCI behavior. Guest-only shutdown does not release the OCI
allocation. Use approved OCI `SOFTSTOP` as the normal initiating action while
the guest is running, after stateful applications are quiescent.

If guest-only poweroff has already completed, confirm SSH and application
listeners are gone and inspect serial-console or equivalent shutdown evidence.
Reread OCI state. An approved `SOFTSTOP` can reconcile the lifecycle, but OCI
can wait up to 15 minutes before forcing power-off. Immediate `STOP` remains a
separately approved fallback only after the guest is independently proved
quiescent. Never substitute `RESET` or chain a fallback automatically.

After any control-plane stop, wait for `STOPPED` before starting the instance.

## Arch does not boot

Use the OCI Console or serial console and select the retained recovery entry.
Then check:

- The root volume is attached in the correct availability domain.
- The attachment uses paravirtualized mode.
- The UUID in GRUB matches the UUID reported by `blkid`.
- The root partition begins at the recorded sector.
- The staged kernel and initramfs exist and match the Arch root copies.
- Required virtio block and network drivers are present in the initramfs.

Do not recreate a filesystem, change its UUID, or rewrite the partition table
until the target disk and recovery point have been proved and approved.

## Emergency shell cannot find the root filesystem

- Use `lsblk -f`, `blkid`, and OCI attachment metadata together.
- Compare the discovered UUID with `/proc/cmdline`, GRUB, and `fstab`.
- Wait for paravirtualized devices to appear before assuming data loss.
- Mount read-only for inspection when practical.

Never guess the root device from `/dev/sd*` ordering.

## SSH fails after boot or IP cutover

Separate transport, identity, and authentication checks:

1. Confirm the instance is `RUNNING` and the primary VNIC is attached.
2. Confirm the reserved address is assigned to the expected primary private IP.
3. Confirm the security rule permits TCP 22 from the operator source.
4. Test the IP directly before testing DNS.
5. Compare the observed SSH host-key fingerprint with the recorded value.
6. Use the normal non-root account and the intended private key.

Do not bypass host-key verification. Do not enable root or password login as a
quick repair. SSH configuration or daemon restart needs explicit approval and a
working console recovery path.

## DNS still points to the old address

- Query both authoritative nameservers.
- Query at least two independent public resolvers.
- Check the exact record name, type, value, TTL, and proxy mode.
- Allow for the previous TTL before declaring propagation failure.

Do not make repeated DNS edits while answers are still converging.

## Backup pair is incomplete

If one member fails or remains unavailable, keep every previous accepted pair.
Record the new objects as an incomplete attempt. Do not call either member a
machine recovery point and do not delete the successful half until the owner
approves the exact deletion.

Before retrying, check the current combined backup-object limit. A retry may
need a free slot, but an old accepted pair must not be deleted to make room
without explicit approval and another recovery path.

## Backup count or storage total is higher than expected

- List all active and transitional boot volumes, block volumes, and backups.
- Include restored, detached, and recently deleted resources until OCI reports
  their terminal state.
- Compare source sizes and lifecycle states with the private identifier ledger.
- Stop all creation until the count and current policy are reconciled.

Do not assume that a detached volume or a backup being deleted no longer counts.

## Staged kernel parity fails

- Check whether a kernel or initramfs update completed on the Arch root.
- Inspect the boot-sync log and available staging space.
- Confirm that the hook mounted the intended staging filesystem.
- Re-run the sync procedure only after the source and destination identities are
  verified.
- Compare both SHA-256 and byte content before rebooting.

Keep the current running kernel available until the replacement boot has passed.

## Free Tier status or limits differ

Stop before creating, growing, or copying resources. Capture the signed-in
account view and the current Oracle documentation date. Recalculate the whole
steady-state and backup plan. This kit's recorded limits are a dated baseline,
not authorization to incur charges.

## Evidence is missing

Classify the requirement as `missing`; do not infer success from an earlier
report, local file, source configuration, or a different machine. Repeat only
safe read-only checks. If a check needs an outage or mutation, obtain the exact
approval and record it in the approval ledger.

## Scheduled backup requires claim reconciliation

When the scheduler reports `SCHEDULE_CLAIM_RECONCILIATION_REQUIRED`, a stale
one-time acceptance claim has expired while the runtime recorded no OCI create
intent and no group backup ID. The terminal claim is
`.private/backup-scheduled-window.json` with status `reconciliation-required`.
The scheduler keeps skipping with that distinct reason and never allocates a
capture identity until the claim is removed. Reconcile read-only, in order:

1. Read `.private/backup-scheduled-window.json` and confirm status
   `reconciliation-required`, the recorded `reconciliation.requiredAtUtc` and
   `reconciliation.expiredAtUtc`, and that the claim names only its own window
   and period. Do not edit the claim.
2. Read `.private/backup-runtime.json` and confirm its `cycle` journal is the
   failed no-capture journal for this claim, has no
   `volumeGroupBackupIntent: true` and no `volumeGroupBackupId`, and that its
   `policy` source, accepted pair and volume-group ID still match
   `.private/backup-controller.json`. If either capture marker is present, or
   the policy binding is absent or different, STOP: an OCI operation or a
   different runtime may be involved. Keep the scheduler block, reconcile the
   exact recorded group backup identity first, and never remove the claim.
3. From the same runtime journal, record the exact `cycle.suffix` and
   `policy.volumeGroupId` (and confirm they are present and well-formed). Run
   the read-only inventory entry point (`deno task backup:inventory`, or a
   `backup:run` preflight) and confirm no new `FULL` volume-group backup for
   that exact group has the runtime suffix/display identity; the claim's civil
   period (for example `2026-09-06@America/New_York`) is not a backup suffix.
   If the runtime suffix or group identity is missing, malformed, or cannot be
   matched to the inventory, STOP and reconcile before removing the claim. Do
   not use any OCI write for this check.
4. Only after steps 1-3 pass, acquire the existing shared controller lock and
   archive both task-local records without changing their contents: move the
   failed `.private/backup-runtime.json` to a no-clobber private archive named
   with its exact runtime suffix (for example
   `.private/cycles/<suffix>.acceptance-expired.runtime.json`), and move
   `.private/backup-scheduled-window.json` to a no-clobber archive such as
   `.private/cycles/scheduled-claim-<windowId>.expired.json`. If either archive
   already exists with different bytes, STOP. Do not merely remove the claim:
   the preserved blocked runtime would continue to prevent scheduling. Do not
   delete or rewrite the schedule approval, accepted pair, any backup object,
   or any other runtime file.
5. After both archives are safely recorded, the next scheduled invocation
   creates a fresh runtime journal and claim under the latest approved
   schedule. That plan still requires the normal schedule, standing-approval
   and source-binding checks; this reconciliation approves no capture.

If `ACCEPTANCE_WINDOW_EXPIRED` is reported instead, the runtime recorded an
intent or a group ID: fail closed and reconcile the exact recorded OCI
operation before doing anything else.

## Repository synchronization returns partial failure

- Keep the nonzero result and complete failure list.
- Classify each failure as access, renamed or deleted repository, network,
  checkout, or local-state failure.
- Mark an ignored failure only with a documented owner, reason, and expiry.
- Do not convert partial success to exit zero.

## Seven-day metrics are unavailable or incomplete

The audit queries CPU from `oci_vmi_resource_utilization` and labels it as
hypervisor data. Memory and network metrics still require the guest's Oracle
Cloud Agent publisher. A permitted monitoring configuration does not establish
that the publisher is installed or running.

`telemetry-unavailable` means at least one metric has no accepted hourly data
in the requested window. Diagnose publication and the exact source query;
waiting seven days alone will not repair an absent guest publisher.
`incomplete-observation-window` means data exists but some hours are missing.
Both leave the full idle assessment unverified and return exit status 3.

Coverage requires every unique hourly timestamp in the explicit 168-hour
window, excluding its end boundary and the current partial hour. Duplicate or
out-of-window points cannot fill missing hours. Do not replace OCI metrics
with guest-local load data or generate artificial activity. Even complete
byte counters do not define Oracle's network utilization percentage.

## Application data mount is missing

The former `oracle-vps` scaffold identified a useful failure case: an application
can write into a mount directory on the root filesystem when its intended data
volume is absent. Check the exact mount target, source device and filesystem
UUID against the selected recovery metadata. A directory's existence or a
successful `findmnt -T` lookup only proves that a containing filesystem exists;
it does not prove that the intended volume is mounted at that target.

Preserve unexpected files in the unmounted directory. Do not format a device,
move data or stop production applications as an automatic repair. Keep a
recovery target's application acceptance incomplete until its actual mounts
match the recorded layout. The old scaffold's `/srv/data` layout is historical
and must not replace this machine's current filesystem identities.

## Object Storage total is incomplete

List all accessible compartments, buckets, objects, versions when enabled, and
active multipart uploads. Stop if permissions prevent a tenancy-wide result.
Report the result as incomplete instead of assuming that the known recovery
object is the only object.

## External encrypted copy cannot be verified

Do not upload plaintext as a fallback. Stop when the remote destination,
recipient key, or isolated decrypt-test location is missing. Record the control
as `missing` until the owner provides those inputs.
