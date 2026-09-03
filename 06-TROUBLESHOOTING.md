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

## Repository synchronization returns partial failure

- Keep the nonzero result and complete failure list.
- Classify each failure as access, renamed or deleted repository, network,
  checkout, or local-state failure.
- Mark an ignored failure only with a documented owner, reason, and expiry.
- Do not convert partial success to exit zero.

## Seven-day metric coverage is incomplete

Report `pending-seven-day-window`. Keep collecting normal OCI metrics until at
least 167 hours separate the earliest and latest hourly points. Do not replace
OCI metrics with guest-local load data and do not generate artificial activity.

## Object Storage total is incomplete

List all accessible compartments, buckets, objects, versions when enabled, and
active multipart uploads. Stop if permissions prevent a tenancy-wide result.
Report the result as incomplete instead of assuming that the known recovery
object is the only object.

## External encrypted copy cannot be verified

Do not upload plaintext as a fallback. Stop when the remote destination,
recipient key, or isolated decrypt-test location is missing. Record the control
as `missing` until the owner provides those inputs.
