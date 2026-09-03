# Backup and Recovery Contract

## Core rule

The staging boot volume and Arch root volume are one machine. A backup of only
one volume is not a complete recovery point.

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

## Create the golden pair

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

1. Confirm both backup names share the intended suffix.
2. Restore the staging backup as a boot volume in the tenancy home region.
3. Restore the root backup as a block volume in the same availability domain.
4. Confirm the restored root partition still has `<ARCH_ROOT_UUID>`.
5. Launch `VM.Standard.A1.Flex` with the current free-safe OCPU/RAM allocation
   from the restored staging volume.
6. Attach the restored root volume paravirtualized.
7. Assign the reserved public IP to the new primary private IP.
8. Verify UEFI -> GRUB -> staged kernel/initramfs -> UUID root boot.
9. Verify SSH host-key expectations. A restored image may intentionally have the
   old host key; a rebuilt machine should have a newly recorded key.
10. Confirm staged kernel and initramfs parity before normal operation.

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
