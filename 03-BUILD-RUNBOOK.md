# Build Runbook

This runbook is a phase-gated procedure. Do not continue to the next phase until
the current phase has evidence and every required approval.

## Phase 0: Verify current policy and account state

1. Read the current Oracle Always Free resource page in `SOURCES.md`.
2. Open the signed-in OCI account page and record the account type and current
   spend.
3. Confirm the tenancy home region.
4. Record current service limits and current resource use.
5. Calculate the maximum 31-day continuous allocation:

   ```text
   2 OCPUs x 24 hours x 31 days = 1,488 OCPU-hours
   12 GB   x 24 hours x 31 days = 8,928 GB-hours
   ```

   These values fit the 1,500/9,000 baseline verified on 2026-09-03. Recompute
   against the current official limits.

6. Stop if the account is upgraded, the terms differ, A1 is not eligible, or the
   home region is not confirmed.

## Phase 1: Inventory and ownership

1. Assign one orchestrator as the sole OCI and guest writer.
2. List all instances, boot volumes, block volumes, attachments, backups, custom
   images, Object Storage objects, public IPs, VCN resources, security rules,
   and DNS records.
3. Inspect active OCI CLI, SSH, browser, and agent processes without signaling
   them.
4. Fill in `02-VARIABLES-AND-PREFLIGHT.md`.
5. Record a private evidence ledger from `templates/EVIDENCE-LEDGER.md`.
6. Obtain approval for the exact resources that Phase 2 will create.

## Phase 2: Create the free-tier network and instance

Use the Console or the installed OCI CLI. Check the installed CLI help before
copying commands from another machine.

1. Create or select one VCN in the home region.
2. Create or select one public subnet with an internet route.
3. Create a security list with:
   - Stateful TCP 22 ingress from an approved source CIDR.
   - Required stateful egress.
   - No TCP 9090 or public application ports.
4. Launch one supported AArch64 image on `VM.Standard.A1.Flex`:
   - 2 OCPUs.
   - 12 GB RAM.
   - 50 GB boot volume.
   - 10 VPUs/GB or the current Always Free Balanced default.
   - Paravirtualized network and storage.
   - One operator-approved SSH public key.
5. Do not create a second instance as a standby. A standby consumes the same
   allowance and does not protect the primary from idle reclamation.
6. Allocate one 150 GB Balanced block volume and attach it paravirtualized.
7. Record every OCID and the guest-visible attachment mapping.

Acceptance for this phase:

- One running A1 instance at 2 OCPUs/12 GB.
- Exactly 200 GB of live boot plus block storage.
- SSH to the supported staging OS works.
- The OCI account page still shows the intended Free Tier status.

## Phase 3: Prepare the Arch root volume

This phase destroys any data already present on the selected root disk. Obtain
approval for the exact volume OCID and confirm the disk is empty.

1. Resolve the 150 GB disk using OCI attachment metadata, stable device links,
   `lsblk`, and `blkid`. Do not select a disk only because it appears as
   `/dev/sdb`.
2. Assert the selected disk size and attachment OCID.
3. Save any existing partition table if the disk is not new.
4. Create a GPT with 1 MiB alignment. The verified geometry uses:
   - Partition 1: sectors 2048 through 1050623, EFI type.
   - Partition 2: starts at sector 1050624 and extends to the end, Linux
     filesystem type.
5. Create a FAT filesystem on partition 1 if the recovery design uses it.
6. Create ext4 on partition 2 and record its new UUID as `<ARCH_ROOT_UUID>`.
7. Mount the root under a temporary directory and mount its EFI partition at the
   intended Arch EFI path.
8. Download the current Arch Linux ARM generic AArch64 root filesystem from an
   official source. Verify its published digest before extraction.
9. Extract it while preserving numeric ownership, modes, links, ACLs, and
   extended attributes supported by the source archive and target filesystem.
10. Generate UUID-based `fstab` entries. Do not depend on `/dev/sd*` names.

Stop if the device identity, size, geometry, or filesystem UUID differs from the
recorded plan.

## Phase 4: Configure Arch for OCI A1

Work from the AArch64 staging instance so native Arch binaries can run without
cross-architecture emulation.

1. Bind-mount `/dev`, `/proc`, `/sys`, and `/run` only as needed for the
   configuration environment.
2. Configure the locale, time zone, machine name, resolver, and DHCP-based
   network service.
3. Confirm the kernel and initramfs include virtio/paravirtualized block and
   network support.
4. Create a non-root administrative user and install only the approved public
   key.
5. Configure SSH for key authentication:
   - `PermitRootLogin no`
   - `PasswordAuthentication no`
   - `KbdInteractiveAuthentication no`
   - `PubkeyAuthentication yes`
6. Validate the effective SSH configuration before any daemon restart. A restart
   requires exact approval and a serial-console recovery path.
7. Enable only required services. Do not install broad application stacks or
   perform an unrelated full-system upgrade during the boot cutover.

## Phase 5: Configure the staging boot chain

1. Discover the staging boot filesystem and existing OCI-supported recovery
   entry. Preserve it.
2. Copy the Arch kernel and initramfs to stable staging names, for example:

   ```text
   /arch-vmlinuz
   /arch-initrd.img
   ```

3. Add a GRUB entry that uses the staged files and:

   ```text
   root=UUID=<ARCH_ROOT_UUID>
   ```

4. Make the Arch entry the default only after syntax and file checks pass.
5. Add a small synchronization script and package hook that:
   - Mount the correct staging filesystem by UUID or another verified stable
     identity.
   - Copy new files through temporary names.
   - Replace the staged files atomically.
   - Compare SHA-256 hashes and byte content.
   - Write a local success or failure log.
   - Exit nonzero on any mismatch.
6. Run the synchronization once and record both source and destination hashes.

## Phase 6: First Arch boot

1. Keep an OCI Console or serial-console recovery path available.
2. Record the SSH host key before the boot change.
3. Obtain approval for the outage.
4. Run `sync`, request a clean guest poweroff, and wait for OCI `STOPPED`.
5. If the guest is off but OCI remains `RUNNING`, stop. Obtain separate approval
   before using the provider hard `STOP` action. Do not substitute `RESET` or
   `SOFTSTOP`. Use the bounded `wait-for-stopped` action in
   `07-OPERATIONS-AND-DRILLS.md`.
6. Start the same instance.
7. Verify the expected host key before accepting SSH.
8. Prove Arch, AArch64, root UUID, mounts, networking, SSH, services, and staged
   boot parity.

## Phase 7: Reserved IP and DNS

1. Obtain approval for the exact public-IP and DNS changes.
2. Allocate a regional reserved public IPv4 address within the current free
   policy.
3. Resolve the primary VNIC and primary private-IP OCIDs again.
4. Assign the reserved address to that private IP.
5. Verify the address through the OCI API and direct SSH before changing DNS.
6. Update only the intended DNS-only A records.
7. Verify authoritative nameservers and at least two public resolvers.
8. Confirm the SSH host key is unchanged after the address cutover.

## Phase 8: Golden backups and cleanup

Follow `04-BACKUP-RECOVERY.md`. Do not delete any safety point until the new
pair is `AVAILABLE`, the instance has restarted, and every acceptance check has
passed.

## Phase 9: Final handoff

1. Complete `05-ACCEPTANCE.md` against live state.
2. Write the final report from `templates/FINAL-REPORT.md`.
3. Record retained and deleted resource aliases and private OCIDs separately.
4. Create a redacted copy for sharing.
5. Run the weekly OCI and Object Storage audit. Mark a short metric history as
   `pending-seven-day-window`.
6. Record `METADATA_PROVED` or `RESTORE_DRILL_PROVED` accurately.
7. Stop. Refinement, package upgrades, and unrelated hardening need a separate
   task and approval.
