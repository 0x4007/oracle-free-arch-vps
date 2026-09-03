# Agent Instructions for the Arch OCI Mirror

## Role and ownership

- Use one primary orchestrator and one live infrastructure writer.
- Read-only research and audit agents may run in parallel.
- Do not allow two agents to create, resize, attach, detach, stop, start, or
  delete OCI resources at the same time.
- Reconcile the current OCI and guest state before every mutation.
- Treat implementation, backup creation, restart, and live acceptance as
  separate stages.

## Account and cost safety

- Never upgrade the account to Pay As You Go.
- Confirm the signed-in account still says Free Tier or Always Free before
  provisioning.
- Verify current Oracle limits from official documentation. Do not rely only on
  the values copied into this kit.
- Use only the tenancy home region for resources that must remain Always Free.
- Do not enable retention locks, cross-region copies, higher volume performance,
  paid load balancers, or other paid features.
- Before creating a resource, calculate the resulting OCPU, RAM, live-volume,
  backup-count, public-IP, and Object Storage totals.
- Stop if the operation would exceed the current free allowance.

## Explicit approval gates

Obtain current, exact approval before:

- Creating or deleting an instance, volume, image, backup, public IP, or DNS
  record.
- Formatting a disk, changing a partition table, changing a filesystem UUID, or
  deleting data.
- Stopping or restarting the instance or any managed service.
- Using hard `STOP`, `RESET`, forced detach, or another unclean control-plane
  action.
- Changing SSH configuration, firewall rules, users, credentials, or package
  versions.
- Replacing or deleting the last known-good backup pair.
- Upgrading the account or accepting a paid feature.

Name the exact resource and OCID in each destructive approval request.

## Process and data safety

- Never signal, stop, restart, replace, or detach another agent, shell, browser,
  SSH session, tmux session, or its process tree.
- Inspect active OCI CLI and SSH writers before each mutation.
- Preserve dirty files, unrelated work, credentials, and private recovery data.
- Never print OCI private keys, tokens, passwords, SSH private keys, console
  connection credentials, or cloud-init secrets.
- Use the normal non-root SSH account and passwordless `sudo` only for the exact
  privileged operation.
- Do not use `root` over SSH.

## Storage and boot invariants

- The staging boot and Arch root volumes are one recovery unit.
- Never accept a backup of only one volume as a complete machine backup.
- Resolve devices from OCI attachment data, UUIDs, and `lsblk`; never assume
  that `/dev/sda` or `/dev/sdb` is stable.
- Record the root partition start sector and UUID before any resize.
- Never format or recreate the root partition during a same-start resize.
- Keep the staging kernel and initramfs byte-identical to the files on the Arch
  root.
- Keep an OCI-supported recovery boot entry.

## Backup invariants

- Give each pair one shared UTC suffix.
- Create both pair members while the instance is stopped when practical.
- Wait for both objects to become `AVAILABLE` before starting cleanup.
- Verify names, types, source OCIDs, source sizes, timestamps, and region.
- Create and validate the new pair before deleting the old pair.
- After verifying the current backup-object limit, keep one accepted pair and at
  least two free object slots before starting a rotation. The 2026-09-03
  baseline had five Always Free backup slots. A rotation briefly uses four
  objects, then removes the older pair only after accepting the new pair.
- Never describe the unpaired fifth slot as a complete machine recovery point.

## Evidence and completion

- Validate the actual OCI account page, resource API, DNS, SSH, filesystems,
  boot chain, services, listeners, backups, and recovery artifacts.
- Do not substitute a source diff, unit file, mock, or health endpoint for live
  behavior.
- A clean backup must be followed by a real start and SSH acceptance.
- Report each resource as created, attached, stopped, backed up, deleted, or
  accepted. Do not merge these states into one claim.
- If any required evidence is missing or contradictory, continue or report the
  blocker. Do not claim completion.

## Operational invariants

- Use an approved OCI `SOFTSTOP` as the normal mechanism for a planned stop.
  Quiesce stateful applications first, then verify the instance reaches
  `STOPPED`.
- Never automatically invoke immediate `STOP`, `RESET`, or
  `SENDDIAGNOSTICINTERRUPT`. On a `SOFTSTOP` timeout or error, reread OCI state
  and fail closed. Immediate `STOP` remains a separately approved fallback only
  after the guest is independently proved quiescent.
- Treat any repository synchronization error as a visible partial or total
  failure. Exit zero only for complete success.
- Use OCI compute metrics for the seven-day idle-risk report. Local load or RAM
  logs are supporting evidence, not Oracle idle-policy evidence.
- Report tenancy-wide Object Storage bytes and headroom, not only one known
  object.
- Keep external recovery copies client-side encrypted. Keep decryption keys off
  the VPS and out of this repository.
- Distinguish `METADATA_PROVED` from `RESTORE_DRILL_PROVED`.
