# Agent Instructions for the Arch OCI Mirror

## Role and ownership

- The owner-controlled charter is the canonical acceptance authority:
  `/Users/nv/repos/0x4007/oracle-free-arch-vps/PROJECT-VISION.md`. It requires
  routine backups to run online without stopping or interrupting production.
  The current online operation and acceptance contract is
  `ONLINE-BACKUP-CONTRACT.md` in this repository. Routine online group captures
  never stop, reboot, or freeze the instance or any required service. Stopping
  the instance is reserved for separately approved disaster recovery, restore,
  or one-time build work.
- Use one primary orchestrator and one live infrastructure writer.
- Read-only research and audit agents may run in parallel.
- Do not allow two agents to create, resize, attach, detach, stop, start, or
  delete OCI resources at the same time.
- Reconcile the current OCI and guest state before every mutation.
- Treat implementation, backup creation, restart, and live acceptance as
  separate stages.

## Oracle sign-in

- Agents may automatically sign in to Oracle for authorized project work using
  `ORACLE_USERNAME`, `ORACLE_PASSWORD`, and `ORACLE_TOTP_SECRET` from this
  repository's local `.env`. No separate sign-in approval is required.
- Generate the mandatory 2FA code from `ORACLE_TOTP_SECRET` using TOTP with
  SHA-1, six digits, and a 30-second period.
- Never print, log, commit, or include these secrets or generated codes in
  messages. Keep `.env` local and excluded from Git.
- Sign-in authority does not change the resource, spending, or destructive
  action approval gates below.

## Account and cost safety

- Owner authorization dated 2026-09-07: use the shared USD 300 Oracle trial
  credit responsibly for active backup-system development and testing, including
  temporary concurrent instances, disks, and services. Read
  [DEVELOPMENT-BUDGET.md](DEVELOPMENT-BUDGET.md) before planning cloud spending.
  This is a cumulative budget, not a per-agent allowance. Verify remaining
  coverage and expiry, bound each test's cost and lifetime, and clean up its
  temporary resources. Normal operation must return to one Always Free VPS and
  its complete online two-volume recovery backup, with safe rotation headroom.
- Never upgrade the account to Pay As You Go.
- Confirm the signed-in account still says Free Tier or Always Free before
  provisioning; trial-funded development also requires verified active trial
  coverage as described in DEVELOPMENT-BUDGET.md.
- Verify current Oracle limits from official documentation. Do not rely only on
  the values copied into this kit.
- Use only the tenancy home region for resources that must remain Always Free.
- Do not enable retention locks. Normal operation must not use cross-region
  copies, higher volume performance, paid load balancers, or other paid features.
  Temporary trial-funded development resources are permitted only within
  DEVELOPMENT-BUDGET.md and the explicit approval gates below.
- Before creating a resource, calculate the resulting OCPU, RAM, live-volume,
  backup-count, public-IP, and Object Storage totals.
- Stop if normal operation would exceed the current free allowance. Temporary
  development may exceed that allowance within the authorized trial budget;
  stop if available trial funding or its expiry cannot cover the operation.

## Explicit approval gates

Owner clarification at 2026-09-07 22:13 UTC grants standing authority for all
in-scope recovery development/testing and task-owned cleanup within the shared
USD 300 trial budget. Read DEVELOPMENT-BUDGET.md. For covered operations below,
apply that authority to freshly reconciled exact targets; do not ask repeatedly
or interpret an agent-selected freshness timeout as revocation. Production Arch
VPS and required services must stay online. No bulk payload may traverse Mac,
Pi or the home network. Unrelated work, account upgrades, uncovered spending,
production data destruction and loss of the last good backup remain excluded.

For operations not covered by that standing authority, obtain current, exact
approval before:

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

### Never leave an unmanaged heavy process on the host

Incident 2026-09-21/22: two `tar | zstd` pipelines from a diagnostic test kept
running for 12.5 hours after the shell that started them was killed. Killing a
parent shell does not kill its pipeline children. They were reparented to init
and landed in `user.slice/session-*.scope` instead of the backup worker's
cgroup, so `CPUWeight=1` and the IO caps never applied to them. Each `zstd` held
about 71% CPU and streamed the whole root disk continuously, degrading unrelated
production work on the same host.

**A cgroup limit only binds processes inside that cgroup.** A reparented or
otherwise escaped process is unmanaged, and the protection is worth nothing for
it. Never assume a limit is protecting production without checking which cgroup
the running process is actually in.

Rules for any backup-shaped or disk-reading workload:

- Launch it in a transient unit (`systemd-run`) that carries the same limits the
  real worker uses, and bound it with `RuntimeMaxSec`. Do not run an unmanaged
  `tar | zstd` (or similar) pipeline on the production host.
- Stop it with `systemctl stop <unit>`, never by killing a shell or a single
  child. Stopping the unit kills the whole tree.
- After stopping, verify the tree is actually gone before moving on. Check for
  orphans whose parent is 1 and whose cgroup is a user session rather than a
  managed slice:

      ps -eo pid,ppid,etime,pcpu,args | awk '$2 == 1 && $3 ~ /-/'
      for p in $(pgrep -f "tar -C /"); do cat /proc/$p/cgroup; done

- Prefer a bounded test over a full-disk sweep. A diagnostic must not read the
  entire 150 GB root volume or run for hours.
- Reconcile leftovers after every diagnostic, including failure paths, before
  starting unrelated work or handing off.

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
- Routine backups are online group captures: the instance stays `RUNNING` and
  is never stopped, rebooted, or frozen, and no required service is stopped.
  Both pair members are created by one online OCI volume-group backup. Only a
  separately approved disaster-recovery, restore, or historical build capture
  stops the instance first.
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
- A stopped build capture or restore must be followed by a real start and SSH
  acceptance. A routine online group capture must instead prove unchanged
  source boot and service continuity while the instance stayed `RUNNING`
  through capture and acceptance.
- Report each resource as created, attached, stopped, backed up, deleted, or
  accepted. Do not merge these states into one claim.
- If any required evidence is missing or contradictory, continue or report the
  blocker. Do not claim completion.

## Operational invariants

- Use an approved OCI `SOFTSTOP` as the mechanism for a separately approved
  planned outage only: disaster recovery, a restore drill, or the historical
  build cutover. Quiesce stateful applications first, then verify the instance
  reaches `STOPPED`. Routine online backups never stop the instance.
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

## Throttle values must be validated against the whole cycle budget

Incident 2026-09-22: a GPT Pro review recommended a 2 MB/s write cap, and it was
applied without checking it against this repository's own deadline. It was wrong
for this system:

- Capture writes **both** the plaintext archive and its ciphertext, so a 10.3 GB
  payload produces roughly 20.6 GB of writes, not 10.3 GB.
- At 2 MB/s that measured 3.72 h for capture alone. Capture + upload + verify
  then crossed `GATE_DEADLINE_MS` (6 h), and the verifier was killed at the
  deadline with `ORPHANED_TERMINAL_PROOF_MISSING`. The upload had already
  succeeded; the run still failed.
- The same cap would have broken every subsequent weekly run.

Before adopting any resource cap:

- Estimate the whole cycle (capture + upload + verify), not one stage, and keep
  it inside `GATE_DEADLINE_MS`.
- Account for work that is written twice, read back, compressed, or encrypted
  rather than only for the payload size.
- Measure the real stage durations before choosing a value. Prefer a cap that
  leaves clear headroom over one that only looks conservative.
- An external recommendation is input, not authority. It does not know this
  repository's deadlines, so validate it here before applying it.

## Verify what a limit actually binds

Before reporting that a limit protects production:

- Confirm the running process is in the cgroup carrying that limit. A limit on a
  unit does nothing for a process that escaped into a session scope.
- Confirm the control is not inert on this host. The root volume runs the
  `none` IO scheduler, so `IOWeight` and `IOSchedulingClass` do not arbitrate
  anything here; cgroup bandwidth caps do. Measure rather than assume.
- Distinguish a phase that is working from one that is stalled: check CPU
  (`cpu.stat`), archive growth, and the process wait channel together. A file
  that stops growing is still healthy when `zstd -t` or `zstd -dc` is consuming
  CPU, and a process that is asleep in `ep_poll` with 0 ms CPU is not.
