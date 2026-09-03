# Acceptance Checklist

Do not mark the setup complete until every required row has current evidence.
Use `templates/EVIDENCE-LEDGER.md` for raw references and
`templates/FINAL-REPORT.md` for the durable summary.

## OCI and billing

- [ ] Exactly one non-terminated instance exists.
- [ ] The instance display name is `arch`.
- [ ] Lifecycle state is `RUNNING`.
- [ ] Shape is `VM.Standard.A1.Flex`.
- [ ] Allocation is within the current continuously free OCPU/RAM allowance.
- [ ] The signed-in account page still states Free Tier or Always Free.
- [ ] The signed-in account page shows expected current spend.
- [ ] The account was not upgraded.
- [ ] The instance, boot volume, block volume, and backups are in the home
      region.
- [ ] No paid feature, cross-region copy, or retention lock was added.
- [ ] No task-created custom image remains unless it is an explicitly accepted
      recovery artifact.

## Storage and attachments

- [ ] Staging boot volume is 50 GB and Balanced.
- [ ] Arch root volume is 150 GB and Balanced.
- [ ] Total live boot plus block storage is exactly 200 GB.
- [ ] Root attachment is paravirtualized and `ATTACHED`.
- [ ] No temporary data volume remains attached or live.
- [ ] Root partition start sector matches the recorded value.
- [ ] Root filesystem UUID matches the boot contract.
- [ ] `/` is the expected ext4 partition and has the expected usable size.
- [ ] EFI is mounted at the intended path.
- [ ] No retired data mount appears in `findmnt` or `fstab`.
- [ ] `findmnt --verify --verbose` succeeds.

## Boot and operating system

- [ ] `/etc/os-release` identifies Arch Linux ARM.
- [ ] `uname -m` returns `aarch64`.
- [ ] Guest CPU and memory match the target.
- [ ] `/proc/cmdline` includes `root=UUID=<ARCH_ROOT_UUID>`.
- [ ] Staged and source kernel files are byte-identical.
- [ ] Staged and source initramfs files are byte-identical.
- [ ] SHA-256 hashes are recorded.
- [ ] GRUB defaults to the Arch entry and retains the recovery entry.
- [ ] The boot-sync log records success.
- [ ] The final post-backup start boots without manual console input.

## Services and security

- [ ] System failed-unit count is zero.
- [ ] Administrative-user failed-unit count is zero.
- [ ] Required timers are active and enabled.
- [ ] Any metrics oneshot succeeds and writes a current record.
- [ ] Any repository synchronization service has a successful unit result;
      known per-repository failures are reported separately.
- [ ] Only expected listeners exist.
- [ ] Nothing listens publicly on TCP 9090.
- [ ] SSH works for the normal administrative user.
- [ ] Recovery-user SSH works if the design keeps that account.
- [ ] The host-key fingerprint matches the recorded value.
- [ ] `PermitRootLogin no` is effective.
- [ ] `PasswordAuthentication no` is effective.
- [ ] `KbdInteractiveAuthentication no` is effective.
- [ ] Root and password-only login attempts fail.

## Network and DNS

- [ ] One reserved public IPv4 is assigned to the primary private IP.
- [ ] No obsolete ephemeral address remains.
- [ ] The primary VNIC and private-IP OCIDs match the inventory.
- [ ] Ingress permits only approved traffic, normally TCP 22.
- [ ] Required egress remains.
- [ ] DNS records use the intended proxy mode and TTL.
- [ ] Both authoritative nameservers return the reserved address.
- [ ] At least two public resolvers return the reserved address.
- [ ] A wildcard test returns the reserved address when wildcard DNS is used.
- [ ] SSH through DNS reaches the expected host key.

## Backups and recovery

- [ ] Golden boot and root backup names share one UTC suffix.
- [ ] Both are `FULL` and `AVAILABLE`.
- [ ] Source OCIDs and 50/150 GB sizes match the live volumes.
- [ ] Creation timestamps and home region are recorded.
- [ ] Backup-object count is within the current free limit.
- [ ] At least one previous accepted pair remained until the new pair became
      available and passed live acceptance.
- [ ] Retained and deleted recovery artifacts are listed.
- [ ] The Object Storage image, if kept, has a recorded digest and size.
- [ ] Local archive and overlay rules are documented.
- [ ] The recovery procedure has no dependence on the original chat session.

## Completion decision

Classify each item as:

- `proved`: current authoritative evidence directly satisfies it.
- `contradicted`: current evidence shows it is false.
- `missing`: no current evidence exists.
- `not-applicable`: the design does not use the feature, with a stated reason.

Any required `contradicted` or `missing` item blocks completion.
