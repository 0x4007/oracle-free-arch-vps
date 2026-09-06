# Online backup integration contract

Canonical lane: weekly-backup-restore-cycle-g2f1e8856a4, branch
codex/weekly-backup-restore-cycle-g2f1e8856a4. The controlling handoff is
/Users/nv/repos/0x4007/oracle-free-arch-vps/ONLINE-BACKUP-RECOVERY-HANDOFF-2026-09-06.md.

## Shared interfaces

`scripts/online-backup-contract.ts` owns the online phase and capture identity,
source continuity observation, and machine reconstruction proof types. m01 owns
the concrete policy, journal, inventory and provider adapter in its recorded
files. m02 owns only the machine restore module and its focused test. The primary
owns runtime, scheduling, guest reads, shared gates, target selection and live
acceptance. Existing B2 archive and index version 1 remain unchanged.

The ordinary Oracle path has no guest quiesce, stop, start, reboot, freeze or
process-idle operation. A provider group must bind exactly the existing staging
boot and Arch root volumes. A group backup must bind both member backup IDs and
one provider capture identity. Matching display names alone are insufficient.
New online journals use the online phases. Legacy journals remain preserved;
they cannot be replayed by the online scheduler or treated as online proof.
Equivalent approval timestamps compare by epoch while retaining original text.

The read-only guest adapter supplies `acceptSource()` and continuity observations;
it does not repair or restart services. The primary removes all mutation methods
from the scheduled/recovery entrypoint call graph. Failure leaves production
running and retains exact creation intent for reconciliation. An ambiguous create
must not trigger another create. Retention preserves every previous accepted
point until the replacement meets its required acceptance gates.

No new CLI option, environment variable or secret is part of the interface.
Resource binding and any target-write approval use the existing private JSON
configuration convention. The primary records exact target inputs before m02
starts. A reconstruction result proves extraction only; a separate actual boot,
SSH, mount, preserved-data and desktop check is required for RESTORE_DRILL_PROVED.

## Reconciled baseline, 2026-09-06

The canonical lane advanced by fast-forward from ac3a588 to the already merged
4733f8d; their file trees are identical. PRs 4, 5 and 8 are merged. The untracked
B2 handoff and unrelated RDP lane are preserved.

Live provider inventory at 14:36 UTC proves one running 2 OCPU / 12 GB instance,
200 GB live volumes, three available backups and one public IP. Exact source
attachments match. Current subscription and official free-limit checks pass,
including five backup slots and complete Object Storage accounting within its
allowance. Group eligibility and accounting require the dedicated audit.

Pi runtime journal is complete with guest.restored=true. The weekly service has
no process and retains its failed Sunday result. The two-minute recovery timer
remains installed and periodically invokes the old read path; never overwrite
its runtime while active. Five selected deployed source hashes match canonical,
and B2 deployment records source revision 2cc5298. B2 controller is COMPLETE with
two accepted generations. No active source backup worker was found. Production
boot and service identities were read without interruption.

Private read-only inventory evidence is in
.private/reports/online-initial-inventory.json and online-initial-eligibility.json.
The pending GPT Pro job 25830afe-e9a1-4503-b680-b213ebee5f80 still returned HTTP 429
at 14:36:51 UTC. Its owned retriever exited after termination; preserve the job
and do not resubmit. No GPT Pro verdict is available.

## Module assignments and concrete restore target

Both module lanes start at shared foundation
3432a45ab96856ce675715cec41f99d1884412a8. m01 uses policy.volumeGroupId,
journal.mode="online", journal.captureIdentity, and optional
BackupPair.volumeGroupBackupId. Guest operations are only acceptSource() and
observeSource(); scheduler control is beforeCapture(). The primary archives a
proved-complete legacy journal before allocating an online journal, preserving
its accepted pair and original approval text. No legacy phase is replayed.

m02 uses the first accepted generation
`generation-681c4067-aec2-45d5-9afb-77ee530e3a97`. The independent kit audit proved
its GPT, partition starts/sizes/UUIDs, six filesystem identities, LVM PV/LV
metadata, fstab, EFI records, boot files, parity hashes and swap metadata present.
Its encrypted index and archives total 8,419,333,307 bytes. The newer accepted
point has no locally decrypted metadata in the kit; do not substitute it without
retrieving and validating that metadata.

The selected proposed target is the existing Mac ARM QEMU HVF, 4 GiB RAM and two
vCPUs, with an AArch64 Linux rescue guest and two initially empty sparse 50/150
GiB disks. Proposed directory is
/Users/nv/.local/share/arch-vps-recovery/drill-20260906-online. Disk serials are
uos-restore-20260906-stage and uos-restore-20260906-root. m02 executes inside the
rescue guest against exact serial-bound devices; primary owns host launch,
download, private-key handling, clone isolation, EDK2 variables and actual boot.
Home download and destructive target setup/cleanup approval was requested with
the concrete private target request and remains pending. No target was created.

Official API/documentation and the live block-storage limits support a two-member
FULL group backup. At 14:48 UTC free-backup-count reports used=3, available=2.
No separate group-backup limit or SKU was found; wrapper accounting is an
API-backed inference and must be checked after creation before acceptance.
There are zero current groups and zero group backups. The exact group request
is prepared privately; no creation approval or provider mutation is recorded.

The scheduler accepts an optional, separately approved one-time window in the
existing private schedule record. Its start and expiry use real UTC time and
are bounded to four hours from approval. The existing claim prevents a second
attempt for that window. Weekly timing is unchanged; this is a path for actual
scheduler acceptance without a fabricated clock or a week-long wait.

Restore validation accepts provider-generated member names only with a live
FULL, AVAILABLE group record that binds the two exact member IDs, source group,
compartment, source volumes and sizes. Disaster restore approval continues to
bind the selected backups and reserved IP; group IDs are also approval-bound.

The proposed QEMU disks use SCSI behind a virtio SCSI controller so their full
serial strings remain distinct. Virtio block's shorter ID field cannot retain
the requested strings. The target sizes, files and serials are unchanged.
The B2 reconstruction module remains pending integration after review found
plaintext/ciphertext descriptor and rescue-mount accounting defects. No disk
rebuild or boot is proved by these source changes.
