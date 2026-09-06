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
