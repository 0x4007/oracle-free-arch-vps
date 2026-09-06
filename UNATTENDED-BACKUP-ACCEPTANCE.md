# Unattended backup acceptance, 2026-09-06

The owner-controlled PROJECT-VISION.md at the repository root is unchanged and
remains the acceptance authority. This report continues the shared audit in
COST-SAFE-UNATTENDED-BACKUPS-HANDOFF-2026-09-06.md; it does not change
requirements.

## Shared baseline and live evidence

The canonical continuation started at 7be42b95e4851d42a9cfce193b8488f990fd3b45,
on branch codex/weekly-backup-restore-cycle-g2f1e8856a4. All 18 files in the
previous online deployment manifest matched the Pi before this work. The only
pre-existing untracked canonical file was BACKBLAZE-HANDOFF-2026-09-05.md.

A read-only Pi preflight completed at 23:07:18 UTC:

- Source RUNNING; exact staging/root attachments and volume group proved.
- One instance: 2 OCPUs, 12 GB RAM; 200 GB combined live storage.
- Three member backups, one group wrapper, one public IP. A two-member
  replacement peaks at five members and leaves zero spare slots until retention.
- Complete tenancy Object Storage inventory: 1,453,785,088 bytes used;
  18,546,214,912 bytes headroom under the conservative 20 GB bound.
- Current observed account representation and current published terms passed the
  existing free-only guard. No cloud mutation occurred in this preflight.

This establishes current resource headroom, not a universal zero-invoice claim.
The separate dated cost audit recorded historical metered storage/performance
usage on other resource IDs. It did not prove out-of-pocket invoice settlement.

The authoritative Pi journal records Oracle capture 20260906T164037Z, captured
at 16:51:34.128 UTC and complete. The Mac runtime snapshot is older and was not
used to replace the Pi state. The candidate scheduler, given those actual Pi
records, returns PERIOD_ALREADY_SATISFIED. This is a migration decision check,
not a new capture or deployed-runtime acceptance.

## Findings and changes

- F1: Candidate scheduling uses the most recent preferred weekly civil period.
  Missed weeks coalesce into one point; delayed triggers remain due. A completed
  current-period capture suppresses replay. An explicitly approved later
  one-time acceptance window can authorize one capture, with replay suppression
  afterward. The timer is persistent, checks startup, and rechecks 15 minutes
  after the oneshot service finishes. The former window is an alert grace
  period.
- F2: Candidate journals preserve the resume phase, typed failure
  classification, attempt count, next attempt, and deadline. Safe request
  failures use bounded backoff; exhausted bursts cool down for 24 hours and
  retain the same identity. Lost create responses reconcile exact recorded
  resources. Missing or conflicting identity blocks creation. Partial retention
  uses fresh inventory. Source SSH transport errors enter this same durable
  retry path; remote assertions do not. Scheduler claim finalization occurs
  under the runtime lock. Watchdog reports retry waiting, due, cooldown, or
  blocked states as unresolved failures.
- F3: The observed trial representation remains accepted only within the
  verified Always Free resource envelope. Unknown and paid representations
  remain refused. Post-trial continuity is an unverified provider-evidence gap,
  not an owner deferral and not proof of future charges.
- F4: The retained off-source kit contains the corrected serial,
  runtime-directory, and compatible-XFS tooling; manifest hashes match canonical
  source. The earlier B2 drill proved a repaired boot and application/desktop
  acceptance. Clean repeatability still needs one newly approved empty-target
  run. The Oracle group boot drill remains explicitly owner-deferred, with
  metadata proof only.

## Post-trial evidence

Official sources retrieved on 2026-09-06:

- https://www.oracle.com/cloud/free/faq/ documents continued Always Free use
  after a standard trial; special trial offers can have different suspension
  rules.
- https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
  documents post-trial Always-Free-only storage and request limits.
- Organizations API specifications 20200801 and 20230401 define legacy
  paymentModel/subscriptionTier as unrestricted strings. They do not document a
  stable mapping from the observed FREE_AND_TRIAL/FREE_TRIAL values to a
  post-trial Always-Free-only account. A FREE example alone does not prove that
  mapping.

Do not claim post-trial unattended continuity until authoritative account/API
mapping evidence is available. Do not bypass the guard or upgrade the account.

## Acceptance still required

Combined final validation, exact deployment hashes, installed scheduler
behavior, any necessary separately authorized real capture, and the canonical
GitHub review/CI/merge loop remain separate from the candidate checks above. No
new Oracle backup, B2 generation, home payload download, restore disk write, or
service restart has been performed by this continuation as of this report's
initial entry.
