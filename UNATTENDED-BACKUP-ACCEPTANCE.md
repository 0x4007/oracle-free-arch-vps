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

## Deployment and review update, 23:34 UTC

All three worker tips are integrated in canonical ancestry:
179a2c918e0d49352be0b8a66ad89c3b423f34ac (catch-up),
65fb39618683f2ba51c54ecc94525a998bbefbe4 (safe resume), and
77abe9213e1d47bc60973d550dbc66d0e0a81c33 (free eligibility). Primary integration
corrected final claim locking, post-completion timer timing, final slot
accounting, and retry of a provably unsent create intent.

Code revision 7ba7017e1fa8466dcbed2945677bb9f8b61af3f4 passed type, format,
lint, and whitespace checks. The default suite passed 263 tests; 137
permission-gated checks were ignored. Focused changed-path tests passed without
ignored cases.

Local review round one reported two P1 eligibility defects and one P2 historical
schedule defect. The corrections recognize explicit null replica fields and
Oracle-owned platform images, keep missing metadata and paid tenant resources
refused, and calculate historical periods after validating current approval. The
original failed candidate result was retained. A corrected read-only live check
at 23:30:03 UTC passed current account, terms, Object Storage, volume
performance/autotune/replication, and image cost-surface proof.

Review round two exited successfully with no P0/P1 findings and two unresolved
P2 findings. The configured review policy prohibits starting another correction
round for lower-severity findings alone:

1. A crash after runtime completion but before claim completion can leave a
   started Oracle claim. A satisfied-period skip does not repair it, and the
   Backblaze launch gate can remain blocked until a later Oracle cycle or an
   operator reconciles it.
2. If an attempt crosses its burst deadline while running, failure handling can
   reset the burst and schedule 15-minute backoff instead of the intended
   24-hour cooldown. The cooldown implementation is therefore not fully proved.

These are unresolved reliability defects, not owner-authorized deferrals. They
keep full unattended acceptance unproved despite the passing checks above.

The Pi received all 19 deployment-manifest files with exact checked hashes.
Runtime revision: 7ba7017e1fa8466dcbed2945677bb9f8b61af3f4. Both unit files were
updated with guarded prior hashes; systemd configuration was reloaded without
restarting a production service. The timer remains active and persistent. It
fired at 23:32:33 UTC and its oneshot finished successfully at 23:32:37 UTC. A
direct invocation of the installed scheduler also returned
PERIOD_ALREADY_SATISFIED. Next automatic recheck: 23:47:37 UTC. This proves
installed timer/duplicate-suppression behavior; it is not a new capture under
the modified engine. This week's accepted Oracle capture was preserved.

At 23:33:45 UTC, the installed watchdog reported both layers current and
healthy, with no pending alerts and no notification sent. Existing B2
capture/archive verification and dated repaired-boot evidence remain separate.
No extra B2 history was manufactured. Source boot identity, VNC identity, and
running Guacamole containers were preserved across deployment. The separately
managed sales-browser invocation changed at 23:23:10 UTC, before this
deployment; this continuation issued no source service restart and does not
claim all source service identities were unchanged for the whole observation
period.

The full charter and goal remain unproved: the two P2 defects, post-trial API
mapping, a new-engine capture acceptance if required, clean B2 repeatability,
and the owner-deferred Oracle boot drill remain distinct requirements.

## Authorized correction and final review, 23:46 UTC

The owner approved correction of the two round-two P2 defects. Satisfied-period
skips now return and persist a completed stale claim under the runtime lock when
a different completed cycle proves progress beyond the claim's previous cycle.
Retry bursts reset only after an already-scheduled cooldown has elapsed; an
attempt crossing its deadline preserves exhaustion and waits 24 hours.

Validation: 32 focused tests passed without skips; the default suite reported
265 passed and 137 permission-gated tests ignored. All 11 B2 gate integration
tests passed with local read/write permission. Type, format, lint and whitespace
checks passed.

The third and final local review used base
7be42b95e4851d42a9cfce193b8488f990fd3b45 and exited successfully. It did not
repeat either corrected finding. It found one new P2: the weekly beforeCapture
path reads the latest schedule but does not validate a changed approval because
currentWindow is called only for acceptance claims. A removed or future
approvedAtUtc during preflight can therefore go unnoticed. This remains an
unresolved defect, not an owner deferral. The three-round review limit is reached;
no fourth review or further correction pass was started.

The earlier deployment receipt remains historical evidence until the correction
has a separate installed-hash and live scheduler receipt. Post-trial mapping,
clean B2 restore repeatability, and the owner-deferred Oracle boot drill remain
separate outstanding requirements.
