# Automated weekly backup and first restore drill

## Canonical goal identity

- Canonical plan path and goal identifier:
  `/Users/nv/repos/0x4007/oracle-free-arch-vps/WEEKLY-BACKUP-RESTORE-CYCLE.md`.
- Goal slug: `weekly-backup-restore-cycle`; hash suffix: `g2f1e8856a4`.
- Canonical worktree name: `weekly-backup-restore-cycle-g2f1e8856a4`.
- Repository root: `/Users/nv/repos/0x4007/oracle-free-arch-vps`.
- Canonical worktree:
  `/Users/nv/repos/0x4007/oracle-free-arch-vps/.codex-worktrees/weekly-backup-restore-cycle-g2f1e8856a4`.
- Canonical branch: `codex/weekly-backup-restore-cycle-g2f1e8856a4`.
- Base ref: `main`; base SHA: `263128dfde5902659c087289cde1ddb72461b3aa`.
- Lane state: existing, created from the recorded base on 2026-09-05. The
  primary orchestrator owns this lane and is the sole implementation writer.

## Continuation handoff

Goal: Use canonical worktree name weekly-backup-restore-cycle-g2f1e8856a4 at /Users/nv/repos/0x4007/oracle-free-arch-vps/.codex-worktrees/weekly-backup-restore-cycle-g2f1e8856a4 on branch codex/weekly-backup-restore-cycle-g2f1e8856a4; read AGENTS.md and /Users/nv/repos/0x4007/oracle-free-arch-vps/WEEKLY-BACKUP-RESTORE-CYCLE.md in full, then act as the primary orchestrator and sole implementation writer to set up and live-verify automated weekly paired backups and the first isolated full restore drill, honor the recorded recurring authorization without asking for it again, resolve the remaining schedule and controller choices while progressing independent work, obtain only the separate exact approvals still required for the drill and other excluded actions, complete the required GitHub delivery loop, and keep implementation and final validation in this canonical worktree and branch.

The plan currently exists as an untracked file in the original `main` checkout.
Preserve it there as the stable handoff authority; include an identical copy in
the implementation branch for delivery and reconcile later plan amendments.
No implementation, timer activation, fresh backup or drill has run for this goal.

## Objective

Back up the current Arch VPS as one matched staging-boot and Arch-root volume
pair, restore that new pair to an isolated temporary machine, prove recovery,
and run future weekly backup rotations without a person approving every run.
Keep the ongoing monthly bill at zero. Trial-funded drill resources must not
become permanent dependencies. Weekly backups allow up to seven days of data
loss; application data may need a separate, more frequent backup later.

## Verified starting state — 2026-09-05 UTC

- Repository: `/Users/nv/repos/0x4007/oracle-free-arch-vps`; `main` at
  `263128dfde5902659c087289cde1ddb72461b3aa`; clean before this plan.
- Console: `arch` running at 2 OCPUs and 12 GB in Ashburn. Trial expires
  September 29, 2026. Oracle's July 21 notice, edited August 24, states the
  reduced 2/12 Always Free allowance. Do not use trial capacity as proof of
  ongoing free eligibility.
- Private configured OCI CLI works. Queries in the configured compartment show
  a 50 GB boot volume and 150 GB root volume, and three AVAILABLE FULL backups:
  the matched `arch-stage-golden-20260903T191507Z` and
  `arch-root-golden-20260903T191507Z` pair, plus the separate 100 GB
  `arch-root-pre-consolidation-20260903T165853Z` backup.
- This is a compartment inventory, not proof of tenancy-wide headroom.
- System and `codex` user timers were inspected over normal-user SSH. No backup
  timer was visible. Existing timers include updates, repository sync and
  metrics. Docker workload inventory needs a privileged read; the normal-user
  query was denied. Do not infer there are no containers.
- `weekly:audit` reports usage and idle risk; it does not create backups.
- `oci-restore.ts` currently requires FULL pairs, zero existing live storage,
  no existing live instance, and an unassigned reserved IP. Its restore approval
  expires after one hour. It is not suitable for a side-by-side drill as-is.
- `04-BACKUP-RECOVERY.md` describes incremental rotation, which conflicts with
  the current FULL-only restore validation. Use FULL pairs for the first slice;
  do not schedule incremental pairs until actual restore support is proved.

## Design

Use one external controller and one infrastructure writer. Keep the controller
outside the backed-up VPS and independent of its disks, network and processes.
Select an existing reliably available host before implementation; do not assume
the Mac stays awake or provision another host without approval. If the Pi is
chosen, read its maintenance instructions first. Keep OCI credentials outside
the VPS and reuse the existing private JSON configuration convention.

Proposed schedule: Sunday 04:00 America/New_York, pending the user's answer.
Skip an unattended catch-up outage outside the approved maintenance window.
Measure the first full-backup outage before enabling the schedule. Do not promise
a short outage before that evidence exists.

Weekly state machine:

1. Acquire an exclusive controller lock and reconcile OCI, guest state, writers,
   account eligibility, all tenancy resources and free backup slots.
2. Check that the prior accepted pair remains available and that the selected
   source instance, attachments, UUID and volume sizes match the private policy.
3. Quiesce the inventoried stateful applications and sync disks. Abort before
   SOFTSTOP if quiescence cannot be proved. Do not interrupt another agent or job.
4. Request SOFTSTOP and verify STOPPED. Never fall back to hard STOP or RESET.
   OCI may force power-off after its SOFTSTOP grace period; quiescence must
   precede the request. Treat timeout or contradictory state as failure.
5. Create both FULL backups with one UTC suffix. Persist each returned OCID
   immediately. Resume from recorded state after a controller interruption;
   reconcile before retrying any creation to avoid duplicate objects.
6. Wait for both AVAILABLE; verify source IDs, sizes, suffix, type, region and
   timestamps. A partial pair is not a complete backup.
7. Start the original VPS and verify SSH, mounts, boot-file parity and actual
   application behavior. Provide bounded recovery on backup failure so that an
   ordinary failed backup does not leave the source stopped indefinitely;
   preserve incomplete backup evidence and never label it clean or accepted.
8. Accept the new pair only after all required checks. Delete only the exact
   older complete pair allowed by the rotation policy, after the replacement is
   accepted. Never delete the last accepted pair or an unrelated backup.
9. Record completion and backup age outside the VPS. An independent watchdog
   must detect missed runs as well as explicit failures. Select and authorize
   the notification destination before sending messages.

## First full cycle and isolated restore

First create a fresh pair using the same automation intended for weekly use,
restart and accept the original VPS, then restore that fresh pair for the drill.
Keep the previous accepted pair until this first restore drill passes.

The drill adds one temporary 2 OCPU / 12 GB A1 instance and 200 GB of volumes:
the known running footprint would become 4 OCPUs / 24 GB and 400 GB of live
storage. This exceeds the ongoing Always Free allocation. Verify trial coverage,
current prices, remaining credits, capacity, all other tenancy use, a spending
cap and a cleanup deadline before approval. Do not run the drill after trial
expiry under this authorization or upgrade the account.

Create a distinct drill path that cannot move the production reserved IP or
change production DNS. Enforce isolation before the clone's first boot, at the
network level, including egress and access to production. A cloned VPS contains
real credentials and can otherwise run duplicate sync, scheduled jobs, agents,
Tailscale identities or outbound messages. Define how the controller reaches
the isolated guest; do not solve reachability by opening unrestricted access.
Do not modify the original production network to isolate the clone.

Restore both exact backup objects. Resolve attachments rather than assuming
device names. Verify root UUID/start sector, GRUB/recovery boot entry, staged
kernel/initramfs parity, SSH host-key expectations, filesystems, representative
data and applications through the isolated guest's actual runtime. Use safe
read-only application checks; suppress external effects. Distinguish masked
services from services actually tested. Record `RESTORE_DRILL_PROVED` only when
the intended acceptance checklist passes; metadata alone stays
`METADATA_PROVED`.

Delete only recorded drill resources after the approved cleanup step, and prove
that production still works and tenancy use returned to its original footprint.
Do not schedule weekly paid restore drills; weekly rotation remains free, and
this first full drill is a separate trial-funded operation.

## Approval and remaining decisions

On 2026-09-05 at approximately 01:51 UTC, the user explicitly approved recurring
authorization with: "recurring auth approved". This authorizes the weekly cycle
described above for the existing `arch` VPS: quiesce the required applications,
clean SOFTSTOP, create a matched backup pair, restart the source, verify live
recovery, and delete the older accepted pair only after its replacement passes
the required checks. Do not request this recurring authorization again.

This user authorization takes precedence over per-run approval requirements in
repository AGENTS.md for those bounded operations. Bind the standing policy to
the reconciled exact source instance and volume IDs in the private configuration;
do not allow display-name matching to authorize a different source. Record this
as standing approval, not fabricated fresh one-hour approvals, and preserve the
separate one-hour approval check on the disaster restore path.

Before activation, resolve the maintenance window, controller host, exact
quiesced services and notification destination. The schedule question remains
unanswered; recurring authorization does not select a maintenance window or
authorize outbound messages to an unspecified destination. This authorization
does not include hard STOP/RESET, deletion of unrelated backups, paid drill
resources, production IP/DNS changes or new network/security permissions.

There are currently three backup objects. The first new pair would use all five
published slots. Either approve temporary use of the fifth slot for this cycle,
or obtain exact approval to delete the unrelated pre-consolidation backup after
confirming its owner and need. Do not delete it merely to simplify rotation.
Reinventory the whole tenancy before choosing either option.

Separate exact approval remains required for the first drill's paid resources,
isolation and cleanup. Include known OCIDs in destructive requests in the private
approval surface; keep identifiers and credentials out of this public plan.
Controller host, notification destination, maintenance window, measured outage,
price cap and exact application quiescence list remain unresolved.

## Implementation and acceptance

Use one writer in the canonical lane; no delegated modules are needed. Add the
small Deno backup workflow and isolated drill path, reuse OCI execution and
private state helpers, then add the approved controller schedule. Preserve the
strict disaster-restore path. Do not install or enable a timer during planning.

Focused tests cover interrupted/duplicate runs, overlapping controllers, a
partial backup pair, failed quiescence, SOFTSTOP ambiguity, original restart
failure, wrong resource IDs, retention safety, trial expiry and forbidden
production-IP moves. Run repository check, fmt, lint and tests after changes.
Live acceptance requires the fresh pair, the source restart, isolated restore,
real guest/application evidence, verified cleanup, a scheduler-triggered run,
and a tested missed-run/failure signal. Report implementation, backup creation,
source restart, restore proof and scheduled operation as separate states.

Complete the required focused GitHub delivery loop for implementation. This
planning artifact alone does not claim automation, backup creation or recovery.

## Sources

- `AGENTS.md`, `04-BACKUP-RECOVERY.md`, `07-OPERATIONS-AND-DRILLS.md`.
- https://community.oracle.com/customerconnect/discussion/970310/oci-always-free-updated-ampere-a1-compute-allocation
- https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- Signed-in OCI instance and cost overview inspected in this conversation.

## Execution checkpoint — 2026-09-05 02:01 UTC

The primary orchestrator created the exact canonical lane from the recorded base.
The canonical branch remains at `263128dfde5902659c087289cde1ddb72461b3aa`.
The handoff copy is untracked pending implementation delivery; no implementation,
controller installation, schedule activation, outage, backup creation or drill
has occurred. The original handoff and canonical copy are reconciled identically.
This turn made progress by establishing the lane and collecting new live evidence;
it was not a wait on an infrastructure operation.

Current evidence:

- OCI reports one subscribed region, Ashburn, marked as the home region, and
  one accessible active compartment including the tenancy root. The inventory
  contains one RUNNING A1 instance at 2 OCPUs / 12 GB, one 50 GB boot volume,
  one 150 GB root volume and the same three AVAILABLE backups listed above.
- The configured restore and audit instance IDs match the live instance.
  The configured source volume IDs match its ATTACHED boot and root volumes;
  the root attachment is paravirtualized.
- Network inventory contains one production subnet, one reserved public IP,
  no NSGs on the primary VNIC and existing production ingress/egress rules.
  There is no existing isolated subnet suitable for the drill. A separate
  approved network design is still required before clone launch.
- The signed-in account overview states Free Tier / Free Trial, shows trial
  usage of $0.00 out of $300.00 and expiry on September 29, 2026. This displayed
  balance can lag metering and is not a hard spending cap.
- Oracle's Always Free documentation now directly states 1,500 OCPU hours and
  9,000 GB hours monthly, 200 GB combined live boot/block storage, five combined
  volume backups and 20 GB Object Storage. A search summary contradicted the
  official backup rule; the official page is authoritative.
- The current Oracle price list displays $0.01/OCPU-hour, $0.0015/GB-hour of A1
  memory, $0.0255/GB-month storage and $0.0017/VPU/GB-month. At 10 VPUs/GB,
  the extra 2/12 plus 200 GB drill footprint costs about $0.04981/hour in
  September before trial credits, excluding any separately selected services.
  No spending cap or cleanup deadline has been approved.
- The weekly audit completed Object Storage accounting: 1 bucket, 1 object,
  1,453,785,088 bytes, no stored versions or multipart uploads. It exited 3
  because compute metrics cover only four hours (five hourly points from
  September 3), so seven-day idle-risk evidence remains incomplete.
- Guest reads show Guacamole and guacd containers, Caddy, VNC and Tailscale,
  with active Codex processes and another SSH shell. Do not interrupt them.
  Both containers use `unless-stopped`; explicitly stopping them requires
  recording and restoring their running state after source startup.
- The live root UUID matches the configured value. The root partition starts
  at sector 1050624. No disk was changed or mounted for this inspection.
- The Pi is reachable with about 258 MiB available RAM out of 464 MiB and
  approximately 30 hours uptime. Deno binaries exist, but OCI CLI is absent
  from its normal PATH and no default OCI configuration was found. Its user
  manager is degraded due to an existing failed `sync-orgs.service`. No Pi
  package, credential, service or configuration was changed.
- Installed OCI backup-create help does not expose an `--opc-retry-token`
  option. Do not assume retry tokens are supported. Persist creation intent
  before each request, persist returned IDs before waiting, reconcile exact
  names/source IDs and fail closed on unresolved ambiguous creation.

Private evidence lives in the existing repository-root `.private/reports/`:
`weekly-cycle-inventory.json`, `weekly-source-binding.json`,
`weekly-network-inventory.json`, and `weekly-20260905T015744526Z.json`.
The canonical worktree uses an ignored symlink to that existing private folder.
No identifiers or credentials were copied into tracked files.

Pending user input: select the external controller, weekly maintenance window
and notification destination. The asynchronous question is outstanding. The
plan requires selecting the controller before implementation. Recurring backup
authorization remains accepted; do not request it again. Temporary occupation
of all five backup slots and the exact paid drill/isolation/cleanup exception
remain separate decisions. Gather concrete drill targets before requesting the
final drill approval. No GitHub delivery action has occurred for this goal.

## Controller decision — 2026-09-05 02:06 UTC

The user selected the existing Pi with: "lol ok then have the pi handle it thank".
Use pi@pi.local as the external controller. Controller selection no longer
blocks implementation. Keep its memory safeguards. The maintenance window and
notification destination remain pending. This choice does not approve the
separate paid drill or unrelated backup deletion.

## Implementation checkpoint — 2026-09-05 02:21 UTC

The Pi selection is recorded above. Local implementation now contains:

- `scripts/weekly-backup.ts`: journaled paired-backup state machine with exact
  standing-approval/source binding, creation-intent reconciliation, preserved
  initial pair, source acceptance before retention, and bounded recovery hooks.
- `scripts/oci-backup-inventory.ts`: live read-only tenancy inventory, including
  all availability domains and both reserved and ephemeral public IP scopes.
  It uses the source instance ETag, not a nonexistent `time-updated` field.
- `scripts/backup-lock.ts`: OS file lock; its inode must never be unlinked while
  controllers use it. A local real-lock smoke check proved serialized access.
- `tests/weekly_backup_test.ts`: 14 focused state-machine tests. The repository
  suite has 27 passing tests; check, fmt and lint pass for this checkpoint.
- `deno task backup:inventory` and `config/weekly-backup.example.json` provide
  a runnable read-only entry point. The private Mac config reuses the existing
  exact IDs and OCI profile and is not in Git.

The inventory entry point ran successfully against OCI at 02:18:30 UTC and
recorded one instance, 2 OCPUs, 12 GB, 200 GB live volumes, three backups and
one public IP, with source attachments proved. Its private report is
`.private/reports/weekly-controller-inventory.json`.

These are implementation foundations, not working backup automation. The actual
OCI mutation adapter, guest quiescence/acceptance adapter, active-job interlock,
isolated drill, scheduler, watchdog and GitHub delivery remain unfinished.
All implementation is currently uncommitted in the exact canonical worktree;
no task branch was pushed and no PR was opened. Do not claim live backup proof.

Pi preflight confirms Deno 2.9.2 runs through `safepi` and Python/pip are present.
OCI CLI is absent. The installed Mac OCI CLI version is 3.91.0. No package or
credential was installed or copied to the Pi. A strict Pi-to-VPS SSH probe
first failed because the VPS host key was not known. A second probe used a
temporary file containing the existing Mac-trusted host keys, removed on exit;
host verification then passed but authentication failed with publickey denied.
The Pi has an existing ED25519 public key, but the VPS does not accept it.

Pending exact setup approval covers OCI CLI 3.91.0 in
`/home/pi/.venvs/oci`, the existing OCI profile and signing key under
`/home/pi/.oci` with private permissions, a verified VPS host-key pin on the Pi,
and authorization of the Pi's existing SSH public key for the `codex` account
on the VPS. The requested fingerprint is in the private setup-approval file.
Repository AGENTS.md separately gates package, credential and SSH changes.
The maintenance-window and notification questions remain pending. The fifth
backup slot and paid drill/isolation/cleanup are still separately unapproved.

## Pi setup accepted — 2026-09-05 02:35 UTC

The user answered "yes" at approximately 02:22 UTC to the exact Pi package,
credential and SSH setup request. That setup is complete; do not request it
again. The private approval record is `.private/pi-controller-setup-approval.json`.

- OCI CLI 3.91.0 installed successfully in `/home/pi/.venvs/oci`. Installation
  used a systemd scope capped at 220 MiB and 70% CPU and exited zero. It took
  about ten minutes; no process was restarted or replaced while waiting.
- The existing DEFAULT OCI profile and its signing key were copied securely to
  `/home/pi/.oci`. Directory mode is 0700; both private files are 0600.
- Existing Mac-trusted VPS host keys were pinned on the Pi. The Pi's existing
  ED25519 public key was appended to the VPS codex account's authorized keys
  with `restrict`; existing authorized keys were preserved. Strict verified
  SSH from Pi to `codex@vps.pavlovcik.com` succeeded.
- The read-only inventory deployment at `/home/pi/ops/weekly-backup-controller`
  matches all seven source/config hashes recorded in
  `.private/reports/pi-controller-deployment.json`. It is a deployment artifact,
  not a second implementation checkout or branch.
- `safepi deno task backup:inventory` ran on the Pi and exited zero at
  02:35:49 UTC. OCI returned one instance, 2 OCPUs, 12 GB, 200 GB live storage,
  three backups and one public IP; exact source attachments were proved.
  The private result is retained on the Pi and copied to
  `.private/reports/pi-controller-live-inventory.json` on the Mac.

This proves controller-host setup, OCI access and SSH access only. No timer,
backup, outage, restore drill or notification has run. The incomplete code and
GitHub delivery remain as listed in the implementation checkpoint. Schedule,
notification destination, temporary fifth-slot use and the separate exact
paid-drill/isolation/cleanup approval remain unresolved.

## Recovery and activity checkpoint — 2026-09-05 02:50 UTC

The canonical branch remains at the recorded base with uncommitted implementation.
Pi setup remains accepted. This checkpoint made no OCI mutation or managed-service
change and did not enable a schedule.

- The OCI operations adapter now takes the expected stopped ETag for creation
  and START, and rejects a different ETag immediately before either operation.
  START also sends the fresh matching ETag as its conditional request.
- Fixed the resumed `start-requested` phase to reject a later stopped epoch,
  rather than starting an instance stopped by someone else after interruption.
- Added three adapter tests and one restart regression. All 31 repository tests
  pass. Full check, format check and lint pass after the changes.
- Added `scripts/backup-guest-activity.ts`, a read-only Unix-socket WebSocket
  probe. The exact source ran successfully through normal-user SSH on the VPS
  and reported zero loaded app-server threads at approximately 02:49 UTC.
  It does not resume or interrupt a thread and logs no thread contents or IDs.
  Its temporary loopback listener and connections close after the probe.
- The plain-JSON proxy probe timed out because the control transport is
  WebSocket, not newline JSON. All diagnostic processes created here ended.
- The activity result is only a point-in-time observation, not an admission
  lock. It is not yet wired as a sufficient unattended-shutdown interlock.
  Other processes, SSH sessions, background work and new job admission still
  require reconciliation before quiescence.

Official source used for the probe protocol:
https://learn.chatgpt.com/docs/app-server (fetched in this session).

The concrete guest quiescence/recovery/acceptance implementation, controller
eligibility evidence, runtime wiring, isolated drill and scheduler/watchdog
remain unfinished. No new adapter or probe has been deployed to the Pi.
The earlier Pi inventory deployment is still the only deployed controller slice.
No backup, outage, drill, notification, commit, push or PR occurred here.
The maintenance-window and alert-destination question was reissued asynchronously;
no answer has arrived. Separate fifth-slot and drill approvals remain pending.

## Full Pi preflight accepted — 2026-09-05 03:17 UTC

This turn made substantial implementation and live read-only progress. It did
not run a backup, outage, restore clone, timer, or outbound notification.

New canonical implementation:

- `backup-guest.ts`: exact production-host guest adapter. It records container
  IDs and original running state, persists stop intent before each application
  stop, checks for loaded Codex threads, other shells/jobs/browsers, active
  maintenance jobs, unknown running services and active application sessions.
  It stops only the two inventoried Guacamole containers and the Caddy and
  ShadowsocksR application units, then restores their recorded state. No stop
  operation has been run live. It rejects exit 137 as clean quiescence and
  requires successful systemd stop results. HTTP acceptance reads Guacamole
  application markup with bounded retry; boot acceptance compares exact files.
- `backup-controller-evidence.ts`: live Organizations subscription API proof,
  current official Always Free terms, tenancy Object Storage accounting and
  controller-process inspection. No account proof is a hardcoded true value.
- `backup-runtime.ts`: OS-locked entry point with private config at
  `.private/backup-controller.json` and one private transaction containing
  policy, backup phase and guest intent at `.private/backup-runtime.json`.
  `deno task backup:run` supports preflight and cycle through private config.
  Completed ordinary rotations can advance the accepted pair for a new cycle.
  A completed first cycle that retains its prior pair refuses another cycle
  pending the first drill and retained-pair reconciliation. That reconciliation
  workflow remains to be implemented alongside the drill.
- `oci.ts` private JSON writes now fsync the file and parent directory around
  atomic rename. A real Mac write/fsync smoke passed.
- Object Storage accounting now counts old versions when bucket versioning is
  suspended, as well as enabled. A focused regression covers this case.
- `isolated-drill.ts`: initial, non-executable drill policy/approval and launch
  request validators. It binds an exact plan digest, fresh pair, trial coverage,
  price bound, separate network and cloned volumes. No creation or cleanup
  adapter exists yet. Three focused tests pass; do not call this a ready drill.

Validation: full check, format check and lint pass. The full suite passed with
39 tests before the drill validator was added; its three additional focused
tests also pass (42 total individual tests passed across these runs).

Live evidence:

- OCI Organizations list/get returned one ACTIVE subscription with billing
  `FREE_TRIAL`, tier `FREE_AND_TRIAL`, and trial end
  `2026-09-29T23:59:59.999000+00:00`. The private subscription inventory and
  details are retained in `.private/reports/subscription-*.json`.
- Current official Always Free HTML was fetched and retained privately; it
  confirms 1,500 OCPU-hours, 9,000 GB-hours, 2/12 steady allocation, 200 GB live
  volume storage, five combined backups and 20 GB Object Storage.
- Guest read-only acceptance passed on the live VPS. In a private mount
  namespace, the exact staging UUID was mounted `ro,norecovery`, then unmounted.
  Both boot files match byte for byte, and the Oracle Linux fallback is present.
- The read-only activity script is deployed at
  `/home/codex/ops/weekly-backup-controller/backup-guest-activity.ts`.
  This is the only new VPS file; no managed process was restarted.
- All 12 controller source files and deno.json deployment entries were hash
  verified on the Pi (12 files total) after checking the earlier deployment
  manifest for drift. Record: `.private/reports/pi-runtime-deployment.json`.
- Pi runtime config action is `preflight`; `allowFifthSlot` remains false and
  `retainPreviousPair` remains true. The old inventory config remains intact.
- `safepi deno task backup:run` exited zero on the Pi at
  `2026-09-05T03:11:05.893Z`. It proved account, terms, storage, source attachment,
  guest activity, boot and served application checks. Totals remained one
  instance, 2 OCPUs, 12 GB, 200 GB live volumes, three backups and one public IP.
  It correctly reported `twoBackupSlotsApproved: false` and no mutation.
  Local evidence: `.private/reports/pi-backup-preflight.json`.
- Pi-to-VPS SSH source address was captured privately for a future /32 drill
  ingress rule at `.private/reports/pi-ssh-network-source.json`.
- All tool sessions from this checkpoint are terminal.

Remaining safety/design work:

1. The guest activity checks are point-in-time checks, not a new-job admission
   barrier. Resolve how to prevent a new Remote or SSH job entering between the
   idle check and SOFTSTOP without interrupting another job or making an
   unapproved SSH/firewall/managed-daemon change. Do not overstate this proof.
2. Oracle documents that security rules are NOT enforced for 169.254.0.0/16,
   including metadata/platform services. The proposed separate VCN with empty
   egress rules proves only routed-traffic restrictions. The validator is named
   `verifyDrillRoutedNetwork` and explicitly is not full first-boot isolation.
   Resolve link-local/platform access or offline suppression before building a
   runnable clone launcher. Official source fetched:
   https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm
3. Complete drill lifecycle, exact remaining approvals, first backup/source
   acceptance, clone runtime acceptance and cleanup, retained-pair release,
   scheduler/window enforcement, independent missed-run/failure signal, and
   the required GitHub delivery loop.

The fifth-slot approval was explicitly requested asynchronously at 03:11 UTC;
no answer has arrived. It asks only to occupy both currently free slots while
preserving all three existing backups. Recurring backup authorization and Pi
setup authorization remain accepted and must not be requested again. The
maintenance-window and alert-destination questions are also unanswered.
Do not activate cycle mode or a timer from silence. No paid drill resources,
new isolation/security permissions or cleanup operations have been approved.

Canonical branch and HEAD remain unchanged at the recorded base. All task
implementation is uncommitted, with no push or PR. Preserve the exact lane.

## Scheduler, watchdog and recovery checkpoint — 2026-09-05 03:43 UTC

This turn made implementation and read-only live progress. All 49 tests pass;
check, format check, lint and whitespace checks pass on the canonical state.
No backup, outage, timer installation, drill resource or notification has run.

- `backup-schedule.ts` validates a recorded approved maintenance window,
  generates a non-persistent weekly timer, and derives one civil-date identity
  per window, including repeated DST hours and overnight windows. Its watchdog
  assessment detects a missed run as the approved window closes, plus failed,
  stalled, missing, malformed and stale backup states. Six focused tests pass.
- `backup-scheduled.ts` checks the clock and claims the current window while
  the runtime holds the controller OS lock. Completed/failed window attempts
  cannot cause a second outage. Interrupted started windows can resume the
  recorded transaction. These claim/restart paths still need a focused runtime
  exercise and actual scheduler-triggered acceptance before activation.
- `backup-watchdog.ts` writes a private status report and exits nonzero for an
  unhealthy or unconfigured schedule. It sends no notification. It ran on both
  Mac and Pi and correctly returned SCHEDULE_NOT_CONFIGURED, healthy=false,
  notificationSent=false. No schedule approval file exists.
- Uninstalled systemd templates are in config/weekly-backup.service and
  config/weekly-backup-watchdog.{service,timer}. The weekly timer is generated
  only from an approved window. No unit was installed or enabled.
- Fixed a real recovery defect: source restart no longer depends on being able
  to refresh official limits, account evidence or backup inventory after an
  outage. `BackupOperations.recoverySnapshot` checks the exact source instance,
  2/12 shape, attached boot/root volumes and writers independently. The existing
  stopped-ETag guard remains on START. A regression proves recovery after an
  eligibility-evidence failure. The actual read-only recovery snapshot passed
  against OCI and the VPS; evidence is .private/reports/recovery-preflight.json.
- Updated the Pi deployment, preserving private config and checking the prior
  deployment for drift first. All 16 deployed source/task files match canonical
  hashes in .private/reports/pi-runtime-deployment.json. Action remains preflight.

Admission and isolation findings:

- The existing VPS systemd-user-sessions service controls /run/nologin, and PAM
  checks it. Codex's installed CLI provides daemon enable/disable-remote-control;
  current settings report remoteControlEnabled=true. No setting or service was
  changed. An additional access-drain mechanism would require careful recovery
  behavior and is not proved. Do not claim the point-in-time checks are a lock.
- The original plan requires inspection of active work and aborting when it is
  present; it did not prescribe additional login or Remote changes. The first
  supervised cycle can use the implemented fresh checks immediately before
  SOFTSTOP. Do not turn the later admission research into a new per-run approval
  gate or silently change the user's login/Remote behavior. Unattended runtime
  acceptance must still exercise the actual busy-job refusal behavior.
- The guest uses DHCP and the systemd-resolved stub, with no explicit DNS override
  observed in the inspected main network/resolver files. The current DNS server
  is Oracle's exempt link-local resolver. The drill validator now requires a
  separate DHCP options object advertising a non-resolving TEST-NET address,
  together with empty routed egress and Pi-only SSH ingress. It rejects the
  production VCN/subnet and default recursive resolver. OCI link-local platform
  services remain an explicit limitation; do not claim all link-local traffic
  is filtered. This remains a non-executable draft until actual first-boot
  application isolation, lifecycle and cleanup are implemented and accepted.

All tool sessions from this checkpoint are terminal. The canonical branch stays
at the recorded base; changes remain uncommitted and no PR exists. The fifth-slot,
maintenance-window and alert-destination questions remain unanswered. The separate
paid drill/isolation/cleanup approvals have not been obtained. Continue toward the
full objective; do not mark complete or blocked merely because inputs are pending.


## Validation checkpoint — 2026-09-05 03:55 UTC

Reconfirmed the canonical worktree, branch and unchanged base HEAD. Full type
check, format check, lint, all 51 tests and Git whitespace checks pass together.
The completed-cycle recheck regression preserves an accepted journal when a
later read-only API check fails. The scheduler entry-point smoke evidence is
in `.private/reports/scheduler-entry-smoke.json`; it proves outside-window and
duplicate-window refusal without network or command-execution permissions.
The read-only drill preparer requires an accepted fresh cycle before producing
a draft. No fresh cycle exists yet, so no drill plan or approval was produced.

The latest completed-cycle fix and drill preparer remain local and have not
been deployed to the Pi. All implementation remains uncommitted; no push or PR
has occurred. No outage, backup, timer, drill resource or notification ran.
The prior Pi setup approval is already fulfilled. Temporary fifth-slot use,
maintenance window, alert destination and exact drill approvals remain pending.


## Deployment and live activity checkpoint — 2026-09-05 04:02 UTC

This turn made live deployment and acceptance progress. Under the existing Pi
controller file lock, verified every prior deployment hash before updating
weekly-backup.ts and adding prepare-isolated-drill.ts. All 17 deployed files
match canonical hashes. Deployment evidence remains
.private/reports/pi-runtime-deployment.json. No service was restarted; action
remains preflight and allowFifthSlot remains false.

The actual Pi guest-control adapter passed an idle baseline, refused a temporary
self-owned SSH job with exit 20, then passed the idle check after that job exited
naturally. No process was signalled and no application was stopped. Evidence is
.private/reports/pi-busy-job-refusal.json. This proves point-in-time busy-job
refusal, not an admission lock. An earlier baseline returned exit 1; a separate
read showed one Codex process, no pending systemd jobs and no established
application-port connections, and the next complete exercise passed. The
initial transient refusal was not bypassed or treated as permission to stop.

First-boot isolation remains unresolved; no clone launcher is enabled. New
read-only source evidence confirms /usr/bin/nft exists and mkinitcpio uses
base/systemd/autodetect/microcode/modconf/kms/keyboard/sd-vconsole/block/filesystems/fsck
hooks. The initramfs includes udhcpc executables; their presence alone neither
proves nor disproves networking before systemd-networkd. Do not claim early
firewall ordering is proved without inspecting the actual initramfs units.

Official Oracle recovery documentation confirms cloned boot volumes can attach
as data to a separate Linux recovery instance in the same availability domain.
The attachment documentation distinguishes reattaching an instance's own boot
volume from replacement on another instance. Do not assume an arbitrary boot
swap is supported by a plain attach call. Retrieved authoritative pages are
retained privately as recoveringlinuxbootvolume.html,
attach-compute-boot-volume-attachment.html and
detach-compute-boot-volume-attachment.html in .private/reports/.

A candidate offline-preparation approach uses a temporary Oracle Linux recovery
helper with a 50 GB boot disk to modify only the restored Arch root before its
first boot. This would raise peak storage to 450 GB instead of the plan's 400 GB;
it is a proposed design change, NOT approved scope or a new resource allocation.
A question about this choice was sent at 04:01 UTC. If accepted, implement and
review exact isolation, helper lifecycle and updated cost/cleanup proof before
requesting resource creation. Do not weaken the strict disaster restore path.

The fifth-slot, maintenance-window and alert-destination questions are still
unanswered. No backup, outage, timer, drill resource or notification ran. The
canonical branch remains at the recorded base with uncommitted task changes;
no push or PR exists. All tool sessions from this checkpoint are terminal.


## User decisions — 2026-09-05 04:18 UTC

The user replied: "Approved / What / I guess midnight Sunday idk". This approves
temporary use of all five free backup slots while preserving all three existing
backups, and selects Sunday 00:00 America/New_York for future weekly starts.
Recorded the exact-source exception in .private/first-cycle-slot-approval.json;
allowFifthSlot is now true on both Mac and Pi private controller configurations.
The schedule is recorded in .private/backup-schedule.json on both hosts. Use a
conservative 15-minute initiation window; this is not an outage-duration promise.
No timer is installed or enabled pending the remaining live/alert acceptance.

Explained that the recovery helper would prepare copied disks before their first
boot and then be deleted, while production remains Arch. The user's "What" was
a request for explanation, NOT approval of the helper or paid drill resources.
A helper-choice question and free-text alert-destination question remain pending.
The first supervised backup can now proceed under the existing recurring approval
and newly accepted fifth-slot exception. Preserve all three existing backups.


## First cycle started — 2026-09-05 04:24 UTC

Pi full preflight passed at 04:23:20.783 UTC: one instance, 2 OCPUs, 12 GB,
200 GB live volumes, three backups and one public IP; current account, allowance,
Object Storage, guest and source proof passed, and twoBackupSlotsApproved=true.
Added phase-only stderr reporting to backup-runtime.ts and deployed it under the
controller lock after verifying all prior hashes. Its type, format, lint and
whitespace checks pass; deployment manifest is current for all 17 files.

Activated Pi config action=cycle under the lock, requiring matching exact-source
slot approval, recent successful preflight and absent prior runtime journal.
The real Pi backup:run command started at approximately 04:24 UTC. Its local
exec session handle is 78262. It is live as of this checkpoint; poll that handle
before any retry and do not infer completion from missing console output.
Do not open other Pi/VPS SSH sessions while its writer checks are running.
The controller saves authoritative private state on the Pi, not the Mac copy.
It preserves all three existing backups. No timer is enabled.


## Failed first attempt, source recovered — 2026-09-05 04:37 UTC

The first real cycle did NOT create a backup or request instance shutdown. Its
exec handle 78262 is terminal with exit 1. Phases observed on the actual Pi:
quiescing at 04:27:43.277, quiesced at 04:28:31.482, failed at 04:31:47.890 UTC.
A newly present Chromium session (with a flock parent under the codex user)
made the active-work check return 21 after the applications had been stopped.
The controller correctly refused SOFTSTOP; the VPS itself never stopped.
Do not terminate or bypass this browser session to make a backup pass.

Found a real recovery defect: recoverySnapshot also required guest idle, so
it refused to restore the applications after detecting the new browser work.
Restored only this transaction's exact recorded containers and services using
the existing acceptSource adapter, under the Pi controller lock and its writer
check. It verified UUID/boot parity and actual served Guacamole markup, then
saved guest.restored=true and cycle.recoveryStatus=running-accepted at
04:33:38.185 UTC. The conservative application-maintenance span from entering
quiescence to acceptance was 354.908 seconds; this is an upper bound, not an
exact independently measured HTTP outage. No other session was stopped.

Removed the guest-idle requirement only from recoverySnapshot. It still checks
exact source, attachments and controller ownership; START retains its stopped
ETag guard, and shutdown retains the guest activity refusal. A new regression
proves busy guest work blocks SOFTSTOP but permits read-only recovery checking.
All 52 tests, type check, format check, lint and whitespace checks pass. The fix
is deployed to the Pi after checking prior hashes; the 17-file manifest is
current. No Git commit, push or PR exists yet.

The new recoverySnapshot passed against the live source at 04:36:26.686 UTC:
RUNNING, exact attachments proved, recovery read accepted. The same script
confirmed that the normal active-work check still refuses the existing browser.
Evidence: .private/reports/recovery-with-active-work.json. Failure/recovery
summary: .private/reports/first-cycle-failure.json. The accepted failed journal
has been copied from Pi to .private/backup-runtime.json on the Mac.

Pi action was returned to preflight under the lock. The failed journal remains
intact; do not call cycle mode again and expect it to retry a failed phase.
Once the source is idle, reconcile the failed cycle, prove no backup intents or
IDs and accepted guest recovery, preserve it in the existing cycles archive,
then initialize a fresh cycle under the same standing approval. Recheck live
inventory before that cycle. Do not ask for recurring or fifth-slot approval
again. All three existing backups must remain preserved through the first drill.

Sunday 00:00 America/New_York with a 15-minute initiation window is recorded on
both hosts. No timer is installed. Alert destination and the proposed recovery
helper remain unanswered. A readiness question was sent at 04:36 UTC asking the
user to tell us when the VPS browser work is finished; this is not a request to
repeat backup approval. All tool sessions from this checkpoint are terminal.
The canonical branch remains unchanged at the recorded base with task changes
uncommitted. This turn made live failure/recovery and implementation progress.


## Chromium closed and retry started — 2026-09-05 04:47 UTC

The user explicitly authorized terminating Chromium after moving the work to
another machine. Reconciled the codex-owned main browser PID 238736, its flock
parent and /usr/lib/chromium/chromium executable, then sent TERM only to that
main process. It and its Chromium/crashpad/flock helpers exited. No other
session or process was signalled.

The next idle probe returned exit 1 because six established Shadowsocks client
connections remained on port 8388; Codex count was one, pending systemd jobs
were absent, and all inspected desktop/web ports had zero connections. This
was an overbroad gate: ordinary proxy clients are drained by the already-approved
shadowsocksr maintenance shutdown. Removed only 8388 from that connection gate;
agent, shell, browser, desktop and other port checks remain. Type, format, lint,
five guest tests and whitespace checks pass. Deployed backup-guest.ts under the
controller lock after checking all prior hashes; the 17-file manifest is current.

The actual Pi idle check then passed. Under the lock, proved the previous failed
journal had accepted guest recovery and no stop request, backup intent or backup
ID. Preserved it at .private/cycles/<previous suffix>.json and initialized a new
planned cycle with the same approved policy. No existing backup was deleted.
Pi action is cycle. The fresh backup:run exec session 82067 began at about
04:47:22 UTC and is live. Poll that handle before any retry; do not open parallel
Pi/VPS SSH sessions while its active-writer checks run. No timer is enabled.


## Second attempt recovered; third attempt live — 2026-09-05 05:02 UTC

Exec 82067 is terminal, exit 1. It entered quiescing at 04:50:44.115, quiesced
at 04:51:32.256, and failed before SOFTSTOP at 04:54:50.051 UTC with guest exit
20. Automatic recovery now worked: guest.restored=true, recoveryStatus=
running-accepted at 04:55:41.842. A separate live read confirmed both containers
running and caddy/shadowsocksr active. No instance stop or backup creation
occurred. The transient process was gone on inspection; do not invent its
identity or blame Chromium, which remained closed.

Added bounded busy-process diagnostics to backup-guest.ts: only a validated
process name, PID and parent PID may appear in the error, never command arguments
or arbitrary remote output. Eight actual Pi read-only probes passed between
04:58:30 and 04:59:03 UTC; evidence is on Pi at
.private/reports/idle-probe-series.json. Applications stayed online during them.

The post-quiescence checkpoint in weekly-backup.ts now uses the existing exact
source/attachment/controller read, followed by fresh guest checks and the guarded
SOFTSTOP call, instead of another slow tenancy-wide inventory while applications
are down. A stop creates no resource. Full account, allowance and prior-pair
inventory still runs before quiescence and before each backup creation. A new
regression proves attachment drift at this checkpoint prevents shutdown and
recovers applications. The full 52-test suite/check/fmt/lint passed before that
new test; all 18 weekly tests pass after adding it (53 individually passing tests
across runs). Both source changes are hash-verified on the Pi; the 17-file
manifest is current. All work remains uncommitted at the recorded base.

Under the Pi lock, verified accepted recovery with no stop request, backup intents
or backup IDs, passed another live idle check, preserved the second failed
journal in the existing cycles archive, and created a fresh planned journal.
Exec 34378 began backup:run at approximately 05:01:39 UTC and is LIVE. Poll this
exact handle before retrying anything. Do not open parallel Pi/VPS SSH sessions
while the controller's writer checks run. Pi action remains cycle. All three
original backups remain protected; no timer, drill or notification is enabled.


## Source stopped; backup phase live — 2026-09-05 05:12 UTC

Exec 34378 remains live; poll this handle, do not restart. Actual phase output:
quiescing 05:04:55.546; quiesced 05:05:45.079; stop-requested 05:06:26.122;
stopped 05:10:58.597; backing-up 05:10:58.861 UTC. An independent read-only Mac
OCI GetInstance confirmed the exact original source STOPPED at 05:08:07.745 UTC.
The source is now genuinely stopped for this approved clean paired backup.
Do not end operational supervision or leave it stopped without handling source
recovery. Backup creation IDs have not yet been reported to the operator; the
Pi private journal is authoritative. All three original backups remain protected.


## Fresh pair and repaired source accepted — 2026-09-05 05:47 UTC

Exec 34378 is TERMINAL, exit 1 after creating both full backups and restarting
the original VPS. New suffix: 20260905T050131Z. An independent OCI API read
confirmed both the 50 GB staging-boot backup and 150 GB Arch-root backup AVAILABLE
at 05:18:41.450 UTC; the strict pair validator passed. Evidence is
.private/reports/first-live-pair-observation.json and first-fresh-pair-metadata.json.
The controller logged pair-available at 05:21:56.853, start-requested at
05:25:10.878; a separate GetInstance read confirmed RUNNING at 05:25:59.442 UTC.

Post-start acceptance failed at 05:28:37.598. Recovery restored the containers,
Caddy and Shadowsocks, but two pre-existing startup defects were exposed:
- vncserver.service's Perl wrapper probes INADDR_ANY on port 5901, mistakes
  Tailscale's own listener for a desktop, and loops with exit 98. No Xvnc existed.
- codex-remote-daemon.service is Type=oneshot without RemainAfterExit, so its
  daemon does not remain in a live service cgroup when startup returns.
- Found an acceptance bug too: systemctl is-active with multiple units returns
  success if ANY unit is active. Healthy Tailscale hid failed VNC. The old
  recoveryStatus=running-accepted was insufficient proof and was not trusted.

Applied and retained two minimal source recovery overrides, with original units
preserved at /home/codex/ops/weekly-backup-controller/pre-recovery-units-20260905T0536/:
- vncserver.service.d/backup-recovery.conf runs the existing Xfce/Xvnc session
  directly on loopback with the existing password file and Xauthority; it leaves
  Tailscale's listeners intact. The failed unit's existing retry started it after
  systemd manager reload. No working desktop session was stopped.
- codex-remote-daemon.service.d/backup-recovery.conf sets RemainAfterExit=yes.
  Loaded the manager configuration and started the inactive existing daemon unit;
  it now remains active with one codex process. No auth or pairing was changed.
Canonical templates are config/vncserver-backup-recovery.conf and
config/codex-remote-backup-recovery.conf. Direct service reads prove VNC active /
running, Codex active / exited with its daemon present, and Xvnc listening only
on 127.0.0.1 and ::1. A real framebuffer capture shows a working Xfce desktop:
.private/reports/vps-desktop-after-backup.png. Chromium remains closed.

backup-guest.ts now checks every required system/user service separately and
verifies the actual Codex control API, without requiring zero loaded threads for
recovery. A regression proves healthy Tailscale cannot hide failed VNC. All 54
tests, lint, type/format and whitespace checks passed on the updated source;
strict acceptance is deployed and hash-verified on Pi. No commit/push/PR yet.

Operator reconciliation exec 5441 is TERMINAL and succeeded at 05:45:54.069 UTC.
Under the controller lock it archived the original failed journal as
.private/cycles/20260905T050131Z.failed.json, refreshed full OCI/account/allowance
and protected-pair evidence, proved RUNNING and five backups, and passed the
strict guest acceptance including boot parity, each service, Codex API and actual
Guacamole markup. It then recorded source-accepted and let the engine complete
without deleting old backups. Canonical Pi state is now phase=complete,
recoveryStatus=running-accepted, guest.restored=true. Pi action returned to
preflight. Current state and source-recovery-acceptance.json are copied to Mac.

This was NOT a clean unattended success: manual startup repairs were required.
The fresh backup predates those two startup fixes; restoration of this pair must
include the supplied overrides. Do not imply that the fixes are already in its
immutable volumes, or create another pair when all five slots are occupied.
All three original backups remain preserved. No restore drill is proved, and
no timer or alert is enabled. Sunday 00:00 New York is still the recorded start.

Read-only prepare-isolated-drill.ts began on Pi at 05:47 UTC in exec 35075. It is
live at this checkpoint; poll that handle. Its output is a DRAFT, not approval.
The helper choice, alert destination and exact paid drill/isolation/cleanup
approval remain pending. No OCI clone/helper/network resource has been created.


## Scheduler review correction checkpoint — 2026-09-05 06:01 UTC

Read-only drill preparer exec 35075 completed successfully, exit 0. Its private
DRAFT_REQUIRES_APPROVAL artifact is copied to Mac at
.private/isolated-drill-plan.json, SHA256
2473cc531439321a0ee5bb7bbf7ea3f256688079e88d577f07ae0480e037d594.
The draft projects 2 instances / 4 OCPU / 24 GB / 400 GB / 5 backups / 2 IPs,
with a four-hour estimate of $0.1992222222 before credits. It does not include
the proposed helper disk or complete first-boot isolation. No resource approval
is recorded and no helper, clone or network has been created.

Local Codex review rounds 1 and 2 completed with exit 0; logs are in
.private/reports/codex-review-round-{1,2}.log. Corrected their substantiated
P1 findings and the related P2 window finding:
- Interrupted outage journals enter recovery only before schedule checks. This
  does not depend on account/limits inventory and cannot create or retire backups.
- The approved window is reread immediately before quiescence, after inventory.
- Failure records persist recoveryStatus=needed before attempting recovery, so
  another crash cannot leave a failed-phase journal with lost recovery intent.
- A separate recovery entry point and uninstalled systemd timer check after boot
  and every two minutes; they cannot initiate a fresh outage or backup cycle.
- Exact source, attachment, active-writer and stopped-epoch guards remain.

All 60 tests, type check, formatting, lint and whitespace checks pass locally.
These latest changes are NOT deployed to Pi yet. Local review round 3 (the final
permitted round) started in exec 21670 at 06:01 UTC; poll that exact handle before treating it as terminal. Do not launch a fourth round.
No timer or alert is installed or enabled. Pi action remains preflight as last
verified. Source/backup acceptance remains the 05:45 operator-assisted result;
no unattended success or restore proof is claimed. The branch remains at base
263128dfde5902659c087289cde1ddb72461b3aa with uncommitted task work and no PR.

Read-only source inspection recorded the full initramfs listing and network unit
configuration in .private/reports/drill-first-boot-inspection.txt. It contains
no systemd-networkd service; root is ext4. Boot file hashes are recorded there.
Current OCI Oracle Linux A1 helper image candidates were inventoried read-only in
.private/reports/drill-helper-image-inventory.json. This is preparation only.
The alert destination is still pending; no outbound message is authorized.


## Reviewed recovery deployment checkpoint — 2026-09-05 06:06 UTC

Final permitted local Codex review (round 3, exec 21670) is TERMINAL, exit 0.
It reports no P0/P1 finding and one P2: OCI can return 404 after successful backup
deletion before the waiter sees TERMINATED. The current deletion adapter treats
that as failure, so unattended retirement still needs this concrete defect
resolved as part of rotation acceptance. Do not start a fourth review round or
claim an entirely clean review. Full log: .private/reports/codex-review-round-3.log.

The scheduler/recovery corrections are deployed to the Pi under the existing
controller lock, after validating every previous hash. All 18 deployed runtime
files match canonical source; manifest .private/reports/pi-runtime-deployment.json.
Deployment exec 9616 is TERMINAL, exit 0. Controller action remains preflight.
No units were installed and no timer was enabled.

Real entry-point smoke tests ran on Mac and Pi using copies of the accepted
journal, with no command-execution or network permissions: recovery reports
NO_SOURCE_RECOVERY_NEEDED, scheduled backup reports OUTSIDE_APPROVED_WINDOW,
and both leave the copied journal unchanged. Pi systemd-analyze --user verify
also accepted the recovery service/timer definitions. Exec 49648 is TERMINAL,
exit 0; evidence .private/reports/pi-review-recovery-smoke.json and
review-recovery-entry-smoke.json. These are refusal/definition checks, not a
scheduler-triggered live backup or failure recovery acceptance.

A direct VPS read at 06:04 UTC confirmed Chromium closed and every required
system/user service active. Private offline helper sequence is drafted in
.private/reports/drill-offline-preparation-design.md; it remains unapproved and
non-executable. The helper and clone are proposed to run sequentially, keeping
peak compute at 4 OCPU / 24 GB while peak live storage temporarily reaches 450 GB.
Exact costing, trial credit evidence, first-boot isolation implementation, resource
approvals, drill and cleanup remain unfinished. Alert destination remains pending.
All tool sessions from this checkpoint are terminal. No new outage or OCI mutation
occurred during these review corrections.


## Git delivery and CI checkpoint — 2026-09-05 06:12 UTC

The controller implementation is committed and pushed as
17cbfc6b81016ccb30a0e25d0c41d9bfcf9d2f81. Draft PR #4 is open:
https://github.com/0x4007/oracle-free-arch-vps/pull/4.
It remains draft because the full restore, cleanup, retention, alerts and
scheduler-triggered live acceptance are unfinished. Do not merge or claim the
full goal complete yet. The canonical worktree and branch are unchanged.

Current main had an additional publication-audit workflow commit
5c24670a3ab09821f4a305bcf2156f3956d15e48, which was merged without replacing
source work. The first PR check (run 33948981574) failed because the existing
workflow referenced 18 absent encoded audit payload parts. Recovered those exact
public blobs from closed PR #3 and proved the decoded SHA256 equals the existing
workflow pin 5cdc6b11d7b1f3a8dc79708bc459645b8a0c3b14de736fbf56e0febc2013f701.
The legacy variant also matches its existing pin and both scripts pass bash -n.
Added only the exact legacy-commit fetch required because its history is not
reachable from current branch heads. No audit rule or hash pin was weakened.
CI repair commit ddd25be is pushed; run 33949125730 completed SUCCESS.
This audit checks its named publication/legacy targets, not live backup behavior.

Source code remains validated by 60 tests/check/fmt/lint and the recorded Pi
smokes. The single review P2 deletion-404 finding remains recorded, not fixed.
No fourth review is permitted. No P0/P1 issue remains from the three reviews.
No OCI resources, source outages or notifications occurred in this continuation.
All local tool sessions are terminal. The alert destination is still unanswered.
Next substantive work is executable isolated-copy preparation and the exact
reviewable helper/clone approval package, followed by the drill and cleanup.


## Offline preparation and approval package — 2026-09-05 06:40 UTC

The prior continuation made progress: controller recovery fixes were deployed,
committed, pushed, and publication CI passed. This continuation also made concrete
implementation and read-only evidence progress. No blocking-turn count applies yet.

New canonical scripts/drill-offline-preparation.ts generates the copied-root
firewall/startup bundle and a guarded helper command. It checks the helper's live
metadata identity, exact copied OCI attachment IDs and consistent device paths,
50/150 GB disk sizes, no existing mounts, copied UUIDs, root start sector, and exact
kernel/initramfs/GRUB hashes before remounting only the copy writable. Path checks
precede directory creation. It retains boot bytes and the Oracle recovery entry,
requires Arch as the default, masks copied timers/Remote/Tailscale/sync work, and
adds the two startup overrides that postdate this backup. No helper command ran.

The drill plan now includes the exact helper image and a digest of the isolation
files. The guarded command refuses changed files. Helper and clone are sequential:
peak footprint 2 instances / 4 OCPU / 24 GB / 450 GB / 5 backups / 2 IPs. Current
positive Oracle prices give a conservative four-hour estimate of $0.2110277778,
with a proposed $0.50 operating budget. This is not an OCI-enforced spending cap.
The old 400 GB draft is superseded; no user approval is implied by this update.

All 63 tests, type check, format check, lint and whitespace checks pass. The final
generated helper Python and shell parse successfully. Actual Arch nft --check
passed in a separate network namespace with host firewall rules unchanged. The
source GRUB was inspected read-only and defaults to Arch. Containers use host
networking and loopback, so local app acceptance needs no external egress.
Evidence: .private/reports/drill-{nft-syntax-check,preparation-syntax-fixture}.json,
drill-source-grub.cfg and drill-first-boot-inspection.txt. These checks do not prove
a restored first boot. The three Codex review rounds remain exhausted; this new
preparation code has focused checks, not an additional Codex review verdict.

All 19 current runtime files are hash-verified on Pi under its controller lock;
manifest .private/reports/pi-runtime-deployment.json. Deployment exec 80881 and
read-only preparer exec 10028 are TERMINAL, exit 0. Pi remains action=preflight
with no timer installed or enabled. Its refreshed draft and guest bundle are
copied to Mac. Plan SHA256:
2ebae94bd793037c67c870bcea30a84823a1c8258e9b601f23275f0e8decaaa7.

Fresh Organizations API evidence confirms ACTIVE FREE_TRIAL / FREE_AND_TRIAL,
$300 promotion and September 29 trial expiry. Cost API reports $0.001857775537
across four USD rows with no next page; billing can lag. Official Oracle pricing
API responses for B93297, B93298, B91961 and B91962 confirm the positive rates used.
Do not use that API's older free-hour bands instead of the stricter current
Always Free documentation. Reports are retained as drill-current-subscription,
drill-current-billed-usage, drill-billed-usage-summary and drill-price-*.json.
All related read-only command handles (11643, 45192, 59056) are terminal.

Concrete private approval surface: .private/drill-approval-package.md and .json.
Package SHA256:
4dd722e6d8d4acfc15065a8920807eb2c46b9a94d8c578816427873c2687335b.
It binds 10 reviewed creation request templates, source backups, helper image,
controller public key, file hashes, budget, isolation steps and cleanup gates.
The installed CLI schemas were checked; launchVolumeAttachments is supported in
CLI help/SDK despite being absent from its generated example. Templates remain
DRAFT and placeholders may be filled only with this package's recorded new IDs.
The Pi public key matches the already-approved setup fingerprint; no private key
left Pi. Before copied-disk attachment, mask helper lvm2-pvscan@.service to prevent
its Oracle Linux LVM tools activating the staging disk's old volume group. Bind
helper SSH trust to OCI console host-key evidence before remote preparation.

No helper/clone/network was created. Separate user approval of this package is
required before provisioning. Exact cleanup approvals must include the new OCIDs
once they exist; do not delete a resource merely to meet the budget. Refresh live
source/account/limits/controller-IP evidence and validate all package hashes before
any approved mutation. The alert destination remains unanswered. The existing
P2 deletion-404 finding, retained-pair release, live drill/cleanup, unattended
acceptance, alerts/timers and final PR merge remain unfinished.


## Native timer fixture acceptance — 2026-09-05 06:49 UTC

Offline preparation is committed and pushed as bb7424bc2ed91575a14874cd9ab5210f11299e27.
PR #4 remains draft. Its exact-head publication CI run 33950532613 passed.
All 63 source tests remain passing; no source code changed in this continuation.
The concrete drill package was explicitly presented for approval at 06:43 UTC.
No approval reply or alert destination has arrived. Do not treat automatic goal
continuation as authorization for the new resources or outbound messages.

This continuation made independent live controller-test progress. An agent-owned
one-shot systemd timer on Pi invoked a fixture harness through safepi. Deno had
only private-file read/write permissions, no network or command execution. It
proved scheduled outside-window refusal, recovery no-op for an accepted complete
journal, watchdog exit 1 for a failed cycle, and watchdog exit 1 for a missed
maintenance window. These were temporary state copies; the actual Pi config
remains preflight and its completed journal is byte-identical to the canonical
copy. Their file mtimes predate the test. No OCI mutation or notification ran.

Initial evidence collection (exec 67940) exited 1 because it searched only the
parent service journal for the success marker. The harness itself succeeded;
safepi attributes its command output to a separate systemd scope. Read-only
recovery (exec 34917) found the exact scope's TIMER_FIXTURE_SMOKE_PASSED marker
and the parent service's successful completion. Both handles are terminal.
Evidence is .private/reports/pi-timer-fixture-smoke.json, including both journals
and the collector correction. The two agent-owned transient units were stopped
and removed; no permanent weekly/recovery/watchdog timer was enabled.

This does not replace scheduler-triggered real backup, actual source recovery,
external failure alerts or restored-guest acceptance. Those remain unfinished.
The outstanding approval and destination are required user inputs; repeat timer
fixtures, broad checks or stale billing polls are not substitutes for them.
The previous goal turn and this turn both made progress; this is the second
consecutive goal turn with the concrete drill approval pending. Apply the blocked
audit only when its full three-turn threshold and actual impasse are satisfied.


## Approved drill and Mac alerts — 2026-09-05 11:27 UTC

The user approved the exact private drill package at 11:07:23 UTC. The immutable
package and all 14 bound artifacts still match their recorded hashes. Separate
approval record: .private/drill-user-approval-20260905T110723Z.json, copied to Pi.
Do not request creation approval again. Exact cleanup approval remains separate.

Pi source preflight passed at 11:14:17 UTC with live boot/application acceptance:
1 instance / 2 OCPU / 12 GB / 200 GB / 5 backups / 1 IP. A further drill refresh
passed at 11:19:04 UTC: exact fresh pair, helper image, controller IPv4, ACTIVE
FREE_TRIAL / FREE_AND_TRIAL and current official limits. Object Storage contains
1,453,785,088 bytes with no multipart uploads. Billed usage still reports
$0.001857775537; this is lagging usage, not a verified remaining-credit balance.
Evidence: .private/reports/drill-approved-refresh.json.

The approved VCN, SSH-only security list, custom DHCP, gateway, route and subnet
are created. IDs and durable creation intents are in Pi's
.private/drill-creation-journal.json (also copied to Mac). The four-hour deadline
is 15:19:43 UTC. The helper launch was rejected at 11:23:19 UTC with HTTP 400:
“If LaunchOptions is provided, NetworkType must be specified.” The original
request/package remain immutable. The corrected request adds only the selected
image's PARAVIRTUALIZED networkType plus the actual created subnet ID.
.private/drill-launch-helper-corrected.ts rechecks full inventory, account, image,
network and absent helper name before retry, and preserves the rejected intent.
Its Pi run is live in exec session 6612 as of this checkpoint; poll before any
new mutation. No copied disks or clone exist yet. No production outage occurred.

At 11:17:34 UTC the user selected Mac push notifications with records stored on Pi.
The existing Pi-to-Mac SSH connection and installed terminal-notifier work; no
package or credential change was needed. New backup-mac-alert.ts is called by
backup-watchdog.ts, writes status transitions before sending, retains undelivered
events for retry and does not resend delivered events. Config is private at
.private/backup-notification.json; records are .private/backup-alerts.json.
The queue failure/retry/no-duplicate smoke passed. The first fixture attempt had
a scoped-write permission error caused by the private symlink; the corrected
fixture explicitly grants the same private directory by both paths and passed.

All 20 Pi runtime files match canonical hashes after deployment. The first
deployment attempt refused a 0644 task payload; setting that one private payload
to 0600 allowed the unchanged deployment guard to pass. Actual Pi test notification
was received by Mac at 11:25:22 UTC, verified by terminal-notifier's exact group
listing and Pi's saved delivery record. Evidence: mac-alert-queue-smoke.json and
mac-alert-live-test.json. No permanent timer is enabled yet.

All 63 source tests and check/fmt/lint/whitespace checks pass. Three Codex review
rounds remain exhausted; no fourth was started. Mac alert changes are pending
commit at this checkpoint. The P2 retirement-404 issue and full restore, cleanup,
retention and scheduler acceptance remain unfinished; PR #4 stays draft.


## Live copied-volume preparation — 2026-09-05 12:13 UTC

Mac alerts were committed and pushed as f8ad6c9447fc911d3c1849b37f7a7232e8c215d5.
Its publication CI run 33963424638 passed. The canonical lane remains unchanged.
The approved helper is now RUNNING; both exact restored 50/150-GB copies reached
AVAILABLE, attached to it, passed real offline preparation, and cleanly detached.
The original VPS stayed online and all five backups remain preserved.
Current drill peak is 2 instances / 4 OCPU / 24 GB / 450 GB / 5 backups / 2 IPs.
The deadline remains 15:19:43 UTC. No clone has been launched.

The helper SSH key was proved against OCI console output. The first capture
read only the default 10 KiB; requesting the full capture exposed the matching
fingerprint. LVM pvscan was masked before copied-disk attachment. The helper
and staging copy share platform-image filesystem UUIDs, so preparation excludes
mounted disk trees when selecting the copied staging partition.

Real OCI/Oracle Linux execution exposed compatibility defects that static
fixtures missed. Fixed only those needed for the approved operation:
- OCI forbids an explicit device path for a boot volume attached as data. The
  corrected request omits that field; the root keeps its OCI consistent path.
- Live OCI metadata contains Unicode; the command payload now uses UTF-8 before
  base64 encoding. This failure happened before any helper command or intent.
- Oracle Linux lsblk lacks START, so the same partition-start check reads kernel
  sysfs. Its default JSON is flat without NAME; explicitly request --tree.
- Boot device selection requires one unmounted tree with the expected UUID;
  all descendants must be unmounted. The helper's own mounted disk is excluded.

The original approved package and source snapshot are retained unchanged. The
compatibility amendments and exact old/new hashes are recorded separately in
.private/drill-execution-amendments.json. The approved isolation-file digest,
resource identities, firewall rules and budget did not change. The two failed
helper reads stopped before any mount/write; their intents/results were archived
before retries after proving /mnt/arch-drill absent.

The successful helper command proved copied UUIDs, sizes, root start sector,
GRUB and kernel/initramfs hashes, wrote the approved isolation/startup files,
remounted the root read-only, and unmounted both filesystems. It returned
OFFLINE_FILES_PREPARED with the approved plan hash and firstBootProved=false.
The actual resolved boot/root disk paths were recorded for independent detach
checks. Both data attachments are now DETACHED, after UUID/size/unmounted/holder
checks. The CLI --force option used on detach only skips its confirmation prompt;
it is not an unclean detach mode. No hard STOP or RESET was used.

All 65 source tests, check/fmt/lint/whitespace checks pass. No fourth Codex review
was started. Live records remain authoritative on Pi in
.private/drill-creation-journal.json and .private/reports/drill-offline-live-*.json.
The exact helper cleanup request is being generated in exec session 67135; poll
that session before reading .private/drill-helper-cleanup-request.{json,md}.
The request requires a new exact approval for helper SOFTSTOP/termination, its
own 50-GB boot disk deletion and ephemeral-IP release. Preserve both detached
copies and the network for the already-approved Arch clone launch. No cleanup
approval has arrived. Full restored-guest proof, cleanup/source acceptance,
retention release, the P2 deletion-404 issue, timer activation/real scheduled
acceptance and final PR merge remain unfinished.


## Exact helper cleanup pending — 2026-09-05 12:20 UTC

Compatibility fixes are committed and pushed as
61e3688ff7cde785c4a92e66f9acb51b288f562a; CI run 33965484673 passed. All 20 Pi
runtime hashes were recopied and match canonical source. Cleanup-request exec
67135 and push exec 38198 are terminal, exit 0. No tool session remains live.

The concrete cleanup request is ready at
.private/drill-helper-cleanup-request.{json,md}, on both Mac and Pi. It proves
only the helper's own 50-GB boot volume remains attached, both prepared copies
are detached/AVAILABLE, the source is RUNNING, and the helper's ephemeral IP
belongs to its VNIC. Exact approval was requested asynchronously at 12:16 UTC;
no reply has arrived. Do not interpret the earlier creation approval as this
separate deletion approval. The deadline remains 15:19:43 UTC.

.private/drill-cleanup-helper.ts is prepared on Mac and Pi and type checked. It
refuses to execute without a separate .private/drill-helper-cleanup-approval.json
binding the exact request SHA256 and user approval. Once approval arrives,
record it without modifying the request, then run through safepi. The script
rechecks source/helper/copy identities and attachments, syncs the helper, uses
SOFTSTOP without a hard fallback, waits STOPPED, and terminates only the helper
with its own boot disk. It verifies the exact helper disk/IP disappeared, both
copies remain AVAILABLE, all five backup IDs remain and source footprint is
1 instance / 2 OCPU / 12 GB / 400 GB / 5 backups / 1 IP before clone launch.
It has NOT executed. The original creation package's four-hour execution scope
remains in progress; its initial creation began within the one-hour initiation
window. No clone has booted and no RESTORE_DRILL_PROVED claim is permitted.


## Clone launch gate prepared — 2026-09-05 12:27 UTC

The previous goal turn made live infrastructure and notification progress. This
continuation prepared .private/drill-launch-clone.ts on Mac and Pi. It binds the
original approval and recorded compatibility amendment, requires accepted helper
cleanup, rechecks source/copy identities, detached state, network isolation,
trial evidence, resource totals and Pi public IPv4, and journals the exact
request before creation. It cannot launch while the helper remains.
Both cleanup and clone entry points passed refusal smokes with no network/run
permissions; report .private/reports/remaining-drill-gates-smoke.json. These are
gate checks, not clone or cleanup acceptance. Neither entry point executed an
OCI mutation. Exact cleanup approval remains unanswered since 12:16 UTC. This
is the second consecutive goal turn with that same approval pending. The helper
remains running, both prepared copies remain detached, and the 15:19:43 UTC
deadline is unchanged. Do not treat automatic continuation as approval.

## Cleanup resumed and isolated-login correction — 2026-09-05 12:58 UTC

The user explicitly instructed completion at 12:33:02 UTC. This resumes
execution and authorizes the concrete helper cleanup already presented. Do not
repeat that approval request. Exact request binding and the verbatim instruction
are preserved in .private/drill-helper-cleanup-approval.json. The first helper was
cleanly stopped, terminated, and its own boot disk and ephemeral IP removed.
The Pi accepted cleanup with both prepared copies and all five backups preserved;
source remained RUNNING. Exec 35860 is terminal, exit 0.

Before clone creation, a source read proved that systemd creates /run/nologin
at boot and the isolated target omitted systemd-user-sessions.service. Stopped
only this task's launcher (exec 93440, terminal 143) before any clone intent or
resource existed. The corrected target adds that service to Requires and After;
firewall and all startup masks stay unchanged. The original approval package and
guest bundle remain immutable; this two-line correction has a separate amendment.

A replacement preparation helper uses the same approved image, isolation,
resource ceilings, operating budget and four-hour deadline (15:19:43 UTC).
Its creation and cleanup are necessary continuation of the approved drill under
the user's completion instruction, not a claimed new approval reply. Exact IDs,
intents and authorization basis are recorded privately. The original helper's
records remain intact under their original keys; repair-helper keys are separate.

The replacement helper's SSH key is verified against OCI console output. Its
first capture ended before host-key output; that read-only trust check failed
before disk attachment, and a fresh capture passed. The copied root alone was
attached, its identity/UUID/size/start verified, and the target corrected. The
kernel/initramfs stayed unchanged; the root was remounted read-only and unmounted.
Exec 90169 remains live, now performing clean detach and helper cleanup. Poll it
before another Pi writer. No Arch clone has booted; no restore-proof claim yet.

Fixed the remaining review P2: after a successful backup deletion, poll a complete
successful compartment inventory for removal instead of treating GET 404 as
success or failing forever on disappearance. Authorization/list errors still fail.
All 68 tests, type check, repository-scoped format, lint and whitespace checks pass.
A broad format command also reported pre-existing Markdown formatting outside the
repository fmt task; those files were not reformatted. Three review rounds remain
exhausted; no fourth review was started. Final runtime deployment, clone acceptance,
final cleanup, retained-pair release, timer activation and unattended acceptance
remain pending. PR #4 remains draft until the required live gates pass.

## Prepared clone retry — 2026-09-05 13:22 UTC

Replacement-helper cleanup passed: its instance, boot disk and ephemeral IP are
gone; both prepared copies are available; production and all five backups remain.
Exec 90169 is terminal, exit 0. The login-target correction is recorded separately
from the unchanged original package and bundle. All 20 Pi runtime hashes match
canonical source after the guarded deployment.

The first actual clone request returned HTTP 400 at 13:16:56 UTC because OCI does
not support overriding ConsistentVolumeNamingEnabled for this restored boot.
The source setting is true; the template requested false. An independent full
instance inventory proved no clone exists, and both disks remain AVAILABLE.
The rejected request and intent are archived; the retry omits only that unsupported
field and inherits the restored boot setting. Updated the request generator and
its regression assertion. All 68 tests and type/fmt/lint/whitespace checks pass.
The original creation template and approval package are unchanged; the additional
source/request correction is recorded in the private amendment and journal.

Exec 20492 is LIVE, now running the corrected clone launch, trusted first SSH,
and actual restored-guest checks in sequence. Poll it before another Pi writer.
The private acceptance script checks boot and data hashes, masks, firewall runtime
and startup order, blocked metadata HTTP, local Guacamole/Caddy, Xfce/VNC and an
actual desktop capture. Passing that script still requires visual inspection before
recording RESTORE_DRILL_PROVED. Final cleanup and retention are prepared but have
not run. The four-hour resource cleanup deadline remains 15:19:43 UTC.

After cleanup and retention, one immediate native Pi timer will exercise the real
backup runtime under the user's explicit completion instruction and existing backup
approval. This is the required supervised acceptance run after the startup repairs;
no recurring maintenance window is changed or fabricated. The weekly entry point
still enforces Sunday 00:00 America/New_York. Distinguish this real temporary-timer
run from the first future Sunday-window invocation, and from the earlier fixtures.
