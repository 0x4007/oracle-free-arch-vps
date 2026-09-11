# Bounded unattended reconstruction

`deno task backup:replace` uses the existing Pi recovery entry point. An
explicit `unattended` authorization in `.private/pi-machine-recovery.json`
enables one bounded reconstruction run after the destination and independent
generation are selected. Provisioning approval alone does not enable this mode.

Read the owner-controlled PROJECT-VISION.md, DEVELOPMENT-BUDGET.md and
RECOVERY-PROCEDURE.md first. A clean live run at revision
`d462c6d159dc2103af3d94b703a61b530dfd051b` passed application acceptance on
September 11, 2026, at 11:43 UTC. A separate visual desktop check passed at
11:44 UTC. See
[the dated evidence and limits](RECOVERY-ACCEPTANCE-2026-09-11.md). Earlier
operator-assisted proofs remain separate historical evidence.

## Select and authorize once

Use a new request, a reconciled empty destination, its existing isolated subnet
and unassigned reserved IP, a verified platform image and current trial/capacity
proof. Preserve completed journals in their dated evidence location before a new
request; never clear uncertain work to start over. Keep the source online.

The existing replacement configuration must include its exact provisioning
approval and existing RSA console public key. The selected generation must occur
exactly once in `.private/file-backup/controller.json`. The controller loads
this off-source catalog and its deployed runtime receipt; it does not fetch
recovery inputs from production.

Use `unattendedRecoveryPlan` from `scripts/pi-recovery-authority.ts` to
calculate the authorization digest from the replacement configuration, selected
index SHA-256, deployed source revision and expiry. Record these fields under
`unattended` in the existing private configuration:

- `planSha256`: the returned digest.
- `indexSha256`: `machineRestoreIndexSha256` of the validated selected index.
- `sourceRevision`: the exact deployed runtime receipt revision.
- `approvedAtUtc`: the actual authorization time.
- `expiresAtUtc`: a future deadline within four hours of authorization and no
  later than the separately authorized trial lifetime.
- `exactOperation`: the exported `UNATTENDED_RECOVERY_OPERATION` text.

The digest binds the existing console public key as well. Do not extend expiry
or relabel an earlier run. The source files must match the deployment receipt,
including the session, authority and restoration modules. Missing or changed
input stops the run.

## Run and observe

Run `deno task backup:replace` on the Pi through its existing `safepi` wrapper.
One process owns `.private/recovery-unattended.lock`; each infrastructure stage
also holds the shared controller lock. The controller derives and persists exact
stage approvals before use, without refreshing their timestamps on retries. It
builds restoration input from the selected catalog and verified loader/RAM disk
identities, then uses the existing restore, isolation and boot implementations.
Archive bytes travel directly from Backblaze to the target. The Pi forwards its
existing key-agent socket temporarily; it does not relay archives.

Only explicit pending states are revisited, at 15-second intervals, with at most
480 steps and repeated authority checks. Exceptions, exhausted console attempts,
changed identities and uncertain disk/restore/isolation writes stop visibly.
Reconcile these exact operations before continuation; never delete their
intents. The controller rechecks trial coverage before mutations and cannot
silently extend its authorization. An operation already in flight retains its
existing stage-specific bounds; the authorization is not a forced process-kill
deadline.

Read `.private/reports/pi-recovery-unattended.json` for progress and
`.private/reports/pi-recovery-session.json` plus the stage journals for details.
`RESTORED_APPLICATIONS_ACCEPTED` means the existing SSH/application checks
passed. It does not establish visual desktop acceptance or cleanup. Keep
independent visual/runtime acceptance and exact task-owned cleanup as separate
drill stages.

A first unattended run refuses pre-existing session, restoration, restore-input
or target-checkpoint state and operator-supplied stage approvals. A resumed run
must retain its own request and authorization journal. This prevents an earlier
repaired restoration from being reported as a clean unattended run.

# Transient writer conflicts

The unattended driver records `CONTROLLER_BUSY` when the infrastructure writer
guard refuses a step. It makes no guarded mutation, waits within the original
deadline, then repeats reconciliation. This does not bypass the writer guard.
Other errors, including uncertain writes and expired authority, still stop the
run. A stopped run retains source-code failure locations in the private
`pi-recovery-unattended-failure.json` report without command arguments or
output.
