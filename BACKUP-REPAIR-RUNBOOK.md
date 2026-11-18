# Deploy and verify the November 2026 backup repair

Run as the supervisor with the accepted local `fix/b2-cancellation-blocked` commit and existing authenticated Pi access. Keep the Oracle instance, required services and unrelated work online. This procedure moves only revision-bound source and control metadata. Backup payloads take their existing direct VPS-to-cloud routes.

At the start of the November 17 repair, the deployed Pi controller was under `/home/pi/ops/weekly-backup-controller`. Its top-level `release.json` reported `66113e45` while a separate Pi Git checkout reported `1cd25c4`. The current installer receipt had 115 managed hashes and a 44-file source closure. Treat those counts as historical. The B2 controller recorded its previous cycle as complete on October 25, with an accepted verifier receipt and no gate listed in the captured Pi inventory. Fresh lock and remote custody evidence is required before deployment.

## Reconcile the November 18 verifier before changing the deployment

Use this sequence for `job-61d5c174-45ff-4d7d-baec-57d06da81e89`. The worker and verifier ran from immutable source `3e7966c1eb1ef690afe0ee89c6d83e1e7f32e1f2`. On the Pi their worker result lists all seven archive roles. The VPS verifier finished at 03:47:18 UTC with status and result files, and the Pi bridge recorded `CLOSED/TERMINAL` at 03:47:21.605 UTC. The deployed keeper requires a matching `ACCEPTED` status and result hash before recording that terminal reason. The Pi controller still had its last `VERIFYING` observation and lacked a catalog entry after the first blocked reconciliation. Recheck the exact live state before proceeding.

1. **Pause the three schedules on the Pi and let pending invocations settle.** Use the existing Pi supervisor login. Record the current states, then stop the timer activations. Inspect the three services. Continue only with zero main/control PIDs and no active service invocation or queued activation. Leave the job gate, exact verifier, keeper, and their evidence in place for the recovery call.

   ```bash
   systemctl --user is-enabled weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer || true
   systemctl --user list-timers --all
   systemctl --user disable --now weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   systemctl --user show weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service \
     -p ActiveState -p SubState -p MainPID -p ControlPID -p Result
   systemctl --user list-jobs
   ```

2. **Open the verified candidate archive on each host.** Set `revision` and `expected_archive_sha256` to the full values in the release handoff. Put `controller.tar` and `controller.tar.sha256` in a protected `stage=$(mktemp -d /tmp/backup-repair.XXXXXX)` on the Pi and on the VPS through the established authenticated access. The archive contains the supervisor commands listed below. Run this on each host with its normal non-root account. Compare the candidate's deployed Pi and VPS predecessor manifests and file hashes privately before changing either host. The job's old source revision, manifests, package bytes, and request identity remain available throughout.

   ```bash
   set -euo pipefail
   umask 077
   cd "$stage"
   sha256sum --check --strict controller.tar.sha256
   test "$(sha256sum controller.tar | cut -d' ' -f1)" = "$expected_archive_sha256"
   case "$(id -un)" in
     pi) git_command=(/usr/local/bin/safepi git) ;;
     codex) git_command=(git) ;;
     *) exit 1 ;;
   esac
   test "$("${git_command[@]}" get-tar-commit-id < controller.tar)" = "$revision"
   mkdir -m 0700 tree
   tar --extract --file controller.tar --directory tree --no-same-owner
   ```

3. **Bind the recovery and inspect the exact evidence.** On the Pi run the first command from the deployed controller directory. It matches the exact job, verifier gate, source revision, request hash and invocation, then retains the three safe binding values in the protected stage. Review the bound Pi keeper manager and its recorded cgroup. On the VPS use the checked archive and run the second command through the normal privileged boundary. It compares the exact worker and verifier status, result and native custody hashes, proves source lock availability, and emits only validated receipt fields and counts. Review the exact source manager identity and socket state on the host. The staged engine repeats fresh native and bridge proofs before acceptance.

   ```bash
   # Pi
   controller=/home/pi/ops/weekly-backup-controller
   cd "$controller"
   bash "$stage/tree/config/backup-repair/check-job.sh" bind "$stage"
   bash "$stage/tree/config/backup-repair/check-job.sh" keeper "$stage"

   # VPS
   sudo -n systemctl show \
     arch-vps-b2-v2-verify-61d5c174-45ff-4d7d-baec-57d06da81e89-b2e3863e-93cc-4148-9f55-968f52aebb33.service \
     -p InvocationID -p ActiveState -p SubState -p Result -p ExecMainStatus -p MainPID -p ControlPID -p ControlGroup -p TasksCurrent
   sudo -n /bin/bash "$stage/tree/config/backup-repair/check-job.sh" source /var/tmp/arch-vps-file-backup
   public_home=/home/codex/.local/share/arch-vps-verifier/generation-61d5c174-45ff-4d7d-baec-57d06da81e89
   verifier_socket=$(gpgconf --homedir "$public_home" --list-dirs agent-socket)
   default_socket=$(gpgconf --list-dirs agent-socket)
   [[ -n $verifier_socket && $verifier_socket != "$default_socket" &&
      ! -e $verifier_socket && ! -L $verifier_socket ]]
   ```

4. **Reconcile the one verifier on the Pi.** Use the candidate entry point in the checked archive and run from the deployed controller directory. The entry takes the controller flock and verifies the original immutable runtime and exact already-terminal verifier and bridge through normal catalog acceptance. In an interrupted `VERIFY_SETTLED` attempt, run the same command with the saved binding and retained stop proof. If the entry reports a non-`COMPLETE` outcome, keep the three services and timers paused. Retain the gate, saved job, and any `settlement-intent.json` or exact-stop evidence, resolve the fixed check, and retry the same staged command with the saved binding. Later attempts use the staged parser for any newly recorded `cancellationBlockedReason` until normal cutover.

   ```bash
   cd "$controller"
   IFS=$'\t' read -r job_id gate_id request_sha256 < "$stage/job-binding.tsv"
   /usr/local/bin/safepi deno run --no-prompt --cached-only \
     --allow-read=.,"$stage/tree" --allow-write=.private \
     --allow-run=ssh,/usr/bin/id,/usr/bin/env \
     "$stage/tree/config/backup-repair/reconcile-blocked.ts" "$job_id" "$gate_id" "$request_sha256"
   bash "$stage/tree/config/backup-repair/check-job.sh" accepted "$stage"
   ```

   The accepted check compares the saved exact-stop and bridge settlement proofs. On the VPS repeat the source command in step 3 to confirm the source lock and terminal artifacts after gate clearance. The unit manager can unload a settled transient unit and drop its cgroup path. The saved stop proof binds the old invocation and boot. Success here is one catalog entry with the accepted current-period verifier receipt and a clear gate. Regular retention can resume through the existing manager after deployment.

5. **Install the new immutable release on the VPS and deploy the Pi files under the normal gate-free cutover.** Follow steps 3–4 below using the same checked archive on each host. Verify new VPS files, top-level Pi manifest, private deployment receipt, and B2 selector all match the candidate. The existing backup units and timers retain their designated roles. On rollback, preserve the accepted backup, catalog and proofs, and restore the verified Pi configuration snapshot using step 8. Keep both immutable source directories available for any request that references them.

6. **Restore the existing timers and prove cadence.** Start with the accepted current-period Oracle claim and the exact completed Backblaze job. Verify the gate is clear before enabling Oracle. Let each observed initial firing settle before enabling the next timer. The two capture services recheck even when their period is already satisfied. The B2 service can advance regular reference-safe retention and hold a prune gate. Let that operation settle through the normal controller before requiring a clear gate and healthy watchdog. After the two capture timers, enable the hourly watchdog.

   ```bash
   systemctl --user enable --now weekly-backup.timer
   systemctl --user show weekly-backup.timer -p ActiveState -p SubState -p TimersMonotonic -p NextElapseUSecMonotonic -p NextElapseUSecRealtime
   systemctl --user show weekly-backup.service -p ActiveState -p SubState -p InactiveEnterTimestampMonotonic
   # After the Oracle recheck settles:
   systemctl --user enable --now backblaze-file-backup.timer
   systemctl --user show backblaze-file-backup.timer -p ActiveState -p SubState -p TimersMonotonic -p NextElapseUSecMonotonic -p NextElapseUSecRealtime
   systemctl --user show backblaze-file-backup.service -p ActiveState -p SubState -p InactiveEnterTimestampMonotonic
   # After normal reconciliation and any retention settle:
   systemctl --user enable --now weekly-backup-watchdog.timer
   systemctl --user show weekly-backup-watchdog.timer -p ActiveState -p SubState -p NextElapseUSecRealtime
   systemctl --user list-timers --all weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   ```

   `OnUnitInactiveSec=15min` is relative to a prior service deactivation or a known monotonic trigger. `enable --now` activates the timer. A fresh inactivity anchor comes from the target service entering inactivity. `Persistent=true` catches up the calendar trigger. Boot and manager-startup triggers also have their own anchors. If a capture timer has only its weekly calendar `NEXT` after any first firing settles, seed one normal run of its idle service while the timer is active using `systemctl --user start weekly-backup.service` or `systemctl --user start backblaze-file-backup.service` in the same order as above. Allow that invocation to reach inactive or a recorded failure, then verify its fresh monotonic inactive time and a monotonic timer deadline about 15 minutes later, within the declared one-minute accuracy. Diagnose any failure status in its journal. Prove the next natural service invocation and advancing timer `LAST` without a manual start. The watchdog timer uses its hourly calendar deadline. [systemd timer directives](https://www.freedesktop.org/software/systemd/man/252/systemd.timer.html) [systemd inactivity timestamp calculation](https://github.com/systemd/systemd/blob/v252/src/core/timer.c#L426-L431)

   On November 18, B2 timer readback advanced from `LAST` 04:44:44 UTC to 05:00:00 UTC with the next trigger at 05:15:07 UTC. Oracle's live claim had completed at 23:07:29.962 UTC on November 17. The Oracle and watchdog timers were paused during those observations.

   Run the existing watchdog once after gate clearance and retention settlement. Require a fresh healthy Oracle current-period report and a healthy accepted B2 current-period or completed retention report.

   ```bash
   systemctl --user is-enabled weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   since=$(date -u +%s)
   systemctl --user start weekly-backup-watchdog.service
   cd "$controller"
   jq -es --argjson since "$since" '
     .[0].status == "ACCEPTED_BACKUP_CURRENT" and
     (.[1].status | startswith("B2_BACKUP_CURRENT:") or . == "B2_RETENTION_EXECUTE_COMPLETE") and
     all(.[]; .healthy == true and
       ((.observedAtUtc | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601) >= $since))
   ' .private/reports/backup-watchdog.json .private/reports/backblaze-file-backup.json
   test ! -e .private/backup-controller-gate.json && test ! -L .private/backup-controller-gate.json
   ```

   On November 17 at 21:58 UTC, the watchdog reported a completed retention transaction combined with an October 25 recovery point outside the current period. It mapped the combined unhealthy report to `B2_RETENTION_BLOCKED`. A current accepted recovery point addresses that observation.

## General deployment and rollback


The old watchdog only queued a changed combined status and sent it to the Mac's `terminal-notifier` over SSH. The Pi ledger had 70 records with zero pending, most recently marked delivered on November 1, and subsequent unchanged failures produced no new sends. The SSH exit records establish the old publisher's result. Device notification receipt needs independent confirmation.

1. **Build the exact local artifact.** On the build host, bind `revision` to the full accepted commit from the handback. Archive only tracked runtime input from that commit and retain the SHA-256 separately. Copy the two files over the existing host-key-verified, authenticated supervisor-to-Pi channel to a Pi directory created with `mktemp -d /tmp/backup-repair.XXXXXX`. Pin the existing Pi host key using the established access profile. Send the 64-character archive digest to the operator in the authenticated handback. The Pi Git checkout is irrelevant to this transfer.

   ```sh
   set -euo pipefail
   umask 077
   test "$(git rev-parse HEAD)" = "$revision"
   build=$(mktemp -d /tmp/backup-repair-build.XXXXXX)
   git archive --format=tar --output="$build/controller.tar" "$revision" -- \
     deno.json scripts config BACKBLAZE-DIRECT-BACKUP.md DECISIONS.md \
     ONLINE-BACKUP-CONTRACT.md RECOVERY-PROCEDURE.md BACKUP-REPAIR-RUNBOOK.md
   (cd "$build" && sha256sum controller.tar > controller.tar.sha256)
   ```

2. **Verify the Pi and pause the three existing schedules.** On the Pi set `stage` to the private temporary directory holding the archive and `controller=/home/pi/ops/weekly-backup-controller`. Confirm `id -un` reports `pi`, confirm the host identity, and run the commands below. Record enabled and active states of the three timers before taking them out of service. Restore those recorded states after the acceptance steps. Check the service paths, `WorkingDirectory`, unit overrides, and other jobs that use the controller tree. Wait for the three existing services and all other users of the deployment to settle. Check processes and current systemd results. Leave any active job in its existing release until it settles.

   ```sh
   set -euo pipefail
   umask 077
   controller=/home/pi/ops/weekly-backup-controller
   cd "$stage"
   sha256sum -c controller.tar.sha256
   test "$(sha256sum controller.tar | cut -d' ' -f1)" = "$expected_archive_sha256"
   test "$(/usr/local/bin/safepi git get-tar-commit-id < controller.tar)" = "$revision"
   mkdir -m 0700 tree
   tar --extract --file controller.tar --directory tree --no-same-owner
   systemctl --user is-enabled weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer || true
   systemctl --user list-timers --all
   systemctl --user disable --now weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   systemctl --user show weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service \
     -p FragmentPath -p ActiveState -p SubState -p MainPID -p ControlPID -p Result
   ```

3. **Derive the install list and manifests.** Compare the live `.private/reports/pi-session-deployment.json` and `.private/backblaze-deployment.json` `sourceRevision` values privately. Verify the installer receipt's managed files against the live tree. Verify the top-level release's `files` hashes against that revision's immutable source under `.private/file-backup/runtime/releases/<top-level-revision>/` or its independently retained, verified release archive. Compare live controller bytes to the installer receipt rather than assuming the top-level label selects the current Pi source. Independently record the top-level release revision, selector revision, receipt revision, any immutable active B2 job revision and the old unit fragments. Resolve any contradictions before installation. The B2 loader checks the selector and private receipt for the same revision, then rehashes the recursive source closure. Its immutable release is distinct from both the top-level manifest and the controller files.

   ```sh
   top_revision=$(jq -er '.sourceRevision | select(test("^[0-9a-f]{40}$"))' "$controller/release.json")
   top_source="$controller/.private/file-backup/runtime/releases/$top_revision"
   # Use the separately verified historical source root if this revision is archived elsewhere.
   jq -er '.files[] |
     if (.path | test("^scripts/[A-Za-z0-9_.-]+\\.ts$")) and (.sha256 | test("^[0-9a-f]{64}$"))
     then "\(.sha256)  \(.path)" else error("Invalid historical manifest entry") end
   ' "$controller/release.json" > "$stage/top-before.sha256"
   (cd "$top_source" && sha256sum --check --strict --status "$stage/top-before.sha256")
   ```

   The archive ships `config/backup-repair/derive.ts`. Run it from the extracted archive's staging directory. It derives the install paths, revision-bound manifest and hash map from the trusted staged source. It covers the functional entry points and their literal TypeScript import closures, and omits the live exclusions and runtime state.

   ```bash
   (
     cd "$stage"
     /usr/local/bin/safepi deno run --cached-only --allow-read=. --allow-write=. \
       "$stage/tree/config/backup-repair/derive.ts" "$revision"
   )
   ```

4. **Install the VPS runtime and cut over under the Pi controller lock.** On the Pi, confirm the live gate is absent and the B2 controller's current worker, verifier, bridge and pruner are settled. For any exact retained source job, check its current VPS boot and unit invocation against its terminal receipt, empty cgroup and escaped process inventory, zero open pipeline handles and pending operations, and free source lock at `/var/tmp/arch-vps-file-backup/source.lock`. An absent unit alone is incomplete evidence. Resolve any unsettled gate through its exact recorded recovery path before changing files or selectors.

   On the VPS, use the already checked archive in its own protected stage. Confirm the normal non-root account and VPS identity, the free source lock and settled backup custody, and the prior immutable release hashes. The installer validates the new revision's entire import closure against the derived manifest. It builds the new tree beside its final directory, verifies every file, flushes the staged files, and publishes the directory atomically without overwriting an existing revision. The runtime and release directories, including `scripts/`, are root:root mode 0700. Every release file, including the manifest, is root:root mode 0600. A rerun verifies identical bytes and modes. Preserve the prior immutable release and configuration selections for rollback.

   ```bash
   test "$(id -un)" = codex
   uname -nsmr
   (
     cd "$stage"
     nice -n 19 /usr/local/bin/deno run --cached-only --allow-read=. --allow-write=. \
       "$stage/tree/config/backup-repair/derive.ts" "$revision"
   )
   sudo -n /bin/bash "$stage/tree/config/backup-repair/install-vps-release.sh" \
     "$stage" "$revision" /var/tmp/arch-vps-file-backup-runtime/releases
   ```

   Continue on the Pi after the VPS helper confirms the exact revision. Create the rollback directory beneath the existing private controller directory and run the archive's `config/backup-repair/cutover.sh`. It holds the existing lock inode, checks the gate, saves the exact original files and receipt metadata, verifies staged and live hashes, publishes the marked candidate, and rechecks the installed manifests. Existing controller files retain their modes, new source is mode 0600, and the Pi user unit fragments use 0644. The helper keeps receipt fields including preserved exclusions and updates the B2 selector revision alone. Keep the rollback directory protected and accessible through acceptance.

   ```sh
   rollback=$(mktemp -d "$controller/.private/backup-repair-rollback.XXXXXX")
   unit_dir=/home/pi/.config/systemd/user
   bash "$stage/tree/config/backup-repair/cutover.sh" install "$stage" "$controller" "$unit_dir" "$rollback" "$revision"
   systemd-analyze --user verify \
     "$unit_dir/weekly-backup.service" "$unit_dir/backblaze-file-backup.service" \
     "$unit_dir/weekly-backup-watchdog.service"
   systemctl --user daemon-reload
   systemctl --user cat weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service
   ```

   A partial copy leaves the timers paused and the snapshot available. The B2 runner materializes the revision-specific Pi release under `.private/file-backup/runtime/releases/<revision>/` using its current installer. The source job installer verifies the already published VPS release before creating its own immutable job artifacts. Retain previous immutable paths, source job bindings, and the three old manifests.

5. **Check the known claim and notification route.** Read the claim at `.private/backup-scheduled-window.json`, current schedule at `.private/backup-schedule.json`, runtime journal at `.private/backup-runtime.json`, and controller policy at `.private/backup-controller.json` on the Pi using its private permissions. Confirm the old claim is a started weekly claim and its recorded `approvedSchedule` matches the current approved fields, including any acceptance window. Its `windowId` and `periodId` must be the same approved civil period at its `updatedAtUtc` and that period must be at least 13 hours past its start. Confirm `claim.previousCycleSuffix === runtime.cycle.suffix`, `cycle.mode === "online"`, `cycle.phase === "complete"`, and the cycle was updated before the claim. Confirm the same source, group, and standing approval in the journal and configuration. Read the exact home-region group backup inventory and prove the old group's recorded FULL pair remains AVAILABLE, the source is RUNNING, and there is no newer or ambiguous group operation since the old journal checkpoint. Recheck gate, workers and locks. The new scheduler reconciles and archives the exact legacy claim under the shared lock before a fresh attempt. Leave the live claim and journal in place for that proof. If the run reports `SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE` or `SCHEDULED_CLAIM_CUSTODY_OVERDUE`, retain both records and inspect the `SCHEDULED_CLAIM_CHECK_FAILED` code in the originating service journal to identify the refused check. Use the separate documented procedure for an expired one-time acceptance claim. [Troubleshooting](06-TROUBLESHOOTING.md#scheduled-backup-requires-claim-reconciliation)

   The existing notification config stays at `.private/backup-notification.json`, mode 0600. Missing config and the valid legacy Mac config migrate to `https://ntfy.pavlovcik.com/alerts`. To override, set `{"destination":"https://ntfy.pavlovcik.com/alerts"}` with the intended HTTPS server/topic. The destination is one HTTPS topic URL without embedded credentials, query, or fragment. The existing ledger is `.private/backup-alerts.json`. A first refusal is queued immediately, repeated observations remain one incident per stream, and reminders are due every six hours while the streams remain unhealthy. Failed sends stay pending with a 15-minute retry interval through the existing timers. For delivery evidence before recovery, run `systemctl --user start weekly-backup-watchdog.service` while the actual missed-window report still applies. Inspect the current report and ledger for the new receipt and check arrival on a device subscribed to the configured server/topic. An unhealthy watchdog can exit nonzero even when ntfy confirmed the alert.

6. **Start Oracle once and verify.** Keep both capture timers paused initially. Start `systemctl --user start --no-block weekly-backup.service` and follow `journalctl --user -u weekly-backup.service -f`. Verify service result and the fresh runtime/claim are complete in the current approved period. Record the new group and both exact members privately, then query fresh OCI state for FULL/AVAILABLE, expected source volume IDs and 50/150 GB sizes, exact group/suffix, home region, and timestamps. Reconcile live limits and remaining slots. Confirm OCI stayed RUNNING and the journal's `sourceContinuityBeforeCapture` and `sourceContinuityAfterCapture` carry the same boot and required-service invocation IDs with the fresh working probes. Only then accept the point as `METADATA_PROVED`. Retirement requires separate confirmation that the accepted replacement exists and the old pair's status is as approved. Boot restore requires a separately approved drill.

7. **Start Backblaze once and verify.** After Oracle acceptance, start `systemctl --user start --no-block backblaze-file-backup.service`. Follow `journalctl --user -u backblaze-file-backup.service -f` and its exact current job in the private Pi reports. Allow the existing 15-minute timer to reconcile the legitimately active v2 job after its bounded initial invocation, restoring that timer to its recorded state. The initial progress return proves admission or custody only. Acceptance requires the new current-period job's B2 worker result, the independent verifier's successful full reconstruction/decryption and archive verification, the exact verifier receipt and selected B2 root recorded in the new catalog entry, `.private/file-backup/controller.json` at `COMPLETE`, and the exact worker/verifier/bridge settled with its capture gate cleared. Check immutable revision and catalog entry against the fresh reports. Separate the accepted backup from retention/prune success and from machine boot restore. Restore the remaining timer states, run the watchdog again, verify current accepted periods and recovery alert results, then update `runtimeAccepted` in the private Pi installer receipt according to the proven runtime result.

8. **Roll back only from settled custody.** Pause the three existing timers again and repeat the lock, gate, service and remote custody checks. If a fresh operation began, first reconcile its actual OCI or Backblaze journal and immutable request with its original revision. Keep accepted backups, journals, gates, catalog, notification ledger and private configuration with their real state. For a failed pre-operation deployment run `bash "$stage/tree/config/backup-repair/cutover.sh" rollback "$stage" "$controller" "$unit_dir" "$rollback" "$revision"`. It verifies each current target against the two saved revisions, restores original file bytes and modes, and retains newly added candidate files in the rollback directory. Compare all old hashes before reloading the user manager. Verify services resolve to the known fragments before deciding whether the old schedules are safe to resume. The previous code can reproduce the original subscription and claim failures, so a restored source tree alone does not establish a safe resumed backup service.

## Use another ntfy hostname

The shipped Oracle and watchdog commands permit `ntfy.pavlovcik.com`. Editing only the private notification JSON is sufficient for a different topic at that host. For another host or port, use existing systemd user drop-ins with the exact corresponding permission. In these examples replace `alerts.example.net:443` with the permitted server including its port when nondefault. Preserve the archived source and manifest bytes.

For `systemctl --user edit weekly-backup.service`:

```ini
[Service]
ExecStart=
ExecStart=/bin/bash -c 'set -o pipefail; /usr/local/bin/safepi deno run --allow-read=.private --allow-write=.private --allow-run --allow-net=docs.oracle.com,alerts.example.net:443 scripts/alerting-backup-scheduled.ts 2>&1 | cat'
ExecStopPost=
ExecStopPost=-/bin/bash -c 'set -o pipefail; [[ "$$SERVICE_RESULT" == success ]] || /usr/local/bin/safepi deno run --allow-read=.private --allow-write=.private --allow-net=alerts.example.net:443 scripts/backup-mac-alert.ts oracle-scheduled 2>&1 | cat'
```

For `systemctl --user edit backblaze-file-backup.service`:

```ini
[Service]
ExecStopPost=
ExecStopPost=-/bin/bash -c 'set -o pipefail; [[ "$$SERVICE_RESULT" == success ]] || /usr/local/bin/safepi deno run --allow-read=.private --allow-write=.private --allow-net=alerts.example.net:443 scripts/backup-mac-alert.ts backblaze-scheduled 2>&1 | cat'
```

For `systemctl --user edit weekly-backup-watchdog.service`:

```ini
[Service]
ExecStart=
ExecStart=/bin/bash -c 'set -o pipefail; /usr/local/bin/safepi deno run --allow-read=.private --allow-write=.private --allow-run=ssh --allow-net=alerts.example.net:443 scripts/backup-watchdog.ts 2>&1 | cat'
```

Run `systemctl --user daemon-reload`, verify all three effective units with `systemctl --user cat`, then set the matching private HTTPS destination. Backblaze's main process retains the existing dynamic B2 endpoint permission.
