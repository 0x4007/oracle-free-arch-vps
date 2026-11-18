# Deploy and verify the November 2026 backup repair

Run as the supervisor with the verified release archive and existing authenticated Pi and VPS access. Keep the Oracle instance, required services and unrelated work online. This procedure moves only revision-bound source and control metadata. Backup payloads take their existing direct VPS-to-cloud routes.

At the start of the November 17 repair, the deployed Pi controller was under `/home/pi/ops/weekly-backup-controller`. Its top-level `release.json` reported `66113e45` while a separate Pi Git checkout reported `1cd25c4`. The current installer receipt had 115 managed hashes and a 44-file source closure. Treat those counts as historical. The B2 controller recorded its previous cycle as complete on October 25, with an accepted verifier receipt and no gate listed in the captured Pi inventory. Fresh lock and remote custody evidence is required before deployment.

Follow standard deployment for a settled installation with a clear gate. The supervisor completed the November 18 job after stopping its residual Pi key agent. Use the historical recovery only while the exact blocked verifier and live gate still match. [Standard deployment](#standard-deployment-and-rollback)

## Recover the November 18 blocked verifier

Use this sequence for `job-61d5c174-45ff-4d7d-baec-57d06da81e89`. The worker and verifier ran from immutable source `3e7966c1eb1ef690afe0ee89c6d83e1e7f32e1f2`. On the Pi their worker result lists all seven archive roles. The VPS verifier finished at 03:47:18 UTC with status and result files, and the Pi bridge recorded `CLOSED/TERMINAL` at 03:47:21.605 UTC. The deployed keeper requires a matching `ACCEPTED` status and result hash before recording that terminal reason. The Pi controller still had its last `VERIFYING` observation and lacked a catalog entry after the first blocked reconciliation. The previous settlement code could not read the non-dumpable key agent's `/proc/PID/exe` link as user `pi`. Recheck the exact live state before proceeding.

1. **Pause the three schedules on the Pi and let pending invocations settle.** Use the existing Pi supervisor login. Record the current states, then stop the timer activations. Inspect the three services. Continue only with zero main/control PIDs and no active service invocation or queued activation. Leave the job gate, exact verifier, keeper, and their evidence in place for the recovery call.

   ```bash
   systemctl --user is-enabled weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer || true
   systemctl --user list-timers --all
   systemctl --user disable --now weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   systemctl --user show weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service \
     -p ActiveState -p SubState -p MainPID -p ControlPID -p Result
   systemctl --user list-jobs
   ```

2. **Check and stage the candidate on both hosts.** Use the archive verification in standard deployment step 1. Keep the original immutable job revision on the VPS and record the current Pi deployment before recovery. Use a separate protected operator stage. [Standard deployment](#standard-deployment-and-rollback)

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

4. **Attempt guarded terminal reconciliation on the Pi.** Use the repaired candidate entry point in the checked archive and run from the deployed controller directory. The entry takes the controller flock and verifies the original immutable runtime and exact already-terminal verifier and bridge through normal catalog acceptance. In an interrupted `VERIFY_SETTLED` attempt, run the same command with the saved binding and retained stop proof. If the entry reports a non-`COMPLETE` outcome, keep the three services and timers paused. Review the bounded reason. Step 5 applies only to the exact historical blocked keeper. Retain the gate, saved job, and any `settlement-intent.json` or exact-stop evidence, resolve the fixed check, and retry the same staged command with the saved binding. Later attempts use the staged parser for any newly recorded `cancellationBlockedReason` until normal cutover.

   ```bash
   cd "$controller"
   IFS=$'\t' read -r job_id gate_id request_sha256 < "$stage/job-binding.tsv"
   /usr/local/bin/safepi deno run --no-prompt --cached-only \
     --allow-read=.,"$stage/tree" --allow-write=.private \
     --allow-run=ssh,/usr/bin/id,/usr/bin/env \
     "$stage/tree/config/backup-repair/reconcile-blocked.ts" "$job_id" "$gate_id" "$request_sha256"
   # Run after the staged command reports COMPLETE.
   bash "$stage/tree/config/backup-repair/check-job.sh" accepted "$stage"
   ```

   The accepted check compares the saved exact-stop and bridge settlement proofs. On the VPS repeat the source command in step 3 to confirm the source lock and terminal artifacts after gate clearance. The unit manager can unload a settled transient unit and drop its cgroup path. The saved stop proof binds the old invocation and boot. Success here is one catalog entry with the accepted current-period verifier receipt and a clear gate. Regular retention can resume through the existing manager after deployment.

5. **Use the manual fallback only for the documented legacy incident.** This is the scoped workaround confirmed on deployed Pi revision `0f53c957592d4c7783e951718f49a80f51a4e441` for the named November 18 job. Consider it only if step 4 remains blocked and the same `BRIDGE_TERMINAL_PROCESSES_UNPROVED` failure is independently established, the exact source verifier has its accepted result and no source children or custom socket remain. A new or unexplained refusal calls for evidence review before any agent shutdown. Confirm the Pi keeper is `active/exited`, `Result=success`, with zero main and control PIDs and the recorded boot, invocation and cgroup. Step 3 proves its terminal close record and zero pending bridge operations. Keep the three schedules paused and other clients of this backup keyring idle. If the keeper cgroup is already empty, proceed with the guarded reconciliation in step 4.

   ```bash
   (
     set -euo pipefail
     cd "$controller"
     test "$(id -un)" = pi
     lock=.private/backup-controller.lock
     test -f "$lock" && test ! -L "$lock"
     exec 9<"$lock"
     flock -n 9
     deployed=$(jq -er '.sourceRevision' .private/backblaze-deployment.json)
     test "$deployed" = 0f53c957592d4c7783e951718f49a80f51a4e441
     bash "$stage/tree/config/backup-repair/check-job.sh" bind "$stage"
     bash "$stage/tree/config/backup-repair/check-job.sh" keeper "$stage"
     IFS=$'\t' read -r job_id gate_id request_sha256 < "$stage/job-binding.tsv"
     status=.private/file-backup/jobs/$job_id/bridge-$gate_id/status.json
     unit=$(jq -er '.bridge.keeper.unitName' "$status")
     invocation=$(jq -er '.bridge.keeper.invocationId' "$status")
     group=$(jq -er '.bridge.keeper.cgroup' "$status")
     cgroup=/sys/fs/cgroup$group
     keeper_state() {
       local properties
       properties=$(systemctl --user show "$unit" \
         -p InvocationID -p ControlGroup -p ActiveState -p SubState -p Result -p MainPID -p ControlPID) || return 1
       for property in "InvocationID=$invocation" "ControlGroup=$group" ActiveState=active \
         SubState=exited Result=success MainPID=0 ControlPID=0; do
         grep -Fxq "$property" <<< "$properties" || return 1
       done
     }
     keeper_state
     grep -qx 'populated 1' "$cgroup/cgroup.events"
     grep -qx 'nr_descendants 0' "$cgroup/cgroup.stat"
     pid=$(cat "$cgroup/cgroup.procs")
     [[ $pid =~ ^[1-9][0-9]*$ ]]
     start_ticks() { awk '{ sub(/^.*\) /, ""); print $20 }' "/proc/$pid/stat"; }
     start=$(start_ticks)
     [[ $start =~ ^[1-9][0-9]*$ ]]
     test "$(cat "/proc/$pid/cgroup")" = "0::$group"
     keyring=/home/pi/ops/weekly-backup-controller/.private/file-backup/gnupg
     test "$(realpath -e -- "$keyring")" = "$keyring"
     agent_argv() {
       printf '%s\0' "$1" --homedir "$keyring" --use-standard-socket --daemon | cmp -s - "/proc/$pid/cmdline"
     }
     agent_argv gpg-agent || agent_argv /usr/bin/gpg-agent
     socket=$(gpgconf --homedir "$keyring" --list-dirs agent-socket)
     default_socket=$(env -u GNUPGHOME gpgconf --list-dirs agent-socket)
     [[ -S $socket && ! -L $socket && $socket != "$default_socket" ]]
     peer=$(/usr/bin/timeout 5 /usr/bin/gpg-connect-agent --homedir "$keyring" --no-autostart 'GETINFO pid' /bye | awk '/^D [1-9][0-9]*$/ { print $2 }')
     test "$peer" = "$pid"
     keeper_state
     test "$(cat "$cgroup/cgroup.procs")" = "$pid"
     test "$(cat "/proc/$pid/cgroup")" = "0::$group"
     test "$(start_ticks)" = "$start"
     gpgconf --homedir "$keyring" --kill gpg-agent
   )
   ```

   Check `keeperCgroupPresent=false` or `keeperCgroupPopulated=0` with `check-job.sh keeper` before continuing. If any identity, socket or custody check differs, leave the gate and evidence in place. This procedure uses only the absolute backup keyring home and preserves the default GPG agent. A successful GPG command establishes a shutdown request. The fresh cgroup check establishes exit. Retry step 4 with the saved binding and verify `COMPLETE` before proceeding.

6. **Continue with standard deployment once the gate is clear.** Use the same checked archive on both hosts. Verify the new VPS files and the three Pi release records, then restore the three existing schedules as described below. Preserve both immutable source revisions, the accepted catalog and the exact proofs.

The November 17 watchdog mapped a completed retention transaction with an October 25 recovery point outside the current period to `B2_RETENTION_BLOCKED`. A current accepted recovery point addresses that observation.

## Standard deployment and rollback

The old watchdog only queued a changed combined status and sent it to the Mac's `terminal-notifier` over SSH. The Pi ledger had 70 records with zero pending, most recently marked delivered on November 1, and subsequent unchanged failures produced no new sends. The SSH exit records establish the old publisher's result. Device notification receipt needs independent confirmation.

1. **Build and verify the exact archive on both hosts.** On the build host, bind `revision` to the full accepted commit from the handback. Archive only tracked runtime input from that commit and retain the SHA-256 separately. If the release handoff already supplies these files, use that archive and its authenticated digest. Copy the two files to a separate `mktemp -d /tmp/backup-repair.XXXXXX` stage on the Pi and on the VPS using the existing authenticated, host-key-verified access profiles. Send the 64-character archive digest to the operator in the authenticated handback. The Pi Git checkout is irrelevant to this transfer.

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

   On each host use its normal account and its own stage containing both archive files. Set `revision` and `expected_archive_sha256` to the identical authenticated handoff values on each host. Confirm the expected host and user before continuing.

   ```bash
   set -euo pipefail
   umask 077
   uname -nsmr
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

2. **Pause the three Pi schedules.** On the Pi set `controller=/home/pi/ops/weekly-backup-controller`, confirm `id -un` reports `pi`, and record enabled and active states of the three timers before stopping dispatch. Inspect service paths, `WorkingDirectory`, drop-ins and queued jobs. Wait for all users of the deployment to finish. Leave any active backup on its pinned release and settle its custody before cutover.

   ```sh
   set -euo pipefail
   umask 077
   controller=/home/pi/ops/weekly-backup-controller
   test "$(id -un)" = pi
   uname -nsmr
   test -x /usr/bin/gpgconf
   test -x /usr/bin/timeout
   /usr/bin/python3 -IS -c 'import socket; assert hasattr(socket, "SO_PASSCRED") and hasattr(socket, "SCM_CREDENTIALS")'
   systemctl --user show weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer \
     -p Id -p UnitFileState -p ActiveState -p SubState
   systemctl --user list-timers --all
   systemctl --user disable --now weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   systemctl --user show weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service \
     -p FragmentPath -p DropInPaths -p WorkingDirectory -p ActiveState -p SubState -p MainPID -p ControlPID -p Result
   systemctl --user list-jobs
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
   jq -se --arg revision "$revision" 'length == 3 and all(.[]; .sourceRevision == $revision)' \
     "$controller/release.json" "$controller/.private/backblaze-deployment.json" \
     "$controller/.private/reports/pi-session-deployment.json"
   ```

   A partial copy leaves the timers paused and the snapshot available. The B2 runner materializes the revision-specific Pi release under `.private/file-backup/runtime/releases/<revision>/` using its current installer. The source job installer verifies the already published VPS release before creating its own immutable job artifacts. Retain previous immutable paths, source job bindings, and the three old manifests.

5. **Check the Oracle claim and notification route.** If a legacy Oracle claim is still `started`, read the claim at `.private/backup-scheduled-window.json`, current schedule at `.private/backup-schedule.json`, runtime journal at `.private/backup-runtime.json`, and controller policy at `.private/backup-controller.json` on the Pi using its private permissions. Confirm the old claim is a weekly claim and its recorded `approvedSchedule` matches the current approved fields, including any acceptance window. Its `windowId` and `periodId` must be the same approved civil period at its `updatedAtUtc` and that period must be at least 13 hours past its start. Confirm `claim.previousCycleSuffix === runtime.cycle.suffix`, `cycle.mode === "online"`, `cycle.phase === "complete"`, and the cycle was updated before the claim. Confirm the same source, group, and standing approval in the journal and configuration. Read the exact home-region group backup inventory and prove the old group's recorded FULL pair remains AVAILABLE, the source is RUNNING, and there is no newer or ambiguous group operation since the old journal checkpoint. Recheck gate, workers and locks. The new scheduler reconciles and archives the exact legacy claim under the shared lock before a fresh attempt. Leave the live claim and journal in place for that proof. If the run reports `SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE` or `SCHEDULED_CLAIM_CUSTODY_OVERDUE`, retain both records and inspect the `SCHEDULED_CLAIM_CHECK_FAILED` code in the originating service journal to identify the refused check. Use the separate documented procedure for an expired one-time acceptance claim. [Troubleshooting](06-TROUBLESHOOTING.md#scheduled-backup-requires-claim-reconciliation)

   The existing notification config stays at `.private/backup-notification.json`, mode 0600. Missing config and the valid legacy Mac config migrate to `https://ntfy.pavlovcik.com/alerts`. To override, set `{"destination":"https://ntfy.pavlovcik.com/alerts"}` with the intended HTTPS server/topic. The destination is one HTTPS topic URL without embedded credentials, query, or fragment. The existing ledger is `.private/backup-alerts.json`. A first refusal is queued immediately, repeated observations remain one incident per stream, and reminders are due every six hours while the streams remain unhealthy. Failed sends stay pending with a 15-minute retry interval through the existing timers. For an alert due during the watchdog invocation in step 7, inspect the report and ledger for its send receipt and confirm arrival on a device subscribed to that topic. An unhealthy watchdog can exit nonzero even when ntfy confirmed the alert.

6. **Rearm Oracle and verify the pair.** For the normal three-timer rollout, enable and start the Oracle timer first. With that timer active, start `weekly-backup.service` once to give `OnUnitInactiveSec=15min` a fresh anchor. If the persistent calendar catch-up already launched a fresh invocation, let that invocation finish and skip the manual start below. Restore any deliberately disabled timer to its recorded state. If a start reports failure, review the fresh service result and journal before continuing.

   ```bash
   systemctl --user enable --now weekly-backup.timer
   # Run this start only if enabling the timer did not dispatch the service.
   systemctl --user start weekly-backup.service
   # Read the journal and timestamps after the invocation has settled.
   journalctl --user -u weekly-backup.service --no-pager -n 40
   systemctl --user show weekly-backup.service -p Result -p ActiveState -p SubState -p InactiveEnterTimestampMonotonic
   systemctl --user show weekly-backup.timer -p ActiveState -p SubState -p TimersMonotonic -p NextElapseUSecMonotonic -p NextElapseUSecRealtime
   ```

   Wait for the invocation to settle before enabling Backblaze. Verify the current-period runtime and claim are complete. A satisfied period needs only a recheck. For a new capture, query the current home-region OCI inventory for the exact FULL/AVAILABLE volume group, both expected 50/150 GB source members, timestamps, home region and free slots. Confirm the instance stayed `RUNNING` and the saved `sourceContinuityBeforeCapture` and `sourceContinuityAfterCapture` match boot and required-service identities. This establishes `METADATA_PROVED`. A boot restore requires its separately approved drill.

7. **Rearm Backblaze, let retention settle, then start the watchdog once.** Repeat the capture timer sequence for Backblaze after Oracle acceptance. A persistent catch-up invocation counts as the Backblaze service's one start. The active fifteen-minute timer handles reconciliation while a genuine job is running. Let a regular retention operation settle through the normal controller if it holds the gate.

   ```bash
   systemctl --user enable --now backblaze-file-backup.timer
   # Run this start only if enabling the timer did not dispatch the service.
   systemctl --user start backblaze-file-backup.service
   # Read the journal and timestamps after the invocation has settled.
   journalctl --user -u backblaze-file-backup.service --no-pager -n 40
   systemctl --user show backblaze-file-backup.service -p Result -p ActiveState -p SubState -p InactiveEnterTimestampMonotonic
   systemctl --user show backblaze-file-backup.timer -p ActiveState -p SubState -p TimersMonotonic -p NextElapseUSecMonotonic -p NextElapseUSecRealtime
   ```

   Check each capture timer has a fresh service inactivity timestamp and a monotonic deadline around 15 minutes later within its one-minute accuracy. `enable --now` activates the timer and `Persistent=true` covers calendar catch-up. A service entering inactivity supplies the new monotonic anchor. Prove that `LAST` advances on a natural dispatch and the service journal records that invocation. [systemd timer directives](https://www.freedesktop.org/software/systemd/man/252/systemd.timer.html)

   After Backblaze and retention settle, require a current-period verified receipt and clear gate before starting the watchdog. Its trigger is hourly. Read the two reports from the same settled watchdog invocation in the service journal. The scheduled Backblaze service can update its report file between checks. A persistent catch-up counts if its fresh journal result meets the same checks.

   ```bash
   cd "$controller"
   test ! -e .private/backup-controller-gate.json && test ! -L .private/backup-controller-gate.json
   since=$(date -u +%s)
   systemctl --user enable --now weekly-backup-watchdog.timer
   # Run this start only if enabling the timer did not dispatch the service.
   systemctl --user start weekly-backup-watchdog.service
   # Read the timer and report after the watchdog invocation has settled.
   systemctl --user show weekly-backup-watchdog.timer -p ActiveState -p SubState -p NextElapseUSecRealtime
   systemctl --user list-timers --all weekly-backup.timer backblaze-file-backup.timer weekly-backup-watchdog.timer
   journalctl --user -u weekly-backup-watchdog.service --since "@$since" --no-pager -o cat |
     jq -eRs --argjson since "$since" '
       def observed_since:
         (.observedAtUtc | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= $since;
       [split("\n")[] | fromjson? | select(type == "object" and has("oracle") and has("b2"))] |
       length == 1 and (.[0] |
         .oracle.status == "ACCEPTED_BACKUP_CURRENT" and
         (.b2.status | startswith("B2_BACKUP_CURRENT:") or . == "B2_RETENTION_EXECUTE_COMPLETE") and
         all(.oracle, .b2; .healthy == true and observed_since))
     '
   ```

   An idle-arm service start before the next weekly window may only recheck the already accepted period. Verify the repair during the next naturally admitted Backblaze job and preserve its exact revision and request evidence. Require a complete independent cloud reconstruction and decryption, all seven verified archives, the exact accepted receipt and root in the catalog, controller phase `COMPLETE`, settled worker, verifier and keeper, and a clear gate after normal retention. Record `runtimeAccepted` in the Pi installer receipt according to what the running revision actually proved. Archive verification supplies `decryptedRestoreProved`; an authorized boot drill supplies machine boot restoration evidence.

8. **Roll back from settled custody.** Pause the same three schedules and repeat the lock, gate, service and remote custody checks in steps 2 and 4. If an operation began on the candidate, reconcile its journal and immutable request on that revision first. Preserve accepted backups, journals, gates, catalog, notification ledger and private configuration.

   ```bash
   bash "$stage/tree/config/backup-repair/cutover.sh" rollback "$stage" "$controller" "$unit_dir" "$rollback" "$revision"
   systemctl --user daemon-reload
   systemctl --user cat weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service
   ```

   The rollback checks each managed file against the saved snapshots, restores the former bytes and modes, and preserves any candidate additions in the rollback directory. Verify the old receipt, selector, top-level manifest and effective unit paths. After confirming the previous revision can run, restore the timer states captured in step 2 and use the applicable rearm checks in steps 6 and 7. Preserve any new refusal evidence for exact-job diagnosis.

## Backblaze retention rollout

Use the standard deployment procedure above through step 4. Keep the Backblaze service and its timer paused during the key and policy changes. Preserve the existing controller lock inode, accepted catalog and all retirement journals. Only the supervisor runs these commands against the Pi and Backblaze.

1. **Install the archive and configure both scoped keys.** Rotate the exposed backup writer to a key restricted to `pavlovcik-arch-vps-backups` and prefix `restic/`. Its exact runtime capabilities are `listFiles`, `readFiles`, `writeFiles` and `deleteFiles`. Capture and restore authenticate under that existing scope. The separate retention key is restricted to the same single bucket with no filename prefix and needs `listFiles` for versions and unfinished-file listing, `writeFiles` to list parts and cancel unfinished large files, and `deleteFiles` to remove exact versions. Whole-bucket visible metadata supplies the byte denominator. The controller obtains the exact bucket ID and name from `b2_authorize_account`. It does not call `b2_list_buckets` and needs neither `listBuckets` nor `listAllBucketNames`. The latter capability reveals account-wide bucket names. The retention code confirms size and B2 SHA-1 metadata from exact versions, so the retention key does not require `readFiles`. Neither controller key needs bucket settings, delegation, or governance permissions. [Application keys](https://www.backblaze.com/docs/cloud-storage-application-keys) [List versions](https://www.backblaze.com/apidocs/b2-list-file-versions) [List unfinished files](https://www.backblaze.com/apidocs/b2-list-unfinished-large-files) [List parts](https://www.backblaze.com/apidocs/b2-list-parts) [Cancel large file](https://www.backblaze.com/apidocs/b2-cancel-large-file) [Delete exact version](https://www.backblaze.com/apidocs/b2-delete-file-version)

   On the Pi update only `accessKeyId` and `secretAccessKey` in the private `.private/b2-file-backup.json` writer config. Preserve its bucket identity, sources and recipient binding. Put the separate retention key in `.private/file-backup/retention-key.json` with exactly `accessKeyId`, `secretAccessKey`, `bucketId` and `bucketName`. Keep both files at mode `0600` and publish their complete replacements atomically under the existing controller lock when both gates and transactions are settled. Use a private editor or secret manager separate from transcripts and shell history. The controller copies each selected key only in the root-owned mode-`0600` `settings.json` for its immutable VPS runtime under `/var/tmp/arch-vps-file-backup-runtime/jobs/<job-id>/`. Preserve past runtime bindings. Future jobs receive the selected new key through the existing authenticated installation transport.

   Verify the writer without printing settings, IDs or B2 responses. From the deployed Pi controller directory, issue one bounded version-list read with the new writer's exact scope. This also exercises the same authorization capability check as capture. Keep the old key unreused and revoke it under the supervisor's rotation procedure once replacement key readback and settled custody are proved.

   ```bash
   /usr/local/bin/safepi deno run --no-prompt --allow-read=.,.private \
     --allow-run=/usr/bin/curl - <<'DENO'
   import { loadSourceConfig, realPiDeps } from "./scripts/backblaze-file-backup.ts";
   import { BACKUP_V2_NAMESPACE } from "./scripts/backup-v2-profile.ts";
   import { BackupV2Store } from "./scripts/backup-v2-store.ts";
   try {
     const { b2 } = await loadSourceConfig(realPiDeps());
     await new BackupV2Store(b2).versionsPage(BACKUP_V2_NAMESPACE, null);
     console.log("B2_WRITER_KEY_SCOPE_PROVED");
   } catch {
     console.error("B2_WRITER_KEY_SCOPE_UNPROVED");
     Deno.exitCode = 1;
   }
   DENO
   ```

2. **Verify the live catalog, then review a read-only plan before opting into deletion.** Keep execution disabled while doing the initial review. The controller defaults to the policy below when `.private/file-backup/retention-policy.json` is absent. Each property is optional. Existing deployed four-generation retention records and old receipts cannot opt into execution. The manual catalog command checks only exact catalog objects with matching provider IDs, names, lengths and applicable hash metadata. It leaves the bucket untouched even when the execution flag is enabled and does not launch a capture or clean source scratch. Verification does not download or decrypt archive payloads.

   ```json
   {
     "keepAccepted": 2,
     "orphanGraceHours": 72,
     "maxDeleteFraction": 0.5,
     "cleanLegacyOrphans": false,
     "execute": false
   }
   ```

   From the deployed Pi controller directory, use the same managed invocation for both commands. Each invocation reconciles one bounded slice. If it returns a running status, keep the exact transaction and rerun that command after its source unit progresses, or let the existing Backblaze service reconcile it. Inspect the private report for that run. Retention stays fenced while the exact source gate is held. A settled normal plan-only report allows the next due backup to start.

   ```bash
   umask 077
   cd /home/pi/ops/weekly-backup-controller
   /usr/local/bin/safepi deno run --no-prompt --allow-read=.,.private \
     --allow-write=.private --allow-run --allow-sys=uid --allow-net \
     scripts/verify-backblaze-catalog.ts

   november=generation-61d5c174-45ff-4d7d-baec-57d06da81e89
   october=generation-0846ac72-2994-4b1e-8629-9cab95462b3e
   jq -e --arg november "$november" --arg october "$october" '
     .status == "B2_RETENTION_CATALOG_VERIFIED" and .healthy and
     .summary.damagedCaptureIds == [] and
     (.checkedCaptureIds | index($november) != null and index($october) != null)
   ' .private/reports/backblaze-catalog-verification.json

   /usr/local/bin/safepi deno run --no-prompt --allow-read=.,.private \
     --allow-write=.private --allow-run --allow-sys=uid --allow-net \
     scripts/plan-backblaze-retention.ts
   report=.private/reports/backblaze-retention.json
   jq '{transactionId,observedAtUtc,status,policy,plan,retainedCaptureIds,summary}' "$report"
   plan=$(jq -er '.plan.path | select(test("^\\.private/file-backup/retention/[0-9a-f-]{36}/plan\\.json$"))' "$report")
   test "$(sha256sum "$plan" | cut -d' ' -f1)" = "$(jq -er '.plan.sha256' "$report")"
   jq -e --arg november "$november" --arg october "$october" '
     .policy.execute == false and .summary.blockReason == null and
     .summary.damagedCaptureIds == [] and
     (.retainedCaptureIds | index($november) != null and index($october) != null)
   ' "$report"
   jq '{retainedCaptureIds,retiredCaptureIds,evidence,summary}' "$plan"
   ```

   Confirm both named IDs and the transaction time before enabling execution. The report points to a private mode-`0600` plan with each candidate's exact identity, category, counts, bytes and eligibility evidence. Review version and unfinished-part bytes, unclassified/foreign bytes, and the cap. A damaged accepted generation raises an urgent alert with its ID. Keep intact older fallback entries while damage exists. A separately approved boot restore is still required for machine boot proof.

   A plan-only report can flag orphans while deletion is disabled. Review a candidate individually with `jq '.candidates[] | select(.reason == "UNACCEPTED_V2")' "$plan"` on the Pi. Share only counts, categories and the allowed named generation IDs. The controller state contains credential-bearing job settings. Every report and operator command above uses an allowlisted projection.

3. **Enable execution only after reviewing the real plan and verifying both survivors.** Leave `cleanLegacyOrphans` off for the first execution. Enabling the flag starts a fresh transaction that builds and writes its own complete plan before any effect. In the Pi directory, run the following under the existing controller lock with the service and its timer paused.

   ```bash
   flock -n .private/backup-controller.lock bash -euo pipefail -c '
     umask 077
     gate=.private/backup-controller-gate.json
     test ! -e "$gate" && test ! -L "$gate"
     for file in .private/file-backup/retention/{controller-v2,catalog-controller-v2}.json; do
       if [[ -e $file ]]; then
         jq -e '\''(.phase == "PLAN_ONLY" or .phase == "COMPLETE")'\'' "$file" >/dev/null
       fi
     done
     policy=.private/file-backup/retention-policy.json
     candidate=$(mktemp "${policy}.XXXXXX")
     trap '\''rm -f -- "$candidate"'\'' EXIT
     if [[ -e $policy ]]; then
       jq '\''.execute = true'\'' "$policy" > "$candidate"
     else
       printf '\''%s\n'\'' '\''{"execute":true}'\'' > "$candidate"
     fi
     chmod 0600 "$candidate"
     mv -T -- "$candidate" "$policy"
   '
   systemctl --user start backblaze-file-backup.service
   journalctl --user -u backblaze-file-backup.service --no-pager -o cat -n 30
   jq '{status,summary,retainedCaptureIds}' .private/reports/backblaze-retention.json
   ```

   Follow standard steps 5 through 7 to rearm existing schedules. A complete execution reports actual delete counts and bytes separately from prior removals reconciled as already absent. The transaction's private catalog retirement record preserves the preimage. A partial run retains the exact plan, mutation intent and source journal. To retry a transient failure, run the same existing service with that transaction, policy and credentials intact. After a catalog damage or identity mismatch, resolve the cause with the read-only verification command and retain all receipts. Avoid rerunning deletion with a new plan over an unsettled partial transaction. Verify both designated survivors again after the first execution. Before any rollback to a historical four-generation release, leave its Backblaze service paused until the supervisor explicitly reviews the retired legacy deletion path and catalog. That release predates the opt-in flag.

   For a later legacy cleanup review, put reviewed authority in the private policy. For a settled old direct-v1 capture outside the accepted catalog, `retiredLegacyCaptures` may list exact `captureId`, ISO UTC `retiredAtUtc` and SHA-256 `evidenceSha256` for the operator's ownership and retirement record. For an explicitly retired historic Restic repository, `retiredRestic` can identify its exact `prefix`, `retiredAtUtc` and `evidenceSha256`. Only recognized names under that reviewed path are eligible after the grace period. An active or unknown job or a live accepted reference still protects its data. Plan those changes and review before setting `cleanLegacyOrphans: true`.

### Native B2 lifecycle rules

Use the controller for the deployed shared backup namespaces. A native rule cannot verify catalog IDs, active custody, the upload-age grace for hidden data, fractional byte caps, or the private plan and delete journal. A retained exact version can have been hidden by a later upload or an explicit hide. A native one-day hidden rule can therefore remove a retained older version, and the one-day clock starts at hiding, not original upload. Backblaze applies lifecycle rules daily and uses the shortest value where matching prefixes overlap. Do not add a rule for `""`, `restic/`, `restic/backup-v2/`, or `restic/direct-v1/`.

A separately approved, isolated, retired prefix can use the exact rule below only after the operator verifies the prefix has no accepted references, active writers or ongoing uploads, all versions already satisfy the configured upload grace, the resulting deletion fits the approved byte cap, and any overlapping rule leaves the same limits. Replace the placeholder with that exact verified prefix. The cancellation value is the configured upload grace rounded up to whole days (3 for the default 72 hours). The hidden rule removes hidden versions on a later daily pass once one day hidden. It does not age out current visible versions. Keep automatic hiding null. No native rule is required for the current active bucket paths. Only the supervisor can update a lifecycle rule with the appropriate separate bucket settings authority. [B2 lifecycle rules](https://www.backblaze.com/docs/cloud-storage-lifecycle-rules) [Update bucket](https://www.backblaze.com/apidocs/b2-update-bucket)

```json
[
  {
    "fileNamePrefix": "<reviewed-isolated-retired-prefix>/",
    "daysFromStartingToCancelingUnfinishedLargeFiles": 3,
    "daysFromHidingToDeleting": 1,
    "daysFromUploadingToHiding": null
  }
]
```

### Upload-size proposal

No exclusions change in this release. The following VPS numbers are allocated disk bytes from a bounded `nice -n 19 du -sx -B1` pass as `codex` on 2026-11-18. They are neither encrypted archive sizes nor bucket inventory.

| Candidate | Observed allocated bytes | Restore consequence |
| --- | ---: | --- |
| Worktree `.data` under seven accessible repo worktrees | 18,583,552 | `/home/codex/repos` already covers these paths. Build artifacts must be regenerated. Private app repos excluded from the observation were skipped. No further upload saving from a nested exclusion. |
| User cache, Codex cache and Codex downloaded packages | 2,884,886,528 + 85,565,440 + 1,954,066,432 | Existing exclusions already cover these. Restore repopulates download/cache data. Codex sessions and config remain covered. |
| Pacman package cache | 1,012,047,872 | Already excluded. Restore retains the package database and redownloads package archives as needed. |
| `/var/tmp/arch-vps-file-backup*` | Unmeasured with ordinary user access | `/var/tmp` already covers backup scratch and immutable source runtimes. Restore reinstalls the checked release and recreates task scratch. Live recovery does not depend on copied temporary directories. |
| `~/.bun/install/cache` and `~/.cargo/registry/cache` | 845,766,656 + 89,337,856 | Candidates for a later exclusion after reviewing package sources. Restore redownloads registries and package caches, so offline or retired packages lose the local copy. Keep credentials and non-cache toolchain state. |
| `~/.cargo/registry/src` and `~/.npm/_npx` | Cargo source timed out in the bounded pass; npm 8,192 | Registry source may contain local modifications. Review ownership before excluding. npm temporary packages can be reinstalled, with negligible observed saving. |
| Docker image/build layers and containerd overlay data | Unmeasured with ordinary user access | Keep writable layers, volumes and stateful container data. Exclude only confirmed reproducible image/build-cache subtrees after an operator measures them and proves image redeploy or pull by digest. A whole Docker/containerd exclusion would lose local container state. |


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
