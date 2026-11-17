# Deploy and verify the November 2026 backup repair

Run as the supervisor with the accepted local `fix/backup-unblock` commit and existing authenticated Pi access. Keep the Oracle instance, required services and unrelated work online. This procedure moves only revision-bound source and control metadata. Backup payloads take their existing direct VPS-to-cloud routes.

On November 17 the deployed Pi controller was under `/home/pi/ops/weekly-backup-controller`. Its top-level `release.json` reported `66113e45` while a separate Pi Git checkout reported `1cd25c4`. The current installer receipt had 115 managed hashes and a 44-file source closure. Treat those counts as historical. The B2 controller recorded its previous cycle as complete on October 25, with an accepted verifier receipt and no gate listed in the captured Pi inventory. Fresh lock and remote custody evidence is required before deployment.

The old watchdog only queued a changed combined status and sent it to the Mac's `terminal-notifier` over SSH. The Pi ledger had 70 records with zero pending, most recently marked delivered on November 1, and subsequent unchanged failures produced no new sends. The SSH exit records establish the old publisher's result. Device notification receipt needs independent confirmation.

1. **Build the exact local artifact.** On the build host, bind `revision` to the full accepted commit from the handback. Archive only tracked runtime input from that commit and retain the SHA-256 separately. Copy the two files over the existing host-key-verified, authenticated supervisor-to-Pi channel to a Pi directory created with `mktemp -d /tmp/backup-repair.XXXXXX`. Pin the existing Pi host key using the established access profile. Send the 64-character archive digest to the operator in the authenticated handback. The Pi Git checkout is irrelevant to this transfer.

   ```sh
   set -euo pipefail
   umask 077
   test "$(git rev-parse HEAD)" = "$revision"
   build=$(mktemp -d /tmp/backup-repair-build.XXXXXX)
   git archive --format=tar --output="$build/controller.tar" "$revision" -- \
     deno.json scripts config BACKBLAZE-DIRECT-BACKUP.md DECISIONS.md \
     ONLINE-BACKUP-CONTRACT.md RECOVERY-PROCEDURE.md
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

   The following staged helper takes only the extracted source and the candidate SHA. It writes `install-paths.txt`, the new top-level release manifest, and the corresponding `sourceClosure` map to the stage. Save it as `$stage/derive.ts` and run `(cd "$stage" && /usr/local/bin/safepi deno run --cached-only --allow-read=. --allow-write=. derive.ts "$revision")`. The file list includes the functional entry points and their literal TypeScript import closures. It excludes live exclusions and private runtime state.

   ```ts
   import { collectBackupV2Release } from "./tree/scripts/backup-v2-controller.ts";
   import { backupV2ArtifactSha256 } from "./tree/scripts/backup-v2-worker.ts";

   const [revision] = Deno.args;
   const read = async (path: string) => {
     if (!/^scripts\/[A-Za-z0-9_.-]+\.ts$/.test(path)) throw Error("Unexpected module path");
     const stagePath = "tree/" + path;
     if (!(await Deno.lstat(stagePath)).isFile) throw Error("Expected a regular file");
     return await Deno.readFile(stagePath);
   };
   const b2Entries = [
     "scripts/backblaze-file-backup.ts",
     "scripts/backup-v2-controller.ts",
     "scripts/backup-v2-worker.ts",
     "scripts/backup-v2-bridge-runtime.ts",
   ];
   const pending = [
     ...b2Entries,
     "scripts/alerting-backup-scheduled.ts",
     "scripts/scheduled-backblaze-file-backup.ts",
     "scripts/backup-watchdog.ts",
     "scripts/calendar-observations.ts",
     "scripts/pi-recovery-session.ts",
   ];
   const hashes: Record<string, string> = {};
   for (let path = pending.shift(); path !== undefined; path = pending.shift()) {
     if (hashes[path]) continue;
     const bytes = await read(path);
     hashes[path] = backupV2ArtifactSha256(bytes);
     const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
     for (const [, relative] of text.matchAll(/(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'](\.[^"']+\.ts)["']/g)) {
       if (!/^\.\/[A-Za-z0-9_.-]+\.ts$/.test(relative)) throw Error("Unexpected import path");
       pending.push("scripts/" + relative.slice(2));
     }
   }
   const release = await collectBackupV2Release(revision, b2Entries, read, hashes);
   for (const path of [
     "deno.json",
     "config/weekly-backup.service",
     "config/backblaze-file-backup.service",
     "config/weekly-backup-watchdog.service",
   ]) {
     const stagePath = "tree/" + path;
     if (!(await Deno.lstat(stagePath)).isFile) throw Error("Expected a regular file");
     hashes[path] = backupV2ArtifactSha256(await Deno.readFile(stagePath));
   }
   const paths = Object.keys(hashes).sort();
   const json = (value: unknown) => JSON.stringify(value, null, 2) + "\n";
   await Deno.writeTextFile("install-paths.txt", paths.join("\n") + "\n");
   await Deno.writeTextFile("install-hashes.json", json(hashes));
   await Deno.writeTextFile("release.new.json", json(release.manifest));
   await Deno.writeTextFile("source-closure.json", json(Object.fromEntries(
     release.manifest.files.map(({ path, sha256 }) => [path, sha256]),
   )));
   ```

4. **Install under the controller lock.** On the Pi, confirm the live gate is absent and the B2 controller's current worker, verifier, bridge and pruner are settled. For any exact retained source job, check its current VPS boot and unit invocation against its terminal receipt, empty cgroup and escaped process inventory, zero open pipeline handles and pending operations, and free source lock at `/var/tmp/arch-vps-file-backup/source.lock`. An absent unit alone is incomplete evidence. Resolve any unsettled gate through its exact recorded recovery path before changing files or selectors.

   Save the shell helper below as `$stage/cutover.sh`. From the Pi shell create the rollback directory beneath the existing private controller directory, then run the helper. It holds the existing lock inode, checks the gate, saves the exact original files and receipt metadata, verifies staged and live hashes, publishes the marked candidate, and rechecks the installed manifests. Existing controller files retain their modes, new source is mode 0600, and the Pi user unit fragments use 0644. The helper keeps receipt fields including preserved exclusions and updates the B2 selector revision alone. Keep the rollback directory protected and accessible through acceptance.

   ```sh
   rollback=$(mktemp -d "$controller/.private/backup-repair-rollback.XXXXXX")
   unit_dir=/home/pi/.config/systemd/user
   bash "$stage/cutover.sh" install "$stage" "$controller" "$unit_dir" "$rollback" "$revision"
   systemd-analyze --user verify \
     "$unit_dir/weekly-backup.service" "$unit_dir/backblaze-file-backup.service" \
     "$unit_dir/weekly-backup-watchdog.service"
   systemctl --user daemon-reload
   systemctl --user cat weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service
   ```

   A partial copy leaves the timers paused and the snapshot available. The B2 runner materializes the revision-specific Pi release under `.private/file-backup/runtime/releases/<revision>/` using its current installer and uses its revision-bound VPS installation procedure. Retain previous immutable paths, source job bindings, and the three old manifests.

5. **Check the known claim and notification route.** Read the claim at `.private/backup-scheduled-window.json`, current schedule at `.private/backup-schedule.json`, runtime journal at `.private/backup-runtime.json`, and controller policy at `.private/backup-controller.json` on the Pi using its private permissions. Confirm the old claim is a started weekly claim and its recorded `approvedSchedule` matches the current approved fields, including any acceptance window. Its `windowId` and `periodId` must be the same approved civil period at its `updatedAtUtc` and that period must be at least 13 hours past its start. Confirm `claim.previousCycleSuffix === runtime.cycle.suffix`, `cycle.mode === "online"`, `cycle.phase === "complete"`, and the cycle was updated before the claim. Confirm the same source, group, and standing approval in the journal and configuration. Read the exact home-region group backup inventory and prove the old group's recorded FULL pair remains AVAILABLE, the source is RUNNING, and there is no newer or ambiguous group operation since the old journal checkpoint. Recheck gate, workers and locks. The new scheduler reconciles and archives the exact legacy claim under the shared lock before a fresh attempt. Leave the live claim and journal in place for that proof. If the run reports `SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE` or `SCHEDULED_CLAIM_CUSTODY_OVERDUE`, retain both records and resolve the failed comparison. Use the separate documented procedure for an expired one-time acceptance claim. [Troubleshooting](06-TROUBLESHOOTING.md#scheduled-backup-requires-claim-reconciliation)

   The existing notification config stays at `.private/backup-notification.json`, mode 0600. Missing config and the valid legacy Mac config migrate to `https://ntfy.pavlovcik.com/alerts`. To override, set `{"destination":"https://ntfy.pavlovcik.com/alerts"}` with the intended HTTPS server/topic. The destination is one HTTPS topic URL without embedded credentials, query, or fragment. The existing ledger is `.private/backup-alerts.json`. A first refusal is queued immediately, repeated observations remain one incident per stream, and reminders are due every six hours while the streams remain unhealthy. Failed sends stay pending with a 15-minute retry interval through the existing timers. For delivery evidence before recovery, run `systemctl --user start weekly-backup-watchdog.service` while the actual missed-window report still applies. Inspect the current report and ledger for the new receipt and check arrival on a device subscribed to the configured server/topic. An unhealthy watchdog can exit nonzero even when ntfy confirmed the alert.

6. **Start Oracle once and verify.** Keep both capture timers paused initially. Start `systemctl --user start --no-block weekly-backup.service` and follow `journalctl --user -u weekly-backup.service -f`. Verify service result and the fresh runtime/claim are complete in the current approved period. Record the new group and both exact members privately, then query fresh OCI state for FULL/AVAILABLE, expected source volume IDs and 50/150 GB sizes, exact group/suffix, home region, and timestamps. Reconcile live limits and remaining slots. Confirm OCI stayed RUNNING and the journal's `sourceContinuityBeforeCapture` and `sourceContinuityAfterCapture` carry the same boot and required-service invocation IDs with the fresh working probes. Only then accept the point as `METADATA_PROVED`. Retirement requires separate confirmation that the accepted replacement exists and the old pair's status is as approved. Boot restore requires a separately approved drill.

7. **Start Backblaze once and verify.** After Oracle acceptance, start `systemctl --user start --no-block backblaze-file-backup.service`. Follow `journalctl --user -u backblaze-file-backup.service -f` and its exact current job in the private Pi reports. Allow the existing 15-minute timer to reconcile the legitimately active v2 job after its bounded initial invocation, restoring that timer to its recorded state. The initial progress return proves admission or custody only. Acceptance requires the new current-period job's B2 worker result, the independent verifier's successful full reconstruction/decryption and archive verification, the exact verifier receipt and selected B2 root recorded in the new catalog entry, `.private/file-backup/controller.json` at `COMPLETE`, and the exact worker/verifier/bridge settled with its capture gate cleared. Check immutable revision and catalog entry against the fresh reports. Separate the accepted backup from retention/prune success and from machine boot restore. Restore the remaining timer states, run the watchdog again, verify current accepted periods and recovery alert results, then update `runtimeAccepted` in the private Pi installer receipt according to the proven runtime result.

8. **Roll back only from settled custody.** Pause the three existing timers again and repeat the lock, gate, service and remote custody checks. If a fresh operation began, first reconcile its actual OCI or Backblaze journal and immutable request with its original revision. Keep accepted backups, journals, gates, catalog, notification ledger and private configuration with their real state. For a failed pre-operation deployment run `bash "$stage/cutover.sh" rollback "$stage" "$controller" "$unit_dir" "$rollback" "$revision"`. It verifies each current target against the two saved revisions, restores original file bytes and modes, and retains newly added candidate files in the rollback directory. Compare all old hashes before reloading the user manager. Verify services resolve to the known fragments before deciding whether the old schedules are safe to resume. The previous code can reproduce the original subscription and claim failures, so a restored source tree alone does not establish a safe resumed backup service.

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

## Cutover and rollback helper

Save this script as `$stage/cutover.sh`. It expects the verified stage and preflight from steps 2–4, the existing Pi user unit directory, and a newly created private rollback directory for installation. Rollback reuses those same paths.

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# == 6 ]]
action=$1 stage=$(realpath -- "$2") controller=$(realpath -- "$3")
unit_dir=$(realpath -- "$4") rollback=$(realpath -- "$5") revision=$6
[[ $revision =~ ^[0-9a-f]{40}$ && ( $action == install || $action == rollback ) ]]
receipt=.private/reports/pi-session-deployment.json
selector=.private/backblaze-deployment.json
units=(weekly-backup.service backblaze-file-backup.service weekly-backup-watchdog.service)
targets=$rollback/targets
before=$rollback/before

fail() { printf '%s\n' "$*" >&2; exit 1; }
verify_hashes() {
  local hash_map=$1 directory=$2 list
  list=$(mktemp -- "$stage/checksums.XXXXXX")
  jq -er 'to_entries[] |
    if (.key | test("^[A-Za-z0-9][A-Za-z0-9._/-]+$")) and
       (.key | split("/") | all(. != "" and . != "." and . != "..")) and
       (.value | test("^[0-9a-f]{64}$"))
    then "\(.value)  \(.key)" else error("Invalid manifest entry") end' "$hash_map" > "$list"
  (cd "$directory" && sha256sum --check --strict --status "$list")
}

destination() {
  case $1 in
    controller/*) printf '%s/%s\n' "$controller" "${1#controller/}" ;;
    units/*) printf '%s/%s\n' "$unit_dir" "${1#units/}" ;;
    *) fail "Unknown destination class" ;;
  esac
}

candidate() {
  case $1 in
    "controller/$receipt") printf '%s\n' "$rollback/receipt.new.json" ;;
    "controller/$selector") printf '%s\n' "$rollback/selector.new.json" ;;
    controller/release.json) printf '%s\n' "$stage/release.new.json" ;;
    controller/*) printf '%s/%s\n' "$stage/tree" "${1#controller/}" ;;
    units/*) printf '%s/config/%s\n' "$stage/tree" "${1#units/}" ;;
    *) fail "Unknown source class" ;;
  esac
}

copy_atomically() {
  local source=$1 target=$2 mode=$3 temporary
  temporary=$(mktemp -- "$target.backup-repair.XXXXXX")
  install -m "$mode" -- "$source" "$temporary"
  mv -T -- "$temporary" "$target"
}

test -f "$controller/.private/backup-controller.lock"
test ! -L "$controller/.private/backup-controller.lock"
exec {controller_fd}<>"$controller/.private/backup-controller.lock"
flock -n "$controller_fd"
[[ ! -e $controller/.private/backup-controller-gate.json &&
   ! -L $controller/.private/backup-controller-gate.json ]] || fail "Controller gate present"

if [[ $action == install ]]; then
  [[ ! -e $targets && ! -e $before ]] || fail "Use a fresh private rollback directory"
  jq -er '.hashes' "$controller/$receipt" > "$stage/live-hashes.json"
  verify_hashes "$stage/live-hashes.json" "$controller"
  verify_hashes "$stage/install-hashes.json" "$stage/tree"
  baseline=$(jq -er '.sourceRevision | select(test("^[0-9a-f]{40}$"))' "$controller/$receipt")
  [[ $(jq -er .sourceRevision "$controller/$selector") == "$baseline" ]] ||
    fail "Live installer receipt and B2 selector differ"
  jq -e 'keys == ["recipientFingerprint", "recipientSha256", "sourceRevision"]' "$controller/$selector" >/dev/null
  jq -e --arg revision "$revision" --slurpfile closure "$stage/source-closure.json" '
    .sourceRevision == $revision and
    (.files | map({key: .path, value: .sha256}) | from_entries) == $closure[0]
  ' "$stage/release.new.json" >/dev/null
  jq -er 'keys[]' "$stage/install-hashes.json" > "$stage/expected-paths.txt"
  cmp -s -- "$stage/expected-paths.txt" "$stage/install-paths.txt"
  while IFS= read -r path; do
    [[ $path =~ ^scripts/[A-Za-z0-9_.-]+\.ts$ ||
       $path == deno.json ||
       $path == config/weekly-backup.service ||
       $path == config/backblaze-file-backup.service ||
       $path == config/weekly-backup-watchdog.service ]] || fail "Unexpected path in install list"
    printf 'controller/%s\n' "$path" >> "$targets"
  done < "$stage/install-paths.txt"
  for unit in "${units[@]}"; do printf 'units/%s\n' "$unit" >> "$targets"; done
  printf 'controller/%s\n' release.json "$receipt" "$selector" >> "$targets"

  while IFS= read -r key; do
    dest=$(destination "$key")
    [[ ! -L $dest ]] || fail "Refuse symlinked destination"
    if [[ -e $dest ]]; then
      [[ -f $dest && -O $dest ]] || fail "Destination is not a file owned by this account"
      install -d -m 0700 -- "$before/${key%/*}"
      cp -p -- "$dest" "$before/$key"
    fi
  done < "$targets"
  saved_receipt=$before/controller/$receipt
  saved_selector=$before/controller/$selector
  [[ -f $saved_receipt && -f $saved_selector && -f $before/controller/release.json ]]
  previous_hash=$(sha256sum "$saved_receipt" | cut -d' ' -f1)
  jq --arg revision "$revision" --arg baseline "$baseline" \
    --arg stamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg rollback "$rollback" \
    --arg previous "$previous_hash" --slurpfile replacement "$stage/install-hashes.json" \
    --slurpfile closure "$stage/source-closure.json" '
      .sourceRevision = $revision | .baseline = $baseline | .deployedAtUtc = $stamp |
      .runtimeAccepted = false | .previousReceiptSha256 = $previous | .rollbackDirectory = $rollback |
      .preservedUnrelatedManagedPaths = (
        ((.preservedUnrelatedManagedPaths // []) - ($replacement[0] | keys)) +
        ((.hashes | keys) - ($replacement[0] | keys) - ["config/restic-excludes.txt"]) | unique
      ) |
      .hashes += $replacement[0] | .sourceClosure = $closure[0]
    ' "$saved_receipt" > "$rollback/receipt.new.json"
  jq --arg revision "$revision" '.sourceRevision = $revision' "$saved_selector" > "$rollback/selector.new.json"
  touch -- "$rollback/snapshot-ready"

  while IFS= read -r key; do
    origin=$(candidate "$key")
    dest=$(destination "$key")
    case $key in
      units/*) mode=0644 ;;
      controller/.private/*|controller/release.json) mode=0600 ;;
      *) if [[ -e $dest ]]; then mode=$(stat -c %a "$dest"); else mode=0600; fi ;;
    esac
    copy_atomically "$origin" "$dest" "$mode"
    cmp -s -- "$origin" "$dest"
  done < "$targets"
  jq -er '.hashes' "$controller/$receipt" > "$stage/live-hashes.json"
  verify_hashes "$stage/live-hashes.json" "$controller"
  jq -e --slurpfile top "$controller/release.json" '
    ($top[0].files | map({key: .path, value: .sha256}) | from_entries) as $manifest |
    .sourceRevision == $top[0].sourceRevision and .sourceClosure == $manifest and
    (.hashes as $hashes | $manifest | to_entries | all($hashes[.key] == .value))
  ' "$controller/$receipt" >/dev/null
  [[ $(jq -er .sourceRevision "$controller/$selector") == "$revision" ]]
else
  test -f "$rollback/snapshot-ready"
  [[ $(jq -er .sourceRevision "$rollback/receipt.new.json") == "$revision" ]]
  while IFS= read -r key; do
    dest=$(destination "$key")
    archived=$before/$key
    origin=$(candidate "$key")
    [[ ! -L $dest ]] || fail "Refuse symlinked destination"
    if [[ -e $dest ]]; then
      [[ -f $dest && -O $dest ]] || fail "Destination changed ownership or type"
      cmp -s -- "$dest" "$archived" || cmp -s -- "$dest" "$origin" ||
        fail "Destination differs from both deployment snapshots"
    else
      [[ ! -e $archived ]] || fail "An original deployment file disappeared"
    fi
  done < "$targets"
  while IFS= read -r key; do
    dest=$(destination "$key")
    archived=$before/$key
    if [[ -f $archived ]]; then
      copy_atomically "$archived" "$dest" "$(stat -c %a "$archived")"
      cmp -s -- "$archived" "$dest"
    elif [[ -f $dest ]]; then
      retained=$rollback/added-candidate/$key
      install -d -m 0700 -- "${retained%/*}"
      [[ ! -e $retained ]] || fail "Candidate archive already exists"
      mv -T -- "$dest" "$retained"
    fi
  done < "$targets"
  jq -er '.hashes' "$controller/$receipt" > "$stage/live-hashes.json"
  verify_hashes "$stage/live-hashes.json" "$controller"
  [[ $(jq -er .sourceRevision "$controller/$selector") == "$(jq -er .sourceRevision "$controller/$receipt")" ]]
fi
printf '%s\n' "Controller file hashes verified"
```
