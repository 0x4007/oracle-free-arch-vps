#!/usr/bin/env bash
set -euo pipefail
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
[[ $# == 2 ]] || fail 'Usage: check-job.sh (bind|keeper|accepted) STAGE or source BACKUP_BASE'
action=$1
argument=$2
job_id=job-61d5c174-45ff-4d7d-baec-57d06da81e89
pinned_revision=3e7966c1eb1ef690afe0ee89c6d83e1e7f32e1f2
expected_gate=b2e3863e-93cc-4148-9f55-968f52aebb33
expected_invocation=fc7d5665651945d0b4bf724051df08be
base_evidence=.private/file-backup/jobs/$job_id
bridge_path=$base_evidence/bridge-$expected_gate
keeper_unit=arch-vps-b2-bridge-${job_id#job-}-$expected_gate.service

read_binding() {
  [[ -f $argument/job-binding.tsv && ! -L $argument/job-binding.tsv ]] || fail 'Missing recovery binding'
  IFS=$'\t' read -r bound_job gate_id request_sha256 < "$argument/job-binding.tsv"
  [[ $bound_job == "$job_id" && $gate_id == "$expected_gate" && $request_sha256 =~ ^[a-f0-9]{64}$ ]] ||
    fail 'Recovery binding differs'
}
case $action in
  bind)
    [[ -d $argument && ! -L $argument && $(stat -c '%a' -- "$argument") == 700 ]] ||
      fail 'Use a private stage'
    if ! values=$(jq -ers --arg job "$job_id" --arg pin "$pinned_revision" \
      --arg gate "$expected_gate" --arg invocation "$expected_invocation" '
      .[0].job as $job_record | .[1] as $live |
      if $job_record.phase == "CANCELLATION_BLOCKED" and $job_record.activeKind == "verify" and
         $job_record.verifierGate == $live and $live.state == "ACTIVE" and
         $live.kind == "verify" and $live.envelope.request.jobId == $job and
         $live.envelope.request.sourceRevision == $pin and $live.gateId == $gate and
         $live.custody.invocationId == $invocation and
         ($live.envelope.requestSha256 | test("^[a-f0-9]{64}$"))
      then [$job, $live.gateId, $live.envelope.requestSha256] | @tsv
      else error("Current job or verifier custody differs") end
    ' .private/file-backup/controller.json .private/backup-controller-gate.json 2>/dev/null); then
      fail 'Current job or verifier custody differs'
    fi
    binding_file=$argument/job-binding.tsv
    if [[ -e $binding_file || -L $binding_file ]]; then
      [[ -f $binding_file && ! -L $binding_file ]] && cmp -s -- "$binding_file" <(printf '%s\n' "$values") ||
        fail 'Existing recovery binding differs'
    else
      (set -o noclobber; printf '%s\n' "$values" > "$binding_file")
    fi
    printf '%s\n' 'Exact Pi verifier recovery binding verified'
    ;;
  keeper)
    read_binding
    keeper_fields=$(jq -er --arg unit "$keeper_unit" --arg boot "$(cat /proc/sys/kernel/random/boot_id)" '
      .bridge.keeper as $keeper |
      if .keeperBootId == $boot and .bridge.state == "CLOSED" and
         .bridge.reason == "TERMINAL" and .bridge.pendingOperations == 0 and
         $keeper.unitName == $unit and ($keeper.invocationId | test("^[a-f0-9]{32}$")) and
         ($keeper.cgroup | test("^/user\\.slice/[-A-Za-z0-9_./@]+$") and
           endswith("/" + $unit) and (split("/") | all(. != ".." and . != ".")))
      then [$keeper.invocationId, $keeper.cgroup] | @tsv
      else error("Exact closure proof differs") end
    ' "$bridge_path/status.json" 2>/dev/null) || fail 'Exact Pi keeper close proof differs'
    IFS=$'\t' read -r keeper_invocation keeper_cgroup <<< "$keeper_fields"
    [[ $(systemctl --user show --value -p InvocationID "$keeper_unit") == "$keeper_invocation" ]] ||
      fail 'Exact Pi keeper invocation differs'
    systemctl --user show "$keeper_unit" \
      -p ActiveState -p SubState -p Result -p MainPID -p ControlPID -p ControlGroup -p TasksCurrent
    keeper_events=/sys/fs/cgroup$keeper_cgroup/cgroup.events
    if [[ -r $keeper_events ]]; then
      awk '/^populated [01]$/ { print "keeperCgroupPopulated=" $2 }' "$keeper_events"
    else
      [[ ! -d ${keeper_events%/*} ]] || fail 'Recorded keeper cgroup is present but unreadable'
      printf '%s\n' 'keeperCgroupPresent=false'
    fi
    ;;
  source)
    base=$argument
    [[ $base == "$(realpath -e -- "$base")" ]] || fail 'Backup base path is not canonical'
    if [[ $base == /var/tmp/arch-vps-file-backup && $(id -u) != 0 ]]; then
      fail 'VPS source evidence requires the authorized root observer'
    fi
    generation=$base/generation-61d5c174-45ff-4d7d-baec-57d06da81e89
    worker=$generation/v2-bde5edf3-fed1-4e68-8cbc-87927aafd5a0/733d4a3948794ced908079ef83ec9924
    verifier=$generation/v2-$expected_gate/$expected_invocation
    lock=$base/source.lock
    owner=$(id -u):$(id -g)
    [[ -f $lock && ! -L $lock && $(stat -c '%u:%g:%a:%h' -- "$lock") == "$owner:600:1" ]] ||
      fail 'Backup source lock is missing or unsafe'
    lock_identity=$(stat -c '%d:%i' -- "$lock")
    exec 9<"$lock"
    flock -n 9 || fail 'Backup source lock is busy'
    [[ $(stat -Lc '%d:%i' -- /proc/self/fd/9) == "$lock_identity" &&
       $(stat -c '%d:%i' -- "$lock") == "$lock_identity" ]] ||
      fail 'Backup source lock identity differs'
    for directory in "$worker" "$verifier"; do
      [[ $directory == "$(realpath -e -- "$directory")" && $(stat -c '%u:%g:%a' -- "$directory") == "$owner:700" ]] ||
        fail 'Unsafe exact source artifact directory'
      for name in status.json result.json native-custody.ndjson; do
        file=$directory/$name
        [[ -f $file && ! -L $file && $(stat -c '%u:%g:%a:%h' -- "$file") == "$owner:600:1" ]] ||
          fail 'Unsafe exact source artifact'
        size_limit=2097152
        if [[ $name == native-custody.ndjson ]]; then size_limit=67108864; fi
        size=$(stat -c '%s' -- "$file")
        (( 0 < size && size <= size_limit )) || fail 'Exact source artifact size exceeds its bound'
      done
    done
    worker_hash=$(sha256sum -- "$worker/result.json" | cut -d' ' -f1)
    verifier_hash=$(sha256sum -- "$verifier/result.json" | cut -d' ' -f1)
    worker_native_hash=$(sha256sum -- "$worker/native-custody.ndjson" | cut -d' ' -f1)
    verifier_native_hash=$(sha256sum -- "$verifier/native-custody.ndjson" | cut -d' ' -f1)
    boot=$(cat /proc/sys/kernel/random/boot_id)
    jq -en --arg wh "$worker_hash" --arg vh "$verifier_hash" --arg boot "$boot" \
      --arg job "$job_id" --arg pin "$pinned_revision" --arg gate "$expected_gate" --arg invocation "$expected_invocation" \
      --arg wn "$worker_native_hash" --arg vn "$verifier_native_hash" \
      --slurpfile ws "$worker/status.json" --slurpfile wr "$worker/result.json" \
      --slurpfile vs "$verifier/status.json" --slurpfile vr "$verifier/result.json" '
      $ws[0] as $worker_status | $wr[0] as $worker_result |
      $vs[0] as $verifier_status | $vr[0] as $verified |
      $verified.receipt as $receipt |
      if ($worker_status.phase == "CLOUD_COMPLETE" and $worker_status.resultSha256 == $wh) and
         ($verifier_status.phase == "ACCEPTED" and $verifier_status.resultSha256 == $vh) and
         ($worker_status.sourceBootId == $boot and $verifier_status.sourceBootId == $boot) and
         ($worker_status.envelope == $worker_result.envelope and
          $worker_result.envelope == $verifier_status.envelope and
          $verifier_status.envelope == $verified.envelope and
          $verified.envelope.request.jobId == $job and
          $verified.envelope.request.sourceRevision == $pin) and
         ($worker_status.custody == $worker_result.custody and
          $verifier_status.custody == $verified.custody and
          $worker_result.custody.invocationId == "733d4a3948794ced908079ef83ec9924" and
          $verifier_status.gateId == $gate and $verified.gateId == $gate and
          $verified.custody.invocationId == $invocation and
          $worker_result.nativeCustodySha256 == $wn and $verified.nativeCustodySha256 == $vn) and
         ($verified.workerResultSha256 == $wh and
          $worker_result.selectedRoot == $verified.selectedRoot and
          $receipt.root == $verified.selectedRoot.reference and $receipt.verifierRevision == $pin) and
         ($receipt.archives | map(.role) == ["root","efi","staging-boot","staging-efi","oracle-root","oracle-oled","recovery"] and
           all(.[]; .inputComplete == true and .integrityChecked == true and
             .decompressionComplete == true and .gpgExitCode == 0 and
             .zstdExitCode == 0 and .tarExitCode == 0)) and
         ($receipt.bootSamples |
           map({role,member}) == [
             {role:"root",member:"./boot/Image"},
             {role:"root",member:"./boot/initramfs-linux.img"},
             {role:"staging-boot",member:"./arch-vmlinuz"},
             {role:"staging-boot",member:"./arch-initrd.img"}
           ] and all(.[]; .bytes > 0 and (.sha256 | test("^[a-f0-9]{64}$")))) and
         ($receipt.verifiedAtUtc | test("^[0-9T:.-]+Z$")) and
         $receipt.sourceIndependent == true and $receipt.decryptedRestoreProved == true and
         $receipt.machineBootRestoreProved == false
      then {verifiedAtUtc: $receipt.verifiedAtUtc, archiveRoles: ($receipt.archives | map(.role)),
            bootSampleCount: 4, sourceIndependent: true, decryptedRestoreProved: true, machineBootRestoreProved: false}
      else error("Exact VPS verifier proof differs") end
    ' 2>/dev/null || fail 'Exact VPS verifier proof differs'
    ;;
  accepted)
    read_binding
    jq -e --arg job "$job_id" --arg request "$request_sha256" '
      .job as $completed |
      $completed.phase == "COMPLETE" and $completed.verifierStatus.phase == "ACCEPTED" and
      $completed.verified.receipt.decryptedRestoreProved == true and
      $completed.verified.receipt.machineBootRestoreProved == false and
      ([.catalog[] | select(.schemaVersion == 2 and .envelope.request.jobId == $job and
         .envelope.requestSha256 == $request and .selectedRoot == $completed.verified.selectedRoot and
         .receipt == $completed.verified.receipt and .receiptReference == $completed.verified.receiptReference)] | length == 1)
    ' .private/file-backup/controller.json >/dev/null 2>&1 || fail 'Exact Pi catalog receipt is unproved'
    [[ ! -e .private/backup-controller-gate.json && ! -L .private/backup-controller-gate.json ]] ||
      fail 'Controller gate remains present'
    jq -es '
      .[0] as $status | .[1] as $settled |
      ($settled.identity.invocationId | test("^[a-f0-9]{32}$")) and
      ($settled.inputSha256 | test("^[a-f0-9]{64}$")) and
      $status.bridge.state == "CLOSED" and $status.bridge.reason == "TERMINAL" and
      $settled.identity == $status.bridge.keeper and
      $settled.boot == $status.keeperBootId and
      $settled.inputSha256 == $status.inputSha256
    ' "$bridge_path/status.json" "$bridge_path/settled.json" >/dev/null 2>&1 ||
      fail 'Exact Pi bridge settlement proof differs'
    source_proof=$base_evidence/v2-$gate_id-$expected_invocation-cleared.json
    jq -e --arg gate "$gate_id" --arg invocation "$expected_invocation" --arg request "$request_sha256" '
      .gate.gateId == $gate and .gate.envelope.requestSha256 == $request and
      .exactStop.invocationId == $invocation and .exactStop.sourceBootId == .gate.sourceBootId and
      .exactStop.completed == true and .exactStop.code == 0 and
      (.artifacts.resultSha256 | test("^[a-f0-9]{64}$")) and
      (.artifacts.nativeCustodySha256 | test("^[a-f0-9]{64}$"))
    ' "$source_proof" >/dev/null 2>&1 || fail 'Exact VPS verifier stop proof differs'
    printf '%s\n' 'Exact Pi catalog receipt, clear gate and both settlement proofs verified'
    ;;
  *) fail 'Unknown job evidence check' ;;
esac
