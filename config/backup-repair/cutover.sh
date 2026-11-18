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
installer_dir=$controller/config/backup-repair

fail() { printf '%s\n' "$*" >&2; exit 1; }
check_installer_directory() {
  [[ -d $controller/config && ! -L $controller/config && -O $controller/config &&
     ! -L $installer_dir ]] || fail "Unsafe installer parent directory"
  if [[ -e $installer_dir ]]; then
    [[ -d $installer_dir && -O $installer_dir ]] ||
      fail "Unsafe installer parent directory"
  fi
}
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
  check_installer_directory
  if [[ ! -d $installer_dir ]]; then
    touch -- "$rollback/created-installer-directory"
  fi
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
       $path == config/backup-repair/install-b2-credential.sh ||
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
  if [[ -f $rollback/created-installer-directory ]]; then
    mkdir -m 0700 -- "$installer_dir"
  fi

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
  check_installer_directory
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
  if [[ -f $rollback/created-installer-directory && -d $installer_dir ]]; then
    rmdir --ignore-fail-on-non-empty -- "$installer_dir"
  fi
  jq -er '.hashes' "$controller/$receipt" > "$stage/live-hashes.json"
  verify_hashes "$stage/live-hashes.json" "$controller"
  [[ $(jq -er .sourceRevision "$controller/$selector") == "$(jq -er .sourceRevision "$controller/$receipt")" ]]
fi
printf '%s\n' "Controller file hashes verified"
