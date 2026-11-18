#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# == 3 ]] || { printf '%s\n' 'Usage: install-vps-release.sh STAGE REVISION RELEASES_DIR' >&2; exit 64; }
stage=$(realpath -e -- "$1")
revision=$2
releases_dir=$3
uid=$(id -u)
gid=$(id -g)

fail() { printf '%s\n' "$1" >&2; exit 1; }
[[ $revision =~ ^[0-9a-f]{40}$ ]] || fail 'Invalid immutable revision'
[[ $releases_dir == "$(realpath -e -- "$releases_dir")" ]] || fail 'Release directory path is not canonical'
verify_directory() {
  [[ -d $1 && ! -L $1 && $(stat -c '%u:%g:%a' -- "$1") == "$uid:$gid:700" ]] ||
    fail 'Unsafe release directory ownership, type, or mode'
}
verify_file() {
  [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a:%h' -- "$1") == "$uid:$gid:600:1" ]] ||
    fail 'Unsafe release file ownership, type, mode, or link count'
}
if [[ $releases_dir == /var/tmp/arch-vps-file-backup-runtime/releases ]]; then
  [[ $uid:$gid == 0:0 ]] || fail 'The VPS release must be installed by root'
  verify_directory "${releases_dir%/*}"
fi
verify_directory "$releases_dir"
manifest=$stage/release.new.json
[[ -f $manifest && ! -L $manifest ]] || fail 'Staged release manifest is missing'
release_json=$(jq -ce --arg revision "$revision" '
  if keys == ["files", "sourceRevision"] and
     .sourceRevision == $revision and
     (.files | type == "array" and length > 0 and length <= 256) and
     (.files | all(keys == ["path", "sha256"] and
       (.path | test("^scripts/[A-Za-z0-9_.-]+\\.ts$")) and
       (.sha256 | test("^[a-f0-9]{64}$")))) and
     (.files | map(.path) | length == (unique | length))
  then . else error("Invalid immutable release manifest") end
' "$manifest")
hashes=$(jq -er '.files[] | "\(.sha256)  \(.path)"' <<< "$release_json")
expected_paths=$({ printf '%s\n' release.json scripts; awk '{print $2}' <<< "$hashes"; } | LC_ALL=C sort)
verify_release() {
  local tree=$1 path digest actual_paths
  verify_directory "$tree"
  verify_directory "$tree/scripts"
  verify_file "$tree/release.json"
  [[ $(jq -ce . "$tree/release.json") == "$release_json" ]] ||
    fail 'Existing immutable release manifest differs'
  actual_paths=$(cd "$tree" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort)
  [[ $actual_paths == "$expected_paths" ]] || fail 'Immutable release contains a missing or unexpected file'
  while read -r digest path; do
    verify_file "$tree/$path"
  done <<< "$hashes"
  (cd "$tree" && sha256sum --check --strict --status <<< "$hashes") ||
    fail 'Immutable release file hash differs'
}

destination=$releases_dir/$revision
if [[ -e $destination || -L $destination ]]; then
  verify_release "$destination"
  printf 'Verified existing immutable VPS release %s\n' "$revision"
  exit 0
fi

temporary=$(mktemp -d -- "$releases_dir/.install-$revision.XXXXXX")
trap 'if [[ -d $temporary && ! -L $temporary ]]; then rm -rf --one-file-system -- "$temporary"; fi' EXIT
install -d -m 0700 -o "$uid" -g "$gid" -- "$temporary/scripts"
printf '%s\n' "$release_json" > "$temporary/release.json"
while read -r digest path; do
  source_path=$stage/tree/$path
  [[ -f $source_path && ! -L $source_path && $(realpath -e -- "$source_path") == "$source_path" ]] ||
    fail 'Staged source path is not a regular file'
  install -m 0600 -o "$uid" -g "$gid" -- "$source_path" "$temporary/$path"
done <<< "$hashes"
verify_release "$temporary"
sync -- "$temporary"/scripts/* "$temporary/release.json" "$temporary/scripts" "$temporary"
mv -T -n -- "$temporary" "$destination"
verify_release "$destination"
sync -- "$releases_dir"
printf 'Verified immutable VPS release %s\n' "$revision"
