#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

fail() { printf '%s\n' "$1" >&2; exit 1; }
take_b2_controller_lock() {
  local lock=.private/backup-controller.lock
  [[ -d .private && ! -L .private && -O .private &&
     -f $lock && ! -L $lock && -O $lock ]] ||
    fail B2_CREDENTIAL_CONTROLLER_LOCK_UNPROVED
  { exec {lock_fd}<"$lock"; } 2>/dev/null ||
    fail B2_CREDENTIAL_CONTROLLER_LOCK_UNPROVED
  (
    unset BACKBLAZE_MASTER_KEY_ID BACKBLAZE_MASTER_KEY
    exec /usr/bin/flock -n "$lock_fd"
  ) || fail B2_CREDENTIAL_CONTROLLER_LOCK_BUSY
  [[ $lock -ef /proc/$$/fd/$lock_fd ]] ||
    fail B2_CREDENTIAL_CONTROLLER_LOCK_UNPROVED
}

[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
[[ $# == 1 && ( $1 == install || $1 == rollback ) ]] ||
  fail B2_CREDENTIAL_USAGE_INSTALL_OR_ROLLBACK
controller=$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd -P) ||
  fail B2_CREDENTIAL_CONTROLLER_DIRECTORY_UNPROVED
[[ $controller == /home/pi/ops/weekly-backup-controller &&
   $(pwd -P) == "$controller" ]] ||
  fail B2_CREDENTIAL_CONTROLLER_DIRECTORY_UNPROVED
account=$(
  unset BACKBLAZE_MASTER_KEY_ID BACKBLAZE_MASTER_KEY
  /usr/bin/id -un
) || fail B2_CREDENTIAL_PI_ACCOUNT_UNPROVED
[[ $account == pi ]] || fail B2_CREDENTIAL_PI_ACCOUNT_UNPROVED
take_b2_controller_lock
cache=$(
  unset BACKBLAZE_MASTER_KEY_ID BACKBLAZE_MASTER_KEY
  /usr/bin/mktemp -d -- /tmp/pi-b2-credential.XXXXXX
) || fail B2_CREDENTIAL_PERSISTENCE_UNPROVED
trap '(unset BACKBLAZE_MASTER_KEY_ID BACKBLAZE_MASTER_KEY; /usr/bin/rm -rf -- "$cache") 2>/dev/null || :' EXIT

set +e
result=$(DENO_DIR="$cache" DENO_NO_UPDATE_CHECK=1 \
  /usr/bin/timeout --kill-after=5s 75s deno run --no-prompt --no-remote --no-lock \
  --allow-read=.,.private --allow-write=.private --allow-sys=uid \
  --allow-run=ssh,/usr/bin/curl \
  --allow-env=BACKBLAZE_MASTER_KEY_ID,BACKBLAZE_MASTER_KEY \
  scripts/install-b2-credential.ts "$1" 2>&1)
status=$?
set -e
case "$result:$status" in
  B2_CREDENTIAL_INSTALLED:0|B2_CREDENTIAL_ROLLED_BACK:0)
    printf '%s\n' "$result"
    ;;
  B2_CREDENTIAL_LOCAL_CUSTODY_UNPROVED:1|B2_CREDENTIAL_SOURCE_CUSTODY_UNPROVED:1|\
  B2_CREDENTIAL_ENV_MISSING:1|B2_CREDENTIAL_SCOPE_REJECTED:1|\
  B2_CREDENTIAL_ROLLBACK_MISSING:1|B2_CREDENTIAL_CONFIG_CHANGED:1|\
  B2_CREDENTIAL_SETTINGS_INVALID:1|B2_BUCKET_IDENTITY_MISMATCH:1|\
  B2_CREDENTIAL_AUTH_UNPROVED:1|B2_CREDENTIAL_PERSISTENCE_UNPROVED:1)
    fail "$result"
    ;;
  *)
    if [[ $status == 124 || $status == 137 ]]; then
      fail B2_CREDENTIAL_INSTALL_DEADLINE_EXPIRED
    fi
    fail B2_CREDENTIAL_PERSISTENCE_UNPROVED
    ;;
esac
