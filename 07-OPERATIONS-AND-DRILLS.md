# Operations and Recovery Drills

This file covers the operational gaps that remain after the first accepted
build. It does not change the accepted 50/150 GB architecture.

## Automation setup

The tools use Deno and the installed OCI CLI. They accept no resource IDs,
approvals, or secrets on the command line or through environment variables.

1. Copy `config/restore.example.json` to `.private/restore.json` and
   `config/weekly-audit.example.json` to `.private/weekly-audit.json`.
2. Restrict both private files to mode `0600`.
3. Fill them from the private identifier and approval ledgers.
4. Keep `.private/` out of Git and shared reports.
5. Run `deno task restore` or `deno task weekly:audit` from the repository root.

`scripts/oci-restore.ts` reads its action from the private JSON file. `plan` and
`inventory` are read-only. `restore` refuses to run without an exact approval,
an available full 50/150 backup pair, zero live-volume use, no non-terminated
instance, and an unassigned reserved IP. The approval must be less than one hour
old and repeat the exact backup, source-volume, compartment, availability-domain,
subnet, and reserved-IP targets from the restore configuration.

## Shutdown lifecycle state machine

Use this sequence for every backup outage:

```text
quiesce applications
  -> sync disks
  -> request approved OCI SOFTSTOP from the operator system
  -> observe STOPPING
  -> poll OCI for STOPPED for up to 1,200 seconds
       -> STOPPED: continue
       -> timeout/error: reread OCI state and fail closed
```

Set `action` to `soft-stop` only after recording current exact approval for the
configured instance. The tool requires `RUNNING`, uses OCI `SOFTSTOP`, waits for
`STOPPED`, and returns `STOPPED`, `SOFTSTOP_TIMEOUT`, `SOFTSTOP_FAILED`, or
`UNEXPECTED_LIFECYCLE_STATE`. It rereads state after the OCI action and never
automatically invokes immediate `STOP` or `RESET`.

OCI can power off a guest that has not completed a `SOFTSTOP` within 15 minutes.
Stop or flush databases and stateful containers before the request. The
read-only `wait-for-stopped` action remains available, but guest-only poweroff
does not release the OCI allocation. Its timeout returns
`CONTROL_PLANE_STOP_REQUIRED`. The `stopWaitSeconds` setting applies only to
that observer; the `soft-stop` action always uses Oracle's 1,200-second window.

Immediate `STOP` needs separate exact approval after a failed or timed-out
`SOFTSTOP` and independent evidence that the guest is quiescent. Never chain
that fallback automatically.

## Repository synchronization result contract

Repository synchronization is optional and deployment-specific. This sanitized
kit does not contain organization names, credentials, repository lists, or a
sync implementation. If an operator enables a synchronization service, its
implementation must satisfy this contract before acceptance.

A synchronization run must report:

- UTC run ID and completion time.
- Attempted, cloned, synchronized, skipped, and failed counts.
- One classified reason for every failure.
- `complete-success`, `partial-failure`, or `total-failure`.

Return zero only for complete success. Return a distinct nonzero status for a
partial failure and another nonzero status for total failure. A systemd unit
failure is the minimum durable local alert. Do not send an external message
without explicit authorization.

An ignored failure needs a documented owner, reason, and expiry. It must not be
silently removed from the attempted count. Unit exit status alone is not enough
evidence; retain the summary and classified failure list.

## Weekly OCI idle-risk report

Run `deno task weekly:audit` at least weekly from an operator system that has an
authenticated OCI CLI. The tool records:

- Hourly `CpuUtilization` and its calculated seven-day 95th percentile.
- Hourly `MemoryUtilization`.
- `NetworksBytesIn` and `NetworksBytesOut`.
- Coverage start, end, point count, and `pending-seven-day-window` state.
- Tenancy-wide home-region bucket, current-object, stored-version, byte, limit,
  and headroom totals.

Use the tenancy OCID, not a child compartment OCID, as `compartmentId`. A bucket
with versioning enabled is counted from all stored versions. An active multipart
upload makes byte accounting incomplete because the supported OCI CLI does not
report uploaded-part bytes through this command set; the audit then fails closed.

Oracle publishes the idle threshold as a network-utilization percentage, but the
standard compute metrics expose network bytes. The tool reports those bytes and
does not invent a percentage conversion. When CPU is at or above 20% for the
required percentile, that condition alone disproves the all-below-20%
definition. A new or recently restarted metric stream remains
`pending-seven-day-window` until it covers seven days.

Observe normal use. Do not create artificial CPU, memory, or network load to
avoid reclamation.

## Restore automation and capacity

The restore tool first checks both backup objects, all live volumes, all live
instances, and every configured availability domain. It restores nothing when
the existing live-volume total is nonzero because the replacement pair itself
uses the full 200 GB target.

Capacity reports select an availability domain before volume creation. If an
instance launch still fails for capacity after the pair is restored, stop and
record the candidate resource identifiers privately. Do not create another pair
in another domain. Delete the failed candidate pair only after exact approval,
then recompute storage and retry.

The control-plane tool records `METADATA_PROVED`. A restore drill is
`RESTORE_DRILL_PROVED` only after the restored guest boots and passes the UUID,
GRUB, staged-kernel parity, SSH, service, listener, IP, and DNS checks. Under a
strict 200 GB live limit, a full drill requires retiring the current live pair
or a temporary paid exception. Do neither without exact approval.

The tool proves the exact restored root volume has one `ATTACHED`
paravirtualized attachment before it assigns the reserved IP. It does not force
the boot-volume transport in the launch request; OCI rejects that override on
this restore path. Inspect the returned launch options and complete the live
boot checks before acceptance.

## External encrypted recovery copy

Keep one client-side encrypted copy outside both OCI and the operator Mac. Use
`age` or an equivalent authenticated encryption tool. Keep the private recovery
key outside the VPS and outside this repository.

The copy must contain only the approved recovery documents and required local
artifacts. Record:

- Ciphertext name, size, SHA-256, and remote provider.
- Recipient-key fingerprint, not the private key.
- Source artifact hashes.
- Upload completion evidence.
- An isolated decrypt and archive-list test.

Do not call the current unencrypted archive an encrypted external copy. The
owner must select the remote destination and recipient key before this step can
run.
