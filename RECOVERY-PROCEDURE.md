# Repeatable operator-guided recovery

Use this procedure with one revision-bound recovery kit and its matching
`scripts/`, `config/` and `deno.json`. The Pi is the operational controller at
`/home/pi/ops/weekly-backup-controller`. Independent tooling copies live under
`~/.local/share/arch-vps-recovery/tooling/<sourceRevision>` on Pi and Mac.
Verify every manifest hash before use. Keep protected credentials and private
recovery keys outside the public source snapshot.

This procedure incorporates the corrections used in the September 8–10 drills.
Those runs prove dated, operator-assisted recovery. A separate September 11 run
proved clean unattended reconstruction and application acceptance at revision
`d462c6d159dc2103af3d94b703a61b530dfd051b`, followed by visual desktop
acceptance. Read [the dated evidence](RECOVERY-ACCEPTANCE-2026-09-11.md) and
[the unattended entry point](UNATTENDED-RECOVERY.md). A controller approval
report is a checkpoint for binding an authorized operation, not permission to
invent acceptance or to extend an expired resource lifetime.

## Inputs that must survive source loss

Keep these small records off the source, alongside the protected operational
configuration. Never put their private contents in Git:

| Input                  | Required content and origin                                                                                                                                                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tooling                | One complete source revision, import closure, public bootstrap key, manifest and this procedure. Do not mix a rescue manifest from an old request with new bootstrap bytes.                                                            |
| Controller identity    | Existing `.private/backup-controller.json` and OCI CLI/profile configuration; exact source instance, both volumes, home region and compartment. This is retained control data, not a request to read the failed source.                |
| Oracle recovery unit   | Accepted capture identity, group and both member IDs, captured root/staging UUIDs, root partition start sector, kernel/initramfs/GRUB hashes, and representative data expectations. Select the complete group from provider inventory. |
| Independent generation | Complete accepted catalog entry, index digest, all seven indexed roles and exact B2 object versions. Use the portable accepted catalog if the running controller is unavailable. Never combine generations.                            |
| Independent access     | Existing scoped B2 configuration, public recipient and off-source private key/keyring. Verify access without printing secrets. The private key stays on Pi; the target receives a restricted agent connection.                         |
| SSH trust              | Existing non-root login identity and independently verified host keys or console-bound replacement keys. Keep the helper login and restored-machine login distinct.                                                                    |

Fresh target IDs, IPs, attachments and boot IDs come from the new request's
provider and console observations. Historical `operator/` scripts and completed
request JSON are forensic evidence, not inputs for another target. No step
requires a transcript, a file on a deleted clone, or an archive from production.

## Common preflight and boundaries

1. Read `AGENTS.md`, the owner-controlled `PROJECT-VISION.md` and
   `DEVELOPMENT-BUDGET.md`. Reconcile the controller journal, current resources
   and active OCI/SSH writers. Use one live infrastructure writer and the
   existing `.private/backup-controller.lock`. Do not wrap an entry point that
   takes that lock in a second acquisition of the same lock.
2. Verify the actual account tier, active trial coverage and expiry, current
   official limits, remaining credit and delayed-usage reserve. Record exact
   before/peak/after totals for compute, disks, backup members, IPs and complete
   tenancy Object Storage. Bound the attempt's cost and lifetime, including
   helpers and networks. Standing authority covers only its stated scope.
3. Preserve the production instance, services, reserved IP, DNS and all backup
   objects. Record production boot and required-service invocation IDs before,
   during and after a drill. Provision only isolated task-owned targets.
   Recovery does not reserve provider capacity.
4. Record intended timer state. Leave production timers unchanged. Shared-lock
   waiting is normal; never stop another writer to bypass it. After cleanup,
   compare timer state and correct only changes made by this task.
5. Use owner-only JSON files (`umask 077`; mode `0600`) under `.private`. `scp`
   can produce a less restrictive mode: check and correct the receipt's mode
   before submission. Preserve failed attempts and durable intents.

## Oracle online-group restore

The group runner creates two copied volumes, prepares them on an isolated
helper, and boots the isolated clone. It stops at `CREATED`; that is not boot
acceptance. Supply the following existing typed inputs for the **new** attempt:

| File under a new `.private` attempt directory | Schema and binding                                                                                                                                                                                                                                            |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `plan.json`                                   | `GroupRestorePlan` in `scripts/oci-group-restore-drill.ts`: exact source/group/member IDs, production exclusions, new isolated network, controller IPv4, UTC suffix, duration and spending cap.                                                               |
| `approval.json`                               | `GroupRestoreApproval` in the same module: `groupRestorePlanDigest(plan)`, exact operation, current account/trial observations and cost/lifetime coverage under standing authority. Refresh observations without rewriting the durable lifetime.              |
| `evidence.json`                               | `GroupRestoreEvidence`: provider group, boot-member and root-member objects. Both members must belong to this group and match the source and sizes.                                                                                                           |
| `runner.json`                                 | Existing `ociCliPath`, `ociProfile`, `region`; use the installed CLI, not an assumed PATH in a fresh shell.                                                                                                                                                   |
| `preparation.json`                            | `GroupRestorePreparationConfig` in `scripts/oci-group-restore-preparation.ts`: exact helper/image, pinned helper SSH, retained copied filesystem identities/hashes, plan digest and `await drillGuestFilesDigest(await groupRestorePreparationBundle(plan))`. |

Reconcile or create the helper and isolated networks under the same bounded
authority before filling those IDs. Track their cleanup separately: the group
runner owns the clone and two copies, not all supporting infrastructure. For
DHCP reads the existing OCI syntax is `network dhcp-options get --dhcp-id`. Do
not use `--dhcp-options-id`.

From the matching controller source root, substitute the reviewed private paths
in the existing interface (the example directory is not an existing request):

```sh
deno task group-restore --action create \
  --state-dir .private/restore-attempt \
  --plan .private/restore-attempt/plan.json \
  --approval .private/restore-attempt/approval.json \
  --evidence .private/restore-attempt/evidence.json \
  --runner .private/restore-attempt/runner.json \
  --preparation .private/restore-attempt/preparation.json
```

Before first boot the adapter verifies attachments and copied filesystem
identities, installs isolation, masks duplicate jobs, and detaches the copies.
Do not bypass this gate or attach a production disk. On a failed or uncertain
operation, reconcile the recorded exact intent; do not clear state and retry
creation. An expired incomplete attempt is cleanup work, not a reusable plan.

For clone acceptance, use the restored account's existing login identity
(`codex` for the accepted Arch layout). The helper's temporary key is not
automatically authorized by the restored account. Verify the host key from
retained trust or the console, retain a dedicated known-hosts file, and use
`BatchMode=yes`, `StrictHostKeyChecking=yes` and bounded connection timeouts. Do
not disable host verification to resolve a login failure.

Perform and retain all eleven `GroupRestoreAcceptanceChecks` from
`scripts/oci-group-restore-executor.ts`:

| Check                                                 | Required observation                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `productionOnline`                                    | Unchanged production boot, root UUID and required-service invocation IDs through the attempt.                                                                                                                                                                                                                                 |
| `targetBooted`, `ssh`                                 | Real Arch aarch64 boot ID and working pinned non-root SSH to the exact clone.                                                                                                                                                                                                                                                 |
| `mounts`                                              | `findmnt` proves root UUID/ext4 and `/efi` vfat; `lsblk` proves exact attachments, sizes, UUIDs and root start sector. Use the captured fstab: this Arch image mounts EFI at `/efi`, not `/boot/efi`.                                                                                                                         |
| `bootParity`                                          | In a private mount namespace, mount staging read-only by UUID; compare `/boot/Image` with `arch-vmlinuz` and `/boot/initramfs-linux.img` with `arch-initrd.img`. Compare all three retained hashes, root UUID in GRUB, fallback entry and fallback files. Unmount afterward. This does not prove a separate fallback-OS boot. |
| `representativeData`                                  | Compare the retained representative repository/file hashes and required Codex configuration against the selected capture's expectations. Do not fetch missing expectations from production.                                                                                                                                   |
| `applications`                                        | Start only the isolated clone's required Docker/Guacamole, Caddy and VNC services after isolation is proved. Verify running containers, Guacamole application markup, Caddy response and loopback VNC listener.                                                                                                               |
| `desktop`                                             | Check the actual Xfce desktop and retain an image bound to the clone boot ID. A process list or application receipt alone is insufficient.                                                                                                                                                                                    |
| `isolation`, `metadataBlocked`, `duplicateJobsMasked` | Compare the prepared marker and file hashes with the exact plan bundle; verify copied masks, default target, firewall rules, firewall activation before network/SSH, and failed metadata HTTP access.                                                                                                                         |

Only after these observations pass, create `acceptance.json` using
`GroupRestoreAcceptanceReceipt`: exact plan digest/suffix, observed timestamp,
eleven true checks and observed UUID/start-sector/hash values. Validate it with
`validateGroupRestoreAcceptance`. Submit the same command with `--action accept`
and `--acceptance .private/restore-attempt/acceptance.json`; retain the result.

Quiesce and cleanly stop only the accepted clone with approved `SOFTSTOP`, then
use `--action cleanup` with the same inputs and acceptance receipt. Separately
remove the exact helper, its disk and temporary network/console resources.
Verify their absence and the original production/backup footprint. If cleanup
already succeeded but the final audit failed, run only the read-only audit;
never replay deletion to obtain a successful combined log. The existing
`backupControllerEvidence.verify` requires `docs.oracle.com` network permission;
retain it when using a private finalizer, as in `deno task backup:replace`.

Retain `{ "plan": <accepted plan>, "acceptance": <accepted receipt> }` in
`.private/reports/online-oracle-boot.json`, mode `0600`. The watchdog validates
the receipt against the plan digest and reports its exact group and members.
`currentCaptureProved` is true only if the controller's current group matches; a
later group retains its own unproved status. Keep the original detailed runtime,
visual, continuity and cleanup receipts beside this summary.

## Independent Backblaze replacement

Use `deno task backup:replace` from the matching Pi controller root. Its
existing read scope includes source, `.private` and `config`; a `.private`-only
scope cannot build the target source bundle. The entry point is
`scripts/pi-recovery-session.ts`, not the historical `oci-restore.ts` or the
interrupted-backup diagnostic `backup-recovery.ts`.

1. Populate `.private/pi-machine-recovery.json` as `ReplacementConfig` in
   `scripts/pi-machine-recovery.ts`: a new request UUID, selected generation,
   exact tenancy/region/domain, task-owned isolated subnet and unassigned
   reserved IP, current supported loader image, and request-bound `cloudInit`
   from `buildRescueCloudInit({requestId, sshPublicKey})` in
   `scripts/pi-recovery-bootstrap.ts`, using the existing Pi public key. Retain
   current trial cap/expiry and exact `replacementPlanDigest` approval. Use
   `action: "plan"` to inspect before binding `action: "provision"`.
2. Run the entry point. Read `.private/reports/pi-recovery-session.json` and
   `.private/pi-recovery-session.json`. Bind each emitted plan to the matching
   existing `sessionApprovals` field: `consoleConnection`, `loaderConsole`,
   `rescueReboot`, then `ramConsole`. Use the existing RSA console public key
   when required. Preserve every plan digest and console attempt; never replace
   a request merely because a bounded observation timed out.
3. Require `RAM_RESCUE_ACCEPTED` with a new RAM boot ID, retained loader
   identity and matching rescue manifest. Bootstrap uses pinned HTTPS artifacts
   and request-consistent tooling. Never patch a running rescue bundle with
   files from a different revision or reuse the deleted drill's loader identity.
4. At `RESTORE_CONFIGURATION_REQUIRED`, create the existing
   `.private/backblaze-machine-restore.json` as `RecoveryTargetControlInput`
   from `scripts/pi-recovery-restore.ts`. `catalog` is the complete validated
   entry for the selected generation; `requestId`, `loaderBootId` and
   `rescueManifestSha256` come from this session. `target` is
   `MachineRestoreTarget` in `scripts/backblaze-machine-restore.ts`: exact
   instance ID, `aarch64`, both stable by-id paths, hardware serials and byte
   sizes from `loaderIdentity.boot/root`, `/run/uos-recovery` work directory,
   and matching target-only approval. `publicHome` is `/run/uos-recovery/gnupg`.
   Do not build this file before a new target exists.
5. Resume the same entry point. It binds the loader disks to the accepted RAM
   boot and current provider attachments, derives copied-root isolation from the
   actual controller SSH peer, and builds the source bundle from the deployed
   revision. Bind the emitted `restoreInstallation`, `diskPreparation` and
   `isolation` approvals to their exact plans. The reported schema/types are in
   `pi-recovery-session.ts`, `pi-recovery-disk-preparation.ts` and
   `pi-recovery-isolation-executor.ts`. Do not guess approval digests.
6. Archive extraction runs directly B2-to-target, using exact indexed versions,
   verified decryption streams and Pi key-agent access. Six filesystems, layout,
   numeric metadata and swap are reconstructed. `FILESYSTEMS_REBUILT` is not
   boot proof. For a preparation/extraction uncertainty, reconcile the existing
   journal and target state before another write; never rerun formatting
   blindly.
7. Require copied-root isolation before approving `restoredBoot`. Bind
   `restoredConsole` to this new boot and resume acceptance. Current tooling
   recognizes Arch Linux ARM (`ID=archarm`), creates restricted symlinks through
   its scoped command path, compares SSH key material without comments, and
   recreates excluded runtime directories and compatible XFS features. These
   corrections are already in the retained source; do not add manual repairs
   unless the new run demonstrates a failure.
8. Require `RESTORED_APPLICATIONS_ACCEPTED`, then inspect mounts, captured boot
   hashes/staging parity, representative preserved data, isolation and actual
   desktop for the same boot. Test X11 authentication first. Repair a
   hostname-bound cookie only if that check fails; record and verify any repair.
   An Xvnc/application receipt does not establish visual desktop acceptance.
9. Clean up only the exact request-owned clone, both disks, console resources,
   IP and network. Reconcile any pending create/delete before retrying. Verify
   production continuity, unchanged backup IDs, normal resource totals and timer
   state. Preserve the complete request's receipts and source revision.

## Evidence limits

September 10 Oracle proof covers `arch-online-golden-20260908T061252Z`, plan
digest `fd665dbb9edc6ceff76313165c62d51b1763c50585225594f66a41ea1b3e350b`, with
runtime, visual acceptance and completed cleanup. September 8 Backblaze visual
proof and September 9 application proof cover generation
`generation-a0f12b6f-6c4b-436a-b547-58090e39ae71`, index digest
`617de2f54e795c52958f0579d93695d10dac9a0697b5d0d54c2abf8a7649c72a`, but are
different boots. September 9 used runtime `6993583`, not its successor kit.

Repeat a bounded affected path only when a material change lacks valid proof. Do
not create a target solely to recheck documentation, receipt transfer mode,
status projection or an already-tested permission correction. The September 11
clean run applies only to its recorded revision and generation. The fourth
naturally accumulated weekly point, continued unattended cycles, guest
memory/network telemetry and post-trial zero-bill observations remain separate
requirements. Do not poll for calendar events to close this procedure.
