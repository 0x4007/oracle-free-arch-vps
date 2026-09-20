# VPS repair handoff — arch root filesystem boot loop

Prepared 2026-09-20 07:35 UTC by the Prospector `prospector.sh` origin task.
Status: host degraded, production offline. No repair has been attempted.

Written for another agent to execute. Read
[`RECOVERY-PROCEDURE.md`](RECOVERY-PROCEDURE.md) and
[`AGENTS.md`](AGENTS.md) before acting; this file is a situation report plus a
short decision list, not a replacement for them.

## 1. Symptom

`arch` (OCI instance, region `us-ashburn-1`, AD-1) is in a storage-induced boot
loop. The control plane reports `RUNNING`; the guest never finishes booting.

Observed from the Mac, all with fresh commands between 06:49 and 07:35 UTC:

- `ssh codex@vps.pavlovcik.com` — TCP connects, then `Connection timed out
  during banner exchange` (reproduces from the Mac directly and through
  `pi@ssh.pi.pavlovcik.com:2222`).
- Public: `app.prospector.sh`, `auth.prospector.sh`,
  `ubiquity-prospector.ubq.fi`, `ai.ubq.fi` — connection timeouts. Ports 22 and
  443 are intermittently open at TCP level, then closed.
- `ai.ubq.fi` returned Cloudflare `522` (origin unreachable) when it still
  answered at all.

Guest console (OCI `console-history` captures, read-only) shows the machine
cycling:

- `EXT4-fs error (device sdb2) in ext4_reserve_inode_write:6436: IO failure`
  and `ext4_dirty_inode:6641: IO failure` from `systemd-journal`
- `EXT4-fs (sdb2): Detected aborted journal`
- `EXT4-fs warning (device sdb2): ext_end_bio:368: I/O error 5 writing to inode …`
  with matching `Buffer I/O error on device sdb2`
- `Failed to start File System Check …` and an emergency shell
- `FAILED … Verify /srv/data persisted before dependent services start`
- `Reached target System Shutdown` / `System Power Off`

First `EXT4-fs error` appeared at kernel timestamp `128562` s, i.e. about 35.7
hours of uptime, so this is not a power-loss artifact at boot: the running root
filesystem failed under I/O load and its journal aborted.

`sdb2` is the root filesystem (kernel command line
`root=UUID=e61e7a3e-996d-418a-831b-09f09e827e0a`). A probe capture later showed
`sshd` and Docker starting in one cycle, so the host is not dead — it is
looping between partial boots and shutdowns.

Evidence captured on the Mac at `~/.local/state/vps-outage-20260920/`
(`vps-console.txt`, `-2`, `-3`, `SUMMARY.txt`); a fourth capture is
`/tmp/vps-handoff.txt` (host `/tmp`, may not persist).

## 2. Facts the next agent needs

Identity (verified via OCI CLI this session):

| Item | Value |
| --- | --- |
| Instance | `ocid1.instance.oc1.iad.anuwcljruba2nfqc54vhx5p4jyxexslgudxljabfjxpbbyoh35b5tpyzsnka` |
| Name / shape | `arch` / `VM.Standard.A1.Flex` |
| Compartment / tenancy | tenancy root `ocid1.tenancy.oc1..aaaaaaaa5jqdkkm4uqmoo64st3ouf6ileqnoacn24oqoy2khj3jfnj6z2mxq` |
| Availability / fault domain | `wktP:US-ASHBURN-AD-1` / `FAULT-DOMAIN-1` |
| Created | 2026-09-03T01:09:33Z |
| Public IP | `129.158.58.222` (reserved; VNIC `10.0.1.41`, state AVAILABLE) |
| Boot volume | `arch-vps2 (Boot Volume)`, 50 GB, `ocid1.bootvolume.oc1.iad.abuwcljriulm67vkrvnagf5wwx737jd7i3kvx6tiexhbfi6aayi5uxsx5lzq` |
| Data volume | `arch-disk`, 150 GB, vpus 10, `ocid1.volume.oc1.iad.abuwcljrxy5pidtobzjmrmen3k4upe4rirap267jqczz7een5khy6s2bgflq` |
| Volume group | `arch-online-recovery-unit`, `ocid1.volumegroup.oc1.iad.abuwcljrfcwtgbhixhwr6m3qzxwg5n33bcw62gc7ao6ldydaswupiw2qee3q` |

Recovery points (both members of one online group capture, created while the
instance was `RUNNING`):

| Object | Created | State | ID |
| --- | --- | --- | --- |
| Group backup `arch-online-golden-20260920T040549Z` | 2026-09-20T04:24:47Z | `AVAILABLE` | `ocid1.volumegroupbackup.oc1.iad.abuwcljrnd6ynlb6dmvv2ogocojcnomix7ndlkmq7xyskjfg4xjupcxa4yzq` |
| Boot member `arch-vps2 (Boot Volume)_backup_20260920_042431` | 2026-09-20T04:24:47Z | `AVAILABLE` | `ocid1.bootvolume.oc1.iad.…` (enumerate from the group backup) |
| Data member `arch-disk_backup_20260920_042431` | 2026-09-20T04:24:47Z | `AVAILABLE` | `ocid1.volumebackup.oc1.iad.abuwcljr742hwqaovwhcz2shqc4yt4kn566lzd6inxuseuuzf2f7i6vfd3fa` |

The 2026-09-13 pair is `TERMINATED` and is not a recovery point. The older
`capture-pre-fsck-damaged-root-20260907` backup is `AVAILABLE` but predates the
current production and is forensic only.

Two consequences worth weighing:

1. **This is a repeat failure.** A 150 GB backup literally named
   `capture-pre-fsck-damaged-root-20260907` shows the same class of root-fsck
   damage happened on this host before. Repairing in place without addressing
   why it recurs would likely just restart the clock.
2. **The 04:24 backup is from ~2.5 h before the failure**, and the failure
   started ~35.7 h into a run that began before it. Any restore therefore loses
   whatever the guest wrote after 04:24, including the `prospector.sh` work
   described in §4.

## 3. Repair options

Three viable paths, cheapest first. Choose deliberately; they differ in data
loss and in whether they fix the underlying fragility.

**A. Targeted repair in place (lowest cost, uncertain).** Attach the boot volume
to a temporary helper instance and run `fsck.ext4 -f` on the root partition
from outside a booted guest, then reattach. Recovers the machine without losing
anything written before the crash. Does not address why it recurs, and may not
succeed if the damage is on the backing storage rather than the filesystem
metadata.

**B. Restore the 04:24 recovery pair.** This is the path the repository's
tooling is built for; see `04-BACKUP-RECOVERY.md`,
`RECOVERY-PROCEDURE.md` and `07-OPERATIONS-AND-DRILLS.md`. Tools:
`deno task group-restore` (`scripts/oci-group-restore-run.ts`, `create` /
`accept` / `cleanup` actions), or `scripts/oci-restore.ts` for the
boot-target path. Both require exact private inputs under `.private/` with a
matching approval; do not invent or reuse an expired approval, and do not
extend a recorded lifetime. Loses writes after 04:24. The current
`arch-online-recovery-unit` and its capture are the pair the tooling expects —
`RECOVERY-PROCEDURE.md` states the group's restore/boot status is
`METADATA_PROVED` until a live drill proves otherwise.

**C. Rebuild from the documented unattended path** (`UNATTENDED-RECOVERY.md`,
`deno task backup:replace`, Pi-side controller). Highest effort; useful only if
the OCI pair proves unusable or if the boot volume's fragility should be
addressed by rebuilding onto fresh storage.

Whichever path is taken, decide explicitly whether the **boot volume** is
replaced rather than repaired, given §2.1.

## 4. What is lost, and what is not

Not on the host:

- The `prospector.sh` code work from 2026-09-20 is committed and pushed:
  `0x4007/deno-universal-auth` `codex/2026-09-20-vps-https-origin-g5354920979`
  (`2d37996`) and `ubiquity/prospector`
  `codex/prospector-sh-domain-config-2026-09-20-7d1d69dd4d` (`5735eea`).
- Its deployment plan and the exact proven environment values are in
  `/Users/nv/repos/ubiquity/prospector-capture-monorepo/handoffs/prospector-sh-domain-config-2026-09-20.md`.
- The Prospector `ubq.fi` site, `app.prospector.sh` and `auth.prospector.sh`
  Caddy/DNS configuration is documented in
  `handoffs/prospector-sh-vps-temporary-hosting-2026-09-20.md` in the same
  repository, with rollback steps.

Only on the host, and therefore at risk:

- `/var/lib/ubiquity-prospector/` — KV store `kv.sqlite3` and the capture
  downloads store (`downloads/capture/`, including `latest.json` and the
  published ZIPs).
- `/etc/ubiquity-prospector/runtime.env` — live credentials (`DATABASE_URL`,
  Stripe live key, FCM service account, `UOS_AI_TOKEN`, `CEREBRAS_API_KEY`).
- `/etc/caddy/` — the Caddyfile, `ai-ubq-fi/`, `ubiquity-prospector/`
  (`active-route.caddy`, `application.caddy`, `maintenance.caddy`),
  `prospector-sh/Caddyfile`, and `Caddyfile.before-prospector-sh-20260920`.
- The systemd units: `ubiquity-prospector.service`,
  `ai-ubq-fi.service`, and the user units `ubiquity-passport.service`,
  `vps-update.{service,timer}`.
- `/home/codex/repos/ubiquity/prospector-capture-monorepo` and
  `/home/codex/repos/0x4007/deno-universal-auth` checkouts (both pushed, so
  recoverable from origin, but any uncommitted host-local work on them is at
  risk), plus `/home/codex/.local/state/prospector-vps-checkout-backup-20260920/`
  which holds the rollback copies and the `prospector.sh` notes.
- `/srv/ubiquity-prospector/releases/` (staged releases).

Assume §4's second list is only as current as 2026-09-20T04:24Z if path B is
chosen.

## 5. Environment notes for the next agent

- **OCI CLI is not installed on the Mac.** This session installed one into a
  throwaway venv at `/tmp/oci-cli-check2/venv/bin/oci` (put it on `PATH` with
  `export PATH=/tmp/oci-cli-check2/venv/bin:$PATH SUPPRESS_LABEL_WARNING=True`).
  It reads `~/.oci/config` with `oci_api_key.pem` and authenticates against the
  tenancy above; `oci compute instance list --compartment-id "$TENANCY"` works.
  `/tmp` may be cleared, so reinstall if absent
  (`python3 -m venv v && v/bin/pip install oci-cli`).
- **Finding the root compartment:** the repo's earlier configs contain a
  truncated compartment id; use the tenancy id above for top-level lists.
- **Read-only diagnosis that works even while the guest is down:**
  `oci compute console-history capture --instance-id <id> --display-name <n>`,
  then poll `console-history get --instance-console-history-id <id>` for
  `lifecycle-state == SUCCEEDED`, then
  `console-history get-content --instance-console-history-id <id> --length N --file <path>`.
  Captures persist; they are the authoritative view of a wedged guest.
- **Do not** stop/start or reset the instance to "try it again". The guest is
  already looping, and a reset does not repair a damaged root filesystem; it
  only obscures the evidence. Capture the console first.
- Keep one live infrastructure writer. `.private/backup-controller.lock` guards
  the controller; do not wrap a lock-taking entry point in a second acquisition.

## 6. Suggested immediate sequence

1. Read `AGENTS.md`, `RECOVERY-PROCEDURE.md`, `04-BACKUP-RECOVERY.md` and
   `PROJECT-VISION.md`.
2. Reconcile current resources and any active writers; confirm the instance is
   still `RUNNING` and the 04:24 group capture is still `AVAILABLE`.
3. Capture fresh console history and preserve it with the existing evidence in
   `~/.local/state/vps-outage-20260920/`.
4. Decide A, B or C, including whether the boot volume is repaired or replaced,
   and obtain the exact approval the chosen path requires.
5. Execute, then verify the restored guest on its own terms (boot completion,
   sshd, then the service checks in `05-ACCEPTANCE.md`) before claiming
   recovery.
