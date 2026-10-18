# Direct encrypted Backblaze backups

Backup payloads travel directly between the VPS and Backblaze. The Pi sends
control commands and keeps small job records. It does not mirror or stage
filesystem archives.

The backup covers six filesystem roles: Arch root, EFI, staging boot, staging
EFI, Oracle fallback root, and Oracle OLED. Each role is a GNU tar archive
compressed with zstd and encrypted to a public GPG recipient. A seventh
encrypted archive contains recovery metadata. The scoped Backblaze credential is
separate from the master credential. Private decryption keys stay off the VPS
and out of this repository.

This is a live file copy. It is not an atomic filesystem snapshot or proof of
database consistency. Package and boot-file checks detect relevant changes
during capture. Exclusions are in `config/restic-excludes.txt`; they apply
relative to each filesystem root.

## Streaming v2 contract, October 18, 2026

The `backup-v2` source contract retains the per-role `tar.zst.gpg` format and the separate encrypted recovery-metadata payload. It replaces size-proportional archive staging with `tar → zstd → GPG → two ciphertext slots → B2`. Each slot holds at most 64 MiB; when both are occupied, awaited backpressure stops upstream work. Neither capture nor independent verification may hide a complete compressed, ciphertext or plaintext archive in another workspace, cache or temporary path. This section describes the candidate contract and its required acceptance; it does not establish production deployment or a new accepted due-period point.

A slot is sealed and hashed, and a fresh physical PUT intent is durably recorded before each wire request. A successful upload response is only a candidate. The complete selected exact B2 version must pass length, SHA-1 and SHA-256 readback, and its selected reference must be durably journaled before reclaiming the slot. Ambiguous success retains its intent and sealed bytes for exact-version reconciliation. New physical PUT attempts have distinct recorded identities; they do not silently overwrite or forget an uncertain attempt. Payload upload, readback and later verification stay directly between VPS and B2. The Pi carries control records and task-owned GPG-agent operations, with private keys kept off the VPS and outside Git.

Independent verification starts from trusted cloud references and an off-VPS accepted-root digest, without source mounts or capture caches. It checks bounded exact-object slots before feeding the ordered ciphertext to a continuous GPG stream, drains GPG and zstd completely, verifies inventory and all four boot samples, and collects every final process/integrity status. A successful tar listing alone is insufficient. No complete plaintext archive is written. A dead producer starts a new active-role attempt after settlement; ciphertext from a new GPG process is never appended to an old partial stream. Only compatible cloud-sealed roles may be reused, retaining their original capture intervals.

The declared profile in [backup-v2-profile.ts](scripts/backup-v2-profile.ts) is a finite admission envelope, not a measured capacity guarantee:

| Dimension                                                                       | Declared bound                                                                |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Ciphertext payload slots                                                        | Two × 64 MiB, 128 MiB total                                                   |
| Active engine workspace, including metadata, temporary/cache files and overhead | 768 MiB                                                                       |
| Additional ordinary-user free space                                             | Remaining engine workspace plus one 512 MiB writer margin; 1.25 GiB initially |
| Journal / individual manifest                                                   | 64 MiB / 1 MiB                                                                |
| Logical source / capture ciphertext / physical PUT bytes                        | 1 TiB / 256 GiB / 512 GiB                                                     |
| Logical objects / physical PUT attempts / attempts per object                   | 5,000 / 16,384 / 16                                                           |
| Members / aggregate path bytes / inventory stream                               | 2,000,000 / 128 MiB / 512 MiB                                                 |

Admission counts already allocated active workspace once and observes ordinary-user available blocks (`statfs.bavail`), inodes and held-deleted files. Filesystem reserved blocks remain protected without adding the inherited 5.5 GiB floor again. Code-derived phase maxima are about 381 MiB during capture and 499 MiB during sealing; the 768 MiB ceiling includes further native temporary and filesystem allowance. The single 512 MiB writer margin provides more than fourteen seconds at the preserved backup write ceiling, covering monitor/observation/stop reaction rather than promising to bound unrelated writers. Exact active roots include the gate, job-local Deno cache, verifier public-key home, prune transaction and new protection graph; unrelated retained graphs are excluded. Deno uses the accounted job cache with V8 code caching disabled. Unknown capacity fails closed. These bounds need live bounded acceptance and a real complete cycle. The full profile also bounds hardlinks, directory listings, sparse extents, extended metadata, decoder memory and pruning candidates. Exceeding a bound fails closed without dropping source data. Fixed payload slots do not imply constant metadata, GNU tar RAM, runtime or cumulative disk I/O. This remains a weekly full-capture design, without incremental transfer or cross-generation deduplication; complete source reading, compression/encryption, upload/readback and independent cloud verification still consume work proportional to the selected data and metadata.

V2 requests have no inherited twelve-hour whole-job deadline. Source and bridge lifetime instead require finite managed leases bound to the exact gate, boot, invocation, PID/start and cgroup. Source code currently uses 300-second startup/useful-progress grace with short 30-second notification leases. Only verified work or a fixed, durable sealed-transfer/retry episode can extend custody; heartbeats and repeated failed bytes cannot reset the episode. Transport declares a 30-second connection bound, 120-second control-request bound, six-hour payload bound and 120-second curl low-speed window; that rate window is not an exact socket-idle timeout. Transfer episode bounds include associated control requests and settlement. The Pi's existing thirteen-hour service bound limits a controller attempt, while the independent source/bridge continuity must be proved for a healthy long v2 job. Legacy v1 requests retain their original deadline semantics.

Cancellation is separate from successful archive verification. An exact observed invocation and successful exact-unit stop must be followed by fresh process/start, cgroup, namespace, FD and source-lock evidence. Independently dead children can establish cancellation settlement even when the interrupted journal lacks EXIT records; no record, exit status, result or receipt is invented. Missing/malformed custody, a live escape, unresolved namespace, contradictory identity or uncertain closure remains `CANCELLATION_BLOCKED`, retaining ownership and preventing overlapping work or cleanup. Ambiguous upload/delete intents remain for later reconciliation. A missing unit alone proves nothing.

V1 indexes, readers, original requests, FAILED statuses, receipts and timestamps remain preserved behind strict version dispatch. Retention keeps at least four accepted points and protects every exact reference reachable from retained roots, reused roles, metadata, receipts and recovery tools, plus active and unresolved operations. A bounded dry-run plan and fresh protection/custody checks precede exact-version deletion. An old failed-attempt prefix can contain reused data and must never be swept wholesale. The B2 pruner does not own the Oracle recovery pair or unrelated Restic data.

The schedule contract remains Sunday 00:05 America/New_York with fifteen-minute/startup rechecks and one current due period. A completed capture in that period satisfies it; migration must not manufacture a second generation. Required acceptance includes retained-v1 streaming recovery, real failure/cancellation/fidelity and capacity fixtures, one genuine all-role due-period v2 capture with independent complete cloud verification, hash-matched Pi/VPS and recovery-tool releases, safe retention/cleanup, settled gates/units/locks/tunnels, current timers and unchanged production continuity. Pi keeper continuity across the source transfer/startup windows remains part of that acceptance. A later natural weekly cycle is separate repeatability evidence. New archive verification may establish `decryptedRestoreProved=true`; `machineBootRestoreProved` stays false without a separately approved boot drill. Historical boot proof below does not transfer to a new capture.

The owner-controlled charter and [ONLINE-BACKUP-CONTRACT.md](ONLINE-BACKUP-CONTRACT.md) still require routine production operation online: no instance stop, reboot or freeze, and no required-service interruption. Resource authority is unchanged. October 18 operator evidence establishes the shared one-CPU, 6 GiB, zero-swap and preserved-IO envelope; a post-exit leaf sample establishes neither the application nor an override of its requested running limit. Earlier retained-v1 live leaf/ancestor evidence remains separate. Source currently declares `CPUQuota=100%`, `CPUWeight=1`, `Nice=19`, no soft memory ceiling and no swap, with the approved per-direction disk/network ceilings. Its `MemoryMax=6G` declaration is 6,442,450,944 bytes, distinct from the October 2 owner record of 6,255,601,664 bytes. Installation acceptance must reconcile authority and actual unit/ancestor values; this document does not approve a limit increase or infer protection from a unit file alone.

## Historical recovery evidence

On 2026-09-06, two generations passed the following real checks:

- Direct upload and exact-version readback of seven encrypted archives per
  generation: 131 chunks / 8,419,278,642 bytes for the first, and 144 chunks /
  9,293,976,907 bytes for the second.
- Publication and decryption of the portable recovery index.
- Complete direct Backblaze-to-VPS ciphertext reconstruction, with every archive
  hash checked.
- Complete GPG decryption, zstd integrity checks, and six full tar listings.
- Restoration of four fixed boot files with SHA-256 comparisons against captured
  metadata and root/staging parity.

The temporary GPG-agent connection closed after verification. The VPS custom
socket was removed, and its public-only key home contained no private keys.
During capture verification, archive data stayed between the VPS and Backblaze.
A separately approved independent drill later downloaded the first generation
to the Mac, rebuilt two empty disks, and booted the retained EFI/staging chain
into Arch at 17:15:23 UTC. SSH, mounts, boot parity, preserved Codex data,
containers, Guacamole and a visually inspected Xfce desktop passed. Network
isolation blocked Internet and cloud metadata access. Temporary drill disks and
payloads were removed; reports and tested tooling remain in the recovery kit.
See `ONLINE-BACKUP-CONTRACT.md` for corrections and exact evidence boundaries.

The measured namespace contains 277 exact versions and 17,713,370,053 bytes
across two generations, including both encrypted indexes. At $6.95 per decimal
TB-month, that is about $0.1231/month. Four generations at the latest size would
cost about $0.2584/month, before the account-wide free allowance or future
version overhead. This design does not deduplicate across generations.

## Recovery kit

The owner-only Mac recovery kit contains the private-key export, public
recipient, scoped recovery configuration, exclusions, portable index, metadata,
exact-version records, verification receipt, and reviewed recovery libraries
with file hashes. Keep an independent secure copy of this kit. Never copy its
private key or credential into Git or onto the source VPS.

To recover, use an approved Linux target with enough storage, GNU tar with
ACL/xattr/sparse support, zstd, GnuPG, and Backblaze access. Validate the key
fingerprint and index. Download only the selected exact chunk versions, verify
chunk and archive hashes, decrypt with integrity checks, then inspect complete
archive contents before restoring into an empty target. Preserve numeric
ownership, ACLs, all xattrs and sparse files.

Disk, partition, LVM, filesystem, EFI and boot reconstruction require the
encrypted recovery metadata and a separately approved target. Resolve devices by
stable identity. Treat the staging boot and Arch root as one recovery unit.
Recreate excluded swap from metadata, then perform a real boot and service check
before claiming machine restoration.

## Historical automation notes

The following notes preserve earlier rollout observations, including explicitly dated September 2026 counts and timer checks. They are historical context, not a current inventory, current timer readback or a v2 deployment claim. Later dated decisions and the streaming-v2 contract above define the candidate behavior and its acceptance requirements.

The source worker, recovery module, decrypted verifier, shared controller gate,
and Pi controller are integrated. The Pi has a separate verification keyring
with the verified recovery-key fingerprint. Its dedicated SSH key permits the
GPG Unix-socket forward, retains its other restrictions, and limits TCP
forwarding to an unused loopback port. A real Pi-to-VPS socket tunnel passed,
and an ordinary TCP remote-forward request was rejected. A real backup-status
notification reached the Mac through the existing durable alert queue, with no
pending alerts.

Verification checks real filesystem availability before reconstruction and again
before decryption, with a 5 GiB reserve and 512 MiB margin. Its request deadline
bounds polling; temporary retention inventory failures preserve progress for
retry.

The controller schedules Sundays at 00:05 America/New_York. Each period's
catch-up window runs from its Sunday 00:05 to the next Sunday 00:05, so a
delayed or missed trigger coalesces into one fresh request for the latest
Sunday period instead of being lost; a per-job request keeps its immutable
twelve-hour source deadline from the request instant. A shared lock serializes
it with the Oracle backup cycle. It accepts a generation only after complete
archive verification and terminal source-process evidence. Retention keeps
the newest four accepted generations and removes older exact object versions
only after recording and rechecking a deletion plan. Interrupted deletions
resume from a fresh inventory. The watchdog records separate Oracle and
Backblaze assessments and sends one combined status transition through the
existing Mac alert queue.

The installed controller completed the second generation at 04:53 UTC, with two
accepted points in its catalog. Its temporary capture, reconstructed, and
decrypted archive directories were removed. The first run required preserving
three result records outside the scratch directory; the deployed cleanup
correction now accepts those exact producer filenames, and real Linux fixtures
verify cleanup and foreign-file preservation.

The weekly timer is enabled and active, verified September 7, 2026 at 18:12
UTC; its next preferred trigger is Sunday, September 13, 2026 at 00:05 New
York time, and no 15-minute Backblaze timer was deployed yet. The source
configuration adds 15-minute checks on boot/startup and while the unit is
inactive and a seven-hour service timeout to cover worker/verifier polling,
intended to retry an unattended miss or a previously blocked next-period
launch without waiting a full week; activation of these settings remains
pending. Four retained points accumulate through successful runs; two
accepted points currently exist. The Pi image mirror is absent, with 3.19 GiB
reclaimed.

The Oracle controller now uses online group capture. Its real scheduler
acceptance completed on September 6 without source interruption. Existing
backups were preserved through initial acceptance. The user subsequently approved
retiring the old Oracle pair and deferring the separate Oracle boot test for this
development delivery. Retirement leaves two free slots for the next weekly
capture. See `ONLINE-BACKUP-CONTRACT.md`.

The final release passed 379 repository tests, including 71 controller tests,
plus type, format, and lint checks. Its watchdog reports the accepted Backblaze
point as current even when the original request preceded the Sunday boundary.
The successful current-status notification reached the Mac with no pending
alerts.
