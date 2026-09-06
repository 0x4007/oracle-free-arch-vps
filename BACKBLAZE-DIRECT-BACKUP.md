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

## Recovery evidence

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

## Automation status

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

The controller schedules Sundays at 00:05 America/New_York, with a six-hour
catch-up window. A shared lock serializes it with the Oracle backup cycle. It
accepts a generation only after complete archive verification and terminal
source-process evidence. Retention keeps the newest four accepted generations
and removes older exact object versions only after recording and rechecking a
deletion plan. Interrupted deletions resume from a fresh inventory. The watchdog
records separate Oracle and Backblaze assessments and sends one combined status
transition through the existing Mac alert queue.

The installed controller completed the second generation at 04:53 UTC, with two
accepted points in its catalog. Its temporary capture, reconstructed, and
decrypted archive directories were removed. The first run required preserving
three result records outside the scratch directory; the deployed cleanup
correction now accepts those exact producer filenames, and real Linux fixtures
verify cleanup and foreign-file preservation.

The weekly timer is enabled and active. Its next trigger is Sunday, September
13, 2026 at 00:05 New York time. Four retained points accumulate through
successful runs; two accepted points currently exist. The Pi image mirror is
absent, with 3.19 GiB reclaimed.

The Oracle controller now uses online group capture. Its real scheduler
acceptance completed on September 6 without source interruption. Existing
backups remain preserved; Oracle clone boot acceptance and the retention
decision are still separate gates. See `ONLINE-BACKUP-CONTRACT.md`.

The final release passed 379 repository tests, including 71 controller tests,
plus type, format, and lint checks. Its watchdog reports the accepted Backblaze
point as current even when the original request preceded the Sunday boundary.
The successful current-status notification reached the Mac with no pending
alerts.
