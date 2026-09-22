# Verified end-to-end backup — 2026-09-22

Owner request: finish the resource-remediation acceptance through one real online Backblaze generation and record the truthful terminal outcome (continuation of Codex rollout `01a0bd67-63e7-7992-9d31-16a4d875da24`).

## Result

**One online generation ran end to end and was accepted while the VPS stayed up.** Capture, upload, reconstruction, verification, and controller acceptance completed inside the original six-hour gate; normal retention then left four accepted generations in the catalog. This takeover invoked no stop, reboot, or freeze of the instance or any service: the host boot identity stayed unchanged, and the named services that were checked remained active with no failed units in the observed checks.

| Evidence | Value |
| --- | --- |
| Generation / job | `generation-c9511fa9-98c0-4d67-af0a-a0f912ddc726` / `job-c9511fa9-98c0-4d67-af0a-a0f912ddc726` |
| Payload | 10,355,748,786 B ciphertext, 7 archives, 160 chunks, all uploaded and read back |
| Roles | `root`, `efi`, `staging-boot`, `staging-efi`, `oracle-root`, `oracle-oled`, `recovery` |
| Requested / gate deadline | 2026-09-22T02:23:16.600Z / 2026-09-22T08:23:16.600Z (6 h `GATE_DEADLINE_MS`) |
| Worker terminal `PENDING_VERIFIER` | 2026-09-22T07:06:26.640Z |
| Verifier start / exit | 2026-09-22T07:07:20.158Z / 2026-09-22T08:14:11.145Z (`Result=success`, `ExecMainStatus=0`) |
| Verifier receipt | `receipt.json` SHA-256 `73c132b0f4ede167c3609df49be28077336aa16555695d1f260a0e3d107ae3eb`, `verifiedAtUtc` 08:14:11.112 |
| Pi accepted | 2026-09-22T08:14:33.123Z |
| Controller terminal | `COMPLETE` with cleanup done 08:17:03.500Z, gate absent, catalog 4 accepted generations |

The run finished 6 min 13.1 s before the original 08:23:16.600Z deadline.

## What the verification proved

- The verifier reconstructed every archive from Backblaze and proved ciphertext/decrypted-archive integrity, tar inventory, and four boot-file hashes: ciphertext hash, gpg decryption, `zstd -t` frame test, plaintext SHA-256, full tar inventory, and 4 boot samples (2 each for `root` and `staging-boot`).
- The receipt carries one global `decryptedRestoreProved` flag, true for this generation and covering all 7 archive roles together rather than as separate per-role flags; `machineBootRestoreProved` is false. No new boot drill was run, so no generation on this date is claimed boot-restored or application-accepted.
- Controller acceptance is bound to the same generation: `status.json` `ACCEPTED`/`finishedAtUtc` and `receiptSha256` match `receipt.json`, and the Pi catalog entry carries the new `acceptedAtUtc`.

## Resource controls and current-run distinctions

- The run executed from immutable release `c184dbecc915bbd254e0fd47a8007ae21cd098c0`; the source fixes below were not in this run.
- The only live change was a bounded runtime override applied 07:27:39Z to the already-running verifier unit: `IOReadBandwidthMax=/ 30M`. It used the same PID 2709431 and invocation `64eb5d09e04243fcb8fc486568021884` with no restart, and left write bandwidth, read/write IOPS, CPU weight/quota, memory max/swap, and the original `RuntimeMaxSec`/deadline unchanged.
- Reason: the verifier performs about 64.9 GB of full-file read-back passes against a 10.36 GB payload; the 10 MB/s read cap needed about 108 min and could not fit the gate.
- After capture completed, one observed interval had advancing heartbeats but no observed payload progress; the same worker resumed before deployment without repair or restart (upload journal start 05:22:55.649Z). The exact earlier error was not logged, so a stall, a deadlock, or retry backoff is not attributed, and the new source fixes are not claimed as its cause.

## Fixes deployed after acceptance

- Source fixes cover the upload-stall transport repair (120 s per-request deadline including the body, caller abort, sanitized phase-checkpoint retry logs) and the verifier read budget (`30M` for verifier units, `10M` for worker/capture and prune); 135 focused tests passed on integrated revision `54e33bd8883c7de2d7323405bddc7a68cf70c7ec`.
- Release `54e33bd8883c7de2d7323405bddc7a68cf70c7ec` was deployed at 08:20:19.471Z after `COMPLETE`: the VPS release has 53 files with manifest == local Git == deployed bytes (`sourceCheckPassed` true), the Pi's 4 source files were hash-verified and its controller pin updated to the new 3-key `54e33bd…` identity, and rollback copies of the previous pin and Pi scripts were kept. Production was not restarted; the previous `c184dbecc915bbd254e0fd47a8007ae21cd098c0` bundle remains preserved.
- Nothing in this generation ran the new release: the new verifier-read launch default and the request-timeout code were installed after `COMPLETE`. The `30M` verifier read limit was exercised live on this run through the 07:27:39Z runtime override, and the new release's default Backblaze transport was then exercised by the metadata-only probe below. No fresh full backup ran on `54e33bd8883c7de2d7323405bddc7a68cf70c7ec`.

## Post-deploy probe and host hygiene

- A metadata-only Backblaze probe through the new default production transport exited 0 (`authorize` 515 ms, `listVersions` 146 ms, 909 versions) and transferred no backup payload.
- Final hygiene at 08:24:35Z: host boot id `99b28f58-7143-4265-9371-dcc4c9018ae2` unchanged, `sshd`/`docker`/`networkd`/`resolved` active, no failed units, and no `tar`/`zstd` or probe units left running.

## Evidence references

- Terminal acceptance: `/tmp/oracle-takeover-20260922/terminal-acceptance-0814.txt` (receipt hash, receipt body, unit state) and the job's `status.json`/`result.json`/`receipt.json` under `/var/tmp/arch-vps-file-backup/jobs/job-c9511fa9-98c0-4d67-af0a-a0f912ddc726/`.
- Live verifier override: `/tmp/oracle-takeover-20260922/verifier-read-cap-0727.txt`.
- Deployment: `/tmp/oracle-takeover-20260922/postrun-deploy-run.log`; host hygiene: `/tmp/oracle-takeover-20260922/final-host-hygiene.txt`.
- Read-budget analysis and focused-test evidence: `/tmp/oracle-takeover-20260922/verifier-budget-report.md` and registered evidence reference `047ecd50480277305bd956560cc5c9c0484f10fec5edb8175151d66ba6c9b251` / `45a245f3-8faa-44ce-bb2c-7c2e485f30a1` (executed).
- Decisions taken under the owner-controlled [PROJECT-VISION.md](PROJECT-VISION.md) charter are recorded in [DECISIONS.md](DECISIONS.md).
