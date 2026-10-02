# Implementation decisions

Recorded 2026-09-22 for the online Backblaze backup path in this repository. These are implementation decisions made under the owner-controlled [PROJECT-VISION.md](PROJECT-VISION.md) charter. They do not amend, replace, or claim the authority of that charter, which wins on any conflict, and they stay inside the resource-budget and request-transport scope described here.

## Per-phase resource limits

Backup transient units carry these systemd limits per phase: capture/worker read 10 MB/s, verifier read 30 MB/s, write 10 MB/s for both, read/write IOPS 500/200, `CPUWeight=1`, `CPUQuota=100%`, `Nice=19`, `MemoryMax=1 GiB`, `MemorySwapMax=0`, and no `MemoryHigh` (the soft cap was removed in `429b29d` after it throttled a real working set of about 1,078 MB into a stall).

Why the verifier read differs: this 10.36 GB generation (10,355,748,786 B ciphertext) incurs about 64.9 GB of full-file verifier read passes for ciphertext hash, decryption, `zstd -t`, plaintext hash, inventory, and 4 full boot samples. At the shared 10 MB/s read cap, verification alone needs about 108 min and does not fit the 6 h gate; 30 MB/s read with the unchanged 10 MB/s write cap gives about 47.5 min and puts a normal whole cycle at about 300 min (capture 114 + planning/upload ~121 + reconstruct 17 + verify ~47.5), about 60 min inside the deadline. That is headroom for a normal cycle, not a guarantee for every retry or a larger payload.

Observed 2026-09-22: the accepted generation's verifier ran about 67 min (07:07:20.158Z to 08:14:11.145Z), including reconstruction and the initial period under the 10 MB/s read cap before the live verifier-only 30 MB/s runtime override at 07:27:39Z. The 30 MB/s verifier read is now the source default selected from the validated unit kind; worker/capture and prune units keep 10 MB/s.

## Request transport and retry behavior

Each Backblaze request now has a 120 s timeout that applies to the fetch and the response-body read together and is combined with any caller abort signal, so either the timeout or a caller cancellation aborts the request; retry paths log sanitized phase checkpoints that give the allowed operation, error category, and timing instead of raw request detail. The existing bounded retry policy is retained unchanged: 3 attempts with 30 min spacing inside the request's `GATE_DEADLINE_MS`, which the timeout does not extend.

No new environment variable, CLI flag, or configuration surface was introduced for either decision; the limits come from existing unit properties and the timeout is internal to the storage client.

Related receipt: [BACKUP-VERIFIED-2026-09-22.md](BACKUP-VERIFIED-2026-09-22.md).

## 2026-10-02 update: 12 h future request budget and 20% shared CPU quota

Observed reason: the 2026-10-02 catch-up attempt's capture ran 15:44:36Z to 20:39:40Z (4 h 55 min) and included the external 2 MB/s disk caps until they were removed at 19:31:49Z, so it is not a clean 10 MB/s baseline; upload planning continued until 21:07:23Z. During sampled transfer the cadence was about 67 s per 64 MiB PUT plus full readback, which forecasts about 3.6 h of transfer for the 12.91 GB payload; no source CPU or disk bottleneck was continuously evident in those samples, and the disk override is not claimed to be the cause of the observed cloud transfer rate. The six-hour budget recorded above is an implementation choice, not a `PROJECT-VISION.md` requirement, and it left no bounded headroom once that transfer forecast was combined with capture and verification. This update does not pre-judge the still-live attempt; its outcome is whatever its terminal status proves.

Future requests therefore use `GATE_DEADLINE_MS` derived from `GATE_DEADLINE_HOURS = 12`; the validators and their messages derive from that value, while the coupled Pi unit `config/backblaze-file-backup.service` sets `TimeoutStartSec=13h` by manual coupling to the same 12 h budget, not by programmatic derivation. The 12 h value is future bounded headroom, not a proven cycle duration: only a fresh full cycle can show that it fits.

The recorded `CPUQuota=100%` default is superseded for the shared worker/verifier launch: it now carries `CPUQuota=20%`, persisting the owner-approved 20% CPU retention. Worker read/write stay 10 MB/s and the verifier-only read stays 30 MB/s. Unchanged: the 120 s HTTP timeout, 3 attempts with 30 min spacing, receipt and full-readback checks, gate proof conditions, catalog retention and format, source coverage, encryption and private keys, and no new environment variable, CLI flag, or configuration surface.

Cutover: catalog entries carry no request or deadline fields, so existing catalog entries remain valid under the new validator. A stored job envelope still carries its exact deadline, and the new validator accepts only the new exact duration, so this candidate applies to future requests only and must not be installed over an unsettled old job. Old 6 h requests and dated evidence such as [BACKUP-VERIFIED-2026-09-22.md](BACKUP-VERIFIED-2026-09-22.md) stay as recorded and are readable with their old releases.
