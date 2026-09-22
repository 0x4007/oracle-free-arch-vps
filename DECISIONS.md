# Implementation decisions

Recorded 2026-09-22 for the online Backblaze backup path in this repository. These are implementation decisions made under the owner-controlled [PROJECT-VISION.md](PROJECT-VISION.md) charter. They do not amend, replace, or claim the authority of that charter, which wins on any conflict, and they stay inside the resource-budget and request-transport scope described here.

## Per-phase resource limits

Backup transient units carry these systemd limits per phase: capture/worker read 10 MB/s, verifier read 30 MB/s, write 10 MB/s for both, read/write IOPS 500/200, `CPUWeight=1`, `CPUQuota=100%`, `Nice=19`, `MemoryMax=1 GiB`, `MemorySwapMax=0`, and no `MemoryHigh` (the soft cap was removed in `429b29d` after it throttled a real working set of about 1,078 MB into a stall).

Why the verifier read differs: this 10.36 GB generation (10,355,748,786 B ciphertext) incurs about 64.9 GB of full-file verifier read passes for ciphertext hash, decryption, `zstd -t`, plaintext hash, inventory, and 4 full boot samples. At the shared 10 MB/s read cap, verification alone needs about 108 min and does not fit the 6 h gate; 30 MB/s read with the unchanged 10 MB/s write cap gives about 47.5 min and puts a normal whole cycle at about 300 min (capture 114 + planning/upload ~121 + reconstruct 17 + verify ~47.5), about 60 min inside the deadline. That is headroom for a normal cycle, not a guarantee for every retry or a larger payload.

Observed 2026-09-22: the accepted generation's verifier ran about 67 min (07:07:20.158Z to 08:14:11.145Z), including reconstruction and the initial period under the 10 MB/s read cap before the live verifier-only 30 MB/s runtime override at 07:27:39Z. The 30 MB/s verifier read is now the source default selected from the validated unit kind; worker/capture and prune units keep 10 MB/s.

## Request transport and retry behavior

Each Backblaze request now has a 120 s timeout that applies to the fetch and the response-body read together and is combined with any caller abort signal, so either the timeout or a caller cancellation aborts the request; retry paths log sanitized phase checkpoints that give the allowed operation, error category, and timing instead of raw request detail. The existing bounded retry policy is retained unchanged: 3 attempts with 30 min spacing inside the 6 h `GATE_DEADLINE_MS`, which the timeout does not extend.

No new environment variable, CLI flag, or configuration surface was introduced for either decision; the limits come from existing unit properties and the timeout is internal to the storage client.

Related receipt: [BACKUP-VERIFIED-2026-09-22.md](BACKUP-VERIFIED-2026-09-22.md).
