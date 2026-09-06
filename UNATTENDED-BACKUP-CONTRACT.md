# Unattended continuation contract

Acceptance authority: the unchanged owner-controlled
/Users/nv/repos/0x4007/oracle-free-arch-vps/PROJECT-VISION.md. Shared audit:
COST-SAFE-UNATTENDED-BACKUPS-HANDOFF-2026-09-06.md at the repository root,
source baseline 7be42b95e4851d42a9cfce193b8488f990fd3b45.

- A due period is the most recent preferred weekly civil date in the approved
  timezone. It remains due after the former start window. Coalesce missed weeks.
  A completed capture in that period satisfies it, including a manual acceptance
  capture. Do not manufacture a second generation during migration.
- Keep the existing schedule/configuration paths. No new flags, secrets, or
  environment variables. The former windowMinutes remains an alert grace period,
  not an execution deadline. A bounded one-time acceptance approval remains
  exact.
- Use the existing shared lock and scheduled claim. Claim failure permits retry
  of the same journal; completion is authoritative in the runtime journal even
  if the process exited before writing claim completion. An unfinished cycle is
  reconciled before another period can allocate a new identity.
- Retry metadata uses OnlineBackupRetry in online-backup-contract.ts. Keep the
  failed phase plus the exact resume phase. Only a caught external
  read/transport failure or a reconciliable recorded operation is retryable.
  Invalid policy, wrong identity, contradictory evidence and unclassified legacy
  failure remain blocked. Never infer safe failure merely from an error message.
- Each invocation makes one bounded attempt. Persist exponential backoff using
  ONLINE_RETRY_POLICY. After six attempts or four hours, cool down for 24 hours
  before a fresh burst; retain the same journal and operation identity. No
  automatic duplicate create after uncertain intent. No stop/start operations.
- Scheduler timer rechecks due work every 15 minutes and on controller startup,
  while retaining the preferred weekly time. It skips satisfied periods and
  respects durable next-attempt time. Lock contention causes a later recheck.
- m01 owns scheduling and its tests; m02 owns engine/OCI adapter and their
  tests; m03 owns eligibility/inventory and focused tests. Primary owns this
  contract, shared types, runtime, watchdog, deployment and combined acceptance.

These rules grant no new live operation authority. Oracle restoration remains
owner-deferred. B2 repeatability and post-trial evidence remain unproved until
specific evidence closes them. No new backup or payload download is implied.
