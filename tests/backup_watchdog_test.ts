import { assessOracleRetry } from "../scripts/backup-watchdog.ts";
import type { OnlineBackupRetry } from "../scripts/online-backup-contract.ts";

const now = new Date("2026-09-06T23:00:00Z");
const retry: OnlineBackupRetry = {
  disposition: "retryable",
  resumePhase: "backing-up",
  attempts: 1,
  firstFailureAtUtc: "2026-09-06T22:55:00Z",
  nextAttemptAtUtc: "2026-09-06T23:10:00Z",
  deadlineAtUtc: "2026-09-07T02:55:00Z",
};
function assertStatus(value: OnlineBackupRetry, expected: string) {
  const result = assessOracleRetry({ phase: "failed", retry: value }, now);
  if (result?.status !== expected || result.healthy !== false) {
    throw new Error(`Expected visible unresolved ${expected}`);
  }
}
Deno.test("retry watchdog distinguishes waiting, due, cooldown and ambiguity", () => {
  assertStatus(retry, "BACKUP_RETRY_WAITING");
  assertStatus(
    { ...retry, nextAttemptAtUtc: now.toISOString() },
    "BACKUP_RETRY_DUE",
  );
  assertStatus(
    { ...retry, nextAttemptAtUtc: "2026-09-07T23:00:00Z" },
    "BACKUP_RETRY_COOLDOWN",
  );
  assertStatus(
    { ...retry, disposition: "blocked" },
    "BACKUP_BLOCKED_RECONCILIATION",
  );
});
Deno.test("retry watchdog refuses malformed or future evidence", () => {
  assertStatus({ ...retry, attempts: -1 }, "INVALID_RETRY_STATE");
  assertStatus(
    { ...retry, nextAttemptAtUtc: "invalid" },
    "INVALID_RETRY_STATE",
  );
  assertStatus(
    { ...retry, firstFailureAtUtc: "2026-09-07T00:00:00Z" },
    "INVALID_RETRY_STATE",
  );
});
Deno.test("retry watchdog does not overwrite accepted or legacy failure assessments", () => {
  if (
    assessOracleRetry({ phase: "complete", retry }, now) !== undefined ||
    assessOracleRetry({ phase: "failed" }, now) !== undefined
  ) {
    throw new Error("Unexpected retry assessment");
  }
});
