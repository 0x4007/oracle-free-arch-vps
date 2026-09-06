import {
  assessBackupWatchdog,
  type BackupSchedule,
  backupTimer,
  currentWindow,
  duePeriod,
  periodAt,
} from "../scripts/backup-schedule.ts";
import {
  planScheduledClaim,
  type ScheduledRuntimeState,
} from "../scripts/backup-scheduled.ts";
const schedule: BackupSchedule = {
  approvedAtUtc: "2026-09-05T01:51:00Z",
  timeZone: "America/New_York",
  weekday: 0,
  hour: 4,
  minute: 0,
  windowMinutes: 120,
};
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
Deno.test("one-time online acceptance uses real bounded time without changing weekly schedule", () => {
  const acceptance: BackupSchedule = {
    ...schedule,
    acceptanceWindow: {
      approvedAtUtc: "2026-09-06T15:00:00Z",
      startsAtUtc: "2026-09-06T15:05:00Z",
      expiresAtUtc: "2026-09-06T18:00:00Z",
      exactOperation: "one online scheduler acceptance capture",
    },
  };
  assert(
    currentWindow(acceptance, new Date("2026-09-06T15:04:59Z")) ===
      "2026-09-06@America/New_York",
  );
  assert(
    currentWindow(acceptance, new Date("2026-09-06T15:05:00Z")) ===
      "acceptance@2026-09-06T15:05:00.000Z",
  );
  assert(
    currentWindow(acceptance, new Date("2026-09-06T18:00:00Z")) ===
      "2026-09-06@America/New_York",
  );
  assert(
    currentWindow(acceptance, new Date("2026-09-13T08:00:00Z")) ===
      "2026-09-13@America/New_York",
  );
  const invalid = structuredClone(acceptance);
  invalid.acceptanceWindow!.expiresAtUtc = "2026-09-07T18:00:00Z";
  let refused = false;
  try {
    currentWindow(invalid, new Date("2026-09-06T16:00:00Z"));
  } catch {
    refused = true;
  }
  assert(refused);
});
Deno.test("maintenance window follows New York daylight-saving time", () => {
  assert(
    currentWindow(schedule, new Date("2026-09-06T08:00:00Z")) ===
      "2026-09-06@America/New_York",
  );
  assert(
    currentWindow(schedule, new Date("2026-11-08T09:00:00Z")) ===
      "2026-11-08@America/New_York",
  );
  assert(
    currentWindow(schedule, new Date("2026-11-08T08:00:00Z")) ===
      "2026-11-01@America/New_York",
  );
});
Deno.test("late and early timer invocations retain a due period", () => {
  assert(
    currentWindow(schedule, new Date("2026-09-06T07:59:00Z")) ===
      "2026-08-30@America/New_York",
  );
  assert(
    currentWindow(schedule, new Date("2026-09-06T10:00:00Z")) ===
      "2026-09-06@America/New_York",
  );
  const timer = backupTimer(schedule, new Date("2026-09-06T08:00:00Z"));
  assert(timer.includes("Persistent=true"));
  assert(timer.includes("OnStartupSec=15min"));
  assert(timer.includes("OnUnitActiveSec=15min"));
});
Deno.test("repeated DST hours share a single maintenance identity", () => {
  const repeated = { ...schedule, hour: 1 };
  assert(
    currentWindow(repeated, new Date("2026-11-01T05:30:00Z")) ===
      currentWindow(repeated, new Date("2026-11-01T06:30:00Z")),
  );
});
Deno.test("overnight windows retain the start-date identity", () => {
  const overnight = { ...schedule, weekday: 6, hour: 23 };
  assert(
    currentWindow(overnight, new Date("2026-09-06T04:30:00Z")) ===
      "2026-09-05@America/New_York",
  );
});
Deno.test("watchdog detects missing, failed, stalled and overdue runs", () => {
  const now = new Date("2026-09-14T08:00:00Z");
  const state = {
    phase: "complete",
    createdAtUtc: "2026-09-05T08:00:00Z",
    updatedAtUtc: "2026-09-05T09:00:00Z",
    sourceAcceptedAtUtc: "2026-09-05T09:00:00Z",
  };
  assert(!assessBackupWatchdog(undefined, now, schedule).healthy);
  assert(
    assessBackupWatchdog(state, now, schedule).status ===
      "SCHEDULED_WINDOW_MISSED",
  );
  assert(
    assessBackupWatchdog({ ...state, phase: "failed" }, now, schedule)
      .status ===
      "BACKUP_FAILED",
  );
  assert(
    assessBackupWatchdog({ ...state, phase: "backing-up" }, now, schedule)
      .status ===
      "BACKUP_STALLED",
  );
  assert(
    assessBackupWatchdog(
      {
        ...state,
        sourceAcceptedAtUtc: "2026-09-13T09:00:00Z",
      },
      now,
      schedule,
    ).healthy,
  );
});

Deno.test("watchdog detects a missed window as it closes, not a day later", () => {
  const state = {
    phase: "complete",
    createdAtUtc: "2026-09-06T08:00:00Z",
    updatedAtUtc: "2026-09-06T09:00:00Z",
    sourceAcceptedAtUtc: "2026-09-06T09:00:00Z",
  };
  assert(
    assessBackupWatchdog(state, new Date("2026-09-13T09:59:00Z"), schedule)
      .healthy,
  );
  assert(
    assessBackupWatchdog(state, new Date("2026-09-13T10:00:00Z"), schedule)
      .status === "SCHEDULED_WINDOW_MISSED",
  );
  assert(
    assessBackupWatchdog(
      { ...state, phase: "unknown" },
      new Date("2026-09-13T09:59:00Z"),
      schedule,
    ).status === "UNKNOWN_BACKUP_PHASE",
  );
});

Deno.test("due periods coalesce missed weeks and keep the preferred civil time", () => {
  assert(
    duePeriod(schedule, new Date("2026-09-13T08:00:00Z")) ===
      "2026-09-13@America/New_York",
  );
  assert(
    duePeriod(schedule, new Date("2026-09-15T15:00:00Z")) ===
      "2026-09-13@America/New_York",
  );
  assert(
    duePeriod(schedule, new Date("2026-09-20T07:59:59Z")) ===
      "2026-09-13@America/New_York",
  );
  assert(
    periodAt(schedule, new Date("2026-09-13T08:00:00Z")) ===
      "2026-09-13@America/New_York",
  );
});

Deno.test("a completed capture satisfies the current period after timer replay", () => {
  const state: ScheduledRuntimeState = {
    cycle: {
      phase: "complete",
      suffix: "20260906T164037Z",
      captureIdentity: { captureTimeUtc: "2026-09-06T16:51:34.128Z" },
    },
  };
  const decision = planScheduledClaim(
    schedule,
    new Date("2026-09-06T20:00:00Z"),
    state,
    {
      windowId: "acceptance@2026-09-06T15:05:00.000Z",
      status: "started",
      updatedAtUtc: "2026-09-06T16:00:00Z",
    },
  );
  assert(decision.action === "skip");
  if (decision.action === "skip") {
    assert(decision.reason === "PERIOD_ALREADY_SATISFIED");
  }
});

Deno.test("an unfinished journal resumes its claim across a later period", () => {
  const decision = planScheduledClaim(
    schedule,
    new Date("2026-09-20T15:00:00Z"),
    { cycle: { phase: "backing-up", suffix: "20260913T040000Z" } },
    {
      windowId: "2026-09-13@America/New_York",
      periodId: "2026-09-13@America/New_York",
      status: "failed",
      updatedAtUtc: "2026-09-13T06:00:00Z",
    },
  );
  assert(decision.action === "run");
  if (decision.action === "run") {
    assert(decision.claim.windowId === "2026-09-13@America/New_York");
    assert(decision.claim.periodId === "2026-09-13@America/New_York");
    assert(decision.claim.status === "started");
  }
});

Deno.test("durable retry metadata defers or blocks a failed journal", () => {
  const base = {
    cycle: {
      phase: "failed",
      retry: {
        disposition: "retryable" as const,
        resumePhase: "backing-up" as const,
        attempts: 1,
        firstFailureAtUtc: "2026-09-13T05:00:00Z",
        nextAttemptAtUtc: "2026-09-13T05:15:00Z",
        deadlineAtUtc: "2026-09-13T09:00:00Z",
      },
    },
  } satisfies ScheduledRuntimeState;
  const deferred = planScheduledClaim(
    schedule,
    new Date("2026-09-13T05:10:00Z"),
    base,
    undefined,
  );
  assert(deferred.action === "skip");
  if (deferred.action === "skip") {
    assert(deferred.reason === "BACKUP_RETRY_NOT_DUE");
  }

  const blocked = planScheduledClaim(
    schedule,
    new Date("2026-09-13T05:20:00Z"),
    {
      cycle: {
        ...base.cycle,
        retry: { ...base.cycle.retry, disposition: "blocked" },
      },
    },
    undefined,
  );
  assert(blocked.action === "skip");
  if (blocked.action === "skip") {
    assert(blocked.reason === "BACKUP_RETRY_BLOCKED");
  }
});

Deno.test("a new exact acceptance window permits one capture then suppresses replay", () => {
  const acceptedSchedule: BackupSchedule = {
    ...schedule,
    acceptanceWindow: {
      approvedAtUtc: "2026-09-06T22:00:00Z",
      startsAtUtc: "2026-09-06T22:05:00Z",
      expiresAtUtc: "2026-09-07T01:00:00Z",
      exactOperation: "one online scheduler acceptance capture",
    },
  };
  const state = {
    cycle: {
      phase: "complete",
      suffix: "20260906T160000Z",
      captureIdentity: { captureTimeUtc: "2026-09-06T16:00:00Z" },
    },
  };
  assert(
    planScheduledClaim(
      acceptedSchedule,
      new Date("2026-09-06T22:10:00Z"),
      state,
      undefined,
    ).action === "run",
  );
  state.cycle.captureIdentity.captureTimeUtc = "2026-09-06T22:15:00Z";
  assert(
    planScheduledClaim(
      acceptedSchedule,
      new Date("2026-09-06T22:30:00Z"),
      state,
      undefined,
    ).action === "skip",
  );
});
