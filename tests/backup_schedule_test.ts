import {
  assessBackupWatchdog,
  type BackupSchedule,
  backupTimer,
  currentWindow,
  duePeriod,
  periodAt,
} from "../scripts/backup-schedule.ts";
import {
  approvedScheduleOf,
  assertCaptureStillAuthorized,
  planScheduledClaim,
  type ScheduledRuntimeState,
  type WindowClaim,
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
  assert(timer.includes("OnUnitInactiveSec=15min"));
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

Deno.test("schedule reapproval does not reject an older completed capture", () => {
  const reapproved = { ...schedule, approvedAtUtc: "2026-09-07T00:00:00Z" };
  const state = {
    cycle: {
      phase: "complete",
      captureIdentity: { captureTimeUtc: "2026-09-06T16:00:00Z" },
    },
  };
  assert(
    planScheduledClaim(
      reapproved,
      new Date("2026-09-13T12:00:00Z"),
      state,
      undefined,
    ).action === "run",
  );
});

Deno.test("satisfied period repairs a stale claim only after a different cycle completes", () => {
  const now = new Date("2026-09-06T20:00:00Z");
  const state: ScheduledRuntimeState = {
    cycle: {
      phase: "complete",
      suffix: "20260906T164037Z",
      captureIdentity: { captureTimeUtc: "2026-09-06T16:51:34.128Z" },
    },
  };
  const claim = {
    windowId: "2026-09-06@America/New_York",
    status: "started" as const,
    previousCycleSuffix: "20260830T040000Z",
    updatedAtUtc: "2026-09-06T16:00:00Z",
  };
  const repaired = planScheduledClaim(schedule, now, state, claim);
  assert(repaired.action === "skip");
  assert(repaired.completedClaim?.status === "complete");
  assert(repaired.completedClaim?.windowId === claim.windowId);
  const unchanged = planScheduledClaim(schedule, now, state, {
    ...claim,
    previousCycleSuffix: state.cycle!.suffix,
  });
  assert(unchanged.action === "skip");
  assert(unchanged.completedClaim === undefined);
});

function startedClaim(
  schedule: BackupSchedule,
  windowId: string,
): WindowClaim {
  const now = new Date("2026-09-06T08:00:00Z");
  return {
    windowId,
    periodId: duePeriod(schedule, now),
    status: "started",
    updatedAtUtc: now.toISOString(),
    approvedSchedule: approvedScheduleOf(schedule),
  };
}

Deno.test("a pending capture fails closed on revoked, malformed or future approval", () => {
  const claim = startedClaim(schedule, "2026-09-06@America/New_York");
  const now = new Date("2026-09-08T12:00:00Z");
  assertCaptureStillAuthorized(schedule, claim, now);
  // Only an alert-grace change does not change the schedule authority.
  assertCaptureStillAuthorized({ ...schedule, windowMinutes: 240 }, claim, now);
  for (
    const revoked of [
      { ...schedule, approvedAtUtc: "" },
      { ...schedule, approvedAtUtc: "a-timestamp-that-is-not" },
      { ...schedule, approvedAtUtc: "2099-01-01T00:00:00Z" },
    ]
  ) {
    let refused = false;
    try {
      assertCaptureStillAuthorized(revoked, claim, now);
    } catch {
      refused = true;
    }
    assert(refused);
  }
});

Deno.test("a pending capture is refused when the approved schedule authority changes", () => {
  const claim = startedClaim(schedule, "2026-09-06@America/New_York");
  const now = new Date("2026-09-08T12:00:00Z");
  for (
    const changed of [
      { ...schedule, approvedAtUtc: "2026-09-06T00:00:00Z" },
      { ...schedule, weekday: 1 },
      { ...schedule, hour: 2 },
      { ...schedule, timeZone: "UTC" },
    ]
  ) {
    let refused = false;
    try {
      assertCaptureStillAuthorized(changed, claim, now);
    } catch {
      refused = true;
    }
    assert(refused);
  }
});

Deno.test("valid late catch-up and next-period crossing remain authorized", () => {
  const claim = startedClaim(schedule, "2026-09-06@America/New_York");
  // A delayed weekly trigger after the grace period is still authorized.
  assertCaptureStillAuthorized(
    schedule,
    claim,
    new Date("2026-09-08T12:00:00Z"),
  );
  // An unfinished claim crossing into a later preferred week is still authorized.
  assertCaptureStillAuthorized(
    schedule,
    claim,
    new Date("2026-09-20T12:00:00Z"),
  );
  const resumed = planScheduledClaim(
    schedule,
    new Date("2026-09-20T12:00:00Z"),
    { cycle: { phase: "backing-up", suffix: "20260906T080000Z" } },
    { ...claim, status: "failed" },
  );
  assert(resumed.action === "run");
  if (resumed.action === "run") {
    // The original binding survives reuse across periods.
    assert(resumed.claim.windowId === claim.windowId);
    assert(resumed.claim.periodId === claim.periodId);
    assert(
      resumed.claim.approvedSchedule?.approvedAtUtc ===
        schedule.approvedAtUtc,
    );
  }
});

Deno.test("a pending capture rejects a closed or changed one-time acceptance window", () => {
  const accepted: BackupSchedule = {
    ...schedule,
    acceptanceWindow: {
      approvedAtUtc: "2026-09-06T22:00:00Z",
      startsAtUtc: "2026-09-06T22:05:00Z",
      expiresAtUtc: "2026-09-07T01:00:00Z",
      exactOperation: "one online scheduler acceptance capture",
    },
  };
  const claim = startedClaim(accepted, "acceptance@2026-09-06T22:05:00.000Z");
  assertCaptureStillAuthorized(
    accepted,
    claim,
    new Date("2026-09-06T22:10:00Z"),
  );
  let refused = false;
  try {
    assertCaptureStillAuthorized(
      accepted,
      claim,
      new Date("2026-09-07T02:00:00Z"),
    );
  } catch {
    refused = true;
  }
  assert(refused);
  // The window was replaced by a different exact acceptance window.
  const replaced: BackupSchedule = {
    ...schedule,
    acceptanceWindow: {
      approvedAtUtc: "2026-09-06T23:00:00Z",
      startsAtUtc: "2026-09-06T23:05:00Z",
      expiresAtUtc: "2026-09-07T02:00:00Z",
      exactOperation: "one online scheduler acceptance capture",
    },
  };
  refused = false;
  try {
    assertCaptureStillAuthorized(
      replaced,
      claim,
      new Date("2026-09-06T23:10:00Z"),
    );
  } catch {
    refused = true;
  }
  assert(refused);
  // The acceptance window was removed from the schedule.
  refused = false;
  try {
    assertCaptureStillAuthorized(
      schedule,
      claim,
      new Date("2026-09-06T22:10:00Z"),
    );
  } catch {
    refused = true;
  }
  assert(refused);
});

Deno.test("a claim without an approved schedule binding cannot authorize a capture", () => {
  const legacy = {
    windowId: "2026-09-06@America/New_York",
    status: "started" as const,
    updatedAtUtc: "2026-09-06T08:00:00Z",
  };
  let refused = false;
  try {
    assertCaptureStillAuthorized(
      schedule,
      legacy,
      new Date("2026-09-06T09:00:00Z"),
    );
  } catch {
    refused = true;
  }
  assert(refused);
});

Deno.test("a fresh plan binds the approved schedule authority into its claim", () => {
  const accepted: BackupSchedule = {
    ...schedule,
    acceptanceWindow: {
      approvedAtUtc: "2026-09-06T22:00:00Z",
      startsAtUtc: "2026-09-06T22:05:00Z",
      expiresAtUtc: "2026-09-07T01:00:00Z",
      exactOperation: "one online scheduler acceptance capture",
    },
  };
  for (
    const [planned, when] of [
      [schedule, "2026-09-06T08:00:00Z"],
      [accepted, "2026-09-06T22:10:00Z"],
    ] as const
  ) {
    const decision = planScheduledClaim(
      planned,
      new Date(when),
      undefined,
      undefined,
    );
    assert(decision.action === "run");
    if (decision.action === "run") {
      assert(
        JSON.stringify(decision.claim.approvedSchedule) ===
          JSON.stringify(approvedScheduleOf(planned)),
      );
    }
  }
});

Deno.test("a malformed claim schedule binding fails closed", () => {
  const malformed = {
    windowId: "2026-09-06@America/New_York",
    status: "started" as const,
    updatedAtUtc: "2026-09-06T08:00:00Z",
    approvedSchedule: { ...approvedScheduleOf(schedule), hour: 25 },
  };
  let refused = false;
  try {
    planScheduledClaim(
      schedule,
      new Date("2026-09-06T09:00:00Z"),
      undefined,
      malformed,
    );
  } catch {
    refused = true;
  }
  assert(refused);
});
