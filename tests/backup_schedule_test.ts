import {
  assessBackupWatchdog,
  type BackupSchedule,
  backupTimer,
  currentWindow,
} from "../scripts/backup-schedule.ts";
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
    currentWindow(schedule, new Date("2026-11-08T08:00:00Z")) === undefined,
  );
});
Deno.test("late and early timer invocations cannot claim a maintenance window", () => {
  assert(
    currentWindow(schedule, new Date("2026-09-06T07:59:00Z")) === undefined,
  );
  assert(
    currentWindow(schedule, new Date("2026-09-06T10:00:00Z")) === undefined,
  );
  assert(
    backupTimer(schedule, new Date("2026-09-06T08:00:00Z")).includes(
      "Persistent=false",
    ),
  );
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
