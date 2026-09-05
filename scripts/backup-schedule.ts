export interface BackupSchedule {
  approvedAtUtc: string;
  timeZone: string;
  weekday: number; // Sunday = 0
  hour: number;
  minute: number;
  windowMinutes: number;
}
export function validateSchedule(schedule: BackupSchedule, now: Date): void {
  const approved = Date.parse(schedule.approvedAtUtc);
  if (
    !Number.isFinite(approved) || approved > now.getTime() ||
    !/^[A-Za-z_]+(?:\/[A-Za-z_+-]+)*$/.test(schedule.timeZone) ||
    !Number.isInteger(schedule.weekday) || schedule.weekday < 0 ||
    schedule.weekday > 6 ||
    !Number.isInteger(schedule.hour) || schedule.hour < 0 ||
    schedule.hour > 23 ||
    !Number.isInteger(schedule.minute) || schedule.minute < 0 ||
    schedule.minute > 59 ||
    !Number.isInteger(schedule.windowMinutes) || schedule.windowMinutes < 1 ||
    schedule.windowMinutes > 720
  ) throw new Error("An exact approved maintenance window is required");
  new Intl.DateTimeFormat("en-US", { timeZone: schedule.timeZone }).format(now);
}
export function currentWindow(
  schedule: BackupSchedule,
  now: Date,
): string | undefined {
  validateSchedule(schedule, now);
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-US", {
      timeZone: schedule.timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    }).formatToParts(now).map((p) => [p.type, p.value]),
  );
  const civil = new Date(
    Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day)),
  );
  const localMinute = civil.getUTCDay() * 1440 + Number(parts.hour) * 60 +
    Number(parts.minute);
  const scheduledMinute = schedule.weekday * 1440 + schedule.hour * 60 +
    schedule.minute;
  const elapsed = (localMinute - scheduledMinute + 10080) % 10080;
  if (elapsed >= schedule.windowMinutes) return undefined;
  const daysAfterStart = Math.floor(
    (schedule.hour * 60 + schedule.minute + elapsed) / 1440,
  );
  civil.setUTCDate(civil.getUTCDate() - daysAfterStart);
  // Both occurrences of a repeated DST hour share the same id.
  return `${civil.toISOString().slice(0, 10)}@${schedule.timeZone}`;
}
export function backupTimer(schedule: BackupSchedule, now: Date): string {
  validateSchedule(schedule, now);
  const day =
    ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][schedule.weekday];
  const time = `${String(schedule.hour).padStart(2, "0")}:${
    String(schedule.minute).padStart(2, "0")
  }:00`;
  return `[Unit]\nDescription=Approved weekly paired VPS backup\n\n[Timer]\nOnCalendar=${day} *-*-* ${time} ${schedule.timeZone}\nPersistent=false\nAccuracySec=1min\nRandomizedDelaySec=0\nUnit=weekly-backup.service\n\n[Install]\nWantedBy=timers.target\n`;
}

export interface BackupWatchdogState {
  phase: string;
  sourceAcceptedAtUtc?: string;
  createdAtUtc: string;
  updatedAtUtc: string;
  recoveryStatus?: string;
}
export function assessBackupWatchdog(
  state: BackupWatchdogState | undefined,
  now: Date,
  schedule: BackupSchedule,
) {
  validateSchedule(schedule, now);
  const age = (value: string | undefined) =>
    value ? now.getTime() - Date.parse(value) : NaN;
  if (!state) return { status: "NO_ACCEPTED_CYCLE", healthy: false };
  if (
    !Number.isFinite(age(state.updatedAtUtc)) || age(state.updatedAtUtc) < 0
  ) return { status: "INVALID_JOURNAL_TIME", healthy: false };
  if (state.phase === "failed") {
    return {
      status: "BACKUP_FAILED",
      healthy: false,
      recoveryStatus: state.recoveryStatus ?? "unproved",
    };
  }
  if (
    ![
      "planned",
      "quiescing",
      "quiesced",
      "stop-requested",
      "stopped",
      "backing-up",
      "pair-available",
      "start-requested",
      "source-accepted",
      "retiring",
      "complete",
    ].includes(state.phase)
  ) {
    return { status: "UNKNOWN_BACKUP_PHASE", healthy: false };
  }
  if (state.phase !== "complete") {
    const startedAge = age(state.createdAtUtc);
    return Number.isFinite(startedAge) && startedAge >= 0 &&
        startedAge <= 4 * 3_600_000
      ? { status: "BACKUP_IN_PROGRESS", healthy: true }
      : { status: "BACKUP_STALLED", healthy: false };
  }
  const acceptedAge = age(state.sourceAcceptedAtUtc);
  if (!Number.isFinite(acceptedAge) || acceptedAge < 0) {
    return { status: "SOURCE_ACCEPTANCE_MISSING", healthy: false };
  }
  const civilTime = (date: Date) => {
    const parts = Object.fromEntries(
      new Intl.DateTimeFormat("en-US", {
        timeZone: schedule.timeZone,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hourCycle: "h23",
      }).formatToParts(date).map((part) => [part.type, part.value]),
    );
    return Date.UTC(
      Number(parts.year),
      Number(parts.month) - 1,
      Number(parts.day),
      Number(parts.hour),
      Number(parts.minute),
    );
  };
  const localNow = civilTime(now);
  const day = new Date(localNow);
  day.setUTCHours(0, 0, 0, 0);
  let closedWindow = day.getTime() -
    ((day.getUTCDay() - schedule.weekday + 7) % 7) * 86_400_000 +
    (schedule.hour * 60 + schedule.minute) * 60_000;
  if (localNow < closedWindow + schedule.windowMinutes * 60_000) {
    closedWindow -= 7 * 86_400_000;
  }
  if (
    closedWindow >= civilTime(new Date(schedule.approvedAtUtc)) &&
    civilTime(new Date(state.sourceAcceptedAtUtc!)) < closedWindow
  ) {
    return { status: "SCHEDULED_WINDOW_MISSED", healthy: false };
  }
  if (
    acceptedAge > 7 * 86_400_000 + schedule.windowMinutes * 60_000 + 3_600_000
  ) {
    return { status: "BACKUP_OVERDUE", healthy: false };
  }
  return { status: "ACCEPTED_BACKUP_CURRENT", healthy: true };
}
