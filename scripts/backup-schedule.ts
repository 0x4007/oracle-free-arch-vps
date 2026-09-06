export interface BackupSchedule {
  approvedAtUtc: string;
  timeZone: string;
  weekday: number; // Sunday = 0
  hour: number;
  minute: number;
  /** Alert grace after the preferred time; it does not close execution. */
  windowMinutes: number;
  acceptanceWindow?: {
    approvedAtUtc: string;
    startsAtUtc: string;
    expiresAtUtc: string;
    exactOperation: "one online scheduler acceptance capture";
  };
}

const LOCAL_PARTS = {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
} as const;

interface CivilParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
}

function localParts(schedule: BackupSchedule, now: Date): CivilParts {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-US", {
      timeZone: schedule.timeZone,
      year: LOCAL_PARTS.year,
      month: LOCAL_PARTS.month,
      day: LOCAL_PARTS.day,
      hour: LOCAL_PARTS.hour,
      minute: LOCAL_PARTS.minute,
      hourCycle: LOCAL_PARTS.hourCycle,
    }).formatToParts(now).map((part) => [part.type, part.value]),
  );
  const values = ["year", "month", "day", "hour", "minute"].map((name) =>
    Number(parts[name])
  );
  if (values.some((value) => !Number.isInteger(value))) {
    throw new Error("Schedule timezone did not produce complete civil time");
  }
  return {
    year: values[0],
    month: values[1],
    day: values[2],
    hour: values[3],
    minute: values[4],
  };
}

function civilDate(parts: CivilParts): Date {
  return new Date(Date.UTC(parts.year, parts.month - 1, parts.day));
}

function isoCivilDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function validateAcceptanceWindow(
  request: NonNullable<BackupSchedule["acceptanceWindow"]>,
): { starts: number; expires: number } {
  const approved = Date.parse(request.approvedAtUtc);
  const starts = Date.parse(request.startsAtUtc);
  const expires = Date.parse(request.expiresAtUtc);
  if (
    request.exactOperation !== "one online scheduler acceptance capture" ||
    ![approved, starts, expires].every(Number.isFinite) ||
    approved > starts || expires <= starts ||
    expires - approved > 4 * 3_600_000
  ) throw new Error("Invalid one-time scheduler acceptance approval");
  return { starts, expires };
}

/** Return the preferred weekly civil period that is currently due.
 *
 * The returned identity is based on the most recent preferred local date,
 * rather than on a bounded execution window. This keeps a missed Sunday due
 * until the next preferred Sunday and lets the caller coalesce missed weeks.
 */
export function duePeriod(schedule: BackupSchedule, now: Date): string {
  validateSchedule(schedule, now);
  const parts = localParts(schedule, now);
  const date = civilDate(parts);
  const localWeekday = date.getUTCDay();
  const daysSincePreferred = (localWeekday - schedule.weekday + 7) % 7;
  date.setUTCDate(date.getUTCDate() - daysSincePreferred);
  const localMinute = parts.hour * 60 + parts.minute;
  const preferredMinute = schedule.hour * 60 + schedule.minute;
  if (daysSincePreferred === 0 && localMinute < preferredMinute) {
    date.setUTCDate(date.getUTCDate() - 7);
  }
  return `${isoCivilDate(date)}@${schedule.timeZone}`;
}

/** Derive the weekly period for a completed capture timestamp. Acceptance
 * windows never change the period identity used for duplicate prevention. */
export function periodAt(
  schedule: BackupSchedule,
  at: Date,
): string {
  return duePeriod(schedule, at);
}

export function periodDate(period: string): string {
  const date = period.match(/^(\d{4}-\d{2}-\d{2})@/);
  return date?.[1] ?? "";
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
  ) throw new Error("An exact approved weekly schedule is required");
  new Intl.DateTimeFormat("en-US", { timeZone: schedule.timeZone }).format(now);
}
export function currentWindow(
  schedule: BackupSchedule,
  now: Date,
): string {
  validateSchedule(schedule, now);
  if (schedule.acceptanceWindow) {
    const request = schedule.acceptanceWindow;
    const { starts, expires } = validateAcceptanceWindow(request);
    if (now.getTime() >= starts && now.getTime() < expires) {
      return `acceptance@${new Date(starts).toISOString()}`;
    }
  }
  return duePeriod(schedule, now);
}
export function backupTimer(schedule: BackupSchedule, now: Date): string {
  validateSchedule(schedule, now);
  const day =
    ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][schedule.weekday];
  const time = `${String(schedule.hour).padStart(2, "0")}:${
    String(schedule.minute).padStart(2, "0")
  }:00`;
  return `[Unit]\nDescription=Online weekly paired VPS backup\n\n[Timer]\nOnCalendar=${day} *-*-* ${time} ${schedule.timeZone}\nOnStartupSec=15min\nOnBootSec=15min\nOnUnitActiveSec=15min\nPersistent=true\nAccuracySec=1min\nRandomizedDelaySec=0\nUnit=weekly-backup.service\n\n[Install]\nWantedBy=timers.target\n`;
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
      "backing-up",
      "pair-available",
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
