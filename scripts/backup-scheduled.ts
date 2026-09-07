import { main } from "./backup-runtime.ts";
import {
  type BackupSchedule,
  currentWindow,
  duePeriod,
  periodAt,
  periodDate,
  validateSchedule,
} from "./backup-schedule.ts";
import {
  ONLINE_RETRY_POLICY,
  type OnlineBackupRetry,
} from "./online-backup-contract.ts";
import { readPrivateJson, redactOcid, writePrivateJson } from "./oci.ts";

export type ScheduledClaimStatus = "started" | "complete" | "failed";

/** The approved schedule authority a claim was planned under. */
export interface ApprovedSchedule {
  approvedAtUtc: string;
  timeZone: string;
  weekday: number; // Sunday = 0
  hour: number;
  minute: number;
  acceptanceWindow?: {
    approvedAtUtc: string;
    startsAtUtc: string;
    expiresAtUtc: string;
    exactOperation: "one online scheduler acceptance capture";
  };
}

export interface WindowClaim {
  /** Kept as windowId for compatibility with existing private claim readers. */
  windowId: string;
  /** Weekly due-period identity, independent of an acceptance-window trigger. */
  periodId?: string;
  previousCycleSuffix?: string;
  status: ScheduledClaimStatus;
  updatedAtUtc: string;
  /** Approved schedule authority the claim was planned under. */
  approvedSchedule?: ApprovedSchedule;
}

export interface ScheduledCycleState {
  phase?: string;
  suffix?: string;
  createdAtUtc?: string;
  updatedAtUtc?: string;
  sourceAcceptedAtUtc?: string;
  captureIdentity?: { captureTimeUtc?: string };
  retry?: OnlineBackupRetry;
}

export interface ScheduledRuntimeState {
  cycle?: ScheduledCycleState;
  lastSuccessfulCaptureAtUtc?: string;
}

export type ScheduledDecision =
  | { action: "skip"; reason: string; completedClaim?: WindowClaim }
  | { action: "run"; claim: WindowClaim };

const CLAIM = ".private/backup-scheduled-window.json";

class Skipped extends Error {}

function isAcceptanceWindowId(value: string): boolean {
  return value.startsWith("acceptance@");
}

function parseTimestamp(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

const TIME_ZONE_PATTERN = /^[A-Za-z_]+(?:\/[A-Za-z_+-]+)*$/;

/** Canonical approved schedule binding stored on a claim. */
export function approvedScheduleOf(
  schedule: BackupSchedule,
): ApprovedSchedule {
  return {
    approvedAtUtc: schedule.approvedAtUtc,
    timeZone: schedule.timeZone,
    weekday: schedule.weekday,
    hour: schedule.hour,
    minute: schedule.minute,
    ...(schedule.acceptanceWindow
      ? { acceptanceWindow: structuredClone(schedule.acceptanceWindow) }
      : {}),
  };
}

function sameApprovedSchedule(
  a: ApprovedSchedule,
  b: ApprovedSchedule,
): boolean {
  if (
    a.approvedAtUtc !== b.approvedAtUtc ||
    a.timeZone !== b.timeZone ||
    a.weekday !== b.weekday ||
    a.hour !== b.hour ||
    a.minute !== b.minute
  ) return false;
  const aw = a.acceptanceWindow;
  const bw = b.acceptanceWindow;
  if ((aw === undefined) !== (bw === undefined)) return false;
  return aw === undefined || (
    aw.approvedAtUtc === bw!.approvedAtUtc &&
    aw.startsAtUtc === bw!.startsAtUtc &&
    aw.expiresAtUtc === bw!.expiresAtUtc &&
    aw.exactOperation === bw!.exactOperation
  );
}

function validateApprovedSchedule(value: ApprovedSchedule): void {
  if (
    !parseTimestamp(value.approvedAtUtc) ||
    !TIME_ZONE_PATTERN.test(value.timeZone) ||
    !Number.isInteger(value.weekday) || value.weekday < 0 ||
    value.weekday > 6 ||
    !Number.isInteger(value.hour) || value.hour < 0 || value.hour > 23 ||
    !Number.isInteger(value.minute) || value.minute < 0 || value.minute > 59
  ) throw new Error("Scheduled claim has an invalid approved schedule binding");
  if (value.acceptanceWindow !== undefined) {
    const window = value.acceptanceWindow;
    const approved = parseTimestamp(window.approvedAtUtc);
    const starts = parseTimestamp(window.startsAtUtc);
    const expires = parseTimestamp(window.expiresAtUtc);
    if (
      window.exactOperation !== "one online scheduler acceptance capture" ||
      approved === undefined || starts === undefined || expires === undefined ||
      approved > starts || expires <= starts ||
      expires - approved > 4 * 3_600_000
    ) throw new Error("Scheduled claim has an invalid acceptance binding");
  }
}

/** Fail closed when a pending capture is no longer authorized by the latest
 * approved schedule: a revoked, malformed or future approval, a changed
 * weekly or one-time authority, or a closed one-time acceptance window.
 */
export function assertCaptureStillAuthorized(
  latest: BackupSchedule,
  claim: WindowClaim,
  now: Date,
): void {
  validateSchedule(latest, now);
  if (!claim.approvedSchedule) {
    throw new Error("Scheduled claim has no approved schedule binding");
  }
  if (
    !sameApprovedSchedule(claim.approvedSchedule, approvedScheduleOf(latest))
  ) {
    throw new Error("Approved schedule changed while the capture was pending");
  }
  if (
    isAcceptanceWindowId(claim.windowId) &&
    currentWindow(latest, now) !== claim.windowId
  ) {
    throw new Error("One-time scheduler acceptance window closed");
  }
}

function captureTimestamp(
  state: ScheduledRuntimeState | undefined,
): number | undefined {
  const cycle = state?.cycle;
  if (cycle?.phase !== "complete") return undefined;
  return parseTimestamp(
    cycle.captureIdentity?.captureTimeUtc ?? cycle.sourceAcceptedAtUtc ??
      state?.lastSuccessfulCaptureAtUtc,
  );
}

function periodIsSatisfied(
  schedule: BackupSchedule,
  due: string,
  state: ScheduledRuntimeState | undefined,
): boolean {
  const captured = captureTimestamp(state);
  if (captured === undefined) return false;
  const capturedPeriod = periodAt(schedule, new Date(captured));
  const dueDate = periodDate(due);
  const capturedDate = periodDate(capturedPeriod);
  return dueDate !== "" && capturedDate !== "" && capturedDate >= dueDate;
}

function retryDecision(
  state: ScheduledRuntimeState | undefined,
  now: Date,
): string | undefined {
  const retry = state?.cycle?.retry;
  if (!retry) return undefined;
  const firstFailure = parseTimestamp(retry.firstFailureAtUtc);
  const nextAttempt = parseTimestamp(retry.nextAttemptAtUtc);
  const deadline = parseTimestamp(retry.deadlineAtUtc);
  if (
    (retry.disposition !== "retryable" && retry.disposition !== "blocked") ||
    ![
      "planned",
      "backing-up",
      "pair-available",
      "source-accepted",
      "retiring",
    ].includes(retry.resumePhase) ||
    !Number.isInteger(retry.attempts) || retry.attempts < 0 ||
    retry.attempts > ONLINE_RETRY_POLICY.maximumAttempts ||
    firstFailure === undefined || nextAttempt === undefined ||
    deadline === undefined || nextAttempt < firstFailure ||
    deadline < firstFailure
  ) return "BACKUP_RETRY_METADATA_INVALID";
  if (retry.disposition === "blocked") return "BACKUP_RETRY_BLOCKED";
  if (now.getTime() < nextAttempt) return "BACKUP_RETRY_NOT_DUE";
  return undefined;
}

function validateClaim(claim: WindowClaim): void {
  if (
    typeof claim.windowId !== "string" || claim.windowId === "" ||
    !["started", "complete", "failed"].includes(claim.status) ||
    !parseTimestamp(claim.updatedAtUtc)
  ) throw new Error("Scheduled claim has an unknown status");
  if (claim.periodId !== undefined && claim.periodId === "") {
    throw new Error("Scheduled claim has no period identity");
  }
  if (claim.approvedSchedule !== undefined) {
    validateApprovedSchedule(claim.approvedSchedule);
  }
}

function claimFor(
  triggerId: string,
  due: string,
  now: Date,
  state: ScheduledRuntimeState | undefined,
  existing: WindowClaim | undefined,
  schedule: BackupSchedule,
): WindowClaim {
  return {
    ...(existing ?? {}),
    windowId: existing?.windowId ?? triggerId,
    periodId: existing?.periodId ?? due,
    previousCycleSuffix: state?.cycle?.phase === "complete"
      ? state.cycle.suffix
      : existing?.previousCycleSuffix,
    approvedSchedule: existing?.approvedSchedule ??
      approvedScheduleOf(schedule),
    status: "started",
    updatedAtUtc: now.toISOString(),
  };
}

/** Decide one scheduler invocation without touching the runtime or OCI.
 *
 * A completed capture is matched to its weekly civil period. A late trigger
 * therefore observes the same due period and skips it, while a missed period
 * starts one current claim. An unfinished cycle always reuses its claim and
 * journal, even when the clock has crossed a later preferred Sunday.
 */
export function planScheduledClaim(
  schedule: BackupSchedule,
  now: Date,
  state: ScheduledRuntimeState | undefined,
  existing: WindowClaim | undefined,
): ScheduledDecision {
  const due = duePeriod(schedule, now);
  const triggerId = currentWindow(schedule, now);
  if (existing) validateClaim(existing);

  const cycleComplete = state?.cycle?.phase === "complete";
  const acceptanceDue = isAcceptanceWindowId(triggerId) &&
    (captureTimestamp(state) ?? -Infinity) <
      Date.parse(triggerId.slice("acceptance@".length));
  if (
    cycleComplete && !acceptanceDue && periodIsSatisfied(schedule, due, state)
  ) {
    return {
      action: "skip",
      reason: "PERIOD_ALREADY_SATISFIED",
      ...(existing?.status === "started" && state?.cycle?.suffix &&
          state.cycle.suffix !== existing.previousCycleSuffix
        ? {
          completedClaim: {
            ...existing,
            status: "complete" as const,
            updatedAtUtc: now.toISOString(),
          },
        }
        : {}),
    };
  }

  const retry = retryDecision(state, now);
  if (retry) return { action: "skip", reason: retry };

  if (!cycleComplete && existing && isAcceptanceWindowId(existing.windowId)) {
    // A one-time approval cannot silently turn into a standing approval after
    // its exact bounded window expires. The existing journal remains for
    // explicit reconciliation, and no new identity is allocated here.
    if (currentWindow(schedule, now) !== existing.windowId) {
      return { action: "skip", reason: "ACCEPTANCE_WINDOW_EXPIRED" };
    }
  }

  if (!cycleComplete && existing) {
    return {
      action: "run",
      claim: claimFor(
        existing.windowId,
        existing.periodId ?? due,
        now,
        state,
        existing,
        schedule,
      ),
    };
  }

  return {
    action: "run",
    claim: claimFor(triggerId, due, now, state, undefined, schedule),
  };
}

async function readClaim(): Promise<WindowClaim | undefined> {
  try {
    const claim = await readPrivateJson<WindowClaim>(CLAIM);
    validateClaim(claim);
    return claim;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

export async function runScheduledBackup(): Promise<void> {
  let claim: WindowClaim | undefined;
  try {
    await main(async (state) => {
      // The shared lock serializes capture; normal source activity stays online.
      const now = new Date();
      const schedule = await readPrivateJson<BackupSchedule>(
        ".private/backup-schedule.json",
      );
      const existing = await readClaim();
      const runtime = state as unknown as ScheduledRuntimeState | undefined;
      const decision = planScheduledClaim(schedule, now, runtime, existing);
      if (decision.action === "skip") {
        // Repair a crash between durable runtime completion and afterCycle
        // before releasing the shared lock or allowing the B2 launch gate.
        if (decision.completedClaim) {
          await writePrivateJson(CLAIM, decision.completedClaim);
        }
        if (
          [
            "BACKUP_RETRY_BLOCKED",
            "BACKUP_RETRY_METADATA_INVALID",
            "ACCEPTANCE_WINDOW_EXPIRED",
          ].includes(decision.reason)
        ) throw new Error(decision.reason);
        throw new Skipped(decision.reason);
      }
      claim = decision.claim;
      await writePrivateJson(CLAIM, claim);
      return {
        afterCycle: async (cycle) => {
          await writePrivateJson(CLAIM, {
            ...claim,
            status: cycle.phase === "complete" ? "complete" : "failed",
            updatedAtUtc: new Date().toISOString(),
          });
        },
        beforeCapture: async () => {
          const latest = await readPrivateJson<BackupSchedule>(
            ".private/backup-schedule.json",
          );
          // Every capture re-reads the latest approval immediately before
          // creation. A revoked, malformed, future or changed approval, a
          // changed weekly or one-time authority, or a closed one-time
          // acceptance window cannot authorize a stale capture. Weekly claims
          // stay due after the grace period; only the bounded acceptance
          // trigger must also still be active when OCI creation starts.
          assertCaptureStillAuthorized(latest, claim!, new Date());
        },
      };
    });
  } catch (error) {
    if (error instanceof Skipped) {
      console.log(error.message);
      return;
    }
    // Before the runtime starts a journal, leave the durable claim started.
    // Once it starts, afterCycle owns finalization under the shared lock.
    throw error;
  }
}

if (import.meta.main) {
  try {
    await runScheduledBackup();
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
