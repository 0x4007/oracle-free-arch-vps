import { main } from "./backup-runtime.ts";
import {
  type BackupSchedule,
  currentWindow,
  duePeriod,
  periodAt,
  periodDate,
} from "./backup-schedule.ts";
import {
  ONLINE_RETRY_POLICY,
  type OnlineBackupRetry,
} from "./online-backup-contract.ts";
import { readPrivateJson, redactOcid, writePrivateJson } from "./oci.ts";

export type ScheduledClaimStatus = "started" | "complete" | "failed";

export interface WindowClaim {
  /** Kept as windowId for compatibility with existing private claim readers. */
  windowId: string;
  /** Weekly due-period identity, independent of an acceptance-window trigger. */
  periodId?: string;
  previousCycleSuffix?: string;
  status: ScheduledClaimStatus;
  updatedAtUtc: string;
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
  | { action: "skip"; reason: string }
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
}

function claimFor(
  triggerId: string,
  due: string,
  now: Date,
  state: ScheduledRuntimeState | undefined,
  existing: WindowClaim | undefined,
): WindowClaim {
  return {
    ...(existing ?? {}),
    windowId: existing?.windowId ?? triggerId,
    periodId: existing?.periodId ?? due,
    previousCycleSuffix: state?.cycle?.phase === "complete"
      ? state.cycle.suffix
      : existing?.previousCycleSuffix,
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
  if (cycleComplete && periodIsSatisfied(schedule, due, state)) {
    return { action: "skip", reason: "PERIOD_ALREADY_SATISFIED" };
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
      ),
    };
  }

  return {
    action: "run",
    claim: claimFor(triggerId, due, now, state, undefined),
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
      if (decision.action === "skip") throw new Skipped(decision.reason);
      claim = decision.claim;
      await writePrivateJson(CLAIM, claim);
      return {
        beforeCapture: async () => {
          const latest = await readPrivateJson<BackupSchedule>(
            ".private/backup-schedule.json",
          );
          // Weekly claims remain due after the grace period. Only the bounded
          // acceptance trigger must still be active when OCI creation starts.
          if (
            isAcceptanceWindowId(claim!.windowId) &&
            currentWindow(latest, new Date()) !== claim!.windowId
          ) {
            throw new Error("One-time scheduler acceptance window closed");
          }
        },
      };
    });
    if (claim) {
      await writePrivateJson(CLAIM, {
        ...claim,
        status: "complete",
        updatedAtUtc: new Date().toISOString(),
      });
    }
  } catch (error) {
    if (error instanceof Skipped) {
      console.log(error.message);
      return;
    }
    if (claim) {
      await writePrivateJson(CLAIM, {
        ...claim,
        status: "failed",
        updatedAtUtc: new Date().toISOString(),
      });
    }
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
