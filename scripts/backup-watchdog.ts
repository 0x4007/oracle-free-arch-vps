import {
  assessBackupWatchdog,
  type BackupSchedule,
  type BackupWatchdogState,
  validateSchedule,
} from "./backup-schedule.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";
import { notifyMac } from "./backup-mac-alert.ts";
import { readGate } from "./backblaze-controller-gate.ts";
import type { OnlineBackupRetry } from "./online-backup-contract.ts";
import {
  assessBackblazeWatchdog,
  type ControllerState,
  type ObservedSource,
  realRemoteRunner,
  realRemoteSeam,
  validateControllerState,
} from "./backblaze-file-backup.ts";

export const B2_REPORT_PATH = ".private/reports/backblaze-file-backup.json";
export const ORACLE_REPORT_PATH = ".private/reports/backup-watchdog.json";
export const B2_STATE_PATH = ".private/file-backup/controller.json";

/** Retry is an unresolved backup failure, even when automatic recovery is due.
 * Keep its deadline and prior usable capture visible to the operator. */
export function assessOracleRetry(
  cycle: { phase: string; retry?: OnlineBackupRetry } | undefined,
  now: Date,
) {
  if (cycle?.phase !== "failed" || !cycle.retry) return undefined;
  const retry = cycle.retry;
  const next = Date.parse(retry.nextAttemptAtUtc);
  const first = Date.parse(retry.firstFailureAtUtc);
  const deadline = Date.parse(retry.deadlineAtUtc);
  if (
    ![next, first, deadline].every(Number.isFinite) ||
    first > now.getTime() || deadline <= first || next < first ||
    !Number.isInteger(retry.attempts) || retry.attempts < 1 ||
    !["retryable", "blocked"].includes(retry.disposition) ||
    !["planned", "backing-up", "pair-available", "source-accepted", "retiring"]
      .includes(retry.resumePhase)
  ) return { status: "INVALID_RETRY_STATE", healthy: false };
  return {
    status: retry.disposition === "blocked"
      ? "BACKUP_BLOCKED_RECONCILIATION"
      : now.getTime() >= next
      ? "BACKUP_RETRY_DUE"
      : next > deadline
      ? "BACKUP_RETRY_COOLDOWN"
      : "BACKUP_RETRY_WAITING",
    healthy: false,
    retryDisposition: retry.disposition,
    retryAttempts: retry.attempts,
    retryResumePhase: retry.resumePhase,
    nextAttemptAtUtc: retry.nextAttemptAtUtc,
    retryDeadlineAtUtc: retry.deadlineAtUtc,
  };
}

/** Dated boot evidence is independent of per-generation archive verification. */
export async function readBootDrillEvidence(path: string, now: Date) {
  try {
    const proof = await readPrivateJson<Record<string, unknown>>(path);
    const checks = proof.checks as Record<string, unknown> | undefined;
    const bootedAt = Date.parse(String(proof.bootedAtUtc));
    if (
      proof.status !== "RESTORE_DRILL_PROVED" || !Number.isFinite(bootedAt) ||
      bootedAt > now.getTime() || !checks ||
      !["ssh", "mounts", "bootParity", "preservedData", "desktop", "isolation"]
        .every((name) => checks[name] === true)
    ) {
      return { status: "BOOT_DRILL_EVIDENCE_INVALID", bootedAtUtc: null };
    }
    return {
      status: "RESTORE_DRILL_PROVED",
      bootedAtUtc: proof.bootedAtUtc,
      generation: typeof proof.generation === "string"
        ? proof.generation
        : null,
    };
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return { status: "BOOT_DRILL_UNPROVED", bootedAtUtc: null };
    }
    return { status: "BOOT_DRILL_EVIDENCE_UNREADABLE", bootedAtUtc: null };
  }
}

/** Preserve the existing Oracle assessment report and add the Backblaze
 * job/gate assessment; both notifications reuse the same bounded status
 * string and job UUID form. A delivery failure always remains visible.
 *
 * The Backblaze assessment includes a metadata-only live source observation
 * (unit properties plus the bounded status file) through the same source
 * observe command the controller uses, never inside the controller lock. A
 * failed observation is reported as unreachable so a fresh Pi polling time
 * can never stand in for a missing source heartbeat. */
async function observeLiveSource(
  jobId: string,
  unitName: string,
  now: Date,
): Promise<ObservedSource> {
  const observed = await realRemoteSeam(realRemoteRunner).observe(
    unitName,
    jobId,
  );
  return {
    observedAtUtc: now.toISOString(),
    reachable: observed.reachable,
    invocationId: observed.props.get("InvocationID") ?? null,
    status: observed.status,
  };
}

export async function main(): Promise<void> {
  const now = new Date();
  let oracleReport: Record<string, unknown>;
  try {
    const schedule = await readPrivateJson<BackupSchedule>(
      ".private/backup-schedule.json",
    );
    validateSchedule(schedule, now);
    let state: {
      lastSuccessfulCaptureAtUtc?: string;
      cycle: BackupWatchdogState & {
        captureIdentity?: { captureTimeUtc: string };
        retry?: OnlineBackupRetry;
      };
    } | undefined;
    try {
      state = await readPrivateJson(".private/backup-runtime.json");
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    oracleReport = {
      ...assessBackupWatchdog(state?.cycle, now, schedule),
      ...assessOracleRetry(state?.cycle, now),
      lastSuccessfulCaptureAtUtc: state?.cycle.phase === "complete"
        ? state.cycle.captureIdentity?.captureTimeUtc ??
          state.lastSuccessfulCaptureAtUtc ?? null
        : state?.lastSuccessfulCaptureAtUtc ?? null,
      lastArchiveVerificationAtUtc: null,
      lastBootDrill: await readBootDrillEvidence(
        ".private/reports/online-oracle-boot.json",
        now,
      ),
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  } catch (error) {
    oracleReport = {
      status: error instanceof Deno.errors.NotFound
        ? "SCHEDULE_NOT_CONFIGURED"
        : "WATCHDOG_CHECK_FAILED",
      healthy: false,
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  }
  let b2Report: Record<string, unknown>;
  try {
    let controllerState: ControllerState | undefined;
    try {
      controllerState = validateControllerState(
        await readPrivateJson(B2_STATE_PATH),
      );
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    const gate = await readGate();
    let source: ObservedSource | undefined;
    if (gate !== null && controllerState?.job !== undefined) {
      try {
        source = await observeLiveSource(
          gate.jobId,
          gate.unitName,
          now,
        );
      } catch {
        source = {
          observedAtUtc: now.toISOString(),
          reachable: false,
          invocationId: null,
          status: null,
        };
      }
    }
    const latestAccepted = controllerState?.catalog.slice().sort((a, b) =>
      Date.parse(b.acceptedAtUtc) - Date.parse(a.acceptedAtUtc)
    )[0];
    b2Report = {
      lastSuccessfulCaptureAtUtc: latestAccepted?.index.captureFinishedAtUtc ??
        null,
      lastArchiveVerificationAtUtc: latestAccepted?.receipt.verifiedAtUtc ??
        null,
      lastBootDrill: await readBootDrillEvidence(
        ".private/reports/backblaze-machine-boot.json",
        now,
      ),
      ...assessBackblazeWatchdog(controllerState, gate, now, source),
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  } catch (error) {
    b2Report = {
      status: "B2_WATCHDOG_CHECK_FAILED",
      healthy: false,
      observedAtUtc: now.toISOString(),
      notificationSent: false,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  await writePrivateJson(ORACLE_REPORT_PATH, oracleReport);
  await writePrivateJson(B2_REPORT_PATH, b2Report);
  // notifyMac keeps ONE last-status ledger: two separate per-report calls
  // alternate the last status every pass, so any existing alert makes two
  // identical hourly passes emit four notifications. One combined bounded
  // stable status carrying both assessment statuses yields one record per
  // transition; the single delivery outcome is shared by both preserved
  // individual reports and a delivery failure still stays visible on both.
  let delivery:
    | {
      notificationConfigured: boolean;
      notificationSent: boolean;
      pendingAlerts: number;
    }
    | undefined;
  try {
    delivery = await notifyMac({
      status: `B2:${String(b2Report.status)};ORACLE:${
        String(oracleReport.status)
      }`,
      healthy: oracleReport.healthy === true && b2Report.healthy === true,
      observedAtUtc: now.toISOString(),
    });
  } catch {
    for (const report of [b2Report, oracleReport]) {
      report.notificationError = "MAC_ALERT_RECORD_OR_DELIVERY_FAILED";
    }
  }
  if (delivery !== undefined) {
    for (const report of [b2Report, oracleReport]) {
      Object.assign(report, delivery);
    }
  }
  await writePrivateJson(ORACLE_REPORT_PATH, oracleReport);
  await writePrivateJson(B2_REPORT_PATH, b2Report);
  console.log(JSON.stringify({ oracle: oracleReport, b2: b2Report }));
  if (
    !oracleReport.healthy || !b2Report.healthy ||
    oracleReport.notificationError || b2Report.notificationError ||
    Number(oracleReport.pendingAlerts) > 0 ||
    Number(b2Report.pendingAlerts) > 0
  ) {
    Deno.exitCode = 1;
  }
}
if (import.meta.main) await main();
