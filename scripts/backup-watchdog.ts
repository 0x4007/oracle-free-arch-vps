import {
  assessBackupWatchdog,
  type BackupSchedule,
  type BackupWatchdogState,
  validateSchedule,
} from "./backup-schedule.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";
import { notifyMac } from "./backup-mac-alert.ts";
import { readGate } from "./backblaze-controller-gate.ts";
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
    let state: { cycle: BackupWatchdogState } | undefined;
    try {
      state = await readPrivateJson(".private/backup-runtime.json");
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    oracleReport = {
      ...assessBackupWatchdog(state?.cycle, now, schedule),
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
    b2Report = {
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
