import {
  assessBackupWatchdog,
  type BackupSchedule,
  type BackupWatchdogState,
  validateSchedule,
} from "./backup-schedule.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";
import { notifyMac } from "./backup-mac-alert.ts";

export async function main(): Promise<void> {
  const now = new Date();
  let report: Record<string, unknown>;
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
    report = {
      ...assessBackupWatchdog(state?.cycle, now, schedule),
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  } catch (error) {
    report = {
      status: error instanceof Deno.errors.NotFound
        ? "SCHEDULE_NOT_CONFIGURED"
        : "WATCHDOG_CHECK_FAILED",
      healthy: false,
      observedAtUtc: now.toISOString(),
      notificationSent: false,
    };
  }
  await writePrivateJson(".private/reports/backup-watchdog.json", report);
  try {
    Object.assign(
      report,
      await notifyMac({
        status: String(report.status),
        healthy: report.healthy === true,
        observedAtUtc: String(report.observedAtUtc),
      }),
    );
  } catch {
    report.notificationError = "MAC_ALERT_RECORD_OR_DELIVERY_FAILED";
  }
  await writePrivateJson(".private/reports/backup-watchdog.json", report);
  console.log(JSON.stringify(report));
  if (
    !report.healthy || report.notificationError ||
    Number(report.pendingAlerts) > 0
  ) Deno.exitCode = 1;
}
if (import.meta.main) await main();
