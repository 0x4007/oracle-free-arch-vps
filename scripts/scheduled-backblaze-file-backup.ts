/** Pi systemd entry point. Alerting does not belong to the VPS release closure. */
import {
  type BackblazeRunReport,
  runBackblazePiController,
} from "./backblaze-file-backup.ts";
import {
  type BackupAlertOutcome,
  backupAlertReason,
  backupRetentionAlert,
  notifyBackupAlerts,
  runWithBackupAlert,
} from "./backup-mac-alert.ts";
import {
  backblazeReportExplanation,
  reasonForBackblazeError,
} from "./backup-v2-report-reasons.ts";
import { B2_CATALOG_DAMAGED_ALERT } from "./backup-v2-retention-report.ts";

export function backblazeScheduledOutcome(
  report: BackblazeRunReport,
): BackupAlertOutcome {
  if (report.reportWriteError) return "B2_BACKUP_FAILED";
  const [status] = report.status.split(":", 1);
  if (status === B2_CATALOG_DAMAGED_ALERT) return "B2_BACKUP_FAILED";
  if (report.retention && backupRetentionAlert(report)) {
    return report.healthy ? "HEALTHY" : "DEFERRED";
  }
  if (report.healthy) return "HEALTHY";
  if (
    [
      "B2_BACKUP_IDLE",
      "REQUESTED",
      "WORKER_SETTLED",
      "VERIFY_REQUESTED",
      "VERIFY_SETTLED",
    ].includes(status)
  ) return "DEFERRED";
  if (status === "CANCELLATION_BLOCKED") return "B2_CANCELLATION_BLOCKED";
  if (status.startsWith("B2_RETENTION_")) return "B2_RETENTION_BLOCKED";
  if (status === "B2_SKIPPED") {
    return backupAlertReason(
      report.status.slice("B2_SKIPPED:".length),
      "B2_BACKUP_FAILED",
    );
  }
  return backupAlertReason(status, "B2_BACKUP_FAILED");
}

export async function runScheduledBackblaze(
  run = runBackblazePiController,
  notify = notifyBackupAlerts,
): Promise<BackblazeRunReport> {
  return await runWithBackupAlert(
    "backblaze-scheduled",
    run,
    backblazeScheduledOutcome,
    notify,
    console.error,
    (report) => {
      const retention = report.maintenance?.retention;
      const catalog = report.maintenance?.catalog;
      return (retention ? backupRetentionAlert(retention) : undefined) ??
        (catalog
          ? backupRetentionAlert(catalog, "backblaze-catalog-verification")
          : undefined);
    },
  );
}

if (import.meta.main) {
  try {
    const report = await runScheduledBackblaze();
    console.log(JSON.stringify(report));
    const outcome = backblazeScheduledOutcome(report);
    if (outcome !== "HEALTHY" && outcome !== "DEFERRED") Deno.exitCode = 1;
  } catch (error) {
    console.log(JSON.stringify({
      status: "B2_BACKUP_FAILED",
      healthy: false,
      observedAtUtc: new Date().toISOString(),
      ...backblazeReportExplanation(
        reasonForBackblazeError(error, "B2_BACKUP_STEP_FAILED"),
      ),
    }));
    Deno.exitCode = 1;
  }
}
