/** Pi systemd entry point. Alerting does not belong to the VPS release closure. */
import {
  type BackblazeRunReport,
  runBackblazePiController,
} from "./backblaze-file-backup.ts";
import {
  type BackupAlertOutcome,
  backupAlertReason,
  notifyBackupAlerts,
  runWithBackupAlert,
} from "./backup-mac-alert.ts";
import { redactOcid } from "./oci.ts";

export function backblazeScheduledOutcome(
  report: BackblazeRunReport,
): BackupAlertOutcome {
  if (report.healthy) return "HEALTHY";
  const [status] = report.status.split(":", 1);
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
  );
}

if (import.meta.main) {
  try {
    const report = await runScheduledBackblaze();
    console.log(JSON.stringify(report));
    const outcome = backblazeScheduledOutcome(report);
    if (outcome !== "HEALTHY" && outcome !== "DEFERRED") Deno.exitCode = 1;
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
