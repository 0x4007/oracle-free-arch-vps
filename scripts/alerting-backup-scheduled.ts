/** Pi systemd entry point. Alerting stays outside the immutable B2 closure. */
import { notifyBackupAlerts, runWithBackupAlert } from "./backup-mac-alert.ts";
import { runScheduledBackup } from "./backup-scheduled.ts";
import { redactOcid } from "./oci.ts";

export async function runAlertingScheduledBackup(
  run = runScheduledBackup,
  notify = notifyBackupAlerts,
): ReturnType<typeof runScheduledBackup> {
  return await runWithBackupAlert(
    "oracle-scheduled",
    run,
    (outcome) => outcome,
    notify,
  );
}

if (import.meta.main) {
  try {
    await runAlertingScheduledBackup();
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
