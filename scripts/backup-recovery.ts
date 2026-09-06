import { withBackupLock } from "./backup-lock.ts";
import { readPrivateJson, redactOcid } from "./oci.ts";

/** Historical outage evidence is read-only. Online backup failures never start
 * production or replay a saved guest stop/recovery transaction.
 */
export async function recoverInterruptedBackup(): Promise<void> {
  await withBackupLock(".private/backup-controller.lock", async () => {
    let state: {
      cycle?: { mode?: string; phase?: string; recoveryStatus?: string };
      guest?: { restored?: boolean };
    };
    try {
      state = await readPrivateJson(".private/backup-runtime.json");
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
      console.log("NO_SOURCE_RECOVERY_NEEDED");
      return;
    }
    if (
      state.guest && state.guest.restored !== true ||
      state.cycle?.recoveryStatus === "needed" ||
      state.cycle?.recoveryStatus === "failed" ||
      state.cycle?.mode !== "online" &&
        state.cycle?.phase !== "complete"
    ) {
      throw new Error(
        "Legacy outage journal requires read-only diagnosis and explicit operator action; automatic recovery is disabled",
      );
    }
    console.log(
      "NO_AUTOMATIC_SOURCE_RECOVERY:ONLINE_BACKUPS_DO_NOT_STOP_SOURCE",
    );
  });
}
if (import.meta.main) {
  try {
    await recoverInterruptedBackup();
  } catch (error) {
    console.error(
      redactOcid(error instanceof Error ? error.message : String(error)),
    );
    Deno.exitCode = 1;
  }
}
