import { main } from "./backup-runtime.ts";
import { needsSourceRecovery } from "./weekly-backup.ts";
import { redactOcid } from "./oci.ts";

class NoRecoveryNeeded extends Error {}

/** The independent boot/periodic trigger never initiates a backup cycle. */
export async function recoverInterruptedBackup(): Promise<void> {
  try {
    await main((state) => {
      if (!state || !needsSourceRecovery(state.cycle)) {
        throw new NoRecoveryNeeded();
      }
      return Promise.resolve({ recoveryOnly: true });
    });
  } catch (error) {
    if (error instanceof NoRecoveryNeeded) {
      console.log("NO_SOURCE_RECOVERY_NEEDED");
      return;
    }
    // An aborted backup remains a failure even when its source recovered.
    // The next timer invocation reads the persisted result and does nothing.
    throw error;
  }
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
