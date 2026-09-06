import { main } from "./backup-runtime.ts";
import { type BackupSchedule, currentWindow } from "./backup-schedule.ts";
import { readPrivateJson, redactOcid, writePrivateJson } from "./oci.ts";

interface WindowClaim {
  windowId: string;
  previousCycleSuffix?: string;
  status: "started" | "complete" | "failed";
  updatedAtUtc: string;
}
const CLAIM = ".private/backup-scheduled-window.json";
class Skipped extends Error {}

export async function runScheduledBackup(): Promise<void> {
  let claim: WindowClaim | undefined;
  try {
    await main(async (state) => {
      // The shared lock serializes capture; normal source activity stays online.
      const now = new Date();
      const schedule = await readPrivateJson<BackupSchedule>(
        ".private/backup-schedule.json",
      );
      const windowId = currentWindow(schedule, now);
      if (!windowId) throw new Skipped("OUTSIDE_APPROVED_WINDOW");
      let existing: WindowClaim | undefined;
      try {
        existing = await readPrivateJson<WindowClaim>(CLAIM);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
      }
      if (existing?.windowId === windowId) {
        if (!["started", "complete", "failed"].includes(existing.status)) {
          throw new Error("Scheduled claim has an unknown status");
        }
        if (existing.status !== "started") {
          throw new Skipped("WINDOW_ALREADY_ATTEMPTED");
        }
        if (
          state?.cycle.phase === "complete" &&
          state.cycle.suffix !== existing.previousCycleSuffix
        ) {
          await writePrivateJson(CLAIM, {
            ...existing,
            status: "complete",
            updatedAtUtc: now.toISOString(),
          });
          throw new Skipped("WINDOW_ALREADY_COMPLETED");
        }
        claim = existing;
      } else {
        claim = {
          windowId,
          previousCycleSuffix: state?.cycle.phase === "complete"
            ? state.cycle.suffix
            : undefined,
          status: "started",
          updatedAtUtc: now.toISOString(),
        };
        await writePrivateJson(CLAIM, claim);
      }
      return {
        beforeCapture: async () => {
          const latest = await readPrivateJson<BackupSchedule>(
            ".private/backup-schedule.json",
          );
          if (currentWindow(latest, new Date()) !== windowId) {
            throw new Error(
              "Backup capture window closed before creation",
            );
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
