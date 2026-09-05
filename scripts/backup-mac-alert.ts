import { withBackupLock } from "./backup-lock.ts";
import { shellQuote } from "./backup-guest.ts";
import {
  type CommandRunner,
  defaultRunner,
  readPrivateJson,
  writePrivateJson,
} from "./oci.ts";

interface AlertRecord {
  id: string;
  status: string;
  healthy: boolean;
  observedAtUtc: string;
  attempts: number;
  deliveredAtUtc?: string;
}
interface AlertLedger {
  records: AlertRecord[];
}

/** Persist transitions before delivery. An unavailable Mac leaves a durable
 * pending record; the next watchdog invocation retries it without losing history.
 */
export async function notifyMac(
  report: { status: string; healthy: boolean; observedAtUtc: string },
  runner: CommandRunner = defaultRunner,
): Promise<
  {
    notificationConfigured: boolean;
    notificationSent: boolean;
    pendingAlerts: number;
  }
> {
  let config: { destination: string; approvedAtUtc: string };
  try {
    config = await readPrivateJson(".private/backup-notification.json");
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
    return {
      notificationConfigured: false,
      notificationSent: false,
      pendingAlerts: 0,
    };
  }
  if (
    config.destination !== "nv@m1.local" ||
    !Number.isFinite(Date.parse(config.approvedAtUtc))
  ) {
    throw new Error("Mac notification destination is not approved");
  }
  return await withBackupLock(".private/backup-alerts.lock", async () => {
    const path = ".private/backup-alerts.json";
    let ledger: AlertLedger;
    try {
      ledger = await readPrivateJson(path);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
      ledger = { records: [] };
    }
    const previous = ledger.records.at(-1);
    if (
      (!previous && !report.healthy) ||
      (previous && previous.status !== report.status)
    ) {
      ledger.records.push({ ...report, id: crypto.randomUUID(), attempts: 0 });
      await writePrivateJson(path, ledger);
    }
    let sent = false;
    for (
      const record of ledger.records.filter((item) => !item.deliveredAtUtc)
    ) {
      record.attempts++;
      await writePrivateJson(path, ledger);
      const message = `${
        record.status.replaceAll("_", " ").toLowerCase()
      } at ${record.observedAtUtc}. Records are stored on Pi.`;
      let delivered = false;
      try {
        const result = await runner("ssh", [
          "-o",
          "BatchMode=yes",
          "-o",
          "StrictHostKeyChecking=yes",
          "-o",
          "ConnectTimeout=10",
          "-o",
          "ServerAliveInterval=10",
          "-o",
          "ServerAliveCountMax=1",
          config.destination,
          "/opt/homebrew/bin/terminal-notifier -title 'VPS backups' -message " +
          shellQuote(message) + " -group " +
          shellQuote("vps-backup-" + record.id),
        ]);
        delivered = result.code === 0;
      } catch {
        // Keep pending if SSH cannot start or complete. Do not lose the event.
      }
      if (delivered) {
        record.deliveredAtUtc = new Date().toISOString();
        sent = true;
      }
      await writePrivateJson(path, ledger);
      if (!delivered) break;
    }
    return {
      notificationConfigured: true,
      notificationSent: sent,
      pendingAlerts: ledger.records.filter((item) =>
        !item.deliveredAtUtc
      ).length,
    };
  });
}
