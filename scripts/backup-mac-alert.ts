import { withBackupLock } from "./backup-lock.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";

const CONFIG_PATH = ".private/backup-notification.json";
const LEDGER_PATH = ".private/backup-alerts.json";
const LOCK_PATH = ".private/backup-alerts.lock";
export const DEFAULT_ALERT_DESTINATION = "https://ntfy.pavlovcik.com/alerts";
export const ALERT_REMINDER_MS = 6 * 60 * 60_000;
export const ALERT_RETRY_MS = 15 * 60_000;
const ALERT_DELIVERY_TIMEOUT_MS = 10_000;
const MAX_DELIVERIES_PER_RUN = 4;
const MAX_RECEIPT_BYTES = 8192;
const CLAIM_CUSTODY_OVERDUE = "SCHEDULED_CLAIM_CUSTODY_OVERDUE";

const streams = [
  "oracle-scheduled",
  "backblaze-scheduled",
  "oracle-watchdog",
  "backblaze-watchdog",
] as const;

const reasons = [
  "ACCEPTANCE_WINDOW_EXPIRED",
  "BACKUP_FAILED",
  "BACKUP_OVERDUE",
  "BACKUP_BLOCKED_RECONCILIATION",
  "BACKUP_RETRY_BLOCKED",
  "BACKUP_RETRY_COOLDOWN",
  "BACKUP_RETRY_DUE",
  "BACKUP_RETRY_METADATA_INVALID",
  "BACKUP_RETRY_WAITING",
  "BACKUP_STALLED",
  "B2_BACKUP_FAILED",
  "B2_BACKUP_GATE_HELD",
  "B2_BACKUP_GATE_UNKNOWN",
  "B2_BACKUP_MISSING",
  "B2_BACKUP_STALE",
  "B2_CANCELLATION_BLOCKED",
  "B2_PERIOD_MISSED",
  "B2_PROGRESS_BEHIND_SCHEDULE",
  "B2_PROGRESS_FAILED",
  "B2_PROGRESS_STALLED",
  "B2_RETENTION_BLOCKED",
  "B2_WATCHDOG_CHECK_FAILED",
  "SCHEDULE_CLAIM_RECONCILIATION_REQUIRED",
  "SCHEDULED_CLAIM_OWNER_LIVE",
  "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
  "SCHEDULED_CLAIM_CUSTODY_OVERDUE",
  "SCHEDULED_WINDOW_MISSED",
  "SCHEDULED_BACKUP_FAILED",
  "SCHEDULE_NOT_CONFIGURED",
  "WATCHDOG_CHECK_FAILED",
] as const;

type AlertStream = typeof streams[number];
type AlertReason = typeof reasons[number];
export type BackupAlertOutcome = AlertReason | "HEALTHY" | "DEFERRED";

export interface BackupAlertObservation {
  stream: AlertStream;
  outcome: BackupAlertOutcome;
}

interface AlertRecord {
  id: string;
  status: string;
  healthy: boolean;
  observedAtUtc: string;
  attempts: number;
  stream?: AlertStream;
  lastAttemptAtUtc?: string;
  deliveredAtUtc?: string;
}

interface AlertLedger {
  records: AlertRecord[];
}

export interface BackupAlertDelivery {
  notificationConfigured: boolean;
  notificationSent: boolean;
  pendingAlerts: number;
  notificationError?: "NTFY_DESTINATION_INVALID" | "NTFY_DELIVERY_FAILED";
}

type AlertNotifier = (
  observations: readonly BackupAlertObservation[],
) => Promise<BackupAlertDelivery>;

export function backupAlertReason(
  status: unknown,
  fallback: AlertReason,
): AlertReason {
  const code = typeof status === "string" ? status.split(":", 1)[0] : undefined;
  return reasons.find((reason) => reason === code) ?? fallback;
}

function isAlertStream(value: unknown): value is AlertStream {
  return streams.some((stream) => stream === value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

export function backupAlertDestination(value?: unknown): URL {
  if (value === undefined) return new URL(DEFAULT_ALERT_DESTINATION);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Backup notification destination format is invalid");
  }
  const { destination, approvedAtUtc } = value as {
    destination?: unknown;
    approvedAtUtc?: unknown;
  };
  if (destination === "nv@m1.local" && isTimestamp(approvedAtUtc)) {
    return new URL(DEFAULT_ALERT_DESTINATION);
  }
  if (typeof destination !== "string") {
    throw new Error("Backup notification destination is missing");
  }
  const endpoint = new URL(destination);
  if (
    endpoint.protocol !== "https:" || endpoint.username || endpoint.password ||
    endpoint.search || endpoint.hash ||
    !/^\/[A-Za-z0-9_-]{1,64}$/.test(endpoint.pathname)
  ) throw new Error("Backup notifications require an HTTPS ntfy topic URL");
  return endpoint;
}

async function readLedger(): Promise<AlertLedger> {
  let ledger: AlertLedger;
  try {
    ledger = await readPrivateJson(LEDGER_PATH);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
    return { records: [] };
  }
  if (
    !Array.isArray(ledger?.records) ||
    !ledger.records.every((record) =>
      record && typeof record.id === "string" &&
      typeof record.status === "string" &&
      typeof record.healthy === "boolean" &&
      isTimestamp(record.observedAtUtc) &&
      Number.isSafeInteger(record.attempts) && record.attempts >= 0 &&
      (record.stream === undefined || isAlertStream(record.stream)) &&
      (record.deliveredAtUtc === undefined ||
        isTimestamp(record.deliveredAtUtc)) &&
      (record.lastAttemptAtUtc === undefined ||
        isTimestamp(record.lastAttemptAtUtc))
    )
  ) throw new Error("Backup alert ledger is invalid");
  return ledger;
}

async function readDestination(): Promise<URL> {
  let value: unknown;
  try {
    value = await readPrivateJson(CONFIG_PATH);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  return backupAlertDestination(value);
}

function updateLedger(
  ledger: AlertLedger,
  observations: readonly BackupAlertObservation[],
  now: Date,
): boolean {
  let updated = false;
  for (const { stream, outcome } of observations) {
    if (outcome === "DEFERRED") continue;
    const previous = ledger.records.findLast((record) =>
      record.stream === stream
    );
    const healthy = outcome === "HEALTHY";
    const status = healthy
      ? "BACKUP_RECOVERED"
      : previous?.status === CLAIM_CUSTODY_OVERDUE
      ? CLAIM_CUSTODY_OVERDUE
      : outcome;
    const escalation = status === CLAIM_CUSTODY_OVERDUE &&
      previous?.status !== CLAIM_CUSTODY_OVERDUE;
    const due = !healthy && previous?.deliveredAtUtc !== undefined &&
      now.getTime() - Date.parse(previous.deliveredAtUtc) >= ALERT_REMINDER_MS;
    const transition = previous ? previous.healthy !== healthy : !healthy;
    if (!transition && !escalation && !due) continue;
    ledger.records.push({
      id: crypto.randomUUID(),
      stream,
      status,
      healthy,
      observedAtUtc: now.toISOString(),
      attempts: 0,
    });
    updated = true;
  }
  return updated;
}

async function publishAlert(
  destination: URL,
  record: AlertRecord,
  request: typeof fetch,
): Promise<boolean> {
  const service = record.stream ?? "backup-watchdog";
  const reason = record.healthy
    ? "BACKUP_RECOVERED"
    : backupAlertReason(record.status, "WATCHDOG_CHECK_FAILED");
  const timestamp = new Date(record.observedAtUtc).toISOString();
  const message = `${service} ${reason} ${timestamp}`;
  const response = await request(destination, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(ALERT_DELIVERY_TIMEOUT_MS),
    headers: { Title: "VPS backups", "Content-Type": "text/plain" },
    body: message,
  });
  const reader = response.body?.getReader();
  if (!reader) return false;
  try {
    if (!response.ok) return false;
    const decoder = new TextDecoder();
    let size = 0, receipt = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_RECEIPT_BYTES) return false;
      receipt += decoder.decode(value, { stream: true });
    }
    const value = JSON.parse(receipt + decoder.decode());
    return value?.event === "message" &&
      value.topic === destination.pathname.slice(1) &&
      typeof value.id === "string" && value.id.length > 0 &&
      value.message === message;
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Preserve alerts before reading delivery configuration or contacting ntfy.
 * All existing scheduled invocations can retry undelivered records. */
export async function notifyBackupAlerts(
  observations: readonly BackupAlertObservation[],
  { now = new Date(), request = fetch }: {
    now?: Date;
    request?: typeof fetch;
  } = {},
): Promise<BackupAlertDelivery> {
  return await withBackupLock(LOCK_PATH, async () => {
    const ledger = await readLedger();
    if (updateLedger(ledger, observations, now)) {
      await writePrivateJson(LEDGER_PATH, ledger);
    }
    const pending = ledger.records.filter((record) => !record.deliveredAtUtc);
    let destination: URL;
    try {
      destination = await readDestination();
    } catch {
      return {
        notificationConfigured: false,
        notificationSent: false,
        pendingAlerts: pending.length,
        notificationError: "NTFY_DESTINATION_INVALID",
      };
    }
    const result: BackupAlertDelivery = {
      notificationConfigured: true,
      notificationSent: false,
      pendingAlerts: pending.length,
    };
    const blockedStreams = new Set<AlertStream | undefined>();
    let attempts = 0;
    for (const record of pending) {
      if (attempts >= MAX_DELIVERIES_PER_RUN) break;
      if (blockedStreams.has(record.stream)) continue;
      const elapsed = record.lastAttemptAtUtc === undefined
        ? Infinity
        : now.getTime() - Date.parse(record.lastAttemptAtUtc);
      if (elapsed >= 0 && elapsed < ALERT_RETRY_MS) {
        blockedStreams.add(record.stream);
        continue;
      }
      attempts++;
      record.attempts++;
      record.lastAttemptAtUtc = now.toISOString();
      await writePrivateJson(LEDGER_PATH, ledger);
      const delivered = await publishAlert(destination, record, request).catch(
        () => false,
      );
      if (!delivered) {
        result.notificationError = "NTFY_DELIVERY_FAILED";
        blockedStreams.add(record.stream);
        continue;
      }
      record.deliveredAtUtc = now.toISOString();
      await writePrivateJson(LEDGER_PATH, ledger);
      result.notificationSent = true;
      result.pendingAlerts--;
    }
    return result;
  });
}

async function reportScheduledObservation(
  observation: BackupAlertObservation,
  notify: AlertNotifier,
  log: (message: string) => void,
): Promise<void> {
  try {
    const delivery = await notify([observation]);
    if (delivery.notificationError) log(delivery.notificationError);
  } catch {
    log("BACKUP_ALERT_RECORD_FAILED");
  }
}

/** Report each scheduled entry point outcome after releasing its controller
 * lock. Preserve the controller's exception even if alerting also fails. */
export async function runWithBackupAlert<T>(
  stream: "oracle-scheduled" | "backblaze-scheduled",
  operation: () => Promise<T>,
  classify: (result: T) => BackupAlertOutcome,
  notify: AlertNotifier = notifyBackupAlerts,
  log: (message: string) => void = console.error,
): Promise<T> {
  let result: T, outcome: BackupAlertOutcome;
  try {
    result = await operation();
    outcome = classify(result);
  } catch (error) {
    const status = error instanceof Error ? error.message : undefined;
    await reportScheduledObservation(
      {
        stream,
        outcome: backupAlertReason(status, "SCHEDULED_BACKUP_FAILED"),
      },
      notify,
      log,
    );
    throw error;
  }
  await reportScheduledObservation({ stream, outcome }, notify, log);
  return result;
}

if (import.meta.main) {
  const [stream] = Deno.args;
  if (
    Deno.args.length !== 1 ||
    (stream !== "oracle-scheduled" && stream !== "backblaze-scheduled")
  ) {
    throw new Error("Scheduled backup alert stream is invalid");
  }
  await reportScheduledObservation(
    { stream, outcome: "SCHEDULED_BACKUP_FAILED" },
    notifyBackupAlerts,
    console.error,
  );
}
