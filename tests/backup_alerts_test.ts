import {
  ALERT_REMINDER_MS,
  ALERT_RETRY_MS,
  backupAlertDestination,
  type BackupAlertObservation,
  backupRetentionAlert,
  DEFAULT_ALERT_DESTINATION,
  notifyBackupAlerts,
  runWithBackupAlert,
} from "../scripts/backup-mac-alert.ts";
import { runAlertingScheduledBackup } from "../scripts/alerting-backup-scheduled.ts";
import { watchdogAlertOutcome } from "../scripts/backup-watchdog.ts";
import { readPrivateJson, writePrivateJson } from "../scripts/oci.ts";
import { runScheduledBackblaze } from "../scripts/scheduled-backblaze-file-backup.ts";
import {
  canUseBackupTestFixtures,
  withBackupTestFixture,
} from "./backup-test-fixtures.ts";

import {
  B2_CATALOG_DAMAGED_ALERT,
  B2_RETENTION_CATEGORIES,
} from "../scripts/backup-v2-retention-report.ts";
import type { BackupV2RetentionSummary } from "../scripts/backup-v2-retention.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

const started = Date.parse("2026-11-17T20:51:03Z");
const at = (offset = 0) => new Date(started + offset);
const oracleFailure = {
  stream: "oracle-scheduled",
  outcome: "SCHEDULED_BACKUP_FAILED",
} as const;
const b2Failure = {
  stream: "backblaze-scheduled",
  outcome: "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
} as const;

function receipt(input: string | URL | Request, init?: RequestInit) {
  const url = new URL(String(input));
  assert(init?.method === "POST" && init.redirect === "error" && init.signal);
  assert(url.protocol === "https:");
  return Response.json({
    id: "received-fixture",
    event: "message",
    topic: url.pathname.slice(1),
    message: init.body,
  });
}

async function withLedgerFixture(
  work: (
    notify: typeof notifyBackupAlerts,
    ledgerPath: string,
    configPath: string,
  ) => Promise<void>,
) {
  await withBackupTestFixture("alert-ledger", (stateDirectory) =>
    work(
      (observations, options) =>
        notifyBackupAlerts(observations, { ...options, stateDirectory }),
      `${stateDirectory}/backup-alerts.json`,
      `${stateDirectory}/backup-notification.json`,
    ));
}

Deno.test("backup notifications migrate the old Mac approval and accept an HTTPS topic override", () => {
  assert(backupAlertDestination().href === DEFAULT_ALERT_DESTINATION);
  assert(
    backupAlertDestination({
      destination: "nv@m1.local",
      approvedAtUtc: at().toISOString(),
    }).href === DEFAULT_ALERT_DESTINATION,
  );
  assert(
    backupAlertDestination({ destination: "https://ntfy.example/ops" }).href ===
      "https://ntfy.example/ops",
  );
  for (
    const destination of [
      "nv@m1.local",
      "http://ntfy.example/ops",
      "https://example:password@ntfy.example/ops",
      "https://ntfy.example/ops?anything=yes",
      "https://ntfy.example/ops#otherwise",
      "https://ntfy.example/ops/topic",
      "https://ntfy.example/",
    ]
  ) {
    let failed = false;
    try {
      backupAlertDestination({ destination });
    } catch {
      failed = true;
    }
    assert(failed);
  }
});

Deno.test({
  name:
    "first refusal, reminders and recovery are independent for every alert stream",
  ignore: !canUseBackupTestFixtures,
  fn: () =>
    withLedgerFixture(async (notify) => {
      const messages: string[] = [];
      const request: typeof fetch = (input, init) => {
        messages.push(String(init?.body));
        return Promise.resolve(receipt(input, init));
      };
      const first = await notify([oracleFailure, b2Failure], {
        now: at(),
        request,
      });
      assert(first.notificationSent && first.pendingAlerts === 0);
      assert(messages.splice(0).length === 2);
      await notify(
        [
          b2Failure,
          { ...oracleFailure, outcome: "BACKUP_RETRY_BLOCKED" },
        ],
        { now: at(ALERT_REMINDER_MS - 1), request },
      );
      assert(messages.splice(0).length === 0);
      await notify([
        oracleFailure,
        { ...b2Failure, outcome: "DEFERRED" },
        { stream: "oracle-watchdog", outcome: "SCHEDULED_WINDOW_MISSED" },
      ], { now: at(ALERT_REMINDER_MS), request });
      const reminders = messages.splice(0);
      assert(reminders.length === 2);
      assert(
        reminders[0].startsWith("oracle-scheduled SCHEDULED_BACKUP_FAILED"),
      );
      assert(
        reminders[1].startsWith("oracle-watchdog SCHEDULED_WINDOW_MISSED"),
      );
      await notify([
        { ...oracleFailure, outcome: "HEALTHY" },
        b2Failure,
      ], {
        now: at(ALERT_REMINDER_MS + ALERT_RETRY_MS),
        request,
      });
      const recovery = messages.splice(0);
      assert(recovery.length === 2);
      assert(recovery[0].startsWith("oracle-scheduled BACKUP_RECOVERED"));
      assert(recovery[1].startsWith("backblaze-scheduled SCHEDULED_CLAIM"));
      await notify([oracleFailure], {
        now: at(ALERT_REMINDER_MS + 2 * ALERT_RETRY_MS),
        request,
      });
      assert(Number(messages.length) === 1);
      assert(
        messages[0].startsWith("oracle-scheduled SCHEDULED_BACKUP_FAILED"),
      );
    }),
});

Deno.test({
  name:
    "legacy alerts and new refusals stay pending until ntfy confirms delivery",
  ignore: !canUseBackupTestFixtures,
  fn: () =>
    withLedgerFixture(async (notify, ledgerPath, configPath) => {
      await writePrivateJson(ledgerPath, {
        records: [{
          id: "legacy-row",
          healthy: false,
          status: "B2:job-redact-this;ORACLE:retained-source-reference",
          observedAtUtc: at(-1000).toISOString(),
          attempts: 1,
        }],
      });
      await writePrivateJson(configPath, {
        destination: "nv@m1.local",
        approvedAtUtc: at(-1000).toISOString(),
      });
      const messages: string[] = [];
      const request: typeof fetch = (input, init) => {
        messages.push(String(init?.body));
        assert(String(input) === DEFAULT_ALERT_DESTINATION);
        return Promise.resolve(new Response("unavailable", { status: 503 }));
      };
      const failed = await notify([], { now: at(), request });
      assert(failed.notificationError === "NTFY_DELIVERY_FAILED");
      assert(failed.pendingAlerts === 1 && messages.length === 1);
      assert(!messages[0].includes("redact-this"));
      messages.splice(0);
      const first = await notify([oracleFailure], {
        now: at(1),
        request: (input, init) => {
          messages.push(String(init?.body));
          return Promise.resolve(receipt(input, init));
        },
      });
      assert(first.notificationSent && first.pendingAlerts === 1);
      assert(Number(messages.length) === 1);
      assert(
        messages[0].startsWith("oracle-scheduled SCHEDULED_BACKUP_FAILED"),
      );
      messages.splice(0);

      const malformed = await notify([], {
        now: at(ALERT_RETRY_MS),
        request: () => Promise.resolve(Response.json({ event: "message" })),
      });
      assert(malformed.notificationError === "NTFY_DELIVERY_FAILED");
      assert(malformed.pendingAlerts === 1);

      await writePrivateJson(configPath, {
        destination: "http://ntfy.example/ops",
      });
      const invalid = await notify([], {
        now: at(2 * ALERT_RETRY_MS),
        request,
      });
      assert(invalid.notificationError === "NTFY_DESTINATION_INVALID");
      assert(!invalid.notificationConfigured && invalid.pendingAlerts === 1);

      await writePrivateJson(configPath, {
        destination: "https://ntfy.example/ops",
      });
      const recovered = await notify([], {
        now: at(2 * ALERT_RETRY_MS),
        request: (input, init) => {
          assert(String(input) === "https://ntfy.example/ops");
          messages.push(String(init?.body));
          return Promise.resolve(receipt(input, init));
        },
      });
      assert(recovered.notificationSent && recovered.pendingAlerts === 0);
      assert(
        messages.splice(0).every((message) => !message.includes("redact")),
      );
      const ledger = await readPrivateJson<{
        records: Record<string, unknown>[];
      }>(ledgerPath);
      assert(ledger.records.length === 2);
      assert(ledger.records.every((record) => !!record.deliveredAtUtc));
      assert(ledger.records[0].attempts === 4);
    }),
});

Deno.test({
  name:
    "overdue claim escalation is immediate and remains deduplicated across fallback failures",
  ignore: !canUseBackupTestFixtures,
  fn: () =>
    withLedgerFixture(async (notify) => {
      const messages: string[] = [];
      const request: typeof fetch = (input, init) => {
        messages.push(String(init?.body));
        return Promise.resolve(receipt(input, init));
      };
      const overdue = {
        ...b2Failure,
        outcome: "SCHEDULED_CLAIM_CUSTODY_OVERDUE",
      } as const;
      await notify([b2Failure], { now: at(), request });
      await notify([overdue], { now: at(1), request });
      assert(messages.length === 2);
      assert(messages[1].includes("SCHEDULED_CLAIM_CUSTODY_OVERDUE"));
      await notify([overdue], { now: at(2), request });
      assert(messages.splice(0).length === 2);
      await notify(
        [{ ...b2Failure, outcome: "SCHEDULED_BACKUP_FAILED" }],
        { now: at(1 + ALERT_REMINDER_MS), request },
      );
      assert(Number(messages.length) === 1);
      assert(messages[0].includes("SCHEDULED_CLAIM_CUSTODY_OVERDUE"));
      await notify([overdue], {
        now: at(2 + ALERT_REMINDER_MS),
        request,
      });
      assert(Number(messages.length) === 1);
    }),
});

Deno.test("scheduled entry points alert on thrown refusal and returned blocked reports", async () => {
  const observations: BackupAlertObservation[] = [];
  const notify = (events: readonly BackupAlertObservation[]) => {
    observations.push(...events);
    return Promise.resolve({
      notificationConfigured: true,
      notificationSent: true,
      pendingAlerts: 0,
    });
  };
  const earlyFailure = new Error("fixture information must stay private");
  let failure: unknown;
  try {
    await runAlertingScheduledBackup(
      () => Promise.reject(earlyFailure),
      notify,
    );
  } catch (error) {
    failure = error;
  }
  assert(failure === earlyFailure);
  assert(observations[0].stream === "oracle-scheduled");
  assert(observations[0].outcome === "SCHEDULED_BACKUP_FAILED");
  await runAlertingScheduledBackup(() => Promise.resolve("DEFERRED"), notify);
  assert(observations[1].outcome === "DEFERRED");
  const blocked = {
    healthy: false,
    status: "B2_SKIPPED:SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE",
    observedAtUtc: at().toISOString(),
  };
  assert(
    await runScheduledBackblaze(() => Promise.resolve(blocked), notify) ===
      blocked,
  );
  assert(observations[2].stream === "backblaze-scheduled");
  assert(observations[2].outcome === "SCHEDULED_CLAIM_CUSTODY_UNDECIDABLE");

  for (
    const [status, healthy, expected] of [
      ["WORKER", true, "HEALTHY"],
      ["COMPLETE", true, "HEALTHY"],
      ["VERIFY_REQUESTED", false, "DEFERRED"],
      ["CANCELLATION_BLOCKED", false, "B2_CANCELLATION_BLOCKED"],
      ["B2_RETENTION_EXECUTE_PARTIAL", false, "B2_RETENTION_BLOCKED"],
    ] as const
  ) {
    await runScheduledBackblaze(
      () => Promise.resolve({ ...blocked, status, healthy }),
      notify,
    );
    assert(observations.at(-1)?.outcome === expected);
  }

  await runScheduledBackblaze(
    () =>
      Promise.resolve({
        status: "B2_BACKUP_CURRENT:job-fixture",
        healthy: true,
        observedAtUtc: at().toISOString(),
        maintenance: {
          retention: {
            status: "B2_RETENTION_PLAN_BLOCKED",
            healthy: false,
            observedAtUtc: at().toISOString(),
            reason: "SOURCE_STATUS_CANCELLATION_BLOCKED",
            retentionTransactionId: "61d5c174-45ff-4d7d-baec-57d06da81e89",
          },
        },
      }),
    notify,
  );
  assert(observations.at(-2)?.stream === "backblaze-scheduled");
  assert(observations.at(-2)?.outcome === "HEALTHY");
  assert(observations.at(-1)?.stream === "backblaze-retention");
  assert(observations.at(-1)?.outcome === "B2_RETENTION_BLOCKED");
  assert(
    observations.at(-1)?.reportReason === "SOURCE_STATUS_CANCELLATION_BLOCKED",
  );
});

Deno.test("watchdog distinguishes normal progress from current acceptance", () => {
  for (
    const [status, healthy, expected] of [
      ["ACCEPTED_BACKUP_CURRENT", true, "HEALTHY"],
      ["BACKUP_IN_PROGRESS", true, "DEFERRED"],
      ["B2_BACKUP_ACTIVE:job-fixture", true, "DEFERRED"],
      ["B2_BACKUP_PENDING:job-fixture", false, "DEFERRED"],
      ["B2_BACKUP_CURRENT:job-fixture", true, "HEALTHY"],
      ["SCHEDULED_WINDOW_MISSED", false, "SCHEDULED_WINDOW_MISSED"],
      ["B2_PROGRESS_STALLED:job-fixture", false, "B2_PROGRESS_STALLED"],
    ] as const
  ) {
    assert(
      watchdogAlertOutcome({ status, healthy }, "WATCHDOG_CHECK_FAILED") ===
        expected,
    );
  }
});

Deno.test("an alert recording failure leaves the original backup failure intact", async () => {
  const original = new Error("original");
  const logged: string[] = [];
  let caught: unknown;
  try {
    await runWithBackupAlert(
      "oracle-scheduled",
      () => Promise.reject(original),
      () => "HEALTHY",
      () =>
        Promise.reject(new Error("transport error may contain private data")),
      (message) => logged.push(message),
    );
  } catch (error) {
    caught = error;
  }
  assert(caught === original);
  assert(logged.length === 1 && logged[0] === "BACKUP_ALERT_RECORD_FAILED");
});

Deno.test({
  name:
    "damage alerts name the verified generation at urgent priority and deduplicate by transaction",
  ignore: !canUseBackupTestFixtures,
  async fn() {
    await withLedgerFixture(async (notify) => {
      const generation = "generation-61d5c174-45ff-4d7d-baec-57d06da81e89";
      const damaged = [
        generation,
        ...Array.from(
          { length: 17 },
          (_, index) =>
            `generation-00000000-0000-4000-8000-${
              String(index).padStart(12, "0")
            }`,
        ),
      ];
      const categories = Object.fromEntries(
        B2_RETENTION_CATEGORIES.map((
          name,
        ) => [name, {
          objects: 1,
          bytes: 10,
          plannedObjects: 0,
          plannedBytes: 0,
        }]),
      ) as BackupV2RetentionSummary["categories"];
      const report = backupRetentionAlert({
        status: B2_CATALOG_DAMAGED_ALERT,
        retentionTransactionId: "61d5c174-45ff-4d7d-baec-57d06da81e89",
        retention: {
          keptGenerations: 1,
          damagedCaptureIds: damaged,
          bucketBytes: 100,
          categories,
          blockReason: "DAMAGED_ACCEPTED_GENERATION",
          deletedObjects: 0,
          deletedBytes: 0,
          reconciledAbsentObjects: 0,
          reconciledAbsentBytes: 0,
        },
      });
      assert(report);
      const messages: string[] = [];
      const request: typeof fetch = (input, init) => {
        assert(new Headers(init?.headers).get("Priority") === "5");
        const body = String(init?.body);
        messages.push(body);
        assert(body.includes("Kept 1 generations"));
        return Promise.resolve(receipt(input, init));
      };
      await notify([report], { now: at(), request });
      await notify([report], { now: at(1000), request });
      assert(messages.length === 2);
      assert(
        damaged.every((id) =>
          messages.filter((message) => message.includes(id)).length === 1
        ),
      );
    });
  },
});
