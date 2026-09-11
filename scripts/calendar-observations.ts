/** Dated read-only observations. A late trigger records current reality, never
 * backdated coverage, successful backup history or a finalized billing claim. */
import { withBackupLock } from "./backup-lock.ts";
import {
  type BackupInventoryConfig,
  readBackupInventory,
} from "./oci-backup-inventory.ts";
import { validateCatalogEntry } from "./backblaze-file-backup.ts";
import { readGuestTelemetrySummary } from "./guest-telemetry.ts";
import {
  type CommandRunner,
  dataObject,
  defaultRunner,
  type JsonRecord,
  readPrivateJson,
  runJson,
  writePrivateJson,
} from "./oci.ts";
import { periodAt } from "./backup-schedule.ts";

export const OBSERVATION_DATES = [
  "2026-09-13T06:00:00.000Z",
  "2026-09-18T06:00:00.000Z",
  "2026-09-20T06:00:00.000Z",
  "2026-09-27T06:00:00.000Z",
  "2026-09-30T06:00:00.000Z",
  "2026-10-02T06:00:00.000Z",
] as const;
export function observationTiming(now: Date) {
  if (!Number.isFinite(now.getTime())) throw Error("Invalid observation time");
  const due = OBSERVATION_DATES.filter((date) =>
    Date.parse(date) <= now.getTime()
  ).at(-1);
  return {
    observedAtUtc: now.toISOString(),
    latestDueAtUtc: due ?? null,
    mode: !due
      ? "baseline"
      : now.getTime() - Date.parse(due) <= 3 * 3600000
      ? "scheduled-window"
      : "late-current-observation",
    historicalStateReconstructed: false,
  };
}
export function summarizePostedCosts(response: unknown) {
  const data = dataObject(dataObject({ data: response }));
  if (!Array.isArray(data.items)) {
    throw Error("Cost response has no complete item list");
  }
  let amount = 0;
  const days = new Set<string>();
  for (const item of data.items) {
    if (
      !item || item.currency !== "USD" || item["is-forecast"] !== false ||
      typeof item["computed-amount"] !== "number" ||
      !Number.isFinite(item["computed-amount"]) ||
      !Number.isFinite(Date.parse(item["time-usage-started"])) ||
      !Number.isFinite(Date.parse(item["time-usage-ended"]))
    ) throw Error("Cost item has unknown currency, amount or provenance");
    amount += item["computed-amount"];
    days.add(item["time-usage-started"]);
  }
  if (!Number.isFinite(amount)) {
    throw Error("Cost sum is outside its numeric bound");
  }
  return {
    postedAmountUsd: amount,
    items: data.items.length,
    reportedPeriods: days.size,
    status: data.items.length ? "provisional-cost-reported" : "no-cost-data",
    finalizedStatementProved: false,
    zeroBillProved: false,
  };
}
export function summarizeWeeklyCatalog(values: unknown[], now: Date) {
  const entries = values.map(validateCatalogEntry);
  if (new Set(entries.map((e) => e.index.generation)).size !== entries.length) {
    throw Error("Duplicate retained generation");
  }
  const schedule = {
    approvedAtUtc: "2026-09-07T22:13:00.000Z",
    timeZone: "America/New_York",
    weekday: 0,
    hour: 0,
    minute: 5,
    windowMinutes: 120,
  };
  const records = entries.map((e) => {
    if (
      Date.parse(e.index.captureStartedAtUtc) > now.getTime() ||
      Date.parse(e.acceptedAtUtc) > now.getTime()
    ) throw Error("Future catalog evidence");
    return {
      generation: e.index.generation,
      captureStartedAtUtc: e.index.captureStartedAtUtc,
      acceptedAtUtc: e.acceptedAtUtc,
      civilPeriod: periodAt(schedule, new Date(e.index.captureStartedAtUtc)),
      indexedCiphertextBytes: e.index.archives.reduce(
        (n, a) => n + a.bytes,
        0,
      ),
    };
  });
  return {
    generations: records,
    retainedGenerationCount: records.length,
    distinctCapturePeriods: new Set(records.map((r) => r.civilPeriod)).size,
    automaticRunProvenanceProved: false,
    fourNaturallyAccumulatedWeeksProved: false,
  };
}

export async function readPostedCosts(
  query: (args: string[]) => Promise<JsonRecord>,
  args: string[],
) {
  const responses: JsonRecord[] = [];
  const items: unknown[] = [];
  const seen = new Set<string>();
  let page: string | undefined;
  try {
    // Bound provider time within the existing 15-minute observer service.
    for (let count = 0; count < 5; count++) {
      const response = await query([
        ...args,
        ...(page ? ["--page", page] : []),
      ]);
      responses.push(response);
      summarizePostedCosts(response);
      items.push(...dataObject(response).items as unknown[]);
      const next = response["opc-next-page"];
      if (next === undefined || next === null || next === "") {
        return {
          responses,
          summary: summarizePostedCosts({ data: { items } }),
          collectionComplete: true,
        };
      }
      if (typeof next !== "string" || seen.has(next)) {
        throw Error("Invalid cost continuation");
      }
      seen.add(next);
      page = next;
    }
    throw Error("Cost page bound exhausted");
  } catch {
    return {
      responses,
      summary: null,
      collectionComplete: false,
    };
  }
}

export function observationFailure(value: unknown): string | undefined {
  if (value && typeof value === "object") {
    if ("collectionComplete" in value && value.collectionComplete === false) {
      return "Cost collection incomplete; inspect retained pages";
    }
    if ("status" in value && value.status === "unavailable") {
      return "Observation surface unavailable; inspect retained coverage";
    }
  }
}

export async function main(runner: CommandRunner = defaultRunner) {
  await withBackupLock(".private/calendar-observations.lock", async () => {
    const started = new Date();
    const config = await readPrivateJson<BackupInventoryConfig>(
      ".private/backup-controller.json",
    );
    const release = await readPrivateJson<{ sourceRevision: string }>(
      ".private/reports/pi-session-deployment.json",
    );
    const queryStart = new Date(
      Date.UTC(started.getUTCFullYear(), started.getUTCMonth(), 1),
    );
    const queryEnd = new Date(
      Date.UTC(
        started.getUTCFullYear(),
        started.getUTCMonth(),
        started.getUTCDate() + 1,
      ),
    );
    const query = (args: string[]) =>
      runJson(config.ociCliPath, [
        "--profile",
        config.ociProfile,
        "--region",
        config.source.region,
        "--no-retry",
        "--connection-timeout",
        "10",
        "--read-timeout",
        "60",
        ...args,
      ], runner);
    const observations: Record<string, unknown> = {};
    const failures: Record<string, string> = {};
    const observe = async (name: string, read: () => Promise<unknown>) => {
      try {
        observations[name] = await read();
        const failure = observationFailure(observations[name]);
        if (failure) failures[name] = failure;
      } catch (error) {
        failures[name] = error instanceof Error
          ? error.message.slice(0, 4096)
          : "Observation failed; no successful evidence inferred";
      }
    };
    // Keep Pi and provider load bounded: all network reads are serial.
    await observe("inventory", () => readBackupInventory(config, runner));
    await observe("subscription", async () => {
      const list = dataObject(
        await query([
          "organizations",
          "subscription",
          "list",
          "--compartment-id",
          config.tenancyId,
          "--all",
        ]),
      );
      if (
        !Array.isArray(list.items) || list.items.length !== 1 ||
        typeof list.items[0]?.id !== "string"
      ) throw Error("Subscription identity ambiguous");
      const value = dataObject(
        await query([
          "organizations",
          "subscription",
          "get",
          "--subscription-id",
          list.items[0].id,
        ]),
      );
      return {
        observedAtUtc: new Date().toISOString(),
        value,
        postTrialEligibilityProved: false,
      };
    });
    await observe("postedCost", async () => {
      const result = await readPostedCosts(query, [
        "usage-api",
        "usage-summary",
        "request-summarized-usages",
        "--tenant-id",
        config.tenancyId,
        "--time-usage-started",
        queryStart.toISOString(),
        "--time-usage-ended",
        queryEnd.toISOString(),
        "--granularity",
        "DAILY",
        "--query-type",
        "COST",
        "--is-aggregate-by-time",
        "false",
      ]);
      return {
        queryStartUtc: queryStart.toISOString(),
        queryEndUtc: queryEnd.toISOString(),
        ...result,
      };
    });
    await observe("retainedCatalog", async () => {
      const c = await readPrivateJson<{ catalog: unknown[] }>(
        ".private/file-backup/controller.json",
      );
      return summarizeWeeklyCatalog(c.catalog, new Date());
    });
    await observe(
      "oracleController",
      () => readPrivateJson(".private/backup-runtime.json"),
    );
    await observe("supportingGuestTelemetry", async () => {
      const end = new Date(Math.floor(Date.now() / 3600000) * 3600000);
      return await readGuestTelemetrySummary(
        config.source.instanceId,
        new Date(end.getTime() - 7 * 86400000),
        end,
      );
    });
    const report = {
      ...observationTiming(new Date()),
      collectionStartedAtUtc: started.toISOString(),
      sourceRevision: release.sourceRevision,
      status: Object.keys(failures).length
        ? "PARTIAL_OBSERVATION"
        : "OBSERVATIONS_RECORDED",
      observations,
      failures,
      resourceMutations: false,
      backupCreated: false,
      finalizedBillProved: false,
      fullObjectiveComplete: false,
    };
    const stamp = report.observedAtUtc.replaceAll(/[-:.]/g, "");
    const path = `.private/reports/calendar-${stamp}.json`;
    await writePrivateJson(path, report);
    console.log(
      JSON.stringify({
        status: report.status,
        observedAtUtc: report.observedAtUtc,
        mode: report.mode,
        privateReport: path,
        failedSurfaces: Object.keys(failures),
        resourceMutations: false,
      }),
    );
    if (Object.keys(failures).length) Deno.exitCode = 3;
  });
}
if (import.meta.main) await main();
