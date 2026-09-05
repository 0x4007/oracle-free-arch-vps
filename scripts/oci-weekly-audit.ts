import {
  type CommandRunner,
  dataArray,
  dataObject,
  dataString,
  defaultRunner,
  type JsonRecord,
  numberField,
  readPrivateJson,
  runJson,
  stringField,
  writePrivateJson,
} from "./oci.ts";

const CONFIG_PATH = ".private/weekly-audit.json";

interface AuditConfig {
  ociCliPath: string;
  ociProfile: string;
  region: string;
  compartmentId: string;
  instanceId: string;
  objectStorageLimitGb: number;
}

interface SeriesSummary {
  points: number;
  firstUtc?: string;
  lastUtc?: string;
  minimum?: number;
  maximum?: number;
  mean?: number;
  percentile95?: number;
  sum?: number;
}

interface StoredObjectSummary {
  count: number;
  bytes: number;
}

export function summarizeStoredObjects(
  currentObjects: JsonRecord[],
  objectVersions: JsonRecord[] | undefined,
): StoredObjectSummary {
  const storedObjects = objectVersions ?? currentObjects;
  return {
    count: storedObjects.length,
    bytes: storedObjects.reduce(
      (total, item) => total + numberField(item, "size"),
      0,
    ),
  };
}

function percentile(values: number[], fraction: number): number | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil(fraction * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
}

export function summarizeSeries(series: JsonRecord[]): SeriesSummary {
  const points = series.flatMap((item) => {
    const values = item["aggregated-datapoints"];
    return Array.isArray(values) ? values as JsonRecord[] : [];
  }).filter((item) =>
    typeof item.value === "number" && typeof item.timestamp === "string"
  );
  const values = points.map((item) => numberField(item, "value"));
  const timestamps = points.map((item) => stringField(item, "timestamp"))
    .sort();
  if (values.length === 0) return { points: 0 };
  return {
    points: values.length,
    firstUtc: timestamps[0],
    lastUtc: timestamps.at(-1),
    minimum: Math.min(...values),
    maximum: Math.max(...values),
    mean: values.reduce((sum, value) => sum + value, 0) / values.length,
    percentile95: percentile(values, 0.95),
    sum: values.reduce((sum, value) => sum + value, 0),
  };
}

export function idleAssessment(
  cpu: SeriesSummary,
  memory: SeriesSummary,
  coveredHours: number,
): string {
  if (
    coveredHours < 167 || cpu.points < 168 || memory.points < 168 ||
    cpu.percentile95 === undefined || memory.mean === undefined
  ) return "pending-seven-day-window";
  if (cpu.percentile95 >= 20) return "not-idle-cpu";
  if (memory.mean >= 20) return "not-idle-memory";
  return "indeterminate-network-percentage";
}

function seriesCoverageHours(series: SeriesSummary): number {
  return series.firstUtc && series.lastUtc
    ? (Date.parse(series.lastUtc) - Date.parse(series.firstUtc)) / 3_600_000
    : 0;
}

function ociArgs(config: AuditConfig, args: string[]): string[] {
  return [
    "--profile",
    config.ociProfile || "DEFAULT",
    "--region",
    config.region,
    ...args,
  ];
}

async function metric(
  config: AuditConfig,
  runner: CommandRunner,
  name: string,
  start: string,
  end: string,
): Promise<SeriesSummary> {
  const query = `${name}[1h]{resourceId = "${config.instanceId}"}.mean()`;
  const response = await runJson(
    config.ociCliPath,
    ociArgs(config, [
      "monitoring",
      "metric-data",
      "summarize-metrics-data",
      "--compartment-id",
      config.compartmentId,
      "--namespace",
      "oci_computeagent",
      "--start-time",
      start,
      "--end-time",
      end,
      "--resolution",
      "1h",
      "--query-text",
      query,
    ]),
    runner,
  );
  return summarizeSeries(dataArray(response));
}

export async function objectStorage(
  config: AuditConfig,
  runner: CommandRunner,
) {
  const namespaceValue = dataString(
    await runJson(
      config.ociCliPath,
      ociArgs(config, ["os", "ns", "get"]),
      runner,
    ),
  );
  const childCompartments = dataArray(
    await runJson(
      config.ociCliPath,
      ociArgs(config, [
        "iam",
        "compartment",
        "list",
        "--compartment-id",
        config.compartmentId,
        "--compartment-id-in-subtree",
        "true",
        "--access-level",
        "ANY",
        "--all",
      ]),
      runner,
    ),
  );
  const compartmentIds = [
    config.compartmentId,
    ...childCompartments
      .filter((item) => item["lifecycle-state"] === "ACTIVE")
      .map((item) => stringField(item, "id")),
  ];
  const buckets: JsonRecord[] = [];
  for (const compartmentId of compartmentIds) {
    buckets.push(...dataArray(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "os",
          "bucket",
          "list",
          "--compartment-id",
          compartmentId,
          "--namespace-name",
          namespaceValue,
          "--all",
        ]),
        runner,
      ),
    ));
  }
  let objects = 0;
  let storedObjects = 0;
  let versionedBuckets = 0;
  let bytes = 0;
  let multipartUploads = 0;
  for (const bucket of buckets) {
    const bucketName = stringField(bucket, "name");
    const bucketDetails = dataObject(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "os",
          "bucket",
          "get",
          "--namespace-name",
          namespaceValue,
          "--bucket-name",
          bucketName,
        ]),
        runner,
      ),
    );
    const items = dataArray(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "os",
          "object",
          "list",
          "--namespace-name",
          namespaceValue,
          "--bucket-name",
          bucketName,
          "--all",
        ]),
        runner,
      ),
    );
    objects += items.length;
    const versioningEnabled = ["enabled", "suspended"].includes(
      String(bucketDetails.versioning).toLowerCase(),
    );
    const versions = versioningEnabled
      ? dataArray(
        await runJson(
          config.ociCliPath,
          ociArgs(config, [
            "os",
            "object",
            "list-object-versions",
            "--namespace-name",
            namespaceValue,
            "--bucket-name",
            bucketName,
            "--all",
          ]),
          runner,
        ),
      )
      : undefined;
    if (versioningEnabled) versionedBuckets++;
    const stored = summarizeStoredObjects(items, versions);
    storedObjects += stored.count;
    bytes += stored.bytes;
    multipartUploads += dataArray(
      await runJson(
        config.ociCliPath,
        ociArgs(config, [
          "os",
          "multipart",
          "list",
          "--namespace-name",
          namespaceValue,
          "--bucket-name",
          bucketName,
          "--all",
        ]),
        runner,
      ),
    ).length;
  }
  const limitBytes = config.objectStorageLimitGb * 1024 ** 3;
  const inventoryComplete = multipartUploads === 0;
  return {
    scope: "configured-tenancy-home-region",
    compartments: compartmentIds.length,
    buckets: buckets.length,
    objects,
    storedObjects,
    versionedBuckets,
    multipartUploads,
    multipartBytes: multipartUploads === 0 ? 0 : "unknown",
    bytes,
    gibibytes: bytes / 1024 ** 3,
    verifiedLimitGb: config.objectStorageLimitGb,
    headroomBytes: limitBytes - bytes,
    inventoryComplete,
    withinVerifiedLimit: inventoryComplete && bytes <= limitBytes,
  };
}

export async function main(
  runner: CommandRunner = defaultRunner,
): Promise<void> {
  const config = await readPrivateJson<AuditConfig>(CONFIG_PATH);
  if (!config.compartmentId.startsWith("ocid1.tenancy.")) {
    throw new Error(
      "compartmentId must be the tenancy OCID for a tenancy-wide audit",
    );
  }
  const end = new Date();
  const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
  const [cpu, memory, networkIn, networkOut, storage] = await Promise.all([
    metric(
      config,
      runner,
      "CpuUtilization",
      start.toISOString(),
      end.toISOString(),
    ),
    metric(
      config,
      runner,
      "MemoryUtilization",
      start.toISOString(),
      end.toISOString(),
    ),
    metric(
      config,
      runner,
      "NetworksBytesIn",
      start.toISOString(),
      end.toISOString(),
    ),
    metric(
      config,
      runner,
      "NetworksBytesOut",
      start.toISOString(),
      end.toISOString(),
    ),
    objectStorage(config, runner),
  ]);
  const coveredHours = Math.min(
    seriesCoverageHours(cpu),
    seriesCoverageHours(memory),
    seriesCoverageHours(networkIn),
    seriesCoverageHours(networkOut),
  );
  const completeMetricWindow = coveredHours >= 167 &&
    [cpu, memory, networkIn, networkOut].every((series) =>
      series.points >= 168
    );
  const report = {
    generatedAtUtc: end.toISOString(),
    requestedWindowHours: 168,
    coveredHours,
    windowStatus: completeMetricWindow
      ? "complete"
      : "pending-seven-day-window",
    idleReclamationAssessment: idleAssessment(cpu, memory, coveredHours),
    policyCaveat:
      "OCI publishes network byte metrics, but the Always Free page does not define how to convert them to its network utilization percentage. Do not infer that percentage.",
    cpuUtilizationPercent: cpu,
    memoryUtilizationPercent: memory,
    networkBytesIn: networkIn,
    networkBytesOut: networkOut,
    objectStorage: storage,
  };
  const stamp = end.toISOString().replaceAll(/[-:.]/g, "").replace("Z", "Z");
  const path = `.private/reports/weekly-${stamp}.json`;
  await writePrivateJson(path, report);
  console.log(JSON.stringify({ ...report, privateReport: path }, null, 2));
  if (report.windowStatus !== "complete") Deno.exitCode = 3;
  if (!storage.withinVerifiedLimit) Deno.exitCode = 4;
}

if (import.meta.main) await main();
