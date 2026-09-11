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
import { readGuestTelemetrySummary } from "./guest-telemetry.ts";

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
  coveredHours: number;
  missingHours: number;
  status: "unavailable" | "incomplete" | "complete";
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

export function summarizeSeries(
  series: JsonRecord[],
  start: string,
  end: string,
): SeriesSummary {
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  const expectedHours = (endMs - startMs) / 3_600_000;
  if (!Number.isInteger(expectedHours) || expectedHours <= 0) {
    throw new Error("Metric window must contain whole hours");
  }
  const hourlyPoints = new Map<number, number>();
  for (
    const item of series.flatMap((item) => {
      const values = item["aggregated-datapoints"];
      return Array.isArray(values) ? values as JsonRecord[] : [];
    })
  ) {
    const timestamp = Date.parse(String(item.timestamp));
    if (
      typeof item.value !== "number" || !Number.isFinite(item.value) ||
      !Number.isFinite(timestamp) || timestamp < startMs ||
      timestamp >= endMs ||
      (timestamp - startMs) % 3_600_000 !== 0
    ) continue;
    if (
      hourlyPoints.has(timestamp) && hourlyPoints.get(timestamp) !== item.value
    ) {
      throw new Error("Conflicting metric values for one hourly timestamp");
    }
    hourlyPoints.set(timestamp, item.value);
  }
  const values = [...hourlyPoints.values()];
  const timestamps = [...hourlyPoints.keys()].sort((a, b) => a - b);
  const coverage = {
    points: values.length,
    coveredHours: values.length,
    missingHours: expectedHours - values.length,
    status: values.length === 0
      ? "unavailable" as const
      : values.length === expectedHours
      ? "complete" as const
      : "incomplete" as const,
  };
  if (values.length === 0) return coverage;
  return {
    ...coverage,
    firstUtc: new Date(timestamps[0]).toISOString(),
    lastUtc: new Date(timestamps.at(-1)!).toISOString(),
    minimum: Math.min(...values),
    maximum: Math.max(...values),
    mean: values.reduce((sum, value) => sum + value, 0) / values.length,
    percentile95: percentile(values, 0.95),
    sum: values.reduce((sum, value) => sum + value, 0),
  };
}

export function observationWindowStatus(series: SeriesSummary[]): string {
  if (series.some((item) => item.status === "unavailable")) {
    return "telemetry-unavailable";
  }
  return series.every((item) => item.status === "complete")
    ? "complete"
    : "incomplete-observation-window";
}

export function idleAssessment(series: SeriesSummary[]): string {
  const status = observationWindowStatus(series);
  if (status !== "complete") return `unverified-${status}`;
  // Hypervisor CPU and guest byte counters do not establish Oracle's full
  // idle-policy evaluation, including its network utilization percentage.
  return "indeterminate-network-percentage";
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

export async function metric(
  config: AuditConfig,
  runner: CommandRunner,
  name: string,
  start: string,
  end: string,
) {
  const namespace = name === "CpuUtilization"
    ? "oci_vmi_resource_utilization"
    : "oci_computeagent";
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
      namespace,
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
  const series = dataArray(response);
  if (
    series.some((item) =>
      item.namespace !== namespace || item.name !== name ||
      (item.dimensions as JsonRecord | undefined)?.resourceId !==
        config.instanceId
    )
  ) throw new Error("Metric response does not match the requested source");
  return {
    ...summarizeSeries(series, start, end),
    namespace,
    source: name === "CpuUtilization" ? "hypervisor" : "guest-agent",
    resourceId: config.instanceId,
    metricName: name,
  };
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
  const generatedAt = new Date();
  // Exclude the current partial hour and OCI's inclusive end-boundary point.
  const end = new Date(
    Math.floor(generatedAt.getTime() / 3_600_000) * 3_600_000,
  );
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
  const series = [cpu, memory, networkIn, networkOut];
  const report = {
    generatedAtUtc: generatedAt.toISOString(),
    windowStartUtc: start.toISOString(),
    windowEndUtcExclusive: end.toISOString(),
    requestedWindowHours: 168,
    coveredHours: Math.min(...series.map((item) => item.coveredHours)),
    windowStatus: observationWindowStatus(series),
    idleReclamationAssessment: idleAssessment(series),
    policyCaveat:
      "CPU is collected by Oracle's hypervisor, not Oracle Cloud Agent. Guest memory/network telemetry requires a running guest publisher; unavailable telemetry is not a pending healthy collector. Network bytes do not establish Oracle's network utilization percentage or its full idle-risk verdict.",
    cpuUtilizationPercent: cpu,
    memoryUtilizationPercent: memory,
    networkBytesIn: networkIn,
    networkBytesOut: networkOut,
    supportingGuestTelemetry: await readGuestTelemetrySummary(
      config.instanceId,
      start,
      end,
    ),
    objectStorage: storage,
  };
  const stamp = generatedAt.toISOString().replaceAll(/[-:.]/g, "");
  const path = `.private/reports/weekly-${stamp}.json`;
  await writePrivateJson(path, report);
  console.log(JSON.stringify({ ...report, privateReport: path }, null, 2));
  if (report.windowStatus !== "complete") Deno.exitCode = 3;
  if (!storage.withinVerifiedLimit) Deno.exitCode = 4;
}

if (import.meta.main) await main();
