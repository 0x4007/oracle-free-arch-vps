Deno.test("summarizeStoredObjects counts all versions when supplied", () => {
  assertEquals(
    summarizeStoredObjects(
      [{ name: "backup.qcow2", size: 100 }],
      [
        { name: "backup.qcow2", size: 100, "version-id": "new" },
        { name: "backup.qcow2", size: 80, "version-id": "old" },
      ],
    ),
    { count: 2, bytes: 180 },
  );
});

Deno.test("summarizeStoredObjects uses current objects without versioning", () => {
  assertEquals(
    summarizeStoredObjects(
      [
        { name: "one", size: 40 },
        { name: "two", size: 60 },
      ],
      undefined,
    ),
    { count: 2, bytes: 100 },
  );
});
import {
  idleAssessment,
  metric,
  observationWindowStatus,
  summarizeSeries,
  summarizeStoredObjects,
} from "../scripts/oci-weekly-audit.ts";

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

const start = "2026-09-03T20:00:00.000Z";
const end = "2026-09-10T20:00:00.000Z";
const points = Array.from({ length: 168 }, (_, hour) => ({
  timestamp: new Date(Date.parse(start) + hour * 3_600_000).toISOString(),
  value: hour % 30,
}));
const series = (values = points) => [{ "aggregated-datapoints": values }];

Deno.test("summary bounds seven days and excludes the inclusive API endpoint", () => {
  const summary = summarizeSeries(
    series([
      { timestamp: "2026-09-03T19:00:00Z", value: 1000 },
      ...points,
      points[0],
      { timestamp: end, value: 1000 },
    ]),
    start,
    end,
  );
  assertEquals(summary.points, 168);
  assertEquals(summary.coveredHours, 168);
  assertEquals(summary.missingHours, 0);
  assertEquals(summary.status, "complete");
  assertEquals(summary.firstUtc, start);
  assertEquals(summary.lastUtc, "2026-09-10T19:00:00.000Z");
  assertEquals(summary.maximum, 29);
});

Deno.test("summary does not count duplicates, off-grid or invalid points as coverage", () => {
  const values = points.filter((_, i) => i !== 80);
  const summary = summarizeSeries(
    series([
      ...values,
      points[0],
      { timestamp: "2026-09-04T00:30:00Z", value: 99 },
      { timestamp: "invalid", value: 99 },
      { ...points[80], value: Infinity },
    ]),
    start,
    end,
  );
  assertEquals(summary.points, 167);
  assertEquals(summary.missingHours, 1);
  assertEquals(summary.status, "incomplete");
});

Deno.test("summary calculates statistics only from accepted hours", () => {
  const summary = summarizeSeries(
    series([
      { ...points[0], value: 10 },
      { ...points[1], value: 30 },
      { ...points[2], value: 20 },
    ]),
    start,
    end,
  );
  assertEquals(summary.percentile95, 30);
  assertEquals(summary.mean, 20);
});

Deno.test("missing guest metrics remain unavailable despite complete high CPU", () => {
  const cpu = summarizeSeries(
    series(points.map((p) => ({ ...p, value: 80 }))),
    start,
    end,
  );
  const missing = summarizeSeries([], start, end);
  assertEquals(missing.status, "unavailable");
  assertEquals(missing.missingHours, 168);
  assertEquals(
    observationWindowStatus([cpu, missing]),
    "telemetry-unavailable",
  );
  assertEquals(
    idleAssessment([cpu, missing]),
    "unverified-telemetry-unavailable",
  );
});

Deno.test("partial observed data is distinct from unavailable telemetry", () => {
  const partial = summarizeSeries(series(points.slice(0, 5)), start, end);
  assertEquals(
    observationWindowStatus([partial]),
    "incomplete-observation-window",
  );
  assertEquals(
    idleAssessment([partial]),
    "unverified-incomplete-observation-window",
  );
});

Deno.test("complete metrics do not invent Oracle network percentage or idle verdict", () => {
  const complete = summarizeSeries(series(), start, end);
  assertEquals(
    observationWindowStatus([complete, complete, complete, complete]),
    "complete",
  );
  assertEquals(
    idleAssessment([complete, complete, complete, complete]),
    "indeterminate-network-percentage",
  );
});

const config = {
  ociCliPath: "oci",
  ociProfile: "DEFAULT",
  region: "test-region",
  compartmentId: "test-compartment",
  instanceId: "test-instance",
  objectStorageLimitGb: 20,
};

Deno.test("CPU uses only hypervisor namespace and retains exact query provenance", async () => {
  const result = await metric(
    config,
    (_command, args) => {
      const value = (flag: string) => args[args.indexOf(flag) + 1];
      assertEquals(value("--namespace"), "oci_vmi_resource_utilization");
      assertEquals(value("--region"), config.region);
      assertEquals(value("--compartment-id"), config.compartmentId);
      assertEquals(
        value("--query-text"),
        'CpuUtilization[1h]{resourceId = "test-instance"}.mean()',
      );
      assertEquals(value("--start-time"), start);
      assertEquals(value("--end-time"), end);
      assertEquals(value("--resolution"), "1h");
      return Promise.resolve({
        code: 0,
        stderr: "",
        stdout: JSON.stringify({
          data: [{
            namespace: "oci_vmi_resource_utilization",
            name: "CpuUtilization",
            dimensions: { resourceId: config.instanceId },
            "aggregated-datapoints": points,
          }],
        }),
      });
    },
    "CpuUtilization",
    start,
    end,
  );
  assertEquals(result.source, "hypervisor");
  assertEquals(result.resourceId, config.instanceId);
  assertEquals(result.status, "complete");
});

Deno.test("guest memory and network keep agent provenance and empty-output status", async () => {
  for (
    const name of ["MemoryUtilization", "NetworksBytesIn", "NetworksBytesOut"]
  ) {
    const result = await metric(
      config,
      (_command, args) => {
        assertEquals(args[args.indexOf("--namespace") + 1], "oci_computeagent");
        return Promise.resolve({ code: 0, stderr: "", stdout: "" });
      },
      name,
      start,
      end,
    );
    assertEquals(result.source, "guest-agent");
    assertEquals(result.status, "unavailable");
  }
});

Deno.test("provider failures and wrong source responses cannot become missing telemetry", async () => {
  for (
    const response of [
      { code: 1, stderr: "access denied", stdout: "" },
      {
        code: 0,
        stderr: "",
        stdout: JSON.stringify({
          data: [{
            namespace: "oci_vmi_resource_utilization",
            name: "CpuUtilization",
            dimensions: { resourceId: "other-instance" },
            "aggregated-datapoints": points,
          }],
        }),
      },
    ]
  ) {
    let rejected = false;
    try {
      await metric(
        config,
        () => Promise.resolve(response),
        "CpuUtilization",
        start,
        end,
      );
    } catch {
      rejected = true;
    }
    assertEquals(rejected, true);
  }
});
