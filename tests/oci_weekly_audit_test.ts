import {
  idleAssessment,
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

Deno.test("summarizeSeries calculates the 95th percentile", () => {
  const summary = summarizeSeries([{
    "aggregated-datapoints": [
      { timestamp: "2026-09-01T00:00:00Z", value: 10 },
      { timestamp: "2026-09-01T01:00:00Z", value: 30 },
      { timestamp: "2026-09-01T02:00:00Z", value: 20 },
    ],
  }]);
  assertEquals(summary.percentile95, 30);
  assertEquals(summary.mean, 20);
  assertEquals(summary.points, 3);
});

Deno.test("idleAssessment waits for a complete window", () => {
  assertEquals(
    idleAssessment({ points: 5, percentile95: 80 }, { points: 5, mean: 10 }, 4),
    "pending-seven-day-window",
  );
});

Deno.test("idleAssessment rejects sparse metrics across a long window", () => {
  assertEquals(
    idleAssessment(
      { points: 2, percentile95: 30 },
      { points: 168, mean: 10 },
      167,
    ),
    "pending-seven-day-window",
  );
});

Deno.test("idleAssessment proves non-idle CPU after a full window", () => {
  assertEquals(
    idleAssessment(
      { points: 168, percentile95: 21 },
      { points: 168, mean: 10 },
      167,
    ),
    "not-idle-cpu",
  );
});

Deno.test("idleAssessment does not invent a network percentage", () => {
  assertEquals(
    idleAssessment(
      { points: 168, percentile95: 10 },
      { points: 168, mean: 10 },
      167,
    ),
    "indeterminate-network-percentage",
  );
});

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
