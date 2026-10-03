import {
  assessProgress,
  parseResourceLimits,
  parseTransferBudget,
  type ProgressSample,
} from "../scripts/backup-progress.ts";

const start = new Date("2026-10-02T10:00:00.000Z");
function sample(extra: Partial<ProgressSample> = {}): ProgressSample {
  return {
    observedAtUtc: start.toISOString(),
    jobId: "job-test",
    generation: "generation-test",
    requestedAtUtc: start.toISOString(),
    invocationId: "invocation",
    phase: "CAPTURING",
    unitName: "unit",
    cpuUsec: 100,
    readBytes: 200,
    writeBytes: 300,
    archiveBytes: { "root.tar.zst.partial": 400 },
    uploadedBytes: null,
    verifiedChunks: null,
    captureBytes: null,
    sourceRevision: null,
    resourceLimits: null,
    ...extra,
  };
}
function equal(actual: unknown, expected: unknown): void {
  if (actual !== expected) throw new Error(`${actual} != ${expected}`);
}

Deno.test("unchanged evidence becomes stalled despite a fresh observation", () => {
  const baseline = assessProgress(sample(), null, start);
  const later = new Date(start.getTime() + 3_600_000);
  equal(
    assessProgress(
      sample({ observedAtUtc: later.toISOString() }),
      baseline,
      later,
    ).state,
    "STALLED",
  );
});

Deno.test("resource limits preserve measured quota, unbounded memory and per-device caps", () => {
  const result = parseResourceLimits("/sys/fs/cgroup/exact-job", {
    "cpu.max": "100000 100000\n",
    "cpu.weight": "1\n",
    "memory.max": "6253244416\n",
    "memory.high": "max\n",
    "memory.swap.max": "0\n",
    "io.max":
      "8:0 rbps=30000000 wbps=30000000 riops=12500 wiops=max\n8:16 rbps=max wbps=10000000 riops=max wiops=200\n",
  });
  equal(result.cpuQuotaCores, 1);
  equal(result.cpuWeight, 1);
  equal(result.memoryMaxBytes, 6253244416);
  equal(result.memoryHighBytes, "max");
  equal(result.memorySwapMaxBytes, 0);
  equal(result.ioDevices?.length, 2);
  equal(result.ioDevices?.[0].rbps, 30000000);
  equal(result.ioDevices?.[0].wiops, "max");
  equal(result.ioDevices?.[1].wbps, 10000000);
  equal(result.ioDevices?.[1].wiops, 200);
  const serialized = JSON.parse(JSON.stringify(assessProgress(
    sample({
      resourceLimits: result,
      sourceRevision: "a".repeat(40),
    }),
    null,
    start,
  )));
  equal(serialized.sample.resourceLimits.ioDevices[1].wiops, 200);
  equal(serialized.sample.sourceRevision, "a".repeat(40));
});

Deno.test("unavailable and malformed limits are distinct from unbounded controls", () => {
  const absent = parseResourceLimits("/sys/fs/cgroup/missing-job", {});
  equal(absent.cpuQuotaCores, null);
  equal(absent.memoryMaxBytes, null);
  equal(absent.ioDevices, null);
  equal(absent.networkBudgetProvenance, "UNKNOWN");
  equal(
    parseResourceLimits("group", { "cpu.max": "max 100000" }).cpuQuotaCores,
    "max",
  );
  equal(
    parseResourceLimits("group", { "cpu.max": "25000 100000" }).cpuQuotaCores,
    0.25,
  );
  equal(
    parseResourceLimits("group", { "cpu.max": "100000 0" }).cpuQuotaCores,
    null,
  );
  equal(
    parseResourceLimits("group", { "memory.max": "invalid" }).memoryMaxBytes,
    null,
  );
  equal(parseResourceLimits("group", { "io.max": "" }).ioDevices?.length, 0);
});

Deno.test("network history parses each pinned release without evaluating expressions", () => {
  equal(
    parseTransferBudget(
      "export const TRANSFER_BYTES_PER_SECOND = 4 * 1024 * 1024;",
    ),
    4194304,
  );
  equal(
    parseTransferBudget(
      "export const TRANSFER_BYTES_PER_SECOND = 125_000_000;",
    ),
    125000000,
  );
  equal(
    parseTransferBudget("export const TRANSFER_BYTES_PER_SECOND = other();"),
    null,
  );
  equal(
    parseTransferBudget("export const TRANSFER_BYTES_PER_SECOND = 4 / 2;"),
    null,
  );
  equal(
    parseTransferBudget("export const TRANSFER_BYTES_PER_SECOND = 0;"),
    null,
  );
  equal(
    parseTransferBudget(
      "export const TRANSFER_BYTES_PER_SECOND = 9007199254740991 * 2;",
    ),
    null,
  );
  equal(parseTransferBudget(null), null);
});

Deno.test("archive growth and phase transitions prove progress without fabricated ETA", () => {
  const baseline = assessProgress(sample(), null, start);
  const later = new Date(start.getTime() + 3_600_000);
  const growing = assessProgress(
    sample({
      observedAtUtc: later.toISOString(),
      archiveBytes: { "root.tar.zst.partial": 500 },
    }),
    baseline,
    later,
  );
  equal(growing.state, "PROGRESSING");
  equal(growing.uploadFinishAtUtc, null);
  const verifying = assessProgress(
    sample({ observedAtUtc: later.toISOString(), phase: "VERIFYING" }),
    baseline,
    later,
  );
  equal(verifying.state, "PROGRESSING");
  equal(verifying.cycleFinishAtUtc, null);
});

Deno.test("upload forecast measures verified byte delta and flags upload beyond 24 hours", () => {
  const first = sample({
    phase: "UPLOADING",
    uploadedBytes: 0,
    verifiedChunks: 0,
    captureBytes: 1000,
  });
  const baseline = assessProgress(first, null, start);
  const later = new Date(start.getTime() + 3_600_000);
  const result = assessProgress(
    sample({
      observedAtUtc: later.toISOString(),
      phase: "UPLOADING",
      uploadedBytes: 10,
      verifiedChunks: 1,
      captureBytes: 1000,
    }),
    baseline,
    later,
  );
  equal(result.state, "BEHIND_SCHEDULE");
  equal(result.uploadFinishAtUtc, "2026-10-06T14:00:00.000Z");
  equal(result.cycleFinishAtUtc, null);
});

Deno.test("missing evidence is unknown and a reset starts a fresh baseline", () => {
  const baseline = assessProgress(sample(), null, start);
  const later = new Date(start.getTime() + 3_600_000);
  equal(
    assessProgress(
      sample({
        observedAtUtc: later.toISOString(),
        cpuUsec: null,
        readBytes: null,
        writeBytes: null,
        archiveBytes: null,
      }),
      baseline,
      later,
    ).state,
    "UNKNOWN",
  );
  equal(
    assessProgress(
      sample({
        observedAtUtc: later.toISOString(),
        cpuUsec: null,
        archiveBytes: { "root.tar.zst.partial": 500 },
      }),
      baseline,
      later,
    ).state,
    "UNKNOWN",
  );
  equal(
    assessProgress(
      sample({ observedAtUtc: later.toISOString(), cpuUsec: 0 }),
      baseline,
      later,
    ).state,
    "BASELINE",
  );
  equal(
    assessProgress(sample({ phase: "FAILED" }), baseline, start).state,
    "FAILED",
  );
  equal(
    assessProgress(sample({ phase: "ACCEPTED" }), baseline, start).state,
    "COMPLETE",
  );
});

Deno.test("resource changes reset throughput comparisons without losing counter history", () => {
  const controls = {
    "cpu.max": "25000 100000",
    "cpu.weight": "1",
    "memory.max": "1610612736",
    "memory.high": "max",
    "memory.swap.max": "0",
    "io.max": "8:16 rbps=10000000 wbps=10000000 riops=500 wiops=200",
  };
  const beforeLimits = parseResourceLimits("/sys/fs/cgroup/test", controls);
  const before = sample({
    phase: "UPLOADING",
    uploadedBytes: 100,
    verifiedChunks: 1,
    captureBytes: 1000,
    resourceLimits: beforeLimits,
  });
  const baseline = assessProgress(before, null, start);
  const later = new Date(start.getTime() + 3_600_000);
  const afterLimits = parseResourceLimits("/sys/fs/cgroup/test", {
    ...controls,
    "cpu.max": "100000 100000",
    "memory.max": "6255601664",
  });
  const after = assessProgress(
    sample({
      observedAtUtc: later.toISOString(),
      phase: "UPLOADING",
      uploadedBytes: 200,
      verifiedChunks: 2,
      captureBytes: 1000,
      resourceLimits: afterLimits,
    }),
    baseline,
    later,
  );
  equal(after.state, "BASELINE");
  equal(after.uploadBytesPerSecond, null);
  equal(after.sample?.uploadedBytes, 200);
  equal(after.sample?.resourceLimits?.cpuQuotaCores, 1);
});
