import {
  assessProgress,
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
