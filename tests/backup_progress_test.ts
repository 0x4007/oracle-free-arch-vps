import {
  assessProgress,
  backupV2ProcessBound,
  isBackupCgroupControlPath,
  parseResourceLimits,
  parseTransferBudget,
  type ProgressSample,
  validateBackupV2ProgressGate,
  verifiedBackupV2JournalBytes,
} from "../scripts/backup-progress.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2Status,
} from "../scripts/backup-v2-runtime-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import { backupV2ObjectName } from "../scripts/backup-v2-contract.ts";
import {
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";

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

Deno.test("control reader permits only exact backup units in approved slices", () => {
  const unit =
    "arch-vps-b2-worker-374d86e2-f4b1-4268-bcca-d5e052304f7b.service";
  for (const parent of ["system.slice", "weekly.slice/weekly-backup.slice"]) {
    for (
      const control of ["cgroup.events", "memory.max", "cpu.stat", "io.max"]
    ) {
      equal(
        isBackupCgroupControlPath(
          `/sys/fs/cgroup/${parent}/${unit}/${control}`,
        ),
        true,
      );
    }
  }
  for (
    const path of [
      `/sys/fs/cgroup/other.slice/${unit}/memory.max`,
      `/sys/fs/cgroup/weekly.slice/weekly-backup.slice/${unit}/memory.stat`,
      `/sys/fs/cgroup/weekly.slice/weekly-backup.slice/${unit}/../memory.max`,
      `/sys/fs/cgroup/system.slice/sshd.service/memory.max`,
      "/proc/self/environ",
    ]
  ) equal(isBackupCgroupControlPath(path), false);
});

const V2_ID = "00000000-0000-4000-8000-000000000001";
const V2_ATTEMPT = "00000000-0000-4000-8000-000000000002";
const V2_PUT = "00000000-0000-4000-8000-000000000003";
function v2Sample(
  at = start,
  extra: Partial<ProgressSample> = {},
): ProgressSample {
  const request: BackupV2Request = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId: `job-${V2_ID}`,
    captureId: `generation-${V2_ID}`,
    periodKey: "2026-09-27",
    requestedAtUtc: start.toISOString(),
    sourceRevision: "a".repeat(40),
    sourceConfigSha256: "b".repeat(64),
    recipientSha256: "c".repeat(64),
    recipientFingerprint: "A".repeat(40),
  };
  const unitName = `arch-vps-b2-v2-worker-${V2_ID}.service`,
    observed = at.getTime() - start.getTime() + 1;
  const status = validateBackupV2Status({
    schemaVersion: 2,
    format: "backup-v2",
    envelope: { request, requestSha256: backupV2RequestSha256(request) },
    gateId: V2_ATTEMPT,
    sourceBootId: V2_ID,
    custody: {
      unitName,
      invocationId: "1".repeat(32),
      mainPid: 123,
      mainStartTicks: "456",
      cgroup: `/weekly.slice/weekly-backup.slice/${unitName}`,
    },
    kind: "worker",
    phase: "CAPTURING_AND_UPLOADING",
    activeRoleAttempt: { role: "root", attemptId: V2_ATTEMPT },
    startedAtUtc: start.toISOString(),
    updatedAtUtc: at.toISOString(),
    finishedAtUtc: null,
    progress: {
      phase: "CAPTURING_AND_UPLOADING",
      observedMonotonicMs: observed,
      sourceBytes: 100,
      compressionInputBytes: 100,
      verifiedChunks: 1,
      decryptedBytes: 0,
      inventoryMembers: 2,
    },
    lease: {
      observedMonotonicMs: observed,
      usefulProgressAtMs: 1,
      usefulProgressExpiresAtMs: 120001,
      retryEpisode: null,
    },
    resultSha256: null,
  });
  return sample({
    format: "backup-v2",
    v2Status: status,
    processBound: true,
    jobId: request.jobId,
    generation: request.captureId,
    requestedAtUtc: request.requestedAtUtc,
    observedAtUtc: at.toISOString(),
    invocationId: status.custody.invocationId,
    phase: status.phase,
    unitName,
    archiveBytes: null,
    uploadedBytes: 100,
    verifiedChunks: 1,
    ...extra,
  });
}
Deno.test("v2 capture/upload overlap measures selected bytes without a link-ceiling ETA", () => {
  const first = v2Sample(),
    baseline = assessProgress(first, null, start),
    later = new Date(start.getTime() + 60000),
    next = v2Sample(later);
  next.v2Status!.progress.sourceBytes += 20;
  next.v2Status!.progress.compressionInputBytes += 20;
  next.v2Status!.progress.verifiedChunks++;
  next.uploadedBytes = 160;
  const report = assessProgress(next, baseline, later);
  equal(report.state, "PROGRESSING");
  equal(report.uploadBytesPerSecond, 1);
  equal(report.uploadFinishAtUtc, null);
  equal(report.cycleFinishAtUtc, null);
  const changedLimits = assessProgress(
    {
      ...next,
      resourceLimits: parseResourceLimits("exact-v2", {
        "cpu.max": "100000 100000",
      }),
    },
    baseline,
    later,
  );
  equal(changedLimits.state, "PROGRESSING");
  equal(changedLimits.uploadBytesPerSecond, null);
});
Deno.test("v2 CPU IO phase and heartbeat changes alone cannot hide stalled useful work", () => {
  const baseline = assessProgress(v2Sample(), null, start),
    later = new Date(start.getTime() + 3600000),
    next = v2Sample(later, {
      cpuUsec: 1000,
      readBytes: 2000,
      writeBytes: 3000,
    });
  equal(assessProgress(next, baseline, later).state, "STALLED");
  equal(
    assessProgress({ ...next, processBound: false }, baseline, later).state,
    "UNKNOWN",
  );
  equal(
    assessProgress({ ...next, readBytes: null }, baseline, later).state,
    "UNKNOWN",
  );
  equal(
    assessProgress({ ...next, v2Status: v2Sample().v2Status }, baseline, later)
      .state,
    "UNKNOWN",
  );
  next.v2Status!.lease.retryEpisode = {
    startedAtMs: 1,
    expiresAtMs: 6 * 3600000,
  };
  equal(assessProgress(next, baseline, later).state, "BASELINE");
});
Deno.test("v2 source completion is separate from catalog acceptance and blocked cancellation is unhealthy", () => {
  for (
    const phase of ["CLOUD_COMPLETE", "FAILED", "CANCELLATION_BLOCKED"] as const
  ) {
    const current = v2Sample();
    current.phase = phase;
    current.v2Status!.phase = phase;
    current.v2Status!.progress.phase = phase;
    current.v2Status!.finishedAtUtc = phase === "CANCELLATION_BLOCKED"
      ? null
      : start.toISOString();
    current.v2Status!.resultSha256 = phase === "CLOUD_COMPLETE"
      ? "d".repeat(64)
      : null;
    equal(
      assessProgress(current, null, start).state,
      phase === "CLOUD_COMPLETE" ? "BASELINE" : "FAILED",
    );
  }
});
Deno.test("v2 process binding requires boot, PID start, live cgroup membership and exact group", () => {
  const status = v2Sample().v2Status!,
    fields = ["S", ...Array(18).fill("0"), "456", "0"],
    stat = `123 (deno worker) ${fields.join(" ")}`;
  equal(
    backupV2ProcessBound(
      status,
      V2_ID,
      `0::${status.custody.cgroup}`,
      stat,
      "123\n124\n",
    ),
    true,
  );
  equal(
    backupV2ProcessBound(
      status,
      V2_PUT,
      `0::${status.custody.cgroup}`,
      stat,
      "123",
    ),
    false,
  );
  equal(
    backupV2ProcessBound(
      status,
      V2_ID,
      "0::/user.slice/session.scope",
      stat,
      "123",
    ),
    false,
  );
  equal(
    backupV2ProcessBound(
      status,
      V2_ID,
      `0::${status.custody.cgroup}`,
      stat.replace("456", "457"),
      "123",
    ),
    false,
  );
  equal(
    backupV2ProcessBound(
      status,
      V2_ID,
      `0::${status.custody.cgroup}`,
      stat,
      "124",
    ),
    false,
  );
});
Deno.test("v2 public observation gate must bind the exact generation gate and invocation directory", () => {
  const status = v2Sample().v2Status!,
    directory =
      `/var/tmp/arch-vps-file-backup/${status.envelope.request.captureId}/v2-${status.gateId}/${status.custody.invocationId}`;
  const gate = {
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope: status.envelope,
    gateId: status.gateId,
    sourceBootId: status.sourceBootId,
    kind: status.kind,
    unitName: status.custody.unitName,
    custody: status.custody,
    state: "ACTIVE",
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc: status.startedAtUtc,
    updatedAtUtc: status.updatedAtUtc,
  };
  equal(validateBackupV2ProgressGate(gate, directory).gateId, status.gateId);
  for (
    const [value, path] of [
      [{ ...gate, custody: null, state: "PENDING" }, directory],
      [gate, directory.replace(status.gateId, V2_PUT)],
      [gate, directory.replace(status.custody.invocationId, "2".repeat(32))],
      [gate, "/tmp/other"],
      [null, directory],
    ] as const
  ) {
    let rejected = false;
    try {
      validateBackupV2ProgressGate(value, path);
    } catch {
      rejected = true;
    }
    equal(rejected, true);
  }
});
function journalFixture() {
  const captureId = `generation-${V2_ID}`,
    name = backupV2ObjectName(captureId, V2_ATTEMPT, "data", 0, V2_PUT),
    sha1 = "1".repeat(40),
    sha256 = "2".repeat(64);
  const intent = {
    captureId,
    role: "root",
    attemptId: V2_ATTEMPT,
    kind: "data",
    ordinal: 0,
    offset: 0,
    putId: V2_PUT,
    createdAtUtc: start.toISOString(),
    name,
    slot: {
      index: 0,
      path: "/var/tmp/v2-progress/slot-0",
      device: 8,
      inode: 10,
      bytes: 17,
      sha1,
      sha256,
      uid: 0,
      mode: 384,
      links: 1,
    },
  };
  const object = {
    fileId: "selected-one",
    fileName: name,
    contentLength: 17,
    contentSha1: sha1,
    uploadTimestamp: 1,
    action: "upload",
    sha256,
  };
  return {
    captureId,
    records: [{ type: "intent", intent }, { type: "verify", name }, {
      type: "selected",
      name,
      object,
    }],
  };
}
async function* journalChunks(records: unknown[], tail = "") {
  const bytes = new TextEncoder().encode(
    records.map((r) => JSON.stringify(r) + "\n").join("") + tail,
  );
  for (let at = 0; at < bytes.length; at += 37) {
    yield bytes.subarray(at, at + 37);
  }
}
Deno.test("v2 progress bytes require readback selection, dedupe replay, and ignore an unfinished trailing record", async () => {
  const { captureId, records } = journalFixture();
  equal(
    await verifiedBackupV2JournalBytes(
      journalChunks(records.slice(0, 2)),
      captureId,
    ),
    0,
  );
  equal(
    await verifiedBackupV2JournalBytes(
      journalChunks([...records, records[2]], '{"type":"selected"'),
      captureId,
    ),
    17,
  );
  for (
    const broken of [[records[0], records[2]], [records[2]], [{
      type: "unexpected",
    }]]
  ) {
    let rejected = false;
    try {
      await verifiedBackupV2JournalBytes(journalChunks(broken), captureId);
    } catch {
      rejected = true;
    }
    equal(rejected, true);
  }
});
