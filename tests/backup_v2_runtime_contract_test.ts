import {
  assertBackupV2StatusTransition,
  type BackupV2Request,
  backupV2RequestSha256,
  type BackupV2Status,
  canonicalBackupV2RequestString,
  validateBackupRuntimeCatalogEntry,
  validateBackupV2CatalogEntry,
  validateBackupV2Gate,
  validateBackupV2Request,
  validateBackupV2RequestEnvelope,
  validateBackupV2Result,
  validateBackupV2Status,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ObjectKind,
  backupV2ObjectName,
} from "../scripts/backup-v2-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import { createBackupV2InventorySummary } from "../scripts/backup-v2-inventory.ts";
import { validateCatalogEntry } from "../scripts/backblaze-file-backup.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import { BackupV2WorkerProgress } from "../scripts/backup-v2-worker.ts";
import { BackupV2Supervisor } from "../scripts/backup-v2-supervisor.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function equal(actual: unknown, expected: unknown): void {
  assert(JSON.stringify(actual) === JSON.stringify(expected));
}
function rejects(run: () => unknown): void {
  let rejected = false;
  try {
    run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}
const ID = "00000000-0000-4000-8000-000000000001";
const ATTEMPT = "00000000-0000-4000-8000-000000000002";
const OTHER = "00000000-0000-4000-8000-000000000003";
const SHA = "a".repeat(64), REVISION = "a".repeat(40);
const START = "2026-10-18T04:00:00.000Z", END = "2026-10-18T04:01:00.000Z";
function request(): BackupV2Request {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId: `job-${ID}`,
    captureId: `generation-${ID}`,
    periodKey: "2026-10-18",
    requestedAtUtc: START,
    sourceRevision: REVISION,
    sourceConfigSha256: SHA,
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
  };
}
function envelope(value = request()) {
  return { request: value, requestSha256: backupV2RequestSha256(value) };
}
function identity() {
  const unitName = `arch-vps-b2-v2-worker-${ID}-${ATTEMPT}.service`;
  return {
    unitName,
    invocationId: "1".repeat(32),
    mainPid: 123,
    mainStartTicks: "456",
    cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`,
  };
}
function gate() {
  return validateBackupV2Gate({
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope: envelope(),
    gateId: ATTEMPT,
    sourceBootId: ID,
    kind: "worker",
    unitName: identity().unitName,
    custody: identity(),
    state: "ACTIVE",
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc: START,
    updatedAtUtc: END,
  });
}
function status(): BackupV2Status {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: envelope(),
    gateId: ATTEMPT,
    sourceBootId: ID,
    custody: identity(),
    kind: "worker",
    phase: "CAPTURING_AND_UPLOADING",
    activeRoleAttempt: { role: "root", attemptId: ATTEMPT },
    startedAtUtc: START,
    updatedAtUtc: END,
    finishedAtUtc: null,
    progress: {
      phase: "CAPTURING_AND_UPLOADING",
      observedMonotonicMs: 10,
      sourceBytes: 100,
      compressionInputBytes: 100,
      verifiedChunks: 1,
      decryptedBytes: 0,
      inventoryMembers: 5,
    },
    lease: {
      observedMonotonicMs: 10,
      usefulProgressAtMs: 10,
      usefulProgressExpiresAtMs: 20,
      retryEpisode: null,
    },
    resultSha256: null,
  };
}
function reference(
  ordinal = 0,
  kind: BackupV2ObjectKind = "manifest",
  captureId = request().captureId,
) {
  return {
    object: {
      fileId: `file-${kind}-${ordinal}`,
      fileName: backupV2ObjectName(captureId, ATTEMPT, kind, ordinal, OTHER),
      contentLength: 17,
      contentSha1: "1".repeat(40),
      uploadTimestamp: 1,
      action: "upload" as const,
      sha256: SHA,
    },
    plaintextSha256: SHA,
  };
}
function selectedRoot() {
  const r = request();
  return {
    reference: reference(),
    root: {
      schemaVersion: 2,
      format: "backup-v2",
      profile: r.profile,
      captureId: r.captureId,
      periodKey: r.periodKey,
      sourceRevision: r.sourceRevision,
      sourceConfigSha256: r.sourceConfigSha256,
      recipientSha256: r.recipientSha256,
      recipientFingerprint: r.recipientFingerprint,
      roles: BACKUP_V2_ROLES.map((role, ordinal) => ({
        role,
        attemptId: ATTEMPT,
        manifest: reference(ordinal),
        captureStartedAtUtc: START,
        captureFinishedAtUtc: END,
      })),
      metadata: [],
    },
  };
}
function result() {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: envelope(),
    gateId: ATTEMPT,
    sourceBootId: ID,
    custody: identity(),
    finishedAtUtc: END,
    selectedRoot: selectedRoot(),
  };
}
function catalog() {
  const summary = createBackupV2InventorySummary();
  summary.add({ path: new TextEncoder().encode("./etc/os-release") });
  const inventory = summary.finish();
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: envelope(),
    resultSha256: SHA,
    selectedRoot: selectedRoot(),
    receipt: {
      schemaVersion: 2,
      format: "backup-v2",
      captureId: request().captureId,
      root: reference(),
      verifiedAtUtc: END,
      recipientSha256: SHA,
      recipientFingerprint: "A".repeat(40),
      verifierRevision: REVISION,
      configurationSha256: SHA,
      tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4.9" },
      archives: BACKUP_V2_ROLES.map((role) => ({
        role,
        format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
        ciphertextBytes: 17,
        ciphertextSha256: SHA,
        compressedBytes: 1,
        compressedSha256: SHA,
        inventory: role === "recovery" ? null : inventory,
        inputComplete: true,
        integrityChecked: true,
        decompressionComplete: true,
        gpgExitCode: 0,
        zstdExitCode: 0,
        tarExitCode: 0,
      })),
      bootSamples: BACKUP_V2_BOOT_SAMPLES.map((sample) => ({
        ...sample,
        bytes: 1,
        sha256: SHA,
      })),
      metadataSha256: SHA,
      sourceIndependent: true,
      decryptedRestoreProved: true,
      machineBootRestoreProved: false,
    },
    receiptReference: reference(0, "receipt"),
    acceptedAtUtc: END,
  };
}

Deno.test("runtime request canonical digest binds every immutable field and excludes mutable deadlines", () => {
  const r = request(), saved = envelope(r);
  equal(validateBackupV2RequestEnvelope(saved), saved);
  const reordered = Object.fromEntries(
    Object.entries(r).reverse(),
  ) as unknown as BackupV2Request;
  equal(
    canonicalBackupV2RequestString(reordered),
    canonicalBackupV2RequestString(r),
  );
  equal(backupV2RequestSha256(reordered), saved.requestSha256);
  for (
    const [key, value] of Object.entries({
      sourceRevision: "b".repeat(40),
      sourceConfigSha256: "b".repeat(64),
      recipientSha256: "b".repeat(64),
      recipientFingerprint: "B".repeat(40),
      requestedAtUtc: END,
      periodKey: "2026-10-25",
    })
  ) {
    rejects(() =>
      validateBackupV2RequestEnvelope({
        ...saved,
        request: { ...r, [key]: value },
      })
    );
  }
  for (
    const extra of [{ deadlineAtUtc: END }, { retryEpisode: null }, {
      progress: {},
    }, { gateId: ID }]
  ) rejects(() => validateBackupV2Request({ ...r, ...extra }));
});
Deno.test("runtime requests reject unknown versions, bad Sunday dates and contradictory capture identity", () => {
  for (
    const bad of [
      { schemaVersion: 1 },
      { schemaVersion: 3 },
      { format: "backup-v1" },
      { profile: "unknown" },
      { periodKey: "2026-10-19" },
      { periodKey: "2026-02-30" },
      { captureId: `capture-${ID}` },
      { captureId: `generation-${OTHER}` },
      { recipientFingerprint: "a".repeat(40) },
      { sourceRevision: "A".repeat(40) },
    ]
  ) rejects(() => validateBackupV2Request({ ...request(), ...bad }));
  rejects(() =>
    validateBackupV2RequestEnvelope({
      ...envelope(),
      requestSha256: "b".repeat(64),
    })
  );
});
Deno.test("runtime gate retains blocked or pending custody without any time-only expiration", () => {
  const g = gate();
  equal(validateBackupV2Gate(g), g);
  equal(
    validateBackupV2Gate({
      ...g,
      state: "CANCELLATION_BLOCKED",
      updatedAtUtc: "2027-10-17T00:00:00.000Z",
    }).state,
    "CANCELLATION_BLOCKED",
  );
  equal(
    validateBackupV2Gate({ ...g, state: "PENDING", custody: null }).custody,
    null,
  );
  equal(
    validateBackupV2Gate({ ...g, state: "CANCELLATION_BLOCKED", custody: null })
      .custody,
    null,
  );
  for (
    const bad of [
      { state: "ACTIVE", custody: null },
      { state: "PENDING" },
      { deadlineAtUtc: END },
      { remoteHost: "other" },
      { sourceLockPath: "/tmp/other" },
      { sourceBootId: "" },
      { unitName: "other.service" },
    ]
  ) rejects(() => validateBackupV2Gate({ ...g, ...bad }));
});
Deno.test("runtime status binds exact gate, boot, process-start and unit invocation custody", () => {
  const s = status(), g = gate();
  equal(validateBackupV2Status(s, g), s);
  for (
    const bad of [
      { gateId: OTHER },
      { sourceBootId: OTHER },
      { custody: { ...s.custody, invocationId: "2".repeat(32) } },
      { custody: { ...s.custody, mainPid: 124 } },
      { custody: { ...s.custody, mainStartTicks: "457" } },
      {
        envelope: envelope({
          ...request(),
          requestedAtUtc: "2026-10-18T03:59:00.000Z",
        }),
      },
    ]
  ) rejects(() => validateBackupV2Status({ ...s, ...bad }, g));
  for (
    const bad of [
      { mainPid: 0 },
      { cgroup: `/user.slice/${s.custody.unitName}` },
      { mainStartTicks: "0" },
      { invocationId: "" },
    ]
  ) {
    rejects(() =>
      validateBackupV2Status({ ...s, custody: { ...s.custody, ...bad } })
    );
  }
  rejects(() =>
    validateBackupV2Status(s, { ...g, state: "PENDING", custody: null })
  );
});
Deno.test("runtime status requires coherent phase, terminal artifact, role and monotonic-window data", () => {
  const s = status();
  for (
    const bad of [
      { activeRoleAttempt: null },
      { phase: "ACCEPTED" },
      { progress: { ...s.progress, observedMonotonicMs: 11 } },
      { finishedAtUtc: END },
      { resultSha256: SHA },
      { updatedAtUtc: "2026-10-17T00:00:00.000Z" },
      { progress: { ...s.progress, verifiedChunks: -1 } },
      { activeRoleAttempt: { role: "unknown", attemptId: ATTEMPT } },
      {
        lease: {
          ...s.lease,
          retryEpisode: { startedAtMs: 9, expiresAtMs: 9 + 7 * 3_600_000 },
        },
      },
    ]
  ) rejects(() => validateBackupV2Status({ ...s, ...bad }));
  const complete = {
    ...s,
    phase: "CLOUD_COMPLETE",
    progress: { ...s.progress, phase: "CLOUD_COMPLETE" },
    finishedAtUtc: END,
    resultSha256: SHA,
  };
  equal(validateBackupV2Status(complete).finishedAtUtc, END);
  rejects(() => validateBackupV2Status({ ...complete, resultSha256: null }));
  rejects(() => validateBackupV2Status({ ...complete, deadlineAtUtc: END }));
});
Deno.test("runtime status transitions preserve failed history and reject replay or sliding retry windows", () => {
  const a = status(), b = structuredClone(a);
  b.progress.sourceBytes++;
  b.progress.observedMonotonicMs++;
  b.lease.observedMonotonicMs++;
  assertBackupV2StatusTransition(a, b);
  rejects(() => assertBackupV2StatusTransition(b, a));
  rejects(() =>
    assertBackupV2StatusTransition(a, { ...b, sourceBootId: OTHER })
  );
  a.lease.retryEpisode = { startedAtMs: 9, expiresAtMs: 19 };
  b.lease.retryEpisode = { startedAtMs: 10, expiresAtMs: 20 };
  rejects(() => assertBackupV2StatusTransition(a, b));
  rejects(() =>
    assertBackupV2StatusTransition(a, {
      ...a,
      lease: { ...a.lease, retryEpisode: null },
    })
  );
  rejects(() =>
    assertBackupV2StatusTransition(status(), {
      ...status(),
      lease: { ...status().lease, usefulProgressExpiresAtMs: 30 },
    })
  );
  const progressed = structuredClone(a);
  progressed.progress.sourceBytes++;
  progressed.lease.retryEpisode = null;
  assertBackupV2StatusTransition(a, progressed);
  const failed = validateBackupV2Status({
    ...status(),
    phase: "FAILED",
    progress: { ...status().progress, phase: "FAILED" },
    finishedAtUtc: END,
  });
  assertBackupV2StatusTransition(failed, failed);
  rejects(() => assertBackupV2StatusTransition(failed, status()));
  rejects(() =>
    assertBackupV2StatusTransition(failed, {
      ...failed,
      updatedAtUtc: "2026-10-18T04:02:00.000Z",
    })
  );
});
Deno.test("runtime status keeps progress paired with its lease when work advances during persistence", async () => {
  const template = status(), work = new BackupV2WorkerProgress();
  const active = template.activeRoleAttempt;
  work.capture(
    { role: "root", kind: "source", bytes: 100, members: 0 },
    active,
  );
  let now = 10, advanced = false;
  const supervisor = new BackupV2Supervisor(template.custody, {
    progressGraceMs: 1000,
    notificationGraceMs: 100,
    observationTimeoutMs: 20,
    maximumObservationAgeMs: 100,
    productionWriterMarginBytes: 4096,
    minimumFreeInodes: 100,
    maximumSourceHeldDeletedBytes: 1024,
  }, {
    now: () => now,
    notifier: {
      ready() {},
      extend() {},
      stopping() {},
      close() {},
    },
    observe: () =>
      Promise.resolve({
        identity: template.custody,
        progress: work.observe(now),
        capacity: {
          observedMonotonicMs: now,
          availableBytes: 10 * 1024 ** 3,
          freeInodes: 10_000,
          allocatedWorkspaceBytes: 0,
          workspaceHeldDeletedBytes: 0,
          sourceHeldDeletedBytes: 0,
        },
      }),
    persistRuntimeLease: () => {
      if (!advanced) {
        work.capture(
          { role: "root", kind: "source", bytes: 101, members: 0 },
          active,
        );
        advanced = true;
        now++;
      }
      return Promise.resolve();
    },
  });
  const publish = () =>
    validateBackupV2Status({
      ...template,
      ...work.status(now),
      lease: { ...supervisor.window(), observedMonotonicMs: now },
    });
  equal((await supervisor.poll()).action, "renew");
  const first = publish();
  now = 20;
  equal((await supervisor.poll()).action, "renew");
  const second = publish();
  assertBackupV2StatusTransition(first, second);
  equal(first.progress.sourceBytes, 100);
  equal(second.progress.sourceBytes, 101);
  const expiry = second.lease.usefulProgressExpiresAtMs;
  now = 30;
  equal((await supervisor.poll()).action, "renew");
  const heartbeat = publish();
  assertBackupV2StatusTransition(second, heartbeat);
  equal(heartbeat.lease.usefulProgressExpiresAtMs, expiry);
  work.capture(
    { role: "root", kind: "source", bytes: 102, members: 0 },
    active,
  );
  supervisor.cancel();
  work.phase = "CANCELLATION_BLOCKED";
  const cancelled = publish();
  assertBackupV2StatusTransition(heartbeat, cancelled);
  equal(cancelled.progress.sourceBytes, 102);
  equal(cancelled.lease.usefulProgressExpiresAtMs, expiry);
});
Deno.test("terminal and cancellation status preserve final counters instead of the prior observation", () => {
  for (
    const phase of [
      "CLOUD_COMPLETE",
      "ACCEPTED",
      "CLEANED",
      "FAILED",
      "CANCELLATION_BLOCKED",
    ] as const
  ) {
    const work = new BackupV2WorkerProgress(),
      active = status().activeRoleAttempt;
    work.capture(
      { role: "root", kind: "source", bytes: 100, members: 0 },
      active,
    );
    work.observe(10);
    work.capture(
      { role: "root", kind: "source", bytes: 101, members: 0 },
      active,
    );
    work.phase = phase;
    const final = work.status(20);
    equal(final.phase, phase);
    equal(final.progress.phase, phase);
    equal(final.progress.sourceBytes, 101);
  }
});
function verificationStatus(): BackupV2Status {
  const value = status();
  value.kind = "verify";
  value.phase = "VERIFYING";
  value.progress.phase = "VERIFYING";
  value.activeRoleAttempt = null;
  value.custody.unitName = value.custody.unitName.replace(
    "-worker-",
    "-verify-",
  );
  value.custody.cgroup = `${GATE_BACKUP_CGROUP_ROOT}/${value.custody.unitName}`;
  return value;
}
Deno.test("runtime verification accepts decoded-only useful progress with an optional legacy zero", () => {
  for (const previous of [undefined, 100]) {
    const before = verificationStatus(), after = structuredClone(before);
    if (previous !== undefined) before.progress.decodedBytes = previous;
    after.progress.decodedBytes = (previous ?? 0) + 1;
    after.progress.observedMonotonicMs++;
    after.lease.observedMonotonicMs++;
    after.lease.usefulProgressAtMs++;
    after.lease.usefulProgressExpiresAtMs++;
    assertBackupV2StatusTransition(before, after);
  }
});
Deno.test("runtime verification rejects decoded regression including disappearance", () => {
  for (const next of [99, undefined]) {
    const before = verificationStatus(), after = structuredClone(before);
    before.progress.decodedBytes = 100;
    if (next !== undefined) after.progress.decodedBytes = next;
    after.progress.observedMonotonicMs++;
    after.lease.observedMonotonicMs++;
    rejects(() => assertBackupV2StatusTransition(before, after));
  }
});
Deno.test("runtime verification still rejects an unchanged heartbeat renewing its lease", () => {
  const before = verificationStatus();
  before.progress.decodedBytes = 100;
  const after = structuredClone(before);
  after.progress.observedMonotonicMs++;
  after.lease.observedMonotonicMs++;
  after.lease.usefulProgressAtMs++;
  after.lease.usefulProgressExpiresAtMs++;
  rejects(() => assertBackupV2StatusTransition(before, after));
});
Deno.test("runtime result binds selected root identity and preserves reused role capture intervals", () => {
  const r = result();
  equal(
    validateBackupV2Result(r, gate()).selectedRoot.reference,
    r.selectedRoot.reference,
  );
  for (
    const bad of [
      { captureId: `generation-${OTHER}` },
      { sourceConfigSha256: "b".repeat(64) },
      { recipientSha256: "b".repeat(64) },
      { periodKey: "2026-10-25" },
      { sourceRevision: "b".repeat(40) },
    ]
  ) {
    rejects(() =>
      validateBackupV2Result({
        ...r,
        selectedRoot: {
          ...r.selectedRoot,
          root: { ...r.selectedRoot.root, ...bad },
        },
      })
    );
  }
  rejects(() =>
    validateBackupV2Result({
      ...r,
      selectedRoot: {
        ...r.selectedRoot,
        reference: reference(0, "manifest", `generation-${OTHER}`),
      },
    })
  );
  rejects(() => validateBackupV2Result({ ...r, finishedAtUtc: START }));
  const reused = structuredClone(r);
  reused.selectedRoot.root.roles[0].manifest = reference(
    0,
    "manifest",
    `generation-${OTHER}`,
  );
  reused.selectedRoot.root.roles[0].captureStartedAtUtc =
    "2026-10-11T04:00:00.000Z";
  reused.selectedRoot.root.roles[0].captureFinishedAtUtc =
    "2026-10-11T04:01:00.000Z";
  equal(
    validateBackupV2Result(reused).selectedRoot.root.roles[0],
    reused.selectedRoot.root.roles[0],
  );
});
Deno.test("runtime accepted catalog requires independent complete receipt matching selected cloud root", () => {
  const entry = catalog();
  equal(validateBackupV2CatalogEntry(entry).format, "backup-v2");
  for (
    const bad of [
      { configurationSha256: "b".repeat(64) },
      { captureId: `generation-${OTHER}` },
      { recipientSha256: "b".repeat(64) },
      { root: reference(1) },
      { decryptedRestoreProved: false },
      { machineBootRestoreProved: true },
      { verifiedAtUtc: START },
      { archives: entry.receipt.archives.slice(1) },
    ]
  ) {
    rejects(() =>
      validateBackupV2CatalogEntry({
        ...entry,
        receipt: { ...entry.receipt, ...bad },
      })
    );
  }
  rejects(() =>
    validateBackupV2CatalogEntry({ ...entry, receiptReference: reference() })
  );
  rejects(() =>
    validateBackupV2CatalogEntry({
      ...entry,
      receiptReference: reference(0, "receipt", `generation-${OTHER}`),
    })
  );
  equal(
    validateBackupV2CatalogEntry({ ...entry, acceptedAtUtc: START })
      .acceptedAtUtc,
    START,
  );
});
Deno.test("mixed catalog dispatch rejects unknown tags and delegates untouched v1 body to existing validator", () => {
  const legacy = { index: { generation: "preserved" }, acceptedAtUtc: START };
  let calls = 0;
  const validateLegacy = (body: unknown) => {
    calls++;
    assert(body === legacy);
    return validateCatalogEntry(body);
  };
  rejects(() =>
    validateBackupRuntimeCatalogEntry({
      schemaVersion: 1,
      format: "backup-v1",
      entry: legacy,
    }, validateLegacy)
  );
  equal(calls, 1);
  equal(legacy, { index: { generation: "preserved" }, acceptedAtUtc: START });
  equal(
    validateBackupRuntimeCatalogEntry(catalog(), validateLegacy).format,
    "backup-v2",
  );
  for (
    const bad of [
      { schemaVersion: 3, format: "backup-v2" },
      { schemaVersion: 2, format: "backup-v1" },
      { schemaVersion: 1, format: "backup-v2" },
      { schemaVersion: 1, format: "backup-v1", entry: legacy, extra: true },
    ]
  ) rejects(() => validateBackupRuntimeCatalogEntry(bad, validateLegacy));
  equal(calls, 1);
});
