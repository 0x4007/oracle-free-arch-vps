import {
  acceptedBackupRuntimeCapture,
  assessBackupV2Retention,
  assessBackupV2Watchdog,
  assessHourlyProgress,
  assessOracleBootDrillEvidence,
  assessOracleRetry,
} from "../scripts/backup-watchdog.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2Gate,
  validateBackupV2Status,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  type BackupV2ControllerObservation,
  validateBackupV2ControllerState,
} from "../scripts/backup-v2-controller.ts";
import { validateBackupV2WorkerSettings } from "../scripts/backup-v2-worker.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  backupV2ObjectName,
} from "../scripts/backup-v2-contract.ts";
import { createBackupV2InventorySummary } from "../scripts/backup-v2-inventory.ts";
import {
  type CaptureSettings,
  REQUIRED_EXCLUSIONS,
  ROLE_ORDER,
} from "../scripts/backblaze-capture.ts";
import {
  requestSha256Of,
  sourceConfigSha256,
} from "../scripts/backblaze-source-worker.ts";
import { newJobState } from "../scripts/backblaze-file-backup.ts";
import {
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import {
  type GroupRestorePlan,
  groupRestorePlanDigest,
} from "../scripts/oci-group-restore-drill.ts";
import type { GroupRestoreAcceptanceReceipt } from "../scripts/oci-group-restore-executor.ts";
import type { OnlineBackupRetry } from "../scripts/online-backup-contract.ts";

const now = new Date("2026-09-06T23:00:00Z");
const retry: OnlineBackupRetry = {
  disposition: "retryable",
  resumePhase: "backing-up",
  attempts: 1,
  firstFailureAtUtc: "2026-09-06T22:55:00Z",
  nextAttemptAtUtc: "2026-09-06T23:10:00Z",
  deadlineAtUtc: "2026-09-07T02:55:00Z",
};
function assertStatus(value: OnlineBackupRetry, expected: string) {
  const result = assessOracleRetry({ phase: "failed", retry: value }, now);
  if (result?.status !== expected || result.healthy !== false) {
    throw new Error(`Expected visible unresolved ${expected}`);
  }
}
Deno.test("retry watchdog distinguishes waiting, due, cooldown and ambiguity", () => {
  assertStatus(retry, "BACKUP_RETRY_WAITING");
  assertStatus(
    { ...retry, nextAttemptAtUtc: now.toISOString() },
    "BACKUP_RETRY_DUE",
  );
  assertStatus(
    { ...retry, nextAttemptAtUtc: "2026-09-07T23:00:00Z" },
    "BACKUP_RETRY_COOLDOWN",
  );
  assertStatus(
    { ...retry, disposition: "blocked" },
    "BACKUP_BLOCKED_RECONCILIATION",
  );
});
Deno.test("retry watchdog refuses malformed or future evidence", () => {
  assertStatus({ ...retry, attempts: -1 }, "INVALID_RETRY_STATE");
  assertStatus(
    { ...retry, nextAttemptAtUtc: "invalid" },
    "INVALID_RETRY_STATE",
  );
  assertStatus(
    { ...retry, firstFailureAtUtc: "2026-09-07T00:00:00Z" },
    "INVALID_RETRY_STATE",
  );
});
Deno.test("retry watchdog does not overwrite accepted or legacy failure assessments", () => {
  if (
    assessOracleRetry({ phase: "complete", retry }, now) !== undefined ||
    assessOracleRetry({ phase: "failed" }, now) !== undefined
  ) {
    throw new Error("Unexpected retry assessment");
  }
});

async function oracleProof() {
  const plan: GroupRestorePlan = {
    source: {
      instanceId: "source-instance",
      bootVolumeId: "source-boot",
      rootVolumeId: "source-root",
      compartmentId: "tenancy",
      region: "us-ashburn-1",
    },
    availabilityDomain: "AD-1",
    volumeGroupId: "source-group",
    volumeGroupBackupId: "accepted-group",
    bootMemberBackupId: "boot-member",
    rootMemberBackupId: "root-member",
    productionSubnetId: "production-subnet",
    productionVcnId: "production-vcn",
    productionReservedIpId: "production-ip",
    isolatedSubnetId: "clone-subnet",
    isolatedVcnId: "clone-vcn",
    isolatedCidrBlock: "10.77.0.0/28",
    controllerIpv4: "192.0.2.1",
    suffix: "20260906T200000Z",
    maxDurationHours: 4,
    spendingCapUsd: 0.5,
  };
  const acceptance: GroupRestoreAcceptanceReceipt = {
    status: "RESTORE_DRILL_PROVED",
    observedAtUtc: "2026-09-06T22:00:00.000Z",
    suffix: plan.suffix,
    planSha256: await groupRestorePlanDigest(plan),
    checks: {
      productionOnline: true,
      targetBooted: true,
      ssh: true,
      mounts: true,
      bootParity: true,
      representativeData: true,
      applications: true,
      desktop: true,
      isolation: true,
      metadataBlocked: true,
      duplicateJobsMasked: true,
    },
    rootUuid: "11111111-1111-4111-8111-111111111111",
    stagingUuid: "22222222-2222-4222-8222-222222222222",
    rootPartitionStartSector: 1050624,
    kernelSha256: "a".repeat(64),
    initramfsSha256: "b".repeat(64),
    grubSha256: "c".repeat(64),
  };
  return { plan, acceptance };
}

Deno.test("Oracle watchdog keeps dated group proof separate from a later capture", async () => {
  const proof = await oracleProof();
  for (
    const [current, expected] of [
      ["accepted-group", true],
      ["new-group", false],
      [undefined, null],
    ] as const
  ) {
    const result = await assessOracleBootDrillEvidence(proof, now, current);
    if (
      result.status !== "RESTORE_DRILL_PROVED" ||
      result.generation !== "accepted-group" ||
      result.bootMemberBackupId !== "boot-member" ||
      result.rootMemberBackupId !== "root-member" ||
      result.currentCaptureProved !== expected
    ) throw Error("Dated proof was lost or transferred to another capture");
  }
});

Deno.test("Oracle watchdog rejects substituted group/member bindings and incomplete proof", async () => {
  const original = await oracleProof();
  const mutations = [
    (p: typeof original) => {
      p.plan.volumeGroupBackupId = "other-group";
    },
    (p: typeof original) => {
      p.plan.rootMemberBackupId = "other-root";
    },
    (p: typeof original) => {
      p.acceptance.checks.desktop = false;
    },
    (p: typeof original) => {
      p.acceptance.observedAtUtc = "2026-09-07T00:00:00.000Z";
    },
  ];
  for (const mutate of mutations) {
    const proof = structuredClone(original);
    mutate(proof);
    let rejected = false;
    try {
      await assessOracleBootDrillEvidence(proof, now);
    } catch {
      rejected = true;
    }
    if (!rejected) throw Error("Invalid Oracle proof accepted");
  }
});

Deno.test("hourly progress alarms require a fresh matching source invocation", () => {
  const observed = new Date("2026-10-02T22:00:00.000Z");
  const report = {
    schemaVersion: 1,
    jobId: "job-current",
    observedAtUtc: observed.toISOString(),
    state: "STALLED",
    detail: "No observed progress",
    sample: { invocationId: "current" },
  };
  const alarm = assessHourlyProgress(
    report,
    "job-current",
    "current",
    observed,
  );
  if (
    alarm?.healthy !== false ||
    alarm?.status !== "B2_PROGRESS_STALLED:job-current"
  ) {
    throw new Error("Expected matching stall alarm");
  }
  for (
    const candidate of [
      { ...report, state: "PROGRESSING" },
      { ...report, jobId: "job-previous" },
      { ...report, sample: { invocationId: "previous" } },
      { ...report, observedAtUtc: "2026-10-02T20:00:00.000Z" },
      { ...report, observedAtUtc: "2026-10-02T23:00:00.000Z" },
    ]
  ) {
    if (assessHourlyProgress(candidate, "job-current", "current", observed)) {
      throw new Error("Unbound or stale progress must not alert");
    }
  }
});

const V2_ID = "00000000-0000-4000-8000-000000000001",
  V2_GATE = "00000000-0000-4000-8000-000000000002",
  V2_VERIFY = "00000000-0000-4000-8000-000000000003";
const V2_START = "2026-10-18T04:05:00.000Z",
  V2_NOW = new Date("2026-10-18T05:00:00.000Z"),
  V2_HASH = "b".repeat(64);
function v2Fixture() {
  const capture: CaptureSettings = {
    generation: `generation-${V2_ID}`,
    recipientFile: "/fixture/recipient.asc",
    recipientSha256: V2_HASH,
    recipientFingerprint: "A".repeat(40),
    exclusionsText: REQUIRED_EXCLUSIONS.join("\n"),
    sources: ROLE_ORDER.map((name, i) => ({
      name,
      uuid: `aaaaaaa${i}-1111-2222-3333-444444444444`,
      filesystem: name === "root"
        ? "ext4" as const
        : name.includes("efi")
        ? "vfat" as const
        : "xfs" as const,
      size: 1024 * (i + 1),
      ...(name === "root"
        ? { livePath: "/" as const }
        : name === "efi"
        ? { livePath: "/efi" as const }
        : {}),
    })),
  };
  const request: BackupV2Request = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId: `job-${V2_ID}`,
    captureId: capture.generation,
    periodKey: "2026-10-18",
    requestedAtUtc: V2_START,
    sourceRevision: "a".repeat(40),
    sourceConfigSha256: sourceConfigSha256(capture),
    recipientSha256: V2_HASH,
    recipientFingerprint: "A".repeat(40),
  };
  const envelope = { request, requestSha256: backupV2RequestSha256(request) };
  const unitName = `arch-vps-b2-v2-worker-${V2_ID}.service`,
    custody = {
      unitName,
      invocationId: "1".repeat(32),
      mainPid: 123,
      mainStartTicks: "456",
      cgroup: `/weekly.slice/weekly-backup.slice/${unitName}`,
    };
  const workerGate = validateBackupV2Gate({
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope,
    gateId: V2_GATE,
    sourceBootId: V2_ID,
    kind: "worker",
    unitName,
    custody,
    state: "ACTIVE",
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc: V2_START,
    updatedAtUtc: V2_NOW.toISOString(),
  });
  const verifierGate = validateBackupV2Gate({
    ...workerGate,
    gateId: V2_VERIFY,
    kind: "verify",
    unitName: unitName.replace("worker", "verify"),
    custody: null,
    state: "PENDING",
  });
  const settings = validateBackupV2WorkerSettings({
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    captureSettings: capture,
    B2Settings: {
      accessKeyId: "fixture-id",
      secretAccessKey: "fixture-secret",
      bucketId: "fixture-bucket",
      bucketName: "pavlovcik-arch-vps-backups",
    },
    workerGate,
    verifierGate,
    publicationAttemptId: V2_VERIFY,
  });
  const status = validateBackupV2Status({
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    gateId: workerGate.gateId,
    sourceBootId: workerGate.sourceBootId,
    custody,
    kind: "worker",
    phase: "CAPTURING_AND_UPLOADING",
    activeRoleAttempt: { role: "root", attemptId: V2_GATE },
    startedAtUtc: V2_START,
    updatedAtUtc: V2_NOW.toISOString(),
    finishedAtUtc: null,
    progress: {
      phase: "CAPTURING_AND_UPLOADING",
      observedMonotonicMs: 10,
      sourceBytes: 100,
      compressionInputBytes: 100,
      verifiedChunks: 1,
      decryptedBytes: 0,
      inventoryMembers: 2,
    },
    lease: {
      observedMonotonicMs: 10,
      usefulProgressAtMs: 9,
      usefulProgressExpiresAtMs: 120009,
      retryEpisode: null,
    },
    resultSha256: null,
  }, workerGate);
  const state = validateBackupV2ControllerState({
    schemaVersion: 2,
    format: "backup-v2-controller",
    legacy: { schemaVersion: 1, catalog: [] },
    catalog: [],
    job: {
      settings,
      phase: "WORKER",
      activeKind: "worker",
      predecessor: { format: "backup-v1", jobId: null, sha256: V2_HASH },
      workerGate,
      verifierGate,
      workerStatus: status,
      verifierStatus: null,
      workerResult: null,
      workerResultBytes: null,
      verified: null,
      updatedAtUtc: V2_NOW.toISOString(),
    },
  });
  const source: BackupV2ControllerObservation = {
    sourceBootId: V2_ID,
    unit: "RUNNING",
    identity: custody,
    status,
    resultBytes: null,
    tree: null,
  };
  const progress = {
    schemaVersion: 1,
    jobId: request.jobId,
    observedAtUtc: V2_NOW.toISOString(),
    state: "PROGRESSING",
    sample: { format: "backup-v2", processBound: true, v2Status: status },
  };
  return { request, envelope, workerGate, state, source, progress };
}
function acceptedV2Entry(oldCapture = false) {
  const { envelope } = v2Fixture(), r = envelope.request;
  const reference = (ordinal = 0, kind = "manifest") => ({
    object: {
      fileId: `file-${kind}-${ordinal}`,
      fileName: backupV2ObjectName(
        r.captureId,
        V2_GATE,
        kind as "manifest" | "receipt",
        ordinal,
        V2_VERIFY,
      ),
      contentLength: 17,
      contentSha1: "1".repeat(40),
      uploadTimestamp: 1,
      action: "upload",
      sha256: V2_HASH,
    },
    plaintextSha256: V2_HASH,
  });
  const captured = oldCapture
      ? "2026-10-11T04:10:00.000Z"
      : "2026-10-18T04:10:00.000Z",
    started = oldCapture
      ? "2026-10-11T04:06:00.000Z"
      : "2026-10-18T04:06:00.000Z";
  const inventory = createBackupV2InventorySummary();
  inventory.add({ path: new TextEncoder().encode("./etc/os-release") });
  const summary = inventory.finish();
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    resultSha256: V2_HASH,
    selectedRoot: {
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
        roles: BACKUP_V2_ROLES.map((role, i) => ({
          role,
          attemptId: V2_GATE,
          manifest: reference(i),
          captureStartedAtUtc: started,
          captureFinishedAtUtc: captured,
        })),
        metadata: [],
      },
    },
    receipt: {
      schemaVersion: 2,
      format: "backup-v2",
      captureId: r.captureId,
      root: reference(),
      verifiedAtUtc: "2026-10-18T04:20:00.000Z",
      recipientSha256: r.recipientSha256,
      recipientFingerprint: r.recipientFingerprint,
      verifierRevision: r.sourceRevision,
      configurationSha256: r.sourceConfigSha256,
      tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4.9" },
      archives: BACKUP_V2_ROLES.map((role) => ({
        role,
        format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
        ciphertextBytes: 17,
        ciphertextSha256: V2_HASH,
        compressedBytes: 1,
        compressedSha256: V2_HASH,
        inventory: role === "recovery" ? null : summary,
        inputComplete: true,
        integrityChecked: true,
        decompressionComplete: true,
        gpgExitCode: 0,
        zstdExitCode: 0,
        tarExitCode: 0,
      })),
      bootSamples: BACKUP_V2_BOOT_SAMPLES.map((s) => ({
        ...s,
        bytes: 1,
        sha256: V2_HASH,
      })),
      metadataSha256: V2_HASH,
      sourceIndependent: true,
      decryptedRestoreProved: true,
      machineBootRestoreProved: false,
    },
    receiptReference: reference(0, "receipt"),
    acceptedAtUtc: "2026-10-18T04:30:00.000Z",
  };
}
Deno.test("v2 watchdog requires actual advancing work and exact live custody beyond a twelve-hour request age", () => {
  const f = v2Fixture();
  if (
    !assessBackupV2Watchdog(f.state, f.workerGate, V2_NOW, f.source, f.progress)
      .healthy
  ) throw Error("Useful work should be visible");
  const reordered = Object.fromEntries(
    Object.entries(f.source.identity!).reverse(),
  ) as typeof f.source.identity;
  if (
    !assessBackupV2Watchdog(f.state, f.workerGate, V2_NOW, {
      ...f.source,
      identity: reordered,
    }, f.progress).healthy
  ) throw Error("Property order is not process identity");
  const later = new Date(V2_NOW.getTime() + 13 * 3600000),
    state = structuredClone(f.state),
    source = structuredClone(f.source),
    progress = structuredClone(f.progress);
  state.job!.workerStatus!.updatedAtUtc = later.toISOString();
  source.status = state.job!.workerStatus;
  progress.sample.v2Status.updatedAtUtc = later.toISOString();
  progress.observedAtUtc = later.toISOString();
  if (
    !assessBackupV2Watchdog(state, f.workerGate, later, source, progress)
      .healthy
  ) throw Error("No invented v1 whole-job deadline");
  for (
    const p of [undefined, { ...f.progress, state: "BASELINE" }, {
      ...f.progress,
      state: "UNKNOWN",
    }, { ...f.progress, sample: { ...f.progress.sample, processBound: false } }]
  ) {
    if (
      assessBackupV2Watchdog(f.state, f.workerGate, V2_NOW, f.source, p).healthy
    ) throw Error("Unknown work became healthy");
  }
  if (
    assessBackupV2Watchdog(f.state, f.workerGate, V2_NOW, {
      ...f.source,
      sourceBootId: V2_VERIFY,
    }, f.progress).healthy
  ) throw Error("Wrong boot accepted");
  if (
    assessBackupV2Watchdog(
      f.state,
      { ...f.workerGate, state: "CANCELLATION_BLOCKED" },
      V2_NOW,
      f.source,
      f.progress,
    ).healthy
  ) throw Error("Blocked gate became healthy");
});
Deno.test("v2 watchdog preserves stall, missing identity and old report failures", () => {
  const f = v2Fixture();
  for (
    const p of [
      { ...f.progress, state: "STALLED" },
      { ...f.progress, observedAtUtc: "2026-10-18T03:00:00.000Z" },
      { ...f.progress, jobId: "other" },
      {
        ...f.progress,
        sample: {
          ...f.progress.sample,
          v2Status: { ...f.progress.sample.v2Status, gateId: V2_VERIFY },
        },
      },
    ]
  ) {
    if (
      assessBackupV2Watchdog(f.state, f.workerGate, V2_NOW, f.source, p).healthy
    ) throw Error("Unproved progress accepted");
  }
  if (
    assessBackupV2Watchdog(f.state, null, V2_NOW, f.source, f.progress).healthy
  ) throw Error("Missing gate became healthy");
});
Deno.test("v2 due-period proof uses capture interval, not new acceptance or verification of an old capture", () => {
  const original = v2Fixture().state;
  const state = { ...original, job: null, catalog: [acceptedV2Entry()] };
  if (
    !acceptedBackupRuntimeCapture(state, V2_NOW).current ||
    !assessBackupV2Watchdog(state, null, V2_NOW).healthy
  ) throw Error("Accepted capture is missing");
  if (
    !assessBackupV2Watchdog(
      {
        ...state,
        catalog: [{ ...acceptedV2Entry(), acceptedAtUtc: V2_START }],
      },
      null,
      V2_NOW,
    ).healthy
  ) throw Error("Cross-host acceptance ordering was invented");
  if (
    assessBackupV2Watchdog(
      {
        ...state,
        catalog: [{
          ...acceptedV2Entry(),
          acceptedAtUtc: "2026-10-19T04:30:00.000Z",
        }],
      },
      null,
      V2_NOW,
    ).status !== "B2_BACKUP_ACCEPTANCE_UNKNOWN"
  ) throw Error("Future acceptance became missing or healthy");
  const old = { ...state, catalog: [acceptedV2Entry(true)] };
  if (
    acceptedBackupRuntimeCapture(old, V2_NOW).current ||
    assessBackupV2Watchdog(old, null, V2_NOW).healthy
  ) throw Error("Old capture was refreshed by verification");
  const legacyRequest = {
    schemaVersion: 1 as const,
    jobId: original.job!.settings.envelope.request.jobId,
    generation: original.job!.settings.envelope.request.captureId,
    periodKey: "2026-10-18",
    requestedAtUtc: V2_START,
    deadlineAtUtc: "2026-10-18T16:05:00.000Z",
    recipientSha256: V2_HASH,
    recipientFingerprint: "A".repeat(40),
    sourceRevision: "a".repeat(40),
    sourceConfigSha256:
      original.job!.settings.envelope.request.sourceConfigSha256,
  };
  const failed = {
    ...newJobState({
      request: legacyRequest,
      requestSha256: requestSha256Of(legacyRequest),
    }, V2_NOW),
    phase: "FAILED" as const,
    failure: { code: "CAPTURE_FAILED", atUtc: V2_NOW.toISOString() },
  };
  const preserved = JSON.stringify(failed),
    withFailed = { ...state, legacy: { ...state.legacy, job: failed } };
  if (
    !assessBackupV2Watchdog(withFailed, null, V2_NOW).healthy ||
    JSON.stringify(withFailed.legacy.job) !== preserved
  ) throw Error("Historical failure was rewritten or hid current acceptance");
  if (assessBackupV2Watchdog(state, v2Fixture().workerGate, V2_NOW).healthy) {
    throw Error("Held source gate was ignored");
  }
});

Deno.test("accepted backup retains prune stage reporting until controller cleanup completes", () => {
  const f = v2Fixture(),
    unitName = f.workerGate.unitName.replace("worker", "prune");
  const gate = validateBackupV2Gate({
    ...f.workerGate,
    kind: "prune",
    unitName,
    custody: {
      ...f.workerGate.custody!,
      unitName,
      cgroup: `/weekly.slice/weekly-backup.slice/${unitName}`,
    },
  });
  const status = validateBackupV2Status({
    ...f.source.status as object,
    kind: "prune",
    phase: "PRUNING",
    activeRoleAttempt: null,
    custody: gate.custody,
    progress: { ...f.progress.sample.v2Status.progress, phase: "PRUNING" },
  }, gate);
  const source = { ...f.source, identity: gate.custody, status };
  const control = {
    schemaVersion: 2,
    format: "backup-v2-retention-controller",
    input: {
      schemaVersion: 2,
      format: "backup-v2-prune",
      gate,
      transactionId: V2_GATE,
      stage: "PLAN",
    },
    gate,
    phase: "RUNNING",
    result: null,
  };
  const running = assessBackupV2Retention(
    f.envelope,
    gate,
    V2_NOW,
    control,
    source,
  );
  if (running.status !== "B2_RETENTION_PLAN_RUNNING" || !running.healthy) {
    throw Error("Prune work was hidden behind final backup status");
  }
  for (
    const phase of [
      "REQUESTED",
      "SETTLED",
      "PARTIAL",
      "CANCELLATION_BLOCKED",
    ] as const
  ) {
    const report = assessBackupV2Retention(f.envelope, null, V2_NOW, {
      ...control,
      phase,
    });
    if (report.status !== `B2_RETENTION_PLAN_${phase}` || report.healthy) {
      throw Error("Incomplete retention became healthy");
    }
  }
  const blocked = assessBackupV2Retention(
    f.envelope,
    { ...gate, state: "CANCELLATION_BLOCKED" },
    V2_NOW,
    control,
    source,
  );
  if (
    blocked.status !== "B2_RETENTION_PLAN_CANCELLATION_BLOCKED" ||
    blocked.healthy
  ) throw Error("Blocked prune became healthy");
  const complete = {
    ...control,
    input: { ...control.input, stage: "EXECUTE" },
    phase: "COMPLETE",
    result: {
      schemaVersion: 2,
      format: "backup-v2-prune-result",
      stage: "EXECUTE",
      state: "COMPLETE",
      gate,
      transactionId: V2_GATE,
      nativeCustodySha256: V2_HASH,
    },
  };
  if (
    !assessBackupV2Retention(f.envelope, null, V2_NOW, complete).healthy ||
    assessBackupV2Retention(f.envelope, gate, V2_NOW, complete).healthy ||
    assessBackupV2Retention(f.envelope, null, V2_NOW, {
      ...complete,
      result: null,
    }).healthy
  ) throw Error("Cleanup completion or held-gate distinction was lost");
  if (
    assessBackupV2Retention(f.envelope, gate, V2_NOW, undefined).healthy ||
    assessBackupV2Retention(f.envelope, gate, V2_NOW, {
        ...control,
        gate: { ...gate, gateId: V2_VERIFY },
      }).status !== "B2_RETENTION_UNKNOWN"
  ) throw Error("Unknown or mismatched retention was accepted");
});
