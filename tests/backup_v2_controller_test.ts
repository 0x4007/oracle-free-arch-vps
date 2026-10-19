// Capability fakes settle synchronously; no cloud, process or filesystem IO.
// deno-lint-ignore-file require-await
import {
  type CaptureSettings,
  REQUIRED_EXCLUSIONS,
  ROLE_ORDER,
} from "../scripts/backblaze-capture.ts";
import {
  buildRequestEnvelope,
  type ControllerState,
  GATE_PATH,
  newJobState,
  type PiDeps,
} from "../scripts/backblaze-file-backup.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ManifestRef,
  backupV2ObjectName,
  type BackupV2Receipt,
} from "../scripts/backup-v2-contract.ts";
import { backupV2SourceConfigSha256 } from "../scripts/backup-v2-metadata.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import {
  type BackupV2Gate,
  type BackupV2Request,
  backupV2RequestSha256,
  type BackupV2Result,
  type BackupV2Status,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import {
  backupV2ArtifactBytes,
  backupV2ArtifactSha256,
  backupV2ControlCacheDirectory,
  backupV2GateDirectory,
  type BackupV2VerifiedResult,
  BackupV2WorkerProgress,
  type BackupV2WorkerSettings,
  validateBackupV2WorkerSettings,
} from "../scripts/backup-v2-worker.ts";
import {
  backupRuntimeCatalog,
  type BackupV2ControllerCapabilities,
  type BackupV2ControllerObservation,
  type BackupV2ControllerState,
  backupV2LaunchArguments,
  backupV2ObservationProgram,
  backupV2PeriodSatisfied,
  backupV2PiReleaseRoot,
  backupV2RemoteProgram,
  type BackupV2RetentionControl,
  collectBackupV2Release,
  copyBackupV2Protection,
  realBackupV2ControllerCapabilities,
  resumeBackupV2ControllerJob,
  runBackupV2RetentionCycle,
  stepBackupV2Controller,
  validateBackupV2ControllerState,
} from "../scripts/backup-v2-controller.ts";
import { createBackupV2InventorySummary } from "../scripts/backup-v2-inventory.ts";
import {
  backupV2ProtectionPageName,
  buildBackupV2Protection,
} from "../scripts/backup-v2-protection.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}
function equal(a: unknown, b: unknown): void {
  assert(JSON.stringify(a) === JSON.stringify(b));
}
async function rejects(run: () => unknown) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed);
}
const uuid = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const START = "2026-10-18T10:00:00.000Z",
  END = "2026-10-18T10:01:00.000Z",
  SHA = "a".repeat(64);
function settings(requestedAtUtc = START): BackupV2WorkerSettings {
  const captureSettings: CaptureSettings = {
    generation: `generation-${uuid(1)}`,
    recipientFile: "/fixture/recipient.asc",
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
    exclusionsText: REQUIRED_EXCLUSIONS.join("\n") + "\n",
    sources: ROLE_ORDER.map((name, i) => ({
      name,
      uuid: `aaaaaaa${i}-1111-2222-3333-444444444444`,
      filesystem: name === "root"
        ? "ext4"
        : name.includes("efi")
        ? "vfat"
        : "xfs",
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
    jobId: `job-${uuid(1)}`,
    captureId: captureSettings.generation,
    periodKey: "2026-10-18",
    requestedAtUtc,
    sourceRevision: "a".repeat(40),
    sourceConfigSha256: backupV2SourceConfigSha256(captureSettings),
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
  };
  const envelope = { request, requestSha256: backupV2RequestSha256(request) };
  const gate = (kind: "worker" | "verify", n: number): BackupV2Gate => ({
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope,
    gateId: uuid(n),
    sourceBootId: uuid(5),
    kind,
    unitName: `arch-vps-b2-v2-${kind}-${uuid(1)}-${uuid(n)}.service`,
    custody: null,
    state: "PENDING",
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc: requestedAtUtc,
    updatedAtUtc: requestedAtUtc,
  });
  return validateBackupV2WorkerSettings({
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    captureSettings,
    B2Settings: {
      accessKeyId: "fixture",
      secretAccessKey: "fixture",
      bucketId: "fixture",
      bucketName: "pavlovcik-arch-vps-backups",
    },
    workerGate: gate("worker", 2),
    verifierGate: gate("verify", 3),
    publicationAttemptId: uuid(4),
  });
}
function bound(gate: BackupV2Gate): BackupV2Gate {
  return {
    ...gate,
    state: "ACTIVE",
    updatedAtUtc: END,
    custody: {
      unitName: gate.unitName,
      invocationId: (gate.kind === "worker" ? "1" : "2").repeat(32),
      mainPid: gate.kind === "worker" ? 101 : 102,
      mainStartTicks: "123",
      cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${gate.unitName}`,
    },
  };
}
function observation(gate: BackupV2Gate): BackupV2ControllerObservation {
  const active = bound(gate);
  return {
    sourceBootId: gate.sourceBootId,
    unit: "RUNNING",
    identity: active.custody,
    status: status(active, "PREFLIGHT"),
    resultBytes: null,
    nativeCustodySha256: SHA,
    managerNamespaceReferences: 0,
    tree: {
      identity: active.custody!,
      observedMonotonicMs: 10,
      mainPid: active.custody!.mainPid,
      controlPid: 0,
      cgroupPopulated: true,
      descendants: 1,
      escapedProcesses: 0,
      namespaceReferences: 0,
      openPipelineHandles: 0,
      pendingOperations: 0,
      sourceLockFree: false,
    },
  };
}
function status(
  gate: BackupV2Gate,
  phase: BackupV2Status["phase"],
  bytes: Uint8Array | null = null,
): BackupV2Status {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: gate.envelope,
    gateId: gate.gateId,
    sourceBootId: gate.sourceBootId,
    custody: gate.custody!,
    kind: gate.kind,
    phase,
    activeRoleAttempt: null,
    startedAtUtc: START,
    updatedAtUtc: END,
    finishedAtUtc: bytes ? END : null,
    progress: {
      phase,
      observedMonotonicMs: 10,
      sourceBytes: 0,
      compressionInputBytes: 0,
      verifiedChunks: 0,
      decryptedBytes: 0,
      inventoryMembers: 0,
    },
    lease: {
      observedMonotonicMs: 10,
      usefulProgressAtMs: 10,
      usefulProgressExpiresAtMs: 120010,
      retryEpisode: null,
    },
    resultSha256: bytes ? backupV2ArtifactSha256(bytes) : null,
  };
}
function reference(
  kind: "manifest" | "receipt" = "manifest",
  n = 0,
): BackupV2ManifestRef {
  return {
    object: {
      fileId: `file-${kind}-${n}`,
      fileName: backupV2ObjectName(
        settings().envelope.request.captureId,
        uuid(4),
        kind,
        n,
        uuid(20 + n),
      ),
      contentLength: 17,
      contentSha1: "1".repeat(40),
      sha256: SHA,
      uploadTimestamp: 1,
      action: "upload",
    },
    plaintextSha256: SHA,
  };
}
function workerResult(gate: BackupV2Gate): BackupV2Result {
  const r = gate.envelope.request;
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: gate.envelope,
    gateId: gate.gateId,
    sourceBootId: gate.sourceBootId,
    custody: gate.custody!,
    finishedAtUtc: END,
    nativeCustodySha256: SHA,
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
          attemptId: uuid(4),
          manifest: reference("manifest", i),
          captureStartedAtUtc: START,
          captureFinishedAtUtc: END,
        })),
        metadata: [],
      },
    },
  };
}
function receipt(result: BackupV2Result): BackupV2Receipt {
  const summary = createBackupV2InventorySummary();
  summary.add({ path: new TextEncoder().encode("./etc/os-release") });
  const inventory = summary.finish(), r = result.envelope.request;
  return {
    schemaVersion: 2,
    format: "backup-v2",
    captureId: r.captureId,
    root: result.selectedRoot.reference,
    verifiedAtUtc: END,
    recipientSha256: r.recipientSha256,
    recipientFingerprint: r.recipientFingerprint,
    verifierRevision: r.sourceRevision,
    configurationSha256: r.sourceConfigSha256,
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
    bootSamples: BACKUP_V2_BOOT_SAMPLES.map((s) => ({
      ...s,
      bytes: 1,
      sha256: SHA,
    })),
    metadataSha256: SHA,
    sourceIndependent: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
}
function legacy(): ControllerState {
  const r = settings().envelope.request;
  return {
    schemaVersion: 1,
    catalog: [],
    job: {
      ...newJobState(
        buildRequestEnvelope({
          jobUuid: uuid(99),
          periodKey: r.periodKey,
          requestedAtUtc: r.requestedAtUtc,
          recipientSha256: r.recipientSha256,
          recipientFingerprint: r.recipientFingerprint,
          sourceRevision: r.sourceRevision,
          sourceConfigSha256: r.sourceConfigSha256,
        }),
        new Date(START),
      ),
      phase: "FAILED",
      failure: { code: "CAPTURE_FAILED", atUtc: START },
    },
  };
}
function fixture() {
  let live: BackupV2Gate | null = null,
    current = observation(settings().workerGate),
    close: "CLOSED" | "CANCELLATION_BLOCKED" = "CLOSED",
    bridge: "READY" | "PENDING" | "CANCELLATION_BLOCKED" = "READY";
  const calls: string[] = [],
    cleared = new Set<string>(),
    saved: BackupV2ControllerState[] = [];
  const deps: BackupV2ControllerCapabilities = {
    now: () => new Date(END),
    persist: async (s) => {
      saved.push(structuredClone(s));
    },
    archive: async () => {
      calls.push("archive");
    },
    gate: {
      read: async () => live,
      replace: async (expected, next) => {
        equal(live, expected);
        live = next;
        if (!next) cleared.add(expected!.gateId);
        calls.push(next ? "gate" : "clear");
      },
      cleared: async (g) => cleared.has(g.gateId),
    },
    create: async () => settings(),
    admit: async () => {
      calls.push("admit");
    },
    install: async () => {
      calls.push("install");
    },
    launch: async (_s, k) => {
      calls.push(`launch:${k}`);
    },
    observe: async () => structuredClone(current),
    acknowledge: async () => {
      calls.push("ack");
    },
    verifierInput: async () => {
      calls.push("verifier-input");
    },
    preserveProtection: async () => {
      calls.push("protect");
    },
    stop: async () => {
      calls.push("stop");
    },
    cancel: async () => "CANCELLATION_BLOCKED",
    bridge: { ensure: async () => bridge, close: async () => close },
  };
  return {
    deps,
    calls,
    saved,
    set live(value: BackupV2Gate | null) {
      live = value;
    },
    get live() {
      return live;
    },
    set observation(value: BackupV2ControllerObservation) {
      current = value;
    },
    get observation() {
      return current;
    },
    set close(value: typeof close) {
      close = value;
    },
    set bridge(value: typeof bridge) {
      bridge = value;
    },
  };
}
async function launched(f = fixture()) {
  let state = await stepBackupV2Controller(legacy(), f.deps);
  state = await stepBackupV2Controller(state, f.deps);
  state = await stepBackupV2Controller(state, f.deps);
  return { f, state };
}
function completeObservation(
  gate: BackupV2Gate,
  value: unknown,
  phase: BackupV2Status["phase"],
): BackupV2ControllerObservation {
  const bytes = backupV2ArtifactBytes(value), o = observation(gate);
  o.unit = "EXITED";
  o.status = status(gate, phase, bytes);
  o.resultBytes = bytes;
  o.tree = {
    ...o.tree!,
    mainPid: 0,
    cgroupPopulated: false,
    descendants: 0,
    sourceLockFree: true,
  };
  return o;
}
async function workerDone(
  f: ReturnType<typeof fixture>,
  state: BackupV2ControllerState,
) {
  const gate = state.job!.workerGate;
  f.observation = completeObservation(
    gate,
    workerResult(gate),
    "CLOUD_COMPLETE",
  );
  state = await stepBackupV2Controller(state, f.deps);
  return await stepBackupV2Controller(state, f.deps);
}

Deno.test("bounded controller preserves FAILED v1 and snapshots predecessor before one new due request", async () => {
  const f = fixture(), old = legacy(), bytes = backupV2ArtifactBytes(old);
  const state = await stepBackupV2Controller(old, f.deps);
  equal(backupV2ArtifactBytes(state.legacy), bytes);
  equal(f.calls, ["admit", "archive"]);
  equal(state.job!.predecessor.sha256, backupV2ArtifactSha256(bytes));
  assert(!("deadlineAtUtc" in state.job!.settings.envelope.request));
  equal(backupRuntimeCatalog(state), []);
  equal(backupRuntimeCatalog(old), []);
  await rejects(() =>
    validateBackupV2ControllerState({ ...state, unexpected: true })
  );
});
Deno.test("controller binds external invocation and recovers crash after gate binding before state write", async () => {
  const f = fixture();
  let state = await stepBackupV2Controller(legacy(), f.deps);
  state = await stepBackupV2Controller(state, f.deps);
  f.live = bound(state.job!.workerGate);
  state = await stepBackupV2Controller(state, f.deps);
  equal(state.job!.workerGate, f.live);
  assert(f.calls.includes("ack"));
  assert(!f.calls.includes("launch:verify"));
});
Deno.test("missing unit and zero counters cannot clear gate or start a replacement", async () => {
  const { f, state } = await launched();
  f.observation = {
    ...f.observation,
    unit: "ABSENT",
    identity: null,
    tree: null,
  };
  const blocked = await stepBackupV2Controller(state, f.deps);
  equal(blocked.job!.phase, "CANCELLATION_BLOCKED");
  assert(f.live !== null);
  equal(f.calls.filter((c) => c.startsWith("launch:")), ["launch:worker"]);
});
Deno.test("wrong custody status rejects before acceptance and leaves gate", async () => {
  const { f, state } = await launched();
  const bad = status(state.job!.workerGate, "PREFLIGHT");
  bad.custody = { ...bad.custody, invocationId: "e".repeat(32) };
  f.observation = { ...f.observation, status: bad };
  await rejects(() => stepBackupV2Controller(state, f.deps));
  assert(f.live !== null);
  equal(state.catalog.length, 0);
});
Deno.test("terminal status waits for actual process exit; result hash and tree must agree", async () => {
  const { f, state } = await launched();
  const gate = state.job!.workerGate,
    result = workerResult(gate),
    o = completeObservation(gate, result, "CLOUD_COMPLETE");
  o.unit = "RUNNING";
  o.tree!.mainPid = gate.custody!.mainPid;
  f.observation = o;
  let next = await stepBackupV2Controller(state, f.deps);
  equal(next.job!.phase, "WORKER");
  o.unit = "EXITED";
  o.tree!.mainPid = 0;
  o.resultBytes = backupV2ArtifactBytes({ ...result, extra: true });
  f.observation = o;
  next = await stepBackupV2Controller(next, f.deps);
  equal(next.job!.phase, "CANCELLATION_BLOCKED");
  assert(f.live !== null);
});
Deno.test("complete cloud receipt waits for bridge closure and accepted period never duplicates", async () => {
  let { f, state } = await launched();
  state = await workerDone(f, state);
  equal(state.job!.phase, "VERIFY_REQUESTED");
  state = await stepBackupV2Controller(state, f.deps);
  f.observation = observation(state.job!.verifierGate);
  f.bridge = "PENDING";
  const before = f.calls.filter((c) => c === "ack").length;
  state = await stepBackupV2Controller(state, f.deps);
  equal(f.calls.filter((c) => c === "ack").length, before);
  f.bridge = "READY";
  state = await stepBackupV2Controller(state, f.deps);
  const g = state.job!.verifierGate,
    w = state.job!.workerResult!,
    verified: BackupV2VerifiedResult = {
      schemaVersion: 2,
      format: "backup-v2-verified",
      envelope: g.envelope,
      gateId: g.gateId,
      sourceBootId: g.sourceBootId,
      custody: g.custody!,
      workerResultSha256: backupV2ArtifactSha256(
        new Uint8Array(state.job!.workerResultBytes!),
      ),
      selectedRoot: w.selectedRoot,
      receipt: receipt(w),
      receiptReference: reference("receipt"),
      finishedAtUtc: END,
      nativeCustodySha256: SHA,
      protectedGraph: buildBackupV2Protection(w.selectedRoot.reference, [
        reference("receipt").object,
        ...w.selectedRoot.root.roles.map((role) => role.manifest.object),
      ]).descriptor,
    };
  f.observation = completeObservation(g, verified, "ACCEPTED");
  state = await stepBackupV2Controller(state, f.deps);
  equal(state.catalog.length, 0);
  state = await stepBackupV2Controller(state, f.deps);
  equal(state.job!.phase, "COMPLETE");
  equal(state.catalog.length, 1);
  assert(f.calls.includes("protect"));
  const accepted = state.catalog[0];
  assert(backupV2PeriodSatisfied(state, new Date(END)));
  state = await stepBackupV2Controller(state, f.deps);
  equal(state.catalog[0], accepted);
  equal(f.calls.filter((c) => c === "launch:worker").length, 1);
});
Deno.test("bridge closure failure keeps verifier gate and no accepted catalog", async () => {
  let { f, state } = await launched();
  state = await workerDone(f, state);
  state = await stepBackupV2Controller(state, f.deps);
  f.observation = observation(state.job!.verifierGate);
  state = await stepBackupV2Controller(state, f.deps);
  const g = state.job!.verifierGate, w = state.job!.workerResult!;
  const verified = {
    schemaVersion: 2,
    format: "backup-v2-verified",
    envelope: g.envelope,
    gateId: g.gateId,
    sourceBootId: g.sourceBootId,
    custody: g.custody,
    workerResultSha256: backupV2ArtifactSha256(
      new Uint8Array(state.job!.workerResultBytes!),
    ),
    selectedRoot: w.selectedRoot,
    receipt: receipt(w),
    receiptReference: reference("receipt"),
    finishedAtUtc: END,
    nativeCustodySha256: SHA,
    protectedGraph: buildBackupV2Protection(w.selectedRoot.reference, [
      reference("receipt").object,
      ...w.selectedRoot.root.roles.map((role) => role.manifest.object),
    ]).descriptor,
  };
  f.observation = completeObservation(g, verified, "ACCEPTED");
  state = await stepBackupV2Controller(state, f.deps);
  f.close = "CANCELLATION_BLOCKED";
  state = await stepBackupV2Controller(state, f.deps);
  equal(state.job!.phase, "CANCELLATION_BLOCKED");
  equal(state.catalog.length, 0);
  assert(f.live !== null);
});
Deno.test("actual generated source launch is finite notify custody with pinned scoped FFI", () => {
  const s = settings(), argv = backupV2LaunchArguments(s, "worker");
  for (const kind of ["worker", "verify"] as const) {
    equal(
      backupV2LaunchArguments(s, kind).filter((arg) =>
        arg.startsWith("--property=Memory")
      ),
      [
        "--property=MemoryHigh=infinity",
        "--property=MemoryMax=6255601664",
        "--property=MemorySwapMax=0",
      ],
    );
    equal(
      backupV2LaunchArguments(s, kind).filter((arg) =>
        arg.startsWith("--allow-sys")
      ),
      ["--allow-sys=statfs"],
    );
  }
  for (
    const part of [
      "--property=Type=notify",
      "--property=NotifyAccess=main",
      "--property=RemainAfterExit=yes",
      "--property=RuntimeMaxSec=30000ms",
      "--property=LimitCORE=0",
      `--property=Environment=DENO_DIR=/var/tmp/arch-vps-file-backup-runtime/jobs/${s.envelope.request.jobId}/deno-cache`,
      "--no-code-cache",
      "--allow-ffi=/usr/lib/libsystemd.so.0",
    ]
  ) assert(argv.includes(part));
  const runGrant = argv.find((arg) => arg.startsWith("--allow-run="))!;
  for (
    const tool of [
      "/bin/sh",
      "/usr/bin/flock",
      "/usr/bin/systemctl",
      "/usr/bin/sha256sum",
    ]
  ) assert(runGrant.split(/[=,]/).includes(tool));
  assert(
    argv.find((arg) => arg.startsWith("--allow-read="))!.split(/[=,]/).includes(
      "/var/tmp/arch-vps-file-backup-runtime",
    ),
  );
  assert(
    !argv.includes("-A") && !argv.includes("--allow-env") &&
      !argv.includes("--allow-ffi"),
  );
  const active = bound(s.workerGate);
  assert(backupV2GateDirectory(active).endsWith(active.custody!.invocationId));
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  const program = backupV2ObservationProgram(active);
  new AsyncFunction(program);
  assert(program.includes("observeBackupV2Kernel(gate,undefined,options)"));
  assert(
    program.includes(
      `${s.envelope.request.sourceRevision}/scripts/backup-v2-kernel.ts`,
    ),
  );
  assert(
    !program.includes('Deno.readTextFile("/proc') &&
      !program.includes('Deno.readDir("/proc'),
  );
  assert(
    !argv.find((arg) => arg.startsWith("--allow-read="))!.includes("/proc"),
  );
});
Deno.test("root control helpers use each exact job cache with unchanged read-only script grants", async () => {
  const s = settings(), jobId = s.envelope.request.jobId;
  const cache = backupV2ControlCacheDirectory(jobId);
  const program = backupV2RemoteProgram(jobId, "console.log('control')");
  assert(program.includes(`DENO_DIR='${cache}' /usr/local/bin/deno run`));
  assert(
    program.includes("--no-code-cache") && program.includes("--cached-only"),
  );
  assert(
    !program.includes("--allow-write") && !program.includes("/root") &&
      !program.includes("HOME="),
  );
  assert(
    backupV2RemoteProgram(jobId.replace(/.$/, "9"), "").includes(
      "/control-cache-" + jobId.replace(/.$/, "9"),
    ),
  );
  await rejects(() => backupV2RemoteProgram("../another-job", ""));
  const scripts: string[] = [];
  const deps = {
    remote: {
      root: async (script: string) => {
        scripts.push(script);
        return { code: 0, stdout: "", stderr: "" };
      },
    },
  } as unknown as PiDeps;
  await realBackupV2ControllerCapabilities(deps, fixture().deps.bridge)
    .acknowledge(bound(s.workerGate));
  equal(scripts.length, 1);
  assert(scripts[0].includes(`DENO_DIR='${cache}' /usr/local/bin/deno run`));
  assert(scripts[0].includes("--no-code-cache"));
});
Deno.test("worker progress rejects reused counters and invocation paths retain old attempts", async () => {
  const p = new BackupV2WorkerProgress(),
    active = { role: "root" as const, attemptId: uuid(9) };
  p.capture({ role: "root", kind: "source", bytes: 100, members: 0 }, active);
  p.capture({ role: "root", kind: "source", bytes: 150, members: 0 }, active);
  equal(p.snapshot(1).sourceBytes, 150);
  await rejects(() =>
    p.capture({ role: "root", kind: "source", bytes: 149, members: 0 }, active)
  );
  const a = bound(settings().workerGate),
    b = { ...a, custody: { ...a.custody!, invocationId: "3".repeat(32) } };
  assert(backupV2GateDirectory(a) !== backupV2GateDirectory(b));
});

Deno.test("verification exports decompression work after compressed input ends", () => {
  const progress = new BackupV2WorkerProgress();
  progress.verification({
    role: "root",
    pass: 1,
    kind: "compressedPlaintext",
    bytes: 50,
  });
  progress.verification({
    role: "root",
    pass: 1,
    kind: "decoded",
    bytes: 100000,
  });
  const before = progress.snapshot(1);
  progress.verification({
    role: "root",
    pass: 1,
    kind: "decoded",
    bytes: 200000,
  });
  const after = progress.snapshot(2);
  equal(after.decryptedBytes, before.decryptedBytes);
  equal(after.decodedBytes! - before.decodedBytes!, 100000);
});

Deno.test("immutable release closure includes dynamic/type-only imports and refuses unpinned modules", async () => {
  const files = new Map(
    [
      [
        "scripts/entry.ts",
        'import type { X } from "./types.ts";\nawait import("./leaf.ts");',
      ],
      ["scripts/types.ts", "export interface X {}"],
      ["scripts/leaf.ts", 'import "./types.ts";\nexport {};'],
    ].map(([path, text]) => [path, new TextEncoder().encode(text)]),
  );
  const hashes = Object.fromEntries(
      [...files].map(([path, bytes]) => [path, backupV2ArtifactSha256(bytes)]),
    ),
    read = async (path: string) => {
      assert(files.has(path));
      return files.get(path)!;
    };
  const value = await collectBackupV2Release(
    "a".repeat(40),
    ["scripts/entry.ts"],
    read,
    hashes,
  );
  equal(value.files.map((f) => f.path), [
    "scripts/entry.ts",
    "scripts/leaf.ts",
    "scripts/types.ts",
  ]);
  assert(
    backupV2PiReleaseRoot("a".repeat(40)).endsWith(
      "/.private/file-backup/runtime/releases/" + "a".repeat(40),
    ),
  );
  await rejects(() =>
    collectBackupV2Release("a".repeat(40), ["scripts/entry.ts"], read, {
      ...hashes,
      "scripts/leaf.ts": "0".repeat(64),
    })
  );
  files.set(
    "scripts/entry.ts",
    new TextEncoder().encode('import "../outside.ts";'),
  );
  await rejects(() =>
    collectBackupV2Release("a".repeat(40), ["scripts/entry.ts"], read, {
      ...hashes,
      "scripts/entry.ts": backupV2ArtifactSha256(
        files.get("scripts/entry.ts")!,
      ),
    })
  );
});
Deno.test("real stop adapter retains terminal proof before unload and clears exact gate after fresh kernel settlement", async () => {
  const g = bound(settings().workerGate),
    files = new Map<string, unknown>([[GATE_PATH, g]]),
    events: string[] = [];
  let current = completeObservation(g, workerResult(g), "CLOUD_COMPLETE");
  current.tree!.namespaceReferences = 1;
  current.managerNamespaceReferences = 1;
  const pi = {
    now: () => new Date(END),
    private: {
      read: async (path: string) => files.get(path),
      write: async (path: string, value: unknown) => {
        files.set(path, structuredClone(value));
        events.push("proof");
      },
    },
    remote: {
      root: async (script: string) => {
        if (script.includes("\nsystemctl stop ")) {
          events.push("stop");
          current = {
            ...current,
            unit: "ABSENT",
            managerNamespaceReferences: 0,
            tree: { ...current.tree!, namespaceReferences: 0 },
          };
          return { code: 0, stdout: "", stderr: "" };
        }
        return {
          code: 0,
          stdout: JSON.stringify({
            ...current,
            resultBytes: current.resultBytes ? [...current.resultBytes] : null,
          }),
          stderr: "",
        };
      },
    },
  } as unknown as PiDeps;
  const bridge = fixture().deps.bridge,
    cap = realBackupV2ControllerCapabilities(pi, bridge, async (path) => {
      events.push("remove");
      files.delete(path);
    });
  await cap.stop(g);
  equal(events, ["proof", "stop", "proof"]);
  await cap.gate.replace(g, null);
  equal(events, ["proof", "stop", "proof", "remove"]);
  assert(await cap.gate.cleared(g));
  files.clear();
  await rejects(() => cap.stop(g));
});
Deno.test("explicit verifier resume preserves selected cloud root and original intervals", async () => {
  let { f, state } = await launched();
  state = await workerDone(f, state);
  state = await stepBackupV2Controller(state, f.deps);
  f.observation = observation(state.job!.verifierGate);
  state = await stepBackupV2Controller(state, f.deps);
  const failed = structuredClone(state);
  failed.job!.phase = "FAILED";
  const gate = failed.job!.verifierGate;
  await f.deps.gate.replace(gate, null);
  const root = structuredClone(failed.job!.workerResult);
  const next = await resumeBackupV2ControllerJob(failed, f.deps);
  equal(next.job!.phase, "VERIFY_REQUESTED");
  equal(next.job!.workerResult, root);
  equal(next.job!.workerResultBytes, failed.job!.workerResultBytes);
  equal(failed.job!.phase, "FAILED");
});

Deno.test("post-stop namespace holders or changed native journal retain the exact gate", async () => {
  for (const issue of ["namespace", "journal"] as const) {
    const gate = bound(settings().workerGate),
      files = new Map<string, unknown>([[GATE_PATH, gate]]);
    let current = completeObservation(
      gate,
      workerResult(gate),
      "CLOUD_COMPLETE",
    );
    current.tree!.namespaceReferences = 1;
    current.managerNamespaceReferences = 1;
    const expected = {
      resultSha256: backupV2ArtifactSha256(current.resultBytes!),
      nativeCustodySha256: SHA,
    };
    const deps = {
      now: () => new Date(END),
      private: {
        read: async (path: string) => files.get(path),
        write: async (path: string, value: unknown) => {
          files.set(path, structuredClone(value));
        },
      },
      remote: {
        root: async (script: string) => {
          if (script.includes("\nsystemctl stop ")) {
            current = {
              ...current,
              unit: "ABSENT",
              managerNamespaceReferences: 0,
              tree: {
                ...current.tree!,
                namespaceReferences: issue === "namespace" ? 1 : 0,
              },
              nativeCustodySha256: issue === "journal" ? "e".repeat(64) : SHA,
            };
            return { code: 0, stdout: "", stderr: "" };
          }
          return {
            code: 0,
            stdout: JSON.stringify({
              ...current,
              resultBytes: current.resultBytes
                ? [...current.resultBytes]
                : null,
            }),
            stderr: "",
          };
        },
      },
    } as unknown as PiDeps;
    const caps = realBackupV2ControllerCapabilities(
      deps,
      fixture().deps.bridge,
      async (path) => {
        files.delete(path);
      },
    );
    await caps.stop(gate, expected);
    await rejects(() => caps.gate.replace(gate, null));
    assert(files.has(GATE_PATH));
  }
});

Deno.test("only manager-held namespaces permit the exact successful unit stop", async () => {
  const gate = bound(settings().workerGate),
    current = completeObservation(gate, workerResult(gate), "CLOUD_COMPLETE");
  current.tree!.namespaceReferences = 1;
  current.managerNamespaceReferences = 0;
  const writes: unknown[] = [];
  const deps = {
    now: () => new Date(END),
    private: {
      read: async () => undefined,
      write: async (_path: string, value: unknown) => {
        writes.push(value);
      },
    },
    remote: {
      root: async () => ({
        code: 0,
        stdout: JSON.stringify({
          ...current,
          resultBytes: [...current.resultBytes!],
        }),
        stderr: "",
      }),
    },
  } as unknown as PiDeps;
  const caps = realBackupV2ControllerCapabilities(deps, fixture().deps.bridge);
  await rejects(() => caps.stop(gate));
  equal(writes, []);
});

Deno.test("failed exact stop never records completed custody or permits gate release", async () => {
  const gate = bound(settings().workerGate),
    current = completeObservation(gate, workerResult(gate), "CLOUD_COMPLETE");
  const files = new Map<string, unknown>([[GATE_PATH, gate]]);
  const deps = {
    now: () => new Date(END),
    private: {
      read: async (path: string) => files.get(path),
      write: async (path: string, value: unknown) => {
        files.set(path, structuredClone(value));
      },
    },
    remote: {
      root: async (script: string) =>
        script.includes("\nsystemctl stop ")
          ? { code: 1, stdout: "", stderr: "stop failed" }
          : {
            code: 0,
            stdout: JSON.stringify({
              ...current,
              resultBytes: [...current.resultBytes!],
            }),
            stderr: "",
          },
    },
  } as unknown as PiDeps;
  const caps = realBackupV2ControllerCapabilities(deps, fixture().deps.bridge);
  await rejects(() => caps.stop(gate));
  await rejects(() => caps.gate.replace(gate, null));
  assert(
    [...files.values()].every((value) =>
      !(value as { exactStop?: unknown }).exactStop
    ),
  );
  assert(files.has(GATE_PATH));
});

Deno.test("protected graph copy checks every bounded page and complete direct references before descriptor publication", async () => {
  const selected = workerResult(bound(settings().workerGate)).selectedRoot,
    receiptReference = reference("receipt");
  const objects = [
    receiptReference.object,
    ...selected.root.roles.map((role) => role.manifest.object),
    ...Array.from(
      { length: 110 },
      (_, ordinal) => reference("manifest", ordinal + 50).object,
    ),
  ];
  for (const defect of [null, "hash", "receipt"] as const) {
    const graph = buildBackupV2Protection(
      selected.reference,
      defect === "receipt"
        ? objects.filter((object) =>
          object.fileId !== receiptReference.object.fileId
        )
        : objects,
    );
    const files = new Map<string, Uint8Array>([
      ["manifest.json", graph.manifestBytes],
      ...graph.pages.map((page) =>
        [backupV2ProtectionPageName(page.value.pageIndex), page.bytes] as [
          string,
          Uint8Array,
        ]
      ),
    ]);
    const copied = new Map<string, Uint8Array>();
    const verified = {
      selectedRoot: selected,
      receiptReference,
      protectedGraph: graph.descriptor,
    } as BackupV2VerifiedResult;
    const operation = () =>
      copyBackupV2Protection(verified, {
        read(name) {
          const bytes = files.get(name);
          if (!bytes) throw Error("Missing graph page");
          return Promise.resolve(
            defect === "hash" && name.endsWith("00000001.json")
              ? new Uint8Array([1])
              : bytes,
          );
        },
        write(name, bytes) {
          copied.set(name, bytes.slice());
          return Promise.resolve();
        },
      });
    if (defect) {
      await rejects(operation);
      assert(!copied.has("descriptor.json"));
    } else {
      equal(await operation(), graph.descriptor);
      assert(copied.size === graph.pages.length + 2);
      equal([...copied.get("manifest.json")!], [...graph.manifestBytes]);
    }
  }
});

Deno.test("managed retention persists launch intent once and binds cold source custody before ACK", async () => {
  const s = settings(),
    pending = {
      ...s.workerGate,
      kind: "prune" as const,
      unitName: s.workerGate.unitName.replace("-worker-", "-prune-"),
    };
  const f = fixture(), calls: string[] = [];
  let live: BackupV2Gate | null = null;
  let control = {
    schemaVersion: 2,
    format: "backup-v2-retention-controller",
    phase: "REQUESTED",
    gate: pending,
    result: null,
    input: {
      schemaVersion: 2,
      format: "backup-v2-prune",
      gate: pending,
      transactionId: uuid(18),
      stage: "PLAN",
      plan: null,
      graphs: [],
      snapshot: {
        catalog: [],
        custody: {
          lockId: GATE_SOURCE_LOCK_PATH,
          sourceBootId: pending.sourceBootId,
          sourceSettled: true,
        },
        receipts: [],
        protection: {
          acceptedRoots: [],
          activeObjects: [],
          sealedRoleManifests: [],
          unresolvedPuts: [],
        },
      },
    },
  } as BackupV2RetentionControl;
  // Acceptance is upstream; this fixture isolates the managed-stage crash seam.
  const state = {
    job: { phase: "COMPLETE", settings: s, verified: { protectedGraph: {} } },
    catalog: [{}, {}, {}, {}],
  } as unknown as BackupV2ControllerState;
  let observed = {
    sourceBootId: pending.sourceBootId,
    unit: "ABSENT",
    identity: null,
    status: null,
    resultBytes: null,
    tree: null,
  } as BackupV2ControllerObservation;
  const pi = {
    now: () => new Date(END),
    private: {
      read: async () => structuredClone(control),
      write: async (_path: string, value: unknown) => {
        control = structuredClone(value) as BackupV2RetentionControl;
        calls.push(`save:${control.phase}`);
      },
    },
    remote: {
      root: async (script: string) => {
        calls.push(script.includes("systemd-run") ? "launch" : "install");
        return { code: 0, stdout: "", stderr: "" };
      },
    },
  } as unknown as PiDeps;
  const caps: BackupV2ControllerCapabilities = {
    ...f.deps,
    gate: {
      read: async () => live,
      replace: async (expected, next) => {
        equal(live, expected);
        live = next;
        calls.push(next?.custody ? "bind" : "gate");
      },
      cleared: async () => false,
    },
    observe: async () => observed,
    acknowledge: async () => {
      calls.push("ack");
    },
  };
  await runBackupV2RetentionCycle(state, pi, caps);
  equal(calls, ["install", "gate", "save:RUNNING", "launch"]);
  observed = { ...observed, unit: "STARTING" };
  assert((await runBackupV2RetentionCycle(state, pi, caps))!.healthy);
  equal(calls.filter((call) => call === "launch").length, 1);
  observed = observation(pending);
  await runBackupV2RetentionCycle(state, pi, caps);
  assert(control.gate.custody !== null);
  assert(calls.indexOf("bind") < calls.indexOf("ack"));
  equal(calls.filter((call) => call === "launch").length, 1);
  const argv = backupV2LaunchArguments(s, "prune", pending);
  equal(
    argv.filter((arg) => arg.startsWith("--property=Memory")),
    [
      "--property=MemoryHigh=infinity",
      "--property=MemoryMax=6255601664",
      "--property=MemorySwapMax=0",
    ],
  );
  equal(
    argv.filter((arg) => arg.startsWith("--allow-sys")),
    ["--allow-sys=statfs"],
  );
  assert(argv.at(-1)!.endsWith("/scripts/backup-v2-worker.ts"));
  assert(
    argv.includes("--property=Type=notify") &&
      argv.includes("--property=CPUWeight=1"),
  );
});

Deno.test("verification work bounds cover replay without enlarging source admission", () => {
  const progress = new BackupV2WorkerProgress(), gib = 1024 ** 3;
  for (const pass of [1, 2]) {
    progress.verification({
      role: "root",
      pass,
      kind: "compressedPlaintext",
      bytes: 200 * gib,
    });
    progress.verification({
      role: "root",
      pass,
      kind: "decoded",
      bytes: 600 * gib,
    });
  }
  const value = progress.snapshot(1);
  equal(value.decodedBytes, 1200 * gib);
  equal(value.decryptedBytes, 400 * gib);
  equal(value.compressionInputBytes, 0);
});

Deno.test("initial persistence samples time after asynchronous request creation", async () => {
  const f = fixture();
  let clock = Date.parse(END);
  f.deps.now = () => new Date(clock);
  f.deps.create = async () => {
    clock += 1000;
    return settings(new Date(clock).toISOString());
  };
  const state = await stepBackupV2Controller(legacy(), f.deps);
  equal(state.job!.updatedAtUtc, new Date(clock).toISOString());
  equal(
    state.job!.settings.envelope.request.requestedAtUtc,
    state.job!.updatedAtUtc,
  );
});
