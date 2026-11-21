/** Bounded Pi reconciliation. Source work and its decrypt bridge have their own
 * managed leases; a controller attempt never owns their process lifetime. */
import { isDeepStrictEqual } from "node:util";
import {
  B2_REPORT_PATH,
  type BackblazeRunReport,
  backblazeScheduledClaim,
  BACKUP_BASE,
  BACKUP_RUNTIME_BASE,
  CONTROLLER_LOCK_PATH,
  CONTROLLER_STATE_PATH,
  type ControllerState,
  GATE_PATH,
  JOBS_RUNTIME_ROOT,
  loadDeployment,
  loadSourceConfig,
  MANIFEST_PATH,
  PI_CONTROLLER_CWD,
  type PiDeps,
  PIP_JOB_EVIDENCE_PATH,
  type PrivateSeam,
  proveBackblazeSourceIdle,
  PUBLIC_HOME_BASE,
  realPiDeps,
  realPrivateSeam,
  realRemoteRunner,
  realRemoteSeam,
  type ReleaseManifest,
  RELEASES_ROOT,
  type RemoteSeam,
  validateCatalogEntry,
  validateControllerState,
  validateReleaseManifest,
  verifyUnitName,
  weekWindow,
  withinCatchUp,
  workerUnitNameOf,
} from "./backblaze-file-backup.ts";
import {
  assertBackupV2StatusTransition,
  type BackupRuntimeCatalogEntry,
  type BackupV2Gate,
  type BackupV2Request,
  backupV2RequestSha256,
  type BackupV2Result,
  type BackupV2Status,
  validateBackupRuntimeCatalogEntry,
  validateBackupV2CatalogEntry,
  validateBackupV2Gate,
  validateBackupV2Result,
  validateBackupV2Status,
} from "./backup-v2-runtime-contract.ts";
import {
  backupV2ArtifactBytes,
  backupV2ArtifactSha256,
  backupV2ControlCacheDirectory,
  backupV2GateDirectory,
  type BackupV2PruneWorkerResult,
  type BackupV2VerifiedResult,
  type BackupV2WorkerSettings,
  validateBackupV2VerifiedResult,
  validateBackupV2WorkerSettings,
} from "./backup-v2-worker.ts";
import {
  type BackupV2SupervisorIdentity,
  backupV2SupervisorUnitProperties,
  type BackupV2TreeObservation,
  pollBackupV2Settlement,
  settleBackupV2Cancellation,
} from "./backup-v2-supervisor.ts";
import { backupV2RuntimeLeaseDirectory } from "./backup-v2-runtime-lease.ts";
import { BACKUP_V2_LIMITS, BACKUP_V2_PROFILE_ID } from "./backup-v2-profile.ts";
import { type CaptureSettings } from "./backblaze-capture.ts";
import { backupV2SourceConfigSha256 } from "./backup-v2-metadata.ts";
import {
  assertBackblazeLaunchAllowed,
  type BackupControllerGate,
  GATE_BACKUP_SLICE,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
  validateGate,
} from "./backblaze-controller-contract.ts";
import { shellQuote } from "./backup-guest.ts";
import {
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
} from "./backup-v2-contract.ts";
import {
  type B2Settings,
  selectB2RetentionCredential,
} from "./backblaze-storage.ts";
import {
  type BackupV2RetentionJob,
  type BackupV2RetentionPolicy,
  DEFAULT_BACKUP_V2_RETENTION_POLICY,
  validateBackupV2RetentionJob,
  validateBackupV2RetentionPolicy,
  validateBackupV2RetiredRestic,
} from "./backup-v2-retention.ts";
import {
  B2_CATALOG_CONTROL_PATH,
  B2_CATALOG_DAMAGED_ALERT,
  B2_RETENTION_CONTROL_PATH,
  B2_RETENTION_KEY_PATH,
  B2_RETENTION_ORPHAN_ALERT,
  B2_RETENTION_PAGE_BYTES,
  B2_RETENTION_POLICY_PATH,
  type BackblazeMaintenanceMode,
  type BackblazeMaintenanceReports,
  type BackblazeMaintenanceResult,
  type BackupV2PiRetentionReport,
  maintenanceFailure,
  persistPrivateRetentionPlan,
  publishMaintenanceReport,
  readBackblazeMaintenance,
  retentionOrphansFound,
  retentionTransactionPath,
  validateRetentionPlanReference,
  validateRetentionSummary,
} from "./backup-v2-retention-report.ts";
import {
  addBackblazeFailureReason,
  BackblazeReportError,
  backblazeReportExplanation,
  type BackblazeReportReason,
  reasonForBackblazeError,
  withBackblazeReportReason,
} from "./backup-v2-report-reasons.ts";
import type {
  BackupV2KernelObservation,
  BackupV2KernelObservationOptions,
} from "./backup-v2-kernel.ts";
import {
  BACKUP_V2_PROTECTION_CONTROL_BASE,
  BACKUP_V2_PROTECTION_SOURCE_BASE,
  backupV2ProtectionControlDirectory,
  type BackupV2ProtectionDescriptor,
  backupV2ProtectionPageName,
  backupV2ProtectionSourceDirectory,
  type BackupV2PruneInput,
  parseBackupV2ProtectionManifest,
  parseBackupV2ProtectionPage,
  validateBackupV2ProtectionDescriptor,
} from "./backup-v2-protection.ts";

export type BackupV2ControllerPhase =
  | "REQUESTED"
  | "WORKER"
  | "WORKER_SETTLED"
  | "VERIFY_REQUESTED"
  | "VERIFY"
  | "VERIFY_SETTLED"
  | "COMPLETE"
  | "FAILED"
  | "CANCELLATION_BLOCKED";
const cancellationBlockedReasons = [
  "LEGACY_CANCELLATION_UNCLASSIFIED",
  "SOURCE_BOOT_CHANGED",
  "SOURCE_UNIT_ABSENT",
  "SOURCE_UNIT_FAILED",
  "SOURCE_INVOCATION_UNPROVED",
  "SOURCE_STATUS_FAILED",
  "SOURCE_STATUS_CANCELLATION_BLOCKED",
  "SOURCE_TERMINAL_STATUS_UNPROVED",
  "SOURCE_TERMINAL_PROCESSES_UNSETTLED",
  "SOURCE_TERMINAL_RESULT_MISSING",
  "SOURCE_TERMINAL_RESULT_HASH_MISMATCH",
  "SOURCE_TERMINAL_NATIVE_CUSTODY_MISMATCH",
  "SOURCE_TERMINAL_RESULT_INVALID",
  "SOURCE_OBSERVATION_UNPROVED",
  "SOURCE_CLEAR_PROOF_MISSING",
  "SOURCE_EXACT_STOP_FAILED",
  "SOURCE_GATE_CLEAR_FAILED",
  "SOURCE_CANCELLATION_SAMPLE_INVALID",
  "SOURCE_CANCELLATION_UNSETTLED",
  "BRIDGE_SETTINGS_UNPROVED",
  "BRIDGE_MANAGER_UNPROVED",
  "BRIDGE_STATUS_UNPROVED",
  "BRIDGE_BINDING_MISMATCH",
  "BRIDGE_SOURCE_UNPROVED",
  "BRIDGE_SOCKET_UNPROVED",
  "BRIDGE_READINESS_UNPROVED",
  "BRIDGE_TERMINAL_CLOSE_UNPROVED",
  "BRIDGE_CANCELLATION_CLOSE_PENDING",
  "BRIDGE_TERMINAL_PROCESSES_UNPROVED",
  "BRIDGE_EXACT_STOP_UNPROVED",
  "BRIDGE_KEEPER_CANCELLED",
  "BRIDGE_KEEPER_LEASE_EXPIRED",
  "BRIDGE_KEEPER_IDENTITY_CHANGED",
  "BRIDGE_KEEPER_PROGRESS_REGRESSED",
  "BRIDGE_KEEPER_PROGRESS_WRONG_PHASE",
  "BRIDGE_KEEPER_TUNNEL_LOST",
  "BRIDGE_KEEPER_OVERLAPPING_OPERATION",
  "BRIDGE_KEEPER_OBSERVATION_OR_NOTIFICATION_UNPROVED",
] as const;
export type BackupV2CancellationBlockedReason =
  typeof cancellationBlockedReasons[number];
export type BackupV2CancellationBlocked = {
  state: "CANCELLATION_BLOCKED";
  reason: BackupV2CancellationBlockedReason;
};
export interface BackupV2ControllerJob {
  settings: BackupV2WorkerSettings;
  phase: BackupV2ControllerPhase;
  activeKind: "worker" | "verify";
  predecessor: {
    format: "backup-v1" | "backup-v2";
    jobId: string | null;
    sha256: string;
  };
  workerGate: BackupV2Gate;
  verifierGate: BackupV2Gate;
  workerStatus: BackupV2Status | null;
  verifierStatus: BackupV2Status | null;
  workerResult: BackupV2Result | null;
  workerResultBytes: number[] | null;
  verified: BackupV2VerifiedResult | null;
  cancellationBlockedReason?: BackupV2CancellationBlockedReason;
  updatedAtUtc: string;
}
export interface BackupV2ControllerState {
  schemaVersion: 2;
  format: "backup-v2-controller";
  /** Preserved byte-for-byte as a JSON value, including its original FAILED job. */
  legacy: ControllerState;
  job: BackupV2ControllerJob | null;
  catalog: BackupRuntimeCatalogEntry[];
}
export interface BackupV2ControllerObservation {
  sourceBootId: string;
  unit: "ABSENT" | "STARTING" | "RUNNING" | "EXITED" | "FAILED";
  identity: BackupV2SupervisorIdentity | null;
  status: unknown | null;
  resultBytes: Uint8Array | null;
  nativeCustodySha256?: string | null;
  managerNamespaceReferences?: number | null;
  /** Independent collector, never inferred from a source status or missing unit. */
  tree: BackupV2TreeObservation | null;
}
type TerminalArtifacts = { resultSha256: string; nativeCustodySha256: string };
export interface BackupV2ControllerCapabilities {
  now(): Date;
  log(message: string): void;
  persist(state: BackupV2ControllerState): Promise<void>;
  /** Snapshot predecessor/controller state before any replacement request. */
  archive(value: ControllerState | BackupV2ControllerState): Promise<void>;
  gate: {
    read(): Promise<unknown | null>;
    replace(
      expected: BackupV2Gate | null,
      next: BackupV2Gate | null,
    ): Promise<void>;
    /** Durable exact-gate tombstone, recorded only after independent settlement. */
    cleared(gate: BackupV2Gate, expected?: TerminalArtifacts): Promise<boolean>;
  };
  create(periodKey: string): Promise<BackupV2WorkerSettings>;
  /** Includes existing Oracle/scheduled claim, legacy invocation/lock settlement. */
  admit(legacy: ControllerState): Promise<void>;
  install(settings: BackupV2WorkerSettings): Promise<void>;
  launch(
    settings: BackupV2WorkerSettings,
    kind: "worker" | "verify",
  ): Promise<void>;
  observe(gate: BackupV2Gate): Promise<BackupV2ControllerObservation>;
  acknowledge(gate: BackupV2Gate): Promise<void>;
  verifierInput(job: BackupV2ControllerJob): Promise<void>;
  preserveProtection(verified: BackupV2VerifiedResult): Promise<void>;
  /** Must freshly reconcile the exact retained invocation immediately before stop. */
  stop(
    gate: BackupV2Gate,
    expected?: TerminalArtifacts,
  ): Promise<void>;
  cancel(gate: BackupV2Gate): Promise<"SETTLED" | BackupV2CancellationBlocked>;
  bridge: {
    ensure(
      settings: BackupV2WorkerSettings,
      gate: BackupV2Gate,
    ): Promise<"READY" | "PENDING" | BackupV2CancellationBlocked>;
    close(
      gate: BackupV2Gate,
      mode: "terminal" | "cancel",
    ): Promise<"CLOSED" | "PENDING" | BackupV2CancellationBlocked>;
  };
}
function fail(): never {
  throw new Error("Backup v2 controller state or custody invalid");
}
function same(a: unknown, b: unknown): void {
  if (!isDeepStrictEqual(a, b)) fail();
}
function preserveLegacy(value: unknown): ControllerState {
  validateControllerState(value);
  return structuredClone(value) as ControllerState;
}
function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (
    Object.keys(r).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(r, key))
  ) fail();
  return r;
}
const phases: BackupV2ControllerPhase[] = [
  "REQUESTED",
  "WORKER",
  "WORKER_SETTLED",
  "VERIFY_REQUESTED",
  "VERIFY",
  "VERIFY_SETTLED",
  "COMPLETE",
  "FAILED",
  "CANCELLATION_BLOCKED",
];
export function validateBackupV2ControllerState(
  value: unknown,
): BackupV2ControllerState {
  const r = record(value, [
    "schemaVersion",
    "format",
    "legacy",
    "job",
    "catalog",
  ]);
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2-controller" ||
    !Array.isArray(r.catalog)
  ) fail();
  const legacy = preserveLegacy(r.legacy),
    catalog = r.catalog.map((entry) =>
      validateBackupRuntimeCatalogEntry(entry, validateCatalogEntry)
    );
  same(
    catalog.filter((entry) => entry.schemaVersion === 1).map((entry) =>
      entry.entry
    ),
    legacy.catalog,
  );
  const ids = catalog.map((entry) =>
    entry.schemaVersion === 1
      ? entry.entry.index.generation
      : entry.envelope.request.captureId
  );
  if (new Set(ids).size !== ids.length) fail();
  let job: BackupV2ControllerJob | null = null;
  if (r.job !== null) {
    const hasBlockReason = typeof r.job === "object" &&
      Object.hasOwn(r.job, "cancellationBlockedReason");
    const j = record(r.job, [
      "settings",
      "phase",
      "activeKind",
      "predecessor",
      "workerGate",
      "verifierGate",
      "workerStatus",
      "verifierStatus",
      "workerResult",
      "workerResultBytes",
      "verified",
      "updatedAtUtc",
      ...(hasBlockReason ? ["cancellationBlockedReason"] : []),
    ]);
    const cancellationBlockedReason = j
      .cancellationBlockedReason as BackupV2CancellationBlockedReason;
    if (
      hasBlockReason &&
      (j.phase !== "CANCELLATION_BLOCKED" ||
        !cancellationBlockedReasons.includes(cancellationBlockedReason))
    ) fail();
    const settings = validateBackupV2WorkerSettings(j.settings),
      workerGate = validateBackupV2Gate(j.workerGate),
      verifierGate = validateBackupV2Gate(j.verifierGate);
    for (const gate of [workerGate, verifierGate]) {
      same(gate.envelope, settings.envelope);
    }
    if (
      workerGate.gateId !== settings.workerGate.gateId ||
      verifierGate.gateId !== settings.verifierGate.gateId ||
      !phases.includes(j.phase as BackupV2ControllerPhase) ||
      !["worker", "verify"].includes(String(j.activeKind))
    ) fail();
    const predecessor = record(j.predecessor, ["format", "jobId", "sha256"]);
    if (
      !["backup-v1", "backup-v2"].includes(String(predecessor.format)) ||
      predecessor.jobId !== null &&
        (typeof predecessor.jobId !== "string" ||
          !/^job-[0-9a-f-]{36}$/.test(predecessor.jobId)) ||
      typeof predecessor.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(predecessor.sha256)
    ) fail();
    const workerStatus = j.workerStatus === null
        ? null
        : validateBackupV2Status(j.workerStatus, workerGate),
      verifierStatus = j.verifierStatus === null
        ? null
        : validateBackupV2Status(j.verifierStatus, verifierGate);
    const workerResult = j.workerResult === null
      ? null
      : validateBackupV2Result(j.workerResult, workerGate);
    if ((workerResult === null) !== (j.workerResultBytes === null)) fail();
    let workerResultBytes: number[] | null = null;
    if (j.workerResultBytes !== null) {
      if (
        !Array.isArray(j.workerResultBytes) ||
        j.workerResultBytes.length > BACKUP_V2_LIMITS.controlResponseBytes ||
        j.workerResultBytes.some((n) =>
          !Number.isInteger(n) || n < 0 || n > 255
        )
      ) fail();
      workerResultBytes = j.workerResultBytes as number[];
      same(
        JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            new Uint8Array(workerResultBytes),
          ),
        ),
        workerResult,
      );
      if (
        !workerStatus || workerStatus.phase !== "CLOUD_COMPLETE" ||
        workerStatus.resultSha256 !==
          backupV2ArtifactSha256(new Uint8Array(workerResultBytes))
      ) fail();
    }
    const verified = j.verified === null
      ? null
      : workerResult && workerResultBytes
      ? validateBackupV2VerifiedResult(
        j.verified,
        verifierGate,
        workerResult,
        backupV2ArtifactSha256(new Uint8Array(workerResultBytes)),
      )
      : fail();
    if (
      typeof j.updatedAtUtc !== "string" ||
      !Number.isFinite(Date.parse(j.updatedAtUtc)) ||
      j.updatedAtUtc < settings.envelope.request.requestedAtUtc
    ) fail();
    if (
      [
          "WORKER_SETTLED",
          "VERIFY_REQUESTED",
          "VERIFY",
          "VERIFY_SETTLED",
          "COMPLETE",
        ].includes(String(j.phase)) && !workerResult ||
      ["VERIFY_SETTLED", "COMPLETE"].includes(String(j.phase)) && !verified
    ) fail();
    job = {
      settings,
      phase: j.phase as BackupV2ControllerPhase,
      activeKind: j.activeKind as "worker" | "verify",
      predecessor:
        predecessor as unknown as BackupV2ControllerJob["predecessor"],
      workerGate,
      verifierGate,
      workerStatus,
      verifierStatus,
      workerResult,
      workerResultBytes,
      verified,
      ...(hasBlockReason ? { cancellationBlockedReason } : {}),
      updatedAtUtc: j.updatedAtUtc,
    };
    if (
      job.phase === "COMPLETE" &&
      !catalog.some((entry) =>
        entry.schemaVersion === 2 &&
        entry.envelope.requestSha256 === settings.envelope.requestSha256
      )
    ) fail();
  }
  return {
    schemaVersion: 2,
    format: "backup-v2-controller",
    legacy,
    job,
    catalog,
  };
}
export function backupV2PeriodSatisfied(
  state: BackupV2ControllerState,
  now: Date,
): boolean {
  const window = weekWindow(now),
    start = Date.parse(window.startAtUtc),
    end = Date.parse(window.endAtUtc);
  return state.catalog.some((entry) => {
    const times = entry.schemaVersion === 1
      ? [entry.entry.index.captureFinishedAtUtc]
      : entry.selectedRoot.root.roles.map((role) => role.captureFinishedAtUtc);
    const latest = Math.max(...times.map(Date.parse));
    return latest >= start && latest < end;
  });
}
/** Version-dispatch before recovery/watchdog field access; v1 validators stay unchanged. */
export function backupRuntimeCatalog(
  value: unknown,
): BackupRuntimeCatalogEntry[] {
  if ((value as { schemaVersion?: unknown } | null)?.schemaVersion === 1) {
    return validateControllerState(value).catalog.map((entry) => ({
      schemaVersion: 1,
      format: "backup-v1",
      entry,
    }));
  }
  return validateBackupV2ControllerState(value).catalog;
}
/** Strict gate union at the existing Pi path; no secret settings read is needed. */
export async function readBackupRuntimeGate(
  privateIO: PrivateSeam = realPrivateSeam(),
  path = GATE_PATH,
): Promise<BackupControllerGate | BackupV2Gate | null> {
  const value = await privateIO.read<unknown>(path);
  if (value === undefined) return null;
  return (value as { schemaVersion?: unknown } | null)?.schemaVersion === 2
    ? validateBackupV2Gate(value)
    : validateGate(value);
}
export function backupV2TreeSettled(
  gate: BackupV2Gate,
  observation: BackupV2ControllerObservation,
  retainedTerminalProof = false,
): boolean {
  return backupV2ProcessesSettled(gate, observation, retainedTerminalProof) &&
    observation.tree!.namespaceReferences === 0;
}
/** A retained unit may pin its own mount namespace after all work is gone.
 * Preserve this actual process proof before stopping that exact invocation;
 * only a separate fresh namespace-zero proof permits gate removal. */
export function backupV2ProcessesSettled(
  gate: BackupV2Gate,
  observation: BackupV2ControllerObservation,
  retainedTerminalProof = false,
): boolean {
  const tree = observation.tree;
  if (
    !gate.custody || !tree || observation.sourceBootId !== gate.sourceBootId ||
    !["EXITED", "FAILED", ...(retainedTerminalProof ? ["ABSENT"] : [])]
      .includes(observation.unit)
  ) return false;
  same(observation.identity, gate.custody);
  same(tree.identity, gate.custody);
  return tree.mainPid === 0 && tree.controlPid === 0 &&
    tree.cgroupPopulated === false && tree.descendants === 0 &&
    tree.escapedProcesses === 0 && tree.namespaceReferences !== null &&
    Number.isSafeInteger(tree.namespaceReferences) &&
    tree.namespaceReferences >= 0 &&
    tree.openPipelineHandles === 0 && tree.pendingOperations === 0 &&
    tree.sourceLockFree === true &&
    tree.namespaceReferences ===
      (observation.managerNamespaceReferences ?? null);
}

interface BackupV2VerifierRecoveryBinding {
  jobId: string;
  gateId: string;
  requestSha256: string;
}

function logCancellationBlocked(
  log: BackupV2ControllerCapabilities["log"],
  gate: BackupV2Gate,
  reason: BackupV2CancellationBlockedReason,
): void {
  log(
    `Backup v2 CANCELLATION_BLOCKED job=${gate.envelope.request.jobId} gate=${gate.gateId} kind=${gate.kind} reason=${reason}`,
  );
}

export function normalizeBackupV2ControllerState(
  input: ControllerState | BackupV2ControllerState,
): BackupV2ControllerState {
  return (input as { schemaVersion: number }).schemaVersion === 1
    ? {
      schemaVersion: 2,
      format: "backup-v2-controller",
      legacy: preserveLegacy(input),
      job: null,
      catalog: validateControllerState(input).catalog.map((entry) => ({
        schemaVersion: 1,
        format: "backup-v1",
        entry,
      })),
    }
    : validateBackupV2ControllerState(input);
}

/** Exactly one bounded reconciliation; no polling loop and no whole-job timer. */
export async function stepBackupV2Controller(
  input: ControllerState | BackupV2ControllerState,
  deps: BackupV2ControllerCapabilities,
  recover?: BackupV2VerifierRecoveryBinding,
): Promise<BackupV2ControllerState> {
  let state = normalizeBackupV2ControllerState(input);
  if (recover) {
    const job = state.job, gate = job?.verifierGate;
    if (
      !job || !gate || job.activeKind !== "verify" ||
      !["CANCELLATION_BLOCKED", "VERIFY_SETTLED"].includes(job.phase) ||
      gate.state !== "ACTIVE" || !gate.custody ||
      recover.jobId !== gate.envelope.request.jobId ||
      recover.gateId !== gate.gateId ||
      recover.requestSha256 !== gate.envelope.requestSha256
    ) {
      throw new Error(
        "Blocked verifier recovery no longer matches the job and gate",
      );
    }
  }
  const now = deps.now();
  const save = async () => {
    const checked = validateBackupV2ControllerState(state);
    await deps.persist(checked);
    return checked;
  };
  if (
    !state.job ||
    state.job.phase === "COMPLETE" &&
      state.job.settings.envelope.request.periodKey !==
        weekWindow(now).periodKey
  ) {
    if (!withinCatchUp(now) || backupV2PeriodSatisfied(state, now)) {
      return state;
    }
    if (await deps.gate.read() !== null) {
      throw new BackblazeReportError("B2_BACKUP_GATE_HELD");
    }
    await withBackblazeReportReason(
      "B2_BACKUP_ADMISSION_BLOCKED",
      () => deps.admit(state.legacy),
    );
    await deps.archive(input);
    const settings = validateBackupV2WorkerSettings(
      await deps.create(weekWindow(now).periodKey),
    );
    if (settings.envelope.request.periodKey !== weekWindow(now).periodKey) {
      fail();
    }
    const predecessor = {
      format: (input as { schemaVersion: number }).schemaVersion === 1
        ? "backup-v1" as const
        : "backup-v2" as const,
      jobId: state.job?.settings.envelope.request.jobId ??
        state.legacy.job?.envelope.request.jobId ?? null,
      sha256: backupV2ArtifactSha256(backupV2ArtifactBytes(input)),
    };
    state = {
      ...state,
      job: {
        settings,
        phase: "REQUESTED",
        activeKind: "worker",
        predecessor,
        workerGate: settings.workerGate,
        verifierGate: settings.verifierGate,
        workerStatus: null,
        verifierStatus: null,
        workerResult: null,
        workerResultBytes: null,
        verified: null,
        updatedAtUtc: deps.now().toISOString(),
      },
    };
    return await save();
  }
  const job = state.job;
  job.updatedAtUtc = now.toISOString();
  if (job.phase === "COMPLETE" || job.phase === "FAILED") return state;
  const kind = job.activeKind;
  let gate = kind === "worker" ? job.workerGate : job.verifierGate;
  const block = async (reason: BackupV2CancellationBlockedReason) => {
    job.phase = "CANCELLATION_BLOCKED";
    job.cancellationBlockedReason = reason;
    logCancellationBlocked(deps.log, gate, reason);
    return await save();
  };
  const live = await deps.gate.read();
  if (job.phase === "REQUESTED" || job.phase === "VERIFY_REQUESTED") {
    if (live !== null) same(validateBackupV2Gate(live), gate);
    else {
      // An Oracle invocation could have acquired the controller lock
      // after a crash or between the worker and verifier gates.
      await withBackblazeReportReason(
        "B2_BACKUP_ADMISSION_BLOCKED",
        () => deps.admit(state.legacy),
      );
      await deps.gate.replace(null, gate);
    }
    await deps.install(job.settings);
    if (kind === "verify") await deps.verifierInput(job);
    job.phase = kind === "worker" ? "WORKER" : "VERIFY";
    const saved = await save();
    // PENDING gate exists before the launch intent. Resume only observes it;
    // an ambiguous failed launch never starts another invocation automatically.
    await deps.launch(job.settings, kind);
    return saved;
  }
  if (
    job.phase === "WORKER_SETTLED" || job.phase === "VERIFY_SETTLED" ||
    kind === "verify" && job.phase === "CANCELLATION_BLOCKED" && job.verified
  ) {
    const terminal = kind === "worker" ? job.workerStatus : job.verifierStatus,
      output = kind === "worker" ? job.workerResult : job.verified;
    if (!terminal?.resultSha256 || !output?.nativeCustodySha256) {
      return await block("SOURCE_TERMINAL_NATIVE_CUSTODY_MISMATCH");
    }
    const artifacts = {
      resultSha256: terminal.resultSha256,
      nativeCustodySha256: output.nativeCustodySha256,
    };
    let proofFailure: BackupV2CancellationBlockedReason =
      "SOURCE_CLEAR_PROOF_MISSING";
    if (live !== null) {
      same(validateBackupV2Gate(live), gate);
      proofFailure = "SOURCE_TERMINAL_PROCESSES_UNSETTLED";
    }
    let proved: boolean;
    try {
      proved = (live !== null &&
        backupV2ProcessesSettled(gate, await deps.observe(gate))) ||
        await deps.gate.cleared(gate, artifacts);
    } catch {
      return await block("SOURCE_OBSERVATION_UNPROVED");
    }
    if (!proved) return await block(proofFailure);
    if (kind === "verify") {
      const close = await deps.bridge.close(gate, "terminal");
      if (close === "PENDING") {
        if (job.phase === "CANCELLATION_BLOCKED") {
          return await block("BRIDGE_TERMINAL_CLOSE_UNPROVED");
        }
        return state;
      }
      if (close !== "CLOSED") return await block(close.reason);
    }
    if (live !== null) {
      try {
        await deps.stop(gate, artifacts);
      } catch {
        return await block("SOURCE_EXACT_STOP_FAILED");
      }
      try {
        await deps.gate.replace(gate, null);
      } catch {
        return await block("SOURCE_GATE_CLEAR_FAILED");
      }
    }
    delete job.cancellationBlockedReason;
    if (kind === "worker") {
      job.phase = "VERIFY_REQUESTED";
      job.activeKind = "verify";
      return await save();
    }
    const verified = job.verified!;
    if (!verified.protectedGraph) fail();
    await deps.preserveProtection(verified);
    const entry = validateBackupV2CatalogEntry({
      schemaVersion: 2,
      format: "backup-v2",
      envelope: job.settings.envelope,
      resultSha256: backupV2ArtifactSha256(
        new Uint8Array(job.workerResultBytes!),
      ),
      selectedRoot: verified.selectedRoot,
      receipt: verified.receipt,
      receiptReference: verified.receiptReference,
      acceptedAtUtc: deps.now().toISOString(),
    });
    const existing = state.catalog.find((old) =>
      old.schemaVersion === 2 &&
      old.envelope.requestSha256 === entry.envelope.requestSha256
    );
    if (existing) {
      if (existing.schemaVersion !== 2) fail();
      same({ ...existing, acceptedAtUtc: entry.acceptedAtUtc }, entry);
    } else state.catalog.push(entry);
    job.phase = "COMPLETE";
    return await save();
  }
  if (live === null) fail();
  const savedLive = validateBackupV2Gate(live);
  if (recover) same(savedLive, gate);
  if (gate.custody === null && savedLive.custody !== null) {
    same({
      ...savedLive,
      custody: null,
      state: "PENDING",
      updatedAtUtc: gate.updatedAtUtc,
    }, gate);
    gate = savedLive;
    if (kind === "worker") job.workerGate = gate;
    else job.verifierGate = gate;
    await save();
  } else same(savedLive, gate);
  // Read fresh success proof before attempting to cancel a verifier. An
  // unfinished controller observation can outlive clean source completion.
  const retryVerifierTerminal = job.phase === "CANCELLATION_BLOCKED" &&
    kind === "verify" &&
    !["FAILED", "CANCELLATION_BLOCKED"].includes(
      job.verifierStatus?.phase ?? "",
    ) &&
    job.cancellationBlockedReason !== "SOURCE_UNIT_FAILED";
  if (
    job.phase === "CANCELLATION_BLOCKED" && !recover && !retryVerifierTerminal
  ) {
    if (!gate.custody) return await block("SOURCE_INVOCATION_UNPROVED");
    const cancelled = await deps.cancel(gate);
    if (cancelled !== "SETTLED") return await block(cancelled.reason);
    if (kind === "verify") {
      const close = await deps.bridge.close(gate, "cancel");
      if (close === "PENDING") {
        return await block("BRIDGE_CANCELLATION_CLOSE_PENDING");
      }
      if (close !== "CLOSED") return await block(close.reason);
    }
    try {
      await deps.stop(gate);
    } catch {
      return await block("SOURCE_EXACT_STOP_FAILED");
    }
    try {
      await deps.gate.replace(gate, null);
    } catch {
      return await block("SOURCE_GATE_CLEAR_FAILED");
    }
    delete job.cancellationBlockedReason;
    job.phase = "FAILED";
    return await save();
  }
  let observation: BackupV2ControllerObservation;
  try {
    observation = await deps.observe(gate);
  } catch (error) {
    if (!recover && !retryVerifierTerminal) throw error;
    return await block("SOURCE_OBSERVATION_UNPROVED");
  }
  if (observation.sourceBootId !== gate.sourceBootId) {
    return await block(
      observation.sourceBootId
        ? "SOURCE_BOOT_CHANGED"
        : "SOURCE_OBSERVATION_UNPROVED",
    );
  }
  if (observation.unit === "ABSENT") return await block("SOURCE_UNIT_ABSENT");
  if (!observation.identity) {
    if (
      recover || retryVerifierTerminal ||
      !["RUNNING", "STARTING"].includes(observation.unit)
    ) {
      return await block("SOURCE_INVOCATION_UNPROVED");
    }
    return state;
  }
  if (gate.custody === null) {
    gate = validateBackupV2Gate({
      ...gate,
      state: "ACTIVE",
      custody: observation.identity,
      updatedAtUtc: now.toISOString(),
    });
    await deps.gate.replace(
      kind === "worker" ? job.workerGate : job.verifierGate,
      gate,
    );
    if (kind === "worker") job.workerGate = gate;
    else job.verifierGate = gate;
    await save();
  } else if (!isDeepStrictEqual(gate.custody, observation.identity)) {
    if (!recover && !retryVerifierTerminal) fail();
    return await block("SOURCE_INVOCATION_UNPROVED");
  }
  if (observation.status === null) {
    return recover || retryVerifierTerminal || observation.unit === "EXITED"
      ? await block("SOURCE_TERMINAL_STATUS_UNPROVED")
      : state;
  }
  let status: BackupV2Status;
  try {
    status = validateBackupV2Status(observation.status, gate);
    const prior = kind === "worker" ? job.workerStatus : job.verifierStatus;
    if (prior) assertBackupV2StatusTransition(prior, status);
  } catch (error) {
    if (!recover && !retryVerifierTerminal) throw error;
    return await block("SOURCE_TERMINAL_STATUS_UNPROVED");
  }
  if (
    recover && (status.phase !== "ACCEPTED" || observation.unit !== "EXITED")
  ) {
    return await block("SOURCE_TERMINAL_STATUS_UNPROVED");
  }
  const sourceFailure = status.phase === "CANCELLATION_BLOCKED"
    ? "SOURCE_STATUS_CANCELLATION_BLOCKED"
    : status.phase === "FAILED"
    ? "SOURCE_STATUS_FAILED"
    : observation.unit === "FAILED"
    ? "SOURCE_UNIT_FAILED"
    : null;
  if (!sourceFailure && !status.finishedAtUtc) {
    if (retryVerifierTerminal) {
      return await block(
        job.cancellationBlockedReason ?? "LEGACY_CANCELLATION_UNCLASSIFIED",
      );
    }
    if (observation.unit === "EXITED") {
      return now.getTime() - Date.parse(status.updatedAtUtc) <= 90_000
        ? state
        : await block("SOURCE_TERMINAL_STATUS_UNPROVED");
    }
    if (kind === "verify") {
      const bridge = await deps.bridge.ensure(job.settings, gate);
      if (typeof bridge === "object") return await block(bridge.reason);
      if (bridge === "PENDING") return state;
    }
    await deps.acknowledge(gate);
  }
  if (kind === "worker") job.workerStatus = status;
  else job.verifierStatus = status;
  if (sourceFailure) return await block(sourceFailure);
  if (status.finishedAtUtc === null) return await save();
  if (["RUNNING", "STARTING"].includes(observation.unit)) {
    return retryVerifierTerminal
      ? await block("SOURCE_TERMINAL_PROCESSES_UNSETTLED")
      : await save();
  }
  let settled: boolean;
  try {
    settled = backupV2ProcessesSettled(gate, observation);
  } catch {
    return await block("SOURCE_INVOCATION_UNPROVED");
  }
  if (!settled) return await block("SOURCE_TERMINAL_PROCESSES_UNSETTLED");
  if (!observation.resultBytes) {
    return await block("SOURCE_TERMINAL_RESULT_MISSING");
  }
  if (backupV2ArtifactSha256(observation.resultBytes) !== status.resultSha256) {
    return await block("SOURCE_TERMINAL_RESULT_HASH_MISMATCH");
  }
  let result: Record<string, unknown> | null;
  try {
    result = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(observation.resultBytes),
    );
  } catch {
    return await block("SOURCE_TERMINAL_RESULT_INVALID");
  }
  if (
    typeof result?.nativeCustodySha256 !== "string" ||
    result.nativeCustodySha256 !== observation.nativeCustodySha256
  ) return await block("SOURCE_TERMINAL_NATIVE_CUSTODY_MISMATCH");
  try {
    if (kind === "worker") {
      job.workerResult = validateBackupV2Result(result, gate);
      job.workerResultBytes = [...observation.resultBytes];
      job.phase = "WORKER_SETTLED";
    } else {
      job.verified = validateBackupV2VerifiedResult(
        result,
        gate,
        job.workerResult!,
        backupV2ArtifactSha256(new Uint8Array(job.workerResultBytes!)),
      );
      job.phase = "VERIFY_SETTLED";
    }
  } catch {
    return await block("SOURCE_TERMINAL_RESULT_INVALID");
  }
  if (recover || retryVerifierTerminal) await deps.archive(input);
  delete job.cancellationBlockedReason;
  return await save();
}

/** Actual capture intervals and independently accepted receipts determine
 * freshness. A request, heartbeat or new verification date cannot refresh it. */
export function acceptedBackupRuntimeCapture(
  value: unknown,
  now: Date,
  damaged: readonly string[] = [],
) {
  const window = weekWindow(now),
    start = Date.parse(window.startAtUtc),
    end = Date.parse(window.endAtUtc);
  let unknown = false;
  const entries = backupRuntimeCatalog(value).flatMap((entry) => {
    const capture = entry.schemaVersion === 2
      ? entry.envelope.request.captureId
      : entry.entry.index.generation;
    if (damaged.includes(capture)) return [];
    const verifiedAtUtc = entry.schemaVersion === 1
      ? entry.entry.receipt.verifiedAtUtc
      : entry.receipt.verifiedAtUtc;
    const acceptedAtUtc = entry.schemaVersion === 1
      ? entry.entry.acceptedAtUtc
      : entry.acceptedAtUtc;
    const starts = entry.schemaVersion === 1
      ? [entry.entry.index.captureStartedAtUtc]
      : entry.selectedRoot.root.roles.map((role) => role.captureStartedAtUtc);
    const finishes = entry.schemaVersion === 1
      ? [entry.entry.index.captureFinishedAtUtc]
      : entry.selectedRoot.root.roles.map((role) => role.captureFinishedAtUtc);
    const captured = Math.max(...finishes.map(Date.parse)),
      verified = Date.parse(verifiedAtUtc),
      accepted = Date.parse(acceptedAtUtc);
    if (
      ![captured, verified, accepted, ...starts.map(Date.parse)].every(
        Number.isFinite,
      ) || captured > verified || verified > now.getTime() ||
      accepted > now.getTime()
    ) {
      unknown = true;
      return [];
    }
    return [{
      entry,
      captureStartedAtUtc: new Date(Math.min(...starts.map(Date.parse)))
        .toISOString(),
      captureFinishedAtUtc: new Date(captured).toISOString(),
      verifiedAtUtc,
      current: captured >= start && captured < end,
    }];
  }).sort((a, b) =>
    Date.parse(b.captureFinishedAtUtc) - Date.parse(a.captureFinishedAtUtc)
  );
  return {
    latest: entries[0] ?? null,
    current: entries.find((entry) => entry.current) ?? null,
    periodKey: window.periodKey,
    unknown,
  };
}

export function backupV2ControllerReport(
  state: BackupV2ControllerState,
  now: Date,
  damaged: readonly string[] = [],
): BackblazeRunReport {
  const job = state.job, phase = job?.phase ?? "IDLE";
  const observedAtUtc = now.toISOString();
  if (phase === "COMPLETE" || phase === "IDLE") {
    const accepted = acceptedBackupRuntimeCapture(state, now, damaged);
    const entry = accepted.current?.entry;
    if (accepted.unknown) {
      return addBackblazeFailureReason({
        status: "B2_BACKUP_ACCEPTANCE_UNKNOWN",
        observedAtUtc,
        healthy: false,
      }, "B2_BACKUP_ACCEPTANCE_UNKNOWN");
    }
    if (entry) {
      const generation = acceptedId(entry);
      const jobId = entry.schemaVersion === 2
        ? entry.envelope.request.jobId
        : generation.replace(/^generation-/, "job-");
      return {
        status: `B2_BACKUP_CURRENT:${jobId}`,
        observedAtUtc,
        healthy: true,
        jobId,
        generation,
      };
    }
    const currentWasDamaged = damaged.length > 0 &&
      acceptedBackupRuntimeCapture(state, now).current !== null;
    return {
      status: currentWasDamaged
        ? B2_CATALOG_DAMAGED_ALERT
        : phase === "IDLE"
        ? "B2_BACKUP_IDLE"
        : `B2_PERIOD_MISSED:${accepted.periodKey}`,
      observedAtUtc,
      healthy: false,
      ...backblazeReportExplanation(
        currentWasDamaged ? "DAMAGED_ACCEPTED_GENERATION" : "B2_PERIOD_MISSED",
      ),
    };
  }
  const status = job?.activeKind === "worker"
    ? job.workerStatus
    : job?.verifierStatus;
  const fresh = status &&
    now.getTime() - Date.parse(status.updatedAtUtc) >= -5000 &&
    now.getTime() - Date.parse(status.updatedAtUtc) <= 60_000;
  const initializing = status?.phase === "PREFLIGHT" &&
    now.getTime() - Date.parse(status.startedAtUtc) <= 300_000;
  const leased = status &&
    Math.max(
        status.lease.usefulProgressExpiresAtMs,
        status.lease.retryEpisode?.expiresAtMs ?? 0,
        status.lease.transferEpisode?.expiresAtMs ?? 0,
      ) > status.lease.observedMonotonicMs;
  const healthy = ["WORKER", "VERIFY"].includes(phase) &&
    Boolean(fresh && (initializing || leased));
  return {
    status: phase,
    observedAtUtc,
    healthy,
    ...(job
      ? {
        jobId: job.settings.envelope.request.jobId,
        generation: job.settings.envelope.request.captureId,
      }
      : {}),
    ...(healthy ? {} : backblazeReportExplanation(
      job?.cancellationBlockedReason ??
        (phase === "FAILED"
          ? status?.phase === "FAILED"
            ? "SOURCE_STATUS_FAILED"
            : "B2_BACKUP_FAILED"
          : ["WORKER", "VERIFY"].includes(phase)
          ? "B2_BACKUP_PROGRESS_UNKNOWN"
          : "B2_BACKUP_PENDING"),
    )),
  };
}

/** On the Pi, finish only the named blocked verifier with the candidate
 * controller code and the original immutable source runtime. */
export async function recoverBlockedBackupV2Verifier(
  expected: BackupV2VerifierRecoveryBinding,
): Promise<BackblazeRunReport> {
  if (await Deno.realPath(".") !== PI_CONTROLLER_CWD) fail();
  if (!expected) fail();
  const deps = realPiDeps();
  const { realBackupV2BridgeRuntime } = await import(
    "./backup-v2-bridge-runtime.ts"
  );
  return await deps.lock(CONTROLLER_LOCK_PATH, async () => {
    const saved = await deps.private.read<BackupV2ControllerState>(
      CONTROLLER_STATE_PATH,
    );
    if (!saved) fail();
    const caps = realBackupV2ControllerCapabilities(
      deps,
      realBackupV2BridgeRuntime(deps),
    );
    let next = await stepBackupV2Controller(saved, caps, expected);
    if (next.job?.phase === "VERIFY_SETTLED") {
      next = await stepBackupV2Controller(next, caps, expected);
    }
    const now = deps.now();
    const { damaged } = await readBackblazeMaintenance(deps.private, now);
    const report = backupV2ControllerReport(next, now, damaged);
    await deps.private.write(B2_REPORT_PATH, report);
    return next.job?.phase === "COMPLETE"
      ? { ...report, status: "COMPLETE" }
      : report;
  });
}

/** Explicit recovery after exact cancellation/settlement. Unknown failures are
 * never automatically retried. The complete failed state remains archived. */
export async function resumeBackupV2ControllerJob(
  input: BackupV2ControllerState,
  deps: BackupV2ControllerCapabilities,
): Promise<BackupV2ControllerState> {
  const state = validateBackupV2ControllerState(input), job = state.job;
  if (
    !job || job.phase !== "FAILED" || await deps.gate.read() !== null ||
    backupV2PeriodSatisfied(state, deps.now())
  ) fail();
  const old = job.activeKind === "worker" ? job.workerGate : job.verifierGate;
  if (!await deps.gate.cleared(old)) fail();
  await deps.archive(input);
  job.predecessor = {
    format: "backup-v2",
    jobId: job.settings.envelope.request.jobId,
    sha256: backupV2ArtifactSha256(backupV2ArtifactBytes(input)),
  };
  job.updatedAtUtc = deps.now().toISOString();
  job.verified = null;
  job.verifierStatus = null;
  job.verifierGate = job.settings.verifierGate;
  if (job.workerResult) {
    job.activeKind = "verify";
    job.phase = "VERIFY_REQUESTED";
  } else {
    job.activeKind = "worker";
    job.phase = "REQUESTED";
    job.workerGate = job.settings.workerGate;
    job.workerStatus = null;
    job.workerResultBytes = null;
  }
  const checked = validateBackupV2ControllerState(state);
  await deps.persist(checked);
  return checked;
}

/** Real adapter is below; injectable coordination above is also the acceptance
 * surface for crash boundaries, legacy preservation and exact custody tests. */
export type BackupV2PiDependencies = PiDeps;

export function backupV2PiReleaseRoot(revision: string): string {
  if (!/^[0-9a-f]{40}$/.test(revision)) fail();
  return `${PI_CONTROLLER_CWD}/.private/file-backup/runtime/releases/${revision}`;
}
export interface BackupV2ReleaseFile {
  path: string;
  bytes: Uint8Array;
  sha256: string;
}
/** Full literal relative-import closure, including type-only and dynamic imports.
 * Every script must already be present in the guarded installation receipt. */
export async function collectBackupV2Release(
  revision: string,
  entries: readonly string[],
  read: (path: string) => Promise<Uint8Array>,
  trustedHashes: Readonly<Record<string, string>>,
): Promise<{ manifest: ReleaseManifest; files: BackupV2ReleaseFile[] }> {
  backupV2PiReleaseRoot(revision);
  const queue = [...entries],
    seen = new Set<string>(),
    files: BackupV2ReleaseFile[] = [];
  while (queue.length) {
    const path = queue.shift()!;
    if (seen.has(path)) continue;
    if (!/^scripts\/[A-Za-z0-9_.-]+\.ts$/.test(path) || seen.size >= 256) {
      fail();
    }
    seen.add(path);
    const bytes = await read(path), sha256 = backupV2ArtifactSha256(bytes);
    if (
      bytes.length > BACKUP_V2_LIMITS.controlResponseBytes ||
      trustedHashes[path] !== sha256
    ) throw new Error("Backup v2 module differs from installed receipt");
    files.push({ path, bytes, sha256 });
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const imports =
      /(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'](\.[^"']+\.ts)["']/g;
    for (const match of text.matchAll(imports)) {
      if (!/^\.\/[A-Za-z0-9_.-]+\.ts$/.test(match[1])) fail();
      queue.push(`scripts/${match[1].slice(2)}`);
    }
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  return {
    manifest: validateReleaseManifest({
      sourceRevision: revision,
      files: files.map(({ path, sha256 }) => ({ path, sha256 })),
    }, revision),
    files,
  };
}
/** Internal Pi release materialization beneath the existing private runtime.
 * It never changes a selector or a previously installed file. */
export async function installBackupV2PiRelease(
  deps: PiDeps,
  revision: string,
): Promise<string> {
  if (await Deno.realPath(".") !== PI_CONTROLLER_CWD) fail();
  const receipt = await deps.private.read<
    { sourceRevision: string; hashes: Record<string, string> }
  >(".private/reports/pi-session-deployment.json");
  if (!receipt || receipt.sourceRevision !== revision || !receipt.hashes) {
    fail();
  }
  const release = await collectBackupV2Release(revision, [
    "scripts/backblaze-file-backup.ts",
    "scripts/backup-v2-controller.ts",
    "scripts/backup-v2-worker.ts",
    "scripts/backup-v2-bridge-runtime.ts",
  ], async (path) => {
    const info = await Deno.lstat(path);
    if (
      !info.isFile || info.isSymlink ||
      info.size > BACKUP_V2_LIMITS.controlResponseBytes ||
      await Deno.realPath(path) !== `${PI_CONTROLLER_CWD}/${path}`
    ) fail();
    return await Deno.readFile(path);
  }, receipt.hashes);
  const root = backupV2PiReleaseRoot(revision), uid = Deno.uid();
  const ensure = async (path: string) => {
    try {
      await Deno.mkdir(path, { mode: 0o700 });
    } catch (e) {
      if (!(e instanceof Deno.errors.AlreadyExists)) throw e;
    }
    const info = await Deno.lstat(path);
    if (
      !info.isDirectory || info.isSymlink || info.uid !== uid ||
      info.mode === null || (info.mode & 0o777) !== 0o700 ||
      await Deno.realPath(path) !== path
    ) fail();
  };
  let path = PI_CONTROLLER_CWD;
  for (const part of root.slice(PI_CONTROLLER_CWD.length + 1).split("/")) {
    path += `/${part}`;
    await ensure(path);
  }
  await ensure(`${root}/scripts`);
  const install = async (relative: string, bytes: Uint8Array) => {
    const destination = `${root}/${relative}`;
    try {
      const info = await Deno.lstat(destination);
      if (
        !info.isFile || info.isSymlink || info.uid !== uid ||
        info.nlink !== 1 || info.mode === null ||
        (info.mode & 0o777) !== 0o600 || info.size !== bytes.length
      ) fail();
      same(await Deno.readFile(destination), bytes);
      return;
    } catch (e) {
      if (!(e instanceof Deno.errors.NotFound)) throw e;
    }
    const temporary = `${destination}.${crypto.randomUUID()}.tmp`,
      file = await Deno.open(temporary, {
        createNew: true,
        write: true,
        mode: 0o600,
      });
    try {
      let at = 0;
      while (at < bytes.length) {
        const count = await file.write(bytes.subarray(at));
        if (count <= 0) fail();
        at += count;
      }
      await file.sync();
    } finally {
      file.close();
    }
    await Deno.link(temporary, destination);
    await Deno.remove(temporary);
  };
  for (const file of release.files) await install(file.path, file.bytes);
  await install("release.json", backupV2ArtifactBytes(release.manifest));
  for (const directory of [`${root}/scripts`, root]) {
    using file = await Deno.open(directory, { read: true });
    await file.sync();
  }
  return root;
}

/** Existing immutable wrapper names, with an explicit version-specific import. */
export async function copyBackupV2Protection(
  verified: BackupV2VerifiedResult,
  io: {
    read(name: string): Promise<Uint8Array>;
    write(name: string, bytes: Uint8Array): Promise<void>;
  },
): Promise<BackupV2ProtectionDescriptor> {
  const descriptor = validateBackupV2ProtectionDescriptor(
    verified.protectedGraph,
  );
  same(descriptor.root, verified.selectedRoot.reference);
  const manifestBytes = await io.read("manifest.json"),
    manifest = parseBackupV2ProtectionManifest(manifestBytes, descriptor);
  const objects = new Map<
    string,
    ReturnType<typeof validateBackupV2ObjectRef>
  >();
  for (const page of manifest.pages) {
    const name = backupV2ProtectionPageName(page.pageIndex),
      bytes = await io.read(name),
      checked = parseBackupV2ProtectionPage(bytes, manifest, page.pageIndex);
    for (const object of checked.objects) {
      if (objects.has(object.fileId)) fail();
      objects.set(object.fileId, object);
    }
    await io.write(name, bytes);
  }
  for (
    const required of [
      descriptor.root.object,
      verified.receiptReference.object,
      ...verified.selectedRoot.root.roles.map((role) => role.manifest.object),
      ...verified.selectedRoot.root.metadata,
    ]
  ) {
    same(objects.get(required.fileId), required);
  }
  if (objects.size !== descriptor.objectCount) fail();
  await io.write("manifest.json", manifestBytes);
  await io.write("descriptor.json", backupV2ArtifactBytes(descriptor));
  return descriptor;
}

export function backupV2Entrypoint(
  jobId: string,
  revision: string,
  kind: "worker" | "verify",
): string {
  if (
    !/^job-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(jobId) ||
    !/^[a-f0-9]{40}$/.test(revision)
  ) fail();
  return `import { runBackupV2RemoteWorker } from ${
    JSON.stringify(`${RELEASES_ROOT}/${revision}/scripts/backup-v2-worker.ts`)
  };\nawait runBackupV2RemoteWorker(${JSON.stringify(jobId)}, ${
    JSON.stringify(kind)
  });\n`;
}
export function backupV2LaunchArguments(
  settings: BackupV2WorkerSettings,
  kind: "worker" | "verify" | "prune",
  pruneGate?: BackupV2Gate,
): string[] {
  validateBackupV2WorkerSettings(settings);
  const gate = kind === "prune"
    ? validateBackupV2Gate(pruneGate)
    : kind === "worker"
    ? settings.workerGate
    : settings.verifierGate;
  if (gate.kind !== kind) fail();
  same(gate.envelope, settings.envelope);
  return backupV2ManagedLaunchArguments(gate);
}

export function backupV2PruneLaunchArguments(gate: BackupV2Gate): string[] {
  if (gate.kind !== "prune") fail();
  return backupV2ManagedLaunchArguments(validateBackupV2Gate(gate));
}

function backupV2ManagedLaunchArguments(gate: BackupV2Gate): string[] {
  const { kind, envelope: { request } } = gate;
  const runtime = `${JOBS_RUNTIME_ROOT}/${request.jobId}`,
    publicHome = `${PUBLIC_HOME_BASE}/${request.captureId}`;
  const stagingDevice =
    "/dev/disk/by-id/scsi-3608cae23d6ea4b84be48c40d288c890e";
  const properties = [
    ...Object.entries({
      ...backupV2SupervisorUnitProperties(30_000),
      RemainAfterExit: "yes",
      Slice: GATE_BACKUP_SLICE,
      MemoryHigh: "infinity",
      MemoryMax: "6255601664",
      MemorySwapMax: "0",
      CPUQuota: "100%",
      CPUWeight: "1",
      Nice: "19",
      TasksMax: "256",
      LimitCORE: "0",
      OOMPolicy: "kill",
      UMask: "0077",
      WorkingDirectory: runtime,
      Environment: `DENO_DIR=${runtime}/deno-cache`,
    }).map(([k, v]) => `${k}=${v}`),
    "IOAccounting=yes",
    "IOReadBandwidthMax=/ 36M",
    "IOWriteBandwidthMax=/ 36M",
    "IOReadIOPSMax=/ 4500",
    "IOWriteIOPSMax=/ 4500",
    `IOReadBandwidthMax=${stagingDevice} 12M`,
    `IOWriteBandwidthMax=${stagingDevice} 12M`,
    `IOReadIOPSMax=${stagingDevice} 1500`,
    `IOWriteIOPSMax=${stagingDevice} 1500`,
  ];
  return [
    "systemd-run",
    "--quiet",
    `--unit=${gate.unitName}`,
    ...properties.map((p) => `--property=${p}`),
    ...(kind === "prune"
      ? [`--setenv=BACKUP_V2_PRUNE_GATE_ID=${gate.gateId}`]
      : []),
    "/usr/local/bin/deno",
    "run",
    "--no-prompt",
    "--no-config",
    "--no-lock",
    "--cached-only",
    "--no-code-cache",
    `--allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT},${publicHome},${BACKUP_RUNTIME_BASE},${
      backupV2RuntimeLeaseDirectory(gate.unitName)
    }`,
    `--allow-write=${BACKUP_BASE},${PUBLIC_HOME_BASE},${BACKUP_V2_PROTECTION_SOURCE_BASE},${
      backupV2RuntimeLeaseDirectory(gate.unitName)
    }`,
    "--allow-env=INVOCATION_ID,NOTIFY_SOCKET" +
    (kind === "prune" ? ",BACKUP_V2_PRUNE_GATE_ID" : ""),
    "--allow-sys=statfs",
    "--allow-ffi=/usr/lib/libsystemd.so.0",
    "--allow-run=/bin/sh,/usr/bin/systemctl,/usr/bin/sha256sum,/usr/bin/flock,/usr/bin/bash,/usr/bin/unshare,/usr/bin/gpg,/usr/bin/zstd,/usr/bin/tar,/usr/bin/mkfifo,/usr/bin/curl,/usr/bin/sudo,/usr/bin/cat,/usr/bin/chown,/usr/bin/find,/usr/bin/stat,/usr/bin/readlink",
    kind === "prune"
      ? `${RELEASES_ROOT}/${request.sourceRevision}/scripts/backup-v2-worker.ts`
      : `${runtime}/entry-${kind}.ts`,
  ];
}

/** Root-only bounded control read; payload and private keys never cross this seam. */
export function backupV2RemoteProgram(jobId: string, program: string): string {
  return `printf '%s' ${shellQuote(program)} | DENO_DIR=${
    shellQuote(backupV2ControlCacheDirectory(jobId))
  } /usr/local/bin/deno run --no-prompt --no-config --no-lock --no-code-cache --cached-only --allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT},${BACKUP_V2_PROTECTION_SOURCE_BASE} --allow-run=/bin/sh,/usr/bin/systemctl,/usr/bin/flock,/usr/bin/cat,/usr/bin/find,/usr/bin/stat,/usr/bin/readlink,/usr/bin/sha256sum -`;
}
/** Only the exact settled invocation's two lease files may be removed. */
export function backupV2RuntimeLeaseCleanupProgram(
  gateInput: BackupV2Gate,
): string {
  const gate = validateBackupV2Gate(gateInput);
  if (!gate.custody) fail();
  const directory = backupV2RuntimeLeaseDirectory(gate.unitName),
    release = `${RELEASES_ROOT}/${gate.envelope.request.sourceRevision}`,
    program = `import { removeBackupV2RuntimeLease } from ${
      JSON.stringify(release + "/scripts/backup-v2-runtime-lease.ts")
    }; await removeBackupV2RuntimeLease(${JSON.stringify(gate.custody)});`;
  return `printf '%s' ${shellQuote(program)} | DENO_DIR=${
    shellQuote(backupV2ControlCacheDirectory(gate.envelope.request.jobId))
  } /usr/local/bin/deno run --no-prompt --no-config --no-lock --no-code-cache --cached-only --allow-read=${release},${directory} --allow-write=${directory} -`;
}
export function backupV2ObservationProgram(
  gateInput: BackupV2Gate,
  options: BackupV2KernelObservationOptions = {},
): string {
  const gate = validateBackupV2Gate(gateInput);
  return `
const {observeBackupV2Kernel}=await import(${
    JSON.stringify(
      `${RELEASES_ROOT}/${gate.envelope.request.sourceRevision}/scripts/backup-v2-kernel.ts`,
    )
  });
const gate=${JSON.stringify(gate)},options=${JSON.stringify(options)};
const observed=await observeBackupV2Kernel(gate,undefined,options);
const read=async(path,limit)=>{try{const info=await Deno.lstat(path);if(!info.isFile||info.isSymlink||info.uid!==0||info.nlink!==1||(info.mode&511)!==384||info.size>limit)throw Error("Unsafe artifact");const bytes=await Deno.readFile(path),after=await Deno.lstat(path);if(bytes.length!==info.size||info.dev!==after.dev||info.ino!==after.ino||info.size!==after.size)throw Error("Changed artifact");return bytes;}catch(e){if(e instanceof Deno.errors.NotFound)return null;throw e;}};
const directory=observed.identity?${
    JSON.stringify(BACKUP_BASE)
  }+"/"+gate.envelope.request.captureId+"/v2-"+gate.gateId+"/"+observed.identity.invocationId:null;
const statusBytes=directory?await read(directory+"/status.json",${BACKUP_V2_LIMITS.controlResponseBytes}):null;
const resultBytes=directory?await read(directory+"/result.json",${BACKUP_V2_LIMITS.controlResponseBytes}):null;
console.log(JSON.stringify({...observed,status:statusBytes?JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(statusBytes)):null,resultBytes:resultBytes?[...resultBytes]:null}));
`;
}

export async function observeBackupV2Source(
  gate: BackupV2Gate,
  remote: Pick<RemoteSeam, "root"> = realRemoteSeam(realRemoteRunner),
  options: BackupV2KernelObservationOptions = {},
): Promise<BackupV2ControllerObservation> {
  const result = await remote.root(
    backupV2RemoteProgram(
      gate.envelope.request.jobId,
      backupV2ObservationProgram(gate, options),
    ),
  );
  if (
    result.code !== 0 ||
    result.stdout.length > 12 * BACKUP_V2_LIMITS.controlResponseBytes
  ) throw new Error("Backup v2 independent source observation failed");
  const value = JSON.parse(result.stdout) as BackupV2ControllerObservation & {
    resultBytes: number[] | null;
  };
  if (value.tree) value.tree.observedMonotonicMs = performance.now();
  return {
    ...value,
    resultBytes: value.resultBytes ? new Uint8Array(value.resultBytes) : null,
  };
}

/** Persist one exact generated artifact without replacing an old job's bytes. */
async function installBackupV2Artifact(
  deps: PiDeps,
  jobId: string,
  path: string,
  value: unknown,
): Promise<void> {
  if (
    !path.startsWith(JOBS_RUNTIME_ROOT + "/") &&
    !path.startsWith(BACKUP_BASE + "/")
  ) fail();
  const bytes = [...backupV2ArtifactBytes(value)];
  const program = `const path=${JSON.stringify(path)},bytes=new Uint8Array(${
    JSON.stringify(bytes)
  });const before=await Deno.lstat(path.slice(0,path.lastIndexOf("/")));if(!before.isDirectory||before.isSymlink||before.uid!==0||(before.mode&511)!==448||await Deno.realPath(path.slice(0,path.lastIndexOf("/")))!==path.slice(0,path.lastIndexOf("/")))throw Error("Unsafe parent");try{const info=await Deno.lstat(path);if(!info.isFile||info.isSymlink||info.uid!==0||info.nlink!==1||(info.mode&511)!==384||info.size!==bytes.length)throw Error("Unsafe existing artifact");const prior=await Deno.readFile(path);if(prior.some((b,i)=>b!==bytes[i]))throw Error("Artifact conflict");}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;using file=await Deno.open(path,{createNew:true,write:true,mode:384});let at=0;while(at<bytes.length){const count=await file.write(bytes.subarray(at));if(count<=0)throw Error("Short write");at+=count;}await file.sync();}using parent=await Deno.open(path.slice(0,path.lastIndexOf("/")),{read:true});await parent.sync();`;
  const script = `printf '%s' ${shellQuote(program)} | DENO_DIR=${
    shellQuote(backupV2ControlCacheDirectory(jobId))
  } /usr/local/bin/deno run --no-prompt --no-config --no-lock --no-code-cache --allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT} --allow-write=${BACKUP_BASE},${JOBS_RUNTIME_ROOT} -`;
  if ((await deps.remote.root(script)).code !== 0) {
    throw new Error("Backup v2 immutable artifact installation failed");
  }
}

export function realBackupV2ControllerCapabilities(
  deps: PiDeps,
  bridge: BackupV2ControllerCapabilities["bridge"],
  removeGate: (path: string) => Promise<void> = Deno.remove,
): BackupV2ControllerCapabilities {
  const pathForClear = (gate: BackupV2Gate) =>
    `${PIP_JOB_EVIDENCE_PATH}/${gate.envelope.request.jobId}/v2-${gate.gateId}-${gate.custody?.invocationId}-cleared.json`;
  type StopProof = {
    gate: BackupV2Gate;
    proof: BackupV2ControllerObservation;
    cancellation?: boolean;
    artifacts?: TerminalArtifacts;
    exactStop?: {
      unitName: string;
      invocationId: string;
      sourceBootId: string;
      completed: true;
      code: 0;
    };
  };
  const observe = async (gate: BackupV2Gate) => {
    const saved = await deps.private.read<StopProof>(pathForClear(gate));
    let options: BackupV2KernelObservationOptions = {};
    if (saved?.exactStop) {
      same(saved.gate, gate);
      if (saved.cancellation) {
        options = {
          cancellationStopProof: {
            gate,
            observation: saved.proof as BackupV2KernelObservation,
            exactStop: saved.exactStop,
          },
        };
      } else {
        if (!backupV2ProcessesSettled(gate, saved.proof)) fail();
        options = {
          expectedCustodySha256: saved.artifacts?.nativeCustodySha256,
          retainedTerminalProof: {
            gate,
            observation: saved.proof as BackupV2KernelObservation,
            resultSha256: saved.artifacts?.resultSha256 ?? null,
            exactStop: saved.exactStop,
          },
        };
      }
    }
    return await observeBackupV2Source(gate, deps.remote, options);
  };
  const retainedProof = async (
    gate: BackupV2Gate,
    timeoutMs = 30_000,
    expected?: TerminalArtifacts,
  ): Promise<boolean> => {
    const saved = await deps.private.read<
      StopProof
    >(pathForClear(gate));
    if (!saved?.exactStop) return false;
    same(saved.gate, gate);
    if (
      expected &&
      (saved.cancellation || !isDeepStrictEqual(saved.artifacts, expected))
    ) return false;
    if (saved.cancellation) {
      if (saved.proof.sourceBootId !== gate.sourceBootId) fail();
      same(saved.proof.identity, gate.custody);
    } else if (!backupV2ProcessesSettled(gate, saved.proof, false)) fail();
    return await pollBackupV2Settlement(async () => {
      const current = await observe(gate);
      if (
        current.sourceBootId !== null &&
        current.sourceBootId !== gate.sourceBootId
      ) fail();
      if (current.identity !== null) same(current.identity, gate.custody);
      if (!backupV2TreeSettled(gate, current, true)) return false;
      if (saved.artifacts) {
        if (!current.resultBytes || !current.nativeCustodySha256) return false;
        if (
          backupV2ArtifactSha256(current.resultBytes) !==
            saved.artifacts.resultSha256 ||
          current.nativeCustodySha256 !== saved.artifacts.nativeCustodySha256
        ) fail();
      }
      return true;
    }, timeoutMs);
  };
  return {
    now: deps.now,
    log: deps.logger,
    persist: (state) => deps.private.write(CONTROLLER_STATE_PATH, state),
    archive: (state) =>
      deps.private.write(
        `${PIP_JOB_EVIDENCE_PATH}/predecessor-${
          backupV2ArtifactSha256(backupV2ArtifactBytes(state))
        }.json`,
        state,
      ),
    gate: {
      read: async () => await deps.private.read(GATE_PATH) ?? null,
      async replace(expected, next) {
        same(await deps.private.read(GATE_PATH) ?? null, expected);
        if (next) {
          await deps.private.write(GATE_PATH, validateBackupV2Gate(next));
          return;
        }
        if (!expected || !await retainedProof(expected)) fail();
        if (
          (await deps.remote.root(backupV2RuntimeLeaseCleanupProgram(expected)))
            .code !== 0
        ) {
          throw new Error("Exact settled runtime lease cleanup failed");
        }
        // Only the controller lock holder may remove the exact compared gate.
        same(await deps.private.read(GATE_PATH), expected);
        await removeGate(GATE_PATH);
      },
      cleared: (gate, expected) => retainedProof(gate, 30_000, expected),
    },
    async create(periodKey) {
      const deployment = await loadDeployment(deps),
        config = await loadSourceConfig(deps),
        id = crypto.randomUUID(),
        jobId = `job-${id}`;
      const captureSettings: CaptureSettings = {
        sources: config.sources,
        generation: `generation-${id}`,
        recipientFile: `${JOBS_RUNTIME_ROOT}/${jobId}/recipient.asc`,
        recipientSha256: deployment.recipientSha256,
        recipientFingerprint: deployment.recipientFingerprint,
        exclusionsText: config.exclusionsText,
      };
      const request: BackupV2Request = {
        schemaVersion: 2,
        format: "backup-v2",
        profile: BACKUP_V2_PROFILE_ID,
        jobId,
        captureId: captureSettings.generation,
        periodKey,
        requestedAtUtc: deps.now().toISOString(),
        sourceRevision: deployment.sourceRevision,
        sourceConfigSha256: backupV2SourceConfigSha256(captureSettings),
        recipientSha256: deployment.recipientSha256,
        recipientFingerprint: deployment.recipientFingerprint,
      };
      const envelope = {
        request,
        requestSha256: backupV2RequestSha256(request),
      };
      const boot = await deps.remote.source(
        "cat /proc/sys/kernel/random/boot_id",
      );
      if (boot.code !== 0 || !/^[0-9a-f-]{36}$/.test(boot.stdout.trim())) {
        fail();
      }
      const gate = (kind: "worker" | "verify") => {
        const gateId = crypto.randomUUID();
        return validateBackupV2Gate({
          schemaVersion: 2,
          format: "backup-v2",
          owner: GATE_OWNER,
          envelope,
          gateId,
          sourceBootId: boot.stdout.trim(),
          kind,
          unitName: `arch-vps-b2-v2-${kind}-${id}-${gateId}.service`,
          custody: null,
          state: "PENDING",
          remoteHost: GATE_REMOTE_HOST,
          sourceLockPath: GATE_SOURCE_LOCK_PATH,
          createdAtUtc: request.requestedAtUtc,
          updatedAtUtc: request.requestedAtUtc,
        });
      };
      return validateBackupV2WorkerSettings({
        schemaVersion: 2,
        format: "backup-v2",
        envelope,
        captureSettings,
        B2Settings: config.b2,
        workerGate: gate("worker"),
        verifierGate: gate("verify"),
        publicationAttemptId: crypto.randomUUID(),
      });
    },
    async admit(legacy) {
      const oracleState = await deps.private.read(
        ".private/backup-runtime.json",
      );
      const claim = await backblazeScheduledClaim(
        deps,
        oracleState,
        deps.now(),
      );
      assertBackblazeLaunchAllowed(oracleState, claim);
      if (legacy.job && !["COMPLETE", "FAILED"].includes(legacy.job.phase)) {
        fail();
      }
      const check = await deps.remote.root(
        `flock -n ${shellQuote(GATE_SOURCE_LOCK_PATH)} true`,
      );
      if (check.code !== 0) fail();
      if (legacy.job) {
        for (
          const name of [
            workerUnitNameOf(legacy.job.envelope.request.generation),
            verifyUnitName(legacy.job.envelope.request.generation),
          ]
        ) {
          const observed = await deps.remote.observe(
            name,
            legacy.job.envelope.request.jobId,
          );
          if (
            !observed.reachable || !observed.lockFree ||
            Number(observed.props.get("MainPID") || 0) !== 0 ||
            Number(observed.props.get("ControlPID") || 0) !== 0 ||
            (observed.props.get("LoadState") !== "not-found" &&
              Number(observed.props.get("TasksCurrent") || 0) !== 0)
          ) fail();
        }
      }
    },
    async install(settings) {
      const recipient = (await loadSourceConfig(deps)).recipientBytes;
      if (
        backupV2ArtifactSha256(recipient) !==
          settings.envelope.request.recipientSha256
      ) fail();
      const req = settings.envelope.request;
      const files = [
        { path: "settings.json", data: backupV2ArtifactBytes(settings) },
        { path: "recipient.asc", data: recipient },
        {
          path: "entry-worker.ts",
          data: new TextEncoder().encode(
            backupV2Entrypoint(req.jobId, req.sourceRevision, "worker"),
          ),
        },
        {
          path: "entry-verify.ts",
          data: new TextEncoder().encode(
            backupV2Entrypoint(req.jobId, req.sourceRevision, "verify"),
          ),
        },
      ].map((entry) => ({
        path: entry.path,
        data: [...entry.data],
        sha256: backupV2ArtifactSha256(entry.data),
      }));
      if (
        (await deps.remote.installer({
          jobId: req.jobId,
          sourceRevision: req.sourceRevision,
          files,
        })).code !== 0
      ) throw new Error("Backup v2 immutable runtime installation failed");
    },
    async launch(settings, kind) {
      const gate = kind === "worker"
        ? settings.workerGate
        : settings.verifierGate;
      const before = await observe(gate);
      if (
        before.unit !== "ABSENT" || before.sourceBootId !== gate.sourceBootId
      ) fail();
      if (
        (await deps.remote.root(
          backupV2LaunchArguments(settings, kind).map(shellQuote).join(" "),
        )).code !== 0
      ) throw new Error("Backup v2 launch outcome unproved");
    },
    observe,
    acknowledge: (gate) =>
      installBackupV2Artifact(
        deps,
        gate.envelope.request.jobId,
        `${backupV2GateDirectory(gate)}/gate-bound.json`,
        {
          gateId: gate.gateId,
          requestSha256: gate.envelope.requestSha256,
          sourceBootId: gate.sourceBootId,
          custody: gate.custody,
        },
      ),
    verifierInput: (job) =>
      installBackupV2Artifact(
        deps,
        job.settings.envelope.request.jobId,
        `${JOBS_RUNTIME_ROOT}/${job.settings.envelope.request.jobId}/verifier-request.json`,
        {
          workerGate: job.workerGate,
          workerResult: job.workerResult,
          workerResultBytes: job.workerResultBytes,
        },
      ),
    async preserveProtection(verified) {
      const descriptor = validateBackupV2ProtectionDescriptor(
          verified.protectedGraph,
        ),
        source = backupV2ProtectionSourceDirectory(descriptor.manifestSha256),
        target = backupV2ProtectionControlDirectory(descriptor.manifestSha256);
      const write = async (path: string, bytes: Uint8Array) => {
        const old = await deps.private.readBytes(
          path,
          BACKUP_V2_LIMITS.controlResponseBytes,
        );
        if (old) same([...old], [...bytes]);
        else await deps.private.writeBytes(path, bytes);
        const actual = await deps.private.readBytes(
          path,
          BACKUP_V2_LIMITS.controlResponseBytes,
        );
        if (
          !actual ||
          backupV2ArtifactSha256(actual) !== backupV2ArtifactSha256(bytes)
        ) fail();
      };
      await copyBackupV2Protection(verified, {
        async read(name) {
          if (name !== "manifest.json" && !/^page-[0-9]{8}\.json$/.test(name)) {
            fail();
          }
          const path = `${source}/${name}`;
          const program = `const path=${
            JSON.stringify(path)
          },parent=path.slice(0,path.lastIndexOf("/")),dir=await Deno.lstat(parent);if(!dir.isDirectory||dir.isSymlink||dir.uid!==0||(dir.mode&511)!==448||await Deno.realPath(parent)!==parent)throw Error("Unsafe graph parent");const before=await Deno.lstat(path);if(!before.isFile||before.isSymlink||before.uid!==0||before.nlink!==1||(before.mode&511)!==384||before.size>${BACKUP_V2_LIMITS.controlResponseBytes})throw Error("Unsafe graph");const bytes=await Deno.readFile(path),after=await Deno.lstat(path);if(bytes.length!==before.size||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size)throw Error("Changed graph");let at=0;while(at<bytes.length){const count=await Deno.stdout.write(bytes.subarray(at));if(count<=0)throw Error("Short graph read");at+=count;}`;
          const result = await deps.remote.root(
            backupV2RemoteProgram(verified.envelope.request.jobId, program),
          );
          const bytes = new TextEncoder().encode(result.stdout);
          if (
            result.code !== 0 ||
            bytes.length > BACKUP_V2_LIMITS.controlResponseBytes
          ) fail();
          return bytes;
        },
        write: (name, bytes) => write(`${target}/${name}`, bytes),
      });
      await write(
        `${
          target.slice(0, target.lastIndexOf("/"))
        }/roots/${descriptor.root.plaintextSha256}.json`,
        backupV2ArtifactBytes(descriptor),
      );
    },
    async stop(gate, expected) {
      const actual = await observe(gate);
      if (actual.unit === "ABSENT") {
        if (!await retainedProof(gate, 30_000, expected)) fail();
        return;
      }
      if (!backupV2ProcessesSettled(gate, actual)) fail();
      if (
        expected &&
        (!actual.resultBytes ||
          backupV2ArtifactSha256(actual.resultBytes) !==
            expected.resultSha256 ||
          actual.nativeCustodySha256 !== expected.nativeCustodySha256)
      ) fail();
      const artifacts = expected ??
        (actual.resultBytes && actual.nativeCustodySha256
          ? {
            resultSha256: backupV2ArtifactSha256(actual.resultBytes),
            nativeCustodySha256: actual.nativeCustodySha256,
          }
          : undefined);
      const prior = await deps.private.read<StopProof>(pathForClear(gate));
      if (prior) {
        same(prior.gate, gate);
        if (
          expected &&
          (prior.cancellation || !isDeepStrictEqual(prior.artifacts, expected))
        ) fail();
      } else {
        await deps.private.write(pathForClear(gate), {
          gate,
          proof: { ...actual, resultBytes: null },
          ...(artifacts ? { artifacts } : {}),
          recordedAtUtc: deps.now().toISOString(),
        });
      }
      const script = `test "$(cat /proc/sys/kernel/random/boot_id)" = ${
        shellQuote(gate.sourceBootId)
      }\ntest "$(systemctl show --value --property=InvocationID ${
        shellQuote(gate.unitName)
      })" = ${shellQuote(gate.custody!.invocationId)}\nsystemctl stop ${
        shellQuote(gate.unitName)
      }`;
      if ((await deps.remote.root(script)).code !== 0) {
        throw new Error("Exact source unit stop failed");
      }
      const saved = await deps.private.read<StopProof>(pathForClear(gate));
      if (!saved) fail();
      same(saved.gate, gate);
      await deps.private.write(pathForClear(gate), {
        ...saved,
        exactStop: {
          unitName: gate.unitName,
          invocationId: gate.custody!.invocationId,
          sourceBootId: gate.sourceBootId,
          completed: true,
          code: 0,
        },
      });
    },
    async cancel(gate) {
      if (!gate.custody) {
        return {
          state: "CANCELLATION_BLOCKED",
          reason: "SOURCE_INVOCATION_UNPROVED",
        };
      }
      let observationFailure: BackupV2CancellationBlockedReason | undefined;
      const deadline = performance.now() + 30_000;
      const settled = await settleBackupV2Cancellation(gate.custody, {
        now: () => performance.now(),
        observe: async () => {
          observationFailure = undefined;
          const value = await observe(gate);
          if (value.sourceBootId === null) return null;
          if (value.sourceBootId !== gate.sourceBootId) {
            observationFailure = "SOURCE_BOOT_CHANGED";
            fail();
          }
          if (
            value.identity !== null &&
            !isDeepStrictEqual(value.identity, gate.custody)
          ) {
            observationFailure = "SOURCE_INVOCATION_UNPROVED";
            fail();
          }
          if (!value.tree && value.unit === "ABSENT") {
            observationFailure = "SOURCE_UNIT_ABSENT";
          }
          return value.tree;
        },
        stop: async () => {
          const before = await observe(gate);
          same(before.identity, gate.custody);
          if (before.sourceBootId !== gate.sourceBootId) fail();
          if (!await deps.private.read(pathForClear(gate))) {
            await deps.private.write(pathForClear(gate), {
              gate,
              proof: { ...before, resultBytes: null },
              cancellation: true,
              recordedAtUtc: deps.now().toISOString(),
            });
          }
          if (
            (await deps.remote.root(
              `test "$(cat /proc/sys/kernel/random/boot_id)" = ${
                shellQuote(gate.sourceBootId)
              }
test "$(systemctl show --value --property=InvocationID ${
                shellQuote(gate.unitName)
              })" = ${shellQuote(gate.custody!.invocationId)}\nsystemctl stop ${
                shellQuote(gate.unitName)
              }`,
            )).code !== 0
          ) fail();
          const saved = await deps.private.read<StopProof>(pathForClear(gate));
          if (!saved) fail();
          same(saved.gate, gate);
          await deps.private.write(pathForClear(gate), {
            ...saved,
            exactStop: {
              unitName: gate.unitName,
              invocationId: gate.custody!.invocationId,
              sourceBootId: gate.sourceBootId,
              completed: true,
              code: 0,
            },
          });
        },
      });
      if (settled.state !== "SETTLED") {
        return {
          state: settled.state,
          reason: observationFailure ?? settled.reason,
        };
      }
      const remaining = deadline - performance.now();
      try {
        if (remaining > 0 && await retainedProof(gate, remaining)) {
          return "SETTLED";
        }
      } catch {
        return {
          state: "CANCELLATION_BLOCKED",
          reason: "SOURCE_OBSERVATION_UNPROVED",
        };
      }
      return {
        state: "CANCELLATION_BLOCKED",
        reason: "SOURCE_CLEAR_PROOF_MISSING",
      };
    },
    bridge,
  };
}

type RetentionPhase =
  | "REQUESTED"
  | "RUNNING"
  | "SETTLED"
  | "PLAN_ONLY"
  | "PLAN_BLOCKED"
  | "COMPLETE"
  | "PARTIAL"
  | "CANCELLATION_BLOCKED";

type MaintenanceSettings = Omit<BackupV2WorkerSettings, "B2Settings">;

export interface BackupV2RetentionControl {
  schemaVersion: 3;
  format: "backup-v2-retention-controller";
  anchor: string;
  settings: MaintenanceSettings;
  input: BackupV2PruneInput;
  gate: BackupV2Gate;
  phase: RetentionPhase;
  result: BackupV2PruneWorkerResult | null;
  resultSha256?: string;
  retryInterrupted?: boolean;
  plannedResult?: BackupV2PruneWorkerResult;
  cancellationBlockedReason?: BackupV2CancellationBlockedReason;
}

type RetiredRestic = NonNullable<
  BackupV2PruneInput["snapshot"]["retiredRestic"]
>;
interface RetiredLegacyCapture {
  captureId: string;
  retiredAtUtc: string;
  evidenceSha256: string;
}

export function backupV2RetentionPolicy(
  value: unknown,
  planOnly = false,
): {
  policy: BackupV2RetentionPolicy;
  retiredRestic?: RetiredRestic;
  retiredLegacyCaptures?: RetiredLegacyCapture[];
} {
  const defaults = DEFAULT_BACKUP_V2_RETENTION_POLICY;
  if (value === undefined) return { policy: { ...defaults } };
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const { retiredRestic, retiredLegacyCaptures, ...raw } = value as Record<
    string,
    unknown
  >;
  const policy = validateBackupV2RetentionPolicy({ ...defaults, ...raw });
  if (planOnly) policy.execute = false;
  let legacy: RetiredLegacyCapture[] | undefined;
  if (retiredLegacyCaptures !== undefined) {
    if (
      !Array.isArray(retiredLegacyCaptures) ||
      retiredLegacyCaptures.length > 256
    ) fail();
    legacy = retiredLegacyCaptures.map((value) => {
      const r = record(value, ["captureId", "retiredAtUtc", "evidenceSha256"]);
      const job = validateBackupV2RetentionJob({
        captureId: r.captureId,
        evidenceSha256: r.evidenceSha256,
        format: "backup-v1",
        custody: "SETTLED_UNACCEPTED",
      });
      if (
        typeof r.retiredAtUtc !== "string" ||
        new Date(r.retiredAtUtc).toISOString() !== r.retiredAtUtc
      ) fail();
      return {
        captureId: job.captureId,
        evidenceSha256: job.evidenceSha256!,
        retiredAtUtc: r.retiredAtUtc,
      };
    });
    if (
      new Set(legacy.map((entry) => entry.captureId)).size !== legacy.length
    ) fail();
  }
  return {
    policy,
    ...(retiredRestic !== undefined
      ? { retiredRestic: validateBackupV2RetiredRestic(retiredRestic) }
      : {}),
    ...(legacy ? { retiredLegacyCaptures: legacy } : {}),
  };
}

const acceptedId = (entry: BackupRuntimeCatalogEntry) =>
  entry.format === "backup-v2"
    ? entry.envelope.request.captureId
    : entry.entry.index.generation;
const acceptedAt = (entry: BackupRuntimeCatalogEntry) =>
  entry.format === "backup-v2"
    ? entry.acceptedAtUtc
    : entry.entry.acceptedAtUtc;
const digest = (value: unknown) =>
  backupV2ArtifactSha256(backupV2ArtifactBytes(value));
const withoutKey = (
  { B2Settings: _key, ...settings }: BackupV2WorkerSettings,
): MaintenanceSettings => settings;
const proofPath = (gate: BackupV2Gate) =>
  `${PIP_JOB_EVIDENCE_PATH}/${gate.envelope.request.jobId}/v2-${gate.gateId}-${gate.custody?.invocationId}-cleared.json`;

export function backupV2RetentionNeedsReconcile(
  control: BackupV2RetentionControl,
): boolean {
  return !["PLAN_ONLY", "PLAN_BLOCKED", "COMPLETE"].includes(control.phase);
}

export async function readBackupV2RetentionControl(
  privateIO: Pick<PrivateSeam, "read">,
  verifyCatalogOnly = false,
): Promise<BackupV2RetentionControl | undefined> {
  const control = await privateIO.read<BackupV2RetentionControl>(
    verifyCatalogOnly ? B2_CATALOG_CONTROL_PATH : B2_RETENTION_CONTROL_PATH,
  );
  if (control === undefined) return undefined;
  if (
    !control || control.schemaVersion !== 3 ||
    control.format !== "backup-v2-retention-controller" ||
    !/^[a-f0-9]{64}$/.test(control.anchor) ||
    ![
      "REQUESTED",
      "RUNNING",
      "SETTLED",
      "PLAN_ONLY",
      "PLAN_BLOCKED",
      "COMPLETE",
      "PARTIAL",
      "CANCELLATION_BLOCKED",
    ].includes(control.phase) ||
    !control.input || control.input.schemaVersion !== 2 ||
    control.input.format !== "backup-v2-prune" ||
    !["PLAN", "EXECUTE"].includes(control.input.stage)
  ) fail();
  const gate = validateBackupV2Gate(control.gate),
    pending = validateBackupV2Gate(control.input.gate);
  if (
    gate.kind !== "prune" || pending.kind !== "prune" ||
    pending.state !== "PENDING"
  ) fail();
  same({
    ...gate,
    custody: null,
    state: "PENDING",
    updatedAtUtc: pending.updatedAtUtc,
  }, pending);
  same(gate.envelope, control.settings.envelope);
  retentionTransactionPath(control.input.transactionId, "plan");
  if (
    verifyCatalogOnly !== (control.input.snapshot.verifyCatalogOnly === true)
  ) fail();
  if (
    control.input.stage === "EXECUTE" &&
    (!control.plannedResult || !control.input.snapshot.policy.execute ||
      !isDeepStrictEqual(control.input.plan, control.plannedResult.plan))
  ) fail();
  if (
    control.phase === "SETTLED" &&
    (!control.result || !/^[a-f0-9]{64}$/.test(control.resultSha256 ?? ""))
  ) fail();
  return control;
}

function newPruneGate(settings: MaintenanceSettings, now: Date): BackupV2Gate {
  const id = crypto.randomUUID();
  return validateBackupV2Gate({
    ...settings.verifierGate,
    kind: "prune",
    gateId: id,
    unitName: `arch-vps-b2-v2-prune-${
      settings.envelope.request.captureId.slice("generation-".length)
    }-${id}.service`,
    state: "PENDING",
    custody: null,
    createdAtUtc: now.toISOString(),
    updatedAtUtc: now.toISOString(),
  });
}

type CleanupProof = {
  gate: BackupV2Gate;
  proof: BackupV2ControllerObservation & BackupV2KernelObservation;
  artifacts: TerminalArtifacts;
  exactStop:
    & NonNullable<
      BackupV2KernelObservationOptions["retainedTerminalProof"]
    >["exactStop"]
    & { code: 0 };
};

async function prepareAcceptedBackupV2ScratchCleanup(
  job: BackupV2ControllerJob,
  maintenanceJobId: string,
  deps: PiDeps,
  caps: BackupV2ControllerCapabilities,
): Promise<void> {
  if (job.phase !== "COMPLETE" || !job.verified?.protectedGraph) fail();
  const proofs = [];
  for (const gate of [job.workerGate, job.verifierGate]) {
    if (!await caps.gate.cleared(gate)) fail();
    const saved = await deps.private.read<CleanupProof>(proofPath(gate));
    if (!saved?.artifacts || !saved.exactStop) fail();
    same(saved.gate, gate);
    proofs.push({
      gate,
      options: {
        expectedCustodySha256: saved.artifacts.nativeCustodySha256,
        retainedTerminalProof: {
          gate,
          observation: saved.proof,
          resultSha256: saved.artifacts.resultSha256,
          exactStop: saved.exactStop,
        },
      },
    });
  }
  await installBackupV2Artifact(
    deps,
    maintenanceJobId,
    `${JOBS_RUNTIME_ROOT}/${maintenanceJobId}/prune-cleanup-proofs.json`,
    proofs,
  );
}

async function proveRetentionIdle(deps: PiDeps): Promise<void> {
  await withBackblazeReportReason(
    "B2_RETENTION_ORACLE_CUSTODY_UNPROVED",
    async () => {
      const oracle = await deps.private.read(".private/backup-runtime.json");
      const claim = await deps.private.read(MANIFEST_PATH);
      assertBackblazeLaunchAllowed(oracle, claim);
    },
  );
  await withBackblazeReportReason(
    "B2_RETENTION_CUSTODY_UNPROVED",
    () => proveBackblazeSourceIdle(deps.remote),
  );
}

async function discoverRetentionCustody(
  deps: PiDeps,
  settings: MaintenanceSettings,
  state: BackupV2ControllerState,
  options: ReturnType<typeof backupV2RetentionPolicy>,
): Promise<Pick<BackupV2PruneInput["snapshot"], "protection" | "jobs">> {
  const request = settings.envelope.request;
  const result = await deps.remote.root(backupV2RemoteProgram(
    request.jobId,
    `import { discoverBackupV2SourceGates, discoverBackupV2UnresolvedPuts } from ${
      JSON.stringify(
        `${RELEASES_ROOT}/${request.sourceRevision}/scripts/backup-v2-worker.ts`,
      )
    };const boot=await (async()=>{const read=await new Deno.Command("/usr/bin/cat",{args:["/proc/sys/kernel/random/boot_id"],clearEnv:true,env:{PATH:"/usr/bin:/bin"},stdout:"piped",stderr:"piped"}).output();if(!read.success)throw Error("Source boot unavailable");return new TextDecoder().decode(read.stdout);})();console.log(JSON.stringify({sourceBootId:boot.trim(),gates:(await discoverBackupV2SourceGates()).filter(g=>g.kind!=="prune"),unresolvedPuts:await discoverBackupV2UnresolvedPuts()}));`,
  ));
  if (
    result.code !== 0 ||
    new TextEncoder().encode(result.stdout).length >
      BACKUP_V2_LIMITS.controlResponseBytes
  ) fail();
  const observed = JSON.parse(result.stdout);
  if (
    observed.sourceBootId !== settings.verifierGate.sourceBootId ||
    !Array.isArray(observed.gates) || !Array.isArray(observed.unresolvedPuts) ||
    observed.gates.length > 256
  ) fail();
  const jobs = new Map<string, BackupV2RetentionJob>();
  for (const raw of observed.gates) {
    const gate = validateBackupV2Gate(raw),
      capture = gate.envelope.request.captureId;
    if (gate.kind === "prune" || !gate.custody) fail();
    if (jobs.get(capture)?.custody === "PROTECTED") continue;
    const saved = await deps.private.read<
      CleanupProof & { cancellation?: boolean }
    >(proofPath(gate));
    const exact = saved?.exactStop;
    const settled = saved && exact &&
      isDeepStrictEqual(
        { ...saved.gate, updatedAtUtc: gate.updatedAtUtc },
        gate,
      ) &&
      exact.code === 0 && exact.completed === true &&
      exact.unitName === gate.unitName &&
      exact.invocationId === gate.custody.invocationId &&
      exact.sourceBootId === gate.sourceBootId &&
      saved.proof.sourceBootId === gate.sourceBootId &&
      isDeepStrictEqual(saved.proof.identity, gate.custody) &&
      (saved.cancellation === true ||
        backupV2ProcessesSettled(gate, saved.proof));
    jobs.set(capture, {
      captureId: capture,
      custody: settled ? "SETTLED_UNACCEPTED" : "PROTECTED",
    });
  }
  // A current failure can still be retried. A completed current job must
  // either have proved terminal custody in the census or remain protected.
  if (state.job) {
    const captureId = state.job.settings.envelope.request.captureId;
    if (state.job.phase !== "COMPLETE" || !jobs.has(captureId)) {
      jobs.set(captureId, { captureId, custody: "PROTECTED" });
    }
  }
  if (state.legacy.job && state.legacy.job.phase !== "COMPLETE") {
    const captureId = state.legacy.job.envelope.request.generation;
    jobs.set(captureId, {
      captureId,
      custody: "PROTECTED",
      format: "backup-v1",
    });
  }
  const cutoff = deps.now().getTime() -
    options.policy.orphanGraceHours * 3_600_000;
  for (const entry of options.retiredLegacyCaptures ?? []) {
    if (
      !jobs.has(entry.captureId) && Date.parse(entry.retiredAtUtc) <= cutoff
    ) {
      jobs.set(entry.captureId, {
        captureId: entry.captureId,
        custody: "SETTLED_UNACCEPTED",
        format: "backup-v1",
        evidenceSha256: entry.evidenceSha256,
      });
    }
  }
  const accepted = new Set(state.catalog.map(acceptedId));
  return {
    jobs: [...jobs.values()].filter((job) =>
      job.custody === "PROTECTED" || !accepted.has(job.captureId)
    )
      .sort((a, b) => a.captureId.localeCompare(b.captureId)),
    protection: {
      acceptedRoots: [],
      activeObjects: [],
      sealedRoleManifests: [],
      unresolvedPuts: observed.unresolvedPuts.map(validateBackupV2PutIntent),
    },
  };
}

async function configuredRetentionKey(deps: PiDeps): Promise<B2Settings> {
  const config = await loadSourceConfig(deps);
  return await selectB2RetentionCredential(
    config.b2,
    () => deps.private.read(B2_RETENTION_KEY_PATH),
  );
}

async function startRetentionControl(
  state: BackupV2ControllerState,
  deps: PiDeps,
  caps: BackupV2ControllerCapabilities,
  anchor: string,
  options: ReturnType<typeof backupV2RetentionPolicy>,
  verifyCatalogOnly: boolean,
): Promise<BackupV2RetentionControl> {
  await proveRetentionIdle(deps);
  const settings = withoutKey(
    await withBackblazeReportReason(
      "B2_RETENTION_SOURCE_PREFLIGHT_FAILED",
      () => caps.create(weekWindow(deps.now()).periodKey),
    ),
  );
  const graphs = await withBackblazeReportReason(
    "B2_RETENTION_CATALOG_BINDING_INVALID",
    async () => {
      const graphs: BackupV2ProtectionDescriptor[] = [];
      for (const entry of state.catalog) {
        if (entry.format !== "backup-v2") continue;
        const bytes = await deps.private.readBytes(
          `${BACKUP_V2_PROTECTION_CONTROL_BASE}/roots/${entry.selectedRoot.reference.plaintextSha256}.json`,
          BACKUP_V2_LIMITS.controlResponseBytes,
        );
        if (!bytes) fail();
        const descriptor = validateBackupV2ProtectionDescriptor(
          JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
        );
        same(descriptor.root, entry.selectedRoot.reference);
        graphs.push(descriptor);
      }
      return graphs;
    },
  );
  const custody = verifyCatalogOnly
    ? {
      jobs: [],
      protection: {
        acceptedRoots: [],
        activeObjects: [],
        sealedRoleManifests: [],
        unresolvedPuts: [],
      },
    }
    : await withBackblazeReportReason(
      "B2_RETENTION_CUSTODY_UNPROVED",
      () => discoverRetentionCustody(deps, settings, state, options),
    );
  const gate = newPruneGate(settings, deps.now());
  const job = state.job;
  const scratchProof = job?.phase === "COMPLETE"
    ? await deps.private.read(
      `${PIP_JOB_EVIDENCE_PATH}/${job.settings.envelope.request.jobId}/v2-scratch-cleanup.json`,
    )
    : undefined;
  const scratchCleanupRequestSha256 =
    !verifyCatalogOnly && job?.phase === "COMPLETE" &&
      job.workerGate.sourceBootId === gate.sourceBootId &&
      job.verifierGate.sourceBootId === gate.sourceBootId &&
      scratchProof === undefined
      ? job.settings.envelope.requestSha256
      : null;
  return {
    schemaVersion: 3,
    format: "backup-v2-retention-controller",
    anchor,
    settings,
    gate,
    phase: "REQUESTED",
    result: null,
    input: {
      schemaVersion: 2,
      format: "backup-v2-prune",
      gate,
      transactionId: crypto.randomUUID(),
      stage: "PLAN",
      plan: null,
      scratchCleanupRequestSha256,
      graphs,
      snapshot: {
        policy: options.policy,
        ...(options.retiredRestic
          ? { retiredRestic: options.retiredRestic }
          : {}),
        ...(verifyCatalogOnly ? { verifyCatalogOnly: true as const } : {}),
        plannedAtUtc: deps.now().toISOString(),
        catalog: state.catalog,
        custody: {
          lockId: GATE_SOURCE_LOCK_PATH,
          sourceBootId: gate.sourceBootId,
          sourceSettled: true,
        },
        receipts: [],
        ...custody,
      },
    },
  };
}

export function validateBackupV2PruneWorkerResult(
  value: unknown,
  gate: BackupV2Gate,
  input: BackupV2PruneInput,
): BackupV2PruneWorkerResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as BackupV2PruneWorkerResult;
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2-prune-result" ||
    r.transactionId !== input.transactionId || r.stage !== input.stage ||
    !/^[a-f0-9]{64}$/.test(r.nativeCustodySha256) ||
    !["PLAN_PROVED", "COMPLETE", "PARTIAL"].includes(r.state) ||
    (r.stage === "PLAN") !== (r.state === "PLAN_PROVED") ||
    new Date(r.finishedAtUtc).toISOString() !== r.finishedAtUtc
  ) fail();
  const actual = validateBackupV2Gate(r.gate);
  same({ ...actual, updatedAtUtc: gate.updatedAtUtc }, gate);
  const plan = validateRetentionPlanReference(r.plan);
  if (input.stage === "EXECUTE") same(plan, input.plan);
  const summary = validateRetentionSummary(r.summary);
  const originals = input.snapshot.catalog;
  const ranking = [...originals].sort((a, b) =>
    (acceptedAt(a) === acceptedAt(b)
      ? 0
      : acceptedAt(a) > acceptedAt(b)
      ? -1
      : 1) ||
    (acceptedId(a) < acceptedId(b) ? -1 : 1)
  );
  const damaged = new Set(summary.damagedCaptureIds);
  const ids = ranking.map(acceptedId);
  if (
    [...damaged].some((id) => !ids.includes(id)) ||
    !Array.isArray(r.retainedCaptureIds) ||
    new Set(r.retainedCaptureIds).size !== r.retainedCaptureIds.length ||
    r.retainedCaptureIds.some((id) => !ids.includes(id) || damaged.has(id))
  ) fail();
  const kept = r.retainedCaptureIds;
  same(kept, ids.filter((id) => kept.includes(id)));
  const intact = ids.filter((id) => !damaged.has(id));
  if (r.stage === "PLAN") {
    const required = damaged.size || input.snapshot.verifyCatalogOnly
      ? intact
      : intact.slice(0, input.snapshot.policy.keepAccepted);
    if (required.some((id) => !kept.includes(id))) fail();
  }
  const old = new Set(
    ids.filter((id) => !kept.includes(id) && !damaged.has(id)),
  );
  if (
    summary.keptGenerations !== kept.length ||
    !Array.isArray(r.retiredCaptureIds) ||
    new Set(r.retiredCaptureIds).size !== r.retiredCaptureIds.length ||
    r.retiredCaptureIds.some((id) => !old.has(id)) ||
    !Array.isArray(r.obsoleteLegacyCaptureIds) ||
    r.obsoleteLegacyCaptureIds.some((id) =>
      !r.retiredCaptureIds.includes(id) ||
      !originals.some((entry) =>
        entry.format === "backup-v1" && acceptedId(entry) === id
      )
    )
  ) fail();
  if (
    input.stage === "PLAN" && (summary.deletedObjects || summary.deletedBytes ||
      summary.reconciledAbsentObjects || summary.reconciledAbsentBytes)
  ) fail();
  let scratchCleanup: BackupV2PruneWorkerResult["scratchCleanup"];
  if (
    r.stage === "PLAN" && input.scratchCleanupRequestSha256 !== null &&
    (r.scratchCleanup !== undefined || summary.damagedCaptureIds.length === 0)
  ) {
    const cleanup = r.scratchCleanup;
    if (
      !cleanup || cleanup.schemaVersion !== 2 ||
      cleanup.format !== "backup-v2-scratch-cleanup" ||
      cleanup.requestSha256 !== input.scratchCleanupRequestSha256 ||
      !Number.isSafeInteger(cleanup.entriesRemoved) ||
      cleanup.entriesRemoved < 0 ||
      !Number.isSafeInteger(cleanup.logicalBytesRemoved) ||
      cleanup.logicalBytesRemoved < 0 ||
      cleanup.logicalBytesRemoved > BACKUP_V2_LIMITS.workspaceBytes
    ) fail();
    scratchCleanup = cleanup;
  } else if (r.scratchCleanup !== undefined) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-prune-result",
    gate: actual,
    transactionId: r.transactionId,
    stage: r.stage,
    state: r.state,
    plan,
    retainedCaptureIds: kept,
    retiredCaptureIds: r.retiredCaptureIds,
    obsoleteLegacyCaptureIds: r.obsoleteLegacyCaptureIds,
    summary,
    finishedAtUtc: r.finishedAtUtc,
    nativeCustodySha256: r.nativeCustodySha256,
    ...(scratchCleanup ? { scratchCleanup } : {}),
  };
}

function planStatus(
  control: BackupV2RetentionControl,
  result: BackupV2PruneWorkerResult,
): string {
  if (result.summary.damagedCaptureIds.length) return B2_CATALOG_DAMAGED_ALERT;
  if (
    control.input.snapshot.verifyCatalogOnly && control.phase === "PLAN_ONLY"
  ) return "B2_RETENTION_CATALOG_VERIFIED";
  if (
    control.phase === "PLAN_ONLY" && !control.input.snapshot.policy.execute &&
    retentionOrphansFound(result.summary)
  ) {
    return B2_RETENTION_ORPHAN_ALERT;
  }
  if (control.phase === "PLAN_ONLY" || control.phase === "PLAN_BLOCKED") {
    return `B2_RETENTION_${control.phase}`;
  }
  return `B2_RETENTION_${control.input.stage}_${control.phase}`;
}

async function retentionReport(
  control: BackupV2RetentionControl,
  deps: PiDeps,
  healthy: boolean,
  publish = false,
): Promise<BackblazeMaintenanceResult> {
  const result = control.result ?? control.plannedResult;
  const status = result
    ? planStatus(control, result)
    : control.phase === "PLAN_BLOCKED"
    ? "B2_RETENTION_PLAN_BLOCKED"
    : `B2_RETENTION_${control.input.stage}_${control.phase}`;
  const mode = control.input.snapshot.verifyCatalogOnly
    ? "verify-catalog"
    : "scheduled";
  const now = deps.now();
  const terminal = result && (publish ||
    ["PLAN_ONLY", "PLAN_BLOCKED", "COMPLETE", "PARTIAL"].includes(
      control.phase,
    ));
  const summary = result ? validateRetentionSummary(result.summary) : undefined;
  const reason = healthy
    ? terminal ? undefined : "B2_RETENTION_RECONCILIATION_PENDING"
    : summary?.blockReason ?? control.cancellationBlockedReason ??
      "B2_RETENTION_STATUS_UNPROVED";
  const checkedCaptureIds = control.input.snapshot.verifyCatalogOnly && result
    ? control.input.snapshot.catalog.map(acceptedId)
    : undefined;
  const observation: BackblazeMaintenanceResult = {
    status,
    observedAtUtc: terminal ? result.finishedAtUtc : now.toISOString(),
    healthy,
    retentionTransactionId: control.input.transactionId,
    ...(reason ? backblazeReportExplanation(reason) : {}),
    ...(summary ? { retention: summary } : {}),
    ...(checkedCaptureIds ? { checkedCaptureIds } : {}),
  };
  if (terminal) {
    const report: BackupV2PiRetentionReport = {
      schemaVersion: 1,
      format: "backblaze-retention-report",
      transactionId: control.input.transactionId,
      observedAtUtc: observation.observedAtUtc,
      status,
      healthy,
      policy: control.input.snapshot.policy,
      plan: {
        ...result.plan,
        path: retentionTransactionPath(control.input.transactionId, "plan"),
      },
      summary: summary!,
      retainedCaptureIds: result.retainedCaptureIds,
      ...(checkedCaptureIds ? { checkedCaptureIds } : {}),
      ...(reason ? backblazeReportExplanation(reason) : {}),
    };
    await withBackblazeReportReason("B2_REPORT_WRITE_FAILED", async () => {
      const path = retentionTransactionPath(
        control.input.transactionId,
        "report",
      );
      if (!isDeepStrictEqual(report, await deps.private.read(path))) {
        await deps.private.write(path, report);
      }
      await publishMaintenanceReport(
        deps.private,
        mode,
        observation,
        now,
        report,
      );
    });
  } else {
    await withBackblazeReportReason(
      "B2_REPORT_WRITE_FAILED",
      () => publishMaintenanceReport(deps.private, mode, observation, now),
    );
  }
  return observation;
}

async function readPrivatePlan(
  control: BackupV2RetentionControl,
  deps: PiDeps,
  fetchFromSource: boolean,
): Promise<void> {
  const result = control.plannedResult ?? control.result;
  if (!result) fail();
  const ref = validateRetentionPlanReference(result.plan);
  const transaction = control.input.transactionId;
  const path = retentionTransactionPath(transaction, "plan");
  const req = control.gate.envelope.request;
  await persistPrivateRetentionPlan(
    path,
    ref,
    fetchFromSource
      ? async (offset) => {
        const response = await deps.remote.root(
          backupV2RemoteProgram(
            req.jobId,
            `import { Buffer } from "node:buffer";import { readBackupV2RetentionPlanPage } from ${
              JSON.stringify(
                `${RELEASES_ROOT}/${req.sourceRevision}/scripts/backup-v2-prune-runtime.ts`,
              )
            };console.log(Buffer.from(await readBackupV2RetentionPlanPage(${
              JSON.stringify(transaction)
            },${JSON.stringify(ref)},${offset})).toString("base64"));`,
          ),
        );
        const text = response.stdout.trim();
        if (
          response.code !== 0 ||
          text.length > 4 * Math.ceil(B2_RETENTION_PAGE_BYTES / 3) ||
          !/^[A-Za-z0-9+/]+={0,2}$/.test(text)
        ) fail();
        return Uint8Array.from(atob(text), (byte) => byte.charCodeAt(0));
      }
      : undefined,
  );
}

interface BackupV2RetentionCycleSeam {
  proveIdle(deps: PiDeps): Promise<void>;
  installRuntime(
    control: BackupV2RetentionControl,
    deps: PiDeps,
    caps: BackupV2ControllerCapabilities,
    preflightCredential?: B2Settings,
  ): Promise<void>;
  readPlan(
    control: BackupV2RetentionControl,
    deps: PiDeps,
    fetchFromSource: boolean,
  ): Promise<void>;
}
const retentionIO: BackupV2RetentionCycleSeam = {
  proveIdle: proveRetentionIdle,
  readPlan: readPrivatePlan,
  async installRuntime(control, deps, caps, preflightCredential) {
    const key = preflightCredential ?? await configuredRetentionKey(deps);
    if (!preflightCredential) await deps.verifyRetentionCredential?.(key);
    await caps.install({
      ...control.settings,
      B2Settings: key,
    });
  },
};

/** Record the retirement decision before mutation. Apply the visible catalog
 * change only after the source has proved completion and retained integrity. */
export async function authorizeCatalogRetirement(
  deps: PiDeps,
  caps: BackupV2ControllerCapabilities,
  control: BackupV2RetentionControl,
  commit = false,
): Promise<void> {
  const plan = control.plannedResult;
  const snapshot = control.input.snapshot;
  if (
    !plan || !snapshot.policy.execute || plan.summary.blockReason !== null ||
    plan.summary.damagedCaptureIds.length || !plan.retainedCaptureIds.length
  ) fail();
  const originals = snapshot.catalog;
  const retired = new Set(plan.retiredCaptureIds),
    kept = new Set(plan.retainedCaptureIds);
  if (
    retired.size !== plan.retiredCaptureIds.length ||
    [...retired].some((id) => kept.has(id))
  ) fail();
  const surviving = originals.filter((entry) =>
    !retired.has(acceptedId(entry))
  );
  if (
    surviving.length < 1 ||
    surviving.length !== originals.length - retired.size ||
    [...kept].some((id) => !surviving.some((entry) => acceptedId(entry) === id))
  ) fail();
  const live = normalizeBackupV2ControllerState(
    await deps.private.read<ControllerState | BackupV2ControllerState>(
      CONTROLLER_STATE_PATH,
    ) ?? { schemaVersion: 1, catalog: [] },
  );
  if (live.job && !["COMPLETE", "FAILED"].includes(live.job.phase)) fail();
  const evidence = {
    transactionId: control.input.transactionId,
    planSha256: plan.plan.sha256,
    oldCatalog: originals,
    newCatalogSha256: digest(surviving),
    retiredCaptureIds: plan.retiredCaptureIds,
  };
  const path = retentionTransactionPath(
    control.input.transactionId,
    "retirement",
  );
  const prior = await deps.private.read(path);
  if (prior !== undefined) same(prior, evidence);
  if (isDeepStrictEqual(live.catalog, surviving) && prior !== undefined) return;
  same(live.catalog, originals);
  const next = validateBackupV2ControllerState({
    ...live,
    catalog: surviving,
    legacy: {
      ...live.legacy,
      catalog: surviving.flatMap((entry) =>
        entry.format === "backup-v1" ? [entry.entry] : []
      ),
    },
  });
  if (prior === undefined) await deps.private.write(path, evidence);
  same(await deps.private.read(path), evidence);
  if (commit && retired.size) await caps.persist(next);
}

export async function runBackupV2RetentionCycle(
  state: BackupV2ControllerState,
  deps: PiDeps,
  caps: BackupV2ControllerCapabilities,
  mode: "scheduled" | "plan" | "verify-catalog" = "scheduled",
  io: BackupV2RetentionCycleSeam = retentionIO,
): Promise<BackblazeMaintenanceResult | null> {
  const verifyCatalogOnly = mode === "verify-catalog";
  const planOnly = mode !== "scheduled";
  const path = verifyCatalogOnly
    ? B2_CATALOG_CONTROL_PATH
    : B2_RETENTION_CONTROL_PATH;
  let control = await readBackupV2RetentionControl(
    deps.private,
    verifyCatalogOnly,
  );
  const live = await caps.gate.read();
  if (
    planOnly && !verifyCatalogOnly && control &&
    backupV2RetentionNeedsReconcile(control) &&
    control.input.snapshot.policy.execute
  ) throw new BackblazeReportError("B2_RETENTION_EXECUTION_IN_PROGRESS");
  if (state.job && !["COMPLETE", "FAILED"].includes(state.job.phase)) {
    return null;
  }
  if (
    state.legacy.job && !["COMPLETE", "FAILED"].includes(state.legacy.job.phase)
  ) return null;
  const { rawPolicy, options } = await withBackblazeReportReason(
    "B2_RETENTION_POLICY_INVALID",
    async () => {
      const rawPolicy = await deps.private.read(B2_RETENTION_POLICY_PATH);
      return {
        rawPolicy,
        options: backupV2RetentionPolicy(rawPolicy, planOnly),
      };
    },
  );
  const head =
    [...state.catalog].sort((a, b) =>
      acceptedAt(b).localeCompare(acceptedAt(a))
    )[0];
  // Pre-upgrade anchors include the retired policy field. A settled plan
  // from that release must go through a fresh PLAN under the current policy.
  const anchor = digest({
    accepted: head ? [acceptedId(head), acceptedAt(head)] : null,
    job: state.job
      ? [state.job.settings.envelope.requestSha256, state.job.phase]
      : null,
    ...options,
  });
  let preflightCredential: B2Settings | undefined;
  if (!control || !backupV2RetentionNeedsReconcile(control)) {
    if (live !== null) return null;
    if (!planOnly && control?.anchor === anchor) {
      return retentionReport(control, deps, control.phase !== "PLAN_BLOCKED");
    }
    if (!planOnly && !state.catalog.length) return null;
    preflightCredential = await configuredRetentionKey(deps);
    await deps.verifyRetentionCredential?.(preflightCredential);
    control = await startRetentionControl(
      state,
      deps,
      caps,
      anchor,
      options,
      verifyCatalogOnly,
    );
    await withBackblazeReportReason(
      "B2_RETENTION_CONTROL_WRITE_FAILED",
      () => deps.private.write(path, control),
    );
  }
  const current = control;
  const input = current.input;
  const save = () =>
    withBackblazeReportReason(
      "B2_RETENTION_CONTROL_WRITE_FAILED",
      () => deps.private.write(path, current),
    );
  const report = (healthy = false) => retentionReport(current, deps, healthy);
  if (input.stage === "EXECUTE" && planOnly) return report(false);
  if (input.stage === "EXECUTE") {
    if (current.anchor !== anchor) {
      throw new BackblazeReportError("B2_RETENTION_APPROVAL_CHANGED");
    }
    const livePolicy = backupV2RetentionPolicy(rawPolicy);
    if (
      !isDeepStrictEqual(livePolicy.policy, input.snapshot.policy) ||
      !isDeepStrictEqual(livePolicy.retiredRestic, input.snapshot.retiredRestic)
    ) {
      throw new BackblazeReportError("B2_RETENTION_APPROVAL_CHANGED");
    }
  }
  const block = async (reason: BackupV2CancellationBlockedReason) => {
    current.phase = "CANCELLATION_BLOCKED";
    current.cancellationBlockedReason = reason;
    logCancellationBlocked(caps.log, current.gate, reason);
    await save();
    return await report();
  };
  const req = current.settings.envelope.request;
  const launch = async () => {
    if (
      (await deps.remote.root(
        backupV2PruneLaunchArguments(current.gate).map(shellQuote).join(" "),
      )).code !== 0
    ) {
      throw new BackblazeReportError("B2_RETENTION_LAUNCH_UNPROVED");
    }
  };
  const freshStage = () => {
    const next = newPruneGate(current.settings, deps.now());
    current.gate = next;
    current.result = null;
    delete current.resultSha256;
    delete current.cancellationBlockedReason;
    delete current.retryInterrupted;
    current.phase = "REQUESTED";
    current.input = {
      ...input,
      gate: next,
      stage: "EXECUTE",
      plan: current.plannedResult!.plan,
      scratchCleanupRequestSha256: null,
    };
  };

  if (current.phase === "PARTIAL") {
    if (
      live !== null ||
      (!current.retryInterrupted &&
        current.result?.summary.blockReason !== "TRANSPORT_UNCERTAIN")
    ) return report();
    freshStage();
    await save();
    return report(true);
  }
  if (current.phase === "CANCELLATION_BLOCKED") {
    if (!current.gate.custody) {
      return block(
        current.cancellationBlockedReason ?? "SOURCE_INVOCATION_UNPROVED",
      );
    }
    if (live !== null) {
      same(validateBackupV2Gate(live), current.gate);
      const settled = await caps.cancel(current.gate);
      if (settled !== "SETTLED") return block(settled.reason);
      await caps.gate.replace(current.gate, null);
    } else if (!await caps.gate.cleared(current.gate)) fail();
    if (input.stage === "PLAN") {
      current.phase = "PLAN_BLOCKED";
    } else {
      current.phase = "PARTIAL";
      current.retryInterrupted = [
        "SOURCE_STATUS_CANCELLATION_BLOCKED",
        "SOURCE_TERMINAL_RESULT_MISSING",
      ].includes(current.cancellationBlockedReason ?? "");
    }
    await save();
    return report();
  }
  if (current.phase === "REQUESTED") {
    if (live !== null) same(validateBackupV2Gate(live), current.gate);
    await io.proveIdle(deps);
    const before = await caps.observe(current.gate);
    if (
      before.unit !== "ABSENT" ||
      before.sourceBootId !== current.gate.sourceBootId
    ) fail();
    if (input.stage === "EXECUTE") {
      await withBackblazeReportReason(
        "B2_RETENTION_PLAN_UNPROVED",
        async () => {
          await io.readPlan(current, deps, false);
          const saved = await deps.private.read<BackupV2PiRetentionReport>(
            retentionTransactionPath(input.transactionId, "report"),
          );
          if (
            saved?.schemaVersion !== 1 ||
            saved.format !== "backblaze-retention-report" ||
            saved.transactionId !== input.transactionId ||
            saved.plan.path !==
              retentionTransactionPath(input.transactionId, "plan")
          ) fail();
          same(validateRetentionPlanReference(saved.plan), input.plan);
          await authorizeCatalogRetirement(deps, caps, current);
        },
      );
    }
    await withBackblazeReportReason(
      "B2_RETENTION_SOURCE_SETTINGS_FAILED",
      async () => {
        await io.installRuntime(current, deps, caps, preflightCredential);
        if (input.scratchCleanupRequestSha256 !== null) {
          if (
            state.job?.settings.envelope.requestSha256 !==
              input.scratchCleanupRequestSha256
          ) fail();
          await prepareAcceptedBackupV2ScratchCleanup(
            state.job,
            req.jobId,
            deps,
            caps,
          );
        }
        await installBackupV2Artifact(
          deps,
          req.jobId,
          `${JOBS_RUNTIME_ROOT}/${req.jobId}/prune-${current.gate.gateId}-request.json`,
          input,
        );
      },
    );
    if (live === null) await caps.gate.replace(null, current.gate);
    current.phase = "RUNNING";
    await save();
    await launch();
    return await report(true);
  }
  if (current.phase === "RUNNING") {
    if (!live) fail();
    const liveGate = validateBackupV2Gate(live);
    if (!current.gate.custody && liveGate.custody) {
      same({
        ...liveGate,
        custody: null,
        state: "PENDING",
        updatedAtUtc: current.gate.updatedAtUtc,
      }, current.gate);
      current.gate = liveGate;
      await save();
    } else same(liveGate, current.gate);
    const observed = await caps.observe(current.gate);
    if (observed.sourceBootId !== current.gate.sourceBootId) {
      return block("SOURCE_BOOT_CHANGED");
    }
    if (!observed.identity) {
      if (observed.unit === "ABSENT" && !current.gate.custody) {
        // With no acknowledged invocation, the exact unique unit can be
        // retried after a controller crash preceding the launch.
        await io.proveIdle(deps);
        await launch();
        return report(true);
      }
      return report(
        ["STARTING", "RUNNING"].includes(observed.unit) &&
          deps.now().getTime() - Date.parse(current.gate.createdAtUtc) <=
            300_000,
      );
    }
    if (!current.gate.custody) {
      const bound = validateBackupV2Gate({
        ...current.gate,
        state: "ACTIVE",
        custody: observed.identity,
        updatedAtUtc: deps.now().toISOString(),
      });
      await caps.gate.replace(current.gate, bound);
      current.gate = bound;
      await save();
    }
    if (input.stage === "EXECUTE") {
      await authorizeCatalogRetirement(deps, caps, current);
    }
    await caps.acknowledge(current.gate);
    if (!observed.status) return await report(true);
    const status = validateBackupV2Status(observed.status, current.gate);
    if (status.phase === "CANCELLATION_BLOCKED") {
      return block("SOURCE_STATUS_CANCELLATION_BLOCKED");
    }
    if (status.finishedAtUtc === null) {
      const fresh =
        Math.abs(deps.now().getTime() - Date.parse(status.updatedAtUtc)) <=
          60_000;
      const leased = Math.max(
        status.lease.usefulProgressExpiresAtMs,
        status.lease.retryEpisode?.expiresAtMs ?? 0,
        status.lease.transferEpisode?.expiresAtMs ?? 0,
      ) >
        status.lease.observedMonotonicMs;
      return report(fresh && leased);
    }
    if (["RUNNING", "STARTING"].includes(observed.unit)) return report(true);
    if (!observed.resultBytes || !observed.nativeCustodySha256) {
      return block("SOURCE_TERMINAL_RESULT_MISSING");
    }
    if (status.phase !== "CLEANED" || observed.unit !== "EXITED") {
      return block("SOURCE_TERMINAL_STATUS_UNPROVED");
    }
    const resultSha256 = backupV2ArtifactSha256(observed.resultBytes);
    if (status.resultSha256 !== resultSha256) {
      return block("SOURCE_TERMINAL_RESULT_HASH_MISMATCH");
    }
    const result = validateBackupV2PruneWorkerResult(
      JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(observed.resultBytes),
      ),
      current.gate,
      input,
    );
    if (result.nativeCustodySha256 !== observed.nativeCustodySha256) {
      return block("SOURCE_TERMINAL_NATIVE_CUSTODY_MISMATCH");
    }
    if (!backupV2ProcessesSettled(current.gate, observed)) {
      return block("SOURCE_TERMINAL_PROCESSES_UNSETTLED");
    }
    if (input.stage === "EXECUTE" && result.state === "COMPLETE") {
      same(result.retiredCaptureIds, current.plannedResult?.retiredCaptureIds);
      same(
        result.retainedCaptureIds,
        current.plannedResult?.retainedCaptureIds,
      );
    }
    current.result = result;
    current.resultSha256 = resultSha256;
    current.phase = "SETTLED";
    await save();
    return report(true);
  }
  if (current.phase !== "SETTLED" || !current.result || !current.resultSha256) {
    fail();
  }
  const result = validateBackupV2PruneWorkerResult(
    current.result,
    current.gate,
    input,
  );
  const artifacts = {
    resultSha256: current.resultSha256,
    nativeCustodySha256: result.nativeCustodySha256,
  };
  if (live !== null) {
    same(validateBackupV2Gate(live), current.gate);
    await caps.stop(current.gate, artifacts);
    await caps.gate.replace(current.gate, null);
  } else if (!await caps.gate.cleared(current.gate, artifacts)) fail();

  if (input.stage === "PLAN") {
    await withBackblazeReportReason(
      "B2_RETENTION_PLAN_UNPROVED",
      () => io.readPlan(current, deps, true),
    );
    if (result.scratchCleanup && state.job) {
      await deps.private.write(
        `${PIP_JOB_EVIDENCE_PATH}/${state.job.settings.envelope.request.jobId}/v2-scratch-cleanup.json`,
        result.scratchCleanup,
      );
    }
    current.plannedResult = result;
    if (
      result.summary.blockReason !== null || !result.retainedCaptureIds.length
    ) {
      current.phase = "PLAN_BLOCKED";
      await save();
      return report();
    }
    const hasWork = result.retiredCaptureIds.length > 0 ||
      Object.values(result.summary.categories).some((category) =>
        category.plannedObjects > 0
      );
    if (!input.snapshot.policy.execute || planOnly || !hasWork) {
      current.phase = "PLAN_ONLY";
      await save();
      return report(true);
    }
    // Both the full plan bytes and its private, redacted summary must exist
    // before execution can be requested or the accepted catalog changed.
    await retentionReport(current, deps, true, true);
    freshStage();
    await save();
    return report(true);
  }
  if (result.state === "COMPLETE") {
    await authorizeCatalogRetirement(deps, caps, current, true);
  }
  current.phase = result.state === "COMPLETE" ? "COMPLETE" : "PARTIAL";
  await save();
  return report(current.phase === "COMPLETE");
}

export async function runBackupV2ControllerCycle(
  deps: PiDeps,
  bridge: BackupV2ControllerCapabilities["bridge"],
  mode: BackblazeMaintenanceMode = "scheduled",
): Promise<BackblazeRunReport> {
  let { value, state } = await withBackblazeReportReason(
    "B2_CONTROLLER_STATE_UNREADABLE",
    async () => {
      const value =
        await deps.private.read<ControllerState | BackupV2ControllerState>(
          CONTROLLER_STATE_PATH,
        ) ?? { schemaVersion: 1 as const, catalog: [] };
      return { value, state: normalizeBackupV2ControllerState(value) };
    },
  );
  const caps = realBackupV2ControllerCapabilities(deps, bridge);
  const deadline = performance.now() + 240_000;
  const observations: BackblazeMaintenanceReports = {};
  const record = (
    requested: BackblazeMaintenanceMode,
    result: BackblazeMaintenanceResult,
  ) => {
    observations[requested === "verify-catalog" ? "catalog" : "retention"] =
      result;
    return result;
  };
  const refused = async (
    requested: BackblazeMaintenanceMode,
    reason: BackblazeReportReason,
    status?: string,
    transactionId?: string,
  ) => {
    const now = deps.now();
    const result = {
      ...maintenanceFailure(requested, now, reason, status),
      ...(transactionId ? { retentionTransactionId: transactionId } : {}),
    };
    try {
      await publishMaintenanceReport(deps.private, requested, result, now);
      return record(requested, result);
    } catch {
      return record(requested, {
        ...result,
        reportWriteError: "B2_REPORT_WRITE_FAILED",
      });
    }
  };
  const publishBackup = async (failed?: BackblazeReportReason) => {
    const now = deps.now();
    const { damaged, reports } = await readBackblazeMaintenance(
      deps.private,
      now,
    );
    const backup = backupV2ControllerReport(state, now, damaged);
    const maintenance = { ...reports, ...observations };
    if (
      !failed && backup.healthy &&
      (!state.job || state.job.phase === "COMPLETE")
    ) {
      try {
        const gate = await readBackupRuntimeGate(deps.private);
        if (gate && (gate.schemaVersion !== 2 || gate.kind !== "prune")) {
          failed = "B2_BACKUP_GATE_HELD";
        }
      } catch {
        failed = "B2_BACKUP_GATE_UNKNOWN";
      }
    }
    const report: BackblazeRunReport = {
      ...backup,
      ...(failed
        ? {
          status: "B2_BACKUP_FAILED",
          healthy: false,
          ...backblazeReportExplanation(failed),
        }
        : {}),
      ...(Object.keys(maintenance).length ? { maintenance } : {}),
    };
    try {
      await deps.private.write(B2_REPORT_PATH, report);
      return report;
    } catch {
      return {
        ...report,
        reportWriteError: "B2_REPORT_WRITE_FAILED",
        ...(!report.reason
          ? backblazeReportExplanation("B2_REPORT_WRITE_FAILED")
          : {}),
      } satisfies BackblazeRunReport;
    }
  };
  const readControl = (requested: BackblazeMaintenanceMode) =>
    withBackblazeReportReason(
      "B2_RETENTION_CONTROL_INVALID",
      () =>
        readBackupV2RetentionControl(
          deps.private,
          requested === "verify-catalog",
        ),
    );
  const retention = async (
    requested: BackblazeMaintenanceMode,
    control?: BackupV2RetentionControl,
  ) => {
    let report: BackblazeMaintenanceResult | null = null;
    try {
      do {
        report = await runBackupV2RetentionCycle(state, deps, caps, requested);
        if (!report || !report.healthy) break;
        control = await readControl(requested);
        if (
          !control || !backupV2RetentionNeedsReconcile(control) ||
          (control.phase === "RUNNING" && control.gate.custody &&
            !control.result)
        ) break;
        await deps.sleep(1000);
      } while (performance.now() < deadline);
    } catch (error) {
      const reason = reasonForBackblazeError(error, "B2_RETENTION_STEP_FAILED");
      return await refused(
        requested,
        reason,
        undefined,
        control?.input.transactionId,
      );
    }
    return report ? record(requested, report) : null;
  };

  if (mode !== "scheduled") {
    try {
      const gate = await withBackblazeReportReason(
        "B2_RETENTION_CONTROL_INVALID",
        () => readBackupRuntimeGate(deps.private),
      );
      const control = await readControl(mode);
      const other = await readControl(
        mode === "plan" ? "verify-catalog" : "plan",
      );
      if (
        (gate && (gate.schemaVersion !== 2 || gate.kind !== "prune" ||
          gate.gateId !== control?.gate.gateId)) ||
        other && backupV2RetentionNeedsReconcile(other)
      ) {
        return await refused(
          mode,
          "B2_RETENTION_BACKUP_IN_PROGRESS",
          "B2_RETENTION_BUSY",
        );
      }
      return await retention(mode, control) ??
        await refused(
          mode,
          "B2_RETENTION_BACKUP_IN_PROGRESS",
          "B2_RETENTION_BUSY",
        );
    } catch (error) {
      return await refused(
        mode,
        reasonForBackblazeError(error, "B2_RETENTION_STEP_FAILED"),
      );
    }
  }

  let liveGate: Awaited<ReturnType<typeof readBackupRuntimeGate>>;
  try {
    liveGate = await readBackupRuntimeGate(deps.private);
  } catch {
    return await publishBackup("B2_BACKUP_GATE_UNKNOWN");
  }
  const observeControl = async (requested: BackblazeMaintenanceMode) => {
    try {
      return await readControl(requested);
    } catch {
      await refused(requested, "B2_RETENTION_CONTROL_INVALID");
      return undefined;
    }
  };
  const verify = await observeControl("verify-catalog");
  const prune = await observeControl("scheduled");
  if (
    verify && backupV2RetentionNeedsReconcile(verify) &&
    (!liveGate || liveGate.schemaVersion === 2 && liveGate.kind === "prune" &&
        liveGate.gateId === verify.gate.gateId)
  ) {
    if (!await retention("verify-catalog", verify)) {
      await refused("verify-catalog", "B2_RETENTION_CUSTODY_UNPROVED");
    }
    return await publishBackup();
  }
  if (prune && backupV2RetentionNeedsReconcile(prune)) {
    if (!await retention("scheduled", prune)) {
      await refused("scheduled", "B2_RETENTION_CUSTODY_UNPROVED");
    }
    return await publishBackup();
  }
  if (liveGate?.schemaVersion === 2 && liveGate.kind === "prune") {
    await refused(
      "scheduled",
      "B2_RETENTION_CUSTODY_UNPROVED",
      "B2_RETENTION_LEGACY_CUSTODY_UNSETTLED",
    );
    return await publishBackup();
  }

  // A terminal plan-only or refused transaction cannot keep a due capture
  // behind maintenance. Schedule the backup before creating a new plan.
  try {
    do {
      const previousPhase = value.schemaVersion === 2
        ? value.job?.phase
        : undefined;
      state = await stepBackupV2Controller(value, caps);
      value = state;
      const job = state.job;
      if (
        !job ||
        ["COMPLETE", "FAILED", "CANCELLATION_BLOCKED"].includes(job.phase)
      ) break;
      if (previousPhase === "VERIFY_SETTLED" && job.phase === previousPhase) {
        break;
      }
      const status = job.activeKind === "worker"
        ? job.workerStatus
        : job.verifierStatus;
      if (["WORKER", "VERIFY"].includes(job.phase) && status !== null) break;
      if (["WORKER", "VERIFY"].includes(job.phase)) await deps.sleep(1000);
    } while (performance.now() < deadline);
  } catch (error) {
    return await publishBackup(
      reasonForBackblazeError(error, "B2_BACKUP_STEP_FAILED"),
    );
  }
  if (!observations.retention) await retention("scheduled", prune);
  return await publishBackup();
}
