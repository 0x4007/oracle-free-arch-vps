/** Bounded Pi reconciliation. Source work and its decrypt bridge have their own
 * managed leases; a controller attempt never owns their process lifetime. */
import { isDeepStrictEqual } from "node:util";
import {
  B2_REPORT_PATH,
  type BackblazeRunReport,
  BACKUP_BASE,
  BACKUP_RUNTIME_BASE,
  CONTROLLER_STATE_PATH,
  type ControllerState,
  GATE_PATH,
  generationPrefixes,
  JOBS_RUNTIME_ROOT,
  loadDeployment,
  loadSourceConfig,
  PI_CONTROLLER_CWD,
  type PiDeps,
  PIP_JOB_EVIDENCE_PATH,
  type PrivateSeam,
  type PrunePlanEntry,
  PUBLIC_HOME_BASE,
  realPrivateSeam,
  realRemoteRunner,
  realRemoteSeam,
  type ReleaseManifest,
  RELEASES_ROOT,
  type RemoteSeam,
  retainedIdsPresent,
  revalidatePruneDeletions,
  selectPruneCandidates,
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
import {
  BACKUP_V2_LIMITS,
  BACKUP_V2_NAMESPACE,
  BACKUP_V2_PROFILE_ID,
} from "./backup-v2-profile.ts";
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
import { validateBackupV2ObjectRef } from "./backup-v2-contract.ts";
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
export interface BackupV2ControllerCapabilities {
  now(): Date;
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
    cleared(gate: BackupV2Gate): Promise<boolean>;
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
    expected?: { resultSha256: string; nativeCustodySha256: string },
  ): Promise<void>;
  cancel(gate: BackupV2Gate): Promise<"SETTLED" | "CANCELLATION_BLOCKED">;
  bridge: {
    ensure(
      settings: BackupV2WorkerSettings,
      gate: BackupV2Gate,
    ): Promise<"READY" | "PENDING" | "CANCELLATION_BLOCKED">;
    close(gate: BackupV2Gate): Promise<"CLOSED" | "CANCELLATION_BLOCKED">;
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
    ]);
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

/** Exactly one bounded reconciliation; no polling loop and no whole-job timer. */
export async function stepBackupV2Controller(
  input: ControllerState | BackupV2ControllerState,
  deps: BackupV2ControllerCapabilities,
): Promise<BackupV2ControllerState> {
  let state: BackupV2ControllerState =
    (input as { schemaVersion: number }).schemaVersion === 1
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
  const now = deps.now();
  const save = async () => {
    state = validateBackupV2ControllerState(state);
    await deps.persist(state);
    return state;
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
    if (await deps.gate.read() !== null) fail();
    await deps.admit(state.legacy);
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
  const live = await deps.gate.read();
  if (job.phase === "REQUESTED" || job.phase === "VERIFY_REQUESTED") {
    if (live !== null) same(validateBackupV2Gate(live), gate);
    else await deps.gate.replace(null, gate);
    await deps.install(job.settings);
    if (kind === "verify") await deps.verifierInput(job);
    job.phase = kind === "worker" ? "WORKER" : "VERIFY";
    await save();
    // PENDING gate exists before the launch intent. Resume only observes it;
    // an ambiguous failed launch never starts another invocation automatically.
    await deps.launch(job.settings, kind);
    return state;
  }
  if (job.phase === "WORKER_SETTLED" || job.phase === "VERIFY_SETTLED") {
    if (live !== null) {
      same(validateBackupV2Gate(live), gate);
      if (
        !backupV2ProcessesSettled(gate, await deps.observe(gate)) &&
        !await deps.gate.cleared(gate)
      ) {
        job.phase = "CANCELLATION_BLOCKED";
        return await save();
      }
      if (kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") {
        job.phase = "CANCELLATION_BLOCKED";
        return await save();
      }
      const terminal = kind === "worker"
          ? job.workerStatus!
          : job.verifierStatus!,
        output = kind === "worker" ? job.workerResult! : job.verified!;
      if (!output.nativeCustodySha256) fail();
      await deps.stop(gate, {
        resultSha256: terminal.resultSha256!,
        nativeCustodySha256: output.nativeCustodySha256,
      });
      await deps.gate.replace(gate, null);
    } else {
      if (!await deps.gate.cleared(gate)) {
        job.phase = "CANCELLATION_BLOCKED";
        return await save();
      }
      if (kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") {
        job.phase = "CANCELLATION_BLOCKED";
        return await save();
      }
    }
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
  if (job.phase === "CANCELLATION_BLOCKED") {
    if (
      !gate.custody || await deps.cancel(gate) !== "SETTLED" ||
      kind === "verify" && await deps.bridge.close(gate) !== "CLOSED"
    ) return await save();
    await deps.stop(gate);
    await deps.gate.replace(gate, null);
    job.phase = "FAILED";
    return await save();
  }
  const observation = await deps.observe(gate);
  if (
    observation.sourceBootId !== gate.sourceBootId ||
    observation.unit === "ABSENT"
  ) {
    job.phase = "CANCELLATION_BLOCKED";
    return await save();
  }
  if (!observation.identity) {
    if (!["RUNNING", "STARTING"].includes(observation.unit)) {
      job.phase = "CANCELLATION_BLOCKED";
      return await save();
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
  } else same(gate.custody, observation.identity);
  if (observation.status === null) return state;
  if (kind === "verify") {
    const bridge = await deps.bridge.ensure(job.settings, gate);
    if (bridge === "CANCELLATION_BLOCKED") {
      job.phase = "CANCELLATION_BLOCKED";
      return await save();
    }
    if (bridge !== "READY") return state;
  }
  await deps.acknowledge(gate);
  const status = validateBackupV2Status(observation.status, gate),
    prior = kind === "worker" ? job.workerStatus : job.verifierStatus;
  if (prior) assertBackupV2StatusTransition(prior, status);
  if (kind === "worker") job.workerStatus = status;
  else job.verifierStatus = status;
  if (
    status.phase === "CANCELLATION_BLOCKED" || status.phase === "FAILED" ||
    observation.unit === "FAILED"
  ) {
    job.phase = "CANCELLATION_BLOCKED";
    return await save();
  }
  if (status.finishedAtUtc === null) return await save();
  if (["RUNNING", "STARTING"].includes(observation.unit)) return await save();
  if (
    !backupV2ProcessesSettled(gate, observation) || !observation.resultBytes ||
    backupV2ArtifactSha256(observation.resultBytes) !== status.resultSha256
  ) {
    job.phase = "CANCELLATION_BLOCKED";
    return await save();
  }
  const result = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(observation.resultBytes),
  );
  if (
    typeof result?.nativeCustodySha256 !== "string" ||
    result.nativeCustodySha256 !== observation.nativeCustodySha256
  ) {
    job.phase = "CANCELLATION_BLOCKED";
    return await save();
  }
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
  return await save();
}

export function backupV2ControllerReport(
  state: BackupV2ControllerState,
  now: Date,
): BackblazeRunReport {
  const job = state.job, phase = job?.phase ?? "IDLE";
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
  return {
    status: phase,
    observedAtUtc: now.toISOString(),
    healthy: phase === "COMPLETE" ||
      phase === "IDLE" && backupV2PeriodSatisfied(state, now) ||
      ["WORKER", "VERIFY"].includes(phase) &&
        Boolean(fresh && (initializing || leased)),
    ...(job
      ? {
        jobId: job.settings.envelope.request.jobId,
        generation: job.settings.envelope.request.captureId,
      }
      : {}),
    detail: phase === "COMPLETE"
      ? "Cloud recovery point accepted; retention requires its separate reference-safe proof"
      : "Bounded v2 reconciliation; source lease and custody remain independent",
  };
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
  const request = settings.envelope.request,
    gate = kind === "prune"
      ? validateBackupV2Gate(pruneGate)
      : kind === "worker"
      ? settings.workerGate
      : settings.verifierGate;
  if (gate.kind !== kind) fail();
  same(gate.envelope, settings.envelope);
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
      MemoryMax: "6G",
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
    "/usr/local/bin/deno",
    "run",
    "--no-prompt",
    "--no-config",
    "--no-lock",
    "--cached-only",
    "--no-code-cache",
    `--allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT},${publicHome},${BACKUP_RUNTIME_BASE}`,
    `--allow-write=${BACKUP_BASE},${PUBLIC_HOME_BASE},${BACKUP_V2_PROTECTION_SOURCE_BASE}`,
    "--allow-env=INVOCATION_ID,NOTIFY_SOCKET",
    "--allow-sys=statfs",
    "--allow-ffi=/usr/lib/libsystemd.so.0",
    "--allow-run=/bin/sh,/usr/bin/systemctl,/usr/bin/sha256sum,/usr/bin/flock,/usr/bin/bash,/usr/bin/unshare,/usr/bin/gpg,/usr/bin/zstd,/usr/bin/tar,/usr/bin/mkfifo,/usr/bin/curl,/usr/bin/sudo,/usr/bin/cat,/usr/bin/chown,/usr/bin/find,/usr/bin/stat,/usr/bin/readlink",
    kind === "prune"
      ? `${RELEASES_ROOT}/${request.sourceRevision}/scripts/backup-v2-worker.ts`
      : `${runtime}/entry-${kind}.ts`,
  ];
}

/** Root-only bounded control read; payload and private keys never cross this seam. */
function remoteProgram(program: string): string {
  return `printf '%s' ${
    shellQuote(program)
  } | /usr/local/bin/deno run --no-prompt --no-config --no-lock --cached-only --allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT},${BACKUP_V2_PROTECTION_SOURCE_BASE} --allow-run=/bin/sh,/usr/bin/systemctl,/usr/bin/flock,/usr/bin/cat,/usr/bin/find,/usr/bin/stat,/usr/bin/readlink,/usr/bin/sha256sum -`;
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
    remoteProgram(backupV2ObservationProgram(gate, options)),
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
  const script = `printf '%s' ${
    shellQuote(program)
  } | /usr/local/bin/deno run --no-prompt --no-config --no-lock --allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT} --allow-write=${BACKUP_BASE},${JOBS_RUNTIME_ROOT} -`;
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
    artifacts?: { resultSha256: string; nativeCustodySha256: string };
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
  ): Promise<boolean> => {
    const saved = await deps.private.read<
      StopProof
    >(pathForClear(gate));
    if (!saved?.exactStop) return false;
    same(saved.gate, gate);
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
        // Only the controller lock holder may remove the exact compared gate.
        same(await deps.private.read(GATE_PATH), expected);
        await removeGate(GATE_PATH);
      },
      cleared: retainedProof,
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
      assertBackblazeLaunchAllowed(
        await deps.private.read(".private/backup-runtime.json"),
        await deps.private.read(".private/backup-scheduled-window.json"),
      );
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
          const result = await deps.remote.root(remoteProgram(program));
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
        if (!await retainedProof(gate)) fail();
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
      if (!await deps.private.read(pathForClear(gate))) {
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
      if (!gate.custody) return "CANCELLATION_BLOCKED";
      const deadline = performance.now() + 30_000;
      const settled = await settleBackupV2Cancellation(gate.custody, {
        now: () => performance.now(),
        observe: async () => {
          const value = await observe(gate);
          if (value.sourceBootId === null) return null;
          if (value.sourceBootId !== gate.sourceBootId) fail();
          if (value.identity !== null) same(value.identity, gate.custody);
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
      if (settled.state === "SETTLED") {
        const remaining = deadline - performance.now();
        if (remaining <= 0 || !await retainedProof(gate, remaining)) {
          return "CANCELLATION_BLOCKED";
        }
      }
      return settled.state;
    },
    bridge,
  };
}

export interface BackupV2RetentionControl {
  schemaVersion: 2;
  format: "backup-v2-retention-controller";
  input: BackupV2PruneInput;
  gate: BackupV2Gate;
  phase:
    | "REQUESTED"
    | "RUNNING"
    | "SETTLED"
    | "COMPLETE"
    | "PARTIAL"
    | "CANCELLATION_BLOCKED";
  result: BackupV2PruneWorkerResult | null;
  legacyPlan?: PrunePlanEntry[];
}
export async function prepareAcceptedBackupV2ScratchCleanup(
  job: BackupV2ControllerJob,
  deps: PiDeps,
  caps: BackupV2ControllerCapabilities,
): Promise<void> {
  if (job.phase !== "COMPLETE" || !job.verified?.protectedGraph) fail();
  const proofs = [];
  for (const gate of [job.workerGate, job.verifierGate]) {
    if (!await caps.gate.cleared(gate)) fail();
    const saved = await deps.private.read<
      {
        gate: BackupV2Gate;
        proof: BackupV2KernelObservation;
        artifacts: { resultSha256: string; nativeCustodySha256: string };
        exactStop: NonNullable<
          BackupV2KernelObservationOptions["retainedTerminalProof"]
        >["exactStop"];
      }
    >(`${PIP_JOB_EVIDENCE_PATH}/${gate.envelope.request.jobId}/v2-${gate.gateId}-${gate.custody?.invocationId}-cleared.json`);
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
    `${JOBS_RUNTIME_ROOT}/${job.settings.envelope.request.jobId}/prune-cleanup-proofs.json`,
    proofs,
  );
}
export function validateBackupV2PruneWorkerResult(
  value: unknown,
  gate: BackupV2Gate,
  input: BackupV2PruneInput,
): BackupV2PruneWorkerResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as BackupV2PruneWorkerResult;
  const keys = [
    "schemaVersion",
    "format",
    "gate",
    "transactionId",
    "stage",
    "state",
    "plan",
    "retainedCaptureIds",
    "obsoleteLegacyCaptureIds",
    "finishedAtUtc",
    "nativeCustodySha256",
    ...(Object.hasOwn(r, "scratchCleanup") ? ["scratchCleanup"] : []),
  ];
  if (
    Object.keys(r).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(r, key)) || r.schemaVersion !== 2 ||
    r.format !== "backup-v2-prune-result" ||
    r.transactionId !== input.transactionId || r.stage !== input.stage ||
    !/^[a-f0-9]{64}$/.test(r.nativeCustodySha256) ||
    !["PLAN_PROVED", "COMPLETE", "PARTIAL"].includes(r.state) ||
    (r.stage === "PLAN") !== (r.state === "PLAN_PROVED") ||
    new Date(r.finishedAtUtc).toISOString() !== r.finishedAtUtc
  ) fail();
  if (r.stage === "PLAN") {
    const cleanup = r.scratchCleanup;
    if (
      !cleanup || cleanup.schemaVersion !== 2 ||
      cleanup.format !== "backup-v2-scratch-cleanup" ||
      cleanup.requestSha256 !== gate.envelope.requestSha256 ||
      !Number.isSafeInteger(cleanup.entriesRemoved) ||
      cleanup.entriesRemoved < 0 ||
      !Number.isSafeInteger(cleanup.logicalBytesRemoved) ||
      cleanup.logicalBytesRemoved < 0 ||
      cleanup.logicalBytesRemoved > BACKUP_V2_LIMITS.workspaceBytes
    ) fail();
  }
  const actual = validateBackupV2Gate(r.gate);
  same({ ...actual, updatedAtUtc: gate.updatedAtUtc }, gate);
  if (
    !r.plan || !/^[a-f0-9]{64}$/.test(r.plan.sha256) ||
    !/^[a-f0-9]{64}$/.test(r.plan.digest) ||
    !Number.isSafeInteger(r.plan.bytes) || r.plan.bytes < 1 ||
    r.plan.bytes > BACKUP_V2_LIMITS.journalBytes
  ) fail();
  if (input.stage === "EXECUTE") same(r.plan, input.plan);
  if (
    !Array.isArray(r.retainedCaptureIds) || r.retainedCaptureIds.length !== 4 ||
    new Set(r.retainedCaptureIds).size !== 4 ||
    !Array.isArray(r.obsoleteLegacyCaptureIds)
  ) fail();
  const ids = input.snapshot.catalog.map((entry) =>
    entry.format === "backup-v1"
      ? entry.entry.index.generation
      : entry.envelope.request.captureId
  );
  if (
    r.retainedCaptureIds.some((id) => !ids.includes(id)) ||
    r.obsoleteLegacyCaptureIds.some((id) =>
      r.retainedCaptureIds.includes(id) ||
      !input.snapshot.catalog.some((entry) =>
        entry.format === "backup-v1" && entry.entry.index.generation === id
      )
    )
  ) fail();
  return structuredClone(r);
}

/** Each call only reconciles one managed stage. A saved plan precedes execution;
 * no detached deletion or fixed whole-job deadline is introduced. */
export async function runBackupV2RetentionCycle(
  state: BackupV2ControllerState,
  deps: PiDeps,
  caps: BackupV2ControllerCapabilities,
): Promise<BackblazeRunReport | null> {
  const job = state.job;
  if (
    !job || job.phase !== "COMPLETE" || !job.verified?.protectedGraph ||
    state.catalog.length < 4
  ) return null;
  const settings = job.settings,
    path =
      `.private/file-backup/retention/${settings.envelope.request.jobId}.json`;
  let control = await deps.private.read<BackupV2RetentionControl>(path);
  const save = () => deps.private.write(path, control);
  const report = (healthy = false): BackblazeRunReport => ({
    status: `B2_RETENTION_${control!.input.stage}_${control!.phase}`,
    observedAtUtc: deps.now().toISOString(),
    healthy,
    jobId: settings.envelope.request.jobId,
    generation: settings.envelope.request.captureId,
    detail: control!.phase === "COMPLETE"
      ? "Four complete recovery points retained"
      : "Backup accepted; reference-safe retention is separately in progress",
  });
  const gate = (sourceBootId: string) => {
    const id = crypto.randomUUID(), now = deps.now().toISOString();
    return validateBackupV2Gate({
      ...settings.verifierGate,
      kind: "prune",
      gateId: id,
      sourceBootId,
      unitName: `arch-vps-b2-v2-prune-${
        settings.envelope.request.captureId.slice("generation-".length)
      }-${id}.service`,
      state: "PENDING",
      custody: null,
      createdAtUtc: now,
      updatedAtUtc: now,
    });
  };
  if (!control) {
    await prepareAcceptedBackupV2ScratchCleanup(job, deps, caps);
    if (await caps.gate.read() !== null) fail();
    await caps.admit(state.legacy);
    const result = await deps.remote.root(
      remoteProgram(
        `const {discoverBackupV2UnresolvedPuts}=await import(${
          JSON.stringify(
            `${RELEASES_ROOT}/${settings.envelope.request.sourceRevision}/scripts/backup-v2-worker.ts`,
          )
        });const boot=await new Deno.Command("/usr/bin/cat",{args:["/proc/sys/kernel/random/boot_id"],clearEnv:true,env:{PATH:"/usr/bin:/bin"},stdout:"piped",stderr:"piped"}).output();if(!boot.success)throw Error("Source boot unavailable");console.log(JSON.stringify({sourceBootId:new TextDecoder().decode(boot.stdout).trim(),unresolvedPuts:await discoverBackupV2UnresolvedPuts()}));`,
      ),
    );
    if (
      result.code !== 0 ||
      result.stdout.length > BACKUP_V2_LIMITS.controlResponseBytes
    ) fail();
    const observed = JSON.parse(result.stdout),
      graphs: BackupV2ProtectionDescriptor[] = [];
    for (const entry of state.catalog) {
      if (entry.format === "backup-v2") {
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
    }
    const retained = [...state.catalog].sort((a, b) =>
      Date.parse(
        b.format === "backup-v1" ? b.entry.acceptedAtUtc : b.acceptedAtUtc,
      ) -
      Date.parse(
        a.format === "backup-v1" ? a.entry.acceptedAtUtc : a.acceptedAtUtc,
      )
    ).slice(0, 4);
    const pending = gate(observed.sourceBootId);
    control = {
      schemaVersion: 2,
      format: "backup-v2-retention-controller",
      phase: "REQUESTED",
      gate: pending,
      result: null,
      input: {
        schemaVersion: 2,
        format: "backup-v2-prune",
        gate: pending,
        transactionId: crypto.randomUUID(),
        stage: "PLAN",
        plan: null,
        graphs,
        snapshot: {
          catalog: state.catalog,
          custody: {
            lockId: GATE_SOURCE_LOCK_PATH,
            sourceBootId: observed.sourceBootId,
            sourceSettled: true,
          },
          receipts: retained.flatMap((entry) =>
            entry.format === "backup-v2" ? [entry.receiptReference] : []
          ),
          protection: {
            acceptedRoots: [],
            activeObjects: [],
            sealedRoleManifests: [],
            unresolvedPuts: observed.unresolvedPuts,
          },
        },
      },
    };
    await save();
  }
  if (
    control.schemaVersion !== 2 ||
    control.format !== "backup-v2-retention-controller" ||
    control.gate.kind !== "prune"
  ) fail();
  if (
    ![
      "REQUESTED",
      "RUNNING",
      "SETTLED",
      "COMPLETE",
      "PARTIAL",
      "CANCELLATION_BLOCKED",
    ].includes(control.phase)
  ) fail();
  if (
    control.input.format !== "backup-v2-prune" ||
    control.input.schemaVersion !== 2 ||
    !["PLAN", "EXECUTE"].includes(control.input.stage)
  ) fail();
  same(control.gate.envelope, settings.envelope);
  same(control.input.gate.envelope, settings.envelope);
  if (control.result) {
    control.result = validateBackupV2PruneWorkerResult(
      control.result,
      control.gate,
      control.input,
    );
  }
  if (control.phase === "COMPLETE") return null;
  if (["PARTIAL", "CANCELLATION_BLOCKED"].includes(control.phase)) {
    return report();
  }
  if (control.phase === "REQUESTED") {
    if (await caps.gate.read() !== null) fail();
    const before = await caps.observe(control.gate);
    if (
      before.unit !== "ABSENT" ||
      before.sourceBootId !== control.gate.sourceBootId
    ) fail();
    await installBackupV2Artifact(
      deps,
      `${JOBS_RUNTIME_ROOT}/${settings.envelope.request.jobId}/prune-${
        control.input.stage === "PLAN" ? "plan" : "execute"
      }-request.json`,
      control.input,
    );
    await caps.gate.replace(null, control.gate);
    control.phase = "RUNNING";
    await save();
    if (
      (await deps.remote.root(
        backupV2LaunchArguments(settings, "prune", control.gate).map(shellQuote)
          .join(" "),
      )).code !== 0
    ) throw new Error("Prune launch outcome unproved");
    return report(true);
  }
  if (control.phase === "RUNNING") {
    const observed = await caps.observe(control.gate);
    if (!observed.identity) {
      return report(
        ["STARTING", "RUNNING"].includes(observed.unit) &&
          deps.now().getTime() - Date.parse(control.gate.createdAtUtc) <=
            300_000,
      );
    }
    if (!control.gate.custody) {
      const bound = validateBackupV2Gate({
        ...control.gate,
        state: "ACTIVE",
        custody: observed.identity,
        updatedAtUtc: deps.now().toISOString(),
      });
      await caps.gate.replace(control.gate, bound);
      control.gate = bound;
      await save();
    }
    await caps.acknowledge(control.gate);
    if (!observed.status) return report(true);
    const status = validateBackupV2Status(observed.status, control.gate);
    if (status.phase === "CANCELLATION_BLOCKED") {
      control.phase = "CANCELLATION_BLOCKED";
      await save();
      return report();
    }
    if (status.finishedAtUtc === null) {
      const fresh =
        Math.abs(deps.now().getTime() - Date.parse(status.updatedAtUtc)) <=
          60_000;
      const leased = Math.max(
        status.lease.usefulProgressExpiresAtMs,
        status.lease.retryEpisode?.expiresAtMs ?? 0,
        status.lease.transferEpisode?.expiresAtMs ?? 0,
      ) > status.lease.observedMonotonicMs;
      return report(fresh && leased);
    }
    if (["RUNNING", "STARTING"].includes(observed.unit)) return report(true);
    if (
      !observed.resultBytes || !observed.nativeCustodySha256 ||
      status.phase === "CLEANED" &&
        status.resultSha256 !== backupV2ArtifactSha256(observed.resultBytes)
    ) fail();
    const result = validateBackupV2PruneWorkerResult(
      JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(observed.resultBytes),
      ),
      control.gate,
      control.input,
    );
    if (result.nativeCustodySha256 !== observed.nativeCustodySha256) fail();
    if (!backupV2ProcessesSettled(control.gate, observed)) {
      if (
        result.state !== "PARTIAL" ||
        await caps.cancel(control.gate) !== "SETTLED"
      ) {
        control.phase = "CANCELLATION_BLOCKED";
        await save();
        return report();
      }
    }
    control.result = result;
    control.phase = "SETTLED";
    await save();
    return report(true);
  }
  if (!control.result) fail();
  const result = control.result;
  const live = await caps.gate.read();
  if (live !== null) {
    same(validateBackupV2Gate(live), control.gate);
    const observed = await caps.observe(control.gate);
    if (observed.unit !== "ABSENT") {
      if (!observed.resultBytes) fail();
      await caps.stop(control.gate, {
        resultSha256: backupV2ArtifactSha256(observed.resultBytes),
        nativeCustodySha256: result.nativeCustodySha256,
      });
    }
    await caps.gate.replace(control.gate, null);
  } else if (!await caps.gate.cleared(control.gate)) fail();
  if (result.state === "PARTIAL") {
    control.phase = "PARTIAL";
    await save();
    return report();
  }
  if (control.input.stage === "PLAN") {
    await deps.private.write(
      `${PIP_JOB_EVIDENCE_PATH}/${settings.envelope.request.jobId}/v2-scratch-cleanup.json`,
      result.scratchCleanup,
    );
    await deps.private.write(`${path}.plan-proved.json`, control);
    const next = gate(control.gate.sourceBootId);
    control = {
      ...control,
      phase: "REQUESTED",
      gate: next,
      result: null,
      input: {
        ...control.input,
        gate: next,
        stage: "EXECUTE",
        plan: result.plan,
      },
    };
    await save();
    return report(true);
  }
  const retained = state.catalog.filter((entry) =>
    result.retainedCaptureIds.includes(
      entry.format === "backup-v1"
        ? entry.entry.index.generation
        : entry.envelope.request.captureId,
    )
  );
  if (retained.length !== 4) fail();
  const store = deps.metadataStore((await loadSourceConfig(deps)).b2);
  const retainedLegacy = retained.filter((entry) =>
    entry.format === "backup-v1"
  );
  const freshInventory = async () =>
    (await Promise.all([store.versions(), store.versions(BACKUP_V2_NAMESPACE)]))
      .flat();
  let inventory = await freshInventory();
  const selection = selectPruneCandidates(
    inventory,
    state.legacy.catalog,
    retainedLegacy.length,
  );
  same(
    [...selection.toPrune].sort(),
    [...result.obsoleteLegacyCaptureIds].sort(),
  );
  const protectedIds = new Set(selection.retainedFileIds);
  for (const entry of retained) {
    if (entry.format === "backup-v2") {
      const descriptor = control.input.graphs.find((graph) =>
        graph.root.plaintextSha256 ===
          entry.selectedRoot.reference.plaintextSha256
      );
      if (!descriptor) fail();
      const base = backupV2ProtectionControlDirectory(
          descriptor.manifestSha256,
        ),
        bytes = await deps.private.readBytes(
          `${base}/manifest.json`,
          BACKUP_V2_LIMITS.controlResponseBytes,
        );
      if (!bytes) fail();
      const manifest = parseBackupV2ProtectionManifest(bytes, descriptor);
      for (const page of manifest.pages) {
        const raw = await deps.private.readBytes(
          `${base}/${backupV2ProtectionPageName(page.pageIndex)}`,
          BACKUP_V2_LIMITS.controlResponseBytes,
        );
        if (!raw) fail();
        for (
          const object of parseBackupV2ProtectionPage(
            raw,
            manifest,
            page.pageIndex,
          ).objects
        ) protectedIds.add(object.fileId);
      }
    }
  }
  if (!control.legacyPlan) {
    control.legacyPlan = selection.toPrune.map((generation) => ({
      generation,
      fileIds: selection.toDelete.filter((object) =>
        generationPrefixes(generation).some((prefix) =>
          object.fileName.startsWith(prefix)
        )
      ).map((object) => object.fileId),
    }));
    await save();
  }
  for (const entry of control.legacyPlan) {
    for (const id of entry.fileIds) {
      inventory = await freshInventory();
      if (!retainedIdsPresent(inventory, [...protectedIds])) fail();
      const check = revalidatePruneDeletions(
        inventory,
        control.legacyPlan,
        selection.toPrune,
        [...protectedIds],
      );
      if (check.violation) fail();
      const object = check.pending.find((item) => item.fileId === id);
      if (object) await store.remove(object);
    }
  }
  inventory = await freshInventory();
  const final = revalidatePruneDeletions(
    inventory,
    control.legacyPlan,
    selection.toPrune,
    [...protectedIds],
  );
  if (
    final.violation || final.pending.length ||
    !retainedIdsPresent(inventory, [...protectedIds])
  ) fail();
  await deps.private.write(`${path}.before-catalog-trim.json`, state);
  state.catalog = retained;
  state.legacy.catalog = retainedLegacy.map((entry) => entry.entry);
  await deps.private.write(
    CONTROLLER_STATE_PATH,
    validateBackupV2ControllerState(state),
  );
  control.phase = "COMPLETE";
  await save();
  return null;
}

export async function runBackupV2ControllerCycle(
  deps: PiDeps,
  bridge: BackupV2ControllerCapabilities["bridge"],
): Promise<BackblazeRunReport> {
  let value =
    await deps.private.read<ControllerState | BackupV2ControllerState>(
      CONTROLLER_STATE_PATH,
    ) ?? { schemaVersion: 1 as const, catalog: [] };
  const caps = realBackupV2ControllerCapabilities(deps, bridge),
    deadline = performance.now() + 240_000;
  let state: BackupV2ControllerState;
  do {
    state = await stepBackupV2Controller(value, caps);
    value = state;
    const job = state.job;
    if (
      !job || ["COMPLETE", "FAILED", "CANCELLATION_BLOCKED"].includes(job.phase)
    ) break;
    const status = job.activeKind === "worker"
      ? job.workerStatus
      : job.verifierStatus;
    if (["WORKER", "VERIFY"].includes(job.phase) && status !== null) break;
    if (["WORKER", "VERIFY"].includes(job.phase)) await deps.sleep(1000);
  } while (performance.now() < deadline);
  let retention: BackblazeRunReport | null = null;
  do {
    try {
      retention = await runBackupV2RetentionCycle(state!, deps, caps);
    } catch {
      retention = {
        status: "B2_RETENTION_BLOCKED",
        observedAtUtc: deps.now().toISOString(),
        healthy: false,
        detail:
          "Backup acceptance is preserved; retention or cleanup proof is incomplete",
      };
      break;
    }
    if (!retention || !retention.healthy) break;
    const current = await deps.private.read<BackupV2RetentionControl>(
      `.private/file-backup/retention/${
        state!.job!.settings.envelope.request.jobId
      }.json`,
    );
    if (
      current?.phase === "RUNNING" && current.gate.custody &&
      current.result === null
    ) break;
    await deps.sleep(1000);
  } while (performance.now() < deadline);
  const report = retention ?? backupV2ControllerReport(state!, deps.now());
  await deps.private.write(B2_REPORT_PATH, report);
  return report;
}
