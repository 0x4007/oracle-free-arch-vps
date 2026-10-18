/** Bounded Pi reconciliation. Source work and its decrypt bridge have their own
 * managed leases; a controller attempt never owns their process lifetime. */
import {
  type BackblazeRunReport, type ControllerState, type PiDeps,
  validateCatalogEntry, validateControllerState, weekWindow, withinCatchUp,
} from "./backblaze-file-backup.ts";
import {
  type BackupRuntimeCatalogEntry, type BackupV2Gate,
  type BackupV2Result, type BackupV2Status, validateBackupRuntimeCatalogEntry,
  validateBackupV2CatalogEntry, validateBackupV2Gate, validateBackupV2Result,
  validateBackupV2Status, assertBackupV2StatusTransition,
} from "./backup-v2-runtime-contract.ts";
import {
  type BackupV2WorkerSettings, type BackupV2VerifiedResult,
  backupV2ArtifactBytes, backupV2ArtifactSha256, validateBackupV2WorkerSettings,
  validateBackupV2VerifiedResult,
} from "./backup-v2-worker.ts";
import type { BackupV2SupervisorIdentity, BackupV2TreeObservation } from "./backup-v2-supervisor.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";

export type BackupV2ControllerPhase = "REQUESTED" | "WORKER" | "WORKER_SETTLED" | "VERIFY_REQUESTED" | "VERIFY" | "VERIFY_SETTLED" | "COMPLETE" | "FAILED" | "CANCELLATION_BLOCKED";
export interface BackupV2ControllerJob {
  settings: BackupV2WorkerSettings;
  phase: BackupV2ControllerPhase;
  activeKind: "worker" | "verify";
  predecessor: { format: "backup-v1" | "backup-v2"; jobId: string | null; sha256: string };
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
    replace(expected: BackupV2Gate | null, next: BackupV2Gate | null): Promise<void>;
  };
  create(periodKey: string): Promise<BackupV2WorkerSettings>;
  /** Includes existing Oracle/scheduled claim, legacy invocation/lock settlement. */
  admit(legacy: ControllerState): Promise<void>;
  install(settings: BackupV2WorkerSettings): Promise<void>;
  launch(settings: BackupV2WorkerSettings, kind: "worker" | "verify"): Promise<void>;
  observe(gate: BackupV2Gate): Promise<BackupV2ControllerObservation>;
  acknowledge(gate: BackupV2Gate): Promise<void>;
  verifierInput(job: BackupV2ControllerJob): Promise<void>;
  /** Must freshly reconcile the exact retained invocation immediately before stop. */
  stop(gate: BackupV2Gate): Promise<void>;
  cancel(gate: BackupV2Gate): Promise<"SETTLED" | "CANCELLATION_BLOCKED">;
  bridge: {
    ensure(settings: BackupV2WorkerSettings, gate: BackupV2Gate): Promise<"READY" | "PENDING" | "CANCELLATION_BLOCKED">;
    close(gate: BackupV2Gate): Promise<"CLOSED" | "CANCELLATION_BLOCKED">;
  };
}
function fail(): never { throw new Error("Backup v2 controller state or custody invalid"); }
function same(a: unknown, b: unknown): void { if (JSON.stringify(a) !== JSON.stringify(b)) fail(); }
function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (Object.keys(r).length !== keys.length || keys.some((key) => !Object.hasOwn(r, key))) fail(); return r;
}
const phases: BackupV2ControllerPhase[] = ["REQUESTED", "WORKER", "WORKER_SETTLED", "VERIFY_REQUESTED", "VERIFY", "VERIFY_SETTLED", "COMPLETE", "FAILED", "CANCELLATION_BLOCKED"];
export function validateBackupV2ControllerState(value: unknown): BackupV2ControllerState {
  const r = record(value, ["schemaVersion", "format", "legacy", "job", "catalog"]);
  if (r.schemaVersion !== 2 || r.format !== "backup-v2-controller" || !Array.isArray(r.catalog)) fail();
  const legacy = validateControllerState(r.legacy), catalog = r.catalog.map((entry) => validateBackupRuntimeCatalogEntry(entry, validateCatalogEntry));
  same(catalog.filter((entry) => entry.schemaVersion === 1).map((entry) => entry.entry), legacy.catalog);
  const ids = catalog.map((entry) => entry.schemaVersion === 1 ? entry.entry.index.generation : entry.envelope.request.captureId);
  if (new Set(ids).size !== ids.length) fail();
  let job: BackupV2ControllerJob | null = null;
  if (r.job !== null) {
    const j = record(r.job, ["settings", "phase", "activeKind", "predecessor", "workerGate", "verifierGate", "workerStatus", "verifierStatus", "workerResult", "workerResultBytes", "verified", "updatedAtUtc"]);
    const settings = validateBackupV2WorkerSettings(j.settings), workerGate = validateBackupV2Gate(j.workerGate), verifierGate = validateBackupV2Gate(j.verifierGate);
    for (const gate of [workerGate, verifierGate]) same(gate.envelope, settings.envelope);
    if (workerGate.gateId !== settings.workerGate.gateId || verifierGate.gateId !== settings.verifierGate.gateId || !phases.includes(j.phase as BackupV2ControllerPhase) || !["worker", "verify"].includes(String(j.activeKind))) fail();
    const predecessor = record(j.predecessor, ["format", "jobId", "sha256"]);
    if (!["backup-v1", "backup-v2"].includes(String(predecessor.format)) || predecessor.jobId !== null && (typeof predecessor.jobId !== "string" || !/^job-[0-9a-f-]{36}$/.test(predecessor.jobId)) || typeof predecessor.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(predecessor.sha256)) fail();
    const workerStatus = j.workerStatus === null ? null : validateBackupV2Status(j.workerStatus, workerGate), verifierStatus = j.verifierStatus === null ? null : validateBackupV2Status(j.verifierStatus, verifierGate);
    const workerResult = j.workerResult === null ? null : validateBackupV2Result(j.workerResult, workerGate);
    if ((workerResult === null) !== (j.workerResultBytes === null)) fail();
    let workerResultBytes: number[] | null = null;
    if (j.workerResultBytes !== null) {
      if (!Array.isArray(j.workerResultBytes) || j.workerResultBytes.length > BACKUP_V2_LIMITS.controlResponseBytes || j.workerResultBytes.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) fail();
      workerResultBytes = j.workerResultBytes as number[];
      same(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(workerResultBytes))), workerResult);
      if (!workerStatus || workerStatus.phase !== "CLOUD_COMPLETE" || workerStatus.resultSha256 !== backupV2ArtifactSha256(new Uint8Array(workerResultBytes))) fail();
    }
    const verified = j.verified === null ? null : workerResult && workerResultBytes ? validateBackupV2VerifiedResult(j.verified, verifierGate, workerResult, backupV2ArtifactSha256(new Uint8Array(workerResultBytes))) : fail();
    if (typeof j.updatedAtUtc !== "string" || !Number.isFinite(Date.parse(j.updatedAtUtc)) || j.updatedAtUtc < settings.envelope.request.requestedAtUtc) fail();
    if (["WORKER_SETTLED", "VERIFY_REQUESTED", "VERIFY", "VERIFY_SETTLED", "COMPLETE"].includes(String(j.phase)) && !workerResult || ["VERIFY_SETTLED", "COMPLETE"].includes(String(j.phase)) && !verified) fail();
    job = { settings, phase: j.phase as BackupV2ControllerPhase, activeKind: j.activeKind as "worker" | "verify", predecessor: predecessor as unknown as BackupV2ControllerJob["predecessor"], workerGate, verifierGate, workerStatus, verifierStatus, workerResult, workerResultBytes, verified, updatedAtUtc: j.updatedAtUtc };
    if (job.phase === "COMPLETE" && !catalog.some((entry) => entry.schemaVersion === 2 && entry.envelope.requestSha256 === settings.envelope.requestSha256)) fail();
  }
  return { schemaVersion: 2, format: "backup-v2-controller", legacy, job, catalog };
}
export function backupV2PeriodSatisfied(state: BackupV2ControllerState, now: Date): boolean {
  const window = weekWindow(now), start = Date.parse(window.startAtUtc), end = Date.parse(window.endAtUtc);
  return state.catalog.some((entry) => {
    const times = entry.schemaVersion === 1 ? [entry.entry.index.captureFinishedAtUtc] : entry.selectedRoot.root.roles.map((role) => role.captureFinishedAtUtc);
    const latest = Math.max(...times.map(Date.parse)); return latest >= start && latest < end;
  });
}
/** Version-dispatch before recovery/watchdog field access; v1 validators stay unchanged. */
export function backupRuntimeCatalog(value: unknown): BackupRuntimeCatalogEntry[] {
  if ((value as { schemaVersion?: unknown } | null)?.schemaVersion === 1) return validateControllerState(value).catalog.map((entry) => ({ schemaVersion: 1, format: "backup-v1", entry }));
  return validateBackupV2ControllerState(value).catalog;
}
export function backupV2TreeSettled(gate: BackupV2Gate, observation: BackupV2ControllerObservation): boolean {
  const tree = observation.tree;
  if (!gate.custody || !tree || observation.sourceBootId !== gate.sourceBootId || !["EXITED", "FAILED"].includes(observation.unit)) return false;
  same(observation.identity, gate.custody); same(tree.identity, gate.custody);
  return tree.mainPid === 0 && tree.controlPid === 0 && tree.cgroupPopulated === false && tree.descendants === 0 && tree.escapedProcesses === 0 && tree.namespaceReferences === 0 && tree.openPipelineHandles === 0 && tree.pendingOperations === 0 && tree.sourceLockFree === true;
}

/** Exactly one bounded reconciliation; no polling loop and no whole-job timer. */
export async function stepBackupV2Controller(input: ControllerState | BackupV2ControllerState, deps: BackupV2ControllerCapabilities): Promise<BackupV2ControllerState> {
  let state: BackupV2ControllerState = (input as { schemaVersion: number }).schemaVersion === 1
    ? { schemaVersion: 2, format: "backup-v2-controller", legacy: validateControllerState(input), job: null, catalog: validateControllerState(input).catalog.map((entry) => ({ schemaVersion: 1, format: "backup-v1", entry })) }
    : validateBackupV2ControllerState(input);
  const now = deps.now();
  const save = async () => { state = validateBackupV2ControllerState(state); await deps.persist(state); return state; };
  if (!state.job || state.job.phase === "COMPLETE" && state.job.settings.envelope.request.periodKey !== weekWindow(now).periodKey) {
    if (!withinCatchUp(now) || backupV2PeriodSatisfied(state, now)) return state;
    if (await deps.gate.read() !== null) fail();
    await deps.admit(state.legacy); await deps.archive(input);
    const settings = validateBackupV2WorkerSettings(await deps.create(weekWindow(now).periodKey));
    if (settings.envelope.request.periodKey !== weekWindow(now).periodKey) fail();
    const predecessor = { format: (input as { schemaVersion: number }).schemaVersion === 1 ? "backup-v1" as const : "backup-v2" as const, jobId: state.job?.settings.envelope.request.jobId ?? state.legacy.job?.envelope.request.jobId ?? null, sha256: backupV2ArtifactSha256(backupV2ArtifactBytes(input)) };
    state = { ...state, job: { settings, phase: "REQUESTED", activeKind: "worker", predecessor, workerGate: settings.workerGate, verifierGate: settings.verifierGate, workerStatus: null, verifierStatus: null, workerResult: null, workerResultBytes: null, verified: null, updatedAtUtc: now.toISOString() } };
    return await save();
  }
  const job = state.job;
  job.updatedAtUtc = now.toISOString();
  if (job.phase === "COMPLETE" || job.phase === "FAILED") return state;
  const kind = job.activeKind;
  let gate = kind === "worker" ? job.workerGate : job.verifierGate;
  const live = await deps.gate.read();
  if (job.phase === "REQUESTED" || job.phase === "VERIFY_REQUESTED") {
    if (live !== null) same(validateBackupV2Gate(live), gate); else await deps.gate.replace(null, gate);
    await deps.install(job.settings);
    if (kind === "verify") await deps.verifierInput(job);
    job.phase = kind === "worker" ? "WORKER" : "VERIFY"; await save();
    // PENDING gate exists before the launch intent. Resume only observes it;
    // an ambiguous failed launch never starts another invocation automatically.
    await deps.launch(job.settings, kind); return state;
  }
  if (job.phase === "WORKER_SETTLED" || job.phase === "VERIFY_SETTLED") {
    if (live !== null) {
      same(validateBackupV2Gate(live), gate);
      if (!backupV2TreeSettled(gate, await deps.observe(gate))) { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
      if (kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
      await deps.stop(gate); await deps.gate.replace(gate, null);
    } else if (kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
    if (kind === "worker") { job.phase = "VERIFY_REQUESTED"; job.activeKind = "verify"; return await save(); }
    const verified = job.verified!;
    const entry = validateBackupV2CatalogEntry({ schemaVersion: 2, format: "backup-v2", envelope: job.settings.envelope, resultSha256: backupV2ArtifactSha256(new Uint8Array(job.workerResultBytes!)), selectedRoot: verified.selectedRoot, receipt: verified.receipt, receiptReference: verified.receiptReference, acceptedAtUtc: deps.now().toISOString() });
    const existing = state.catalog.find((old) => old.schemaVersion === 2 && old.envelope.requestSha256 === entry.envelope.requestSha256);
    if (existing) same(existing, entry); else state.catalog.push(entry);
    job.phase = "COMPLETE"; return await save();
  }
  if (live === null) fail(); same(validateBackupV2Gate(live), gate);
  if (job.phase === "CANCELLATION_BLOCKED") {
    if (!gate.custody || await deps.cancel(gate) !== "SETTLED" || kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") return await save();
    await deps.stop(gate); await deps.gate.replace(gate, null); job.phase = "FAILED"; return await save();
  }
  const observation = await deps.observe(gate);
  if (observation.sourceBootId !== gate.sourceBootId || observation.unit === "ABSENT") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
  if (!observation.identity) return state;
  if (gate.custody === null) {
    gate = validateBackupV2Gate({ ...gate, state: "ACTIVE", custody: observation.identity, updatedAtUtc: now.toISOString() });
    await deps.gate.replace(kind === "worker" ? job.workerGate : job.verifierGate, gate);
    if (kind === "worker") job.workerGate = gate; else job.verifierGate = gate;
    await save();
  } else same(gate.custody, observation.identity);
  if (kind === "verify") {
    const bridge = await deps.bridge.ensure(job.settings, gate);
    if (bridge === "CANCELLATION_BLOCKED") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
    if (bridge !== "READY") return state;
  }
  await deps.acknowledge(gate);
  if (observation.status === null) return state;
  const status = validateBackupV2Status(observation.status, gate), prior = kind === "worker" ? job.workerStatus : job.verifierStatus;
  if (prior) assertBackupV2StatusTransition(prior, status);
  if (kind === "worker") job.workerStatus = status; else job.verifierStatus = status;
  if (status.phase === "CANCELLATION_BLOCKED" || status.phase === "FAILED" || observation.unit === "FAILED") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
  if (status.finishedAtUtc === null) return await save();
  if (!backupV2TreeSettled(gate, observation) || !observation.resultBytes || backupV2ArtifactSha256(observation.resultBytes) !== status.resultSha256) { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
  const result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(observation.resultBytes));
  if (kind === "worker") { job.workerResult = validateBackupV2Result(result, gate); job.workerResultBytes = [...observation.resultBytes]; job.phase = "WORKER_SETTLED"; }
  else { job.verified = validateBackupV2VerifiedResult(result, gate, job.workerResult!, backupV2ArtifactSha256(new Uint8Array(job.workerResultBytes!))); job.phase = "VERIFY_SETTLED"; }
  return await save();
}

export function backupV2ControllerReport(state: BackupV2ControllerState, now: Date): BackblazeRunReport {
  const job = state.job, phase = job?.phase ?? "IDLE";
  return { status: phase, observedAtUtc: now.toISOString(), healthy: phase === "COMPLETE" || phase === "IDLE" && backupV2PeriodSatisfied(state, now), ...(job ? { jobId: job.settings.envelope.request.jobId, generation: job.settings.envelope.request.captureId } : {}), detail: phase === "COMPLETE" ? "Cloud recovery point accepted; retention requires its separate reference-safe proof" : "Bounded v2 reconciliation; source lease and custody remain independent" };
}

/** Real adapter is below; injectable coordination above is also the acceptance
 * surface for crash boundaries, legacy preservation and exact custody tests. */
export type BackupV2PiDependencies = PiDeps;
