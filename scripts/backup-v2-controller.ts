/** Bounded Pi reconciliation. Source work and its decrypt bridge have their own
 * managed leases; a controller attempt never owns their process lifetime. */
import { isDeepStrictEqual } from "node:util";
import {
  type BackblazeRunReport, type ControllerState, type PiDeps,
  validateCatalogEntry, validateControllerState, weekWindow, withinCatchUp,
  B2_REPORT_PATH, CONTROLLER_STATE_PATH, GATE_PATH, JOBS_RUNTIME_ROOT,
  PIP_JOB_EVIDENCE_PATH, RELEASES_ROOT, BACKUP_BASE, PUBLIC_HOME_BASE,
  loadDeployment, loadSourceConfig,
  workerUnitNameOf, verifyUnitName,
  type RemoteSeam, type PrivateSeam, realPrivateSeam, realRemoteSeam, realRemoteRunner,
} from "./backblaze-file-backup.ts";
import {
  type BackupRuntimeCatalogEntry, type BackupV2Gate,
  type BackupV2Result, type BackupV2Request, type BackupV2Status, validateBackupRuntimeCatalogEntry,
  validateBackupV2CatalogEntry, validateBackupV2Gate, validateBackupV2Result,
  validateBackupV2Status, assertBackupV2StatusTransition,
  backupV2RequestSha256,
} from "./backup-v2-runtime-contract.ts";
import {
  type BackupV2WorkerSettings, type BackupV2VerifiedResult,
  backupV2ArtifactBytes, backupV2ArtifactSha256, validateBackupV2WorkerSettings,
  validateBackupV2VerifiedResult,
  backupV2GateDirectory,
} from "./backup-v2-worker.ts";
import { type BackupV2SupervisorIdentity, type BackupV2TreeObservation, backupV2SupervisorUnitProperties, settleBackupV2Cancellation } from "./backup-v2-supervisor.ts";
import { BACKUP_V2_LIMITS, BACKUP_V2_PROFILE_ID } from "./backup-v2-profile.ts";
import { type CaptureSettings } from "./backblaze-capture.ts";
import { backupV2SourceConfigSha256 } from "./backup-v2-metadata.ts";
import { assertBackblazeLaunchAllowed, type BackupControllerGate, validateGate, GATE_BACKUP_SLICE, GATE_OWNER, GATE_REMOTE_HOST, GATE_SOURCE_LOCK_PATH, GATE_BACKUP_CGROUP_ROOT } from "./backblaze-controller-contract.ts";
import { shellQuote } from "./backup-guest.ts";

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
    /** Durable exact-gate tombstone, recorded only after independent settlement. */
    cleared(gate: BackupV2Gate): Promise<boolean>;
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
function same(a: unknown, b: unknown): void { if (!isDeepStrictEqual(a,b)) fail(); }
function preserveLegacy(value: unknown): ControllerState { validateControllerState(value); return structuredClone(value) as ControllerState; }
function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (Object.keys(r).length !== keys.length || keys.some((key) => !Object.hasOwn(r, key))) fail(); return r;
}
const phases: BackupV2ControllerPhase[] = ["REQUESTED", "WORKER", "WORKER_SETTLED", "VERIFY_REQUESTED", "VERIFY", "VERIFY_SETTLED", "COMPLETE", "FAILED", "CANCELLATION_BLOCKED"];
export function validateBackupV2ControllerState(value: unknown): BackupV2ControllerState {
  const r = record(value, ["schemaVersion", "format", "legacy", "job", "catalog"]);
  if (r.schemaVersion !== 2 || r.format !== "backup-v2-controller" || !Array.isArray(r.catalog)) fail();
  const legacy = preserveLegacy(r.legacy), catalog = r.catalog.map((entry) => validateBackupRuntimeCatalogEntry(entry, validateCatalogEntry));
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
/** Strict gate union at the existing Pi path; no secret settings read is needed. */
export async function readBackupRuntimeGate(privateIO: PrivateSeam = realPrivateSeam(), path = GATE_PATH): Promise<BackupControllerGate | BackupV2Gate | null> {
  const value = await privateIO.read<unknown>(path);
  if (value === undefined) return null;
  return (value as {schemaVersion?:unknown}|null)?.schemaVersion === 2 ? validateBackupV2Gate(value) : validateGate(value);
}
export function backupV2TreeSettled(gate: BackupV2Gate, observation: BackupV2ControllerObservation, retainedTerminalProof = false): boolean {
  const tree = observation.tree;
  if (!gate.custody || !tree || observation.sourceBootId !== gate.sourceBootId || !["EXITED", "FAILED", ...(retainedTerminalProof ? ["ABSENT"] : [])].includes(observation.unit)) return false;
  same(observation.identity, gate.custody); same(tree.identity, gate.custody);
  return tree.mainPid === 0 && tree.controlPid === 0 && tree.cgroupPopulated === false && tree.descendants === 0 && tree.escapedProcesses === 0 && tree.namespaceReferences === 0 && tree.openPipelineHandles === 0 && tree.pendingOperations === 0 && tree.sourceLockFree === true;
}

/** Exactly one bounded reconciliation; no polling loop and no whole-job timer. */
export async function stepBackupV2Controller(input: ControllerState | BackupV2ControllerState, deps: BackupV2ControllerCapabilities): Promise<BackupV2ControllerState> {
  let state: BackupV2ControllerState = (input as { schemaVersion: number }).schemaVersion === 1
    ? { schemaVersion: 2, format: "backup-v2-controller", legacy: preserveLegacy(input), job: null, catalog: validateControllerState(input).catalog.map((entry) => ({ schemaVersion: 1, format: "backup-v1", entry })) }
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
      if (!backupV2TreeSettled(gate, await deps.observe(gate)) && !await deps.gate.cleared(gate)) { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
      if (kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
      await deps.stop(gate); await deps.gate.replace(gate, null);
    } else {
      if (!await deps.gate.cleared(gate)) { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
      if (kind === "verify" && await deps.bridge.close(gate) !== "CLOSED") { job.phase = "CANCELLATION_BLOCKED"; return await save(); }
    }
    if (kind === "worker") { job.phase = "VERIFY_REQUESTED"; job.activeKind = "verify"; return await save(); }
    const verified = job.verified!;
    const entry = validateBackupV2CatalogEntry({ schemaVersion: 2, format: "backup-v2", envelope: job.settings.envelope, resultSha256: backupV2ArtifactSha256(new Uint8Array(job.workerResultBytes!)), selectedRoot: verified.selectedRoot, receipt: verified.receipt, receiptReference: verified.receiptReference, acceptedAtUtc: deps.now().toISOString() });
    const existing = state.catalog.find((old) => old.schemaVersion === 2 && old.envelope.requestSha256 === entry.envelope.requestSha256);
    if (existing) { if (existing.schemaVersion !== 2) fail(); same({ ...existing, acceptedAtUtc: entry.acceptedAtUtc }, entry); } else state.catalog.push(entry);
    job.phase = "COMPLETE"; return await save();
  }
  if (live === null) fail();
  const savedLive = validateBackupV2Gate(live);
  if (gate.custody === null && savedLive.custody !== null) {
    same({ ...savedLive, custody: null, state: "PENDING", updatedAtUtc: gate.updatedAtUtc }, gate);
    gate = savedLive;
    if (kind === "worker") job.workerGate = gate; else job.verifierGate = gate;
    await save();
  } else same(savedLive, gate);
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
  if (["RUNNING", "STARTING"].includes(observation.unit)) return await save();
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

/** Existing immutable wrapper names, with an explicit version-specific import. */
export function backupV2Entrypoint(jobId: string, revision: string, kind: "worker" | "verify"): string {
  if (!/^job-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(jobId) || !/^[a-f0-9]{40}$/.test(revision)) fail();
  return `import { runBackupV2RemoteWorker } from ${JSON.stringify(`${RELEASES_ROOT}/${revision}/scripts/backup-v2-worker.ts`)};\nawait runBackupV2RemoteWorker(${JSON.stringify(jobId)}, ${JSON.stringify(kind)});\n`;
}
export function backupV2LaunchArguments(settings: BackupV2WorkerSettings, kind: "worker" | "verify"): string[] {
  validateBackupV2WorkerSettings(settings);
  const request = settings.envelope.request, gate = kind === "worker" ? settings.workerGate : settings.verifierGate;
  const runtime = `${JOBS_RUNTIME_ROOT}/${request.jobId}`, publicHome = `${PUBLIC_HOME_BASE}/${request.captureId}`;
  const stagingDevice = "/dev/disk/by-id/scsi-3608cae23d6ea4b84be48c40d288c890e";
  const properties = [
    ...Object.entries({ ...backupV2SupervisorUnitProperties(60_000), RemainAfterExit: "yes", Slice: GATE_BACKUP_SLICE, MemoryHigh: "infinity", MemoryMax: "6G", MemorySwapMax: "0", CPUQuota: "100%", CPUWeight: "1", Nice: "19", TasksMax: "256", LimitCORE: "0", OOMPolicy: "kill", UMask: "0077", WorkingDirectory: runtime }).map(([k,v]) => `${k}=${v}`),
    "IOAccounting=yes", "IOReadBandwidthMax=/ 36M", "IOWriteBandwidthMax=/ 36M", "IOReadIOPSMax=/ 4500", "IOWriteIOPSMax=/ 4500",
    `IOReadBandwidthMax=${stagingDevice} 12M`, `IOWriteBandwidthMax=${stagingDevice} 12M`, `IOReadIOPSMax=${stagingDevice} 1500`, `IOWriteIOPSMax=${stagingDevice} 1500`,
  ];
  return ["systemd-run", "--quiet", `--unit=${gate.unitName}`, ...properties.map((p) => `--property=${p}`), "/usr/local/bin/deno", "run", "--no-prompt", "--cached-only",
    `--allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT},${publicHome},/proc,/sys/fs/cgroup`,
    `--allow-write=${BACKUP_BASE},${PUBLIC_HOME_BASE}`, "--allow-env=INVOCATION_ID,NOTIFY_SOCKET",
    "--allow-ffi=/usr/lib/libsystemd.so.0", "--allow-run=/usr/bin/bash,/usr/bin/unshare,/usr/bin/gpg,/usr/bin/zstd,/usr/bin/tar,/usr/bin/mkfifo,/usr/bin/curl,/usr/bin/sudo,/usr/bin/cat,/usr/bin/chown",
    `${runtime}/entry-${kind}.ts`];
}

/** Root-only bounded control read; payload and private keys never cross this seam. */
function remoteProgram(program: string): string {
  return `printf '%s' ${shellQuote(program)} | /usr/local/bin/deno run --no-prompt --allow-read=/proc,/sys/fs/cgroup,${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT} --allow-run=/usr/bin/systemctl,/usr/bin/flock -`;
}
export function backupV2ObservationProgram(gateInput: BackupV2Gate): string {
  const gate = validateBackupV2Gate(gateInput);
  return `
const gate=${JSON.stringify(gate)};
const opts={clearEnv:true,env:{PATH:"/usr/bin:/bin",LC_ALL:"C"},stdout:"piped",stderr:"piped"};
const run=async(command,args)=>await new Deno.Command(command,{...opts,args}).output();
const out=await run("/usr/bin/systemctl",["show",gate.unitName,"--no-pager","--property=LoadState,ActiveState,SubState,Result,MainPID,ControlPID,ControlGroup,InvocationID"]);
const props=Object.fromEntries(new TextDecoder().decode(out.stdout).trim().split("\\n").map(x=>{const p=x.indexOf("=");return[x.slice(0,p),x.slice(p+1)]}));
if(!out.success&&props.LoadState!=="not-found")throw Error("Unit observation unavailable");
const boot=(await Deno.readTextFile("/proc/sys/kernel/random/boot_id")).trim();
const group=${JSON.stringify(GATE_BACKUP_CGROUP_ROOT)}+"/"+gate.unitName;
let unit=props.LoadState==="not-found"?"ABSENT":props.ActiveState==="failed"?"FAILED":props.ActiveState==="active"&&props.SubState==="exited"?"EXITED":props.ActiveState==="active"?"RUNNING":"STARTING";
const pid=Number(props.MainPID||0),controlPid=Number(props.ControlPID||0);
let identity=null;
if(pid>0){const text=await Deno.readTextFile("/proc/"+pid+"/stat");const start=text.slice(text.lastIndexOf(")")+2).split(" ")[19];const cg=(await Deno.readTextFile("/proc/"+pid+"/cgroup")).trim();if(cg!=="0::"+group||props.ControlGroup!==group||! /^[0-9a-f]{32}$/.test(props.InvocationID))throw Error("Unit identity mismatch");identity={unitName:gate.unitName,invocationId:props.InvocationID,mainPid:pid,mainStartTicks:start,cgroup:group};}
else if(gate.custody&&props.InvocationID===gate.custody.invocationId&&props.LoadState==="loaded"){identity=gate.custody;}
else if(gate.custody&&unit==="ABSENT"){let gone=false;try{const s=await Deno.readTextFile("/proc/"+gate.custody.mainPid+"/stat");gone=s.slice(s.lastIndexOf(")")+2).split(" ")[19]!==gate.custody.mainStartTicks;}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;gone=true;}if(!gone)throw Error("Original process still exists");identity=gate.custody;}
const read=async(path,limit)=>{try{const info=await Deno.lstat(path);if(!info.isFile||info.isSymlink||info.uid!==0||info.nlink!==1||(info.mode&511)!==384||info.size>limit)throw Error("Unsafe artifact");const bytes=await Deno.readFile(path);if(bytes.length!==info.size)throw Error("Changed artifact");return bytes;}catch(e){if(e instanceof Deno.errors.NotFound)return null;throw e;}};
const directory=identity?${JSON.stringify(BACKUP_BASE)}+"/"+gate.envelope.request.captureId+"/v2-"+gate.gateId+"/"+identity.invocationId:null;
const statusBytes=directory?await read(directory+"/status.json",${BACKUP_V2_LIMITS.controlResponseBytes}):null;
const resultBytes=directory?await read(directory+"/result.json",${BACKUP_V2_LIMITS.controlResponseBytes}):null;
let descendants=0,populated=false;
const walk=async(path,depth=0)=>{if(depth>32)throw Error("Cgroup depth bound");try{const procs=(await Deno.readTextFile(path+"/cgroup.procs")).trim().split("\\n").filter(Boolean);descendants+=procs.length;if(descendants>4096)throw Error("Process count bound");for await(const child of Deno.readDir(path))if(child.isDirectory)await walk(path+"/"+child.name,depth+1);}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;}};
await walk("/sys/fs/cgroup"+group);populated=descendants>0;
const ancestors=new Set();let ancestor=Deno.pid;while(ancestor>0&&!ancestors.has(ancestor)){ancestors.add(ancestor);try{const s=await Deno.readTextFile("/proc/"+ancestor+"/stat");ancestor=Number(s.slice(s.lastIndexOf(")")+2).split(" ")[1]);}catch{break;}}
let escaped=0,references=0,handles=0,count=0;
for await(const entry of Deno.readDir("/proc")){if(!/^[1-9][0-9]*$/.test(entry.name))continue;if(++count>4096)throw Error("Host process bound");const n=Number(entry.name);if(ancestors.has(n))continue;const base="/proc/"+entry.name;try{const command=new TextDecoder().decode(await Deno.readFile(base+"/cmdline"));let matches=command.includes(gate.envelope.request.captureId)||command.includes(gate.envelope.request.jobId);let fds=0;for await(const fd of Deno.readDir(base+"/fd")){if(++fds>4096)throw Error("Handle bound");try{const target=await Deno.readLink(base+"/fd/"+fd.name);if(target.includes(gate.envelope.request.captureId)||target.includes(gate.envelope.request.jobId)){handles++;matches=true;}}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;}}const mounts=await Deno.readTextFile(base+"/mountinfo");if(mounts.length>2097152)throw Error("Namespace metadata bound");if(mounts.includes(gate.envelope.request.captureId)){references++;matches=true;}if(matches&&!(await Deno.readTextFile(base+"/cgroup")).split("\\n").includes("0::"+group))escaped++;}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;}}
const lock=await run("/usr/bin/flock",["-n",gate.sourceLockPath,"/usr/bin/true"]);
const tree=identity?{identity,observedMonotonicMs:0,mainPid:pid,controlPid,cgroupPopulated:populated,descendants,escapedProcesses:escaped,namespaceReferences:references,openPipelineHandles:handles,pendingOperations:descendants===0&&escaped===0&&handles===0?0:null,sourceLockFree:lock.code===0}:null;
console.log(JSON.stringify({sourceBootId:boot,unit,identity,status:statusBytes?JSON.parse(new TextDecoder().decode(statusBytes)):null,resultBytes:resultBytes?[...resultBytes]:null,tree}));
`;
}

export async function observeBackupV2Source(gate: BackupV2Gate, remote: Pick<RemoteSeam,"root"> = realRemoteSeam(realRemoteRunner)): Promise<BackupV2ControllerObservation> {
  const result = await remote.root(remoteProgram(backupV2ObservationProgram(gate)));
  if (result.code !== 0 || result.stdout.length > 12 * BACKUP_V2_LIMITS.controlResponseBytes) throw new Error("Backup v2 independent source observation failed");
  const value = JSON.parse(result.stdout) as BackupV2ControllerObservation & { resultBytes: number[] | null };
  if (value.tree) value.tree.observedMonotonicMs = performance.now();
  return { ...value, resultBytes: value.resultBytes ? new Uint8Array(value.resultBytes) : null };
}

/** Persist one exact generated artifact without replacing an old job's bytes. */
async function installBackupV2Artifact(deps: PiDeps, path: string, value: unknown): Promise<void> {
  if (!path.startsWith(JOBS_RUNTIME_ROOT+"/") && !path.startsWith(BACKUP_BASE+"/")) fail();
  const bytes = [...backupV2ArtifactBytes(value)];
  const program = `const path=${JSON.stringify(path)},bytes=new Uint8Array(${JSON.stringify(bytes)});const before=await Deno.lstat(path.slice(0,path.lastIndexOf("/")));if(!before.isDirectory||before.isSymlink||before.uid!==0||(before.mode&511)!==448||await Deno.realPath(path.slice(0,path.lastIndexOf("/")))!==path.slice(0,path.lastIndexOf("/")))throw Error("Unsafe parent");try{const info=await Deno.lstat(path);if(!info.isFile||info.isSymlink||info.uid!==0||info.nlink!==1||(info.mode&511)!==384||info.size!==bytes.length)throw Error("Unsafe existing artifact");const prior=await Deno.readFile(path);if(prior.some((b,i)=>b!==bytes[i]))throw Error("Artifact conflict");}catch(e){if(!(e instanceof Deno.errors.NotFound))throw e;using file=await Deno.open(path,{createNew:true,write:true,mode:384});let at=0;while(at<bytes.length){const count=await file.write(bytes.subarray(at));if(count<=0)throw Error("Short write");at+=count;}await file.sync();}using parent=await Deno.open(path.slice(0,path.lastIndexOf("/")),{read:true});await parent.sync();`;
  const script = `printf '%s' ${shellQuote(program)} | /usr/local/bin/deno run --no-prompt --allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT} --allow-write=${BACKUP_BASE},${JOBS_RUNTIME_ROOT} -`;
  if ((await deps.remote.root(script)).code !== 0) throw new Error("Backup v2 immutable artifact installation failed");
}

export function realBackupV2ControllerCapabilities(deps: PiDeps, bridge: BackupV2ControllerCapabilities["bridge"]): BackupV2ControllerCapabilities {
  const pathForClear = (gate: BackupV2Gate) => `${PIP_JOB_EVIDENCE_PATH}/${gate.envelope.request.jobId}/v2-${gate.gateId}-${gate.custody?.invocationId}-cleared.json`;
  const observe = (gate: BackupV2Gate) => observeBackupV2Source(gate, deps.remote);
  const retainedProof = async (gate: BackupV2Gate): Promise<boolean> => {
    const saved = await deps.private.read<{gate:unknown; proof:BackupV2ControllerObservation}>(pathForClear(gate));
    if (!saved) return false; same(saved.gate,gate);
    if (!backupV2TreeSettled(gate,saved.proof,true)) fail();
    return backupV2TreeSettled(gate,await observe(gate),true);
  };
  return {
    now: deps.now, persist: (state) => deps.private.write(CONTROLLER_STATE_PATH, state),
    archive: (state) => deps.private.write(`${PIP_JOB_EVIDENCE_PATH}/predecessor-${backupV2ArtifactSha256(backupV2ArtifactBytes(state))}.json`, state),
    gate: {
      read: async () => await deps.private.read(GATE_PATH) ?? null,
      async replace(expected,next) {
        same(await deps.private.read(GATE_PATH) ?? null, expected);
        if (next) { await deps.private.write(GATE_PATH, validateBackupV2Gate(next)); return; }
        if (!expected || !await retainedProof(expected)) fail();
        // Only the controller lock holder may remove the exact compared gate.
        same(await deps.private.read(GATE_PATH), expected); await Deno.remove(GATE_PATH);
      },
      cleared: retainedProof,
    },
    async create(periodKey) {
      const deployment=await loadDeployment(deps),config=await loadSourceConfig(deps),id=crypto.randomUUID(),jobId=`job-${id}`;
      const captureSettings: CaptureSettings={sources:config.sources,generation:`generation-${id}`,recipientFile:`${JOBS_RUNTIME_ROOT}/${jobId}/recipient.asc`,recipientSha256:deployment.recipientSha256,recipientFingerprint:deployment.recipientFingerprint,exclusionsText:config.exclusionsText};
      const request: BackupV2Request={schemaVersion:2,format:"backup-v2",profile:BACKUP_V2_PROFILE_ID,jobId,captureId:captureSettings.generation,periodKey,requestedAtUtc:deps.now().toISOString(),sourceRevision:deployment.sourceRevision,sourceConfigSha256:backupV2SourceConfigSha256(captureSettings),recipientSha256:deployment.recipientSha256,recipientFingerprint:deployment.recipientFingerprint};
      const envelope={request,requestSha256:backupV2RequestSha256(request)};
      const boot=(await deps.remote.source("cat /proc/sys/kernel/random/boot_id"));if(boot.code!==0||!/^[0-9a-f-]{36}$/.test(boot.stdout.trim()))fail();
      const gate=(kind:"worker"|"verify")=>{const gateId=crypto.randomUUID();return validateBackupV2Gate({schemaVersion:2,format:"backup-v2",owner:GATE_OWNER,envelope,gateId,sourceBootId:boot.stdout.trim(),kind,unitName:`arch-vps-b2-v2-${kind}-${id}-${gateId}.service`,custody:null,state:"PENDING",remoteHost:GATE_REMOTE_HOST,sourceLockPath:GATE_SOURCE_LOCK_PATH,createdAtUtc:request.requestedAtUtc,updatedAtUtc:request.requestedAtUtc});};
      return validateBackupV2WorkerSettings({schemaVersion:2,format:"backup-v2",envelope,captureSettings,B2Settings:config.b2,workerGate:gate("worker"),verifierGate:gate("verify"),publicationAttemptId:crypto.randomUUID()});
    },
    async admit(legacy) {
      assertBackblazeLaunchAllowed(await deps.private.read(".private/backup-runtime.json"),await deps.private.read(".private/backup-scheduled-window.json"));
      if (legacy.job && !["COMPLETE","FAILED"].includes(legacy.job.phase)) fail();
      const check=await deps.remote.root(`flock -n ${shellQuote(GATE_SOURCE_LOCK_PATH)} true`);if(check.code!==0)fail();
      if(legacy.job){for(const name of [workerUnitNameOf(legacy.job.envelope.request.generation),verifyUnitName(legacy.job.envelope.request.generation)]) {const observed=await deps.remote.observe(name,legacy.job.envelope.request.jobId);if(!observed.reachable||!observed.lockFree||Number(observed.props.get("MainPID")||0)!==0||Number(observed.props.get("ControlPID")||0)!==0||(observed.props.get("LoadState")!=="not-found"&&Number(observed.props.get("TasksCurrent")||0)!==0))fail();}}
    },
    async install(settings) {
      const recipient=(await loadSourceConfig(deps)).recipientBytes;
      if(backupV2ArtifactSha256(recipient)!==settings.envelope.request.recipientSha256)fail();
      const req=settings.envelope.request;
      const files=[{path:"settings.json",data:backupV2ArtifactBytes(settings)},{path:"recipient.asc",data:recipient},{path:"entry-worker.ts",data:new TextEncoder().encode(backupV2Entrypoint(req.jobId,req.sourceRevision,"worker"))},{path:"entry-verify.ts",data:new TextEncoder().encode(backupV2Entrypoint(req.jobId,req.sourceRevision,"verify"))}].map(entry=>({path:entry.path,data:[...entry.data],sha256:backupV2ArtifactSha256(entry.data)}));
      if((await deps.remote.installer({jobId:req.jobId,sourceRevision:req.sourceRevision,files})).code!==0)throw new Error("Backup v2 immutable runtime installation failed");
    },
    async launch(settings,kind) { const gate=kind==="worker"?settings.workerGate:settings.verifierGate;const before=await observe(gate);if(before.unit!=="ABSENT"||before.sourceBootId!==gate.sourceBootId)fail();if((await deps.remote.root(backupV2LaunchArguments(settings,kind).map(shellQuote).join(" "))).code!==0)throw new Error("Backup v2 launch outcome unproved"); },
    observe,
    acknowledge: (gate) => installBackupV2Artifact(deps,`${backupV2GateDirectory(gate)}/gate-bound.json`,{gateId:gate.gateId,requestSha256:gate.envelope.requestSha256,sourceBootId:gate.sourceBootId,custody:gate.custody}),
    verifierInput: (job) => installBackupV2Artifact(deps,`${JOBS_RUNTIME_ROOT}/${job.settings.envelope.request.jobId}/verifier-request.json`,{workerGate:job.workerGate,workerResult:job.workerResult,workerResultBytes:job.workerResultBytes}),
    async stop(gate) {
      const actual=await observe(gate);
      if(actual.unit==="ABSENT") {if(!await retainedProof(gate))fail();return;}
      if(!backupV2TreeSettled(gate,actual))fail();
      await deps.private.write(pathForClear(gate),{gate,proof:actual,recordedAtUtc:deps.now().toISOString()});
      const script=`test "$(cat /proc/sys/kernel/random/boot_id)" = ${shellQuote(gate.sourceBootId)}\ntest "$(systemctl show --value --property=InvocationID ${shellQuote(gate.unitName)})" = ${shellQuote(gate.custody!.invocationId)}\nsystemctl stop ${shellQuote(gate.unitName)}`;
      if((await deps.remote.root(script)).code!==0)throw new Error("Exact source unit stop failed");
    },
    async cancel(gate) {
      if(!gate.custody)return "CANCELLATION_BLOCKED";
      const settled=await settleBackupV2Cancellation(gate.custody,{now:()=>performance.now(),observe:async()=>{const value=await observe(gate);if(!value.tree||value.sourceBootId!==gate.sourceBootId)fail();return value.tree;},stop:async()=>{const before=await observe(gate);same(before.identity,gate.custody);if(before.sourceBootId!==gate.sourceBootId)fail();if((await deps.remote.root(`test "$(systemctl show --value --property=InvocationID ${shellQuote(gate.unitName)})" = ${shellQuote(gate.custody!.invocationId)}\nsystemctl stop ${shellQuote(gate.unitName)}`)).code!==0)fail();}});
      if(settled.state==="SETTLED") {const proof=await observe(gate);if(!backupV2TreeSettled(gate,proof,true))return "CANCELLATION_BLOCKED";await deps.private.write(pathForClear(gate),{gate,proof,recordedAtUtc:deps.now().toISOString()});}
      return settled.state;
    },
    bridge,
  };
}

export async function runBackupV2ControllerCycle(deps: PiDeps, bridge: BackupV2ControllerCapabilities["bridge"]): Promise<BackblazeRunReport> {
  const value=await deps.private.read<ControllerState|BackupV2ControllerState>(CONTROLLER_STATE_PATH)??{schemaVersion:1 as const,catalog:[]};
  const state=await stepBackupV2Controller(value,realBackupV2ControllerCapabilities(deps,bridge)),report=backupV2ControllerReport(state,deps.now());
  await deps.private.write(B2_REPORT_PATH,report);return report;
}
