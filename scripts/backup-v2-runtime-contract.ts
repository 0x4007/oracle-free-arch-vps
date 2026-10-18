/** Pure runtime envelopes. Structural validity never substitutes for cloud or
 * independently observed process proof. No v1 request/status is rewritten here. */
import { createHash } from "node:crypto";
import type { CatalogEntry } from "./backblaze-file-backup.ts";
import type { BackupV2SupervisorIdentity } from "./backup-v2-supervisor.ts";
import {
  BACKUP_V2_ROLES,
  type BackupV2LeaseWindow,
  type BackupV2ManifestRef,
  type BackupV2Phase,
  type BackupV2Progress,
  type BackupV2Receipt,
  type BackupV2Role,
  type BackupV2Root,
  parseBackupV2ObjectName,
  validateBackupV2LeaseWindow,
  validateBackupV2ManifestRef,
  validateBackupV2Progress,
  validateBackupV2Receipt,
  validateBackupV2Root,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_LIMITS, BACKUP_V2_PROFILE_ID } from "./backup-v2-profile.ts";
import {
  canonicalUtcMillis,
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "./backblaze-controller-contract.ts";

export interface BackupV2Request {
  schemaVersion: 2;
  format: "backup-v2";
  profile: typeof BACKUP_V2_PROFILE_ID;
  jobId: string;
  captureId: string;
  periodKey: string;
  requestedAtUtc: string;
  sourceRevision: string;
  sourceConfigSha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
}
export interface BackupV2RequestEnvelope {
  request: BackupV2Request;
  requestSha256: string;
}
export type BackupV2UnitKind = "worker" | "verify" | "prune";
export interface BackupV2Execution {
  gateId: string;
  sourceBootId: string;
  custody: BackupV2SupervisorIdentity;
}
export interface BackupV2Status extends BackupV2Execution {
  schemaVersion: 2;
  format: "backup-v2";
  envelope: BackupV2RequestEnvelope;
  kind: BackupV2UnitKind;
  phase: BackupV2Phase;
  activeRoleAttempt: { role: BackupV2Role; attemptId: string } | null;
  startedAtUtc: string;
  updatedAtUtc: string;
  finishedAtUtc: string | null;
  progress: BackupV2Progress;
  lease: BackupV2LeaseWindow;
  resultSha256: string | null;
}
export interface BackupV2SelectedRoot {
  reference: BackupV2ManifestRef;
  root: BackupV2Root;
}
/** Worker output is cloud-complete input for an independent verifier, never an
 * accepted backup. The status hashes its exact persisted result bytes. */
export interface BackupV2Result extends BackupV2Execution {
  schemaVersion: 2;
  format: "backup-v2";
  envelope: BackupV2RequestEnvelope;
  finishedAtUtc: string;
  selectedRoot: BackupV2SelectedRoot;
}
export interface BackupV2Gate {
  schemaVersion: 2;
  format: "backup-v2";
  owner: typeof GATE_OWNER;
  envelope: BackupV2RequestEnvelope;
  gateId: string;
  sourceBootId: string;
  kind: BackupV2UnitKind;
  unitName: string;
  custody: BackupV2SupervisorIdentity | null;
  state: "PENDING" | "ACTIVE" | "CANCELLATION_BLOCKED";
  remoteHost: typeof GATE_REMOTE_HOST;
  sourceLockPath: typeof GATE_SOURCE_LOCK_PATH;
  createdAtUtc: string;
  updatedAtUtc: string;
}
export interface BackupV2CatalogEntry {
  schemaVersion: 2;
  format: "backup-v2";
  envelope: BackupV2RequestEnvelope;
  resultSha256: string;
  selectedRoot: BackupV2SelectedRoot;
  receipt: BackupV2Receipt;
  receiptReference: BackupV2ManifestRef;
  acceptedAtUtc: string;
}
export type BackupRuntimeCatalogEntry = BackupV2CatalogEntry | {
  schemaVersion: 1;
  format: "backup-v1";
  entry: CatalogEntry;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST_KEYS = [
  "schemaVersion",
  "format",
  "profile",
  "jobId",
  "captureId",
  "periodKey",
  "requestedAtUtc",
  "sourceRevision",
  "sourceConfigSha256",
  "recipientSha256",
  "recipientFingerprint",
];
const EXECUTION_KEYS = ["gateId", "sourceBootId", "custody"];
function fail(): never {
  throw new Error("Backup v2 runtime contract is invalid");
}
function record(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (
    Object.keys(r).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(r, k))
  ) fail();
  return r;
}
function text(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) fail();
  return value;
}
function hash(value: unknown, length = 64): string {
  return text(value, new RegExp(`^[0-9a-f]{${length}}$`));
}
function utc(value: unknown): string {
  canonicalUtcMillis(value, "runtime timestamp");
  return value as string;
}
function version(r: Record<string, unknown>): void {
  if (r.schemaVersion !== 2 || r.format !== "backup-v2") fail();
}
function bounded<T>(value: T): T {
  if (
    new TextEncoder().encode(JSON.stringify(value)).length >
      BACKUP_V2_LIMITS.controlResponseBytes
  ) fail();
  return value;
}
function unitName(value: unknown): string {
  return text(value, /^arch-vps-b2-[a-z0-9-]{1,180}\.service$/);
}
function custody(value: unknown): BackupV2SupervisorIdentity {
  const r = record(value, [
    "unitName",
    "invocationId",
    "mainPid",
    "mainStartTicks",
    "cgroup",
  ]);
  const name = unitName(r.unitName);
  if (
    r.cgroup !== `${GATE_BACKUP_CGROUP_ROOT}/${name}` ||
    !Number.isSafeInteger(r.mainPid) || (r.mainPid as number) < 1
  ) fail();
  return {
    unitName: name,
    invocationId: text(r.invocationId, /^[0-9a-f]{32}$/),
    mainPid: r.mainPid as number,
    mainStartTicks: text(r.mainStartTicks, /^[1-9][0-9]{0,19}$/),
    cgroup: r.cgroup as string,
  };
}
function execution(r: Record<string, unknown>): BackupV2Execution {
  return {
    gateId: text(r.gateId, UUID),
    sourceBootId: text(r.sourceBootId, UUID),
    custody: custody(r.custody),
  };
}
function kind(value: unknown): BackupV2UnitKind {
  if (value !== "worker" && value !== "verify" && value !== "prune") fail();
  return value;
}
function equal(a: unknown, b: unknown): void {
  if (JSON.stringify(a) !== JSON.stringify(b)) fail();
}

export function validateBackupV2Request(value: unknown): BackupV2Request {
  const r = record(value, REQUEST_KEYS);
  version(r);
  const jobId = text(r.jobId, /^job-[0-9a-f-]{36}$/);
  text(jobId.slice(4), UUID);
  if (
    r.captureId !== `generation-${jobId.slice(4)}` ||
    r.profile !== BACKUP_V2_PROFILE_ID
  ) fail();
  const periodKey = text(r.periodKey, /^\d{4}-\d{2}-\d{2}$/);
  const day = new Date(`${periodKey}T00:00:00.000Z`);
  if (
    !Number.isFinite(day.getTime()) ||
    day.toISOString().slice(0, 10) !== periodKey || day.getUTCDay() !== 0
  ) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId,
    captureId: r.captureId as string,
    periodKey,
    requestedAtUtc: utc(r.requestedAtUtc),
    sourceRevision: hash(r.sourceRevision, 40),
    sourceConfigSha256: hash(r.sourceConfigSha256),
    recipientSha256: hash(r.recipientSha256),
    recipientFingerprint: text(r.recipientFingerprint, /^[A-F0-9]{40}$/),
  };
}
export function canonicalBackupV2RequestString(value: BackupV2Request): string {
  return JSON.stringify(validateBackupV2Request(value));
}
export function backupV2RequestSha256(value: BackupV2Request): string {
  return createHash("sha256").update(canonicalBackupV2RequestString(value))
    .digest("hex");
}
export function validateBackupV2RequestEnvelope(
  value: unknown,
): BackupV2RequestEnvelope {
  const r = record(value, ["request", "requestSha256"]);
  const request = validateBackupV2Request(r.request),
    requestSha256 = hash(r.requestSha256);
  if (backupV2RequestSha256(request) !== requestSha256) fail();
  return { request, requestSha256 };
}

function selectedRoot(
  value: unknown,
  request: BackupV2Request,
): BackupV2SelectedRoot {
  const r = record(value, ["reference", "root"]);
  const reference = validateBackupV2ManifestRef(r.reference),
    root = validateBackupV2Root(r.root);
  const name = parseBackupV2ObjectName(reference.object.fileName);
  if (name.captureId !== request.captureId || name.kind !== "manifest") fail();
  for (
    const key of [
      "captureId",
      "periodKey",
      "sourceRevision",
      "sourceConfigSha256",
      "recipientSha256",
      "recipientFingerprint",
      "profile",
    ] as const
  ) {
    if (root[key] !== request[key]) fail();
  }
  return { reference, root };
}
/** Pass the saved gate to bind a parsed status/result to the current launch.
 * A null/unbound custody can never validate terminal output. */
function bindGate(
  envelope: BackupV2RequestEnvelope,
  identity: BackupV2Execution,
  gate: BackupV2Gate,
  unitKind: BackupV2UnitKind,
): void {
  const checked = validateBackupV2Gate(gate);
  equal(envelope, checked.envelope);
  if (checked.kind !== unitKind) fail();
  equal(identity, {
    gateId: checked.gateId,
    sourceBootId: checked.sourceBootId,
    custody: checked.custody,
  });
}
export function validateBackupV2Status(
  value: unknown,
  gate?: BackupV2Gate,
): BackupV2Status {
  const r = record(value, [
    "schemaVersion",
    "format",
    "envelope",
    ...EXECUTION_KEYS,
    "kind",
    "phase",
    "activeRoleAttempt",
    "startedAtUtc",
    "updatedAtUtc",
    "finishedAtUtc",
    "progress",
    "lease",
    "resultSha256",
  ]);
  version(r);
  const envelope = validateBackupV2RequestEnvelope(r.envelope),
    identity = execution(r),
    unitKind = kind(r.kind);
  const progress = validateBackupV2Progress(r.progress),
    lease = validateBackupV2LeaseWindow(r.lease);
  const phases = unitKind === "worker"
    ? [
      "PREFLIGHT",
      "CAPTURING_AND_UPLOADING",
      "CLOUD_COMPLETE",
      "FAILED",
      "CANCELLATION_BLOCKED",
    ]
    : unitKind === "verify"
    ? ["PREFLIGHT", "VERIFYING", "ACCEPTED", "FAILED", "CANCELLATION_BLOCKED"]
    : ["PREFLIGHT", "PRUNING", "CLEANED", "FAILED", "CANCELLATION_BLOCKED"];
  if (
    !phases.includes(progress.phase) || r.phase !== progress.phase ||
    progress.observedMonotonicMs !== lease.observedMonotonicMs
  ) fail();
  const startedAtUtc = utc(r.startedAtUtc), updatedAtUtc = utc(r.updatedAtUtc);
  if (
    startedAtUtc < envelope.request.requestedAtUtc ||
    updatedAtUtc < startedAtUtc
  ) fail();
  const terminal = ["CLOUD_COMPLETE", "ACCEPTED", "CLEANED", "FAILED"].includes(
    progress.phase,
  );
  const finishedAtUtc = r.finishedAtUtc === null ? null : utc(r.finishedAtUtc);
  if (
    terminal !== (finishedAtUtc !== null) ||
    finishedAtUtc !== null &&
      (finishedAtUtc < startedAtUtc || finishedAtUtc > updatedAtUtc)
  ) fail();
  const successful = terminal && progress.phase !== "FAILED";
  const resultSha256 = r.resultSha256 === null ? null : hash(r.resultSha256);
  if (successful !== (resultSha256 !== null)) fail();
  let activeRoleAttempt: BackupV2Status["activeRoleAttempt"] = null;
  if (r.activeRoleAttempt !== null) {
    const a = record(r.activeRoleAttempt, ["role", "attemptId"]);
    if (
      unitKind !== "worker" || !BACKUP_V2_ROLES.includes(a.role as BackupV2Role)
    ) fail();
    activeRoleAttempt = {
      role: a.role as BackupV2Role,
      attemptId: text(a.attemptId, UUID),
    };
  }
  if (
    progress.phase === "CAPTURING_AND_UPLOADING" && activeRoleAttempt === null
  ) fail();
  if (gate) bindGate(envelope, identity, gate, unitKind);
  return bounded({
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    ...identity,
    kind: unitKind,
    phase: progress.phase,
    activeRoleAttempt,
    startedAtUtc,
    updatedAtUtc,
    finishedAtUtc,
    progress,
    lease,
    resultSha256,
  });
}
export function validateBackupV2Result(
  value: unknown,
  gate?: BackupV2Gate,
): BackupV2Result {
  const r = record(value, [
    "schemaVersion",
    "format",
    "envelope",
    ...EXECUTION_KEYS,
    "finishedAtUtc",
    "selectedRoot",
  ]);
  version(r);
  const envelope = validateBackupV2RequestEnvelope(r.envelope),
    identity = execution(r),
    finishedAtUtc = utc(r.finishedAtUtc);
  const selected = selectedRoot(r.selectedRoot, envelope.request);
  if (
    finishedAtUtc < envelope.request.requestedAtUtc ||
    selected.root.roles.some((role) =>
      role.captureFinishedAtUtc > finishedAtUtc
    )
  ) fail();
  if (gate) bindGate(envelope, identity, gate, "worker");
  return bounded({
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    ...identity,
    finishedAtUtc,
    selectedRoot: selected,
  });
}
/** Gate presence always blocks competing work, including PENDING, unknown
 * process state and CANCELLATION_BLOCKED. No timestamp authorizes clearing. */
export function validateBackupV2Gate(value: unknown): BackupV2Gate {
  const r = record(value, [
    "schemaVersion",
    "format",
    "owner",
    "envelope",
    "gateId",
    "sourceBootId",
    "kind",
    "unitName",
    "custody",
    "state",
    "remoteHost",
    "sourceLockPath",
    "createdAtUtc",
    "updatedAtUtc",
  ]);
  version(r);
  if (
    r.owner !== GATE_OWNER || r.remoteHost !== GATE_REMOTE_HOST ||
    r.sourceLockPath !== GATE_SOURCE_LOCK_PATH ||
    !["PENDING", "ACTIVE", "CANCELLATION_BLOCKED"].includes(String(r.state))
  ) fail();
  const envelope = validateBackupV2RequestEnvelope(r.envelope),
    name = unitName(r.unitName),
    owned = r.custody === null ? null : custody(r.custody);
  if (
    owned !== null && owned.unitName !== name ||
    r.state === "ACTIVE" && owned === null ||
    r.state === "PENDING" && owned !== null
  ) fail();
  const createdAtUtc = utc(r.createdAtUtc), updatedAtUtc = utc(r.updatedAtUtc);
  if (
    createdAtUtc < envelope.request.requestedAtUtc ||
    updatedAtUtc < createdAtUtc
  ) fail();
  return bounded({
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope,
    gateId: text(r.gateId, UUID),
    sourceBootId: text(r.sourceBootId, UUID),
    kind: kind(r.kind),
    unitName: name,
    custody: owned,
    state: r.state as BackupV2Gate["state"],
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc,
    updatedAtUtc,
  });
}
export function validateBackupV2CatalogEntry(
  value: unknown,
): BackupV2CatalogEntry {
  const r = record(value, [
    "schemaVersion",
    "format",
    "envelope",
    "resultSha256",
    "selectedRoot",
    "receipt",
    "receiptReference",
    "acceptedAtUtc",
  ]);
  version(r);
  const envelope = validateBackupV2RequestEnvelope(r.envelope),
    selected = selectedRoot(r.selectedRoot, envelope.request),
    receipt = validateBackupV2Receipt(r.receipt),
    receiptReference = validateBackupV2ManifestRef(r.receiptReference),
    acceptedAtUtc = utc(r.acceptedAtUtc);
  equal(receipt.root, selected.reference);
  for (
    const key of [
      "captureId",
      "recipientSha256",
      "recipientFingerprint",
    ] as const
  ) if (receipt[key] !== envelope.request[key]) fail();
  const name = parseBackupV2ObjectName(receiptReference.object.fileName);
  if (
    name.captureId !== envelope.request.captureId || name.kind !== "receipt" ||
    receipt.configurationSha256 !== envelope.request.sourceConfigSha256 ||
    selected.root.roles.some((role) =>
      role.captureFinishedAtUtc > receipt.verifiedAtUtc
    )
  ) fail();
  // Pi acceptance and VPS verification clocks are not ordered against each other.
  return bounded({
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    resultSha256: hash(r.resultSha256),
    selectedRoot: selected,
    receipt,
    receiptReference,
    acceptedAtUtc,
  });
}
/** Inject the existing validateCatalogEntry function at the controller boundary;
 * type-only legacy imports keep this module outside the controller's runtime graph. */
export function validateBackupRuntimeCatalogEntry(
  value: unknown,
  validateLegacy: (value: unknown) => CatalogEntry,
): BackupRuntimeCatalogEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const tag = value as Record<string, unknown>;
  if (tag.schemaVersion === 2 && tag.format === "backup-v2") {
    return validateBackupV2CatalogEntry(value);
  }
  const r = record(value, ["schemaVersion", "format", "entry"]);
  if (r.schemaVersion !== 1 || r.format !== "backup-v1") fail();
  return {
    schemaVersion: 1,
    format: "backup-v1",
    entry: validateLegacy(r.entry),
  };
}

/** Only transitions within one invocation are comparable. Restarted roles get
 * new attempt journals; a terminal record, especially FAILED, stays immutable. */
export function assertBackupV2StatusTransition(
  previous: BackupV2Status,
  next: BackupV2Status,
): void {
  const a = validateBackupV2Status(previous), b = validateBackupV2Status(next);
  for (
    const key of [
      "envelope",
      "gateId",
      "sourceBootId",
      "custody",
      "kind",
      "startedAtUtc",
    ] as const
  ) equal(a[key], b[key]);
  if (a.finishedAtUtc !== null) {
    equal(a, b);
    return;
  }
  if (b.updatedAtUtc < a.updatedAtUtc) fail();
  const workCounters = [
    "sourceBytes",
    "compressionInputBytes",
    "verifiedChunks",
    "decryptedBytes",
    "inventoryMembers",
  ] as const;
  const advanced = workCounters.some((key) =>
    b.progress[key] > a.progress[key]
  );
  for (
    const key of [
      "observedMonotonicMs",
      "sourceBytes",
      "compressionInputBytes",
      "verifiedChunks",
      "decryptedBytes",
      "inventoryMembers",
    ] as const
  ) if (b.progress[key] < a.progress[key]) fail();
  if (
    !advanced && (b.lease.usefulProgressAtMs > a.lease.usefulProgressAtMs ||
      b.lease.usefulProgressExpiresAtMs > a.lease.usefulProgressExpiresAtMs)
  ) fail();
  if (a.lease.retryEpisode && b.lease.retryEpisode) {
    equal(a.lease.retryEpisode, b.lease.retryEpisode);
  }
  if (
    a.lease.retryEpisode && !b.lease.retryEpisode && !advanced &&
    b.finishedAtUtc === null
  ) fail();
  if (
    !a.lease.retryEpisode && b.lease.retryEpisode &&
    b.lease.retryEpisode.startedAtMs < a.progress.observedMonotonicMs
  ) fail();
}
