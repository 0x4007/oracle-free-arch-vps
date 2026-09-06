/**
 * Backblaze controller gate identity and terminal-proof contract.
 *
 * A gate records one detached B2 source-side unit (worker/verify/prune) that
 * may still be running after SSH loss. While a valid gate exists the Oracle
 * runtime refuses mutations; clearing requires fresh, strictly bound terminal
 * proof that the unit is gone, its job status is terminal, and the source
 * lock is free.
 *
 * This foundation owns identity and terminal-proof schemas plus validation
 * only. Worker/request/phase schemas, acceptance and pruning semantics belong
 * to later controller modules. There is no expiry or TTL validator: an
 * expired gate is still a gate and continues to block Oracle mutation until
 * it is cleared with real terminal proof.
 *
 * This module is pure; its only imports are type-only (erased), so it never
 * depends on the Oracle runtime at execution time and never touches OCI or
 * the filesystem. The structured terminal observation is always produced by
 * an independent observer; validation never claims that a mock or synthetic
 * input proves live state.
 */
import type {
  BackupJournal,
  BackupPair,
  BackupPolicy,
} from "./weekly-backup.ts";
import type { GuestJournal } from "./backup-guest.ts";

export const GATE_OWNER = "backblaze-direct";
export const GATE_REMOTE_HOST = "codex@vps.pavlovcik.com";
export const GATE_SOURCE_LOCK_PATH =
  "/var/tmp/arch-vps-file-backup/source.lock";
export const GATE_DEADLINE_MS = 6 * 3_600_000;
export const UNIT_INVOCATION_PATTERN = /^[0-9a-f]{32}$/;

export type GateState = "active" | "orphaned";
export type OrphanReason =
  | "SOURCE_UNREACHABLE_AT_DEADLINE"
  | "TERMINAL_PROOF_MISSING"
  | "UNIT_IDENTITY_MISMATCH"
  | "STATUS_INVALID";
export type GateClearProofState =
  | "PENDING_VERIFIER"
  | "ACCEPTED"
  | "COMPLETE"
  | "FAILED";
export type GateUnitResult = "success" | "exit-code" | "timeout" | "signal";

/** One immutable detached worker/verify/prune launch identity. */
export interface BackupControllerGate {
  schemaVersion: 1;
  owner: typeof GATE_OWNER;
  state: GateState;
  /** `job-` plus a UUID; the same UUID as `generation`. */
  jobId: string;
  /** YYYY-MM-DD Sunday calendar date; the caller schedules and may resume. */
  periodKey: string;
  /** `generation-` plus the same UUID as `jobId`. */
  generation: string;
  /** SHA-256 of the immutable request body (64 lower-case hex characters). */
  requestSha256: string;
  requestedAtUtc: string;
  /** Exactly requestedAtUtc + 6 hours. */
  deadlineAtUtc: string;
  createdAtUtc: string;
  updatedAtUtc: string;
  remoteHost: typeof GATE_REMOTE_HOST;
  /**
   * Deterministic `arch-vps-b2-<worker|verify|prune>-<generation UUID>.service`.
   */
  unitName: string;
  /** null while unbound; 32 lower-case hex once systemd bound an invocation. */
  unitInvocationId: string | null;
  sourceLockPath: typeof GATE_SOURCE_LOCK_PATH;
  /** Present exactly when state is "orphaned". */
  orphanReason?: OrphanReason;
}

/**
 * Fresh, structured no-process and terminal-status observation bound to one
 * gate. There is deliberately no loose cgroup-empty boolean: the no-process
 * proof is derived only from either an empty control group with an unset task
 * count, or the canonical systemd cgroup for the exact unit with zero tasks.
 */
/**
 * Live production unit deployment decision (document only; nothing here
 * creates, installs or executes a service):
 *
 * - The detached source-side worker/verify/prune units use `Type=exec` with
 *   `RemainAfterExit=yes`, and `RuntimeMaxSec` derived from the remaining
 *   immutable gate deadline. Never use `Type=oneshot`: systemd ignores
 *   `RuntimeMaxSec` for oneshot units.
 * - A probe of a successfully finished unit retains
 *   loaded/active/exited + InvocationID + MainPID0 + ControlPID0 + empty
 *   ControlGroup and an unset TasksCurrent. An unset task count is NEVER
 *   treated as numeric zero, and this module never requires an inactive-only
 *   proof, which would falsely orphan transient units after GC.
 * - Missing units, blank invocation ids and nonterminal statuses are never
 *   terminal proof, and no journal or reboot fallback exists.
 */
export interface GateClearProof {
  checkedAtUtc: string;
  unitName: string;
  unitInvocationId: string;
  unitLoadState: "loaded";
  unitActiveState: "active" | "failed";
  unitSubState: "exited" | "failed";
  unitResult: GateUnitResult;
  mainPid: 0;
  controlPid: 0;
  controlGroup: string;
  tasksCurrent: null | 0;
  statusPath: string;
  statusState: GateClearProofState;
  statusJobId: string;
  statusPeriodKey: string;
  statusGeneration: string;
  statusRequestSha256: string;
  statusInvocationId: string;
  statusUpdatedAtUtc: string;
  statusHeartbeatAtUtc: string;
  statusFinishedAtUtc: string;
  sourceLockPath: typeof GATE_SOURCE_LOCK_PATH;
  sourceLockFree: true;
}

const JOB_ID_PATTERN =
  /^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const CANONICAL_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PERIOD_KEY_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
const UNIT_NAME_PATTERN =
  /^arch-vps-b2-(?:worker|verify|prune)-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.service$/;
export const ORPHAN_REASONS: readonly OrphanReason[] = [
  "SOURCE_UNREACHABLE_AT_DEADLINE",
  "TERMINAL_PROOF_MISSING",
  "UNIT_IDENTITY_MISMATCH",
  "STATUS_INVALID",
];
const STATUS_STATES: readonly GateClearProofState[] = [
  "PENDING_VERIFIER",
  "ACCEPTED",
  "COMPLETE",
  "FAILED",
];
const FAILED_UNIT_RESULTS: readonly GateUnitResult[] = [
  "exit-code",
  "timeout",
  "signal",
];
const GATE_KEYS = new Set([
  "schemaVersion",
  "owner",
  "state",
  "jobId",
  "periodKey",
  "generation",
  "requestSha256",
  "requestedAtUtc",
  "deadlineAtUtc",
  "createdAtUtc",
  "updatedAtUtc",
  "remoteHost",
  "unitName",
  "unitInvocationId",
  "sourceLockPath",
  "orphanReason",
]);
const PROOF_KEYS = new Set([
  "checkedAtUtc",
  "unitName",
  "unitInvocationId",
  "unitLoadState",
  "unitActiveState",
  "unitSubState",
  "unitResult",
  "mainPid",
  "controlPid",
  "controlGroup",
  "tasksCurrent",
  "statusPath",
  "statusState",
  "statusJobId",
  "statusPeriodKey",
  "statusGeneration",
  "statusRequestSha256",
  "statusInvocationId",
  "statusUpdatedAtUtc",
  "statusHeartbeatAtUtc",
  "statusFinishedAtUtc",
  "sourceLockPath",
  "sourceLockFree",
]);
const SOURCE_KEYS = [
  "instanceId",
  "bootVolumeId",
  "rootVolumeId",
  "compartmentId",
  "region",
] as const;
const PAIR_KEYS = ["suffix", "bootId", "rootId"] as const;
const SUFFIX_PATTERN = /^\d{8}T\d{6}Z$/;
const ID_PATTERN = /^[a-f0-9-]{36}$/;
const RECOVERY_STATUSES = ["needed", "running-accepted", "failed"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: Set<string>,
  what: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`${what} contains an unknown key: ${key}`);
    }
  }
}

/** Canonical millisecond ISO UTC string or fail. */
export function canonicalUtcMillis(value: unknown, name: string): number {
  if (
    typeof value !== "string" || !CANONICAL_UTC_PATTERN.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    throw new Error(`${name} must be a canonical millisecond ISO UTC string`);
  }
  return Date.parse(value);
}

export function validateUnitInvocationId(value: unknown): string {
  if (typeof value !== "string" || !UNIT_INVOCATION_PATTERN.test(value)) {
    throw new Error("Unit invocation id must be 32 lower-case hex characters");
  }
  return value;
}

function validatePeriodKey(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("periodKey must be a YYYY-MM-DD Sunday calendar date");
  }
  const match = PERIOD_KEY_PATTERN.exec(value);
  if (!match) {
    throw new Error("periodKey must be a YYYY-MM-DD Sunday calendar date");
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day || date.getUTCDay() !== 0
  ) {
    throw new Error("periodKey must be a valid Sunday calendar date");
  }
  return value;
}

/** Strict validation. Unknown keys and malformed values are always rejected. */
export function validateGate(input: unknown): BackupControllerGate {
  if (!isRecord(input)) {
    throw new Error("Gate must be a JSON object");
  }
  rejectUnknownKeys(input, GATE_KEYS, "Gate");
  if (input.schemaVersion !== 1) {
    throw new Error("Gate schemaVersion must be 1");
  }
  if (input.owner !== GATE_OWNER) {
    throw new Error("Gate owner must be backblaze-direct");
  }
  const state = input.state;
  if (state !== "active" && state !== "orphaned") {
    throw new Error("Gate state must be active or orphaned");
  }
  if (state === "orphaned" && !("orphanReason" in input)) {
    throw new Error("An orphaned gate requires a fixed orphanReason");
  }
  if (state === "active" && "orphanReason" in input) {
    throw new Error("orphanReason is only valid for an orphaned gate");
  }
  const jobId = input.jobId;
  if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) {
    throw new Error("jobId must be job- plus a lower-case UUID");
  }
  const periodKey = validatePeriodKey(input.periodKey);
  const generation = input.generation;
  if (
    typeof generation !== "string" || !GENERATION_PATTERN.test(generation) ||
    generation.slice("generation-".length) !== jobId.slice("job-".length)
  ) {
    throw new Error("generation must be generation- plus the jobId UUID");
  }
  const requestSha256 = input.requestSha256;
  if (
    typeof requestSha256 !== "string" || !SHA256_PATTERN.test(requestSha256)
  ) {
    throw new Error("requestSha256 must be 64 lower-case hex characters");
  }
  const requestedAtUtc = canonicalUtcMillis(
    input.requestedAtUtc,
    "requestedAtUtc",
  );
  const deadlineAtUtc = canonicalUtcMillis(
    input.deadlineAtUtc,
    "deadlineAtUtc",
  );
  if (deadlineAtUtc !== requestedAtUtc + GATE_DEADLINE_MS) {
    throw new Error(
      "deadlineAtUtc must be exactly requestedAtUtc plus 6 hours",
    );
  }
  const createdAtUtc = canonicalUtcMillis(input.createdAtUtc, "createdAtUtc");
  const updatedAtUtc = canonicalUtcMillis(input.updatedAtUtc, "updatedAtUtc");
  if (requestedAtUtc > createdAtUtc || createdAtUtc > updatedAtUtc) {
    throw new Error(
      "Gate timestamps must satisfy requested <= created <= updated",
    );
  }
  if (input.remoteHost !== GATE_REMOTE_HOST) {
    throw new Error("Gate remoteHost must be codex@vps.pavlovcik.com");
  }
  const unitName = input.unitName;
  const unitMatch = typeof unitName === "string"
    ? UNIT_NAME_PATTERN.exec(unitName)
    : null;
  if (
    !unitMatch ||
    unitMatch[1] !== generation.slice("generation-".length)
  ) {
    throw new Error(
      "unitName must be arch-vps-b2-worker|verify|prune-<generation UUID>.service",
    );
  }
  let orphanReason: OrphanReason | undefined;
  if (state === "orphaned") {
    const value = input.orphanReason;
    if (
      typeof value !== "string" ||
      !(ORPHAN_REASONS as readonly string[]).includes(value)
    ) {
      throw new Error("orphaned gate requires a fixed orphanReason");
    }
    orphanReason = value as OrphanReason;
  }
  const unitInvocationId = input.unitInvocationId === null
    ? null
    : validateUnitInvocationId(input.unitInvocationId);
  if (input.sourceLockPath !== GATE_SOURCE_LOCK_PATH) {
    throw new Error("Gate sourceLockPath must be the fixed source lock path");
  }
  return {
    schemaVersion: 1,
    owner: GATE_OWNER,
    state,
    jobId: jobId as string,
    periodKey,
    generation: generation as string,
    requestSha256,
    requestedAtUtc: input.requestedAtUtc as string,
    deadlineAtUtc: input.deadlineAtUtc as string,
    createdAtUtc: input.createdAtUtc as string,
    updatedAtUtc: input.updatedAtUtc as string,
    remoteHost: GATE_REMOTE_HOST,
    unitName: unitName as string,
    unitInvocationId,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    ...(orphanReason ? { orphanReason } : {}),
  };
}

/** Canonical identity equality; both sides are strictly validated. */
export function gateIdentityEqual(
  expected: unknown,
  current: unknown,
): boolean {
  return JSON.stringify(validateGate(expected)) ===
    JSON.stringify(validateGate(current));
}

/**
 * Strict terminal-proof validation bound to one gate. The success terminal
 * proof requires a bound invocation, zero PIDs, no process above (empty
 * control group with unset tasks, or the canonical unit cgroup with zero
 * tasks), and a terminal status state. Failed systemd proof requires the
 * failed/failed unit with exit-code|timeout|signal and FAILED status.
 * PENDING_VERIFIER clears only because the worker process is gone; this
 * proof never accepts or prunes a restore point.
 */
export function validateGateClearProof(
  input: unknown,
  gate: BackupControllerGate,
  now: Date = new Date(),
): GateClearProof {
  const bound = validateGate(gate);
  if (!isRecord(input)) {
    throw new Error("Gate clear proof must be a JSON object");
  }
  rejectUnknownKeys(input, PROOF_KEYS, "Gate clear proof");
  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs)) {
    throw new Error("Clear proof comparison time is invalid");
  }
  const checkedAtUtc = canonicalUtcMillis(input.checkedAtUtc, "checkedAtUtc");
  if (checkedAtUtc > nowMs || nowMs - checkedAtUtc > 30_000) {
    throw new Error("Gate clear proof is stale or was checked in the future");
  }
  const unitName = input.unitName;
  if (unitName !== bound.unitName) {
    throw new Error(
      "Clear proof unit does not match the gate unit (a missing unit is never terminal proof)",
    );
  }
  const unitInvocationId = validateUnitInvocationId(input.unitInvocationId);
  if (bound.unitInvocationId === null) {
    throw new Error(
      "Gate has no bound unit invocation; a blank invocation is never terminal proof",
    );
  }
  if (unitInvocationId !== bound.unitInvocationId) {
    throw new Error(
      "Clear proof invocation does not match the gate invocation",
    );
  }
  if (input.unitLoadState !== "loaded") {
    throw new Error(
      "Clear proof unit must be loaded (a missing unit is never terminal proof)",
    );
  }
  const unitActiveState = input.unitActiveState;
  if (unitActiveState !== "active" && unitActiveState !== "failed") {
    throw new Error("Clear proof unitActiveState must be active or failed");
  }
  const unitSubState = input.unitSubState;
  if (unitSubState !== "exited" && unitSubState !== "failed") {
    throw new Error("Clear proof unitSubState must be exited or failed");
  }
  const unitResult = input.unitResult;
  if (
    unitResult !== "success" && unitResult !== "exit-code" &&
    unitResult !== "timeout" && unitResult !== "signal"
  ) {
    throw new Error("Clear proof unitResult is unsupported");
  }
  if (input.mainPid !== 0 || input.controlPid !== 0) {
    throw new Error(
      "Clear proof requires both main and control PIDs to be zero",
    );
  }
  const controlGroup = input.controlGroup;
  const tasksCurrent = input.tasksCurrent;
  if (
    typeof controlGroup !== "string" ||
    (tasksCurrent !== null && tasksCurrent !== 0)
  ) {
    throw new Error("Clear proof control group or task count is malformed");
  }
  const canonicalGroup = `/system.slice/${bound.unitName}`;
  const noProcessesBelow = (controlGroup === "" && tasksCurrent === null) ||
    (controlGroup === canonicalGroup && tasksCurrent === 0);
  if (!noProcessesBelow) {
    throw new Error(
      "No-process proof requires an empty control group with unset tasks or the canonical unit cgroup with zero tasks",
    );
  }
  if (
    input.statusPath !==
      `/var/tmp/arch-vps-file-backup/jobs/${bound.jobId}/status.json`
  ) {
    throw new Error(
      "Clear proof status path does not bind the gate job identity",
    );
  }
  const statusState = input.statusState;
  if (!(STATUS_STATES as readonly string[]).includes(String(statusState))) {
    throw new Error("Clear proof statusState is not terminal");
  }
  if (
    input.statusJobId !== bound.jobId ||
    input.statusPeriodKey !== bound.periodKey ||
    input.statusGeneration !== bound.generation ||
    input.statusRequestSha256 !== bound.requestSha256 ||
    input.statusInvocationId !== bound.unitInvocationId
  ) {
    throw new Error("Clear proof status identity does not match the gate");
  }
  const statusUpdatedAtUtc = canonicalUtcMillis(
    input.statusUpdatedAtUtc,
    "statusUpdatedAtUtc",
  );
  const statusHeartbeatAtUtc = canonicalUtcMillis(
    input.statusHeartbeatAtUtc,
    "statusHeartbeatAtUtc",
  );
  const statusFinishedAtUtc = canonicalUtcMillis(
    input.statusFinishedAtUtc,
    "statusFinishedAtUtc",
  );
  const requested = Date.parse(bound.requestedAtUtc);
  if (
    statusFinishedAtUtc < requested || statusFinishedAtUtc > checkedAtUtc ||
    statusHeartbeatAtUtc < requested || statusHeartbeatAtUtc > checkedAtUtc ||
    statusUpdatedAtUtc < requested || statusUpdatedAtUtc > checkedAtUtc ||
    statusUpdatedAtUtc < statusFinishedAtUtc ||
    statusHeartbeatAtUtc > statusUpdatedAtUtc
  ) {
    throw new Error(
      "Clear proof status timestamps are inconsistent with the gate window",
    );
  }
  if (input.sourceLockPath !== GATE_SOURCE_LOCK_PATH) {
    throw new Error("Clear proof sourceLockPath must be the fixed lock path");
  }
  if (input.sourceLockFree !== true) {
    throw new Error("Clear proof requires the source lock to be free");
  }
  const successTerminal = unitResult === "success" &&
    unitActiveState === "active" &&
    unitSubState === "exited";
  const failedTerminal = unitResult !== "success" &&
    unitActiveState === "failed" &&
    unitSubState === "failed" &&
    statusState === "FAILED" &&
    (FAILED_UNIT_RESULTS as readonly string[]).includes(
      String(unitResult),
    );
  if (!successTerminal && !failedTerminal) {
    throw new Error(
      "Terminal proof mismatch: running, nonterminal or unproven states are never proof",
    );
  }
  return {
    checkedAtUtc: input.checkedAtUtc as string,
    unitName: unitName as string,
    unitInvocationId,
    unitLoadState: "loaded",
    unitActiveState: unitActiveState as "active" | "failed",
    unitSubState: unitSubState as "exited" | "failed",
    unitResult: unitResult as GateUnitResult,
    mainPid: 0,
    controlPid: 0,
    controlGroup,
    tasksCurrent: tasksCurrent as null | 0,
    statusPath: input.statusPath as string,
    statusState: statusState as GateClearProofState,
    statusJobId: input.statusJobId as string,
    statusPeriodKey: input.statusPeriodKey as string,
    statusGeneration: input.statusGeneration as string,
    statusRequestSha256: input.statusRequestSha256 as string,
    statusInvocationId: unitInvocationId,
    statusUpdatedAtUtc: input.statusUpdatedAtUtc as string,
    statusHeartbeatAtUtc: input.statusHeartbeatAtUtc as string,
    statusFinishedAtUtc: input.statusFinishedAtUtc as string,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    sourceLockFree: true,
  };
}

/**
 * Oracle mutation guard. Absence (null/undefined) alone permits; any other
 * value is strictly validated and a valid active or orphaned gate rejects
 * Oracle mutation. Malformed or unknown gate values fail closed by throwing
 * rather than being treated as absence.
 */
export function assertOracleMutationAllowed(gate: unknown): void {
  if (gate === null || gate === undefined) return;
  const validated = validateGate(gate);
  throw new Error(
    `Oracle mutation is blocked by the Backblaze controller gate (state=${validated.state}); reconcile the gate first`,
  );
}

function nonEmptyString(value: unknown, name: string): string {
  if (typeof value !== "string" || value === "") {
    throw new Error(`Oracle state ${name} must be a non-empty string`);
  }
  return value;
}

function sameSource(
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): boolean {
  return SOURCE_KEYS.every((key) => a[key] === b[key]);
}

function validateSourceRecord(value: unknown, name: string): void {
  if (!isRecord(value)) {
    throw new Error(`Oracle state ${name} must be a source binding`);
  }
  for (const key of SOURCE_KEYS) nonEmptyString(value[key], `${name}.${key}`);
}

function validatePairRecord(
  value: unknown,
  name: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`Oracle state ${name} must be a backup pair`);
  }
  for (const key of PAIR_KEYS) nonEmptyString(value[key], `${name}.${key}`);
  const suffix = value.suffix;
  if (
    typeof suffix !== "string" || !SUFFIX_PATTERN.test(suffix) ||
    value.bootId === value.rootId
  ) {
    throw new Error(`Oracle state ${name} is malformed`);
  }
  return value;
}

function validateStandingApprovalRecord(value: unknown): void {
  if (!isRecord(value)) {
    throw new Error("Oracle state policy.standingApproval must be an object");
  }
  const approvedAt = typeof value.approvedAtUtc === "string"
    ? Date.parse(value.approvedAtUtc)
    : NaN;
  if (!Number.isFinite(approvedAt)) {
    throw new Error("Oracle standing approval timestamp is invalid");
  }
  if (approvedAt > Date.now()) {
    throw new Error("Oracle standing approval is in the future");
  }
  if (value.exactOperation !== "weekly paired backup rotation") {
    throw new Error("Oracle standing approval operation is unsupported");
  }
  validateSourceRecord(value.source, "policy.standingApproval.source");
}

/** Validates the existing BackupPolicy shape; never mutates the input. */
function validatePolicyRecord(value: unknown): BackupPolicy {
  if (!isRecord(value)) {
    throw new Error("Oracle state policy must be an object");
  }
  validateSourceRecord(value.source, "policy.source");
  validateStandingApprovalRecord(value.standingApproval);
  const standing = value.standingApproval as Record<string, unknown>;
  const source = value.source as Record<string, unknown>;
  if (
    !sameSource(standing.source as Record<string, unknown>, source)
  ) {
    throw new Error("Oracle standing approval does not bind the exact source");
  }
  validatePairRecord(value.acceptedPair, "policy.acceptedPair");
  if (
    typeof value.retainPreviousPair !== "boolean" ||
    typeof value.allowFifthSlot !== "boolean"
  ) {
    throw new Error("Oracle policy booleans are malformed");
  }
  return value as unknown as BackupPolicy;
}

/**
 * Validates the existing BackupJournal shape against the selected source and
 * the recorded accepted pair; never mutates the input.
 */
function validateCycleRecord(
  value: unknown,
  expectedSource: Record<string, unknown>,
  acceptedPair: BackupPair,
): BackupJournal {
  if (!isRecord(value)) {
    throw new Error("Oracle state cycle must be a journal object");
  }
  validateSourceRecord(value.source, "cycle.source");
  if (!sameSource(value.source as Record<string, unknown>, expectedSource)) {
    throw new Error("Oracle journal source does not match the selected source");
  }
  const previous = validatePairRecord(value.previousPair, "cycle.previousPair");
  if (
    previous.suffix !== acceptedPair.suffix ||
    previous.bootId !== acceptedPair.bootId ||
    previous.rootId !== acceptedPair.rootId
  ) {
    throw new Error("Oracle journal previous pair does not match the policy");
  }
  const suffix = value.suffix;
  if (typeof suffix !== "string" || !SUFFIX_PATTERN.test(suffix)) {
    throw new Error("Oracle journal suffix is malformed");
  }
  if (suffix === previous.suffix) {
    throw new Error(
      "Oracle journal suffix must differ from the previous pair suffix",
    );
  }
  if (value.phase !== "complete") {
    throw new Error(
      "Oracle backup cycle is not complete; Backblaze launch is refused",
    );
  }
  const createdAt = canonicalUtcMillis(
    value.createdAtUtc,
    "cycle.createdAtUtc",
  );
  const updatedAt = canonicalUtcMillis(
    value.updatedAtUtc,
    "cycle.updatedAtUtc",
  );
  const sourceAcceptedAt = canonicalUtcMillis(
    value.sourceAcceptedAtUtc,
    "cycle.sourceAcceptedAtUtc",
  );
  if (
    createdAt > updatedAt || sourceAcceptedAt < createdAt ||
    sourceAcceptedAt > updatedAt || sourceAcceptedAt > Date.now()
  ) {
    throw new Error("Oracle journal timestamps are inconsistent");
  }
  if (value.recoveryStatus !== undefined) {
    if (
      typeof value.recoveryStatus !== "string" ||
      !(RECOVERY_STATUSES as readonly string[]).includes(value.recoveryStatus)
    ) {
      throw new Error("Oracle journal recoveryStatus is unsupported");
    }
    if (
      value.recoveryStatus === "needed" || value.recoveryStatus === "failed"
    ) {
      throw new Error(
        "Oracle journal requires source recovery; Backblaze launch is refused",
      );
    }
  }
  return value as unknown as BackupJournal;
}

/** Validates the existing GuestJournal shape; never mutates the input. */
function validateGuestRecord(value: unknown): GuestJournal {
  if (!isRecord(value)) {
    throw new Error("Oracle state guest record is malformed");
  }
  if (value.restored !== true) {
    throw new Error(
      "Oracle guest is not restored; Backblaze launch is refused",
    );
  }
  for (const key of ["rootUuid", "stagingUuid"] as const) {
    const id = value[key];
    if (typeof id !== "string" || !ID_PATTERN.test(id)) {
      throw new Error(`Oracle guest ${key} is malformed`);
    }
  }
  const containers = value.containers;
  if (!Array.isArray(containers)) {
    throw new Error("Oracle guest containers must be an array");
  }
  for (const entry of containers) {
    if (!isRecord(entry)) {
      throw new Error("Oracle guest container entry is malformed");
    }
    nonEmptyString(entry.id, "guest.container.id");
    nonEmptyString(entry.name, "guest.container.name");
    if (
      typeof entry.running !== "boolean" ||
      (entry.stopIntent !== undefined && typeof entry.stopIntent !== "boolean")
    ) {
      throw new Error("Oracle guest container entry is malformed");
    }
  }
  const units = value.units;
  if (!Array.isArray(units)) {
    throw new Error("Oracle guest units must be an array");
  }
  for (const entry of units) {
    if (!isRecord(entry)) {
      throw new Error("Oracle guest unit entry is malformed");
    }
    nonEmptyString(entry.name, "guest.unit.name");
    if (
      typeof entry.active !== "boolean" ||
      (entry.stopIntent !== undefined && typeof entry.stopIntent !== "boolean")
    ) {
      throw new Error("Oracle guest unit entry is malformed");
    }
  }
  return value as unknown as GuestJournal;
}

function validateScheduledClaim(value: unknown): void {
  if (!isRecord(value)) {
    throw new Error("Scheduled backup claim is malformed");
  }
  const status = value.status;
  if (status === "started") {
    throw new Error(
      "Scheduled backup claim is already started; refuse a second remote launch",
    );
  }
  if (status !== "complete" && status !== "failed") {
    throw new Error("Scheduled backup claim has an unknown status");
  }
  nonEmptyString(value.windowId, "scheduledClaim.windowId");
  canonicalUtcMillis(value.updatedAtUtc, "scheduledClaim.updatedAtUtc");
  if (value.previousCycleSuffix !== undefined) {
    const suffix = value.previousCycleSuffix;
    if (typeof suffix !== "string" || !SUFFIX_PATTERN.test(suffix)) {
      throw new Error("scheduledClaim.previousCycleSuffix is malformed");
    }
  }
}

/**
 * Pure launch preflight for the later Pi controller. Fails closed on absent
 * or malformed Oracle state, any cycle that is not complete, an unrecovered
 * source, a guest present without restored=true, or a scheduled claim that
 * is started or unknown. A missing claim and a completed/failed claim are
 * permitted. The caller holds the shared controller lock and then creates a
 * fresh gate before any remote launch. This never invents OCI identifiers,
 * mutates state, or issues new OCI queries.
 */
export function assertBackblazeLaunchAllowed(
  oracleState: unknown,
  scheduledClaim: unknown,
): void {
  if (!isRecord(oracleState)) {
    throw new Error("Oracle state is absent or malformed");
  }
  const policy = validatePolicyRecord(oracleState.policy);
  const acceptedPair = policy.acceptedPair;
  // The journal source is bound to the validated policy source, never to
  // itself; the policy source is the single selected source identity.
  const source = policy.source as unknown as Record<string, unknown>;
  validateCycleRecord(oracleState.cycle, source, acceptedPair);
  if (oracleState.guest === null) {
    throw new Error(
      "Oracle guest is explicitly null; only absence (undefined) permits",
    );
  }
  if (oracleState.guest !== undefined) {
    validateGuestRecord(oracleState.guest);
  }
  if (scheduledClaim !== undefined && scheduledClaim !== null) {
    validateScheduledClaim(scheduledClaim);
  }
}
