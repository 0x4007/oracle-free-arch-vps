/**
 * m07-source-worker: detached source-side worker for the encrypted
 * Backblaze file backup.
 *
 * One unit invocation runs one immutable job: validate the request envelope,
 * bind the deployed source configuration, hold the source lock for input and
 * stage checks, every phase, every write and the terminal status, then drive
 * capture -> upload -> publish to a PENDING_VERIFIER terminal. The worker
 * never accepts or prunes a restore point, never decrypts, never shuts down
 * the source, never signals processes (RuntimeMaxSec belongs to the external
 * Type=exec + RemainAfterExit=yes unit) and contains no CLI entry point.
 *
 * Identity model (all immutable and public):
 *
 * - The request body is the canonical public WorkerRequest. The envelope is
 *   {request, requestSha256} where requestSha256 covers UTF-8
 *   JSON.stringify of the validated request in REQUEST_PROPERTY_ORDER,
 *   excluding requestSha256 itself. The persisted request.json is exactly
 *   those canonical bytes, so a resume requires byte equality.
 * - The deployed source configuration is hashed over the canonical
 *   {sources, exclusionsText} object: six sources in ROLE_ORDER, each with
 *   the fixed {name, uuid, filesystem, size, livePath?} key order.
 * - The worker derives the m06-style active unbound gate identity from the
 *   request (fixed remoteHost, fixed source lock path and deterministic
 *   arch-vps-b2-worker-<generation uuid>.service unit name) and validates it
 *   through the reviewed m06 validator; the supplied systemd invocation id
 *   is separately validated with the m06 unit-invocation rule.
 *
 * Status rules:
 *
 * - Every status write goes through one serialized queue; one in-flight
 *   write at a time. Heartbeats are queued by a 30 s timer that is stopped
 *   and drained in finally. A heartbeat derives its state when it executes
 *   (the last committed phase write), never when it is queued, and heartbeat
 *   tasks that have not started once the terminal write is queued are
 *   skipped, so no heartbeat can overwrite a terminal status with a stale
 *   phase.
 * - A rejected write stays rejected for its caller, but the internal queue
 *   chain recovers, so a failed heartbeat/phase/final-result write never
 *   poisons the FAILED terminal that must follow.
 * - startedAtUtc is preserved from the first write; all timestamps are
 *   monotonic and never precede the request; heartbeatAtUtc never exceeds
 *   updatedAtUtc.
 * - Phase result files are persisted before the state that claims their
 *   phase, and the final jobs/<jobId>/result.json is persisted before the
 *   PENDING_VERIFIER status; resultSha256 hashes exactly those persisted
 *   bytes.
 * - FAILED status stays writable after the deadline; the deadline only gates
 *   phase starts and the next phase.
 *
 * Bounded upload/publish retries: the whole existing uploader/publisher
 * module call (journal and ambiguous-put reconciliation included) is retried
 * at most three times with 30 minute spacing, heartbeat live, inside one
 * invocation and never past the deadline. Only exact B2 operation transport
 * failures are retried; identity/corruption/filesystem/scope/other 4xx
 * errors fail immediately.
 *
 * Error surface: rejected inputs and incoherent saved state throw
 * SourceWorker rejected (CODE) without writing any status; failures during a
 * phase end in a FAILED status whose errorCode is one fixed phase code. Raw
 * underlying messages are retained only as the error cause and never reach a
 * status file or standard output.
 *
 * Persistence: the base directory (fixed /var/tmp/arch-vps-file-backup in
 * production) must be an owner-only 0700 real directory; jobs/<jobId> is
 * created 0700, all job JSON files are regular 0600 owner files, the stage
 * is the fixed base/<generation> and every read/write re-verifies real
 * directory or file identity. No symlink is ever followed and no file with a
 * foreign owner or mode is replaced. No generalized filesystem library is
 * created; this file contains only the worker-local guards.
 */
import { createHash } from "node:crypto";
import type {
  CaptureResult,
  CaptureSettings,
  FileSource,
} from "./backblaze-capture.ts";
import {
  captureGeneration,
  ROLE_ORDER,
  validateCaptureSettings,
} from "./backblaze-capture.ts";
import type {
  IndexRecipient,
  IndexStore,
  PublishedIndex,
} from "./backblaze-index.ts";
import { buildRecoveryIndex, publishRecoveryIndex } from "./backblaze-index.ts";
import type { UploadResult, UploadStore } from "./backblaze-upload.ts";
import {
  uploadCapturedGeneration,
  validateUploadCapture,
} from "./backblaze-upload.ts";
import {
  type BackupControllerGate,
  canonicalUtcMillis,
  GATE_DEADLINE_MS,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
  validateGate,
  validateUnitInvocationId,
} from "./backblaze-controller-contract.ts";
import { DIRECT_PREFIX } from "./backblaze-storage.ts";
import { withBackupLock } from "./backup-lock.ts";

// ---------------------------------------------------------------------------
// Canonical identities
// ---------------------------------------------------------------------------

export const WORKER_DEADLINE_MS = GATE_DEADLINE_MS;
export const PRODUCTION_BASE_PATH = "/var/tmp/arch-vps-file-backup";
export const HEARTBEAT_INTERVAL_MS = 30_000;
/** Bounded retries of one upload/publish module call: 3 attempts total. */
export const MAX_PHASE_ATTEMPTS = 3;
/** Fixed spacing between bounded retries. */
export const RETRY_SPACING_MS = 30 * 60_000;

export const CAPTURE_RESULT_FILE = "capture-result.json";
export const UPLOAD_RESULT_FILE = "upload-result.json";
export const INDEX_RESULT_FILE = "index-result.json";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_STATUS_BYTES = 64 * 1024;
const MAX_RESULT_BYTES = 8 * 1024 * 1024;
const MAX_STAGE_RESULT_BYTES = 8 * 1024 * 1024;
const MAX_RECIPIENT_BYTES = 64 * 1024;

const JOB_ID_PATTERN =
  /^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/;
const PERIOD_KEY_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
const ABSOLUTE_PATH_PATTERN = /^\/[A-Za-z0-9/_.-]+$/;

/** Documented exact property order of the canonical request serialization. */
export const REQUEST_PROPERTY_ORDER: readonly (keyof WorkerRequest)[] = [
  "schemaVersion",
  "jobId",
  "periodKey",
  "generation",
  "requestedAtUtc",
  "deadlineAtUtc",
  "recipientSha256",
  "recipientFingerprint",
  "sourceRevision",
  "sourceConfigSha256",
];

const REQUEST_KEYS = new Set<string>(REQUEST_PROPERTY_ORDER);
const ENVELOPE_KEYS = new Set(["request", "requestSha256"]);

export type WorkerState =
  | "REQUESTED"
  | "CAPTURING"
  | "CAPTURED"
  | "UPLOADING"
  | "UPLOAD_VERIFIED"
  | "INDEXING"
  | "PENDING_VERIFIER"
  | "FAILED";

export const WORKER_STATES: readonly WorkerState[] = [
  "REQUESTED",
  "CAPTURING",
  "CAPTURED",
  "UPLOADING",
  "UPLOAD_VERIFIED",
  "INDEXING",
  "PENDING_VERIFIER",
  "FAILED",
];

/** Fixed error codes recorded in a FAILED status; raw detail is never copied
 * into a status file or standard output. */
export type WorkerErrorCode =
  | "DEADLINE_EXCEEDED"
  | "CAPTURE_FAILED"
  | "CAPTURE_RESULT_INVALID"
  | "UPLOAD_FAILED"
  | "UPLOAD_RESULT_INVALID"
  | "INDEX_FAILED"
  | "INDEX_RESULT_INVALID"
  | "RESULT_FAILED"
  | "STATUS_FAILED";

export const WORKER_ERROR_CODES: readonly WorkerErrorCode[] = [
  "DEADLINE_EXCEEDED",
  "CAPTURE_FAILED",
  "CAPTURE_RESULT_INVALID",
  "UPLOAD_FAILED",
  "UPLOAD_RESULT_INVALID",
  "INDEX_FAILED",
  "INDEX_RESULT_INVALID",
  "RESULT_FAILED",
  "STATUS_FAILED",
];

/** Fixed rejection codes for inputs or saved state refused before any work. */
export type WorkerRejectionCode =
  | "INVALID_REQUEST"
  | "INVALID_REQUEST_HASH"
  | "REQUEST_MISMATCH"
  | "GENERATION_MISMATCH"
  | "CONFIG_MISMATCH"
  | "RECIPIENT_MISMATCH"
  | "REVISION_MISMATCH"
  | "INVALID_INVOCATION"
  | "INVOCATION_MISMATCH"
  | "INVALID_STATUS"
  | "BASE_PATH_INVALID"
  | "JOBS_PATH_INVALID";

export const WORKER_REJECTION_CODES: readonly WorkerRejectionCode[] = [
  "INVALID_REQUEST",
  "INVALID_REQUEST_HASH",
  "REQUEST_MISMATCH",
  "GENERATION_MISMATCH",
  "CONFIG_MISMATCH",
  "RECIPIENT_MISMATCH",
  "REVISION_MISMATCH",
  "INVALID_INVOCATION",
  "INVOCATION_MISMATCH",
  "INVALID_STATUS",
  "BASE_PATH_INVALID",
  "JOBS_PATH_INVALID",
];

/** Canonical immutable public request for one Sunday-period source job. */
export interface WorkerRequest {
  schemaVersion: 1;
  jobId: string;
  /** YYYY-MM-DD Sunday calendar date of the scheduled week. */
  periodKey: string;
  generation: string;
  requestedAtUtc: string;
  /** Exactly requestedAtUtc + 6 hours. */
  deadlineAtUtc: string;
  recipientSha256: string;
  recipientFingerprint: string;
  /** Exact deployed reviewed source Git revision (40 lower-case hex). */
  sourceRevision: string;
  /** Canonical source configuration hash (64 lower-case hex). */
  sourceConfigSha256: string;
}

/** Request envelope: the request plus its own canonical SHA-256. */
export interface WorkerRequestEnvelope {
  request: WorkerRequest;
  requestSha256: string;
}

export interface WorkerStatus {
  schemaVersion: 1;
  jobId: string;
  periodKey: string;
  generation: string;
  requestSha256: string;
  requestedAtUtc: string;
  deadlineAtUtc: string;
  invocationId: string;
  state: WorkerState;
  startedAtUtc: string;
  updatedAtUtc: string;
  heartbeatAtUtc: string;
  /** null until terminal; then the terminal timestamp. */
  finishedAtUtc: string | null;
  /** Present only on FAILED. */
  errorCode?: WorkerErrorCode;
  /** SHA-256 of the persisted result.json bytes; present only on PENDING_VERIFIER. */
  resultSha256?: string;
}

/** Final durable job result: request envelope plus the three phase results. */
export interface WorkerJobResult {
  envelope: WorkerRequestEnvelope;
  capture: CaptureResult;
  upload: UploadResult;
  publishedIndex: PublishedIndex;
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

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

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
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

// ---------------------------------------------------------------------------
// Request validation and canonical hashing
// ---------------------------------------------------------------------------

export function validateRequest(input: unknown): WorkerRequest {
  if (!isRecord(input)) {
    throw new Error("Request must be a JSON object");
  }
  rejectUnknownKeys(input, REQUEST_KEYS, "Request");
  if (input.schemaVersion !== 1) {
    throw new Error("Request schemaVersion must be 1");
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
  const requestedAtUtc = canonicalUtcMillis(
    input.requestedAtUtc,
    "requestedAtUtc",
  );
  const deadlineAtUtc = canonicalUtcMillis(
    input.deadlineAtUtc,
    "deadlineAtUtc",
  );
  if (deadlineAtUtc !== requestedAtUtc + WORKER_DEADLINE_MS) {
    throw new Error(
      "deadlineAtUtc must be exactly requestedAtUtc plus 6 hours",
    );
  }
  const recipientSha256 = input.recipientSha256;
  if (
    typeof recipientSha256 !== "string" ||
    !SHA256_PATTERN.test(recipientSha256)
  ) {
    throw new Error("recipientSha256 must be 64 lower-case hex characters");
  }
  const recipientFingerprint = input.recipientFingerprint;
  if (
    typeof recipientFingerprint !== "string" ||
    !FINGERPRINT_PATTERN.test(recipientFingerprint)
  ) {
    throw new Error(
      "recipientFingerprint must be 40 uppercase hex characters",
    );
  }
  const sourceRevision = input.sourceRevision;
  if (
    typeof sourceRevision !== "string" ||
    !REVISION_PATTERN.test(sourceRevision)
  ) {
    throw new Error("sourceRevision must be 40 lower-case hex characters");
  }
  const sourceConfigSha256 = input.sourceConfigSha256;
  if (
    typeof sourceConfigSha256 !== "string" ||
    !SHA256_PATTERN.test(sourceConfigSha256)
  ) {
    throw new Error("sourceConfigSha256 must be 64 lower-case hex characters");
  }
  return {
    schemaVersion: 1,
    jobId: jobId as string,
    periodKey,
    generation: generation as string,
    requestedAtUtc: input.requestedAtUtc as string,
    deadlineAtUtc: input.deadlineAtUtc as string,
    recipientSha256,
    recipientFingerprint,
    sourceRevision,
    sourceConfigSha256,
  };
}

/** Canonical request text in the documented exact property order. */
export function canonicalRequestString(request: WorkerRequest): string {
  const value = validateRequest(request);
  const ordered: Record<string, unknown> = {};
  for (const key of REQUEST_PROPERTY_ORDER) ordered[key] = value[key];
  return JSON.stringify(ordered);
}

export function requestSha256Of(request: WorkerRequest): string {
  return sha256Hex(
    new TextEncoder().encode(canonicalRequestString(request)),
  );
}

export function validateRequestEnvelope(
  input: unknown,
): WorkerRequestEnvelope {
  if (!isRecord(input)) {
    throw new Error("Request envelope must be a JSON object");
  }
  rejectUnknownKeys(input, ENVELOPE_KEYS, "Envelope");
  const request = validateRequest(input.request);
  const requestSha256 = input.requestSha256;
  if (
    typeof requestSha256 !== "string" || !SHA256_PATTERN.test(requestSha256)
  ) {
    throw new Error("requestSha256 must be 64 lower-case hex characters");
  }
  const computed = requestSha256Of(request);
  if (requestSha256 !== computed) {
    throw new Error(
      "requestSha256 does not match the canonical request bytes",
    );
  }
  return { request, requestSha256 };
}

// ---------------------------------------------------------------------------
// Canonical source configuration hash
// ---------------------------------------------------------------------------

/**
 * Canonical serialization of the deployed source configuration over
 * {sources, exclusionsText}: exactly six sources in ROLE_ORDER with the
 * fixed {name, uuid, filesystem, size, livePath?} key order.
 */
export function canonicalSourceConfig(settings: CaptureSettings): string {
  validateCaptureSettings(settings);
  const byName = new Map<string, FileSource>();
  for (const source of settings.sources) byName.set(source.name, source);
  const sources: Record<string, unknown>[] = [];
  for (const role of ROLE_ORDER) {
    const source = byName.get(role);
    if (source === undefined) {
      throw new Error("Source configuration is missing a canonical role");
    }
    const entry: Record<string, unknown> = {};
    entry["name"] = source.name;
    entry["uuid"] = source.uuid;
    entry["filesystem"] = source.filesystem;
    entry["size"] = source.size;
    if (source.livePath !== undefined) entry["livePath"] = source.livePath;
    sources.push(entry);
  }
  const ordered: Record<string, unknown> = {};
  ordered["sources"] = sources;
  ordered["exclusionsText"] = settings.exclusionsText;
  return JSON.stringify(ordered);
}

export function sourceConfigSha256(settings: CaptureSettings): string {
  return sha256Hex(
    new TextEncoder().encode(canonicalSourceConfig(settings)),
  );
}

// ---------------------------------------------------------------------------
// Status validation
// ---------------------------------------------------------------------------

const STATUS_KEYS = new Set([
  "schemaVersion",
  "jobId",
  "periodKey",
  "generation",
  "requestSha256",
  "requestedAtUtc",
  "deadlineAtUtc",
  "invocationId",
  "state",
  "startedAtUtc",
  "updatedAtUtc",
  "heartbeatAtUtc",
  "finishedAtUtc",
  "errorCode",
  "resultSha256",
]);

const TERMINAL_STATES = new Set<WorkerState>([
  "PENDING_VERIFIER",
  "FAILED",
]);

export function validateStatus(input: unknown): WorkerStatus {
  if (!isRecord(input)) {
    throw new Error("Status must be a JSON object");
  }
  rejectUnknownKeys(input, STATUS_KEYS, "Status");
  if (input.schemaVersion !== 1) {
    throw new Error("Status schemaVersion must be 1");
  }
  const jobId = input.jobId;
  if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) {
    throw new Error("Status jobId must be job- plus a lower-case UUID");
  }
  const periodKey = validatePeriodKey(input.periodKey);
  const generation = input.generation;
  if (
    typeof generation !== "string" || !GENERATION_PATTERN.test(generation) ||
    generation.slice("generation-".length) !== jobId.slice("job-".length)
  ) {
    throw new Error(
      "Status generation must be generation- plus the jobId UUID",
    );
  }
  const requestSha256 = input.requestSha256;
  if (
    typeof requestSha256 !== "string" || !SHA256_PATTERN.test(requestSha256)
  ) {
    throw new Error(
      "Status requestSha256 must be 64 lower-case hex characters",
    );
  }
  const requestedAtUtc = canonicalUtcMillis(
    input.requestedAtUtc,
    "requestedAtUtc",
  );
  const deadlineAtUtc = canonicalUtcMillis(
    input.deadlineAtUtc,
    "deadlineAtUtc",
  );
  if (deadlineAtUtc !== requestedAtUtc + WORKER_DEADLINE_MS) {
    throw new Error(
      "Status deadlineAtUtc must be exactly requestedAtUtc plus 6 hours",
    );
  }
  const invocationId = validateUnitInvocationId(input.invocationId);
  const state = input.state;
  if (!(WORKER_STATES as readonly string[]).includes(String(state))) {
    throw new Error("Status state is unsupported");
  }
  const startedAtUtc = canonicalUtcMillis(input.startedAtUtc, "startedAtUtc");
  const updatedAtUtc = canonicalUtcMillis(input.updatedAtUtc, "updatedAtUtc");
  const heartbeatAtUtc = canonicalUtcMillis(
    input.heartbeatAtUtc,
    "heartbeatAtUtc",
  );
  if (
    startedAtUtc < requestedAtUtc || heartbeatAtUtc < startedAtUtc ||
    updatedAtUtc < heartbeatAtUtc || updatedAtUtc < requestedAtUtc
  ) {
    throw new Error(
      "Status timestamps are not monotonic or precede the request",
    );
  }
  const terminal = TERMINAL_STATES.has(state as WorkerState);
  if (terminal && input.finishedAtUtc === null) {
    throw new Error("A terminal status requires a finishedAtUtc");
  }
  if (!terminal && input.finishedAtUtc !== null) {
    throw new Error("A nonterminal status must have finishedAtUtc null");
  }
  let finishedAtUtc: string | null = null;
  if (terminal) {
    const finishedAtMs = canonicalUtcMillis(
      input.finishedAtUtc,
      "finishedAtUtc",
    );
    if (
      finishedAtMs < startedAtUtc || finishedAtMs < requestedAtUtc ||
      updatedAtUtc < finishedAtMs
    ) {
      throw new Error("Status terminal timestamps are inconsistent");
    }
    finishedAtUtc = input.finishedAtUtc as string;
  }
  if ("errorCode" in input && state !== "FAILED") {
    throw new Error("errorCode is only valid on a FAILED status");
  }
  if (state === "FAILED" && "errorCode" in input) {
    const errorCode = input.errorCode;
    if (
      typeof errorCode !== "string" ||
      !(WORKER_ERROR_CODES as readonly string[]).includes(errorCode)
    ) {
      throw new Error("Status errorCode is not a fixed worker error code");
    }
  }
  if ("resultSha256" in input && state !== "PENDING_VERIFIER") {
    throw new Error(
      "resultSha256 is only valid on a PENDING_VERIFIER status",
    );
  }
  let resultSha256: string | undefined;
  if (state === "PENDING_VERIFIER" && "resultSha256" in input) {
    const value = input.resultSha256;
    if (
      typeof value !== "string" || !SHA256_PATTERN.test(value)
    ) {
      throw new Error(
        "Status resultSha256 must be 64 lower-case hex characters",
      );
    }
    resultSha256 = value;
  }
  return {
    schemaVersion: 1,
    jobId: jobId as string,
    periodKey,
    generation: generation as string,
    requestSha256,
    requestedAtUtc: input.requestedAtUtc as string,
    deadlineAtUtc: input.deadlineAtUtc as string,
    invocationId,
    state: state as WorkerState,
    startedAtUtc: input.startedAtUtc as string,
    updatedAtUtc: input.updatedAtUtc as string,
    heartbeatAtUtc: input.heartbeatAtUtc as string,
    finishedAtUtc,
    ...(state === "FAILED" && "errorCode" in input
      ? { errorCode: input.errorCode as WorkerErrorCode }
      : {}),
    ...(resultSha256 === undefined ? {} : { resultSha256 }),
  };
}

// ---------------------------------------------------------------------------
// m06 gate derivation
// ---------------------------------------------------------------------------

/** Deterministic worker unit name for a generation. */
export function workerUnitName(generation: string): string {
  return `arch-vps-b2-worker-${generation.slice("generation-".length)}.service`;
}

/**
 * Derive the active unbound m06 gate identity the controller must have
 * written for this worker (fixed host, fixed source lock path, deterministic
 * worker unit name, unbound invocation) and validate it through the reviewed
 * m06 gate validator.
 */
export function deriveWorkerGate(
  request: WorkerRequest,
  requestSha256: string,
): BackupControllerGate {
  return validateGate({
    schemaVersion: 1,
    owner: GATE_OWNER,
    state: "active",
    jobId: request.jobId,
    periodKey: request.periodKey,
    generation: request.generation,
    requestSha256,
    requestedAtUtc: request.requestedAtUtc,
    deadlineAtUtc: request.deadlineAtUtc,
    createdAtUtc: request.requestedAtUtc,
    updatedAtUtc: request.requestedAtUtc,
    remoteHost: GATE_REMOTE_HOST,
    unitName: workerUnitName(request.generation),
    unitInvocationId: null,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
  });
}

// ---------------------------------------------------------------------------
// Injected dependency boundaries
// ---------------------------------------------------------------------------

/** Heartbeat scheduler seam: production uses setInterval; tests control the
 * callback manually. The worker stops the timer and drains the queue in
 * finally, and no heartbeat is written after the terminal status. */
export interface HeartbeatScheduler {
  start(callback: () => void, intervalMs: number): () => void;
}

/**
 * Private/internal dependency boundary. Production entry always uses the
 * fixed paths and the real modules; tests inject fake phase functions, a
 * fake clock, a manual heartbeat scheduler, a lock override and the unique
 * temporary persistence root. There is no exported mutable global seam and
 * no alternate production path flag.
 */
export interface SourceWorkerDependencies {
  basePath: string;
  now: () => Date;
  lock: <T>(path: string, work: () => Promise<T>) => Promise<T>;
  capture: (settings: CaptureSettings) => Promise<CaptureResult>;
  upload: (capture: CaptureResult, store: UploadStore) => Promise<UploadResult>;
  publish: (
    capture: CaptureResult,
    upload: UploadResult,
    recipient: IndexRecipient,
    store: IndexStore,
  ) => Promise<PublishedIndex>;
  heartbeatScheduler: HeartbeatScheduler;
  /** Bounded wait between retries; production uses a real timeout, tests are
   * deterministic. The wait is never scheduled past the job deadline. */
  sleep: (ms: number) => Promise<void>;
}

export interface SourceWorkerInputs {
  envelope: WorkerRequestEnvelope;
  captureSettings: CaptureSettings;
  indexRecipient: IndexRecipient;
  /** Exact deployed reviewed source revision; must equal request.sourceRevision. */
  sourceRevision: string;
  /** systemd unit invocation id (32 lower-case hex). */
  invocationId: string;
  /** Upload/index store (put|get|versions only; no remove access). */
  store: UploadStore;
  deps?: Partial<SourceWorkerDependencies>;
}

const PRODUCTION_DEPS: SourceWorkerDependencies = {
  basePath: PRODUCTION_BASE_PATH,
  now: () => new Date(),
  lock: withBackupLock,
  capture: (settings) => captureGeneration(settings),
  upload: (capture, store) => uploadCapturedGeneration(capture, store),
  publish: (capture, upload, recipient, store) =>
    publishRecoveryIndex(capture, upload, recipient, store),
  heartbeatScheduler: {
    start(callback, intervalMs) {
      const id = setInterval(callback, intervalMs);
      return () => clearInterval(id);
    },
  },
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

// ---------------------------------------------------------------------------
// Worker-level errors
// ---------------------------------------------------------------------------

export class WorkerRejection extends Error {
  constructor(
    readonly code: WorkerRejectionCode,
    cause?: unknown,
  ) {
    super(
      `SourceWorker rejected (${code})`,
      cause === undefined ? undefined : { cause },
    );
  }
}

class WorkerPhaseError extends Error {
  constructor(
    readonly code: WorkerErrorCode,
    cause?: unknown,
  ) {
    super(
      `SourceWorker failed (${code})`,
      cause === undefined ? undefined : { cause },
    );
  }
}

function rejection(code: WorkerRejectionCode, cause?: unknown): never {
  throw new WorkerRejection(code, cause);
}

// ---------------------------------------------------------------------------
// Worker-local persistence guards (not a generic filesystem library)
// ---------------------------------------------------------------------------

interface OwnedDir {
  path: string;
  dev: number;
  ino: number;
  uid: number;
}

async function assertOwnedDir(
  path: string,
  ownerUid: number,
  what: string,
): Promise<OwnedDir> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      throw new Error(`${what} directory is missing`);
    }
    throw error;
  }
  if (info.isSymlink || !info.isDirectory) {
    throw new Error(`${what} must be a real directory, never a symlink`);
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o700) {
    throw new Error(`${what} must grant only owner access (0700)`);
  }
  if (
    typeof info.uid !== "number" || typeof info.dev !== "number" ||
    typeof info.ino !== "number" || info.uid !== ownerUid
  ) {
    throw new Error(`${what} must be owned by the base owner`);
  }
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    throw new Error(`${what} must resolve to a real path`);
  }
  if (real !== path) {
    throw new Error(`${what} must not be reached through a symlink`);
  }
  return { path, dev: info.dev, ino: info.ino, uid: info.uid };
}

/** Owner-only real base directory; the base itself is never created here. */
async function resolveOwnedBase(path: string): Promise<OwnedDir> {
  if (typeof path !== "string" || path === "" || path.includes("\0")) {
    rejection("BASE_PATH_INVALID");
  }
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      rejection("BASE_PATH_INVALID");
    }
    throw error;
  }
  if (info.isSymlink || !info.isDirectory) {
    rejection("BASE_PATH_INVALID");
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o700) {
    rejection("BASE_PATH_INVALID");
  }
  if (
    typeof info.uid !== "number" || typeof info.dev !== "number" ||
    typeof info.ino !== "number"
  ) {
    rejection("BASE_PATH_INVALID");
  }
  const real = await Deno.realPath(path);
  return { path: real, dev: info.dev, ino: info.ino, uid: info.uid };
}

/** Create or verify one owner-only jobs directory. */
async function ensureOwnedDir(
  path: string,
  ownerUid: number,
  what: string,
): Promise<OwnedDir> {
  let info: Deno.FileInfo | undefined;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  if (info === undefined) {
    await Deno.mkdir(path, { mode: 0o700 });
    await Deno.chmod(path, 0o700);
  }
  return await assertOwnedDir(path, ownerUid, what);
}

function assertOwnedRegular(
  info: Deno.FileInfo,
  ownerUid: number,
  what: string,
): void {
  if (!info.isFile || info.isSymlink) {
    throw new Error(`${what} must be a regular file, never a symlink`);
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    throw new Error(`${what} must grant only owner access (0600)`);
  }
  if (typeof info.uid !== "number" || info.uid !== ownerUid) {
    throw new Error(`${what} must be owned by the directory owner`);
  }
}

async function readOwnedBytes(
  path: string,
  ownerUid: number,
  maxBytes: number,
  what: string,
): Promise<Uint8Array> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      throw new Error(`${what} is missing`);
    }
    throw error;
  }
  assertOwnedRegular(info, ownerUid, what);
  if (info.size > maxBytes) {
    throw new Error(`${what} exceeds the read bound`);
  }
  const handle = await Deno.open(path, { read: true });
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile || opened.dev !== info.dev || opened.ino !== info.ino ||
      opened.uid !== info.uid || opened.size !== info.size
    ) {
      throw new Error(`${what} changed between lstat and open`);
    }
    const data = new Uint8Array(info.size);
    let offset = 0;
    while (offset < info.size) {
      const read = await handle.read(data.subarray(offset));
      if (read === null || read === 0) break;
      offset += read;
    }
    if (offset !== info.size) {
      throw new Error(`${what} changed while it was being read`);
    }
    const after = await handle.stat();
    if (after.dev !== info.dev || after.ino !== info.ino) {
      throw new Error(`${what} was replaced while it was being read`);
    }
    return data.slice();
  } finally {
    handle.close();
  }
}

/** Missing-path marker; identity errors are distinguished from absence. */
async function readOwnedBytesOrMissing(
  path: string,
  ownerUid: number,
  maxBytes: number,
  what: string,
): Promise<Uint8Array | null> {
  try {
    return await readOwnedBytes(path, ownerUid, maxBytes, what);
  } catch (error) {
    if (error instanceof Error && error.message === `${what} is missing`) {
      return null;
    }
    throw error;
  }
}

async function readOwnedJsonFile(
  path: string,
  ownerUid: number,
  maxBytes: number,
  what: string,
): Promise<unknown> {
  const bytes = await readOwnedBytes(path, ownerUid, maxBytes, what);
  let text = new TextDecoder().decode(bytes);
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${what} is not valid JSON`);
  }
}

async function syncDirectory(dir: string): Promise<void> {
  const handle = await Deno.open(dir, { read: true });
  try {
    await handle.sync();
  } finally {
    handle.close();
  }
}

async function writeTempBytes(
  path: string,
  bytes: Uint8Array,
  ownerUid: number,
  what: string,
): Promise<string> {
  const parent = path.slice(0, path.lastIndexOf("/"));
  const base = path.slice(path.lastIndexOf("/") + 1);
  await assertOwnedDir(parent, ownerUid, `${what} parent`);
  const temp = `${parent}/.${base}.${crypto.randomUUID()}.tmp`;
  const handle = await Deno.open(temp, {
    createNew: true,
    write: true,
    mode: 0o600,
  });
  try {
    const before = await handle.stat();
    assertOwnedRegular(before, ownerUid, `${what} temp`);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const written = await handle.write(bytes.subarray(offset));
      if (!Number.isSafeInteger(written) || written <= 0) {
        throw new Error(`${what} temp write made no progress`);
      }
      if (written > bytes.byteLength - offset) {
        throw new Error(`${what} temp write exceeds the requested length`);
      }
      offset += written;
    }
    await handle.sync();
    const after = await handle.stat();
    if (
      after.dev !== before.dev || after.ino !== before.ino ||
      after.uid !== before.uid || after.size !== bytes.byteLength
    ) {
      throw new Error(`${what} temp identity changed while it was written`);
    }
  } finally {
    handle.close();
  }
  await Deno.chmod(temp, 0o600);
  const tempInfo = await Deno.lstat(temp);
  if (tempInfo.size !== bytes.byteLength) {
    await Deno.remove(temp).catch(() => {});
    throw new Error(`${what} temp size is wrong after write`);
  }
  return temp;
}

async function assertFinalFile(
  path: string,
  ownerUid: number,
  size: number,
  what: string,
): Promise<void> {
  const info = await Deno.lstat(path);
  assertOwnedRegular(info, ownerUid, what);
  if (info.nlink !== 1) {
    throw new Error(`${what} must have exactly one hard link`);
  }
  if (info.size !== size) {
    throw new Error(`${what} size changed after publication`);
  }
}

/** Create-new owner-only file: the final name appears only through an atomic
 * link, so an existing file (or symlink) is never overwritten. */
async function writeOwnedBytesCreateNew(
  path: string,
  bytes: Uint8Array,
  ownerUid: number,
  what: string,
): Promise<void> {
  const temp = await writeTempBytes(path, bytes, ownerUid, what);
  try {
    try {
      await Deno.link(temp, path);
    } catch (error) {
      if (error instanceof Deno.errors.AlreadyExists) {
        throw new Error(`${what} already exists; refusing to overwrite`);
      }
      throw error;
    }
    await Deno.remove(temp);
    await assertFinalFile(path, ownerUid, bytes.byteLength, what);
    await syncDirectory(path.slice(0, path.lastIndexOf("/")));
  } catch (error) {
    await Deno.remove(temp).catch(() => {});
    throw error;
  }
}

/** Owner-only atomic replacement: an existing path must be a regular 0600
 * file of the directory owner (never a symlink or foreign file); otherwise
 * the mutation is refused. */
async function writeOwnedBytesReplace(
  path: string,
  bytes: Uint8Array,
  ownerUid: number,
  what: string,
): Promise<void> {
  const temp = await writeTempBytes(path, bytes, ownerUid, what);
  try {
    let existing: Deno.FileInfo | undefined;
    try {
      existing = await Deno.lstat(path);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    if (existing !== undefined) {
      assertOwnedRegular(existing, ownerUid, `${what} existing`);
    }
    await Deno.rename(temp, path);
    await assertFinalFile(path, ownerUid, bytes.byteLength, what);
    await syncDirectory(path.slice(0, path.lastIndexOf("/")));
  } catch (error) {
    await Deno.remove(temp).catch(() => {});
    throw error;
  }
}

async function writeOwnedJsonFile(
  path: string,
  value: unknown,
  ownerUid: number,
  maxBytes: number,
  what: string,
): Promise<void> {
  const bytes = new TextEncoder().encode(
    `${JSON.stringify(value, null, 2)}\n`,
  );
  if (bytes.byteLength > maxBytes) {
    throw new Error(`${what} exceeds the write bound`);
  }
  await writeOwnedBytesReplace(path, bytes, ownerUid, what);
}

// ---------------------------------------------------------------------------
// Serialized status persist queue
// ---------------------------------------------------------------------------

interface StatusIdentity {
  jobId: string;
  periodKey: string;
  generation: string;
  requestSha256: string;
  requestedAtUtc: string;
  deadlineAtUtc: string;
  invocationId: string;
}

export interface StatusDelta {
  state: WorkerState;
  errorCode?: WorkerErrorCode;
  resultSha256?: string;
}

export type WriteKind = "phase" | "heartbeat" | "terminal";

export interface StatusMutation {
  /** The state transition. Ignored for heartbeats: the state is derived when
   * the task executes from the last committed phase write. */
  delta?: StatusDelta;
  kind: WriteKind;
  /** Side effect performed before the status write (result-before-state). */
  effect?: () => Promise<void>;
}

/** Structural target used by the serialized queue (StatusWriter satisfies it). */
export interface StatusWriteTarget {
  build(delta: StatusDelta, kind: WriteKind): WorkerStatus;
}

class StatusWriter implements StatusWriteTarget {
  #startedMs: number;
  #lastUpdatedMs: number;
  #lastHeartbeatMs: number;
  #floorMs: number;

  constructor(
    private readonly identity: StatusIdentity,
    private readonly clock: () => number,
    seed: { startedAt: number; updatedAt: number; heartbeatAt: number },
  ) {
    // Never precede the request (controller/worker clock skew never produces
    // a status outside the proof window).
    this.#floorMs = Math.max(
      Date.parse(identity.requestedAtUtc),
      seed.startedAt,
    );
    this.#startedMs = this.#floorMs;
    this.#lastUpdatedMs = Math.max(this.#floorMs, seed.updatedAt);
    this.#lastHeartbeatMs = Math.max(this.#floorMs, seed.heartbeatAt);
  }

  build(delta: StatusDelta, kind: WriteKind): WorkerStatus {
    const now = Math.max(this.clock(), this.#floorMs);
    const updated = Math.max(now, this.#lastUpdatedMs);
    const heartbeat = kind === "heartbeat" && now > this.#lastHeartbeatMs
      ? now
      : this.#lastHeartbeatMs;
    const finished = kind === "terminal" ? Math.min(now, updated) : null;
    const status: WorkerStatus = {
      schemaVersion: 1,
      jobId: this.identity.jobId,
      periodKey: this.identity.periodKey,
      generation: this.identity.generation,
      requestSha256: this.identity.requestSha256,
      requestedAtUtc: this.identity.requestedAtUtc,
      deadlineAtUtc: this.identity.deadlineAtUtc,
      invocationId: this.identity.invocationId,
      state: delta.state,
      startedAtUtc: iso(this.#startedMs),
      updatedAtUtc: iso(updated),
      heartbeatAtUtc: iso(heartbeat),
      finishedAtUtc: finished === null ? null : iso(finished),
      ...(delta.errorCode === undefined ? {} : { errorCode: delta.errorCode }),
      ...(delta.resultSha256 === undefined
        ? {}
        : { resultSha256: delta.resultSha256 }),
    };
    // Self-check: every persisted status must satisfy the strict validator.
    validateStatus(status);
    this.#lastUpdatedMs = Math.max(updated, finished ?? 0);
    if (kind === "heartbeat") this.#lastHeartbeatMs = heartbeat;
    return status;
  }
}

/**
 * Serialized status write queue. Exactly one task runs at a time, tasks run
 * strictly in submission order, and a heartbeat derives its state when it
 * executes from the last phase/terminal write that actually committed, never
 * from a snapshot taken when the heartbeat was queued.
 *
 * A task rejection is still visible to its caller, but the internal chain
 * always settles, so a failed heartbeat/phase/final-result write can never
 * poison later writes — in particular the FAILED terminal that must follow a
 * failed phase or a failed terminal effect.
 */
export class SerialStatusQueue {
  #tail: Promise<unknown> = Promise.resolve();
  #terminal = false;
  #lastCommittedState: WorkerState;

  constructor(initialState: WorkerState) {
    this.#lastCommittedState = initialState;
  }

  /** State of the last phase/terminal write that completed (or the seed). */
  get lastCommittedState(): WorkerState {
    return this.#lastCommittedState;
  }

  submit(
    mutation: StatusMutation,
    writer: StatusWriteTarget,
    persist: (status: WorkerStatus) => Promise<void>,
  ): Promise<WorkerStatus | undefined> {
    const task = this.#tail.then(async () => {
      if (mutation.kind === "heartbeat" && this.#terminal) return undefined;
      if (mutation.kind === "terminal") this.#terminal = true;
      await mutation.effect?.();
      const delta: StatusDelta = mutation.kind === "heartbeat"
        ? { state: this.#lastCommittedState }
        : mutation.delta!;
      const status = writer.build(delta, mutation.kind);
      await persist(status);
      if (mutation.kind !== "heartbeat") {
        this.#lastCommittedState = delta.state;
      }
      return status;
    });
    // The returned task still rejects for its caller; the internal chain
    // always recovers so later writes are not poisoned.
    this.#tail = task.then(() => undefined, () => undefined);
    return task as Promise<WorkerStatus | undefined>;
  }

  drain(): Promise<void> {
    return this.#tail.then(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Bounded retry classification
// ---------------------------------------------------------------------------

/** Exact B2 API operations whose transport failures may be retried. */
const RETRIABLE_B2_OPERATIONS = new Set([
  "b2_authorize_account",
  "b2_get_upload_url",
  "b2_upload_file",
  "b2_download_file_by_id",
  "b2_list_file_versions",
]);

function isRetriableHttpStatus(status: number): boolean {
  return status === 408 || status === 429 ||
    (status >= 500 && status <= 599);
}

/**
 * Exact retriable B2 transport failure classification. Only the documented
 * storage-layer strings are retried for the five B2 operations: network
 * errors, HTTP 408/429/5xx (with optional unusable/invalid response body)
 * and a failed download body read. Scope/identity/corruption/other 4xx and
 * every non-B2 error return false.
 */
export function isRetriableB2Error(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const message = error.message;
  const http =
    /^(.+) failed \(HTTP (\d{3})\)(: unreadable body|: invalid body)?$/
      .exec(message);
  if (http !== null) {
    return RETRIABLE_B2_OPERATIONS.has(http[1]) &&
      isRetriableHttpStatus(Number(http[2]));
  }
  const networkSuffix = " failed (network error)";
  if (message.endsWith(networkSuffix)) {
    return RETRIABLE_B2_OPERATIONS.has(
      message.slice(0, -networkSuffix.length),
    );
  }
  const bodyReadSuffix = " failed: body read failed";
  if (message.endsWith(bodyReadSuffix)) {
    return message.slice(0, -bodyReadSuffix.length) ===
      "b2_download_file_by_id";
  }
  return false;
}

// ---------------------------------------------------------------------------
// Phase helpers
// ---------------------------------------------------------------------------

const STATE_RANK: Record<WorkerState, number> = {
  REQUESTED: 0,
  CAPTURING: 1,
  CAPTURED: 2,
  UPLOADING: 3,
  UPLOAD_VERIFIED: 4,
  INDEXING: 5,
  PENDING_VERIFIER: 6,
  FAILED: 7,
};

interface RunContext {
  request: WorkerRequest;
  requestSha256: string;
  invocationId: string;
  captureSettings: CaptureSettings;
  indexRecipient: IndexRecipient;
  store: UploadStore;
  deps: SourceWorkerDependencies;
  base: OwnedDir;
  jobDir: OwnedDir;
  stagePath: string;
  statusPath: string;
  resultPath: string;
  resumeState: WorkerState;
  fresh: boolean;
  seeded: { startedAt: number; updatedAt: number; heartbeatAt: number };
}

function deadlineMs(ctx: RunContext): number {
  return Date.parse(ctx.request.deadlineAtUtc);
}

function assertInWindow(ctx: RunContext): void {
  if (ctx.deps.now().getTime() > deadlineMs(ctx)) {
    throw new WorkerPhaseError("DEADLINE_EXCEEDED");
  }
}

/** One phase step: any underlying failure (including status or result-file
 * writes) maps to exactly the fixed phase code; explicit invalid-saved-result
 * and deadline errors keep their own codes. */
async function phaseStep<T>(
  code: WorkerErrorCode,
  run: () => Promise<T>,
): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof WorkerPhaseError) throw error;
    throw new WorkerPhaseError(code, error);
  }
}

/**
 * Retry the whole upload/publish module call inside this invocation: at most
 * three attempts, 30 minute spacing, deadline checked before every attempt
 * and after every wait (the wait is capped so it never passes the deadline).
 * Only exact B2 transport failures are retried; every other failure is
 * immediate. The retried call receives the identical capture/upload/store,
 * so the module's own journal and ambiguous-put reconciliation govern each
 * attempt; nothing is re-captured and no raw put is ever issued here.
 */
async function runPhaseWithRetries<T>(
  ctx: RunContext,
  code: WorkerErrorCode,
  run: () => Promise<T>,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_PHASE_ATTEMPTS; attempt += 1) {
    assertInWindow(ctx);
    try {
      return await run();
    } catch (error) {
      if (error instanceof WorkerPhaseError) throw error;
      lastError = error;
      if (!isRetriableB2Error(error)) {
        throw new WorkerPhaseError(code, error);
      }
      if (attempt >= MAX_PHASE_ATTEMPTS) {
        throw new WorkerPhaseError(code, error);
      }
      const now = ctx.deps.now().getTime();
      const deadline = deadlineMs(ctx);
      if (now >= deadline) {
        throw new WorkerPhaseError("DEADLINE_EXCEEDED");
      }
      const wait = Math.min(RETRY_SPACING_MS, deadline - now);
      await ctx.deps.sleep(wait);
      if (ctx.deps.now().getTime() > deadline) {
        throw new WorkerPhaseError("DEADLINE_EXCEEDED");
      }
    }
  }
  throw new WorkerPhaseError(code, lastError);
}

function indexObjectName(generation: string): string {
  return `${DIRECT_PREFIX}indexes/${generation}/index.json.gpg`;
}

/** Full bound validation of one capture result against the request, the
 * fixed stage path and the pinned public recipient in that stage. */
async function validateCaptureResultBound(
  capture: unknown,
  ctx: RunContext,
): Promise<CaptureResult> {
  validateUploadCapture(capture as CaptureResult);
  const value = capture as CaptureResult;
  if (value.generation !== ctx.request.generation) {
    throw new Error("Capture result generation does not bind the request");
  }
  if (value.stageDirectory !== ctx.stagePath) {
    throw new Error("Capture result stage is not the fixed generation stage");
  }
  const started = canonicalUtcMillis(
    value.startedAtUtc,
    "capture.startedAtUtc",
  );
  const finished = canonicalUtcMillis(
    value.finishedAtUtc,
    "capture.finishedAtUtc",
  );
  if (started >= finished || started < Date.parse(ctx.request.requestedAtUtc)) {
    throw new Error("Capture result timestamps are incoherent");
  }
  const stage = await assertOwnedDir(
    ctx.stagePath,
    ctx.base.uid,
    "capture stage",
  );
  const recipientBytes = await readOwnedBytes(
    `${stage.path}/recipient.asc`,
    stage.uid,
    MAX_RECIPIENT_BYTES,
    "stage recipient",
  );
  if (sha256Hex(recipientBytes) !== ctx.request.recipientSha256) {
    throw new Error("Stage recipient identity does not match the request");
  }
  return value;
}

function validateUploadResultBound(
  upload: unknown,
  capture: CaptureResult,
  ctx: RunContext,
): UploadResult {
  buildRecoveryIndex(capture, upload as UploadResult, ctx.indexRecipient);
  const value = upload as UploadResult;
  if (value.generation !== ctx.request.generation) {
    throw new Error("Upload result generation does not bind the request");
  }
  if (value.stageDirectory !== ctx.stagePath) {
    throw new Error("Upload result stage is not the fixed generation stage");
  }
  return value;
}

const PUBLISHED_INDEX_KEYS = new Set([
  "generation",
  "object",
  "ciphertextBytes",
  "ciphertextSha256",
  "indexSha256",
  "uploadVerified",
  "decryptedRestoreProved",
  "machineBootRestoreProved",
]);

const PUBLISHED_OBJECT_KEYS = new Set([
  "fileId",
  "fileName",
  "contentLength",
  "contentSha1",
  "action",
  "uploadTimestamp",
]);

function validatePublishedIndexBound(
  published: unknown,
  capture: CaptureResult,
  upload: UploadResult,
  ctx: RunContext,
): PublishedIndex {
  if (!isRecord(published)) {
    throw new Error("Published index must be a JSON object");
  }
  rejectUnknownKeys(published, PUBLISHED_INDEX_KEYS, "Published index");
  const record = published;
  if (record.generation !== ctx.request.generation) {
    throw new Error("Published index generation does not bind the request");
  }
  if (record.uploadVerified !== true) {
    throw new Error("Published index upload is not verified");
  }
  if (
    record.decryptedRestoreProved !== false ||
    record.machineBootRestoreProved !== false
  ) {
    throw new Error("Published index must not claim restore proof");
  }
  if (
    typeof record.ciphertextBytes !== "number" ||
    !Number.isSafeInteger(record.ciphertextBytes) || record.ciphertextBytes <= 0
  ) {
    throw new Error("Published index ciphertext size is invalid");
  }
  if (
    typeof record.ciphertextSha256 !== "string" ||
    !SHA256_PATTERN.test(record.ciphertextSha256)
  ) {
    throw new Error("Published index ciphertext hash is invalid");
  }
  const index = buildRecoveryIndex(capture, upload, ctx.indexRecipient);
  const expectedIndexSha256 = sha256Hex(
    new TextEncoder().encode(JSON.stringify(index)),
  );
  if (record.indexSha256 !== expectedIndexSha256) {
    throw new Error(
      "Published index does not match the capture/upload identity",
    );
  }
  const object = record.object;
  if (!isRecord(object)) {
    throw new Error("Published index object is missing");
  }
  rejectUnknownKeys(object, PUBLISHED_OBJECT_KEYS, "Published index object");
  if (
    typeof object.fileId !== "string" || object.fileId.length === 0 ||
    typeof object.fileName !== "string" ||
    object.fileName !== indexObjectName(ctx.request.generation) ||
    typeof object.contentLength !== "number" ||
    !Number.isSafeInteger(object.contentLength) || object.contentLength < 0 ||
    typeof object.contentSha1 !== "string" ||
    !/^[0-9a-f]{40}$/.test(object.contentSha1) ||
    object.action !== "upload" ||
    typeof object.uploadTimestamp !== "number" ||
    !Number.isSafeInteger(object.uploadTimestamp) || object.uploadTimestamp < 0
  ) {
    throw new Error("Published index object identity is invalid");
  }
  if (object.contentLength !== record.ciphertextBytes) {
    throw new Error(
      "Published index object length does not match the ciphertext",
    );
  }
  return record as unknown as PublishedIndex;
}

function serializeJobResult(result: WorkerJobResult): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(result, null, 2)}\n`);
}

/** Persist create-new, or accept only a byte-identical existing file. */
async function persistCreateNewOrVerify(
  path: string,
  bytes: Uint8Array,
  ownerUid: number,
  maxBytes: number,
  what: string,
): Promise<void> {
  const existing = await readOwnedBytesOrMissing(
    path,
    ownerUid,
    maxBytes,
    what,
  );
  if (existing !== null) {
    if (existing.byteLength !== bytes.byteLength) {
      throw new Error(`${what} exists with different bytes`);
    }
    for (let i = 0; i < bytes.byteLength; i += 1) {
      if (existing[i] !== bytes[i]) {
        throw new Error(`${what} exists with different bytes`);
      }
    }
    return;
  }
  await writeOwnedBytesCreateNew(path, bytes, ownerUid, what);
}

// ---------------------------------------------------------------------------
// Worker run
// ---------------------------------------------------------------------------

interface WorkerSnapshot {
  request: WorkerRequest;
  requestSha256: string;
  captureSettings: CaptureSettings;
  indexRecipient: IndexRecipient;
  sourceRevision: string;
  invocationId: string;
  store: UploadStore;
  deps: SourceWorkerDependencies;
}

export async function runSourceWorker(
  inputs: SourceWorkerInputs,
): Promise<WorkerStatus> {
  // Snapshot all inputs before the first await; caller mutation after this
  // point cannot change what is authorized.
  let request: WorkerRequest;
  try {
    request = validateRequest(inputs.envelope?.request);
  } catch (error) {
    throw new WorkerRejection("INVALID_REQUEST", error);
  }
  let requestSha256: string;
  try {
    requestSha256 = requestSha256Of(request);
  } catch (error) {
    throw new WorkerRejection("INVALID_REQUEST", error);
  }
  if (inputs.envelope?.requestSha256 !== requestSha256) {
    rejection("INVALID_REQUEST_HASH");
  }
  const captureSettings = structuredClone(inputs.captureSettings);
  const indexRecipient = structuredClone(inputs.indexRecipient);
  const sourceRevision = inputs.sourceRevision;
  const store = inputs.store;
  let invocationId: string;
  try {
    invocationId = validateUnitInvocationId(inputs.invocationId);
  } catch (error) {
    throw new WorkerRejection("INVALID_INVOCATION", error);
  }
  const deps: SourceWorkerDependencies = { ...PRODUCTION_DEPS, ...inputs.deps };

  // Identity bindings against the immutable request, before any filesystem
  // side effect.
  let configSha256: string;
  try {
    configSha256 = sourceConfigSha256(captureSettings);
  } catch (error) {
    throw new WorkerRejection("CONFIG_MISMATCH", error);
  }
  if (configSha256 !== request.sourceConfigSha256) {
    rejection("CONFIG_MISMATCH");
  }
  if (captureSettings.generation !== request.generation) {
    rejection("GENERATION_MISMATCH");
  }
  if (
    captureSettings.recipientSha256 !== request.recipientSha256 ||
    captureSettings.recipientFingerprint !== request.recipientFingerprint
  ) {
    rejection("RECIPIENT_MISMATCH");
  }
  if (
    indexRecipient.recipientSha256 !== request.recipientSha256 ||
    indexRecipient.recipientFingerprint !== request.recipientFingerprint ||
    indexRecipient.recipientFile !== captureSettings.recipientFile ||
    !ABSOLUTE_PATH_PATTERN.test(indexRecipient.recipientFile)
  ) {
    rejection("RECIPIENT_MISMATCH");
  }
  if (sourceRevision !== request.sourceRevision) {
    rejection("REVISION_MISMATCH");
  }
  try {
    deriveWorkerGate(request, requestSha256);
  } catch (error) {
    throw new WorkerRejection("INVALID_REQUEST", error);
  }

  const snapshot: WorkerSnapshot = {
    request,
    requestSha256,
    captureSettings,
    indexRecipient,
    sourceRevision,
    invocationId,
    store,
    deps,
  };
  const base = await resolveOwnedBase(deps.basePath);
  const lockPath = `${base.path}/source.lock`;
  return await deps.lock(lockPath, () => runLocked(snapshot, base));
}

async function runLocked(
  snapshot: WorkerSnapshot,
  base: OwnedDir,
): Promise<WorkerStatus> {
  const { request, deps } = snapshot;
  let jobsDir: OwnedDir;
  try {
    jobsDir = await ensureOwnedDir(`${base.path}/jobs`, base.uid, "jobs");
  } catch (error) {
    throw new WorkerRejection("JOBS_PATH_INVALID", error);
  }
  let jobDir: OwnedDir;
  try {
    jobDir = await ensureOwnedDir(
      `${jobsDir.path}/${request.jobId}`,
      base.uid,
      "job",
    );
  } catch (error) {
    throw new WorkerRejection("JOBS_PATH_INVALID", error);
  }
  const statusPath = `${jobDir.path}/status.json`;
  const resultPath = `${jobDir.path}/result.json`;
  const requestPath = `${jobDir.path}/request.json`;
  const stagePath = `${base.path}/${request.generation}`;

  // Request persist: canonical bytes exactly; create-new first, byte-equal
  // resumes only, a different request is rejected before any phase work.
  const requestBytes = new TextEncoder().encode(
    canonicalRequestString(request),
  );
  let persistedRequest: Uint8Array | null;
  try {
    persistedRequest = await readOwnedBytesOrMissing(
      requestPath,
      jobDir.uid,
      MAX_REQUEST_BYTES,
      "request",
    );
  } catch (error) {
    throw new WorkerRejection("REQUEST_MISMATCH", error);
  }
  if (persistedRequest !== null) {
    if (persistedRequest.byteLength !== requestBytes.byteLength) {
      rejection("REQUEST_MISMATCH");
    }
    for (let i = 0; i < requestBytes.byteLength; i += 1) {
      if (persistedRequest[i] !== requestBytes[i]) {
        rejection("REQUEST_MISMATCH");
      }
    }
    let parsedRequest: WorkerRequest;
    try {
      parsedRequest = validateRequest(
        JSON.parse(new TextDecoder().decode(persistedRequest)) as unknown,
      );
    } catch (error) {
      rejection("REQUEST_MISMATCH", error);
    }
    if (JSON.stringify(parsedRequest) !== JSON.stringify(request)) {
      rejection("REQUEST_MISMATCH");
    }
  } else {
    try {
      await writeOwnedBytesCreateNew(
        requestPath,
        requestBytes,
        jobDir.uid,
        "request",
      );
    } catch (error) {
      throw new WorkerRejection("JOBS_PATH_INVALID", error);
    }
  }

  // Resume identity: coherent saved status, same generation and invocation.
  let savedStatus: WorkerStatus | undefined;
  let savedStatusBytes: Uint8Array | null;
  try {
    savedStatusBytes = await readOwnedBytesOrMissing(
      statusPath,
      jobDir.uid,
      MAX_STATUS_BYTES,
      "status",
    );
  } catch (error) {
    throw new WorkerRejection("INVALID_STATUS", error);
  }
  if (savedStatusBytes !== null) {
    try {
      const raw = JSON.parse(new TextDecoder().decode(savedStatusBytes));
      savedStatus = validateStatus(raw);
    } catch (error) {
      throw new WorkerRejection("INVALID_STATUS", error);
    }
    if (
      savedStatus.jobId !== request.jobId ||
      savedStatus.periodKey !== request.periodKey ||
      savedStatus.generation !== request.generation ||
      savedStatus.requestSha256 !== snapshot.requestSha256 ||
      savedStatus.requestedAtUtc !== request.requestedAtUtc ||
      savedStatus.deadlineAtUtc !== request.deadlineAtUtc
    ) {
      rejection("INVALID_STATUS");
    }
    if (savedStatus.invocationId !== snapshot.invocationId) {
      rejection("INVOCATION_MISMATCH");
    }
    if (savedStatus.state === "PENDING_VERIFIER") {
      let resultBytes: Uint8Array;
      try {
        resultBytes = await readOwnedBytes(
          resultPath,
          jobDir.uid,
          MAX_RESULT_BYTES,
          "result",
        );
      } catch (error) {
        throw new WorkerRejection("INVALID_STATUS", error);
      }
      if (
        savedStatus.resultSha256 === undefined ||
        sha256Hex(resultBytes) !== savedStatus.resultSha256
      ) {
        rejection("INVALID_STATUS");
      }
      return savedStatus;
    }
    if (savedStatus.state === "FAILED") {
      return savedStatus;
    }
  }

  const ctx: RunContext = {
    request,
    requestSha256: snapshot.requestSha256,
    invocationId: snapshot.invocationId,
    captureSettings: snapshot.captureSettings,
    indexRecipient: snapshot.indexRecipient,
    store: snapshot.store,
    deps,
    base,
    jobDir,
    stagePath,
    statusPath,
    resultPath,
    resumeState: savedStatus?.state ?? "REQUESTED",
    fresh: savedStatus === undefined,
    seeded: savedStatus === undefined
      ? { startedAt: deps.now().getTime(), updatedAt: 0, heartbeatAt: 0 }
      : {
        startedAt: Date.parse(savedStatus.startedAtUtc),
        updatedAt: Date.parse(savedStatus.updatedAtUtc),
        heartbeatAt: Date.parse(savedStatus.heartbeatAtUtc),
      },
  };
  return await runJob(ctx);
}

async function runJob(ctx: RunContext): Promise<WorkerStatus> {
  const { deps } = ctx;
  const writer = new StatusWriter(
    {
      jobId: ctx.request.jobId,
      periodKey: ctx.request.periodKey,
      generation: ctx.request.generation,
      requestSha256: ctx.requestSha256,
      requestedAtUtc: ctx.request.requestedAtUtc,
      deadlineAtUtc: ctx.request.deadlineAtUtc,
      invocationId: ctx.invocationId,
    },
    () => deps.now().getTime(),
    ctx.seeded,
  );
  const queue = new SerialStatusQueue(ctx.resumeState);
  const persist = (status: WorkerStatus) =>
    writeOwnedJsonFile(
      ctx.statusPath,
      status,
      ctx.jobDir.uid,
      MAX_STATUS_BYTES,
      "status",
    );
  const submit = (
    delta: StatusDelta,
    kind: WriteKind,
    effect?: () => Promise<void>,
  ): Promise<WorkerStatus | undefined> =>
    queue.submit({ delta, kind, effect }, writer, persist);

  // The queue serializes every write; heartbeat tasks derive their state at
  // execution from the last committed phase, so a heartbeat queued while a
  // phase write is still in flight can never report a stale phase.
  let lastState: WorkerState = ctx.resumeState;
  const advanceTo = async (
    state: WorkerState,
    effect?: () => Promise<void>,
  ): Promise<void> => {
    const target = STATE_RANK[state];
    if (target <= STATE_RANK[lastState]) return;
    for (let rank = STATE_RANK[lastState] + 1; rank <= target; rank += 1) {
      const next = WORKER_STATES.find((candidate) =>
        STATE_RANK[candidate] === rank
      )!;
      const finalStep = rank === target;
      await submit(
        { state: next },
        "phase",
        finalStep ? effect : undefined,
      );
      lastState = next;
    }
  };
  const stopHeartbeat = deps.heartbeatScheduler.start(() => {
    queue.submit({ kind: "heartbeat" }, writer, persist).catch(() => {
      // A failed heartbeat write must never crash the worker; the next
      // phase or terminal write surfaces the storage error.
    });
  }, HEARTBEAT_INTERVAL_MS);

  let captureResult: CaptureResult | undefined;
  let uploadResult: UploadResult | undefined;
  let publishedIndex: PublishedIndex | undefined;

  try {
    // A fresh job records its REQUESTED start before any phase; a resume
    // keeps the original startedAtUtc through the seeded status timestamps.
    if (ctx.fresh) {
      await submit({ state: "REQUESTED" }, "phase");
      lastState = "REQUESTED";
    }
    assertInWindow(ctx);

    // ---- CAPTURE phase: never recapture an existing stage. ----
    await phaseStep("CAPTURE_FAILED", async () => {
      let stagePresent = false;
      try {
        await assertOwnedDir(ctx.stagePath, ctx.base.uid, "capture stage");
        stagePresent = true;
      } catch (error) {
        if (error instanceof Error && error.message.includes("is missing")) {
          stagePresent = false;
        } else {
          throw new WorkerPhaseError("CAPTURE_RESULT_INVALID", error);
        }
      }
      if (stagePresent) {
        let savedCapture: unknown;
        try {
          savedCapture = await readOwnedJsonFile(
            `${ctx.stagePath}/${CAPTURE_RESULT_FILE}`,
            ctx.base.uid,
            MAX_STAGE_RESULT_BYTES,
            "capture result",
          );
          // The saved result must be strictly valid: exact roles, fixed
          // paths, sane timestamps/hashes/sizes and the pinned recipient.
          captureResult = await validateCaptureResultBound(savedCapture, ctx);
        } catch (error) {
          throw new WorkerPhaseError("CAPTURE_RESULT_INVALID", error);
        }
        await advanceTo("CAPTURED");
      } else {
        if (STATE_RANK[ctx.resumeState] >= STATE_RANK.CAPTURED) {
          throw new WorkerPhaseError("CAPTURE_RESULT_INVALID");
        }
        await advanceTo("CAPTURING");
        const fresh = await deps.capture(ctx.captureSettings);
        captureResult = await validateCaptureResultBound(fresh, ctx);
        await advanceTo("CAPTURED", async () => {
          const bytes = new TextEncoder().encode(
            `${JSON.stringify(captureResult, null, 2)}\n`,
          );
          await writeOwnedBytesCreateNew(
            `${ctx.stagePath}/${CAPTURE_RESULT_FILE}`,
            bytes,
            ctx.base.uid,
            "capture result",
          );
        });
      }
    });
    assertInWindow(ctx);

    // ---- UPLOAD phase: invoke the uploader on the valid saved capture so
    // its existing journal is reused. ----
    const stageDirectory = captureResult!.stageDirectory;
    await phaseStep("UPLOAD_FAILED", async () => {
      let savedUploadRaw: unknown | undefined;
      try {
        const uploadResultPath = `${stageDirectory}/${UPLOAD_RESULT_FILE}`;
        const bytes = await readOwnedBytesOrMissing(
          uploadResultPath,
          ctx.base.uid,
          MAX_STAGE_RESULT_BYTES,
          "upload result",
        );
        if (bytes !== null) {
          savedUploadRaw = JSON.parse(new TextDecoder().decode(bytes));
        }
      } catch (error) {
        throw new WorkerPhaseError("UPLOAD_RESULT_INVALID", error);
      }
      if (savedUploadRaw !== undefined) {
        try {
          uploadResult = validateUploadResultBound(
            savedUploadRaw,
            captureResult!,
            ctx,
          );
        } catch (error) {
          throw new WorkerPhaseError("UPLOAD_RESULT_INVALID", error);
        }
        await advanceTo("UPLOAD_VERIFIED");
      } else {
        if (STATE_RANK[ctx.resumeState] >= STATE_RANK.UPLOAD_VERIFIED) {
          throw new WorkerPhaseError("UPLOAD_RESULT_INVALID");
        }
        await advanceTo("UPLOADING");
        // Bounded retries of the whole uploader call: same capture/store on
        // every attempt, the module's journal and inventory reconciliation
        // govern each attempt, and only exact B2 transport errors retry.
        const fresh = await runPhaseWithRetries(
          ctx,
          "UPLOAD_FAILED",
          () => deps.upload(captureResult!, ctx.store),
        );
        uploadResult = validateUploadResultBound(fresh, captureResult!, ctx);
        await advanceTo("UPLOAD_VERIFIED", async () => {
          const bytes = new TextEncoder().encode(
            `${JSON.stringify(uploadResult, null, 2)}\n`,
          );
          await writeOwnedBytesCreateNew(
            `${stageDirectory}/${UPLOAD_RESULT_FILE}`,
            bytes,
            ctx.base.uid,
            "upload result",
          );
        });
      }
    });
    assertInWindow(ctx);

    // ---- INDEX phase: publish only the verified current upload result. ----
    const freshIndex = await phaseStep("INDEX_FAILED", async () => {
      let savedIndexRaw: unknown | undefined;
      try {
        const indexResultPath = `${stageDirectory}/${INDEX_RESULT_FILE}`;
        const bytes = await readOwnedBytesOrMissing(
          indexResultPath,
          ctx.base.uid,
          MAX_STAGE_RESULT_BYTES,
          "index result",
        );
        if (bytes !== null) {
          savedIndexRaw = JSON.parse(new TextDecoder().decode(bytes));
        }
      } catch (error) {
        throw new WorkerPhaseError("INDEX_RESULT_INVALID", error);
      }
      const freshIndex = savedIndexRaw === undefined;
      if (!freshIndex) {
        try {
          publishedIndex = validatePublishedIndexBound(
            savedIndexRaw,
            captureResult!,
            uploadResult!,
            ctx,
          );
        } catch (error) {
          throw new WorkerPhaseError("INDEX_RESULT_INVALID", error);
        }
        // Strict state progression: the INDEXING claim is always persisted
        // before the final terminal.
        await advanceTo("INDEXING");
      } else {
        await advanceTo("INDEXING");
        // Bounded retries of the whole publisher call: same capture/upload/
        // recipient/store on every attempt, the publisher's own state and
        // ambiguous-put reconciliation govern each attempt, and only exact
        // B2 transport errors retry.
        const fresh = await runPhaseWithRetries(
          ctx,
          "INDEX_FAILED",
          () =>
            deps.publish(
              captureResult!,
              uploadResult!,
              ctx.indexRecipient,
              ctx.store,
            ),
        );
        publishedIndex = validatePublishedIndexBound(
          fresh,
          captureResult!,
          uploadResult!,
          ctx,
        );
      }
      return freshIndex;
    });
    assertInWindow(ctx);

    // ---- FINALIZE: index result, job result, then PENDING_VERIFIER. ----
    const result: WorkerJobResult = {
      envelope: { request: ctx.request, requestSha256: ctx.requestSha256 },
      capture: captureResult!,
      upload: uploadResult!,
      publishedIndex: publishedIndex!,
    };
    const resultBytes = serializeJobResult(result);
    const resultSha256 = sha256Hex(resultBytes);
    const terminal = await submit(
      { state: "PENDING_VERIFIER", resultSha256 },
      "terminal",
      async () => {
        try {
          if (freshIndex) {
            const indexBytes = new TextEncoder().encode(
              `${JSON.stringify(publishedIndex, null, 2)}\n`,
            );
            await writeOwnedBytesCreateNew(
              `${stageDirectory}/${INDEX_RESULT_FILE}`,
              indexBytes,
              ctx.base.uid,
              "index result",
            );
          }
          await persistCreateNewOrVerify(
            ctx.resultPath,
            resultBytes,
            ctx.jobDir.uid,
            MAX_RESULT_BYTES,
            "result",
          );
        } catch (error) {
          throw new WorkerPhaseError("RESULT_FAILED", error);
        }
      },
    );
    return terminal!;
  } catch (error) {
    const code = error instanceof WorkerPhaseError
      ? error.code
      : "STATUS_FAILED";
    let terminal: WorkerStatus | undefined;
    try {
      terminal = await submit(
        { state: "FAILED", errorCode: code },
        "terminal",
      );
    } catch (terminalError) {
      throw new WorkerPhaseError(code, terminalError);
    }
    return terminal!;
  } finally {
    stopHeartbeat();
    await queue.drain();
  }
}
