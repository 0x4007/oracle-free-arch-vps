/**
 * m09 weekly Backblaze direct file-backup controller.
 *
 * The Raspberry Pi is control-only: it schedules one immutable request per
 * Sunday period (00:05 America/New_York, bounded six-hour catch-up), drives
 * detached source-side worker/verify units under the shared controller lock,
 * keeps the m06 gate, downloads only small result/receipt JSON, accepts a
 * generation into the durable catalog only after a validated verifier
 * receipt plus terminal proof, prunes older accepted generations through a
 * persisted plan and B2 metadata operations, and finally cleans the
 * source-side scratch directories. No backup payload ever transits the Pi
 * or the home connection.
 *
 * Source-side entry points:
 *   runRemoteWorker(jobId)   fixed-wired production worker run.
 *   runRemoteVerifier(jobId) reconstruct, GPG-decrypt through a task-owned
 *     extra-socket tunnel, verify, and persist receipt.json.
 *
 * The tiny per-job `entry-worker.ts` / `entry-verify.ts` wrappers are
 * generated from strictly validated UUID/revision values and import the two
 * functions above from the reviewed release root; no wrapper source file is
 * added to the project. Capture, upload, index publishing, ciphertext
 * reconstruction and decrypted verification are the integrated
 * m02/m03/m04/m05/m08 modules; gate identity/proof semantics are the
 * integrated m06 contract.
 */
import {
  assertBackblazeLaunchAllowed,
  type BackupControllerGate,
  GATE_DEADLINE_MS,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
  type OrphanReason,
  validateGate,
  validateGateClearProof,
  validateUnitInvocationId,
} from "./backblaze-controller-contract.ts";
import {
  bindInvocation,
  clearGateAfterProof,
  DEFAULT_GATE_PATH,
  markOrphaned,
  readGate,
  writeActiveGate,
} from "./backblaze-controller-gate.ts";
import type {
  CaptureResult,
  CaptureSettings,
  FileSource,
} from "./backblaze-capture.ts";
import { validateCaptureSettings } from "./backblaze-capture.ts";
import {
  buildRecoveryIndex,
  type IndexRecipient,
  type PublishedIndex,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "./backblaze-index.ts";
import type { ReconstructedGeneration } from "./backblaze-recovery.ts";
import { reconstructGeneration } from "./backblaze-recovery.ts";
import {
  deriveWorkerGate,
  requestSha256Of,
  runSourceWorker,
  sourceConfigSha256,
  validateRequest,
  validateRequestEnvelope,
  validateStatus as validateWorkerStatus,
  type WorkerRequest,
  type WorkerRequestEnvelope,
  type WorkerStatus,
  workerUnitName,
} from "./backblaze-source-worker.ts";
import {
  type B2Object,
  type B2Settings,
  B2Store,
} from "./backblaze-storage.ts";
import type { UploadResult } from "./backblaze-upload.ts";
import { UPLOAD_ROLE_ORDER } from "./backblaze-upload.ts";
import type {
  DecryptArchive,
  DecryptedVerification,
} from "./backblaze-verifier.ts";
import {
  validateVerifierReceipt,
  verifyDecryptedGeneration,
} from "./backblaze-verifier.ts";
import { withBackupLock } from "./backup-lock.ts";
import { shellQuote } from "./backup-guest.ts";
import type { CommandResult } from "./oci.ts";
import { readPrivateJson, writePrivateJson } from "./oci.ts";

// ---------------------------------------------------------------------------
// Fixed identities
// ---------------------------------------------------------------------------

export const PI_CONTROLLER_CWD = "/home/pi/ops/weekly-backup-controller";
export const SOURCE_HOST = "codex@vps.pavlovcik.com";
export const BACKUP_BASE = "/var/tmp/arch-vps-file-backup";
export const BACKUP_RUNTIME_BASE = "/var/tmp/arch-vps-file-backup-runtime";
export const RELEASES_ROOT = `${BACKUP_RUNTIME_BASE}/releases`;
export const JOBS_RUNTIME_ROOT = `${BACKUP_RUNTIME_BASE}/jobs`;
export const RECOVERY_BASE = "/var/tmp/arch-vps-file-recovery";
export const VERIFICATION_BASE = "/var/tmp/arch-vps-file-verification";
export const PUBLIC_HOME_BASE = "/home/codex/.local/share/arch-vps-verifier";
export const SOURCE_LOCK_PATH = GATE_SOURCE_LOCK_PATH;
export const GATE_PATH = DEFAULT_GATE_PATH;
export const CONTROLLER_LOCK_PATH = ".private/backup-controller.lock";
export const CONTROLLER_STATE_PATH = ".private/file-backup/controller.json";
export const PIP_JOB_EVIDENCE_PATH = ".private/file-backup/jobs";
export const DEPLOYMENT_PATH = ".private/backblaze-deployment.json";
export const B2_CONFIG_PATH = ".private/b2-file-backup.json";
export const RECIPIENT_PATH = ".private/file-backup/recipient.asc";
export const PI_KEYRING_PATH = ".private/file-backup/gnupg";
export const B2_REPORT_PATH = ".private/reports/backblaze-file-backup.json";

export const SCHEDULE_ZONE = "America/New_York";
export const SCHEDULE_HOUR = 0;
export const SCHEDULE_MINUTE = 5;
export const CATCH_UP_MS = GATE_DEADLINE_MS;
export const HEARTBEAT_INTERVAL_MS = 30_000;
export const POLL_INTERVAL_MS = 30_000;
export const STALE_AFTER_MS = 3 * HEARTBEAT_INTERVAL_MS;
export const KEEP_ACCEPTED = 4;

export const STATUS_FILE = "status.json";
export const RESULT_FILE = "result.json";
export const RECEIPT_FILE = "receipt.json";
export const VERIFIER_REQUEST_FILE = "verifier-request.json";
export const SETTINGS_FILE = "settings.json";
export const RECIPIENT_FILE = "recipient.asc";
export const ENTRY_WORKER_FILE = "entry-worker.ts";
export const ENTRY_VERIFY_FILE = "entry-verify.ts";
export const RELEASE_MANIFEST_FILE = "release.json";
export const MANIFEST_PATH = ".private/backup-scheduled-window.json";

const MAX_STATUS_BYTES = 64 * 1024;
const MAX_RESULT_BYTES = 8 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_SETTINGS_BYTES = 64 * 1024;
const MAX_GPG_DIAGNOSTIC_BYTES = 256 * 1024;

const VERIFIER_GIB = 1024 ** 3;
const VERIFIER_MIB = 1024 ** 2;
/** Same free-space constants as the capture stage: after every verifier
 * write the recovery/verification filesystem must still keep the 5 GiB
 * reserve plus the 512 MiB margin free. */
const VERIFIER_SPACE_RESERVE = 5 * VERIFIER_GIB;
const VERIFIER_SPACE_MARGIN = 512 * VERIFIER_MIB;
const VERIFIER_SPACE_MIN_FREE = VERIFIER_SPACE_RESERVE + VERIFIER_SPACE_MARGIN;

const JOB_ID_PATTERN =
  /^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/;
const UNIT_NAME_PATTERN =
  /^arch-vps-b2-(worker|verify|prune)-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.service$/;
const CANONICAL_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PERIOD_KEY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

const DIRECT_PREFIX = "restic/direct-v1/";
const GENERATIONS_PREFIX = `${DIRECT_PREFIX}generations/`;
const INDEXES_PREFIX = `${DIRECT_PREFIX}indexes/`;

const SSH_FLAGS = [
  "-o",
  "BatchMode=yes",
  "-o",
  "StrictHostKeyChecking=yes",
  "-o",
  "ConnectTimeout=10",
  "-o",
  "ServerAliveInterval=15",
  "-o",
  "ServerAliveCountMax=3",
] as const;

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

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

function canonicalUtc(value: unknown, name: string): string {
  if (
    typeof value !== "string" || !CANONICAL_UTC_PATTERN.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    throw new Error(`${name} must be a canonical millisecond ISO UTC string`);
  }
  return value;
}

export function validateJobId(jobId: unknown): string {
  if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) {
    throw new Error("jobId must be job- plus a lower-case UUID");
  }
  return jobId;
}

export function validateGeneration(generation: unknown): string {
  if (
    typeof generation !== "string" || !GENERATION_PATTERN.test(generation) ||
    generation.slice("generation-".length) !==
      validateJobId(`job-${generation.slice("generation-".length)}`).slice(
        "job-".length,
      )
  ) {
    throw new Error("generation must be generation- plus its job UUID");
  }
  return generation;
}

function validatePeriodKey(value: unknown): string {
  if (typeof value !== "string" || !PERIOD_KEY_PATTERN.test(value)) {
    throw new Error("periodKey must be a YYYY-MM-DD Sunday calendar date");
  }
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day || date.getUTCDay() !== 0
  ) {
    throw new Error("periodKey must be a valid Sunday calendar date");
  }
  return value;
}

export function validateRevision(value: unknown): string {
  if (typeof value !== "string" || !REVISION_PATTERN.test(value)) {
    throw new Error("sourceRevision must be 40 lower-case hex characters");
  }
  return value;
}

export function validateUnitName(value: unknown): string {
  if (typeof value !== "string" || !UNIT_NAME_PATTERN.test(value)) {
    throw new Error("Unit name is not a canonical B2 unit name");
  }
  return value;
}

// ---------------------------------------------------------------------------
// Sunday period window (DST-safe)
// ---------------------------------------------------------------------------

interface ZoneParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  weekday: number;
}

function zoneParts(date: Date, zone: string): ZoneParts {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const values = Object.fromEntries(
    parts.map((part) => [part.type, part.value]),
  );
  return {
    year: Number(values.year),
    month: Number(values.month),
    day: Number(values.day),
    hour: Number(values.hour),
    minute: Number(values.minute),
    second: Number(values.second),
    weekday: new Date(
      Date.UTC(
        Number(values.year),
        Number(values.month) - 1,
        Number(values.day),
      ),
    ).getUTCDay(),
  };
}

/** UTC instant of a civil wall time in the zone; fixed-point offset solve.
 * 00:05 never falls inside a DST gap, so the solved instant is unambiguous. */
function instantForCivil(
  zone: string,
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
): number {
  const target = Date.UTC(year, month - 1, day, hour, minute);
  let guess = target;
  for (let round = 0; round < 3; round += 1) {
    const parts = zoneParts(new Date(guess), zone);
    const asUtc = Date.UTC(
      parts.year,
      parts.month - 1,
      parts.day,
      parts.hour,
      parts.minute,
      parts.second,
    );
    guess = target - (asUtc - guess);
  }
  const parts = zoneParts(new Date(guess), zone);
  if (
    parts.year !== year || parts.month !== month || parts.day !== day ||
    parts.hour !== hour || parts.minute !== minute
  ) {
    throw new Error("Scheduled wall time is not representable in the zone");
  }
  return guess;
}

export interface WeekWindow {
  periodKey: string;
  startAtUtc: string;
  endAtUtc: string;
}

/** Most recent Sunday 00:05 zone window and its six-hour catch-up end. */
export function weekWindow(
  now: Date,
  zone: string = SCHEDULE_ZONE,
): WeekWindow {
  const parts = zoneParts(now, zone);
  const daysBack = parts.weekday;
  const sunday = new Date(
    Date.UTC(parts.year, parts.month - 1, parts.day - daysBack),
  );
  const start = instantForCivil(
    zone,
    sunday.getUTCFullYear(),
    sunday.getUTCMonth() + 1,
    sunday.getUTCDate(),
    SCHEDULE_HOUR,
    SCHEDULE_MINUTE,
  );
  return {
    periodKey: sunday.toISOString().slice(0, 10),
    startAtUtc: new Date(start).toISOString(),
    endAtUtc: new Date(start + CATCH_UP_MS).toISOString(),
  };
}

export function withinCatchUp(
  now: Date,
  zone: string = SCHEDULE_ZONE,
): boolean {
  const window = weekWindow(now, zone);
  return Date.parse(window.startAtUtc) <= now.getTime() &&
    now.getTime() < Date.parse(window.endAtUtc);
}

// ---------------------------------------------------------------------------
// Request identity
// ---------------------------------------------------------------------------

export interface RequestParts {
  jobUuid: string;
  periodKey: string;
  requestedAtUtc: string;
  recipientSha256: string;
  recipientFingerprint: string;
  sourceRevision: string;
  sourceConfigSha256: string;
}

/** The immutable per-period request; deadline is request instant + 6h. */
export function buildRequestEnvelope(parts: RequestParts): {
  request: WorkerRequest;
  requestSha256: string;
} {
  const jobId = validateJobId(`job-${parts.jobUuid}`);
  const generation = validateGeneration(`generation-${parts.jobUuid}`);
  const requestedAtUtc = canonicalUtc(parts.requestedAtUtc, "requestedAtUtc");
  const deadlineAtUtc = new Date(
    Date.parse(requestedAtUtc) + GATE_DEADLINE_MS,
  ).toISOString();
  if (!SHA256_PATTERN.test(parts.recipientSha256)) {
    throw new Error("recipientSha256 must be 64 lower-case hex characters");
  }
  if (!FINGERPRINT_PATTERN.test(parts.recipientFingerprint)) {
    throw new Error(
      "recipientFingerprint must be 40 uppercase hex characters",
    );
  }
  if (!SHA256_PATTERN.test(parts.sourceConfigSha256)) {
    throw new Error("sourceConfigSha256 must be 64 lower-case hex characters");
  }
  const request = validateRequest({
    schemaVersion: 1,
    jobId,
    periodKey: validatePeriodKey(parts.periodKey),
    generation,
    requestedAtUtc,
    deadlineAtUtc,
    recipientSha256: parts.recipientSha256,
    recipientFingerprint: parts.recipientFingerprint,
    sourceRevision: validateRevision(parts.sourceRevision),
    sourceConfigSha256: parts.sourceConfigSha256,
  });
  return { request, requestSha256: requestSha256Of(request) };
}

export function workerUnitNameOf(generation: string): string {
  return workerUnitName(validateGeneration(generation));
}

export function verifyUnitName(generation: string): string {
  const uuid = validateGeneration(generation).slice("generation-".length);
  return `arch-vps-b2-verify-${uuid}.service`;
}

/** Verifier gate with the same immutable identity and the fixed verify unit.
 * The observed unit may be worker or verify; identity always binds the job. */
export function deriveVerifierGate(
  request: WorkerRequest,
  requestSha256: string,
): BackupControllerGate {
  const validated = validateRequest(request);
  return validateGate({
    schemaVersion: 1,
    owner: GATE_OWNER,
    state: "active",
    jobId: validated.jobId,
    periodKey: validated.periodKey,
    generation: validated.generation,
    requestSha256,
    requestedAtUtc: validated.requestedAtUtc,
    deadlineAtUtc: validated.deadlineAtUtc,
    createdAtUtc: validated.requestedAtUtc,
    updatedAtUtc: validated.requestedAtUtc,
    remoteHost: GATE_REMOTE_HOST,
    unitName: verifyUnitName(validated.generation),
    unitInvocationId: null,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
  });
}

// ---------------------------------------------------------------------------
// Verifier status schema (m06 proof fields + receipt hash)
// ---------------------------------------------------------------------------

export type VerifierState = "VERIFYING" | "ACCEPTED" | "FAILED";

export type VerifierErrorCode =
  | "REJECTED"
  | "RESULT_INVALID"
  | "RECONSTRUCT_FAILED"
  | "DECRYPT_FAILED"
  | "VERIFY_FAILED"
  | "RECEIPT_FAILED"
  | "STATUS_FAILED";

export const VERIFIER_ERROR_CODES: readonly VerifierErrorCode[] = [
  "REJECTED",
  "RESULT_INVALID",
  "RECONSTRUCT_FAILED",
  "DECRYPT_FAILED",
  "VERIFY_FAILED",
  "RECEIPT_FAILED",
  "STATUS_FAILED",
];

export interface VerifierStatus {
  schemaVersion: 1;
  jobId: string;
  periodKey: string;
  generation: string;
  requestSha256: string;
  requestedAtUtc: string;
  deadlineAtUtc: string;
  invocationId: string;
  state: VerifierState;
  startedAtUtc: string;
  updatedAtUtc: string;
  heartbeatAtUtc: string;
  finishedAtUtc: string | null;
  errorCode?: VerifierErrorCode;
  receiptSha256?: string;
}

const VERIFIER_STATUS_KEYS = new Set([
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
  "receiptSha256",
]);

export function validateVerifierStatus(input: unknown): VerifierStatus {
  if (!isRecord(input)) {
    throw new Error("Verifier status must be a JSON object");
  }
  rejectUnknownKeys(input, VERIFIER_STATUS_KEYS, "Verifier status");
  if (input.schemaVersion !== 1) {
    throw new Error("Verifier status schemaVersion must be 1");
  }
  const jobId = validateJobId(input.jobId);
  const periodKey = validatePeriodKey(input.periodKey);
  const generation = validateGeneration(input.generation);
  const requestedAtUtc = canonicalUtc(input.requestedAtUtc, "requestedAtUtc");
  const deadlineAtUtc = canonicalUtc(input.deadlineAtUtc, "deadlineAtUtc");
  if (
    Date.parse(deadlineAtUtc) !== Date.parse(requestedAtUtc) + GATE_DEADLINE_MS
  ) {
    throw new Error(
      "Verifier status deadlineAtUtc must be exactly requestedAtUtc plus 6 hours",
    );
  }
  const invocationId = validateUnitInvocationId(input.invocationId);
  const state = input.state;
  if (state !== "VERIFYING" && state !== "ACCEPTED" && state !== "FAILED") {
    throw new Error("Verifier status state is unsupported");
  }
  const startedAtUtc = canonicalUtc(input.startedAtUtc, "startedAtUtc");
  const updatedAtUtc = canonicalUtc(input.updatedAtUtc, "updatedAtUtc");
  const heartbeatAtUtc = canonicalUtc(input.heartbeatAtUtc, "heartbeatAtUtc");
  if (
    Date.parse(startedAtUtc) < Date.parse(requestedAtUtc) ||
    Date.parse(heartbeatAtUtc) < Date.parse(startedAtUtc) ||
    Date.parse(updatedAtUtc) < Date.parse(heartbeatAtUtc)
  ) {
    throw new Error("Verifier status timestamps are not monotonic");
  }
  const terminal = state === "ACCEPTED" || state === "FAILED";
  if (terminal && input.finishedAtUtc === null) {
    throw new Error("A terminal verifier status requires finishedAtUtc");
  }
  if (!terminal && input.finishedAtUtc !== null) {
    throw new Error(
      "A nonterminal verifier status must have finishedAtUtc null",
    );
  }
  let finishedAtUtc: string | null = null;
  if (terminal) {
    finishedAtUtc = canonicalUtc(input.finishedAtUtc, "finishedAtUtc");
    if (
      Date.parse(finishedAtUtc) < Date.parse(startedAtUtc) ||
      Date.parse(updatedAtUtc) < Date.parse(finishedAtUtc)
    ) {
      throw new Error("Verifier status terminal timestamps are inconsistent");
    }
  }
  if ("errorCode" in input && state !== "FAILED") {
    throw new Error("errorCode is only valid on a FAILED verifier status");
  }
  if ("receiptSha256" in input && state !== "ACCEPTED") {
    throw new Error(
      "receiptSha256 is only valid on an ACCEPTED verifier status",
    );
  }
  let errorCode: VerifierErrorCode | undefined;
  if (state === "FAILED") {
    if (!("errorCode" in input)) {
      throw new Error("A FAILED verifier status requires errorCode");
    }
    errorCode = input.errorCode as VerifierErrorCode;
    if (
      typeof errorCode !== "string" ||
      !(VERIFIER_ERROR_CODES as readonly string[]).includes(errorCode)
    ) {
      throw new Error("Verifier status errorCode is not a fixed code");
    }
  }
  let receiptSha256: string | undefined;
  if (state === "ACCEPTED") {
    if (!("receiptSha256" in input)) {
      throw new Error("An ACCEPTED verifier status requires receiptSha256");
    }
    receiptSha256 = input.receiptSha256 as string;
    if (
      typeof receiptSha256 !== "string" || !SHA256_PATTERN.test(receiptSha256)
    ) {
      throw new Error(
        "Verifier status receiptSha256 must be 64 hex characters",
      );
    }
  }
  return {
    schemaVersion: 1,
    jobId,
    periodKey,
    generation,
    requestSha256: input.requestSha256 as string,
    requestedAtUtc,
    deadlineAtUtc,
    invocationId,
    state: state as VerifierState,
    startedAtUtc,
    updatedAtUtc,
    heartbeatAtUtc,
    finishedAtUtc,
    ...(errorCode === undefined ? {} : { errorCode }),
    ...(receiptSha256 === undefined ? {} : { receiptSha256 }),
  };
}

// ---------------------------------------------------------------------------
// Saved worker result validation (pure)
// ---------------------------------------------------------------------------

export interface SavedWorkerResult {
  envelope: WorkerRequestEnvelope;
  capture: CaptureResult;
  upload: UploadResult;
  publishedIndex: PublishedIndex;
  index: RecoveryIndex;
  indexSha256: string;
}

export interface WorkerResultBinding {
  requestSha256: string;
  generation: string;
  recipientSha256: string;
  recipientFingerprint: string;
}

export async function validateSavedWorkerResult(
  raw: unknown,
  recipient: IndexRecipient,
  binding: WorkerResultBinding,
): Promise<SavedWorkerResult> {
  if (!isRecord(raw)) throw new Error("Worker result must be a JSON object");
  const envelope = validateRequestEnvelope(raw.envelope);
  if (envelope.requestSha256 !== binding.requestSha256) {
    throw new Error("Saved result request hash does not match the job");
  }
  if (envelope.request.generation !== binding.generation) {
    throw new Error("Saved result generation does not match the job");
  }
  const capture = raw.capture as CaptureResult;
  const upload = raw.upload as UploadResult;
  const publishedIndex = raw.publishedIndex as PublishedIndex;
  if (!isRecord(capture) || !isRecord(upload) || !isRecord(publishedIndex)) {
    throw new Error("Saved result phase results are malformed");
  }
  const index = buildRecoveryIndex(capture, upload, recipient);
  const indexBytes = new TextEncoder().encode(JSON.stringify(index));
  const indexSha256 = await sha256Hex(indexBytes);
  if (indexSha256 !== publishedIndex.indexSha256) {
    throw new Error("Saved published index hash differs from the built index");
  }
  if (publishedIndex.generation !== binding.generation) {
    throw new Error("Saved published index generation does not match the job");
  }
  if (index.recipientSha256 !== binding.recipientSha256) {
    throw new Error("Saved index recipient does not match the job");
  }
  if (index.recipientFingerprint !== binding.recipientFingerprint) {
    throw new Error(
      "Saved index recipient fingerprint does not match the job",
    );
  }
  if (
    publishedIndex.uploadVerified !== true ||
    publishedIndex.decryptedRestoreProved !== false ||
    publishedIndex.machineBootRestoreProved !== false
  ) {
    throw new Error("Published index flags are not the verified state");
  }
  return { envelope, capture, upload, publishedIndex, index, indexSha256 };
}

// ---------------------------------------------------------------------------
// Receipt binding (pure)
// ---------------------------------------------------------------------------

export interface ReceiptBinding {
  generation: string;
  indexSha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
}

export function validateAcceptedReceipt(
  raw: unknown,
  index: RecoveryIndex,
  binding: ReceiptBinding,
): DecryptedVerification {
  const receipt = validateVerifierReceipt(raw);
  if (receipt.generation !== binding.generation) {
    throw new Error("Receipt generation does not match the job");
  }
  if (receipt.indexSha256 !== binding.indexSha256) {
    throw new Error("Receipt index hash does not match the published index");
  }
  if (receipt.recipientSha256 !== binding.recipientSha256) {
    throw new Error("Receipt recipient does not match the job");
  }
  if (receipt.recipientFingerprint !== binding.recipientFingerprint) {
    throw new Error("Receipt recipient fingerprint does not match the job");
  }
  if (receipt.archives.length !== index.archives.length) {
    throw new Error("Receipt archive count does not match the index");
  }
  for (let i = 0; i < index.archives.length; i += 1) {
    const expected = index.archives[i];
    const actual = receipt.archives[i];
    if (actual.role !== expected.role || actual.format !== expected.format) {
      throw new Error("Receipt archive role does not match the index");
    }
    if (
      actual.ciphertextBytes !== expected.bytes ||
      actual.ciphertextSha256 !== expected.sha256
    ) {
      throw new Error("Receipt ciphertext identity does not match the index");
    }
  }
  return receipt;
}

// ---------------------------------------------------------------------------
// Transport settings and release manifest
// ---------------------------------------------------------------------------

const SETTINGS_KEYS = new Set([
  "schemaVersion",
  "envelope",
  "captureSettings",
  "indexRecipient",
  "B2Settings",
  "sourceRevision",
]);

const B2_SETTINGS_KEYS = new Set([
  "accessKeyId",
  "secretAccessKey",
  "bucketId",
  "bucketName",
]);

const INDEX_RECIPIENT_KEYS = new Set([
  "recipientFile",
  "recipientSha256",
  "recipientFingerprint",
]);

export interface TransportSettings {
  schemaVersion: 1;
  envelope: WorkerRequestEnvelope;
  captureSettings: CaptureSettings;
  indexRecipient: IndexRecipient;
  B2Settings: B2Settings;
  sourceRevision: string;
}

export function validateTransportSettings(input: unknown): TransportSettings {
  if (!isRecord(input)) throw new Error("Settings must be a JSON object");
  rejectUnknownKeys(input, SETTINGS_KEYS, "Settings");
  if (input.schemaVersion !== 1) {
    throw new Error("Settings schemaVersion must be 1");
  }
  const envelope = validateRequestEnvelope(input.envelope);
  const captureSettings = structuredClone(
    input.captureSettings,
  ) as CaptureSettings;
  validateCaptureSettings(captureSettings);
  if (captureSettings.generation !== envelope.request.generation) {
    throw new Error("Settings capture generation does not match the request");
  }
  const recipient = input.indexRecipient;
  if (!isRecord(recipient)) {
    throw new Error("Settings indexRecipient must be an object");
  }
  rejectUnknownKeys(recipient, INDEX_RECIPIENT_KEYS, "Settings indexRecipient");
  if (
    recipient.recipientFile !== captureSettings.recipientFile ||
    recipient.recipientSha256 !== captureSettings.recipientSha256 ||
    recipient.recipientFingerprint !==
      captureSettings.recipientFingerprint ||
    recipient.recipientSha256 !== envelope.request.recipientSha256 ||
    recipient.recipientFingerprint !== envelope.request.recipientFingerprint
  ) {
    throw new Error("Settings recipient identity is not consistent");
  }
  const b2 = input.B2Settings;
  if (!isRecord(b2)) throw new Error("Settings B2Settings must be an object");
  rejectUnknownKeys(b2, B2_SETTINGS_KEYS, "Settings B2Settings");
  for (
    const key of ["accessKeyId", "secretAccessKey", "bucketId", "bucketName"]
  ) {
    if (typeof b2[key] !== "string" || b2[key] === "") {
      throw new Error(`Settings B2Settings ${key} must be a non-empty string`);
    }
  }
  const sourceRevision = validateRevision(input.sourceRevision);
  if (sourceRevision !== envelope.request.sourceRevision) {
    throw new Error("Settings sourceRevision does not match the request");
  }
  return {
    schemaVersion: 1,
    envelope,
    captureSettings,
    indexRecipient: {
      recipientFile: recipient.recipientFile as string,
      recipientSha256: recipient.recipientSha256 as string,
      recipientFingerprint: recipient.recipientFingerprint as string,
    },
    B2Settings: {
      accessKeyId: b2.accessKeyId as string,
      secretAccessKey: b2.secretAccessKey as string,
      bucketId: b2.bucketId as string,
      bucketName: b2.bucketName as string,
    },
    sourceRevision,
  };
}

export interface ReleaseManifest {
  sourceRevision: string;
  files: { path: string; sha256: string }[];
}

const RELEASE_PATH_PATTERN = /^scripts\/[A-Za-z0-9_.-]+\.ts$/;

export function validateReleaseManifest(
  input: unknown,
  sourceRevision: string,
): ReleaseManifest {
  if (!isRecord(input)) {
    throw new Error("Release manifest must be a JSON object");
  }
  if (
    Object.keys(input).length !== 2 ||
    input.sourceRevision !== sourceRevision
  ) {
    throw new Error("Release manifest revision differs from the request");
  }
  if (!Array.isArray(input.files)) {
    throw new Error("Release manifest files must be an array");
  }
  const paths = new Set<string>();
  const files: { path: string; sha256: string }[] = [];
  for (const entry of input.files) {
    if (!isRecord(entry) || Object.keys(entry).length !== 2) {
      throw new Error("Release manifest entry is malformed");
    }
    if (
      typeof entry.path !== "string" ||
      !RELEASE_PATH_PATTERN.test(entry.path) ||
      paths.has(entry.path)
    ) {
      throw new Error("Release manifest contains a disallowed path");
    }
    if (
      typeof entry.sha256 !== "string" ||
      !SHA256_PATTERN.test(entry.sha256)
    ) {
      throw new Error("Release manifest contains a malformed hash");
    }
    paths.add(entry.path);
    files.push({ path: entry.path, sha256: entry.sha256 });
  }
  if (files.length === 0) {
    throw new Error("Release manifest contains no scripts");
  }
  return { sourceRevision, files };
}

/** Generated trusted runtime wrapper; jobId and revision are validated again
 * before interpolation so no unvalidated value reaches the source. */
export function entryWorkerText(jobId: string, sourceRevision: string): string {
  const id = validateJobId(jobId);
  const revision = validateRevision(sourceRevision);
  return [
    "// Generated trusted worker wrapper; do not edit.",
    `import { runRemoteWorker } from "${RELEASES_ROOT}/${revision}/scripts/backblaze-file-backup.ts";`,
    "if (import.meta.main) {",
    "  try {",
    `    await runRemoteWorker(${JSON.stringify(id)});`,
    "  } catch (error) {",
    '    console.error("remote worker failed: " + (error instanceof Error ? error.message : String(error)));',
    "    Deno.exitCode = 1;",
    "  }",
    "}",
    "",
  ].join("\n");
}

export function entryVerifyText(jobId: string, sourceRevision: string): string {
  const id = validateJobId(jobId);
  const revision = validateRevision(sourceRevision);
  return [
    "// Generated trusted verifier wrapper; do not edit.",
    `import { runRemoteVerifier } from "${RELEASES_ROOT}/${revision}/scripts/backblaze-file-backup.ts";`,
    "if (import.meta.main) {",
    "  try {",
    `    await runRemoteVerifier(${JSON.stringify(id)});`,
    "  } catch (error) {",
    '    console.error("remote verifier failed: " + (error instanceof Error ? error.message : String(error)));',
    "    Deno.exitCode = 1;",
    "  }",
    "}",
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// GPG status parsing (pure)
// ---------------------------------------------------------------------------

export interface GpgIntegrityDecision {
  decryptionOkay: boolean;
  integrityOk: boolean;
  rejected: boolean;
}

/** Parse bounded `--status-fd=2` diagnostics; BADMDC/DECRYPTION_FAILED/ERROR/
 * FAILURE lines reject, and DECRYPTION_OKAY plus GOODMDC or the AEAD
 * DECRYPTION_INFO pattern are both required for a clean decryption. */
export function decideGpgStatus(lines: string[]): GpgIntegrityDecision {
  let decryptionOkay = false;
  let integrityOk = false;
  let rejected = false;
  for (const line of lines) {
    if (line === "[GNUPG:] DECRYPTION_OKAY") decryptionOkay = true;
    if (line === "[GNUPG:] GOODMDC") integrityOk = true;
    if (/^\[GNUPG:\] DECRYPTION_INFO \d+ \d+ [1-9]\d*$/.test(line)) {
      integrityOk = true;
    }
    if (/^\[GNUPG:\] (BADMDC|DECRYPTION_FAILED|ERROR|FAILURE)\b/.test(line)) {
      rejected = true;
    }
  }
  return {
    decryptionOkay,
    integrityOk,
    rejected: rejected || !decryptionOkay || !integrityOk,
  };
}

// ---------------------------------------------------------------------------
// Source-side root-owned bounded IO
// ---------------------------------------------------------------------------

async function assertRootDir(path: string, what: string): Promise<string> {
  if (typeof path !== "string" || path === "" || path.includes("\0")) {
    throw new Error(`${what} directory path is invalid`);
  }
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
  if (info.uid !== 0) throw new Error(`${what} must be owned by root`);
  const real = await Deno.realPath(path);
  if (real !== path) {
    throw new Error(`${what} must not be reached through a symlink`);
  }
  return real;
}

async function readRootBounded(
  path: string,
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
  if (info.isSymlink || !info.isFile) {
    throw new Error(`${what} must be a regular file, never a symlink`);
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    throw new Error(`${what} must grant only owner access (0600)`);
  }
  if (info.uid !== 0) throw new Error(`${what} must be owned by root`);
  if (info.size > maxBytes) {
    throw new Error(`${what} exceeds the ${maxBytes} byte read bound`);
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
    return data.slice();
  } finally {
    handle.close();
  }
}

async function writeRootAtomic(
  path: string,
  bytes: Uint8Array,
  what: string,
  createNew: boolean,
): Promise<void> {
  const slash = path.lastIndexOf("/");
  const parent = await assertRootDir(path.slice(0, slash), `${what} parent`);
  const base = path.slice(slash + 1);
  if (createNew) {
    try {
      await Deno.lstat(`${parent}/${base}`);
      const existing = await readRootBounded(
        `${parent}/${base}`,
        bytes.length,
        what,
      );
      if (existing.byteLength !== bytes.byteLength) {
        throw new Error(`${what} already exists with different bytes`);
      }
      for (let i = 0; i < bytes.byteLength; i += 1) {
        if (existing[i] !== bytes[i]) {
          throw new Error(`${what} already exists with different bytes`);
        }
      }
      return;
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  }
  const temp = `${parent}/.${base}.${crypto.randomUUID()}.tmp`;
  const handle = await Deno.open(temp, {
    createNew: true,
    write: true,
    mode: 0o600,
  });
  try {
    let offset = 0;
    while (offset < bytes.byteLength) {
      const written = await handle.write(bytes.subarray(offset));
      if (!Number.isSafeInteger(written) || written <= 0) {
        throw new Error(`${what} temp write made no progress`);
      }
      offset += written;
    }
    await handle.sync();
  } finally {
    handle.close();
  }
  await Deno.chmod(temp, 0o600);
  try {
    await Deno.rename(temp, `${parent}/${base}`);
  } catch (error) {
    await Deno.remove(temp).catch(() => {});
    throw error;
  }
  const final = await Deno.lstat(`${parent}/${base}`);
  if (
    !final.isFile || final.uid !== 0 ||
    final.size !== bytes.byteLength ||
    final.mode === null || (final.mode & 0o777) !== 0o600
  ) {
    throw new Error(`${what} final identity is wrong after publication`);
  }
}

// ---------------------------------------------------------------------------
// Remote seams (Pi side)
// ---------------------------------------------------------------------------

export type RemoteRunner = (
  command: string,
  args: string[],
  input?: Uint8Array,
) => Promise<CommandResult>;

export const realRemoteRunner: RemoteRunner = async (command, args, input) => {
  const child = new Deno.Command(command, {
    args,
    stdin: input === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  if (input !== undefined) {
    const writer = child.stdin.getWriter();
    try {
      await writer.write(input);
    } catch {
      // The remote command exited early; its status is authoritative.
    }
    try {
      await writer.close();
    } catch {
      // Already closed.
    }
  }
  const output = await child.output();
  return {
    code: (await child.status).code,
    stdout: new TextDecoder().decode(output.stdout),
    stderr: new TextDecoder().decode(output.stderr),
  };
};

export interface ObservedUnit {
  props: Map<string, string>;
  status: unknown | null;
  lockFree: boolean;
  reachable: boolean;
}

/** Normalize an observed unit's invocation id. `systemctl show` answers
 * reachable=true for a named but absent unit (LoadState=not-found) and
 * prints an empty InvocationID or omits the property entirely, so both
 * undefined and "" mean "no invocation" and must never count as a running
 * one. A nonempty value is validated and returned exactly: a malformed
 * identity fails closed instead of silently binding or launching a
 * replacement. */
function normalizeObservedInvocation(
  props: Map<string, string>,
): string | null {
  const value = props.get("InvocationID");
  if (value === undefined || value === "") return null;
  return validateUnitInvocationId(value);
}

export interface RemoteSeam {
  source(script: string): Promise<CommandResult>;
  root(script: string): Promise<CommandResult>;
  installer(payload: unknown): Promise<CommandResult>;
  launchUnit(spec: {
    unitName: string;
    runtimeDir: string;
    remainingSec: number;
    args: string[];
  }): Promise<CommandResult>;
  observe(unitName: string, jobId: string): Promise<ObservedUnit>;
  resolveAgentSocket(
    publicHome: string,
  ): Promise<{ socket: string; defaultSocket: string }>;
}

const REMOTE_INSTALLER = String.raw`
const payload = JSON.parse(new TextDecoder().decode(await new Response(Deno.stdin.readable).arrayBuffer()));
const jobId = payload.jobId;
if (!/^job-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(jobId)) throw new Error("Invalid jobId");
const revision = payload.sourceRevision;
if (!/^[0-9a-f]{40}$/.test(revision)) throw new Error("Invalid revision");
const runtime = "/var/tmp/arch-vps-file-backup-runtime/jobs/" + jobId;
const releases = "/var/tmp/arch-vps-file-backup-runtime/releases";
async function safeBase(path) {
  const b = await Deno.lstat(path);
  if (!b.isDirectory || b.isSymlink || b.uid !== 0 || (b.mode & 0o077) || await Deno.realPath(path) !== path) throw new Error("Unsafe runtime base");
}
async function safeDir(path) {
  const b = await Deno.lstat(path);
  if (!b.isDirectory || b.isSymlink || b.uid !== 0 || (b.mode & 0o777) !== 0o700 || await Deno.realPath(path) !== path) throw new Error("Unsafe runtime directory");
}
await safeBase("/var/tmp/arch-vps-file-backup-runtime");
await safeBase(releases);
const releaseRoot = releases + "/" + revision;
await safeDir(releaseRoot);
await safeDir(releaseRoot + "/scripts");
const manifestValue = JSON.parse(new TextDecoder().decode(await Deno.readFile(releaseRoot + "/release.json")));
if (manifestValue.sourceRevision !== revision || !Array.isArray(manifestValue.files)) throw new Error("Release manifest invalid");
const paths = new Set();
for (const entry of manifestValue.files) {
  if (typeof entry.path !== "string" || !/^scripts\/[A-Za-z0-9_.-]+\.ts$/.test(entry.path) || paths.has(entry.path) || typeof entry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error("Release manifest entry invalid");
  paths.add(entry.path);
}
if (paths.size === 0) throw new Error("Release manifest empty");
for (const entry of manifestValue.files) {
  const info = await Deno.lstat(releaseRoot + "/" + entry.path);
  if (!info.isFile || info.isSymlink || info.uid !== 0 || (info.mode & 0o077)) throw new Error("Release file unsafe");
  const bytes = await Deno.readFile(releaseRoot + "/" + entry.path);
  const h = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), x => x.toString(16).padStart(2, "0")).join("");
  if (h !== entry.sha256) throw new Error("Release file hash mismatch: " + entry.path);
}
try { await Deno.mkdir(runtime, { mode: 0o700 }); } catch (error) { if (!(error instanceof Deno.errors.AlreadyExists)) throw error; }
await safeDir(runtime);
for (const entry of payload.files) {
  if (!["settings.json", "recipient.asc", "entry-worker.ts", "entry-verify.ts"].includes(entry.path)) throw new Error("Disallowed runtime file: " + entry.path);
  const bytes = new Uint8Array(entry.data);
  const h = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), x => x.toString(16).padStart(2, "0")).join("");
  if (h !== entry.sha256) throw new Error("Transfer hash mismatch: " + entry.path);
  const finalPath = runtime + "/" + entry.path;
  try {
    const existing = await Deno.readFile(finalPath);
    if (existing.byteLength !== bytes.byteLength) throw new Error("Runtime file differs: " + entry.path);
    for (let i = 0; i < bytes.byteLength; i++) if (existing[i] !== bytes[i]) throw new Error("Runtime file differs: " + entry.path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) await Deno.writeFile(finalPath, bytes, { createNew: true, mode: 0o600 });
    else throw error;
  }
  await Deno.chmod(finalPath, 0o600);
}
console.log(JSON.stringify({ installed: true, runtime, revision, files: payload.files.length, released: manifestValue.files.length }));
`.trim();

const ROOT_OBSERVE = (unitName: string, jobId: string): string => {
  const name = validateUnitName(unitName);
  validateJobId(jobId);
  return [
    "set -eu",
    `unit=${shellQuote(name)}`,
    `props=$(systemctl show --property=LoadState --property=ActiveState --property=SubState --property=Result --property=MainPID --property=ControlPID --property=ControlGroup --property=TasksCurrent --property=InvocationID --no-pager "$unit" 2>/dev/null || true)`,
    "echo ---PROPS---",
    'echo "$props"',
    "echo ---LOCK---",
    `exec 9<>${shellQuote(SOURCE_LOCK_PATH)}`,
    "if flock -n 9; then echo FREE; else echo BUSY; fi",
    "echo ---STATUS---",
    `s=${shellQuote(`${BACKUP_BASE}/jobs/${jobId}/status.json`)}`,
    'test -r "$s" || { echo __MISSING__; exit 0; }',
    'sz=$(stat -c %s "$s")',
    'test "$sz" -le 65536 || { echo __TOO_LARGE__; exit 0; }',
    'cat "$s"',
  ].join("\n");
};

/** The source verifier home is exactly `PUBLIC_HOME_BASE/<one validated
 * generation>`. Nothing else may ever be prepared, resolved or tunneled:
 * the default agent socket, a different home, another agent and the private
 * key file are all out of scope for this controller. */
function validatePublicHome(publicHome: unknown): string {
  if (typeof publicHome !== "string") {
    throw new Error("Public home must be a string");
  }
  if (!publicHome.startsWith(`${PUBLIC_HOME_BASE}/`)) {
    throw new Error("Public home is not under the canonical verifier base");
  }
  const generation = validateGeneration(
    publicHome.slice(PUBLIC_HOME_BASE.length + 1),
  );
  const exactHome = `${PUBLIC_HOME_BASE}/${generation}`;
  if (publicHome !== exactHome) {
    throw new Error("Public home is not the canonical verifier home");
  }
  return exactHome;
}

export function realRemoteSeam(runner: RemoteRunner): RemoteSeam {
  const ssh = (args: string[]) => [...SSH_FLAGS, SOURCE_HOST, ...args];
  return {
    async source(script: string) {
      return await runner(
        "ssh",
        ssh(["bash", "-c", shellQuote(`set -eu\n${script}`)]),
      );
    },
    async root(script: string) {
      return await runner(
        "ssh",
        ssh(["sudo", "-n", "bash", "-c", shellQuote(`set -eu\n${script}`)]),
      );
    },
    async installer(payload: unknown) {
      return await runner(
        "ssh",
        ssh([
          "sudo",
          "-n",
          "/usr/local/bin/deno",
          "eval",
          shellQuote(REMOTE_INSTALLER),
        ]),
        new TextEncoder().encode(JSON.stringify(payload)),
      );
    },
    async launchUnit(spec) {
      const unitName = validateUnitName(spec.unitName);
      const runtimeDir = spec.runtimeDir;
      if (
        typeof runtimeDir !== "string" ||
        !runtimeDir.startsWith(`${JOBS_RUNTIME_ROOT}/`) ||
        runtimeDir.includes("\0")
      ) {
        throw new Error("Unsafe transport runtime directory");
      }
      if (
        !Number.isSafeInteger(spec.remainingSec) || spec.remainingSec < 1
      ) {
        throw new Error("Remaining deadline seconds must be positive");
      }
      const properties = [
        "Type=exec",
        "RemainAfterExit=yes",
        `RuntimeMaxSec=${spec.remainingSec}`,
        "MemoryMax=1G",
        "CPUQuota=100%",
        "Nice=10",
        "IOWeight=100",
        "UMask=0077",
        `WorkingDirectory=${runtimeDir}`,
      ].map((property) => `--property=${shellQuote(property)}`).join(" ");
      return await this.root(
        `systemd-run --quiet --unit=${shellQuote(unitName)} ${properties} ${
          spec.args.map(shellQuote).join(" ")
        }`,
      );
    },
    async observe(unitName, jobId) {
      const result = await this.root(ROOT_OBSERVE(unitName, jobId));
      if (result.code !== 0) {
        return {
          props: new Map(),
          status: null,
          lockFree: false,
          reachable: false,
        };
      }
      const propsText = result.stdout.split("---LOCK---")[0].replace(
        "---PROPS---",
        "",
      );
      const lockLine = result.stdout.match(/---LOCK---\n(FREE|BUSY)/)?.[1];
      const statusText = result.stdout.split("---STATUS---\n")[1]?.trim() ?? "";
      const props = new Map<string, string>();
      for (const line of propsText.split("\n")) {
        const match = line.match(/^([A-Za-z]+)=(.*)$/);
        if (match) props.set(match[1], match[2]);
      }
      if (props.size === 0) {
        return { props, status: null, lockFree: false, reachable: false };
      }
      const status =
        statusText === "__MISSING__" || statusText === "__TOO_LARGE__"
          ? null
          : JSON.parse(statusText);
      return {
        props,
        status,
        lockFree: lockLine === "FREE",
        reachable: true,
      };
    },
    async resolveAgentSocket(publicHome) {
      // Called before the verifier creates the home: prepare the exact
      // validated home as codex first, prove it canonical/codex-owned/0700
      // with no private key entries, then create its socket directory as
      // codex before the reverse -R ever references the socket path.
      const exactHome = validatePublicHome(publicHome);
      const result = await this.root([
        `home=${shellQuote(exactHome)}`,
        `if [ ! -e "$home" ]; then mkdir -p "$home" && chown codex:codex "$home" && chmod 700 "$home"; fi`,
        `test ! -L "$home" || { echo "AGENT_HOME_SYMLINK"; exit 1; }`,
        `test -d "$home" || { echo "AGENT_HOME_NOT_DIR"; exit 1; }`,
        `test "$(realpath "$home")" = "$home" || { echo "AGENT_HOME_NOT_CANONICAL"; exit 1; }`,
        `test "$(stat -c %u "$home")" = "$(id -u codex)" || { echo "AGENT_HOME_NOT_CODEX"; exit 1; }`,
        `test "$(stat -c %a "$home")" = "700" || { echo "AGENT_HOME_MODE"; exit 1; }`,
        `test ! -e "$home/private-keys-v1.d" || { echo "AGENT_HOME_PRIVATE_KEYS"; exit 1; }`,
        `test ! -e "$home/secring.gpg" || { echo "AGENT_HOME_PRIVATE_KEYS"; exit 1; }`,
        `sudo -n -u codex gpgconf --homedir "$home" --create-socketdir`,
        `socket=$(sudo -n -u codex gpgconf --homedir "$home" --list-dirs agent-socket)`,
        `default=$(sudo -n -u codex gpgconf --list-dirs agent-socket)`,
        `echo "socket=$socket"`,
        `echo "default=$default"`,
      ].join("\n"));
      if (result.code !== 0) {
        throw new Error(
          `Agent socket resolution failed: ${
            result.stderr.trim() === ""
              ? result.stdout.trim()
              : result.stderr.trim()
          }`,
        );
      }
      const socket = result.stdout.match(/^socket=(.+)$/m)?.[1];
      const defaultSocket = result.stdout.match(/^default=(.+)$/m)?.[1];
      if (!socket || !defaultSocket) {
        throw new Error("Agent socket resolution returned no socket");
      }
      return { socket, defaultSocket };
    },
  };
}

// ---------------------------------------------------------------------------
// Tunnel seam (Pi side)
// ---------------------------------------------------------------------------

export interface TunnelHandle {
  close(): Promise<void>;
}

export interface TunnelSeam {
  /** The task-owned tunnel, or null while none is open. */
  current(): TunnelHandle | null;
  open(remoteSocket: string): Promise<TunnelHandle>;
  close(): Promise<void>;
}

/** The ssh argv for the task-owned reverse agent tunnel. `-N` is rejected
 * on purpose: without a remote command stdin is never held and closing it
 * cannot terminate the connection naturally, so the remote runs
 * `printf TUNNEL_READY; cat` and the client waits for that acknowledgement
 * before any verifier is launched (`ExitOnForwardFailure=yes` makes ssh
 * exit before the remote command if the forward could not be created). */
export function tunnelForwardArgs(
  remoteSocket: string,
  localSocket: string,
): string[] {
  if (
    typeof remoteSocket !== "string" || remoteSocket === "" ||
    remoteSocket.includes("\0") || remoteSocket.includes("\n")
  ) {
    throw new Error("Unsafe agent tunnel remote socket");
  }
  if (
    typeof localSocket !== "string" || localSocket === "" ||
    localSocket.includes("\0") || localSocket.includes("\n")
  ) {
    throw new Error("Unsafe agent tunnel local socket");
  }
  return [
    ...SSH_FLAGS,
    "-o",
    "ExitOnForwardFailure=yes",
    "-R",
    `${remoteSocket}:${localSocket}`,
    SOURCE_HOST,
    // The remote command removes exactly this task-owned custom socket
    // when it exits (never the default socket or an agent), prints the
    // readiness acknowledgement before it holds stdin open for the
    // lifetime of the reverse forward, and `cat` runs until stdin closes.
    // The whole trap body is single-quoted once, with the exact socket
    // single-quoted inside, so any punctuation in the path survives both
    // the trap registration and the command it runs.
    `${
      trapWrap(`rm -f -- ${shellQuote(remoteSocket)}`)
    }; printf 'TUNNEL_READY\\n'; cat`,
  ];
}

/** `trap <shellQuote(body)> EXIT` keeps the trap action one single-quoted
 * shell word whose content is re-parsed when the trap fires. */
function trapWrap(body: string): string {
  return `trap ${shellQuote(body)} EXIT`;
}

const TUNNEL_READY_MARKER = "TUNNEL_READY";
const TUNNEL_READY_TIMEOUT_MS = 30_000;

/** The parts of one spawned tunnel connection the seam needs; tests inject a
 * small synthetic child instead of spawning `ssh`. */
export interface TunnelChild {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  status: Promise<Deno.CommandStatus>;
}

export type TunnelChildFactory = (args: string[]) => TunnelChild;

function defaultTunnelChildFactory(args: string[]): TunnelChild {
  const child = new Deno.Command("ssh", {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  return {
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    status: child.status,
  };
}

export function realTunnelSeam(
  runner: RemoteRunner,
  keyringPath: string,
  childFactory: TunnelChildFactory = defaultTunnelChildFactory,
): TunnelSeam {
  let active: TunnelHandle | null = null;
  return {
    current() {
      return active;
    },
    async open(remoteSocket) {
      if (active !== null) return active;
      if (
        typeof remoteSocket !== "string" ||
        !remoteSocket.startsWith("/run/user/") ||
        remoteSocket.includes("\0") || remoteSocket === ""
      ) {
        throw new Error("Unsafe agent tunnel socket");
      }
      if (
        typeof keyringPath !== "string" || keyringPath === "" ||
        keyringPath.includes("\0")
      ) {
        throw new Error("Unsafe Pi keyring path");
      }
      // Normal agent launch and an explicit extra-socket resolution: the
      // extra socket is created by default in the keyring home, no
      // gpg-agent.conf rewrite is ever invented.
      await Deno.mkdir(keyringPath, { recursive: true, mode: 0o700 });
      const launch = await runner("gpgconf", [
        "--homedir",
        keyringPath,
        "--launch",
        "gpg-agent",
      ]);
      if (launch.code !== 0) throw new Error("Pi GPG agent launch failed");
      const extra = await runner("gpgconf", [
        "--homedir",
        keyringPath,
        "--list-dirs",
        "agent-extra-socket",
      ]);
      if (extra.code !== 0 || extra.stdout.trim() === "") {
        throw new Error("Pi GPG agent extra socket resolution failed");
      }
      const localSocket = extra.stdout.trim().split("\n").at(-1)!;
      const standard = await runner("gpgconf", [
        "--homedir",
        keyringPath,
        "--list-dirs",
        "agent-socket",
      ]);
      if (standard.code !== 0 || standard.stdout.trim() === "") {
        throw new Error("Pi GPG agent socket resolution failed");
      }
      const standardSocket = standard.stdout.trim().split("\n").at(-1)!;
      if (localSocket === standardSocket) {
        throw new Error(
          "Pi agent extra socket does not differ from the default socket",
        );
      }
      const child = childFactory(tunnelForwardArgs(remoteSocket, localSocket));
      let stderrText = "";
      const stderrDrain = (async () => {
        const decoder = new TextDecoder();
        for await (const bytes of child.stderr) {
          if (stderrText.length + bytes.length > 64 * 1024) continue;
          stderrText += decoder.decode(bytes, { stream: true });
        }
        stderrText += decoder.decode();
      })();
      let ackSeen = false;
      let ackError: unknown = null;
      const ready = (async () => {
        const decoder = new TextDecoder();
        let text = "";
        for await (const chunk of child.stdout) {
          text += decoder.decode(chunk, { stream: true });
          if (text.includes(TUNNEL_READY_MARKER)) {
            ackSeen = true;
            return;
          }
        }
        ackError = new Error(
          `Tunnel closed before readiness acknowledgement${
            stderrText === "" ? "" : `: ${stderrText.trim()}`
          }`,
        );
      })();
      // The readiness timer is cleared the moment the acknowledgement
      // arrives so the seam never keeps the event loop busy for 30s.
      const timeoutError = new Error(
        "Tunnel readiness acknowledgement timed out",
      );
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(timeoutError), TUNNEL_READY_TIMEOUT_MS);
      });
      const closeOwnedChild = async (): Promise<void> => {
        // Close stdin so the remote `cat` gets EOF and exits, which ends
        // the SSH session naturally (ServerAlive bounds a dead transport).
        // Await the terminal exit and drain stderr for proof. Never signal
        // ssh or any agent and never claim a cleanup we did not prove.
        const writer = child.stdin.getWriter();
        try {
          await writer.close();
        } catch {
          // Already closed.
        }
        await child.status;
        await stderrDrain;
      };
      try {
        await Promise.race([ready, timeout]);
      } catch (error) {
        // A readiness timeout OR a readiness stream error rejects the race
        // while this owned child may still hold stdin open (the remote
        // `cat` waits for EOF): close the child's stdin, await its natural
        // exit and stderr drain, then rethrow the original failure. Never
        // signal or kill the SSH child or an agent.
        try {
          await closeOwnedChild();
        } catch {
          // The readiness failure is the reportable one; never replace it
          // with a partial cleanup error or claim more than proved.
        }
        throw error;
      } finally {
        clearTimeout(timer);
      }
      if (!ackSeen) {
        // The stream ended before the acknowledgement: the child may still
        // hold stdin open, so the same owned-child close proof runs before
        // the failure is reported.
        await closeOwnedChild();
        throw ackError ?? timeoutError;
      }
      const handle: TunnelHandle = {
        async close() {
          await closeOwnedChild();
        },
      };
      active = handle;
      // Observe the owned child's natural exit (a dead SSH transport ends
      // the connection without any signal): the active handle is invalidated
      // ONLY if it still is this child's handle, so a later replacement is
      // never cleared. A rejected status is consumed (this seam's own
      // close path reports it); the owned stdin is released on the already
      // terminated child without any signal or kill.
      const exitWatch = (async () => {
        try {
          await child.status;
        } catch {
          // The exit status never resolved: the owned connection still
          // ended, and the invalidation below remains the only consequence.
        }
        if (active === handle) active = null;
        try {
          await child.stdin.getWriter().close();
        } catch {
          // The remote command is already gone; EOF on a closed pipe is
          // neither a cleanup failure nor a signal.
        }
      })();
      void stderrDrain;
      void exitWatch;
      return handle;
    },
    async close() {
      const handle = active;
      active = null;
      await handle?.close();
    },
  };
}

// ---------------------------------------------------------------------------
// Metadata store seam (Pi: versions/delete only)
// ---------------------------------------------------------------------------

export type MetadataStore = Pick<B2Store, "versions" | "remove">;
export type MetadataStoreFactory = (settings: B2Settings) => MetadataStore;

export const realMetadataStoreFactory: MetadataStoreFactory = (settings) =>
  new B2Store(settings);

// ---------------------------------------------------------------------------
// Gate seam
// ---------------------------------------------------------------------------

export interface GateSeam {
  read(): Promise<BackupControllerGate | null>;
  create(gate: BackupControllerGate): Promise<unknown>;
  bind(
    expected: BackupControllerGate,
    invocationId: string,
  ): Promise<BackupControllerGate>;
  orphan(
    expected: BackupControllerGate,
    reason: OrphanReason,
  ): Promise<BackupControllerGate>;
  clear(expected: BackupControllerGate, proof: unknown): Promise<unknown>;
}

export function realGateSeam(path: string = GATE_PATH): GateSeam {
  return {
    read: () => readGate(path),
    create: (gate) => writeActiveGate(gate, path),
    bind: (expected, invocationId) =>
      bindInvocation(expected, invocationId, path),
    orphan: (expected, reason) => markOrphaned(expected, reason, path),
    clear: (expected, proof) => clearGateAfterProof(expected, proof, path),
  };
}

// ---------------------------------------------------------------------------
// Private IO seam (Pi side)
// ---------------------------------------------------------------------------

export interface PrivateSeam {
  read<T>(path: string): Promise<T | undefined>;
  write(path: string, value: unknown): Promise<void>;
  readBytes(path: string, maxBytes: number): Promise<Uint8Array | undefined>;
  writeBytes(path: string, bytes: Uint8Array): Promise<void>;
  readText(path: string, maxBytes: number): Promise<string | undefined>;
}

export function realPrivateSeam(): PrivateSeam {
  return {
    async read<T>(path: string): Promise<T | undefined> {
      try {
        return await readPrivateJson<T>(path);
      } catch (error) {
        if (error instanceof Deno.errors.NotFound) return undefined;
        throw error;
      }
    },
    write: (path, value) => writePrivateJson(path, value),
    async readBytes(path, maxBytes) {
      try {
        const info = await Deno.stat(path);
        if (info.mode !== null && (info.mode & 0o077) !== 0) {
          throw new Error(`${path} must not grant group or other permissions`);
        }
        if (info.size > maxBytes) {
          throw new Error(`${path} exceeds the read bound`);
        }
        return await Deno.readFile(path);
      } catch (error) {
        if (error instanceof Deno.errors.NotFound) return undefined;
        throw error;
      }
    },
    async writeBytes(path, bytes) {
      const slash = path.lastIndexOf("/");
      const directory = slash > 0 ? path.slice(0, slash) : ".";
      if (slash > 0) {
        await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
      }
      const temp = `${directory}/.${
        path.slice(slash + 1)
      }.${crypto.randomUUID()}.tmp`;
      const handle = await Deno.open(temp, {
        createNew: true,
        write: true,
        mode: 0o600,
      });
      try {
        let offset = 0;
        while (offset < bytes.byteLength) {
          const written = await handle.write(bytes.subarray(offset));
          if (!Number.isSafeInteger(written) || written <= 0) {
            throw new Error("Private temp write made no progress");
          }
          offset += written;
        }
        await handle.sync();
      } finally {
        handle.close();
      }
      await Deno.chmod(temp, 0o600);
      await Deno.rename(temp, path);
    },
    async readText(path, maxBytes) {
      if (path === "config/restic-excludes.txt") {
        return await readPublicConfigText(path, maxBytes);
      }
      const bytes = await this.readBytes(path, maxBytes);
      return bytes === undefined ? undefined : new TextDecoder().decode(bytes);
    },
  };
}

/** Bounded read of the single public config file
 * (`config/restic-excludes.txt`): regular non-symlink, canonical path,
 * owner-writable only (0600 and 0644 accepted; any group/world WRITE is
 * rejected), size bounded. Every other readText path stays on the strict
 * private readBytes path, which rejects even group/other read access. */
async function readPublicConfigText(
  path: string,
  maxBytes: number,
): Promise<string | undefined> {
  try {
    const info = await Deno.lstat(path);
    if (!info.isFile) {
      throw new Error(`${path} is not a regular file`);
    }
    if (info.mode !== null && (info.mode & 0o022) !== 0) {
      throw new Error(
        `${path} must not grant group or other write permissions`,
      );
    }
    if (info.size > maxBytes) {
      throw new Error(`${path} exceeds the read bound`);
    }
    const resolved = await Deno.realPath(path);
    const workspace = await Deno.realPath(".");
    const lexical = path.startsWith("/") ? path : `${workspace}/${path}`;
    if (resolved !== lexical) {
      throw new Error(`${path} is not canonical`);
    }
    return await Deno.readTextFile(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

export type ControllerPhase =
  | "REQUESTED"
  | "WORKER_LAUNCHED"
  | "WORKER_RUNNING"
  | "WORKER_TERMINAL"
  | "VERIFIER_LAUNCHED"
  | "VERIFIER_RUNNING"
  | "ACCEPTED"
  | "PRUNING"
  | "PRUNED"
  | "CLEANUP_PENDING"
  | "COMPLETE"
  | "FAILED";

export const CONTROLLER_PHASES: readonly ControllerPhase[] = [
  "REQUESTED",
  "WORKER_LAUNCHED",
  "WORKER_RUNNING",
  "WORKER_TERMINAL",
  "VERIFIER_LAUNCHED",
  "VERIFIER_RUNNING",
  "ACCEPTED",
  "PRUNING",
  "PRUNED",
  "CLEANUP_PENDING",
  "COMPLETE",
  "FAILED",
];

export interface PrunePlanEntry {
  generation: string;
  fileIds: string[];
}

export interface PrunePlanState {
  plan: PrunePlanEntry[];
  startedAtUtc: string;
  completedAtUtc?: string;
  failedAtUtc?: string;
  evidence?: string;
}

export interface CleanupState {
  status: "PENDING" | "DONE" | "FAILED";
  atUtc?: string;
  detail?: string;
}

export interface FailureState {
  code: string;
  atUtc: string;
  detail?: string;
}

export interface CatalogEntry {
  index: RecoveryIndex;
  publishedIndex: PublishedIndex;
  receipt: DecryptedVerification;
  acceptedAtUtc: string;
}

export interface ControllerJob {
  envelope: WorkerRequestEnvelope;
  phase: ControllerPhase;
  updatedAtUtc: string;
  heartbeatAtUtc: string;
  workerInvocationId: string | null;
  verifierInvocationId: string | null;
  workerStatus?: WorkerStatus;
  verifierStatus?: VerifierStatus;
  resultSha256?: string;
  prune?: PrunePlanState;
  cleanup?: CleanupState;
  failure?: FailureState;
}

export interface ControllerState {
  schemaVersion: 1;
  job?: ControllerJob;
  catalog: CatalogEntry[];
}

const B2_OBJECT_KEYS = new Set([
  "fileId",
  "fileName",
  "contentLength",
  "contentSha1",
  "action",
  "uploadTimestamp",
]);

function validateB2Object(input: unknown): B2Object {
  if (!isRecord(input)) throw new Error("B2 object is malformed");
  rejectUnknownKeys(input, B2_OBJECT_KEYS, "B2 object");
  for (const key of ["fileId", "fileName", "contentSha1", "action"]) {
    if (typeof input[key] !== "string" || input[key] === "") {
      throw new Error(`B2 object ${key} must be a non-empty string`);
    }
  }
  if (
    typeof input.contentLength !== "number" ||
    !Number.isSafeInteger(input.contentLength) ||
    input.contentLength < 0 ||
    typeof input.uploadTimestamp !== "number" ||
    !Number.isSafeInteger(input.uploadTimestamp)
  ) {
    throw new Error("B2 object numeric fields are malformed");
  }
  return input as unknown as B2Object;
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

function validatePublishedIndex(input: unknown): PublishedIndex {
  if (!isRecord(input)) throw new Error("Published index is malformed");
  rejectUnknownKeys(input, PUBLISHED_INDEX_KEYS, "Published index");
  const generation = validateGeneration(input.generation);
  if (
    typeof input.indexSha256 !== "string" ||
    !SHA256_PATTERN.test(input.indexSha256) ||
    typeof input.ciphertextSha256 !== "string" ||
    !SHA256_PATTERN.test(input.ciphertextSha256) ||
    typeof input.ciphertextBytes !== "number" ||
    !Number.isSafeInteger(input.ciphertextBytes) ||
    input.ciphertextBytes <= 0
  ) {
    throw new Error("Published index hashes are malformed");
  }
  if (
    input.uploadVerified !== true ||
    input.decryptedRestoreProved !== false ||
    input.machineBootRestoreProved !== false
  ) {
    throw new Error("Published index flags are malformed");
  }
  return {
    generation,
    object: validateB2Object(input.object),
    ciphertextBytes: input.ciphertextBytes as number,
    ciphertextSha256: input.ciphertextSha256 as string,
    indexSha256: input.indexSha256 as string,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}

const CATALOG_ENTRY_KEYS = new Set([
  "index",
  "publishedIndex",
  "receipt",
  "acceptedAtUtc",
]);

export function validateCatalogEntry(input: unknown): CatalogEntry {
  if (!isRecord(input)) throw new Error("Catalog entry is malformed");
  rejectUnknownKeys(input, CATALOG_ENTRY_KEYS, "Catalog entry");
  const index = validateRecoveryIndex(input.index);
  const publishedIndex = validatePublishedIndex(input.publishedIndex);
  const receipt = validateVerifierReceipt(input.receipt);
  const acceptedAtUtc = canonicalUtc(input.acceptedAtUtc, "acceptedAtUtc");
  if (publishedIndex.generation !== index.generation) {
    throw new Error("Catalog published index generation differs");
  }
  if (publishedIndex.indexSha256 !== receipt.indexSha256) {
    throw new Error("Catalog receipt index hash differs");
  }
  if (
    index.recipientSha256 !== receipt.recipientSha256 ||
    index.recipientFingerprint !== receipt.recipientFingerprint
  ) {
    throw new Error("Catalog receipt recipient differs");
  }
  if (receipt.generation !== index.generation) {
    throw new Error("Catalog receipt generation differs");
  }
  return { index, publishedIndex, receipt, acceptedAtUtc };
}

const CONTROLLER_STATE_KEYS = new Set(["schemaVersion", "job", "catalog"]);
const JOB_KEYS = new Set([
  "envelope",
  "phase",
  "updatedAtUtc",
  "heartbeatAtUtc",
  "workerInvocationId",
  "verifierInvocationId",
  "workerStatus",
  "verifierStatus",
  "resultSha256",
  "prune",
  "cleanup",
  "failure",
]);

export function validateControllerState(input: unknown): ControllerState {
  if (!isRecord(input)) {
    throw new Error("Controller state must be a JSON object");
  }
  rejectUnknownKeys(input, CONTROLLER_STATE_KEYS, "Controller state");
  if (input.schemaVersion !== 1) {
    throw new Error("Controller state schemaVersion must be 1");
  }
  if (!Array.isArray(input.catalog)) {
    throw new Error("Controller state catalog must be an array");
  }
  const catalog: CatalogEntry[] = [];
  const generations = new Set<string>();
  for (const entry of input.catalog) {
    const validated = validateCatalogEntry(entry);
    if (generations.has(validated.index.generation)) {
      throw new Error("Controller state catalog has a duplicate generation");
    }
    generations.add(validated.index.generation);
    catalog.push(validated);
  }
  let job: ControllerJob | undefined;
  if (input.job !== undefined) {
    if (!isRecord(input.job)) throw new Error("Controller job is malformed");
    rejectUnknownKeys(input.job, JOB_KEYS, "Controller job");
    const envelope = validateRequestEnvelope(input.job.envelope);
    const phase = input.job.phase;
    if (!(CONTROLLER_PHASES as readonly string[]).includes(String(phase))) {
      throw new Error("Controller job phase is unknown");
    }
    const updatedAtUtc = canonicalUtc(
      input.job.updatedAtUtc,
      "job.updatedAtUtc",
    );
    const heartbeatAtUtc = canonicalUtc(
      input.job.heartbeatAtUtc,
      "job.heartbeatAtUtc",
    );
    const workerInvocationId = input.job.workerInvocationId === null
      ? null
      : validateUnitInvocationId(input.job.workerInvocationId);
    const verifierInvocationId = input.job.verifierInvocationId === null
      ? null
      : validateUnitInvocationId(input.job.verifierInvocationId);
    const workerStatus = input.job.workerStatus === undefined
      ? undefined
      : validateWorkerStatus(input.job.workerStatus);
    const verifierStatus = input.job.verifierStatus === undefined
      ? undefined
      : validateVerifierStatus(input.job.verifierStatus);
    const resultSha256 = input.job.resultSha256 === undefined
      ? undefined
      : (() => {
        if (
          typeof input.job.resultSha256 !== "string" ||
          !SHA256_PATTERN.test(input.job.resultSha256)
        ) {
          throw new Error("Controller job resultSha256 is malformed");
        }
        return input.job.resultSha256 as string;
      })();
    const prune = input.job.prune === undefined ? undefined : (() => {
      if (!isRecord(input.job.prune)) {
        throw new Error("Controller job prune is malformed");
      }
      rejectUnknownKeys(
        input.job.prune,
        new Set([
          "plan",
          "startedAtUtc",
          "completedAtUtc",
          "failedAtUtc",
          "evidence",
        ]),
        "Controller job prune",
      );
      if (!Array.isArray(input.job.prune.plan)) {
        throw new Error("Controller job prune plan must be an array");
      }
      const plan: PrunePlanEntry[] = [];
      for (const entry of input.job.prune.plan) {
        if (!isRecord(entry) || Object.keys(entry).length !== 2) {
          throw new Error("Controller job prune plan entry is malformed");
        }
        const generation = validateGeneration(entry.generation);
        if (!Array.isArray(entry.fileIds)) {
          throw new Error("Controller job prune plan fileIds must be an array");
        }
        const fileIds: string[] = [];
        for (const fileId of entry.fileIds) {
          if (typeof fileId !== "string" || fileId === "") {
            throw new Error("Controller job prune plan fileId is malformed");
          }
          fileIds.push(fileId);
        }
        plan.push({ generation, fileIds });
      }
      if (
        typeof input.job.prune.evidence !== "undefined" &&
        typeof input.job.prune.evidence !== "string"
      ) {
        throw new Error("Controller job prune evidence is malformed");
      }
      return {
        plan,
        startedAtUtc: canonicalUtc(
          input.job.prune.startedAtUtc,
          "prune.startedAtUtc",
        ),
        ...(input.job.prune.completedAtUtc === undefined ? {} : {
          completedAtUtc: canonicalUtc(
            input.job.prune.completedAtUtc,
            "prune.completedAtUtc",
          ),
        }),
        ...(input.job.prune.failedAtUtc === undefined ? {} : {
          failedAtUtc: canonicalUtc(
            input.job.prune.failedAtUtc,
            "prune.failedAtUtc",
          ),
        }),
        ...(typeof input.job.prune.evidence === "string"
          ? { evidence: input.job.prune.evidence }
          : {}),
      };
    })();
    const cleanup = input.job.cleanup === undefined ? undefined : (() => {
      if (!isRecord(input.job.cleanup)) {
        throw new Error("Controller job cleanup is malformed");
      }
      rejectUnknownKeys(
        input.job.cleanup,
        new Set(["status", "atUtc", "detail"]),
        "Controller job cleanup",
      );
      const status = input.job.cleanup.status;
      if (status !== "PENDING" && status !== "DONE" && status !== "FAILED") {
        throw new Error("Controller job cleanup status is unknown");
      }
      return {
        status: status as CleanupState["status"],
        ...(input.job.cleanup.atUtc === undefined
          ? {}
          : { atUtc: canonicalUtc(input.job.cleanup.atUtc, "cleanup.atUtc") }),
        ...(typeof input.job.cleanup.detail === "string"
          ? { detail: input.job.cleanup.detail }
          : {}),
      };
    })();
    const failure = input.job.failure === undefined ? undefined : (() => {
      if (!isRecord(input.job.failure)) {
        throw new Error("Controller job failure is malformed");
      }
      rejectUnknownKeys(
        input.job.failure,
        new Set(["code", "atUtc", "detail"]),
        "Controller job failure",
      );
      if (
        typeof input.job.failure.code !== "string" ||
        input.job.failure.code === ""
      ) {
        throw new Error("Controller job failure code is malformed");
      }
      return {
        code: input.job.failure.code as string,
        atUtc: canonicalUtc(input.job.failure.atUtc, "failure.atUtc"),
        ...(typeof input.job.failure.detail === "string"
          ? { detail: input.job.failure.detail }
          : {}),
      };
    })();
    job = {
      envelope,
      phase: phase as ControllerPhase,
      updatedAtUtc,
      heartbeatAtUtc,
      workerInvocationId,
      verifierInvocationId,
      ...(workerStatus === undefined ? {} : { workerStatus }),
      ...(verifierStatus === undefined ? {} : { verifierStatus }),
      ...(resultSha256 === undefined ? {} : { resultSha256 }),
      ...(prune === undefined ? {} : { prune }),
      ...(cleanup === undefined ? {} : { cleanup }),
      ...(failure === undefined ? {} : { failure }),
    };
  }
  return { schemaVersion: 1, ...(job === undefined ? {} : { job }), catalog };
}

export function emptyControllerState(): ControllerState {
  return { schemaVersion: 1, catalog: [] };
}

export function newJobState(
  envelope: WorkerRequestEnvelope,
  now: Date,
): ControllerJob {
  const validated = validateRequestEnvelope(envelope);
  const nowUtc = now.toISOString();
  return {
    envelope: validated,
    phase: "REQUESTED",
    updatedAtUtc: nowUtc,
    heartbeatAtUtc: nowUtc,
    workerInvocationId: null,
    verifierInvocationId: null,
  };
}

// ---------------------------------------------------------------------------
// Retention selection (pure)
// ---------------------------------------------------------------------------

export interface RetentionSelection {
  toDelete: B2Object[];
  toPrune: string[];
  retainedFileIds: string[];
}

export function generationPrefixes(generation: string): string[] {
  const valid = validateGeneration(generation);
  return [`${GENERATIONS_PREFIX}${valid}/`, `${INDEXES_PREFIX}${valid}/`];
}

function isObjectOfGeneration(object: B2Object, generation: string): boolean {
  return generationPrefixes(generation).some((prefix) =>
    object.fileName.startsWith(prefix)
  );
}

export function selectPruneCandidates(
  versions: B2Object[],
  catalog: CatalogEntry[],
  keep: number = KEEP_ACCEPTED,
): RetentionSelection {
  const ordered = [...catalog].sort(
    (a, b) => Date.parse(a.acceptedAtUtc) - Date.parse(b.acceptedAtUtc),
  );
  const kept = ordered.slice(Math.max(0, ordered.length - keep));
  const keptSet = new Set(kept.map((entry) => entry.index.generation));
  const toPrune = ordered
    .filter((entry) => !keptSet.has(entry.index.generation))
    .map((entry) => entry.index.generation);
  const toDelete: B2Object[] = [];
  const seen = new Set<string>();
  for (const generation of toPrune) {
    for (const object of versions) {
      if (object.action !== "upload" && object.action !== "hide") continue;
      if (!isObjectOfGeneration(object, generation)) continue;
      const key = `${generation}:${object.fileId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      toDelete.push(object);
    }
  }
  const retainedFileIds: string[] = [];
  for (const entry of kept) {
    retainedFileIds.push(entry.publishedIndex.object.fileId);
    for (const archive of entry.index.archives) {
      for (const chunk of archive.chunks) retainedFileIds.push(chunk.fileId);
    }
  }
  return { toDelete, toPrune, retainedFileIds };
}

export function retainedIdsPresent(
  versions: B2Object[],
  retainedFileIds: string[],
): boolean {
  const present = new Map<string, string>();
  for (const object of versions) {
    if (!present.has(object.fileId)) present.set(object.fileId, object.action);
  }
  return retainedFileIds.every((id) => present.get(id) === "upload");
}

export function resumePruneDeletions(
  versions: B2Object[],
  plan: PrunePlanEntry[],
): { remaining: B2Object[]; removed: string[] } {
  const present = new Map<string, B2Object>();
  for (const object of versions) present.set(object.fileId, object);
  const remaining: B2Object[] = [];
  const removed: string[] = [];
  for (const entry of plan) {
    for (const fileId of entry.fileIds) {
      const object = present.get(fileId);
      if (object === undefined) removed.push(fileId);
      else remaining.push(object);
    }
  }
  return { remaining, removed };
}

/** Revalidate a persisted plan against the current inventory before every
 * removal: an ID-only plan is never trusted. Each pending fileId must still
 * be bound to its plan generation's exact namespace prefixes, must still be
 * an upload/hide version (never a `start` marker or a foreign key), and must
 * never collide with the freshly selected retained membership of the newest
 * four accepted generations (which also protects the current generation,
 * pending pre-acceptance data and foreign namespaces). Missing IDs are
 * already removed and stay removed; any other drift yields a violation so
 * the caller fails closed without deleting anything. */
export function revalidatePruneDeletions(
  versions: B2Object[],
  plan: PrunePlanEntry[],
  eligibleGenerations: string[],
  retainedFileIds: string[],
): { pending: B2Object[]; removed: string[]; violation: string | null } {
  const present = new Map<string, B2Object>();
  for (const object of versions) present.set(object.fileId, object);
  const eligible = new Set(eligibleGenerations);
  const retained = new Set(retainedFileIds);
  const pending: B2Object[] = [];
  const removed: string[] = [];
  for (const entry of plan) {
    if (!eligible.has(entry.generation)) {
      return {
        pending: [],
        removed,
        violation:
          `planned generation ${entry.generation} is no longer eligible`,
      };
    }
    const prefixes = generationPrefixes(entry.generation);
    for (const fileId of entry.fileIds) {
      const object = present.get(fileId);
      if (object === undefined) {
        removed.push(fileId);
        continue;
      }
      if (retained.has(object.fileId)) {
        return {
          pending: [],
          removed,
          violation: `planned id ${fileId} is now retained`,
        };
      }
      if (object.action !== "upload" && object.action !== "hide") {
        return {
          pending: [],
          removed,
          violation: `planned id ${fileId} is not an upload/hide version`,
        };
      }
      if (!prefixes.some((prefix) => object.fileName.startsWith(prefix))) {
        return {
          pending: [],
          removed,
          violation: `planned id ${fileId} is outside its generation namespace`,
        };
      }
      pending.push(object);
    }
  }
  return { pending, removed, violation: null };
}

// ---------------------------------------------------------------------------
// Watchdog assessment (pure)
// ---------------------------------------------------------------------------

export interface WatchdogAssessment {
  status: string;
  healthy: boolean;
  detail?: string;
}

/** Metadata-only live source observation (unit properties plus the bounded
 * status file) collected without holding the controller lock. */
export interface ObservedSource {
  observedAtUtc: string;
  reachable: boolean;
  invocationId: string | null;
  status: unknown;
}

const ACTIVE_HEARTBEAT_PHASES: readonly ControllerPhase[] = [
  "REQUESTED",
  "WORKER_LAUNCHED",
  "WORKER_RUNNING",
  "VERIFIER_LAUNCHED",
  "VERIFIER_RUNNING",
];

const ACTIVE_STATE_PHASES: readonly ControllerPhase[] = [
  "ACCEPTED",
  "PRUNING",
  "PRUNED",
  "CLEANUP_PENDING",
];

function sourceStatusFor(
  job: ControllerJob,
): { status: WorkerStatus | VerifierStatus; verifier: boolean } {
  const verifier = job.phase === "VERIFIER_LAUNCHED" ||
    job.phase === "VERIFIER_RUNNING";
  if (verifier) {
    if (job.verifierStatus === undefined) {
      throw new Error("Verifier source status is missing");
    }
    return { status: job.verifierStatus, verifier: true };
  }
  if (job.workerStatus === undefined) {
    throw new Error("Worker source status is missing");
  }
  return { status: job.workerStatus, verifier: false };
}

function parseObservedSource(
  raw: unknown,
  verifier: boolean,
  job: ControllerJob,
): WorkerStatus | VerifierStatus | null {
  if (raw === null) return null;
  if (verifier) {
    const parsed = validateVerifierStatus(raw);
    assertVerifierStatusIdentity(parsed, job.envelope);
    return parsed;
  }
  const parsed = validateWorkerStatus(raw);
  validateWorkerStatusIdentity(parsed, job.envelope);
  return parsed;
}

export function assessBackblazeWatchdog(
  state: ControllerState | undefined,
  gate: BackupControllerGate | null,
  now: Date,
  source?: ObservedSource,
): WatchdogAssessment {
  if (gate !== null && gate.state === "orphaned") {
    return {
      status: `B2_JOB_ORPHANED:${gate.jobId}`,
      healthy: false,
      detail: gate.orphanReason,
    };
  }
  const job = state?.job;
  if (job === undefined) {
    const window = weekWindow(now);
    const latest = state?.catalog.at(-1);
    if (now.getTime() < Date.parse(window.startAtUtc)) {
      return { status: "B2_BACKUP_IDLE", healthy: true };
    }
    if (now.getTime() < Date.parse(window.endAtUtc)) {
      return { status: "B2_BACKUP_MISSING", healthy: false };
    }
    if (
      latest !== undefined &&
      Date.parse(latest.acceptedAtUtc) >= Date.parse(window.startAtUtc)
    ) {
      return { status: "B2_BACKUP_CURRENT", healthy: true };
    }
    return {
      status: `B2_PERIOD_MISSED:${window.periodKey}`,
      healthy: false,
    };
  }
  const deadline = Date.parse(job.envelope.request.deadlineAtUtc);
  const idleStale = now.getTime() - Date.parse(job.heartbeatAtUtc) >
    STALE_AFTER_MS;
  const jobId = job.envelope.request.jobId;
  if (job.failure !== undefined) {
    return {
      status: `B2_BACKUP_FAILED:${jobId}`,
      healthy: false,
      detail: job.failure.code,
    };
  }
  if (ACTIVE_HEARTBEAT_PHASES.includes(job.phase)) {
    if (now.getTime() > deadline) {
      return { status: `B2_BACKUP_OVERDEADLINE:${jobId}`, healthy: false };
    }
    // The gate must bind this job and the expected unit before any source
    // status can prove liveness.
    const verifier = job.phase === "VERIFIER_LAUNCHED" ||
      job.phase === "VERIFIER_RUNNING";
    const expectedUnit = verifier
      ? verifyUnitName(job.envelope.request.generation)
      : workerUnitName(job.envelope.request.generation);
    const gateIssue = gate === null
      ? "gate is missing while the source phase is active"
      : gate.jobId !== jobId ||
          gate.periodKey !== job.envelope.request.periodKey ||
          gate.generation !== job.envelope.request.generation ||
          gate.requestSha256 !== job.envelope.requestSha256 ||
          gate.unitName !== expectedUnit
      ? "gate identity does not bind the job and unit"
      : null;
    if (gateIssue !== null) {
      return {
        status: `B2_BACKUP_ACTIVE_UNBOUND:${jobId}`,
        healthy: false,
        detail: gateIssue,
      };
    }
    let observed: WorkerStatus | VerifierStatus;
    try {
      const found = sourceStatusFor(job);
      observed = found.status;
      try {
        if (found.verifier) {
          assertVerifierStatusIdentity(
            observed as VerifierStatus,
            job.envelope,
          );
        } else {
          validateWorkerStatusIdentity(
            observed as WorkerStatus,
            job.envelope,
          );
        }
      } catch {
        return {
          status: `B2_BACKUP_SOURCE_MISMATCH:${jobId}`,
          healthy: false,
          detail: "stored source status does not bind the request",
        };
      }
      if (source !== undefined) {
        if (!source.reachable) {
          return {
            status: `B2_SOURCE_UNREACHABLE:${jobId}`,
            healthy: false,
            detail: "metadata-only source observation failed",
          };
        }
        if (
          source.invocationId !== null &&
          source.invocationId !== observed.invocationId
        ) {
          return {
            status: `B2_BACKUP_SOURCE_MISMATCH:${jobId}`,
            healthy: false,
            detail: "observed unit invocation differs from the source status",
          };
        }
        if (source.status === null) {
          return {
            status: `B2_BACKUP_SOURCE_STATUS_MISSING:${jobId}`,
            healthy: false,
            detail: "the source status file is missing",
          };
        }
        let live: WorkerStatus | VerifierStatus | null;
        try {
          live = parseObservedSource(source.status, found.verifier, job);
        } catch {
          live = null;
        }
        if (live === null) {
          return {
            status: `B2_BACKUP_SOURCE_MISMATCH:${jobId}`,
            healthy: false,
            detail:
              "live source status is malformed or does not bind the request",
          };
        }
        if (live.invocationId !== observed.invocationId) {
          return {
            status: `B2_BACKUP_SOURCE_MISMATCH:${jobId}`,
            healthy: false,
            detail:
              "live source status invocation differs from the stored status",
          };
        }
      }
    } catch (error) {
      return {
        status: `B2_BACKUP_SOURCE_STATUS_MISSING:${jobId}`,
        healthy: false,
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    const committedGate = gate;
    const expectedInvocation = committedGate?.unitInvocationId ??
      source?.invocationId ?? null;
    if (expectedInvocation === null) {
      return {
        status: `B2_BACKUP_SOURCE_UNBOUND:${jobId}`,
        healthy: false,
        detail: "the source status is not bound to an observed unit invocation",
      };
    }
    if (observed.invocationId !== expectedInvocation) {
      return {
        status: `B2_BACKUP_SOURCE_MISMATCH:${jobId}`,
        healthy: false,
        detail:
          "source status invocation differs from the bound unit invocation",
      };
    }
    // Freshness is the actual source heartbeat, never the Pi polling time.
    if (
      now.getTime() - Date.parse(observed.heartbeatAtUtc) > STALE_AFTER_MS
    ) {
      return { status: `B2_BACKUP_STALE:${jobId}`, healthy: false };
    }
    return { status: `B2_BACKUP_ACTIVE:${jobId}`, healthy: true };
  }
  if (job.phase === "WORKER_TERMINAL") {
    return { status: `B2_BACKUP_PENDING:${jobId}`, healthy: false };
  }
  if (job.phase === "FAILED") {
    return { status: `B2_BACKUP_FAILED:${jobId}`, healthy: false };
  }
  if (job.phase === "PRUNING" && job.prune?.failedAtUtc !== undefined) {
    return {
      status: `B2_PRUNE_FAILED:${jobId}`,
      healthy: false,
      detail: job.prune.evidence,
    };
  }
  if (job.phase === "CLEANUP_PENDING" && job.cleanup?.status === "FAILED") {
    return {
      status: `B2_CLEANUP_FAILED:${jobId}`,
      healthy: false,
      detail: job.cleanup.detail,
    };
  }
  if (job.phase === "COMPLETE") {
    const window = weekWindow(now);
    if (job.envelope.request.periodKey === window.periodKey) {
      return { status: `B2_BACKUP_CURRENT:${jobId}`, healthy: true };
    }
    return {
      status: `B2_PERIOD_MISSED:${window.periodKey}`,
      healthy: false,
    };
  }
  if (ACTIVE_STATE_PHASES.includes(job.phase)) {
    if (idleStale) {
      return { status: `B2_BACKUP_STALE:${jobId}`, healthy: false };
    }
    return { status: `B2_BACKUP_RETIRING:${jobId}`, healthy: true };
  }
  return {
    status: `B2_STATE_UNKNOWN:${jobId}`,
    healthy: false,
    detail: job.phase,
  };
}

// ---------------------------------------------------------------------------
// Terminal proof assembly (m06 contract)
// ---------------------------------------------------------------------------

export interface ClearProofObservation {
  props: Map<string, string>;
  lockFree: boolean;
  checkedAtUtc: string;
}

export function buildClearProof(
  observation: ClearProofObservation,
  gate: BackupControllerGate,
  statusState: string,
  statusTimestamps: {
    updatedAtUtc: string;
    heartbeatAtUtc: string;
    finishedAtUtc: string;
  },
): unknown {
  const props = observation.props;
  const invocation = props.get("InvocationID") ?? null;
  if (invocation === null) {
    throw new Error("Observed unit has no invocation id");
  }
  const invoke = Number(props.has("MainPID") ? props.get("MainPID") : "-1");
  const control = Number(
    props.has("ControlPID") ? props.get("ControlPID") : "-1",
  );
  // systemd reports TasksCurrent=[not set] for a unit with no tasks at all
  // (recorded live as RemainAfterExit=yes/active/exited with an empty
  // ControlGroup). The exact recognized marker maps to null ONLY; every
  // other value is coerced and any malformed or non-zero one is rejected by
  // the m06 contract below (empty group requires unset tasks, the canonical
  // unit cgroup requires zero tasks).
  const tasksRaw = props.get("TasksCurrent");
  const tasks = tasksRaw === undefined || tasksRaw === "[not set]"
    ? null
    : Number(tasksRaw);
  const proof = {
    checkedAtUtc: observation.checkedAtUtc,
    unitName: gate.unitName,
    unitInvocationId: invocation,
    unitLoadState: props.get("LoadState") ?? "",
    unitActiveState: props.get("ActiveState") ?? "",
    unitSubState: props.get("SubState") ?? "",
    unitResult: props.get("Result") ?? "",
    mainPid: invoke,
    controlPid: control,
    controlGroup: props.get("ControlGroup") ?? "",
    tasksCurrent: tasks,
    statusPath: `${BACKUP_BASE}/jobs/${gate.jobId}/${STATUS_FILE}`,
    statusState,
    statusJobId: gate.jobId,
    statusPeriodKey: gate.periodKey,
    statusGeneration: gate.generation,
    statusRequestSha256: gate.requestSha256,
    statusInvocationId: invocation,
    statusUpdatedAtUtc: statusTimestamps.updatedAtUtc,
    statusHeartbeatAtUtc: statusTimestamps.heartbeatAtUtc,
    statusFinishedAtUtc: statusTimestamps.finishedAtUtc,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    sourceLockFree: observation.lockFree as true,
  };
  validateGateClearProof(proof, gate, new Date(observation.checkedAtUtc));
  return proof;
}

// ---------------------------------------------------------------------------
// Source-side worker/verifier entry points
// ---------------------------------------------------------------------------

export interface SourceVerifyDependencies {
  basePath: string;
  now: () => Date;
  lock: <T>(path: string, work: () => Promise<T>) => Promise<T>;
  storeFor: (settings: B2Settings) => Pick<B2Store, "get" | "versions">;
  verify: (
    index: RecoveryIndex,
    reconstruction: ReconstructedGeneration,
    outputDirectory: string,
    decrypt: DecryptArchive,
  ) => Promise<DecryptedVerification>;
  reconstruct: (
    index: RecoveryIndex,
    store: Pick<B2Store, "get">,
    recoveryDirectory: string,
  ) => Promise<ReconstructedGeneration>;
}

const SOURCE_VERIFY_DEPS: SourceVerifyDependencies = {
  basePath: BACKUP_BASE,
  now: () => new Date(),
  lock: withBackupLock,
  storeFor: (settings) => new B2Store(settings),
  verify: verifyDecryptedGeneration,
  reconstruct: reconstructGeneration,
};

function requireInvocationId(): string {
  const value = Deno.env.get("INVOCATION_ID");
  try {
    return validateUnitInvocationId(value);
  } catch (error) {
    throw new Error(
      `Source unit invocation id is required (${
        error instanceof Error ? error.message : String(error)
      })`,
    );
  }
}

async function loadRuntimeSettings(): Promise<{
  settings: TransportSettings;
  runtimeDir: string;
  recipientBytes: Uint8Array;
}> {
  const cwd = Deno.cwd();
  const runtimeDir = await Deno.realPath(cwd);
  if (runtimeDir !== cwd) {
    throw new Error("Transport runtime must not be reached through a symlink");
  }
  const jobId = runtimeDir.slice(JOBS_RUNTIME_ROOT.length + 1);
  validateJobId(jobId);
  if (runtimeDir !== `${JOBS_RUNTIME_ROOT}/${jobId}`) {
    throw new Error("Working directory is not a per-job transport runtime");
  }
  const settingsBytes = await readRootBounded(
    `${runtimeDir}/${SETTINGS_FILE}`,
    MAX_SETTINGS_BYTES,
    "settings",
  );
  const settings = validateTransportSettings(
    JSON.parse(new TextDecoder().decode(settingsBytes)),
  );
  if (settings.envelope.request.jobId !== jobId) {
    throw new Error("Transport settings jobId differs from the runtime path");
  }
  const recipientBytes = await readRootBounded(
    `${runtimeDir}/${RECIPIENT_FILE}`,
    64 * 1024,
    "recipient",
  );
  if (
    await sha256Hex(recipientBytes) !== settings.captureSettings.recipientSha256
  ) {
    throw new Error("Transport recipient does not match the settings identity");
  }
  return { settings, runtimeDir, recipientBytes };
}

/** Production source worker entry: fixed real modules, no dependency
 * overrides, systemd INVOCATION_ID binding, real store, root runtime cwd. */
export async function runRemoteWorker(
  jobIdInput: unknown,
): Promise<WorkerStatus> {
  const jobId = validateJobId(jobIdInput);
  const { settings } = await loadRuntimeSettings();
  if (settings.envelope.request.jobId !== jobId) {
    throw new Error("Runtime settings do not bind this jobId");
  }
  const invocationId = requireInvocationId();
  const store = new B2Store(settings.B2Settings);
  return await runSourceWorker({
    envelope: settings.envelope,
    captureSettings: settings.captureSettings,
    indexRecipient: settings.indexRecipient,
    sourceRevision: settings.sourceRevision,
    invocationId,
    store,
  });
}

export function validateWorkerStatusIdentity(
  status: WorkerStatus,
  envelope: WorkerRequestEnvelope,
): void {
  if (
    status.jobId !== envelope.request.jobId ||
    status.periodKey !== envelope.request.periodKey ||
    status.generation !== envelope.request.generation ||
    status.requestSha256 !== envelope.requestSha256 ||
    status.requestedAtUtc !== envelope.request.requestedAtUtc ||
    status.deadlineAtUtc !== envelope.request.deadlineAtUtc
  ) {
    throw new Error("Worker status does not bind the immutable request");
  }
}

function assertVerifierStatusIdentity(
  status: VerifierStatus,
  envelope: WorkerRequestEnvelope,
): void {
  if (
    status.jobId !== envelope.request.jobId ||
    status.periodKey !== envelope.request.periodKey ||
    status.generation !== envelope.request.generation ||
    status.requestSha256 !== envelope.requestSha256 ||
    status.requestedAtUtc !== envelope.request.requestedAtUtc ||
    status.deadlineAtUtc !== envelope.request.deadlineAtUtc
  ) {
    throw new Error("Verifier status does not bind the immutable request");
  }
}

/** Drain every chunk of a child stdout stream into the bound destination
 * file with checked per-write progress. The destination is never closed:
 * the verifier owns its lifecycle and syncs/stats after the callback
 * returns. Explicit `for await` plus `FsFile.write` is required because
 * `pipeTo(destination.writable, { preventClose: true })` leaves buffered
 * bytes unflushed in the stream wrapper, so a later sync/stat sees zero
 * bytes even though the producer exited successfully. */
export async function pumpGpgStdout(
  stdout: ReadableStream<Uint8Array>,
  destination: Deno.FsFile,
): Promise<number> {
  let total = 0;
  for await (const chunk of stdout) {
    let offset = 0;
    while (offset < chunk.byteLength) {
      const written = await destination.write(chunk.subarray(offset));
      if (!Number.isSafeInteger(written) || written <= 0) {
        throw new Error("GPG plaintext write made no progress");
      }
      offset += written;
      total += written;
    }
  }
  return total;
}

/** Standard GPG decrypt callback for one archive: root streams the
 * ciphertext into `sudo -u codex gpg` with a public-only custom home; the
 * task-owned SSH reverse extra-socket tunnel supplies the decrypting agent.
 * No private key exists on the source and the default agent socket is never
 * touched. */
export function makeDecryptArchive(publicHome: string): DecryptArchive {
  return async (ciphertextPath, destination) => {
    const socketResult = await new Deno.Command("sudo", {
      args: [
        "-n",
        "-u",
        "codex",
        "gpgconf",
        "--homedir",
        publicHome,
        "--list-dirs",
        "agent-socket",
      ],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!socketResult.success) {
      throw new Error("Custom agent socket resolution failed");
    }
    const agentSocket = new TextDecoder().decode(socketResult.stdout).trim()
      .split("\n").at(-1) ?? "";
    const defaultResult = await new Deno.Command("sudo", {
      args: ["-n", "-u", "codex", "gpgconf", "--list-dirs", "agent-socket"],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!defaultResult.success) {
      throw new Error("Default agent socket resolution failed");
    }
    const defaultSocket = new TextDecoder().decode(defaultResult.stdout).trim()
      .split("\n").at(-1) ?? "";
    if (agentSocket === "" || agentSocket === defaultSocket) {
      throw new Error("Custom agent socket does not differ from the default");
    }
    const privateKeys = `${publicHome}/private-keys-v1.d`;
    try {
      const entries = [];
      for await (const entry of Deno.readDir(privateKeys)) {
        entries.push(entry);
      }
      if (entries.length > 0) {
        throw new Error("Source private key directory is not empty");
      }
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    const ciphertext = await Deno.open(ciphertextPath, { read: true });
    const child = new Deno.Command("sudo", {
      args: [
        "-n",
        "-u",
        "codex",
        "gpg",
        "--no-options",
        "--no-autostart",
        "--batch",
        "--no-tty",
        "--homedir",
        publicHome,
        "--status-fd=2",
        "--decrypt",
      ],
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    let statusText = "";
    let overflow = false;
    const diagnostics = (async () => {
      const decoder = new TextDecoder();
      for await (const bytes of child.stderr) {
        if (statusText.length + bytes.length > MAX_GPG_DIAGNOSTIC_BYTES) {
          overflow = true;
          continue;
        }
        statusText += decoder.decode(bytes, { stream: true });
      }
      statusText += decoder.decode();
      return statusText;
    })();
    // All four legs start concurrently: stdin pumping, checked stdout
    // drains, bounded stderr collection and the exit status are never
    // awaited one-by-one, so a stalled leg cannot deadlock another.
    const settled = await Promise.allSettled([
      ciphertext.readable.pipeTo(child.stdin),
      pumpGpgStdout(child.stdout, destination),
      diagnostics,
      child.status,
    ]);
    try {
      ciphertext.close();
    } catch (error) {
      // `readable.pipeTo` auto-closes the ciphertext handle on completion;
      // cleanup must never mask a successful integrity result.
      if (!(error instanceof Deno.errors.BadResource)) throw error;
    }
    const failed = settled.find((entry) => entry.status === "rejected");
    if (failed !== undefined) {
      const reason = (failed as PromiseRejectedResult).reason;
      throw reason instanceof Error ? reason : new Error(String(reason));
    }
    if (overflow) throw new Error("GPG diagnostics exceeded the bound");
    const lines = (settled[2] as PromiseFulfilledResult<string>).value
      .split("\n");
    const exited =
      (settled[3] as PromiseFulfilledResult<Deno.CommandStatus>).value;
    if (!exited.success || decideGpgStatus(lines).rejected) {
      throw new Error("GPG integrity verification failed");
    }
    return { integrityChecked: true };
  };
}

async function importRecipient(
  publicHome: string,
  recipientBytes: Uint8Array,
): Promise<void> {
  // Idempotent public-only import as codex; the keyring never holds secrets.
  const child = new Deno.Command("sudo", {
    args: [
      "-n",
      "-u",
      "codex",
      "gpg",
      "--no-options",
      "--no-autostart",
      "--batch",
      "--no-tty",
      "--homedir",
      publicHome,
      "--import",
    ],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const writer = child.stdin.getWriter();
  try {
    await writer.write(recipientBytes);
  } catch {
    // The command may have exited early; its status below is authoritative.
  }
  try {
    await writer.close();
  } catch {
    // Already closed.
  }
  const output = await child.output();
  if (!output.success) throw new Error("Public recipient import failed");
}

async function ensurePublicHome(publicHome: string): Promise<void> {
  try {
    const info = await Deno.lstat(publicHome);
    if (info.isSymlink || !info.isDirectory) {
      throw new Error("Source public key home must be a real directory");
    }
    if (info.mode === null || (info.mode & 0o777) !== 0o700) {
      throw new Error("Source public key home must grant only owner access");
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
    await Deno.mkdir(publicHome, { mode: 0o700, recursive: true });
    const parent = publicHome.slice(0, publicHome.lastIndexOf("/"));
    const chown = await new Deno.Command("chown", {
      args: ["codex:codex", publicHome],
    }).output();
    void chown;
    const real = await Deno.realPath(parent);
    void real;
    await Deno.chmod(publicHome, 0o700);
  }
}

function verifierErrorCode(message: string): VerifierErrorCode {
  const text = message.toLowerCase();
  if (text.includes("rejected") || text.includes("invocation")) {
    return "REJECTED";
  }
  if (
    text.includes("result") || text.includes("index") ||
    text.includes("status")
  ) {
    return "RESULT_INVALID";
  }
  if (text.includes("recovery") || text.includes("reconstruction")) {
    return "RECONSTRUCT_FAILED";
  }
  if (
    text.includes("decrypt") || text.includes("gpg") ||
    text.includes("gnupg") || text.includes("agent")
  ) {
    return "DECRYPT_FAILED";
  }
  if (text.includes("verify") || text.includes("verification")) {
    return "VERIFY_FAILED";
  }
  return "STATUS_FAILED";
}

/** Sum of the validated index's ciphertext archive byte totals with safe
 * integer arithmetic; a malformed or overflowing total fails closed. */
export function verifierCiphertextTotal(index: RecoveryIndex): number {
  let total = 0;
  for (const archive of index.archives) {
    const bytes = archive.bytes;
    if (!Number.isSafeInteger(bytes) || bytes <= 0) {
      throw new Error("Recovery index archive byte total is invalid");
    }
    total += bytes;
    if (!Number.isSafeInteger(total)) {
      throw new Error("Recovery index archive byte totals overflow");
    }
  }
  return total;
}

/** Additional bytes the recovery/verification filesystem must still hold,
 * over and above what is already on disk: one complete new ciphertext copy
 * plus the full decrypted plaintext plus a conservative ciphertext-sized
 * allowance for verifier scratch/sample overhead. The capture stage encrypts
 * with `--compress-algo none`, so the ciphertext byte total bounds the
 * compressed plaintext size; after reconstruction the ciphertext copy is on
 * disk and only the plaintext/scratch requirement remains (never counting
 * the reconstruction twice). The 5 GiB reserve + 512 MiB margin are applied
 * by the on-disk check, not here. */
export function verifierHeadroomRequirement(
  index: RecoveryIndex,
  afterReconstruction: boolean,
): number {
  const ciphertext = verifierCiphertextTotal(index);
  const reconstructionCopy = afterReconstruction ? 0 : ciphertext;
  const requirement = reconstructionCopy + ciphertext + ciphertext;
  if (!Number.isSafeInteger(requirement) || requirement < 0) {
    throw new Error("Verifier headroom requirement overflows");
  }
  return requirement;
}

/** Fixed GNU df availability read: `df -B1 --output=avail <path>` resolved
 * from PATH, with strict numeric parsing and a fail-closed unreadable or
 * malformed capacity (non-zero exit, extra data lines, non-numeric output,
 * non-safe-integer or non-positive values all reject). */
export async function readVerifierAvailBytes(path: string): Promise<number> {
  const result = await new Deno.Command("df", {
    args: ["-B1", "--output=avail", path],
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!result.success) {
    throw new Error(
      `Verifier filesystem availability check failed (${result.code})`,
    );
  }
  const lines = new TextDecoder().decode(result.stdout).split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
  let data = lines;
  if (data.length > 0 && /^Avail$/i.test(data[0])) data = data.slice(1);
  if (data.length !== 1 || !/^[0-9]+$/.test(data[0])) {
    throw new Error("Verifier filesystem availability output is malformed");
  }
  const avail = Number(data[0]);
  if (!Number.isSafeInteger(avail) || avail <= 0) {
    throw new Error("Verifier filesystem availability is invalid");
  }
  return avail;
}

async function nearestExistingAncestor(path: string): Promise<string> {
  let current = path;
  while (true) {
    try {
      await Deno.stat(current);
      return current;
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    const parent = current.slice(0, current.lastIndexOf("/"));
    if (parent === "" || parent === current) {
      throw new Error(`No existing ancestor for ${path}`);
    }
    current = parent;
  }
}

/** Real capacity gate before any verifier payload write: the recovery and
 * verification production paths must live on the checked filesystem, and the
 * available bytes there must cover the requirement plus the 5 GiB reserve
 * and 512 MiB margin. Any unreadable capacity fails closed. */
export async function assertVerifierHeadroom(
  recoveryDir: string,
  verificationDir: string,
  requirement: number,
): Promise<void> {
  if (!Number.isSafeInteger(requirement) || requirement < 0) {
    throw new Error("Verifier headroom requirement is invalid");
  }
  const [recoveryInfo, verificationInfo] = await Promise.all([
    Deno.stat(recoveryDir),
    Deno.stat(await nearestExistingAncestor(verificationDir)),
  ]);
  if (
    recoveryInfo.dev === null || verificationInfo.dev === null ||
    recoveryInfo.dev !== verificationInfo.dev
  ) {
    throw new Error(
      "Verifier recovery and verification paths are on different filesystems",
    );
  }
  const avail = await readVerifierAvailBytes(recoveryDir);
  const required = requirement + VERIFIER_SPACE_MIN_FREE;
  if (!Number.isSafeInteger(required) || avail - required < 0) {
    throw new Error(
      `Verifier recovery space insufficient: available ${avail} bytes, ` +
        `required ${required} bytes`,
    );
  }
}

async function runSourceVerifier(
  jobId: string,
  settings: TransportSettings,
  invocationId: string,
  recipientBytes: Uint8Array,
  deps: SourceVerifyDependencies,
): Promise<VerifierStatus> {
  const request = settings.envelope.request;
  const base = await assertRootDir(deps.basePath, "backup base");
  const jobDir = await assertRootDir(`${base}/jobs/${jobId}`, "job");
  const at = () => deps.now().getTime();
  const startedAt = at();
  let serial = Promise.resolve();
  const enqueueStatus = (status: VerifierStatus): Promise<void> => {
    const value = validateVerifierStatus(status);
    serial = serial.then(() =>
      writeRootAtomic(
        `${jobDir}/${STATUS_FILE}`,
        new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`),
        "verifier status",
        false,
      )
    ).catch(() => {
      // A heartbeat persistence failure surfaces at the terminal write.
    });
    return serial;
  };
  const persistStatusNow = async (status: VerifierStatus): Promise<void> => {
    clearInterval(heartbeat);
    await serial;
    await writeRootAtomic(
      `${jobDir}/${STATUS_FILE}`,
      new TextEncoder().encode(
        `${JSON.stringify(validateVerifierStatus(status), null, 2)}\n`,
      ),
      "verifier status",
      false,
    );
  };
  const statusFor = (
    state: VerifierState,
    finishedAtUtc: string | null,
    extra: Partial<VerifierStatus> = {},
  ): VerifierStatus => {
    const nowAt = at();
    return validateVerifierStatus({
      schemaVersion: 1,
      jobId: request.jobId,
      periodKey: request.periodKey,
      generation: request.generation,
      requestSha256: settings.envelope.requestSha256,
      requestedAtUtc: request.requestedAtUtc,
      deadlineAtUtc: request.deadlineAtUtc,
      invocationId,
      state,
      startedAtUtc: new Date(startedAt).toISOString(),
      updatedAtUtc: new Date(nowAt).toISOString(),
      heartbeatAtUtc: new Date(nowAt).toISOString(),
      finishedAtUtc: finishedAtUtc === null
        ? null
        : canonicalUtc(finishedAtUtc, "finishedAtUtc"),
      ...extra,
    });
  };
  const heartbeat = setInterval(() => {
    enqueueStatus(statusFor("VERIFYING", null)).catch(() => {});
  }, HEARTBEAT_INTERVAL_MS);

  let workerStatus: WorkerStatus;
  try {
    const savedStatus = validateWorkerStatus(
      JSON.parse(
        new TextDecoder().decode(
          await readRootBounded(
            `${jobDir}/${STATUS_FILE}`,
            MAX_STATUS_BYTES,
            "status",
          ),
        ),
      ),
    );
    if (savedStatus.state !== "PENDING_VERIFIER") {
      throw new Error(
        `Verifier requires a PENDING_VERIFIER worker status (got ${savedStatus.state})`,
      );
    }
    validateWorkerStatusIdentity(savedStatus, settings.envelope);
    if (savedStatus.invocationId === invocationId) {
      throw new Error("Verifier invocation differs from the worker proof");
    }
    workerStatus = savedStatus;
  } catch (error) {
    try {
      await persistStatusNow(
        statusFor("FAILED", new Date(at()).toISOString(), {
          errorCode: "REJECTED",
        }),
      );
    } catch {
      // The original rejection is the visible failure.
    }
    throw error;
  }

  try {
    const resultBytes = await readRootBounded(
      `${jobDir}/${RESULT_FILE}`,
      MAX_RESULT_BYTES,
      "result",
    );
    const resultSha256 = await sha256Hex(resultBytes);
    if (
      workerStatus.resultSha256 !== undefined &&
      workerStatus.resultSha256 !== resultSha256
    ) {
      throw new Error("Worker result hash does not match its terminal status");
    }
    const workerResult = await validateSavedWorkerResult(
      JSON.parse(new TextDecoder().decode(resultBytes)),
      settings.indexRecipient,
      {
        requestSha256: settings.envelope.requestSha256,
        generation: request.generation,
        recipientSha256: request.recipientSha256,
        recipientFingerprint: request.recipientFingerprint,
      },
    );
    const publishedIndex = workerResult.publishedIndex;

    const verifierRequest = {
      schemaVersion: 1,
      jobId: request.jobId,
      requestSha256: settings.envelope.requestSha256,
      generation: request.generation,
      invocationId,
      persistedAtUtc: new Date(at()).toISOString(),
    };
    await writeRootAtomic(
      `${jobDir}/${VERIFIER_REQUEST_FILE}`,
      new TextEncoder().encode(`${JSON.stringify(verifierRequest, null, 2)}\n`),
      "verifier request",
      true,
    );
    const publicHome = `${PUBLIC_HOME_BASE}/${request.generation}`;
    await ensurePublicHome(publicHome);
    await importRecipient(publicHome, recipientBytes);

    const store = deps.storeFor(settings.B2Settings);
    const publishedBytes = await store.get(publishedIndex.object);
    if (await sha256Hex(publishedBytes) !== publishedIndex.ciphertextSha256) {
      throw new Error(
        "Published index ciphertext hash differs from the result",
      );
    }
    await enqueueStatus(statusFor("VERIFYING", null));

    const recoveryDir = `${RECOVERY_BASE}/${request.generation}`;
    await ensureRecoveryDir(recoveryDir);
    const verificationDir = `${VERIFICATION_BASE}/${request.generation}`;
    // Real capacity gate before any reconstruction payload is written: the
    // recovery and verification paths must be on the same checked
    // filesystem, and it must hold the fresh ciphertext copy plus the
    // plaintext plus a scratch allowance on top of the free reserve.
    await assertVerifierHeadroom(
      recoveryDir,
      verificationDir,
      verifierHeadroomRequirement(workerResult.index, false),
    );
    const reconstructed = await deps.reconstruct(
      workerResult.index,
      store,
      recoveryDir,
    );
    try {
      await Deno.mkdir(verificationDir, { mode: 0o700 });
    } catch (error) {
      if (error instanceof Deno.errors.AlreadyExists) {
        throw new Error("Verification output directory already exists");
      }
      throw error;
    }
    // Recheck once the reconstruction is on disk so its bytes are already
    // subtracted by availability: only the remaining plaintext/scratch
    // requirement plus the reserve must still fit.
    await assertVerifierHeadroom(
      recoveryDir,
      verificationDir,
      verifierHeadroomRequirement(workerResult.index, true),
    );
    const receipt = await deps.verify(
      workerResult.index,
      reconstructed,
      verificationDir,
      makeDecryptArchive(publicHome),
    );
    const receiptBytes = new TextEncoder().encode(
      `${JSON.stringify(receipt, null, 2)}\n`,
    );
    const receiptSha256 = await sha256Hex(receiptBytes);
    await writeRootAtomic(
      `${jobDir}/${RECEIPT_FILE}`,
      receiptBytes,
      "receipt",
      true,
    );
    const accepted = statusFor("ACCEPTED", new Date(at()).toISOString(), {
      receiptSha256,
    });
    await persistStatusNow(accepted);
    return accepted;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const failed = statusFor("FAILED", new Date(at()).toISOString(), {
      errorCode: verifierErrorCode(message),
    });
    try {
      await persistStatusNow(failed);
      return failed;
    } catch {
      throw error;
    }
  }
}

async function ensureRecoveryDir(recoveryDir: string): Promise<void> {
  const base = recoveryDir.slice(0, recoveryDir.lastIndexOf("/"));
  try {
    await Deno.mkdir(base, { mode: 0o700 });
  } catch (error) {
    if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
  }
  try {
    await assertRootDir(base, "recovery base");
    await assertRootDir(recoveryDir, "recovery");
  } catch (error) {
    if (error instanceof Error && error.message.includes("is missing")) {
      await Deno.mkdir(recoveryDir, { mode: 0o700 });
      await assertRootDir(recoveryDir, "recovery");
      return;
    }
    throw error;
  }
}

/** Source reconstruct+verify under the source lock; fixed public-only GPG
 * home and the task-owned tunnel; terminal ACCEPTED carries the receipt hash
 * while machineBootRestoreProved stays false. */
export async function runRemoteVerifier(
  jobIdInput: unknown,
  deps: Partial<SourceVerifyDependencies> = {},
): Promise<VerifierStatus> {
  const jobId = validateJobId(jobIdInput);
  const { settings, recipientBytes } = await loadRuntimeSettings();
  if (settings.envelope.request.jobId !== jobId) {
    throw new Error("Runtime settings do not bind this jobId");
  }
  const invocationId = requireInvocationId();
  const dependencies: SourceVerifyDependencies = {
    ...SOURCE_VERIFY_DEPS,
    ...deps,
  };
  return await dependencies.lock(SOURCE_LOCK_PATH, () =>
    runSourceVerifier(
      jobId,
      settings,
      invocationId,
      recipientBytes,
      dependencies,
    ));
}

// ---------------------------------------------------------------------------
// Pi controller dependencies
// ---------------------------------------------------------------------------

export interface PiDeps {
  now: () => Date;
  lock: <T>(path: string, work: () => Promise<T>) => Promise<T>;
  private: PrivateSeam;
  remote: RemoteSeam;
  tunnel: TunnelSeam;
  metadataStore: MetadataStoreFactory;
  gate: GateSeam;
  logger: (message: string) => void;
  sleep: (ms: number) => Promise<void>;
}

export function realPiDeps(): PiDeps {
  const runner = realRemoteRunner;
  return {
    now: () => new Date(),
    lock: withBackupLock,
    private: realPrivateSeam(),
    remote: realRemoteSeam(runner),
    tunnel: realTunnelSeam(runner, PI_KEYRING_PATH),
    metadataStore: realMetadataStoreFactory,
    gate: realGateSeam(),
    logger: (message) => console.log(message),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  };
}

// ---------------------------------------------------------------------------
// Pi configuration loading
// ---------------------------------------------------------------------------

export interface PiDeployment {
  sourceRevision: string;
  recipientSha256: string;
  recipientFingerprint: string;
}

export interface PiSourceConfig {
  sources: FileSource[];
  b2: B2Settings;
  recipientPath: string;
  recipientBytes: Uint8Array;
  exclusionsText: string;
}

async function loadDeployment(deps: PiDeps): Promise<PiDeployment> {
  const value = await deps.private.read<unknown>(DEPLOYMENT_PATH);
  if (!isRecord(value) || Object.keys(value).length !== 3) {
    throw new Error("Backblaze deployment identity is missing");
  }
  if (
    typeof value.recipientSha256 !== "string" ||
    !SHA256_PATTERN.test(value.recipientSha256)
  ) {
    throw new Error("Deployment recipient hash is malformed");
  }
  if (
    typeof value.recipientFingerprint !== "string" ||
    !FINGERPRINT_PATTERN.test(value.recipientFingerprint)
  ) {
    throw new Error("Deployment recipient fingerprint is malformed");
  }
  return {
    sourceRevision: validateRevision(value.sourceRevision),
    recipientSha256: value.recipientSha256,
    recipientFingerprint: value.recipientFingerprint,
  };
}

async function loadSourceConfig(deps: PiDeps): Promise<PiSourceConfig> {
  const config = await deps.private.read<Record<string, unknown>>(
    B2_CONFIG_PATH,
  );
  if (!isRecord(config)) throw new Error("B2 scoped configuration is missing");
  const deployment = await loadDeployment(deps);
  const recipientPath = RECIPIENT_PATH;
  const recipientBytes = await deps.private.readBytes(recipientPath, 64 * 1024);
  if (recipientBytes === undefined) {
    throw new Error("Public recipient key is missing");
  }
  if (await sha256Hex(recipientBytes) !== deployment.recipientSha256) {
    throw new Error("Public recipient does not match the deployment identity");
  }
  const exclusionsText = await deps.private.readText(
    "config/restic-excludes.txt",
    64 * 1024,
  );
  if (exclusionsText === undefined) {
    throw new Error("Approved exclusions file is missing");
  }
  if (!Array.isArray(config.sources)) {
    throw new Error("B2 scoped configuration sources are missing");
  }
  return {
    sources: config.sources as FileSource[],
    b2: {
      accessKeyId: config.accessKeyId as string,
      secretAccessKey: config.secretAccessKey as string,
      bucketId: config.bucketId as string,
      bucketName: config.bucketName as string,
    },
    recipientPath,
    recipientBytes,
    exclusionsText,
  };
}

export interface BackblazeRunReport {
  status: string;
  observedAtUtc: string;
  jobId?: string;
  generation?: string;
  healthy: boolean;
  detail?: string;
}

// ---------------------------------------------------------------------------
// Pi step machine
// ---------------------------------------------------------------------------

async function fetchStatusJson(
  deps: PiDeps,
  jobId: string,
): Promise<unknown | null> {
  const script = [
    `path=${shellQuote(`${BACKUP_BASE}/jobs/${jobId}/${STATUS_FILE}`)}`,
    `test -r "$path" || { echo __MISSING__; exit 0; }`,
    `sz=$(stat -c %s "$path")`,
    `test "$sz" -le ${MAX_STATUS_BYTES} || { echo __TOO_LARGE__; exit 0; }`,
    'cat "$path"',
  ].join("\n");
  const result = await deps.remote.root(script);
  if (result.code !== 0) return null;
  const text = result.stdout.trim();
  if (text === "__MISSING__") return null;
  if (text === "__TOO_LARGE__") {
    throw new Error("Source status exceeds the read bound");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Source status is not valid JSON");
  }
}

async function fetchBoundedFile(
  deps: PiDeps,
  jobId: string,
  name: string,
  maxBytes: number,
  what: string,
): Promise<Uint8Array> {
  const script = [
    `path=${shellQuote(`${BACKUP_BASE}/jobs/${jobId}/${name}`)}`,
    `test -r "$path" || exit 3`,
    `sz=$(stat -c %s "$path")`,
    `test "$sz" -le ${maxBytes} || exit 4`,
    'cat "$path"',
  ].join("\n");
  const result = await deps.remote.root(script);
  if (result.code !== 0) {
    throw new Error(`${what} download failed (${result.code})`);
  }
  return new TextEncoder().encode(result.stdout);
}

async function observeProof(
  deps: PiDeps,
  job: ControllerJob,
  unitName: string,
): Promise<ClearProofObservation> {
  const observed = await deps.remote.observe(
    unitName,
    job.envelope.request.jobId,
  );
  if (!observed.reachable) {
    throw new Error("Source is unreachable at terminal proof time");
  }
  return {
    props: observed.props,
    lockFree: observed.lockFree,
    checkedAtUtc: deps.now().toISOString(),
  };
}

/** A durable terminal phase (WORKER_TERMINAL, ACCEPTED or FAILED) may
 * resume with its matching gate still alive after a crash between the
 * durable persist and the gate removal: the terminal unit must be
 * re-observed, a FRESH terminal proof revalidated against the exact
 * surviving gate, and only then the gate is removed — before any next
 * launch or prune. A gate already absent is idempotently fine in those
 * durable phases; a foreign or identity-mismatched gate is never cleared
 * and throws, while a transiently unreachable or not-yet-terminal unit
 * keeps the gate and returns false so the poll pair retries. */
async function clearSurvivingTerminalGate(
  deps: PiDeps,
  job: ControllerJob,
  unitName: string,
  status: WorkerStatus | VerifierStatus,
): Promise<boolean> {
  const request = job.envelope.request;
  const gate = await deps.gate.read();
  if (gate === null) return true;
  if (
    gate.state !== "active" ||
    gate.jobId !== request.jobId ||
    gate.periodKey !== request.periodKey ||
    gate.generation !== request.generation ||
    gate.requestSha256 !== job.envelope.requestSha256 ||
    gate.unitName !== unitName
  ) {
    throw new Error("Surviving terminal gate does not match the job or unit");
  }
  let observation: ClearProofObservation;
  try {
    observation = await observeProof(deps, job, unitName);
  } catch {
    // Source unreachable at resume time: keep the gate and let the next
    // poll re-observe; nothing is launched or pruned meanwhile.
    return false;
  }
  if (observation.props.get("InvocationID") !== status.invocationId) {
    throw new Error(
      "Surviving terminal gate unit invocation no longer matches the status",
    );
  }
  const active = observation.props.get("ActiveState");
  const sub = observation.props.get("SubState");
  if (active !== "failed" && !(active === "active" && sub === "exited")) {
    // Not terminal yet (or a fresh nonterminal observation): keep the gate.
    return false;
  }
  const proof = buildClearProof(observation, gate, status.state, {
    updatedAtUtc: status.updatedAtUtc,
    heartbeatAtUtc: status.heartbeatAtUtc,
    finishedAtUtc: status.finishedAtUtc ?? deps.now().toISOString(),
  });
  await deps.gate.clear(gate, proof);
  return true;
}

async function installTransportRuntime(
  deps: PiDeps,
  job: ControllerJob,
  config: PiSourceConfig,
): Promise<void> {
  const request = job.envelope.request;
  const runtimeDir = `${JOBS_RUNTIME_ROOT}/${request.jobId}`;
  const settings: TransportSettings = {
    schemaVersion: 1,
    envelope: job.envelope,
    captureSettings: {
      sources: config.sources,
      generation: request.generation,
      recipientFile: `${runtimeDir}/${RECIPIENT_FILE}`,
      recipientSha256: request.recipientSha256,
      recipientFingerprint: request.recipientFingerprint,
      exclusionsText: config.exclusionsText,
    },
    indexRecipient: {
      recipientFile: `${runtimeDir}/${RECIPIENT_FILE}`,
      recipientSha256: request.recipientSha256,
      recipientFingerprint: request.recipientFingerprint,
    },
    B2Settings: config.b2,
    sourceRevision: request.sourceRevision,
  };
  const files: { path: string; data: number[]; sha256: string }[] = [];
  const entries = [
    {
      path: SETTINGS_FILE,
      bytes: new TextEncoder().encode(
        `${JSON.stringify(settings, null, 2)}\n`,
      ),
    },
    { path: RECIPIENT_FILE, bytes: config.recipientBytes },
    {
      path: ENTRY_WORKER_FILE,
      bytes: new TextEncoder().encode(
        entryWorkerText(request.jobId, request.sourceRevision),
      ),
    },
    {
      path: ENTRY_VERIFY_FILE,
      bytes: new TextEncoder().encode(
        entryVerifyText(request.jobId, request.sourceRevision),
      ),
    },
  ];
  for (const entry of entries) {
    files.push({
      path: entry.path,
      data: Array.from(entry.bytes),
      sha256: await sha256Hex(entry.bytes),
    });
  }
  const result = await deps.remote.installer({
    jobId: request.jobId,
    sourceRevision: request.sourceRevision,
    files,
  });
  if (result.code !== 0) {
    throw new Error(`Transport runtime installation failed (${result.code})`);
  }
}

async function beat(
  deps: PiDeps,
  state: ControllerState,
  phase: ControllerPhase,
  workerStatus?: WorkerStatus,
  verifierStatus?: VerifierStatus,
): Promise<ControllerState> {
  const job = state.job;
  if (job === undefined) throw new Error("No controller job to update");
  const nowUtc = deps.now().toISOString();
  // The heartbeat is the actual source status heartbeat, never the Pi's
  // fresh polling time: polling the controller with an unreachable or
  // silent source must not make the job look healthy.
  const heartbeatAtUtc = workerStatus?.heartbeatAtUtc ??
    verifierStatus?.heartbeatAtUtc ?? job.heartbeatAtUtc;
  const next = {
    ...job,
    phase,
    updatedAtUtc: nowUtc,
    heartbeatAtUtc,
    ...(workerStatus === undefined ? {} : { workerStatus }),
    ...(verifierStatus === undefined ? {} : { verifierStatus }),
  };
  const updated = validateControllerState({ ...state, job: next });
  await deps.private.write(CONTROLLER_STATE_PATH, updated);
  return updated;
}

async function persist(
  deps: PiDeps,
  state: ControllerState,
): Promise<ControllerState> {
  const updated = validateControllerState(state);
  await deps.private.write(CONTROLLER_STATE_PATH, updated);
  return updated;
}

async function failJob(
  deps: PiDeps,
  state: ControllerState,
  code: string,
  detail?: string,
): Promise<ControllerState> {
  const job = state.job;
  if (job === undefined) throw new Error("No controller job to fail");
  const next = {
    ...job,
    phase: "FAILED" as ControllerPhase,
    failure: {
      code,
      atUtc: deps.now().toISOString(),
      ...(detail === undefined ? {} : { detail }),
    },
  };
  return await persist(deps, validateControllerState({ ...state, job: next }));
}

async function orphanJob(
  deps: PiDeps,
  state: ControllerState,
  reason: OrphanReason,
): Promise<ControllerState> {
  const gate = await deps.gate.read();
  if (gate !== null) await deps.gate.orphan(gate, reason);
  return await failJob(deps, state, `ORPHANED_${reason}`);
}

/** One monotonic controller step; every mutation is a durable write and the
 * gate/lock identity is re-checked before any remote launch or clear. */
export async function stepBackupController(
  stateInput: ControllerState | undefined,
  deps: PiDeps,
  now: Date,
): Promise<ControllerState> {
  const state = validateControllerState(stateInput ?? emptyControllerState());
  const window = weekWindow(now);
  const inWindow = now.getTime() >= Date.parse(window.startAtUtc) &&
    now.getTime() < Date.parse(window.endAtUtc);
  const requestNewJob = async (
    base: ControllerState,
    currentWindow: WeekWindow,
  ): Promise<ControllerState> => {
    const oracleState = await deps.private.read<unknown>(
      ".private/backup-runtime.json",
    );
    const scheduledClaim = await deps.private.read<unknown>(MANIFEST_PATH);
    assertBackblazeLaunchAllowed(oracleState, scheduledClaim);
    const deployment = await loadDeployment(deps);
    const config = await loadSourceConfig(deps);
    const uuid = crypto.randomUUID();
    const captureSettings: CaptureSettings = {
      sources: config.sources,
      generation: `generation-${uuid}`,
      recipientFile: `${JOBS_RUNTIME_ROOT}/jobs/job-${uuid}/${RECIPIENT_FILE}`,
      recipientSha256: deployment.recipientSha256,
      recipientFingerprint: deployment.recipientFingerprint,
      exclusionsText: config.exclusionsText,
    };
    validateCaptureSettings(captureSettings);
    const envelope = buildRequestEnvelope({
      jobUuid: uuid,
      periodKey: currentWindow.periodKey,
      requestedAtUtc: now.toISOString(),
      recipientSha256: deployment.recipientSha256,
      recipientFingerprint: deployment.recipientFingerprint,
      sourceRevision: deployment.sourceRevision,
      sourceConfigSha256: sourceConfigSha256(captureSettings),
    });
    const created = {
      ...base,
      job: newJobState(envelope, now),
    };
    await persist(deps, created);
    deps.logger(
      `Backblaze job ${envelope.request.jobId} requested for ${currentWindow.periodKey}`,
    );
    return created;
  };
  const job = state.job;
  if (job === undefined) {
    if (!inWindow) {
      throw new Error(
        `Outside the Sunday catch-up window for ${window.periodKey}`,
      );
    }
    const gate = await deps.gate.read();
    if (gate !== null) {
      throw new Error(
        "Backblaze gate is active without a controller job",
      );
    }
    return await requestNewJob(state, window);
  }
  if (
    (job.phase === "COMPLETE" || job.phase === "FAILED") &&
    job.envelope.request.periodKey !== window.periodKey
  ) {
    // A closed previous period never blocks the next Sunday window, but a
    // fresh job is never created in the same period, never for a clock
    // rollback into an earlier period, and never while the active/orphaned
    // gate or an unfinished source still owns the slot.
    if (
      inWindow && job.envelope.request.periodKey < window.periodKey
    ) {
      const gate = await deps.gate.read();
      if (gate === null) {
        return await requestNewJob(state, window);
      }
    }
    return state;
  }

  const request = job.envelope.request;
  const generation = request.generation;
  const deadline = Date.parse(request.deadlineAtUtc);
  const remainingSec = Math.max(
    1,
    Math.floor((deadline - now.getTime()) / 1000),
  );
  const config = await loadSourceConfig(deps);
  const boundedDeadline = deadline;

  switch (job.phase) {
    case "REQUESTED": {
      // The immutable deadline gates every retry: an expired request never
      // installs or launches, and its owned gate (if any) is orphaned.
      if (now.getTime() > boundedDeadline) {
        const deadlineGate = await deps.gate.read();
        if (deadlineGate !== null && deadlineGate.jobId !== request.jobId) {
          throw new Error("Gate belongs to a different job");
        }
        return await orphanJob(
          deps,
          state,
          "SOURCE_UNREACHABLE_AT_DEADLINE",
        );
      }
      try {
        await installTransportRuntime(deps, job, config);
      } catch {
        // Transient transport failure before any gate or launch: claiming
        // WORKER_LAUNCHED here would make the next observe fail on the
        // missing gate. Stay REQUESTED; the poll pair retries the same
        // immutable request until the deadline.
        return await beat(deps, state, "REQUESTED");
      }
      const gate = await deps.gate.read();
      if (gate === null) {
        await deps.gate.create(
          deriveWorkerGate(request, job.envelope.requestSha256),
        );
        deps.logger("Created active unbound worker gate");
      } else if (gate.jobId !== request.jobId) {
        throw new Error("Gate belongs to a different job");
      }
      let launch: CommandResult;
      try {
        launch = await deps.remote.launchUnit({
          unitName: workerUnitName(generation),
          runtimeDir: `${JOBS_RUNTIME_ROOT}/${request.jobId}`,
          remainingSec,
          args: [
            "/usr/local/bin/deno",
            "run",
            "--allow-read",
            "--allow-write",
            "--allow-run",
            "--allow-env",
            "--allow-net",
            ENTRY_WORKER_FILE,
          ],
        });
      } catch {
        // A throw or lost response may follow an actual systemd launch, and
        // the exact unbound worker gate is already created: never replace
        // it, never fail terminally. Observe the same unit; matching
        // evidence resumes as WORKER_LAUNCHED, absence keeps the retry in
        // REQUESTED.
        let existing: ObservedUnit;
        try {
          existing = await deps.remote.observe(
            workerUnitName(generation),
            request.jobId,
          );
        } catch {
          return await beat(deps, state, "REQUESTED");
        }
        if (
          existing.reachable &&
          normalizeObservedInvocation(existing.props) !== null
        ) {
          return await beat(deps, state, "WORKER_LAUNCHED");
        }
        return await beat(deps, state, "REQUESTED");
      }
      if (launch.code !== 0) {
        // A resume after an interrupted launch may already own the unit;
        // an existing loaded unit is resumed instead of creating a second
        // one. An unknowable launch outcome stays resumable too.
        const existing = await deps.remote.observe(
          workerUnitName(generation),
          request.jobId,
        );
        if (
          !existing.reachable ||
          normalizeObservedInvocation(existing.props) === null
        ) {
          return await beat(deps, state, "WORKER_LAUNCHED");
        }
      }
      return await beat(deps, state, "WORKER_LAUNCHED");
    }
    case "WORKER_LAUNCHED":
    case "WORKER_RUNNING": {
      const observed = await deps.remote.observe(
        workerUnitName(generation),
        request.jobId,
      );
      if (!observed.reachable) {
        if (now.getTime() > boundedDeadline) {
          return await orphanJob(deps, state, "SOURCE_UNREACHABLE_AT_DEADLINE");
        }
        return await beat(deps, state, "WORKER_RUNNING");
      }
      const gate = await deps.gate.read();
      if (gate === null) {
        throw new Error("Worker gate is missing while the unit runs");
      }
      const invocation = observed.props.get("InvocationID") ?? null;
      if (invocation !== null && job.workerInvocationId !== invocation) {
        if (job.workerInvocationId !== null) {
          await deps.gate.orphan(gate, "UNIT_IDENTITY_MISMATCH");
          return await failJob(deps, state, "ORPHANED_UNIT_IDENTITY_MISMATCH");
        }
        const bound = await deps.gate.bind(gate, invocation);
        const boundState = await persist(deps, {
          ...state,
          job: { ...state.job!, workerInvocationId: bound.unitInvocationId },
        });
        return await beat(deps, boundState, "WORKER_RUNNING");
      }
      const rawStatus = observed.status ??
        await fetchStatusJson(deps, request.jobId);
      const status = rawStatus === null ? undefined : (() => {
        let parsed: WorkerStatus;
        try {
          parsed = validateWorkerStatus(rawStatus);
          validateWorkerStatusIdentity(parsed, job.envelope);
        } catch {
          // Malformed or identity-mismatched status is never a healthy
          // source heartbeat and never becomes terminal evidence.
          return undefined;
        }
        return parsed;
      })();
      if (
        status !== undefined && job.workerInvocationId !== null &&
        status.invocationId !== job.workerInvocationId
      ) {
        // A surviving status file from a different invocation of the same
        // unit must never move the job forward.
        const mismatched = await deps.gate.read();
        if (mismatched !== null) {
          await deps.gate.orphan(mismatched, "UNIT_IDENTITY_MISMATCH");
        }
        return await failJob(deps, state, "ORPHANED_UNIT_IDENTITY_MISMATCH");
      }
      const terminalStatus = status?.state === "PENDING_VERIFIER" ||
        status?.state === "FAILED";
      const unitTerminal = observed.props.get("ActiveState") === "failed" ||
        (observed.props.get("ActiveState") === "active" &&
          observed.props.get("SubState") === "exited");
      if (!terminalStatus || !unitTerminal) {
        if (now.getTime() > boundedDeadline) {
          return await orphanJob(deps, state, "TERMINAL_PROOF_MISSING");
        }
        return await beat(deps, state, "WORKER_RUNNING", status);
      }
      const proofObservation = await observeProof(
        deps,
        job,
        workerUnitName(generation),
      );
      const proofGate = await deps.gate.read();
      if (proofGate === null) {
        throw new Error("Worker gate vanished before proof");
      }
      let proof: unknown;
      try {
        proof = buildClearProof(
          proofObservation,
          proofGate,
          status!.state as string,
          {
            updatedAtUtc: status!.updatedAtUtc,
            heartbeatAtUtc: status!.heartbeatAtUtc,
            finishedAtUtc: status!.finishedAtUtc ?? now.toISOString(),
          },
        );
      } catch (error) {
        const reason = error instanceof Error &&
            error.message.toLowerCase().includes("invocation")
          ? "UNIT_IDENTITY_MISMATCH"
          : "TERMINAL_PROOF_MISSING";
        await deps.gate.orphan(proofGate, reason);
        return await failJob(deps, state, `ORPHANED_${reason}`);
      }
      // The durable terminal state is persisted BEFORE the gate is removed:
      // a crash between the two leaves WORKER_TERMINAL with the surviving
      // worker gate, which that phase re-observes and revalidates; a gate
      // must never be removed while a previously unused state remains.
      if (status!.state === "FAILED") {
        const failed = await failJob(
          deps,
          { ...state, job: { ...state.job!, workerStatus: status } },
          status!.errorCode ?? "WORKER_FAILED",
        );
        await deps.gate.clear(proofGate, proof);
        return failed;
      }
      const resultBytes = await fetchBoundedFile(
        deps,
        request.jobId,
        RESULT_FILE,
        MAX_RESULT_BYTES,
        "Worker result",
      );
      const resultSha256 = await sha256Hex(resultBytes);
      if (
        status!.resultSha256 !== undefined &&
        status!.resultSha256 !== resultSha256
      ) {
        throw new Error(
          "Worker result hash does not match its terminal status",
        );
      }
      const workerResult = await validateSavedWorkerResult(
        JSON.parse(new TextDecoder().decode(resultBytes)),
        {
          recipientFile:
            `${JOBS_RUNTIME_ROOT}/${request.jobId}/${RECIPIENT_FILE}`,
          recipientSha256: request.recipientSha256,
          recipientFingerprint: request.recipientFingerprint,
        },
        {
          requestSha256: job.envelope.requestSha256,
          generation: request.generation,
          recipientSha256: request.recipientSha256,
          recipientFingerprint: request.recipientFingerprint,
        },
      );
      await deps.private.writeBytes(
        `${PIP_JOB_EVIDENCE_PATH}/${request.jobId}/${RESULT_FILE}`,
        resultBytes,
      );
      deps.logger(
        `Worker result validated for ${request.generation} (resultSha256=${
          resultSha256.slice(0, 12)
        }...)`,
      );
      void workerResult;
      const terminal = {
        ...state.job!,
        phase: "WORKER_TERMINAL" as ControllerPhase,
        workerStatus: status,
        resultSha256,
      };
      const terminalPersisted = await persist(deps, {
        ...state,
        job: terminal,
      });
      await deps.gate.clear(proofGate, proof);
      return terminalPersisted;
    }
    case "WORKER_TERMINAL": {
      // A worker gate may survive a crash between the durable
      // WORKER_TERMINAL persist and its removal: it must be re-observed
      // and revalidated with a fresh terminal proof before anything is
      // launched. A gate already absent is idempotently fine.
      const workerGate = await deps.gate.read();
      if (
        workerGate !== null &&
        workerGate.unitName === workerUnitName(generation)
      ) {
        if (job.workerStatus === undefined) {
          throw new Error(
            "Terminal worker gate survives without a saved status",
          );
        }
        const cleared = await clearSurvivingTerminalGate(
          deps,
          job,
          workerUnitName(generation),
          job.workerStatus,
        );
        if (!cleared) return state;
      }
      // The immutable deadline gates WORKER_TERMINAL before any verifier
      // gate is created, any tunnel is opened or any verifier is launched:
      // an expired request reuses the REQUESTED expiry/orphan semantics. An
      // exact matching gate is orphaned (never cleared without proof); a
      // foreign gate is never touched.
      if (now.getTime() > boundedDeadline) {
        const deadlineGate = await deps.gate.read();
        if (deadlineGate !== null && deadlineGate.jobId !== request.jobId) {
          throw new Error("Gate belongs to a different job");
        }
        return await orphanJob(deps, state, "SOURCE_UNREACHABLE_AT_DEADLINE");
      }
      const derived = deriveVerifierGate(
        request,
        job.envelope.requestSha256,
      );
      const gate = await deps.gate.read();
      if (gate !== null) {
        // A resume may already own the derived verifier gate (crash after
        // gate creation); it must bind this exact job/unit identity and be
        // active.
        if (
          gate.state !== "active" ||
          gate.jobId !== request.jobId ||
          gate.periodKey !== request.periodKey ||
          gate.generation !== request.generation ||
          gate.requestSha256 !== job.envelope.requestSha256 ||
          gate.unitName !== verifyUnitName(generation)
        ) {
          throw new Error("Verifier gate identity does not match the job");
        }
      } else {
        await deps.gate.create(derived);
      }
      const publicHome = `${PUBLIC_HOME_BASE}/${generation}`;
      let existing: ObservedUnit;
      // An already-open tunnel means a previous WORKER_TERMINAL step in
      // this process opened one and its launch outcome was lost to a
      // transport error (the tunnel is process-local, so a fresh setup
      // never owns one): reconcile the exact named verifier unit before
      // assuming another launch is needed -- a reachable unit with a real
      // invocation resumes as VERIFIER_LAUNCHED without a second launch,
      // and its tunnel is reopened by that phase if none is open.
      if (deps.tunnel.current() !== null) {
        try {
          existing = await deps.remote.observe(
            verifyUnitName(generation),
            request.jobId,
          );
        } catch {
          // Transport still down: keep the same WORKER_TERMINAL job and
          // the exact verifier gate (never fail terminally, never claim a
          // launch); the next poll retries the reconcile.
          return await beat(deps, state, "WORKER_TERMINAL");
        }
        if (
          existing.reachable &&
          normalizeObservedInvocation(existing.props) !== null
        ) {
          return await beat(deps, state, "VERIFIER_LAUNCHED");
        }
      }
      let sockets: { socket: string; defaultSocket: string };
      try {
        sockets = await deps.remote.resolveAgentSocket(publicHome);
      } catch {
        // Transient transport failure after the exact verifier gate was
        // created and preserved: stay on the same WORKER_TERMINAL
        // job/generation so the gate survives and the retry resumes it.
        return await beat(deps, state, "WORKER_TERMINAL");
      }
      if (sockets.socket === sockets.defaultSocket) {
        await deps.gate.orphan(derived, "UNIT_IDENTITY_MISMATCH");
        return await failJob(deps, state, "AGENT_SOCKET_DEFAULT");
      }
      // The tunnel must be ready (remote TUNNEL_READY acknowledgement after
      // the -R forward succeeded) before the verifier is launched, and it
      // stays open across every later verifier step: closing it right after
      // the detached launch breaks every decryption.
      let handle: TunnelHandle;
      try {
        handle = await deps.tunnel.open(sockets.socket);
      } catch {
        // Same transient transport handling: the seam proves its own
        // readiness failure cleanup; the retry reopens the tunnel with the
        // exact gate still in place.
        return await beat(deps, state, "WORKER_TERMINAL");
      }
      let launch: CommandResult;
      try {
        launch = await deps.remote.launchUnit({
          unitName: verifyUnitName(generation),
          runtimeDir: `${JOBS_RUNTIME_ROOT}/${request.jobId}`,
          remainingSec,
          args: [
            "/usr/local/bin/deno",
            "run",
            "--allow-read",
            "--allow-write",
            "--allow-run",
            "--allow-env",
            "--allow-net",
            ENTRY_VERIFY_FILE,
          ],
        });
      } catch {
        // A throw or lost response may follow an actual systemd launch:
        // never replace or clear the exact verifier gate, never relaunch
        // blindly. Observe the same named unit to distinguish an
        // already-launched resume from a plain retry.
        try {
          existing = await deps.remote.observe(
            verifyUnitName(generation),
            request.jobId,
          );
        } catch {
          return await beat(deps, state, "WORKER_TERMINAL");
        }
        if (
          existing.reachable &&
          normalizeObservedInvocation(existing.props) !== null
        ) {
          return await beat(deps, state, "VERIFIER_LAUNCHED");
        }
        return await beat(deps, state, "WORKER_TERMINAL");
      }
      if (launch.code !== 0) {
        existing = await deps.remote.observe(
          verifyUnitName(generation),
          request.jobId,
        );
        if (!existing.reachable) {
          // Launch outcome and tunnel are uncertain: keep the same
          // invocation resumable; the poll pair orphans at the deadline.
          return await beat(deps, state, "VERIFIER_LAUNCHED");
        }
        if (normalizeObservedInvocation(existing.props) === null) {
          throw new Error(`Verifier unit launch failed (${launch.code})`);
        }
      }
      void handle;
      return await beat(deps, state, "VERIFIER_LAUNCHED");
    }
    case "VERIFIER_LAUNCHED":
    case "VERIFIER_RUNNING": {
      // The same invocation keeps its decrypt tunnel for its whole life.
      if (deps.tunnel.current() === null) {
        try {
          const sockets = await deps.remote.resolveAgentSocket(
            `${PUBLIC_HOME_BASE}/${generation}`,
          );
          await deps.tunnel.open(sockets.socket);
        } catch {
          // Reopen uncertainty: the verifier owns its lifecycle; polling
          // continues until its terminal status or the deadline orphan.
        }
      }
      const observed = await deps.remote.observe(
        verifyUnitName(generation),
        request.jobId,
      );
      if (!observed.reachable) {
        if (now.getTime() > boundedDeadline) {
          return await orphanJob(deps, state, "SOURCE_UNREACHABLE_AT_DEADLINE");
        }
        return await beat(deps, state, "VERIFIER_RUNNING");
      }
      const gate = await deps.gate.read();
      if (gate === null) {
        throw new Error("Verifier gate is missing while the unit runs");
      }
      const invocation = observed.props.get("InvocationID") ?? null;
      if (invocation !== null && job.verifierInvocationId !== invocation) {
        if (job.verifierInvocationId !== null) {
          await deps.gate.orphan(gate, "UNIT_IDENTITY_MISMATCH");
          return await failJob(deps, state, "ORPHANED_UNIT_IDENTITY_MISMATCH");
        }
        const bound = await deps.gate.bind(gate, invocation);
        const boundState = await persist(deps, {
          ...state,
          job: { ...state.job!, verifierInvocationId: bound.unitInvocationId },
        });
        return await beat(deps, boundState, "VERIFIER_RUNNING");
      }
      const rawStatus = observed.status ??
        await fetchStatusJson(deps, request.jobId);
      const status = rawStatus === null ? undefined : (() => {
        try {
          const parsed = validateVerifierStatus(rawStatus);
          assertVerifierStatusIdentity(parsed, job.envelope);
          return parsed;
        } catch {
          // Until the verifier writes its own bound status the file still
          // holds the worker terminal; polling simply continues. A status
          // that validates but does not bind this request is never used.
          return undefined;
        }
      })();
      if (
        status !== undefined && job.verifierInvocationId !== null &&
        status.invocationId !== job.verifierInvocationId
      ) {
        const mismatched = await deps.gate.read();
        if (mismatched !== null) {
          await deps.gate.orphan(mismatched, "UNIT_IDENTITY_MISMATCH");
        }
        return await failJob(deps, state, "ORPHANED_UNIT_IDENTITY_MISMATCH");
      }
      const terminal = status?.state === "ACCEPTED" ||
        status?.state === "FAILED";
      const unitTerminal = observed.props.get("ActiveState") === "failed" ||
        (observed.props.get("ActiveState") === "active" &&
          observed.props.get("SubState") === "exited");
      if (!terminal || !unitTerminal) {
        if (now.getTime() > boundedDeadline) {
          return await orphanJob(deps, state, "TERMINAL_PROOF_MISSING");
        }
        return await beat(deps, state, "VERIFIER_RUNNING", undefined, status);
      }
      const proofObservation = await observeProof(
        deps,
        job,
        verifyUnitName(generation),
      );
      const proofGate = await deps.gate.read();
      if (proofGate === null) {
        throw new Error("Verifier gate vanished before proof");
      }
      let proof: unknown;
      try {
        proof = buildClearProof(
          proofObservation,
          proofGate,
          status!.state as string,
          {
            updatedAtUtc: status!.updatedAtUtc,
            heartbeatAtUtc: status!.heartbeatAtUtc,
            finishedAtUtc: status!.finishedAtUtc ?? now.toISOString(),
          },
        );
      } catch (error) {
        const reason = error instanceof Error &&
            error.message.toLowerCase().includes("invocation")
          ? "UNIT_IDENTITY_MISMATCH"
          : "TERMINAL_PROOF_MISSING";
        await deps.gate.orphan(proofGate, reason);
        return await failJob(deps, state, `ORPHANED_${reason}`);
      }
      // The durable terminal state is persisted BEFORE the gate is removed:
      // a crash between the two leaves ACCEPTED with the surviving verifier
      // gate, which that phase re-observes and revalidates; a gate must
      // never be removed while a previously unused state remains.
      if (status!.state === "FAILED") {
        const failed = await failJob(
          deps,
          { ...state, job: { ...state.job!, verifierStatus: status } },
          status!.errorCode ?? "VERIFIER_FAILED",
        );
        await deps.gate.clear(proofGate, proof);
        return failed;
      }
      const acceptedState = await acceptCatalogEntry(
        deps,
        state,
        job,
        status!,
        now,
      );
      // Catalog membership and the ACCEPTED phase are persisted in ONE
      // recoverable write before the gate is removed: there is no
      // crash-dependent two-state acceptance.
      const accepted = {
        ...acceptedState.job!,
        phase: "ACCEPTED" as ControllerPhase,
        verifierStatus: status,
      };
      const acceptedPersisted = await persist(deps, {
        ...acceptedState,
        job: accepted,
      });
      await deps.gate.clear(proofGate, proof);
      return acceptedPersisted;
    }
    case "ACCEPTED": {
      // A verifier gate may survive a crash between the durable ACCEPTED
      // persist and its removal: it must be re-observed and revalidated
      // with a fresh terminal proof before any prune runs. A gate already
      // absent is idempotently fine.
      const verifierGate = await deps.gate.read();
      if (
        verifierGate !== null &&
        verifierGate.unitName === verifyUnitName(generation)
      ) {
        if (job.verifierStatus === undefined) {
          throw new Error(
            "Accepted verifier gate survives without a saved status",
          );
        }
        const cleared = await clearSurvivingTerminalGate(
          deps,
          job,
          verifyUnitName(generation),
          job.verifierStatus,
        );
        if (!cleared) return state;
      } else if (verifierGate !== null) {
        throw new Error("Accepted job gate does not match the verifier unit");
      }
      return await pruneStep(deps, state, now);
    }
    case "PRUNING": {
      return await pruneStep(deps, state, now);
    }
    case "PRUNED":
    case "CLEANUP_PENDING": {
      return await cleanupStep(deps, state, now);
    }
    case "COMPLETE":
      return state;
    case "FAILED": {
      // A failure may resume with its matching terminal gate still alive
      // (crash between the durable FAILED persist and its removal): the
      // same fresh-proof revalidation clears it; the gate is never removed
      // silently and a foreign gate is never cleared.
      const unitName = job.verifierStatus !== undefined
        ? verifyUnitName(generation)
        : workerUnitName(generation);
      const status = job.verifierStatus ?? job.workerStatus;
      if (status !== undefined) {
        try {
          await clearSurvivingTerminalGate(deps, job, unitName, status);
        } catch (error) {
          deps.logger(
            `Surviving terminal gate could not be cleared: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
      }
      return state;
    }
  }
}

async function acceptCatalogEntry(
  deps: PiDeps,
  state: ControllerState,
  job: ControllerJob,
  status: VerifierStatus,
  now: Date,
): Promise<ControllerState> {
  const request = job.envelope.request;
  const receiptBytes = await fetchBoundedFile(
    deps,
    request.jobId,
    RECEIPT_FILE,
    MAX_RECEIPT_BYTES,
    "Verifier receipt",
  );
  const receiptSha256 = await sha256Hex(receiptBytes);
  if (receiptSha256 !== status.receiptSha256) {
    throw new Error("Verifier receipt hash does not match its status");
  }
  const resultBytes = await deps.private.readBytes(
    `${PIP_JOB_EVIDENCE_PATH}/${request.jobId}/${RESULT_FILE}`,
    MAX_RESULT_BYTES,
  );
  const saved = resultBytes === undefined
    ? undefined
    : await validateSavedWorkerResult(
      JSON.parse(new TextDecoder().decode(resultBytes)),
      {
        recipientFile:
          `${JOBS_RUNTIME_ROOT}/${request.jobId}/${RECIPIENT_FILE}`,
        recipientSha256: request.recipientSha256,
        recipientFingerprint: request.recipientFingerprint,
      },
      {
        requestSha256: job.envelope.requestSha256,
        generation: request.generation,
        recipientSha256: request.recipientSha256,
        recipientFingerprint: request.recipientFingerprint,
      },
    );
  if (saved === undefined) {
    throw new Error("Worker result evidence is missing on the Pi");
  }
  const receipt = validateAcceptedReceipt(
    JSON.parse(new TextDecoder().decode(receiptBytes)),
    saved.index,
    {
      generation: request.generation,
      indexSha256: saved.publishedIndex.indexSha256,
      recipientSha256: request.recipientSha256,
      recipientFingerprint: request.recipientFingerprint,
    },
  );
  const catalog = [...state.catalog];
  if (catalog.some((entry) => entry.index.generation === request.generation)) {
    // The durable acceptance already happened; a resume must not fail or
    // duplicate it. The receipt above was validated again for identity.
    return state;
  }
  catalog.push({
    index: saved.index,
    publishedIndex: saved.publishedIndex,
    receipt,
    acceptedAtUtc: now.toISOString(),
  });
  // No durable write here: the ACCEPTED phase and the catalog entry are
  // persisted together by the caller in one recoverable state, so a crash
  // never splits acceptance into two crash-dependent states.
  deps.logger(
    `Backblaze generation ${request.generation} accepted into the catalog`,
  );
  return { ...state, catalog };
}

async function pruneStep(
  deps: PiDeps,
  state: ControllerState,
  now: Date,
): Promise<ControllerState> {
  const job = state.job;
  if (job === undefined) throw new Error("No controller job to prune");
  const config = await loadSourceConfig(deps);
  const store = deps.metadataStore(config.b2);
  let fresh: B2Object[];
  try {
    fresh = await store.versions();
  } catch (error) {
    // A transient provider/transport inventory failure is never allowed to
    // escape to the step dispatcher (which would permanently mark the job
    // FAILED): keep the current job/catalog/phase and resumable evidence.
    const reason = error instanceof Error ? error.message : String(error);
    deps.logger(`Prune inventory failed: ${reason.slice(0, 200)}`);
    if (job.prune === undefined) {
      // No prune plan exists yet: never invent an empty completed plan that
      // would drop catalog membership without deleting eligible objects.
      // ACCEPTED and the pending plan allocation are preserved for the
      // next normal poll.
      return state;
    }
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...job.prune,
          failedAtUtc: now.toISOString(),
          evidence: `inventory failed: ${reason.slice(0, 200)}`,
        },
      },
    });
  }
  const selection = selectPruneCandidates(fresh, state.catalog);
  const currentAccepted = state.catalog.some((entry) =>
    entry.index.generation === job.envelope.request.generation
  );
  if (!currentAccepted) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        phase: "PRUNING",
        prune: {
          plan: [],
          startedAtUtc: now.toISOString(),
          failedAtUtc: now.toISOString(),
          evidence: "Current generation is not in the accepted catalog",
        },
      },
    });
  }
  if (job.prune === undefined) {
    if (!retainedIdsPresent(fresh, selection.retainedFileIds)) {
      return await persist(deps, {
        ...state,
        job: {
          ...job,
          phase: "PRUNING",
          prune: {
            plan: [],
            startedAtUtc: now.toISOString(),
            failedAtUtc: now.toISOString(),
            evidence: "Retained-generation guard failed before any deletion",
          },
        },
      });
    }
    if (selection.toDelete.length === 0 && selection.toPrune.length === 0) {
      const completed = {
        ...job,
        phase: "PRUNED" as ControllerPhase,
        prune: {
          plan: [],
          startedAtUtc: now.toISOString(),
          completedAtUtc: now.toISOString(),
        },
      };
      return await persist(deps, { ...state, job: completed });
    }
    // Every eligible older generation enters the plan even with zero
    // remaining IDs: a later fresh inventory may prove that its data is
    // already gone, and the catalog membership still has to shrink to the
    // four retained accepted generations.
    const plan: PrunePlanEntry[] = [];
    for (const generation of selection.toPrune) {
      const ids = selection.toDelete
        .filter((object) =>
          object.fileName.startsWith(`${GENERATIONS_PREFIX}${generation}/`) ||
          object.fileName.startsWith(`${INDEXES_PREFIX}${generation}/`)
        )
        .map((object) => object.fileId);
      plan.push({ generation, fileIds: ids });
    }
    const planned = {
      ...job,
      phase: "PRUNING" as ControllerPhase,
      prune: { plan, startedAtUtc: now.toISOString() },
    };
    return await persist(deps, { ...state, job: planned });
  }
  if (job.prune.failedAtUtc !== undefined) {
    // Idempotent resume: re-inventory and continue with the persisted plan.
    return await deletePruned(deps, state, job, now, fresh);
  }
  if (job.prune.completedAtUtc !== undefined) {
    return await finishPruneCatalog(deps, state, job);
  }
  return await deletePruned(deps, state, job, now, fresh);
}

async function deletePruned(
  deps: PiDeps,
  state: ControllerState,
  job: ControllerJob,
  now: Date,
  inventory: B2Object[],
): Promise<ControllerState> {
  const plan = job.prune;
  if (plan === undefined) throw new Error("Prune plan is missing");
  const config = await loadSourceConfig(deps);
  const store = deps.metadataStore(config.b2);
  let fresh = inventory;
  const guard = selectPruneCandidates(fresh, state.catalog);
  if (!retainedIdsPresent(fresh, guard.retainedFileIds)) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          failedAtUtc: now.toISOString(),
          evidence: "Retained-generation guard failed after inventory",
        },
      },
    });
  }
  const rechecked = revalidatePruneDeletions(
    fresh,
    plan.plan,
    guard.toPrune,
    guard.retainedFileIds,
  );
  if (rechecked.violation !== null) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          failedAtUtc: now.toISOString(),
          evidence: rechecked.violation,
        },
      },
    });
  }
  for (const object of rechecked.pending) {
    try {
      await store.remove(object);
    } catch (error) {
      // Never let one removal failure escape to the outer cycle step
      // dispatcher: from the unchanged PRUNING state it would immediately
      // re-mark the job FAILED and the persisted plan would lose its
      // resumability. Persist the same catalog/job/plan in PRUNING with the
      // failure time and a short bounded evidence string; the next normal
      // step inventories again, treats already-absent IDs as already removed
      // and retries only the still-present eligible IDs.
      const reason = error instanceof Error ? error.message : String(error);
      return await persist(deps, {
        ...state,
        job: {
          ...job,
          prune: {
            ...plan,
            failedAtUtc: now.toISOString(),
            evidence: `remove ${object.fileId} failed: ${reason.slice(0, 200)}`,
          },
        },
      });
    }
    const total = plan.plan.reduce(
      (sum, entry) => sum + entry.fileIds.length,
      0,
    );
    await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          evidence:
            `${rechecked.pending.length} of ${total} pending after deletion`,
        },
      },
    });
  }
  try {
    fresh = await store.versions();
  } catch (error) {
    // The post-delete refresh is a transient provider/transport inventory
    // failure too: it must never escape and permanently mark the job FAILED.
    // Keep PRUNING with the exact plan and all planned IDs, write bounded
    // failure evidence and let the next normal poll re-inventory fresh
    // (already-absent IDs are treated as already removed).
    const reason = error instanceof Error ? error.message : String(error);
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          failedAtUtc: now.toISOString(),
          evidence: `refresh inventory failed: ${reason.slice(0, 200)}`,
        },
      },
    });
  }
  const afterGuard = selectPruneCandidates(fresh, state.catalog);
  const after = revalidatePruneDeletions(
    fresh,
    plan.plan,
    afterGuard.toPrune,
    afterGuard.retainedFileIds,
  );
  if (after.violation !== null) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          failedAtUtc: now.toISOString(),
          evidence: after.violation,
        },
      },
    });
  }
  if (after.pending.length !== 0) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          failedAtUtc: now.toISOString(),
          evidence: `${after.pending.length} planned versions still present`,
        },
      },
    });
  }
  const kept = selectPruneCandidates(fresh, state.catalog);
  if (!retainedIdsPresent(fresh, kept.retainedFileIds)) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        prune: {
          ...plan,
          failedAtUtc: now.toISOString(),
          evidence: "Retained IDs are not all present after pruning",
        },
      },
    });
  }
  const completed = {
    ...job,
    prune: {
      ...plan,
      completedAtUtc: now.toISOString(),
      // A resumed plan carries failedAtUtc; only the fresh absent+retained
      // proof above may complete the prune, and it clears the failure mark
      // so the dispatch reaches finishPruneCatalog instead of re-deleting.
      failedAtUtc: undefined,
      evidence: undefined,
    },
  };
  return await persist(deps, { ...state, job: completed });
}

async function finishPruneCatalog(
  deps: PiDeps,
  state: ControllerState,
  job: ControllerJob,
): Promise<ControllerState> {
  const prunedGenerations = new Set(
    job.prune!.plan.map((entry) => entry.generation),
  );
  const catalog = state.catalog.filter((entry) =>
    !prunedGenerations.has(entry.index.generation)
  );
  const next = {
    ...job,
    phase: "CLEANUP_PENDING" as ControllerPhase,
  };
  return await persist(deps, { ...state, job: next, catalog });
}

// ---------------------------------------------------------------------------
// Source scratch cleanup (generation directories only)
// ---------------------------------------------------------------------------

export const CLEANUP_BASES = [
  "/var/tmp/arch-vps-file-backup",
  "/var/tmp/arch-vps-file-recovery",
  "/var/tmp/arch-vps-file-verification",
] as const;

/** Exact capture-stage contract names, derived from the capture module's
 * fixed writes (never a recursive delete of unknown contents). */
const CLEANUP_STAGE_FIXED = [
  "exclusions.txt",
  "recipient.asc",
  "oracle-root.swapfile.stat",
  "staging-boot.sha.before",
  "staging-boot.sha.after",
  "lvm-ocivolume.vg",
  "capture-error.txt",
  "manifest.json",
] as const;

/** Fixed diagnostic labels of the capture module; every runBash child
 * writes `${label.replaceAll(":", "-")}.stderr.log` into the stage. */
const CLEANUP_LOG_LABELS = [
  "boot-before",
  "boot-after",
  "packages-before",
  "packages-after",
  "recipient-key",
  "layout-initial",
  "layout-final",
  "guard-initial",
  "guard-final",
  "recovery-efivars",
  "recovery-findmnt",
  "recovery-mount-options",
  "recovery-sfdisk",
  "recovery-lvm",
  "recovery-cmdline",
  "recovery-fstab",
  "recovery-encrypt",
  "recovery-compress",
  "hash-recovery",
  "tools-tar",
  "tools-zstd",
  "tools-gpg",
  "tools-sfdisk",
  "tools-vgcfgbackup",
] as const;

/** Verification boot-sample finals from the verifier contract. */
const CLEANUP_BOOT_SAMPLES = [
  "sample.root.Image",
  "sample.root.initramfs-linux.img",
  "sample.staging-boot.arch-vmlinuz",
  "sample.staging-boot.arch-initrd.img",
] as const;

/** Uploader contract: the fixed owner-only resume journal written by
 * backblaze-upload.ts into the generation stage. */
const CLEANUP_UPLOAD_FIXED = ["upload-journal.json"] as const;

/** Index publisher contract (exact fixed names in backblaze-index.ts): the
 * plaintext, ciphertext, receipt and state journals, the staged pinned
 * recipient copy, and the task-owned ciphertext `.partial` that stays when
 * the create-new commit cannot complete. `index-public-home/` is a
 * directory, treated like the capture `gpg-public-home`. */
const CLEANUP_INDEX_FIXED = [
  "recovery-index.json",
  "recovery-index.json.gpg",
  "recovery-index.json.gpg.partial",
  "recovery-index-receipt.json",
  "recovery-index-state.json",
  "index-recipient.asc",
] as const;

/** Atomic write temp prefixes of the upload journal and index publisher
 * (`.${basename}.${crypto.randomUUID()}.tmp` in backblaze-upload.ts and
 * backblaze-index.ts); a crash mid-write may leave one behind. Only the
 * exact prefix plus a v4 UUID plus `.tmp` is accepted. */
const CLEANUP_ATOMIC_TEMP_PREFIXES = [
  ".upload-journal.json",
  ".recovery-index.json",
  ".recovery-index-receipt.json",
  ".recovery-index-state.json",
  ".index-recipient.asc",
] as const;

const CLEANUP_UUID_PATTERN =
  "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

const CLEANUP_ATOMIC_TEMP_PATTERN = new RegExp(
  `^\\.(${
    CLEANUP_ATOMIC_TEMP_PREFIXES.map((prefix) =>
      prefix.slice(1).replaceAll(".", "\\.")
    ).join("|")
  })\\.${CLEANUP_UUID_PATTERN}\\.tmp$`,
);

/** Public-only gpg home entries permitted inside `gpg-public-home`
 * (pubring/trustdb/agent sockets and empty key dirs, never private data). */
const CLEANUP_GPG_HOME_PATTERN =
  /^(pubring\.(kbx|kbx\.lock|gpg|gpg\.lock)|trustdb\.(gpg|gpg\.lock)|gpg\.conf|common\.conf|random_seed|S\.gpg-agent(\.extra|\.lock|\.bak)?|private-keys-v1\.d|crls\.d)$/;

export function cleanupAllowedNames(): {
  files: Set<string>;
  dirs: Set<string>;
} {
  const files = new Set<string>([
    ...CLEANUP_STAGE_FIXED,
    ...CLEANUP_LOG_LABELS.map((label) => `${label}.stderr.log`),
    ...CLEANUP_BOOT_SAMPLES,
    ...CLEANUP_BOOT_SAMPLES.map((sample) => `${sample}.partial`),
    ...CLEANUP_UPLOAD_FIXED,
    ...CLEANUP_INDEX_FIXED,
  ]);
  const dirs = new Set<string>(["gpg-public-home", "index-public-home"]);
  for (const role of UPLOAD_ROLE_ORDER) {
    const format = role === "recovery" ? "json.zst" : "tar.zst";
    // Recovery finals use the full `${role}.${format}.gpg` name; the
    // verification outputs keep the decrypted `${role}.${format}` name;
    // both partials and the capture du records share the same base name.
    files.add(`${role}.${format}`);
    files.add(`${role}.${format}.partial`);
    files.add(`${role}.${format}.gpg`);
    files.add(`${role}.${format}.gpg.partial`);
    files.add(`${role}.du.txt`);
    files.add(`space-${role}.stderr.log`);
    files.add(`encrypt-${role}.stderr.log`);
    files.add(`hash-${role}.stderr.log`);
  }
  return { files, dirs };
}

/** Whether one DIRECT child of a generation scratch directory is an
 * expected capture/recovery/verifier/upload/index output. Unknown contents
 * are preserved: the cleanup aborts instead of deleting them. */
export function cleanupAllowedName(name: string, isDir: boolean): boolean {
  const allowed = cleanupAllowedNames();
  return isDir
    ? allowed.dirs.has(name)
    : allowed.files.has(name) || CLEANUP_ATOMIC_TEMP_PATTERN.test(name);
}

/** Whether a direct descendant of `gpg-public-home` is a known public-only
 * gpg home entry; socket entries are permitted only for the agent socket
 * names and `private-keys-v1.d` must stay empty (checked in the script). */
export function cleanupGpgHomeAllowedName(name: string): boolean {
  return CLEANUP_GPG_HOME_PATTERN.test(name);
}

/** Source-side generation scratch cleanup. The script holds the source lock
 * without touching the controller lock, re-checks canonical root-owned
 * 0700 base and generation directories, rejects ANY mount at or below the
 * target (same-device bind mounts included), rejects symlinks and
 * non-regular or unexpected descendants, permits only the known public-only
 * gpg home entries without private keys, and only then removes the exact
 * generation directory with `rm -rf --one-file-system`. */
export function buildCleanupScript(generation: string): string {
  const gen = validateGeneration(generation);
  const allowed = cleanupAllowedNames();
  const filePatterns = [...allowed.files].sort().join("|");
  const gpgNames = [
    "pubring.kbx",
    "pubring.kbx.lock",
    "pubring.gpg",
    "pubring.gpg.lock",
    "trustdb.gpg",
    "trustdb.gpg.lock",
    "gpg.conf",
    "common.conf",
    "random_seed",
    "S.gpg-agent",
    "S.gpg-agent.extra",
    "S.gpg-agent.lock",
    "S.gpg-agent.bak",
  ].sort().join("|");
  // Atomic temp convention of the upload journal and index publisher:
  // exact prefix + v4 UUID + .tmp, each class hexed one by one so the case
  // pattern never matches a broader name.
  const hexClass = "[0-9a-f]";
  const group = (n: number): string => Array(n).fill(hexClass).join("");
  const uuidGlob = `${group(8)}-${group(4)}-4${group(3)}-[89ab]${group(3)}-${
    group(12)
  }`;
  const tempPatterns = CLEANUP_ATOMIC_TEMP_PREFIXES.map((prefix) =>
    `${prefix}.${uuidGlob}.tmp`
  ).sort().join("|");
  return [
    "set -eu",
    `exec 9<>${shellQuote(SOURCE_LOCK_PATH)}`,
    "flock -n 9 || { echo LOCK_BUSY; exit 3; }",
    `gen=${shellQuote(gen)}`,
    `printf '%s' "$gen" | grep -Eq '^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 4`,
    "cleanup_generation() {",
    "  base=$1",
    '  dir="$base/$gen"',
    '  test -e "$dir" || return 0',
    // A root-owned 0700 regular file at the generation path passes the
    // canonical/uid/mode checks but is still not the generation scratch
    // directory: reject it before any enumeration or removal.
    '  test -d "$dir" || { echo "NOT_DIRECTORY $base"; exit 11; }',
    '  test "$(readlink -e "$base")" = "$base" || { echo "NOT_CANONICAL_BASE $base"; exit 5; }',
    '  test "$(stat -c %u "$base")" = 0 || { echo "NOT_ROOT_BASE $base"; exit 6; }',
    '  test "$(stat -c %a "$base")" = 700 || { echo "NOT_0700_BASE $base"; exit 7; }',
    '  test "$(readlink -e "$dir")" = "$dir" || { echo "NOT_CANONICAL $base"; exit 5; }',
    '  test "$(stat -c %u "$dir")" = 0 || { echo "NOT_ROOT $base"; exit 6; }',
    '  test "$(stat -c %a "$dir")" = 700 || { echo "NOT_0700 $base"; exit 7; }',
    // Any mount at or below the target is rejected, including same-device
    // bind mounts that `--one-file-system` would otherwise not cross.
    '  if awk -v p="$dir" \'$2 == p || substr($2, 1, length(p) + 1) == p "/" {print}\' /proc/self/mounts | grep -q .; then',
    '    echo "MOUNT_AT_OR_BELOW $base"; exit 8;',
    "  fi",
    // Only DIRECT children of the generation directory are validated here;
    // each allowed public-key home is enumerated separately at its own
    // depth below, and any other nested descendant is rejected through its
    // unknown direct parent. `find` emits NUL-separated records (kind char,
    // one space, exact name), and kind/name are derived from fixed character
    // positions: names containing spaces, globs or newlines are preserved
    // verbatim and a record is never silently skipped.
    "  while IFS= read -r -d '' entry; do",
    "    kind=${entry:0:1}",
    "    name=${entry:2}",
    '    case "$kind" in',
    "      f)",
    `        case "$name" in ${filePatterns}|${tempPatterns}) ;; *) echo "UNEXPECTED_FILE $base $name"; exit 9 ;; esac`,
    "        ;;",
    "      d)",
    '        test "$name" = gpg-public-home -o "$name" = index-public-home || { echo "UNEXPECTED_DIR $base $name"; exit 9; }',
    "        ;;",
    "      l)",
    '        echo "UNEXPECTED_SYMLINK $base $name"; exit 9 ;;',
    '      *) echo "UNEXPECTED_ENTRY $base $name"; exit 9 ;;',
    "    esac",
    '  done < <(find "$dir" -mindepth 1 -maxdepth 1 -printf "%y %P\\0")',
    "  for publicName in gpg-public-home index-public-home; do",
    '    home="$dir/$publicName"',
    '    if test -d "$home"; then',
    "      while IFS= read -r -d '' entry; do",
    "        kind=${entry:0:1}",
    "        name=${entry:2}",
    '        case "$kind" in',
    "          f)",
    `            case "$name" in ${gpgNames}) ;; *) echo "UNEXPECTED_GPG_FILE $base $name"; exit 9 ;; esac`,
    "            ;;",
    "          d)",
    '            test "$name" = private-keys-v1.d || { echo "UNEXPECTED_GPG_DIR $base $name"; exit 9; }',
    '            test -z "$(find "$home/$name" -mindepth 1 -print -quit)" || { echo "GPG_PRIVATE_KEYS $base"; exit 10; }',
    "            ;;",
    "          s)",
    '            test "$name" = S.gpg-agent -o "$name" = S.gpg-agent.extra || { echo "UNEXPECTED_GPG_SOCKET $base $name"; exit 9; }',
    "            ;;",
    "          l)",
    '            echo "UNEXPECTED_GPG_SYMLINK $base $name"; exit 9 ;;',
    '          *) echo "UNEXPECTED_GPG_ENTRY $base $name"; exit 9 ;;',
    "        esac",
    '      done < <(find "$home" -mindepth 1 -maxdepth 1 -printf "%y %P\\0")',
    "    fi",
    "  done",
    '  rm -rf --one-file-system -- "$dir"',
    '  echo "CLEANED $dir"',
    "}",
    ...CLEANUP_BASES.map((base) => `cleanup_generation ${shellQuote(base)}`),
    "echo CLEANUP_OK",
  ].join("\n");
}

async function cleanupStep(
  deps: PiDeps,
  state: ControllerState,
  now: Date,
): Promise<ControllerState> {
  const job = state.job;
  if (job === undefined) throw new Error("No controller job to clean");
  const generation = job.envelope.request.generation;
  const script = buildCleanupScript(generation);
  const result = await deps.remote.root(script);
  if (result.code !== 0) {
    return await persist(deps, {
      ...state,
      job: {
        ...job,
        cleanup: {
          status: "FAILED" as const,
          atUtc: now.toISOString(),
          detail: `Scratch cleanup failed (${result.code})`,
        },
      },
    });
  }
  return await persist(deps, {
    ...state,
    job: {
      ...job,
      cleanup: { status: "DONE" as const, atUtc: now.toISOString() },
      phase: "COMPLETE" as ControllerPhase,
    },
  });
}

// ---------------------------------------------------------------------------
// Pi run loop and entry
// ---------------------------------------------------------------------------

/** One polling run: scheduled under the immutable request deadline. The
 * default lifetime follows the job's real `deadlineAtUtc` (checked between
 * steps) and never stops merely at a fixed step count; `maxSteps` remains an
 * explicitly supplied test/diagnostic bound. At the deadline one final state
 * assessment runs (preserving any terminal/orphan evidence the step
 * persisted) and the run reports incomplete/failure truthfully instead of
 * rewriting durable state from stale data. */
export async function runBackblazeCycle(
  deps: PiDeps,
  maxSteps: number = Number.POSITIVE_INFINITY,
): Promise<BackblazeRunReport> {
  const initial = await deps.private.read<ControllerState>(
    CONTROLLER_STATE_PATH,
  );
  let state = validateControllerState(initial ?? emptyControllerState());
  const skip = (status: string, detail?: string): BackblazeRunReport => ({
    status,
    observedAtUtc: deps.now().toISOString(),
    healthy: false,
    ...(detail === undefined ? {} : { detail }),
  });
  const failReport = (
    failed: ControllerState,
    message: string,
  ): BackblazeRunReport => ({
    status: `B2_BACKUP_FAILED:${failed.job!.envelope.request.jobId}`,
    observedAtUtc: deps.now().toISOString(),
    jobId: failed.job!.envelope.request.jobId,
    generation: failed.job!.envelope.request.generation,
    healthy: false,
    detail: message,
  });
  let deadlineExpired = false;
  try {
    for (let step = 0; step < maxSteps; step += 1) {
      // The immutable request deadline bounds the default lifetime; it is
      // re-checked between steps, never derived from the step counter.
      const deadline = state.job?.envelope.request.deadlineAtUtc;
      const atDeadline = deadline !== undefined &&
        Date.parse(deadline) <= deps.now().getTime();
      if (atDeadline) deadlineExpired = true;
      const before = state.job?.phase ?? "none";
      let next: ControllerState;
      try {
        next = await stepBackupController(state, deps, deps.now());
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // Reread the durable state after any step failure: progress the
        // failing step already persisted (launch phase, gate binding,
        // catalog acceptance, prune plan evidence) must never be replaced
        // from the stale pre-step state.
        let durable: ControllerState | undefined;
        try {
          durable = validateControllerState(
            await deps.private.read<ControllerState>(CONTROLLER_STATE_PATH) ??
              emptyControllerState(),
          );
        } catch {
          durable = undefined;
        }
        const progressed = durable !== undefined &&
          durable.job !== undefined && (
            durable.job.updatedAtUtc !== state.job?.updatedAtUtc ||
            durable.job.phase !== state.job?.phase ||
            durable.catalog.length !== (state.catalog?.length ?? 0) ||
            (durable.job.prune?.plan.length ?? 0) !==
              (state.job?.prune?.plan.length ?? 0) ||
            durable.job.workerInvocationId !== state.job?.workerInvocationId ||
            durable.job.verifierInvocationId !==
              state.job?.verifierInvocationId
          );
        if (progressed) {
          // The error followed a durable transition: resume from the
          // latest persisted state instead of forcing a terminal FAILED.
          state = durable!;
          if (
            atDeadline && durable!.job!.phase !== "COMPLETE" &&
            durable!.job!.phase !== "FAILED"
          ) {
            // The final expiry assessment already ran this iteration; a
            // terminal durable transition is reported on the next one.
            break;
          }
          continue;
        }
        const base = durable ?? state;
        if (base.job === undefined) {
          return skip(`B2_SKIPPED:${message}`, message);
        }
        const failed = await failJob(
          deps,
          base,
          "CONTROLLER_STEP_FAILED",
          message,
        );
        return failReport(failed, message);
      }
      const after = next.job?.phase ?? "none";
      if (after !== before && after !== "none") {
        deps.logger(`Backblaze phase ${before} -> ${after}`);
      }
      if (after === "COMPLETE") {
        const reportValue = {
          status: `B2_BACKUP_COMPLETE:${next.job!.envelope.request.jobId}`,
          observedAtUtc: deps.now().toISOString(),
          jobId: next.job!.envelope.request.jobId,
          generation: next.job!.envelope.request.generation,
          healthy: true,
        };
        await deps.private.write(B2_REPORT_PATH, {
          ...assessBackblazeWatchdog(next, await deps.gate.read(), deps.now()),
          observedAtUtc: deps.now().toISOString(),
        });
        return reportValue;
      }
      if (after === "FAILED") {
        const reportValue = {
          status: `B2_BACKUP_FAILED:${next.job!.envelope.request.jobId}`,
          observedAtUtc: deps.now().toISOString(),
          jobId: next.job!.envelope.request.jobId,
          generation: next.job!.envelope.request.generation,
          healthy: false,
          ...(next.job!.failure === undefined
            ? {}
            : { detail: next.job!.failure.code }),
        };
        await deps.private.write(B2_REPORT_PATH, {
          ...assessBackblazeWatchdog(next, await deps.gate.read(), deps.now()),
          observedAtUtc: deps.now().toISOString(),
        });
        return reportValue;
      }
      state = next;
      if (atDeadline) break;
      await deps.sleep(POLL_INTERVAL_MS);
    }
  } finally {
    // The process-local task tunnel is closed only after terminal proof,
    // receipt or controller exit; the decrypt path stays alive for every
    // verifier poll step. Cleanup failures are never silently swallowed:
    // they are reported so the operator sees the missing cleanup.
    try {
      await deps.tunnel.close();
    } catch (error) {
      deps.logger(
        `Tunnel close failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  const reportValue = {
    status: `B2_BACKUP_INCOMPLETE:${
      state.job?.envelope.request.jobId ?? "none"
    }`,
    observedAtUtc: deps.now().toISOString(),
    ...(state.job === undefined ? {} : {
      jobId: state.job.envelope.request.jobId,
      generation: state.job.envelope.request.generation,
    }),
    healthy: false,
    detail: deadlineExpired
      ? "Request deadline reached"
      : "Step budget exhausted",
  };
  await deps.private.write(B2_REPORT_PATH, {
    ...assessBackblazeWatchdog(state, await deps.gate.read(), deps.now()),
    observedAtUtc: deps.now().toISOString(),
  });
  return reportValue;
}

async function piMain(): Promise<void> {
  const cwd = await Deno.realPath(".");
  if (cwd !== PI_CONTROLLER_CWD) {
    throw new Error(`File backup runs only from ${PI_CONTROLLER_CWD}`);
  }
  const deps = realPiDeps();
  await deps.lock(CONTROLLER_LOCK_PATH, async () => {
    const reportValue = await runBackblazeCycle(deps);
    console.log(JSON.stringify(reportValue));
    if (!reportValue.healthy) Deno.exitCode = 1;
  });
}

if (import.meta.main) {
  try {
    await piMain();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    Deno.exitCode = 1;
  }
}
