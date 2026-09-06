import { createHash } from "node:crypto";
import type { CaptureResult } from "./backblaze-capture.ts";
import { isPublicKeyArmorForm } from "./backblaze-capture.ts";
import {
  type B2Object,
  type B2Store,
  DIRECT_PREFIX,
  MAX_CHUNK_BYTES,
} from "./backblaze-storage.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
  type UploadFormat,
  type UploadResult,
  type UploadRole,
  type UploadVersionIdentity,
  validateUploadCapture,
} from "./backblaze-upload.ts";

/**
 * m04-index: source-side library that builds, validates, public-key encrypts
 * and publishes a small immutable portable recovery index right after
 * m03-upload's uploadCapturedGeneration succeeds.
 *
 * The published object is exactly one ciphertext at
 * `restic/direct-v1/indexes/<generation>/index.json.gpg` — a namespace
 * separate from `restic/direct-v1/generations/...`, so the m03 resume
 * inventory contract is untouched. The plaintext is a strict portable v1
 * RecoveryIndex: schemaVersion 1, generation, capture and upload UTC
 * intervals, live-file-copy consistency with sourceShutdown false, the
 * pinned public recipient identity, and exactly seven ordered archive
 * records (UPLOAD_ROLE_ORDER) carrying only the selected exact-version
 * chunk identities. Local paths, stage locations, credentials and duplicate
 * version metadata are deliberately omitted; the index asserts uploadVerified
 * true with decryptedRestoreProved and machineBootRestoreProved false — this
 * is an upload-integrity index, never an acceptance marker and never a
 * decrypted or machine restore proof.
 *
 * Encryption uses exactly the capture module's public-only gpg options
 * (--no-options --no-autostart --no-keyring --no-encrypt-to --batch --no-tty
 * --recipient-file, --compress-algo none, --cipher-algo AES256) invoked as a
 * bounded argv array (no shell interpolation of untrusted fields). The
 * recipient ASCII public key is pinned by SHA-256 and the exact expected
 * public fingerprint is proven with `gpg --no-options --no-autostart
 * --no-keyring --with-colons --show-keys` in a dedicated owner-only
 * `index-public-home` key home; no private key material is ever read or
 * supported and gpg stdout/stderr are bounded and redacted (plaintext
 * metadata and errors are never emitted). The public bytes are re-hashed
 * immediately before encryption.
 *
 * Local fixed files inside capture.stageDirectory:
 *   recovery-index.json         canonical JSON of the built index (0600)
 *   recovery-index.json.gpg     immutable ciphertext, never re-encrypted
 *   recovery-index-receipt.json verified publication receipt (0600)
 *   recovery-index-state.json   owner-only state journal binding
 *                               generation / plaintext hash / recipient
 *                               identity / ciphertext size+hash, written
 *                               before the first put
 *   index-recipient.asc         pinned public recipient copy
 *   index-public-home/          dedicated gpg public-only key home
 * The stage directory itself and every existing fixed input/output file are
 * checked against the established uploader protection: real path, no
 * symlink, regular file/directory, owned by the stage owner (root in the
 * production source deployment; the same current uid in synthetic runtime
 * tests), mode 0700/0600 with no group or other permission and no hardlinks.
 * The staging path is restricted to the fixed production base
 * `/var/tmp/arch-vps-file-backup` plus "/" plus the capture generation
 * (platform ancestor symlinks are allowed only by canonicalizing that fixed
 * base; the caller must supply the canonical path). On every publish path
 * the supplied public recipient is bound to the capture's retained pinned
 * file `recipient.asc` (the file used for all seven archive encryptions):
 * it must be a regular owner-only 0600 file, no symlink or hardlink, ASCII
 * public armor, SHA-256 equal to the supplied hash and byte-equal to the
 * supplied recipient.recipientFile, and exactly the expected public
 * fingerprint is proven with the owner-only public gpg home. The capture
 * recipient and the capture `gpg-public-home` are never written, rewritten
 * or removed. Capture/upload journals, the capture `gpg-public-home` and
 * upload-journal.json are never touched. An interrupted encryption leaves a
 * task-owned `.partial` that is reported clearly and never deleted or
 * reused; an existing ciphertext without coherent state is a visible
 * incomplete state and is never silently uploaded or overwritten (the final
 * ciphertext commit is create-new via link, never rename-over).
 *
 * Publication: a full B2 version inventory of exactly the own per-generation
 * index namespace is classified first (unexpected object names, hide/start
 * markers and conflicting content fail closed). Matching size/SHA-1 versions
 * are reused only after an exact-version download verified by the store plus
 * SHA-256 and byte equality against the local ciphertext; duplicate
 * identical versions are preserved and only the selected exact version is
 * recovery membership. A lost put response refreshes the inventory exactly
 * once and reconciles the same expected object; an absent object rethrows
 * the original (provider-redacted) failure and is never blindly re-uploaded.
 * After a put the exact-ID readback verifies ciphertext byte length/SHA-1 via
 * the store plus SHA-256/byte equality, and the receipt is persisted
 * atomically/fsynced only after that verified readback. Resuming validates
 * the existing state and receipt (including generation, stage directory,
 * hashes, object and recipient identity), requires plaintext byte equality
 * to the newly built index and re-verifies the selected exact object against
 * a fresh inventory; the receipt publication time is preserved only when the
 * selected version id is unchanged, while a missing saved version may be
 * reconciled/uploaded only after that fresh inventory as a new publication.
 * This module never deletes, never prunes, never decrypts, never forwards
 * keys and contains no CLI entrypoint; the caller owns exclusive
 * source/controller locks.
 */

export interface IndexRecipient {
  recipientFile: string;
  recipientSha256: string;
  recipientFingerprint: string;
}

/** One selected exact-version chunk identity (duplicates never appear). */
export interface IndexChunk {
  index: number;
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  /** Exact verified version id used for this chunk. */
  fileId: string;
  uploadTimestamp: number;
}

export interface IndexArchiveRecord {
  role: UploadRole;
  format: UploadFormat;
  bytes: number;
  sha256: string;
  chunks: IndexChunk[];
}

/** Strict portable v1 recovery index (see module header). */
export interface RecoveryIndex {
  schemaVersion: 1;
  generation: string;
  captureStartedAtUtc: string;
  captureFinishedAtUtc: string;
  uploadStartedAtUtc: string;
  uploadFinishedAtUtc: string;
  consistency: "live-file-copy";
  sourceShutdown: false;
  recipientFingerprint: string;
  recipientSha256: string;
  archives: IndexArchiveRecord[];
  uploadVerified: true;
  decryptedRestoreProved: false;
  machineBootRestoreProved: false;
}

export interface PublishedIndex {
  generation: string;
  /** The exact selected/published B2 upload version. */
  object: B2Object;
  ciphertextBytes: number;
  ciphertextSha256: string;
  /** SHA-256 of the canonical plaintext index JSON. */
  indexSha256: string;
  uploadVerified: true;
  decryptedRestoreProved: false;
  machineBootRestoreProved: false;
}

export type IndexStore = Pick<B2Store, "put" | "get" | "versions">;

const FAIL_PREFIX = "Index failed (";
const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA1_PATTERN = /^[0-9a-f]{40}$/;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/;
const ABSOLUTE_PATH_PATTERN = /^\/[A-Za-z0-9/_.-]+$/;
const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const MAX_INDEX_BYTES = 8 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = MAX_INDEX_BYTES + 64 * 1024;
const MAX_RECIPIENT_BYTES = 64 * 1024;
const MAX_STATE_BYTES = 64 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_ID_BYTES = 512;
const MAX_NAME_BYTES = 1000;
const GPG_STDOUT_CAP = 256 * 1024;
const GPG_STDERR_CAP = 64 * 1024;

/** Fixed production staging root. The publisher accepts exactly this base
 * plus "/" plus the capture generation (canonicalized, so macOS /var is
 * resolved to /private/var); arbitrary temp/source paths are rejected. */
const PRODUCTION_STAGE_BASE = "/var/tmp/arch-vps-file-backup";

const INDEX_FILE = "recovery-index.json";
const CIPHERTEXT_FILE = "recovery-index.json.gpg";
const RECEIPT_FILE = "recovery-index-receipt.json";
const STATE_FILE = "recovery-index-state.json";
const RECIPIENT_STAGED = "index-recipient.asc";
const PUBLIC_HOME = "index-public-home";
const CIPHERTEXT_PARTIAL = `${CIPHERTEXT_FILE}.partial`;
const INDEX_PREFIX = `${DIRECT_PREFIX}indexes/`;
const INDEX_OBJECT_TAIL = "index.json.gpg";

const ROLE_SET = new Set<string>(UPLOAD_ROLE_ORDER);

/** Deterministic single object name of the recovery index for a generation. */
function indexObjectName(generation: string): string {
  return `${INDEX_PREFIX}${generation}/${INDEX_OBJECT_TAIL}`;
}

function fail(label: string): never {
  throw new Error(`${FAIL_PREFIX}${label})`);
}

function isUtcTimestamp(value: unknown): value is string {
  return typeof value === "string" &&
    UTC_TIMESTAMP_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value));
}

function beforeOrEqual(a: string, b: string): boolean {
  return Date.parse(a) <= Date.parse(b);
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

function expectedFormat(role: string): UploadFormat {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(label);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  record: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) fail(label);
  }
}

function asString(value: unknown, label: string): string {
  if (typeof value !== "string") fail(label);
  return value;
}

function asNonemptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) fail(label);
  return value;
}

function asBoundedString(
  value: unknown,
  label: string,
  maxBytes: number,
): string {
  const text = asNonemptyString(value, label);
  if (byteLength(text) > maxBytes) fail(label);
  return text;
}

function asSafeInteger(
  value: unknown,
  label: string,
  min: number,
  max: number,
): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) fail(label);
  if (value < min || value > max) fail(label);
  return value;
}

function asSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) fail(label);
  return value;
}

function asSha1(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA1_PATTERN.test(value)) fail(label);
  return value;
}

function asRole(value: unknown, label: string): UploadRole {
  if (typeof value !== "string" || !ROLE_SET.has(value)) fail(label);
  return value as UploadRole;
}

function asFormat(value: unknown, label: string): UploadFormat {
  if (value !== "tar.zst.gpg" && value !== "json.zst.gpg") fail(label);
  return value;
}

const RECIPIENT_KEYS = new Set([
  "recipientFile",
  "recipientSha256",
  "recipientFingerprint",
]);

/** Strict IndexRecipient shape (the file itself is checked by publish). */
function validateRecipientShape(recipient: IndexRecipient): void {
  const record = asObject(recipient, "recipient:shape");
  assertExactKeys(record, RECIPIENT_KEYS, "recipient:shape");
  const recipientFile = asNonemptyString(
    record.recipientFile,
    "recipient:file",
  );
  if (!ABSOLUTE_PATH_PATTERN.test(recipientFile)) fail("recipient:file");
  if (
    typeof record.recipientSha256 !== "string" ||
    !SHA256_PATTERN.test(record.recipientSha256)
  ) {
    fail("recipient:sha256");
  }
  if (
    typeof record.recipientFingerprint !== "string" ||
    !FINGERPRINT_PATTERN.test(record.recipientFingerprint)
  ) {
    fail("recipient:fingerprint");
  }
}

const IDENTITY_KEYS = new Set([
  "fileId",
  "fileName",
  "contentLength",
  "contentSha1",
  "action",
  "uploadTimestamp",
]);

function asIdentity(value: unknown, label: string): UploadVersionIdentity {
  const record = asObject(value, label);
  assertExactKeys(record, IDENTITY_KEYS, label);
  const fileId = asBoundedString(record.fileId, label, MAX_ID_BYTES);
  const fileName = asBoundedString(record.fileName, label, MAX_NAME_BYTES);
  const contentLength = asSafeInteger(
    record.contentLength,
    label,
    1,
    MAX_CHUNK_BYTES,
  );
  const contentSha1 = asSha1(record.contentSha1, label);
  if (record.action !== "upload") fail(label);
  const uploadTimestamp = asSafeInteger(
    record.uploadTimestamp,
    label,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  return {
    fileId,
    fileName,
    contentLength,
    contentSha1,
    action: "upload",
    uploadTimestamp,
  };
}

const UPLOAD_CHUNK_KEYS = new Set([
  "role",
  "index",
  "name",
  "size",
  "sha256",
  "sha1",
  "fileId",
  "uploadTimestamp",
  "verifiedAtUtc",
  "reused",
  "versions",
]);

interface ParsedUploadChunk {
  role: UploadRole;
  index: number;
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  fileId: string;
  uploadTimestamp: number;
  versions: UploadVersionIdentity[];
}

const UPLOAD_ARCHIVE_KEYS = new Set([
  "role",
  "format",
  "path",
  "bytes",
  "sha256",
  "chunks",
  "verifiedAtUtc",
]);

interface ParsedUploadArchive {
  role: UploadRole;
  format: UploadFormat;
  path: string;
  bytes: number;
  sha256: string;
  chunks: ParsedUploadChunk[];
}

const UPLOAD_KEYS = new Set([
  "generation",
  "stageDirectory",
  "archives",
  "chunkCount",
  "totalBytes",
  "duplicateVersions",
  "startedAtUtc",
  "finishedAtUtc",
  "uploadVerified",
  "decryptedRestoreProved",
  "machineBootRestoreProved",
]);

function asUploadChunk(value: unknown, label: string): ParsedUploadChunk {
  const record = asObject(value, label);
  assertExactKeys(record, UPLOAD_CHUNK_KEYS, label);
  const role = asRole(record.role, label);
  const index = asSafeInteger(record.index, label, 0, Number.MAX_SAFE_INTEGER);
  const name = asBoundedString(record.name, label, MAX_NAME_BYTES);
  const size = asSafeInteger(record.size, label, 1, MAX_CHUNK_BYTES);
  const sha256 = asSha256(record.sha256, label);
  const sha1 = asSha1(record.sha1, label);
  const fileId = asBoundedString(record.fileId, label, MAX_ID_BYTES);
  const uploadTimestamp = asSafeInteger(
    record.uploadTimestamp,
    label,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  if (!isUtcTimestamp(record.verifiedAtUtc)) fail(label);
  if (typeof record.reused !== "boolean") fail(label);
  if (!Array.isArray(record.versions) || record.versions.length === 0) {
    fail(label);
  }
  const versions = record.versions.map((entry) => asIdentity(entry, label));
  for (const version of versions) {
    if (
      version.fileName !== name || version.contentLength !== size ||
      version.contentSha1 !== sha1
    ) {
      fail(label);
    }
  }
  const selectedVersion = versions.find((version) => version.fileId === fileId);
  if (selectedVersion === undefined) fail(label);
  if (selectedVersion.uploadTimestamp !== uploadTimestamp) fail(label);
  return {
    role,
    index,
    name,
    size,
    sha256,
    sha1,
    fileId,
    uploadTimestamp,
    versions,
  };
}

function asUploadArchive(value: unknown, label: string): ParsedUploadArchive {
  const record = asObject(value, label);
  assertExactKeys(record, UPLOAD_ARCHIVE_KEYS, label);
  const role = asRole(record.role, label);
  const format = asFormat(record.format, label);
  const path = asBoundedString(record.path, label, MAX_NAME_BYTES);
  if (!ABSOLUTE_PATH_PATTERN.test(path)) fail(label);
  const bytes = asSafeInteger(record.bytes, label, 1, Number.MAX_SAFE_INTEGER);
  const sha256 = asSha256(record.sha256, label);
  if (!isUtcTimestamp(record.verifiedAtUtc)) fail(label);
  if (!Array.isArray(record.chunks) || record.chunks.length === 0) {
    fail(label);
  }
  const chunks = record.chunks.map((entry) => asUploadChunk(entry, label));
  for (let i = 0; i < chunks.length; i += 1) {
    const chunk = chunks[i];
    if (chunk.role !== role || chunk.index !== i) fail(label);
    if (i < chunks.length - 1 && chunk.size !== MAX_CHUNK_BYTES) {
      fail(label);
    }
  }
  if (chunks.reduce((sum, chunk) => sum + chunk.size, 0) !== bytes) {
    fail(label);
  }
  return { role, format, path, bytes, sha256, chunks };
}

/**
 * Strict UploadResult parsing plus exact cross-matching against the capture.
 * Pure: malformed, conflicting and mismatched receipts are rejected here,
 * before any filesystem or store side effect. The upload archive paths must
 * equal the capture paths and every per-chunk deterministic name must be
 * regenerated from the exact generation.
 */
function validateUploadResult(upload: unknown, capture: CaptureResult): void {
  const record = asObject(upload, "upload:shape");
  assertExactKeys(record, UPLOAD_KEYS, "upload:keys");
  const generation = asString(record.generation, "upload:generation");
  const stageDirectory = asString(record.stageDirectory, "upload:stage");
  if (!GENERATION_PATTERN.test(generation)) fail("upload:generation");
  if (!ABSOLUTE_PATH_PATTERN.test(stageDirectory)) fail("upload:stage");
  if (generation !== capture.generation) fail("mismatch:generation");
  if (stageDirectory !== capture.stageDirectory) fail("mismatch:stage");
  if (record.uploadVerified !== true) fail("upload:flags");
  if (record.decryptedRestoreProved !== false) fail("upload:flags");
  if (record.machineBootRestoreProved !== false) fail("upload:flags");
  const startedAtUtc = asString(record.startedAtUtc, "upload:interval");
  const finishedAtUtc = asString(record.finishedAtUtc, "upload:interval");
  if (!isUtcTimestamp(startedAtUtc)) fail("upload:interval");
  if (!isUtcTimestamp(finishedAtUtc)) fail("upload:interval");
  if (Date.parse(startedAtUtc) >= Date.parse(finishedAtUtc)) {
    fail("upload:interval");
  }
  if (!beforeOrEqual(capture.startedAtUtc, capture.finishedAtUtc)) {
    fail("mismatch:timestamps");
  }
  if (!beforeOrEqual(capture.finishedAtUtc, startedAtUtc)) {
    fail("mismatch:timestamps");
  }
  if (!Array.isArray(record.archives) || record.archives.length !== 7) {
    fail("upload:archives");
  }
  const archives = record.archives.map((entry) =>
    asUploadArchive(entry, "upload:archive")
  );
  const chunks: ParsedUploadChunk[] = [];
  let totalBytes = 0;
  for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
    const role = UPLOAD_ROLE_ORDER[i];
    const archive = archives[i];
    if (archive.role !== role) fail("upload:archives");
    const captureArchive = capture.archives.find((entry) =>
      entry.role === role
    );
    if (captureArchive === undefined) fail("mismatch:archive");
    if (archive.format !== captureArchive.format) fail("mismatch:format");
    if (archive.bytes !== captureArchive.bytes) fail("mismatch:bytes");
    if (archive.sha256 !== captureArchive.sha256) fail("mismatch:hash");
    if (archive.path !== captureArchive.path) fail("mismatch:path");
    const expectedPath = `${stageDirectory}/${role}.${archive.format}`;
    if (archive.path !== expectedPath) fail("upload:path");
    for (const chunk of archive.chunks) {
      const expectedName = generationChunkName(generation, role, chunk.index);
      if (chunk.name !== expectedName) fail("upload:chunk-name");
      chunks.push(chunk);
    }
    totalBytes += archive.bytes;
  }
  const chunkCount = asSafeInteger(
    record.chunkCount,
    "upload:totals",
    7,
    Number.MAX_SAFE_INTEGER,
  );
  const total = asSafeInteger(
    record.totalBytes,
    "upload:totals",
    7,
    Number.MAX_SAFE_INTEGER,
  );
  if (total !== totalBytes || chunkCount !== chunks.length) {
    fail("upload:totals");
  }
  if (!Array.isArray(record.duplicateVersions)) fail("upload:duplicates");
  const selected = new Set<string>();
  const versionsByChunk = new Map<string, UploadVersionIdentity[]>();
  for (const archive of archives) {
    for (const chunk of archive.chunks) {
      if (selected.has(chunk.fileId)) fail("upload:duplicates");
      selected.add(chunk.fileId);
      versionsByChunk.set(
        `${chunk.name}\u0000${chunk.size}\u0000${chunk.sha1}`,
        chunk.versions,
      );
    }
  }
  for (const value of record.duplicateVersions) {
    const duplicate = asIdentity(value, "upload:duplicates");
    if (selected.has(duplicate.fileId)) fail("upload:duplicates");
    const versions = versionsByChunk.get(
      `${duplicate.fileName}\u0000${duplicate.contentLength}\u0000${duplicate.contentSha1}`,
    );
    if (
      versions === undefined ||
      !versions.some((version) => version.fileId === duplicate.fileId)
    ) {
      fail("upload:duplicates");
    }
  }
}

const INDEX_KEYS = new Set([
  "schemaVersion",
  "generation",
  "captureStartedAtUtc",
  "captureFinishedAtUtc",
  "uploadStartedAtUtc",
  "uploadFinishedAtUtc",
  "consistency",
  "sourceShutdown",
  "recipientFingerprint",
  "recipientSha256",
  "archives",
  "uploadVerified",
  "decryptedRestoreProved",
  "machineBootRestoreProved",
]);

const INDEX_CHUNK_KEYS = new Set([
  "index",
  "name",
  "size",
  "sha256",
  "sha1",
  "fileId",
  "uploadTimestamp",
]);

const INDEX_ARCHIVE_KEYS = new Set([
  "role",
  "format",
  "bytes",
  "sha256",
  "chunks",
]);

function asIndexChunk(
  value: unknown,
  label: string,
  generation: string,
  role: string,
): IndexChunk {
  const record = asObject(value, label);
  assertExactKeys(record, INDEX_CHUNK_KEYS, label);
  const index = asSafeInteger(record.index, label, 0, Number.MAX_SAFE_INTEGER);
  const name = asBoundedString(record.name, label, MAX_NAME_BYTES);
  const size = asSafeInteger(record.size, label, 1, MAX_CHUNK_BYTES);
  const sha256 = asSha256(record.sha256, label);
  const sha1 = asSha1(record.sha1, label);
  const fileId = asBoundedString(record.fileId, label, MAX_ID_BYTES);
  const uploadTimestamp = asSafeInteger(
    record.uploadTimestamp,
    label,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const expectedName = generationChunkName(generation, role, index);
  if (name !== expectedName) fail(label);
  return { index, name, size, sha256, sha1, fileId, uploadTimestamp };
}

function asIndexArchive(
  value: unknown,
  generation: string,
): IndexArchiveRecord {
  const record = asObject(value, "index:archive");
  assertExactKeys(record, INDEX_ARCHIVE_KEYS, "index:archive");
  const role = asRole(record.role, "index:role");
  const format = asFormat(record.format, "index:format");
  if (format !== expectedFormat(role)) fail("index:format");
  const bytes = asSafeInteger(
    record.bytes,
    "index:bytes",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const sha256 = asSha256(record.sha256, "index:hash");
  if (!Array.isArray(record.chunks) || record.chunks.length === 0) {
    fail("index:chunks");
  }
  const chunks = record.chunks.map((entry) =>
    asIndexChunk(entry, "index:chunk", generation, role)
  );
  let sum = 0;
  for (let i = 0; i < chunks.length; i += 1) {
    const chunk = chunks[i];
    if (chunk.index !== i) fail("index:chunks");
    if (i < chunks.length - 1 && chunk.size !== MAX_CHUNK_BYTES) {
      fail("index:chunk-size");
    }
    sum += chunk.size;
  }
  if (sum !== bytes) fail("index:sum");
  return { role, format, bytes, sha256, chunks };
}

/**
 * Pure strict standalone RecoveryIndex validation. The parser is the only
 * RecoveryIndex shape authority and therefore also validates restored
 * unknown JSON equally: missing, extra, duplicate and malformed content is
 * rejected before any side effect.
 */
export function validateRecoveryIndex(input: unknown): RecoveryIndex {
  const record = asObject(input, "index:shape");
  assertExactKeys(record, INDEX_KEYS, "index:keys");
  if (record.schemaVersion !== 1) fail("index:version");
  const generation = asString(record.generation, "index:generation");
  if (!GENERATION_PATTERN.test(generation)) fail("index:generation");
  const captureStartedAtUtc = asString(
    record.captureStartedAtUtc,
    "index:interval",
  );
  const captureFinishedAtUtc = asString(
    record.captureFinishedAtUtc,
    "index:interval",
  );
  const uploadStartedAtUtc = asString(
    record.uploadStartedAtUtc,
    "index:interval",
  );
  const uploadFinishedAtUtc = asString(
    record.uploadFinishedAtUtc,
    "index:interval",
  );
  if (
    !isUtcTimestamp(captureStartedAtUtc) ||
    !isUtcTimestamp(captureFinishedAtUtc) ||
    !isUtcTimestamp(uploadStartedAtUtc) ||
    !isUtcTimestamp(uploadFinishedAtUtc)
  ) {
    fail("index:interval");
  }
  if (
    Date.parse(captureStartedAtUtc) >= Date.parse(captureFinishedAtUtc) ||
    !beforeOrEqual(captureFinishedAtUtc, uploadStartedAtUtc) ||
    Date.parse(uploadStartedAtUtc) >= Date.parse(uploadFinishedAtUtc)
  ) {
    fail("index:interval");
  }
  if (record.consistency !== "live-file-copy") fail("index:consistency");
  if (record.sourceShutdown !== false) fail("index:shutdown");
  const recipientFingerprint = asString(
    record.recipientFingerprint,
    "index:recipient",
  );
  const recipientSha256 = asString(record.recipientSha256, "index:recipient");
  if (!FINGERPRINT_PATTERN.test(recipientFingerprint)) {
    fail("index:recipient");
  }
  if (!SHA256_PATTERN.test(recipientSha256)) fail("index:recipient");
  if (record.uploadVerified !== true) fail("index:flags");
  if (record.decryptedRestoreProved !== false) fail("index:flags");
  if (record.machineBootRestoreProved !== false) fail("index:flags");
  if (!Array.isArray(record.archives) || record.archives.length !== 7) {
    fail("index:archives");
  }
  const archives = record.archives.map((entry) =>
    asIndexArchive(entry, generation)
  );
  for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
    if (archives[i].role !== UPLOAD_ROLE_ORDER[i]) fail("index:archives");
  }
  // Every selected chunk version id is distinct across ALL seven archives.
  const selectedFileIds = new Set<string>();
  for (const archive of archives) {
    for (const chunk of archive.chunks) {
      if (selectedFileIds.has(chunk.fileId)) {
        fail("index:fileid-duplicate");
      }
      selectedFileIds.add(chunk.fileId);
    }
  }
  return {
    schemaVersion: 1,
    generation,
    captureStartedAtUtc,
    captureFinishedAtUtc,
    uploadStartedAtUtc,
    uploadFinishedAtUtc,
    consistency: "live-file-copy",
    sourceShutdown: false,
    recipientFingerprint,
    recipientSha256,
    archives,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}

/**
 * Build the canonical portable RecoveryIndex from a finalized capture and
 * its verified upload receipt. Pure and side-effect free: both inputs are
 * strictly validated here first (the CaptureResult through the existing
 * upload validator) and the built index is validated again through
 * validateRecoveryIndex before it is returned.
 */
export function buildRecoveryIndex(
  capture: CaptureResult,
  upload: UploadResult,
  recipient: IndexRecipient,
): RecoveryIndex {
  validateUploadCapture(capture);
  validateUploadResult(upload, capture);
  validateRecipientShape(recipient);
  const archives: IndexArchiveRecord[] = UPLOAD_ROLE_ORDER.map((role) => {
    const archive = upload.archives.find((candidate) =>
      candidate.role === role
    )!;
    return {
      role,
      format: archive.format,
      bytes: archive.bytes,
      sha256: archive.sha256,
      chunks: archive.chunks.map((chunk) => ({
        index: chunk.index,
        name: chunk.name,
        size: chunk.size,
        sha256: chunk.sha256,
        sha1: chunk.sha1,
        fileId: chunk.fileId,
        uploadTimestamp: chunk.uploadTimestamp,
      })),
    };
  });
  const index: RecoveryIndex = {
    schemaVersion: 1,
    generation: capture.generation,
    captureStartedAtUtc: capture.startedAtUtc,
    captureFinishedAtUtc: capture.finishedAtUtc,
    uploadStartedAtUtc: upload.startedAtUtc,
    uploadFinishedAtUtc: upload.finishedAtUtc,
    consistency: "live-file-copy",
    sourceShutdown: false,
    recipientFingerprint: recipient.recipientFingerprint,
    recipientSha256: recipient.recipientSha256,
    archives,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  return validateRecoveryIndex(index);
}

// ---------------------------------------------------------------------------
// Filesystem layer (uploader-style protections)
// ---------------------------------------------------------------------------

interface StageInfo {
  uid: number;
}

/** Real owner-only stage directory: no symlink, 0700, no group/other. */
async function assertStageDirectory(path: string): Promise<StageInfo> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("stage:missing");
    throw error;
  }
  if (info.isSymlink || !info.isDirectory) fail("stage:not-directory");
  if (info.mode === null || (info.mode & 0o777) !== 0o700) {
    fail("stage:permissions");
  }
  if (typeof info.uid !== "number") fail("stage:identity");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("stage:symlink");
  }
  if (real !== path) fail("stage:symlink");
  return { uid: info.uid };
}

/**
 * Production staging namespace guard, validated before any side effect: the
 * fixed base directory must already exist as a real 0700 directory (never
 * itself a symlink) and the caller must supply the canonical stage path
 * `<real-base>/<generation>` (platform ancestor symlinks like macOS /var are
 * resolved by canonicalizing the fixed base only). Arbitrary temp or source
 * paths are rejected; the stage must itself be real 0700 and owned by the
 * base owner.
 */
async function assertProductionStage(
  stageDirectory: string,
  generation: string,
): Promise<StageInfo> {
  let baseInfo: Deno.FileInfo;
  try {
    baseInfo = await Deno.lstat(PRODUCTION_STAGE_BASE);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("stage:base");
    throw error;
  }
  if (baseInfo.isSymlink || !baseInfo.isDirectory) fail("stage:base");
  if (baseInfo.mode === null || (baseInfo.mode & 0o777) !== 0o700) {
    fail("stage:base-permissions");
  }
  if (typeof baseInfo.uid !== "number") fail("stage:base-identity");
  let canonicalBase: string;
  try {
    canonicalBase = await Deno.realPath(PRODUCTION_STAGE_BASE);
  } catch {
    fail("stage:base");
  }
  if (stageDirectory !== `${canonicalBase}/${generation}`) {
    fail("stage:namespace");
  }
  const stage = await assertStageDirectory(stageDirectory);
  if (stage.uid !== baseInfo.uid) fail("stage:owner");
  return stage;
}

/** Existing-file protection: regular file, owner-only 0600, stage owner,
 * exactly one hardlink, no symlink. Returns false when the path is absent. */
async function assertPrivateFile(
  path: string,
  uid: number,
  label: string,
): Promise<boolean> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
  if (info.isSymlink || !info.isFile) fail(`${label}:file`);
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    fail(`${label}:permissions`);
  }
  if (info.uid !== uid) fail(`${label}:owner`);
  if (info.nlink !== 1) fail(`${label}:hardlink`);
  return true;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await Deno.lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return false;
    throw error;
  }
}

async function syncDirectory(path: string): Promise<void> {
  let directory: Deno.FsFile | null = null;
  try {
    directory = await Deno.open(path, { read: true });
    await directory.sync();
  } catch {
    fail("write");
  } finally {
    directory?.close();
  }
}

async function fsyncFile(path: string): Promise<void> {
  try {
    const file = await Deno.open(path, { write: true });
    try {
      await file.sync();
    } finally {
      file.close();
    }
  } catch {
    fail("write");
  }
}

/** Owner-only atomic write: 0600 temp, fsync, rename, directory fsync. The
 * caller is responsible for re-validating any overwritten fixed file. */
async function writeBytesAtomic(
  path: string,
  bytes: Uint8Array,
  label: string,
): Promise<void> {
  const slash = path.lastIndexOf("/");
  const directory = slash > 0 ? path.slice(0, slash) : ".";
  const name = slash > 0 ? path.slice(slash + 1) : path;
  const temporary = `${directory}/.${name}.${crypto.randomUUID()}.tmp`;
  try {
    const file = await Deno.open(temporary, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
    try {
      let offset = 0;
      while (offset < bytes.length) {
        offset += await file.write(bytes.subarray(offset));
      }
      await file.sync();
    } finally {
      file.close();
    }
    await Deno.chmod(temporary, 0o600);
    await Deno.rename(temporary, path);
    await Deno.chmod(path, 0o600);
    await syncDirectory(directory);
  } catch (error) {
    try {
      await Deno.remove(temporary);
    } catch (cleanup) {
      if (!(cleanup instanceof Deno.errors.NotFound)) fail(`${label}:write`);
    }
    if (
      typeof error === "object" && error !== null && error instanceof Error &&
      error.message.startsWith(FAIL_PREFIX)
    ) {
      throw error;
    }
    fail(`${label}:write`);
  }
}

/** Bounded file read: size pre-check plus whole read for small files. */
async function readBoundedFile(
  path: string,
  maxBytes: number,
  label: string,
): Promise<Uint8Array<ArrayBuffer>> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail(label);
  }
  if (info.size > maxBytes) fail(label);
  try {
    return await Deno.readFile(path);
  } catch {
    fail(label);
  }
}

/** Read an optional strictly-formatted owner-only JSON file. */
async function readJsonFile(
  path: string,
  uid: number,
  maxBytes: number,
  label: string,
): Promise<unknown | null> {
  if (!(await assertPrivateFile(path, uid, label))) return null;
  const bytes = await readBoundedFile(path, maxBytes, `${label}:size`);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    fail(`${label}:parse`);
  }
}

// ---------------------------------------------------------------------------
// GPG layer: public-only, bounded, redacted
// ---------------------------------------------------------------------------

interface BoundedOutput {
  bytes: Uint8Array;
  overflow: boolean;
}

async function readBounded(
  stream: ReadableStream<Uint8Array> | null,
  cap: number,
): Promise<BoundedOutput> {
  if (stream === null) return { bytes: new Uint8Array(0), overflow: false };
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  let overflow = false;
  try {
    while (true) {
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await reader.read();
      } catch {
        // A failed stream is treated as unbounded content.
        overflow = true;
        break;
      }
      if (result.done) break;
      const value = result.value;
      if (value === undefined) break;
      total += value.byteLength;
      if (total > cap) {
        overflow = true;
        try {
          await reader.cancel();
        } catch {
          // The stream is already finishing.
        }
        break;
      }
      parts.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Already released by cancel.
    }
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return { bytes: joined, overflow };
}

interface GpgResult {
  code: number;
  stdout: Uint8Array;
  stderr: Uint8Array;
  overflow: boolean;
}

/** Bound real gpg: argv only (never shell), stdout/stderr capped in memory;
 * errors are redacted and never include gpg output. */
async function runGpg(args: string[], label: string): Promise<GpgResult> {
  let child: Deno.ChildProcess;
  try {
    child = new Deno.Command("gpg", {
      args,
      stdout: "piped",
      stderr: "piped",
    }).spawn();
  } catch {
    fail(`${label}:command`);
  }
  const [stdout, stderr, status] = await Promise.all([
    readBounded(child.stdout, GPG_STDOUT_CAP),
    readBounded(child.stderr, GPG_STDERR_CAP),
    child.status,
  ]);
  return {
    code: status.code,
    stdout: stdout.bytes,
    stderr: stderr.bytes,
    overflow: stdout.overflow || stderr.overflow,
  };
}

const GPG_PUBLIC_BASE = [
  "--no-options",
  "--no-autostart",
  "--no-keyring",
] as const;

function showKeysArgs(home: string, recipient: string): string[] {
  return [
    ...GPG_PUBLIC_BASE,
    "--homedir",
    home,
    "--with-colons",
    "--show-keys",
    recipient,
  ];
}

function encryptArgs(
  home: string,
  recipient: string,
  output: string,
  input: string,
): string[] {
  return [
    ...GPG_PUBLIC_BASE,
    "--no-encrypt-to",
    "--batch",
    "--no-tty",
    "--homedir",
    home,
    "--recipient-file",
    recipient,
    "--compress-algo",
    "none",
    "--cipher-algo",
    "AES256",
    "--output",
    output,
    "--encrypt",
    input,
  ];
}

const SECRET_HOME_NAMES = new Set([
  "private-keys-v1.d",
  "secret-keys-v1.d",
  "secring.gpg",
  "secring.gpg.lock",
]);
const SECRET_ARMOR_MARKERS = [
  "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "-----BEGIN PGP SECRET KEY BLOCK-----",
] as const;

/** The dedicated public-only key home must contain no secret key material:
 * only owner-only regular files without secret armor markers and no
 * private-keyring names/directories. */
async function assertPublicHome(home: string, uid: number): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(home);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      try {
        await Deno.mkdir(home, { mode: 0o700 });
      } catch {
        fail("recipient:home");
      }
      await Deno.chmod(home, 0o700);
      info = await Deno.lstat(home);
    } else {
      throw error;
    }
  }
  if (info.isSymlink || !info.isDirectory) fail("recipient:home");
  if (info.mode === null || (info.mode & 0o777) !== 0o700) {
    fail("recipient:home-permissions");
  }
  if (info.uid !== uid) fail("recipient:home-owner");
  let real: string;
  try {
    real = await Deno.realPath(home);
  } catch {
    fail("recipient:home");
  }
  if (real !== home) fail("recipient:home");
  const names: string[] = [];
  try {
    for await (const entry of Deno.readDir(home)) names.push(entry.name);
  } catch {
    fail("recipient:home");
  }
  for (const name of names) {
    const entryPath = `${home}/${name}`;
    if (SECRET_HOME_NAMES.has(name)) fail("recipient:secret");
    let entryInfo: Deno.FileInfo;
    try {
      entryInfo = await Deno.lstat(entryPath);
    } catch {
      fail("recipient:home");
    }
    if (entryInfo.isSymlink || !entryInfo.isFile) fail("recipient:home");
    if (entryInfo.mode === null || (entryInfo.mode & 0o777) !== 0o600) {
      fail("recipient:home");
    }
    if (entryInfo.uid !== uid) fail("recipient:home");
    if (entryInfo.nlink !== 1) fail("recipient:home");
    if (entryInfo.size > 64 * 1024) fail("recipient:home");
    let content: Uint8Array;
    try {
      content = await Deno.readFile(entryPath);
    } catch {
      fail("recipient:home");
    }
    const text = new TextDecoder().decode(content);
    for (const marker of SECRET_ARMOR_MARKERS) {
      if (text.includes(marker)) fail("recipient:secret");
    }
  }
}

async function assertRecipientPinned(
  staged: string,
  uid: number,
  expectedSha256: string,
): Promise<void> {
  if (!(await assertPrivateFile(staged, uid, "recipient"))) {
    fail("recipient:file");
  }
  const bytes = await readBoundedFile(staged, MAX_RECIPIENT_BYTES, "recipient");
  if (sha256Hex(bytes) !== expectedSha256) fail("recipient:pin");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Bind the supplied recipient to the capture's retained pinned public file
 * (`<stage>/recipient.asc`, the file used for all seven archive
 * encryptions) on every publish path, before any new output or store
 * mutation. The capture file must already exist as a regular owner-only 0600
 * file (no symlink, no hardlinks), be ASCII public armor, hash to the
 * supplied recipientSha256 and be byte-equal to the supplied
 * recipient.recipientFile; exactly the expected public fingerprint is
 * proven with the dedicated public-only gpg home. The capture recipient and
 * the capture `gpg-public-home` are never written, rewritten or removed; a
 * different valid supplied key is rejected even when its own supplied hash
 * and fingerprint agree with themselves.
 */
async function bindRecipient(
  recipient: IndexRecipient,
  stageDirectory: string,
  uid: number,
  home: string,
  staged: string,
): Promise<void> {
  const captureRecipient = `${stageDirectory}/recipient.asc`;
  if (!(await assertPrivateFile(captureRecipient, uid, "recipient"))) {
    fail("recipient:capture");
  }
  const captureBytes = await readBoundedFile(
    captureRecipient,
    MAX_RECIPIENT_BYTES,
    "recipient",
  );
  if (!isPublicKeyArmorForm(new TextDecoder().decode(captureBytes))) {
    fail("recipient:capture");
  }
  if (sha256Hex(captureBytes) !== recipient.recipientSha256) {
    fail("recipient:capture");
  }
  if (!(await assertPrivateFile(recipient.recipientFile, uid, "recipient"))) {
    fail("recipient:file");
  }
  const supplied = await readBoundedFile(
    recipient.recipientFile,
    MAX_RECIPIENT_BYTES,
    "recipient",
  );
  if (!isPublicKeyArmorForm(new TextDecoder().decode(supplied))) {
    fail("recipient:armor");
  }
  if (sha256Hex(supplied) !== recipient.recipientSha256) fail("recipient:pin");
  if (!bytesEqual(supplied, captureBytes)) fail("recipient:capture");
  // The staged index copy is the captured pinned bytes; it may be created
  // here but is never rewritten and must never diverge from the capture file.
  if (await assertPrivateFile(staged, uid, "recipient")) {
    const stagedBytes = await readBoundedFile(
      staged,
      MAX_RECIPIENT_BYTES,
      "recipient",
    );
    if (!bytesEqual(stagedBytes, captureBytes)) fail("recipient:pin");
  } else {
    await writeBytesAtomic(staged, captureBytes, "recipient");
  }
  await assertPublicHome(home, uid);
  const result = await runGpg(
    showKeysArgs(home, captureRecipient),
    "recipient:key",
  );
  if (result.overflow || result.code !== 0) fail("recipient:key");
  const records = new TextDecoder().decode(result.stdout).split("\n");
  const publicKeys = records.filter((line) => line.startsWith("pub:"));
  const secretRecords = records.filter((line) =>
    line.startsWith("sec:") || line.startsWith("ssb:")
  );
  const fingerprints = records.filter((line) => line.startsWith("fpr:"))
    .map((line) => line.split(":")[9] ?? "");
  if (
    publicKeys.length !== 1 || fingerprints.length === 0 ||
    fingerprints[0] !== recipient.recipientFingerprint ||
    secretRecords.length > 0
  ) {
    fail("recipient:key");
  }
  await assertPublicHome(home, uid);
}

// ---------------------------------------------------------------------------
// Durable local state and receipt
// ---------------------------------------------------------------------------

const STATE_KEYS = new Set([
  "schemaVersion",
  "generation",
  "stageDirectory",
  "objectName",
  "indexSha256",
  "recipientSha256",
  "recipientFingerprint",
  "ciphertextBytes",
  "ciphertextSha256",
  "createdAtUtc",
]);

interface IndexState {
  schemaVersion: 1;
  generation: string;
  stageDirectory: string;
  objectName: string;
  indexSha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
  ciphertextBytes: number;
  ciphertextSha256: string;
  createdAtUtc: string;
}

const RECEIPT_KEYS = new Set([
  "schemaVersion",
  "generation",
  "stageDirectory",
  "objectName",
  "indexSha256",
  "ciphertextBytes",
  "ciphertextSha256",
  "recipientSha256",
  "recipientFingerprint",
  "fileId",
  "uploadTimestamp",
  "publishedAtUtc",
  "reused",
  "uploadVerified",
  "decryptedRestoreProved",
  "machineBootRestoreProved",
]);

interface IndexReceipt {
  schemaVersion: 1;
  generation: string;
  stageDirectory: string;
  objectName: string;
  indexSha256: string;
  ciphertextBytes: number;
  ciphertextSha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
  fileId: string;
  uploadTimestamp: number;
  publishedAtUtc: string;
  reused: boolean;
  uploadVerified: true;
  decryptedRestoreProved: false;
  machineBootRestoreProved: false;
}

function parseState(value: unknown, context: string): IndexState {
  const record = asObject(value, `${context}:shape`);
  assertExactKeys(record, STATE_KEYS, `${context}:keys`);
  if (record.schemaVersion !== 1) fail(`${context}:version`);
  const generation = asNonemptyString(
    record.generation,
    `${context}:generation`,
  );
  if (!GENERATION_PATTERN.test(generation)) fail(`${context}:generation`);
  const stageDirectory = asNonemptyString(
    record.stageDirectory,
    `${context}:stage`,
  );
  if (!ABSOLUTE_PATH_PATTERN.test(stageDirectory)) fail(`${context}:stage`);
  asNonemptyString(record.objectName, `${context}:object`);
  const indexSha256 = asSha256(record.indexSha256, `${context}:index`);
  const recipientSha256 = asSha256(
    record.recipientSha256,
    `${context}:recipient`,
  );
  const recipientFingerprint = asNonemptyString(
    record.recipientFingerprint,
    `${context}:recipient`,
  );
  if (!FINGERPRINT_PATTERN.test(recipientFingerprint)) {
    fail(`${context}:recipient`);
  }
  const ciphertextBytes = asSafeInteger(
    record.ciphertextBytes,
    `${context}:ciphertext`,
    1,
    MAX_CIPHERTEXT_BYTES,
  );
  const ciphertextSha256 = asSha256(
    record.ciphertextSha256,
    `${context}:ciphertext`,
  );
  const createdAtUtc = asNonemptyString(
    record.createdAtUtc,
    `${context}:interval`,
  );
  if (!isUtcTimestamp(createdAtUtc)) fail(`${context}:interval`);
  return {
    schemaVersion: 1,
    generation,
    stageDirectory,
    objectName: record.objectName as string,
    indexSha256,
    recipientSha256,
    recipientFingerprint,
    ciphertextBytes,
    ciphertextSha256,
    createdAtUtc,
  };
}

function parseReceipt(value: unknown, context: string): IndexReceipt {
  const record = asObject(value, `${context}:shape`);
  assertExactKeys(record, RECEIPT_KEYS, `${context}:keys`);
  if (record.schemaVersion !== 1) fail(`${context}:version`);
  const generation = asNonemptyString(
    record.generation,
    `${context}:generation`,
  );
  if (!GENERATION_PATTERN.test(generation)) fail(`${context}:generation`);
  const stageDirectory = asNonemptyString(
    record.stageDirectory,
    `${context}:stage`,
  );
  if (!ABSOLUTE_PATH_PATTERN.test(stageDirectory)) fail(`${context}:stage`);
  const objectName = asBoundedString(
    record.objectName,
    `${context}:object`,
    MAX_NAME_BYTES,
  );
  const indexSha256 = asSha256(record.indexSha256, `${context}:index`);
  const ciphertextBytes = asSafeInteger(
    record.ciphertextBytes,
    `${context}:ciphertext`,
    1,
    MAX_CIPHERTEXT_BYTES,
  );
  const ciphertextSha256 = asSha256(
    record.ciphertextSha256,
    `${context}:ciphertext`,
  );
  const recipientSha256 = asSha256(
    record.recipientSha256,
    `${context}:recipient`,
  );
  const fingerprint = asNonemptyString(
    record.recipientFingerprint,
    `${context}:recipient`,
  );
  if (!FINGERPRINT_PATTERN.test(fingerprint)) fail(`${context}:recipient`);
  const fileId = asBoundedString(
    record.fileId,
    `${context}:fileid`,
    MAX_ID_BYTES,
  );
  const uploadTimestamp = asSafeInteger(
    record.uploadTimestamp,
    `${context}:timestamp`,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const publishedAtUtc = asNonemptyString(
    record.publishedAtUtc,
    `${context}:interval`,
  );
  if (!isUtcTimestamp(publishedAtUtc)) fail(`${context}:interval`);
  if (typeof record.reused !== "boolean") fail(`${context}:reused`);
  if (record.uploadVerified !== true) fail(`${context}:flags`);
  if (record.decryptedRestoreProved !== false) fail(`${context}:flags`);
  if (record.machineBootRestoreProved !== false) fail(`${context}:flags`);
  return {
    schemaVersion: 1,
    generation,
    stageDirectory,
    objectName,
    indexSha256,
    ciphertextBytes,
    ciphertextSha256,
    recipientSha256,
    recipientFingerprint: fingerprint,
    fileId,
    uploadTimestamp,
    publishedAtUtc,
    reused: record.reused,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}

// ---------------------------------------------------------------------------
// Store reconciliation
// ---------------------------------------------------------------------------

/** Every selected own-namespace object must carry valid identity fields
 * before any receipt is constructed from it. */
function assertInventoryIdentity(version: B2Object): void {
  asBoundedString(version.fileId, "inventory:object", MAX_ID_BYTES);
  asSafeInteger(
    version.uploadTimestamp,
    "inventory:object",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  asSafeInteger(
    version.contentLength,
    "inventory:object",
    1,
    MAX_CHUNK_BYTES,
  );
  asSha1(version.contentSha1, "inventory:object");
}

/**
 * Classify the exact own per-generation index namespace. Malformed
 * non-object entries and entries without a string fileName are rejected
 * visibly; proper object names outside this generation are ignored.
 * Unexpected names, hide/start markers and every other namespace path fail
 * closed; other generations and namespaces are left untouched.
 */
function classifyIndexInventory(
  versions: B2Object[],
  generation: string,
): Map<string, B2Object[]> {
  const prefix = `${INDEX_PREFIX}${generation}/`;
  const objectName = indexObjectName(generation);
  const byName = new Map<string, B2Object[]>();
  for (const version of versions) {
    if (
      typeof version !== "object" || version === null || Array.isArray(version)
    ) {
      fail("inventory:shape");
    }
    if (typeof version.fileName !== "string") fail("inventory:shape");
    if (!version.fileName.startsWith(prefix)) continue;
    if (version.fileName !== objectName) fail("inventory:unexpected-object");
    assertInventoryIdentity(version);
    if (version.action !== "upload") fail("inventory:action");
    const list = byName.get(version.fileName) ?? [];
    list.push(version);
    byName.set(version.fileName, list);
  }
  return byName;
}

/** Every candidate must be an exact identical upload version. */
function assertCandidateIdentical(
  candidates: B2Object[],
  ciphertextBytes: Uint8Array,
  ciphertextSha1: string,
): void {
  for (const candidate of candidates) {
    if (
      candidate.action !== "upload" ||
      candidate.contentLength !== ciphertextBytes.byteLength ||
      candidate.contentSha1 !== ciphertextSha1
    ) {
      fail("inventory:conflict");
    }
  }
}

function orderedCandidates(candidates: B2Object[]): B2Object[] {
  return [...candidates].sort((a, b) => {
    if (a.uploadTimestamp !== b.uploadTimestamp) {
      return b.uploadTimestamp - a.uploadTimestamp;
    }
    if (a.fileId < b.fileId) return 1;
    if (a.fileId > b.fileId) return -1;
    return 0;
  });
}

/** Newest first; a saved exact version id is preferred when still present. */
function selectCandidate(
  candidates: B2Object[],
  savedFileId: string | null,
): B2Object {
  const ordered = orderedCandidates(candidates);
  if (savedFileId !== null) {
    const saved = ordered.find((candidate) => candidate.fileId === savedFileId);
    if (saved !== undefined) return saved;
  }
  return ordered[0];
}

function identityToObject(identity: B2Object): B2Object {
  return {
    fileId: identity.fileId,
    fileName: identity.fileName,
    contentLength: identity.contentLength,
    contentSha1: identity.contentSha1,
    action: "upload",
    uploadTimestamp: identity.uploadTimestamp,
  };
}

function assertReadback(
  readback: Uint8Array,
  expected: Uint8Array,
  expectedSha256: string,
): void {
  if (readback.byteLength !== expected.byteLength) fail("publish:readback");
  if (sha256Hex(readback) !== expectedSha256) fail("publish:readback");
  for (let i = 0; i < expected.byteLength; i += 1) {
    if (readback[i] !== expected[i]) fail("publish:readback");
  }
}

interface ReconcileContext {
  store: IndexStore;
  generation: string;
  objectName: string;
  ciphertext: Uint8Array<ArrayBuffer>;
  ciphertextSha256: string;
  ciphertextSha1: string;
  savedFileId: string | null;
}

/** Fresh inventory reconciliation, exact-version readback verification and
 * one non-blind put with a single refresh on a lost response. */
async function reconcileOrUpload(
  ctx: ReconcileContext,
): Promise<{ object: B2Object; reused: boolean }> {
  const byName = classifyIndexInventory(
    await ctx.store.versions(),
    ctx.generation,
  );
  const candidates = byName.get(ctx.objectName) ?? [];
  if (candidates.length > 0) {
    assertCandidateIdentical(candidates, ctx.ciphertext, ctx.ciphertextSha1);
    const selected = selectCandidate(candidates, ctx.savedFileId);
    const readback = await ctx.store.get(identityToObject(selected));
    assertReadback(readback, ctx.ciphertext, ctx.ciphertextSha256);
    return { object: selected, reused: true };
  }
  let put: B2Object;
  try {
    put = await ctx.store.put(ctx.objectName, ctx.ciphertext);
  } catch (error) {
    const refreshed = classifyIndexInventory(
      await ctx.store.versions(),
      ctx.generation,
    );
    const reconciled = refreshed.get(ctx.objectName) ?? [];
    if (reconciled.length === 0) throw error;
    assertCandidateIdentical(reconciled, ctx.ciphertext, ctx.ciphertextSha1);
    const selected = selectCandidate(reconciled, ctx.savedFileId);
    const readback = await ctx.store.get(identityToObject(selected));
    assertReadback(readback, ctx.ciphertext, ctx.ciphertextSha256);
    return { object: selected, reused: true };
  }
  const readback = await ctx.store.get(identityToObject(put));
  assertReadback(readback, ctx.ciphertext, ctx.ciphertextSha256);
  return { object: put, reused: false };
}

// ---------------------------------------------------------------------------
// Publish
// ---------------------------------------------------------------------------

/**
 * Build, encrypt once and publish the recovery index for a finalized
 * capture/upload pair. See the module header for the full contract; caller
 * owns exclusive source/controller locks and no acceptance marker is
 * published.
 */
export async function publishRecoveryIndex(
  capture: CaptureResult,
  upload: UploadResult,
  recipient: IndexRecipient,
  store: IndexStore,
): Promise<PublishedIndex> {
  const index = buildRecoveryIndex(capture, upload, recipient);
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(index));
  if (plaintextBytes.byteLength > MAX_INDEX_BYTES) fail("index:size");
  const indexSha256 = sha256Hex(plaintextBytes);
  const generation = capture.generation;
  const stageDirectory = capture.stageDirectory;
  const objectName = indexObjectName(generation);
  // Production staging namespace (fixed base + generation) before side effects.
  const stage = await assertProductionStage(stageDirectory, generation);
  const plaintextPath = `${stageDirectory}/${INDEX_FILE}`;
  const ciphertextPath = `${stageDirectory}/${CIPHERTEXT_FILE}`;
  const receiptPath = `${stageDirectory}/${RECEIPT_FILE}`;
  const statePath = `${stageDirectory}/${STATE_FILE}`;
  const stagedRecipient = `${stageDirectory}/${RECIPIENT_STAGED}`;
  const publicHome = `${stageDirectory}/${PUBLIC_HOME}`;
  const partialPath = `${stageDirectory}/${CIPHERTEXT_PARTIAL}`;

  // Existing fixed files are protected before anything else; a leftover
  // task-owned partial is a clearly reported incomplete state.
  await assertPrivateFile(plaintextPath, stage.uid, "index");
  await assertPrivateFile(ciphertextPath, stage.uid, "ciphertext");
  await assertPrivateFile(receiptPath, stage.uid, "receipt");
  await assertPrivateFile(statePath, stage.uid, "state");
  if (await fileExists(partialPath)) fail("ciphertext:partial");

  const stateValue = await readJsonFile(
    statePath,
    stage.uid,
    MAX_STATE_BYTES,
    "state",
  );

  if (stateValue === null) {
    // Fresh publish: nothing may exist yet; a leftover file is a visible
    // incomplete state and is never silently overwritten or re-uploaded.
    if (
      await fileExists(plaintextPath) || await fileExists(ciphertextPath) ||
      await fileExists(receiptPath)
    ) {
      fail("state:incomplete");
    }
    // Bind the supplied key to the capture recipient before any output.
    await bindRecipient(
      recipient,
      stageDirectory,
      stage.uid,
      publicHome,
      stagedRecipient,
    );
    await writeBytesAtomic(plaintextPath, plaintextBytes, "index");
    // Public bytes re-hashed immediately before encryption.
    await assertRecipientPinned(
      stagedRecipient,
      stage.uid,
      recipient.recipientSha256,
    );
    const encrypt = await runGpg(
      encryptArgs(publicHome, stagedRecipient, partialPath, plaintextPath),
      "encrypt:gpg",
    );
    if (encrypt.overflow || encrypt.code !== 0) fail("encrypt:gpg");
    await Deno.chmod(partialPath, 0o600);
    await fsyncFile(partialPath);
    // Create-new final: link fails when anything already exists, so an
    // existing final ciphertext is never overwritten; the partial stays for
    // the caller when the commit cannot complete.
    try {
      await Deno.link(partialPath, ciphertextPath);
    } catch (error) {
      if (error instanceof Deno.errors.AlreadyExists) fail("ciphertext:exists");
      fail("ciphertext:write");
    }
    try {
      await Deno.remove(partialPath);
    } catch {
      fail("ciphertext:write");
    }
    await syncDirectory(stageDirectory);
    await assertPrivateFile(ciphertextPath, stage.uid, "ciphertext");
    await assertPublicHome(publicHome, stage.uid);
    const ciphertext = await readBoundedFile(
      ciphertextPath,
      MAX_CIPHERTEXT_BYTES,
      "ciphertext",
    );
    const state: IndexState = {
      schemaVersion: 1,
      generation,
      stageDirectory,
      objectName,
      indexSha256,
      recipientSha256: recipient.recipientSha256,
      recipientFingerprint: recipient.recipientFingerprint,
      ciphertextBytes: ciphertext.byteLength,
      ciphertextSha256: sha256Hex(ciphertext),
      createdAtUtc: new Date().toISOString(),
    };
    // Durable state bound to the generation/plaintext/recipient/ciphertext
    // must exist before the first put.
    await writeBytesAtomic(
      statePath,
      new TextEncoder().encode(JSON.stringify(state)),
      "state",
    );
    const reconciled = await reconcileOrUpload({
      store,
      generation,
      objectName,
      ciphertext,
      ciphertextSha256: state.ciphertextSha256,
      ciphertextSha1: sha1Hex(ciphertext),
      savedFileId: null,
    });
    const surprisingReceipt = await readJsonFile(
      receiptPath,
      stage.uid,
      MAX_RECEIPT_BYTES,
      "receipt",
    );
    if (surprisingReceipt !== null) fail("receipt:unexpected");
    const receipt: IndexReceipt = {
      schemaVersion: 1,
      generation,
      stageDirectory,
      objectName,
      indexSha256,
      ciphertextBytes: ciphertext.byteLength,
      ciphertextSha256: state.ciphertextSha256,
      recipientSha256: recipient.recipientSha256,
      recipientFingerprint: recipient.recipientFingerprint,
      fileId: reconciled.object.fileId,
      uploadTimestamp: reconciled.object.uploadTimestamp,
      publishedAtUtc: new Date().toISOString(),
      reused: reconciled.reused,
      uploadVerified: true,
      decryptedRestoreProved: false,
      machineBootRestoreProved: false,
    };
    await writeBytesAtomic(
      receiptPath,
      new TextEncoder().encode(JSON.stringify(receipt)),
      "receipt",
    );
    return {
      generation,
      object: reconciled.object,
      ciphertextBytes: ciphertext.byteLength,
      ciphertextSha256: state.ciphertextSha256,
      indexSha256,
      uploadVerified: true,
      decryptedRestoreProved: false,
      machineBootRestoreProved: false,
    };
  }

  // Resume: validate the durable state against the newly built index.
  const state = parseState(stateValue, "state");
  if (state.generation !== generation) fail("state:index");
  if (state.stageDirectory !== stageDirectory) fail("state:index");
  if (state.objectName !== objectName) fail("state:object");
  if (state.indexSha256 !== indexSha256) fail("state:index");
  if (state.recipientSha256 !== recipient.recipientSha256) {
    fail("state:recipient");
  }
  if (state.recipientFingerprint !== recipient.recipientFingerprint) {
    fail("state:recipient");
  }
  // The existing canonical plaintext must byte-equal the newly built index;
  // it is never rewritten silently.
  if (!(await assertPrivateFile(plaintextPath, stage.uid, "index"))) {
    fail("state:plaintext");
  }
  const onDiskPlaintext = await readBoundedFile(
    plaintextPath,
    MAX_INDEX_BYTES,
    "state:plaintext",
  );
  if (sha256Hex(onDiskPlaintext) !== indexSha256) fail("state:plaintext");
  for (let i = 0; i < plaintextBytes.length; i += 1) {
    if (onDiskPlaintext[i] !== plaintextBytes[i]) fail("state:plaintext");
  }
  // Ciphertext size and hash are validated from the durable local state and
  // the original ciphertext is reused — never re-encrypted.
  if (!(await assertPrivateFile(ciphertextPath, stage.uid, "ciphertext"))) {
    fail("state:ciphertext");
  }
  const ciphertext = await readBoundedFile(
    ciphertextPath,
    MAX_CIPHERTEXT_BYTES,
    "state:ciphertext",
  );
  if (ciphertext.byteLength !== state.ciphertextBytes) {
    fail("state:ciphertext");
  }
  if (sha256Hex(ciphertext) !== state.ciphertextSha256) {
    fail("state:ciphertext");
  }
  // Recipient identity continuity: bind to the capture pinned file (byte
  // equal to the supplied source, expected fingerprint proven); never
  // re-encrypts and never touches the capture gpg-public-home.
  await bindRecipient(
    recipient,
    stageDirectory,
    stage.uid,
    publicHome,
    stagedRecipient,
  );
  const receiptValue = await readJsonFile(
    receiptPath,
    stage.uid,
    MAX_RECEIPT_BYTES,
    "receipt",
  );
  let savedFileId: string | null = null;
  let existingReceipt: IndexReceipt | null = null;
  if (receiptValue !== null) {
    existingReceipt = parseReceipt(receiptValue, "receipt");
    if (existingReceipt.generation !== generation) fail("receipt:generation");
    if (existingReceipt.stageDirectory !== stageDirectory) {
      fail("receipt:stage");
    }
    if (existingReceipt.objectName !== objectName) fail("receipt:object");
    if (existingReceipt.indexSha256 !== indexSha256) fail("receipt:index");
    if (
      existingReceipt.ciphertextBytes !== ciphertext.byteLength ||
      existingReceipt.ciphertextSha256 !== state.ciphertextSha256
    ) {
      fail("receipt:ciphertext");
    }
    if (
      existingReceipt.recipientSha256 !== recipient.recipientSha256 ||
      existingReceipt.recipientFingerprint !== recipient.recipientFingerprint
    ) {
      fail("receipt:recipient");
    }
    savedFileId = existingReceipt.fileId;
  }
  // Fresh inventory before any reconciliation or put.
  const reconciled = await reconcileOrUpload({
    store,
    generation,
    objectName,
    ciphertext,
    ciphertextSha256: state.ciphertextSha256,
    ciphertextSha1: sha1Hex(ciphertext),
    savedFileId,
  });
  const receipt: IndexReceipt = {
    schemaVersion: 1,
    generation,
    stageDirectory,
    objectName,
    indexSha256,
    ciphertextBytes: ciphertext.byteLength,
    ciphertextSha256: state.ciphertextSha256,
    recipientSha256: recipient.recipientSha256,
    recipientFingerprint: recipient.recipientFingerprint,
    fileId: reconciled.object.fileId,
    uploadTimestamp: reconciled.object.uploadTimestamp,
    // The original publication time is preserved only for the exact same
    // selected version; a replaced/reconciled version is a new publication.
    publishedAtUtc: existingReceipt !== null &&
        reconciled.object.fileId === existingReceipt.fileId
      ? existingReceipt.publishedAtUtc
      : new Date().toISOString(),
    reused: reconciled.reused,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  await writeBytesAtomic(
    receiptPath,
    new TextEncoder().encode(JSON.stringify(receipt)),
    "receipt",
  );
  return {
    generation,
    object: reconciled.object,
    ciphertextBytes: ciphertext.byteLength,
    ciphertextSha256: state.ciphertextSha256,
    indexSha256,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}
