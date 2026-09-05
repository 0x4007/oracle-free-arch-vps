import { createHash, type Hash } from "node:crypto";
import type { CaptureResult } from "./backblaze-capture.ts";
import {
  type B2Object,
  type B2Store,
  DIRECT_PREFIX,
  MAX_CHUNK_BYTES,
} from "./backblaze-storage.ts";

/**
 * m03-upload: source-side uploader for the dedicated-bucket encrypted
 * Backblaze file backup.
 *
 * This module takes a finalized public-key-encrypted CaptureResult from its
 * owner-only stage and streams each ciphertext archive to deterministic
 * object names under
 * DIRECT_PREFIX + "generations/<generation>/<role>/<zero-padded-index>" in
 * bounded pieces of at most MAX_CHUNK_BYTES. The selected exact version of
 * every chunk is verified by readback through B2Store.get (exact file id,
 * length and SHA-1), then by chunk SHA-256 and an incremental ordered
 * full-archive SHA-256 compared to the capture hash, last short chunk
 * included. Local archives are streamed through builtin node:crypto with
 * bounded reads; no archive-sized buffer is ever allocated.
 *
 * Before any upload a full B2 version inventory restricted to the own
 * generation is reconciled: an existing version with the exact name, length
 * and SHA-1 is reused only after an exact-version SHA-256 readback of the
 * selected primary version. Only that primary is read back: duplicate
 * identical versions are metadata-only inventory extras, never downloaded
 * and never independently readback-verified here, so they are not recovery
 * members on their own. Conflicting content or a start/hide marker inside
 * the generation fails closed. A lost put response refreshes the inventory
 * exactly once and reconciles the same expected object; an absent object
 * rethrows the original failure and is never blindly re-uploaded. There are
 * no timed retries and remove is not part of this module's store
 * dependency, so no version is ever deleted or hidden here (duplicate
 * identical versions are preserved and listed in the receipt for later
 * accounting/pruning). The receipt's version lists contain only identities
 * that are currently inventoried or were successfully put in this
 * invocation — a journal identity absent from the current inventory is
 * never reported — and any later retention/pruning must fetch a fresh
 * inventory instead of trusting that receipt list.
 *
 * A fixed owner-only atomic journal
 * (stageDirectory + "/upload-journal.json") is written after every verified
 * chunk and binds the generation, the original archive descriptors and the
 * exact chunk identities/hashes/order. It is validated strictly on resume
 * (wrong generation, changed archive, path, name, hash, index or size all
 * fail); the journal carries no acceptance flag. The original
 * journal.startedAtUtc is preserved across resumed invocations so the
 * receipt describes the same upload operation without silently resetting
 * its age; controller job deadlines remain separately owned. Saved versions
 * are reconciled against the current inventory with readback; a saved
 * object that is missing may be put again only after that reconciliation.
 *
 * The caller owns exclusive source/controller locks, job identity, capture
 * persistence, bounded retries, encryption of the final recovery index,
 * verifier receipt, acceptance and four-point pruning. The result states
 * uploadVerified true and decryptedRestoreProved / machineBootRestoreProved
 * false: upload integrity is not a restore proof. No manifest or acceptance
 * marker is published by this module.
 */

export type UploadRole =
  | "root"
  | "efi"
  | "staging-boot"
  | "staging-efi"
  | "oracle-root"
  | "oracle-oled"
  | "recovery";

/** Canonical processing order of the seven archives. */
export const UPLOAD_ROLE_ORDER: readonly UploadRole[] = [
  "root",
  "efi",
  "staging-boot",
  "staging-efi",
  "oracle-root",
  "oracle-oled",
  "recovery",
];

const ROLE_SET = new Set<string>(UPLOAD_ROLE_ORDER);

export type UploadFormat = "tar.zst.gpg" | "json.zst.gpg";

/** One exact B2 version identity as listed by the version inventory. */
export interface UploadVersionIdentity {
  fileId: string;
  fileName: string;
  contentLength: number;
  contentSha1: string;
  action: "upload" | "hide" | "start";
  uploadTimestamp: number;
}

/** Receipt for one verified chunk in exact upload order. */
export interface UploadedChunk {
  role: UploadRole;
  /** Zero-based index of the chunk within its archive. */
  index: number;
  /** Deterministic B2 object name (no extension). */
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  /** Exact verified version id used for this chunk. */
  fileId: string;
  uploadTimestamp: number;
  /** Readback verification completion (ISO UTC). */
  verifiedAtUtc: string;
  /** True when the content came from an existing version, no put happened
   * in this invocation for this chunk. */
  reused: boolean;
  /** Every exact identical version identity for this chunk (identical name,
   * length and SHA-1) that is currently inventoried or was successfully put
   * in this invocation, newest first. Identical journal-only identities that
   * are absent from the current inventory are never listed. These are
   * metadata-only inventory extras — not independently readback-verified
   * recovery members — and any later retention/pruning must use a fresh
   * inventory instead of this list. */
  versions: UploadVersionIdentity[];
}

export interface UploadedArchive {
  role: UploadRole;
  format: UploadFormat;
  path: string;
  bytes: number;
  sha256: string;
  chunks: UploadedChunk[];
  verifiedAtUtc: string;
}

export interface UploadResult {
  generation: string;
  stageDirectory: string;
  archives: UploadedArchive[];
  chunkCount: number;
  totalBytes: number;
  /** Identical duplicate version identities that were not the selected
   * primary version of their chunk. They are metadata-only inventory extras,
   * not independently readback-verified recovery members, and the list is
   * for later accounting only: retention/pruning must re-fetch a fresh
   * inventory instead of trusting this receipt list. */
  duplicateVersions: UploadVersionIdentity[];
  startedAtUtc: string;
  finishedAtUtc: string;
  uploadVerified: true;
  decryptedRestoreProved: false;
  machineBootRestoreProved: false;
}

export interface UploadProgressRecord {
  role: UploadRole;
  chunkIndex: number;
  totalChunks: number;
}

/** Bounded store dependency: upload, exact-version download, version list.
 * Deliberately omits remove and every other storage operation. */
export type UploadStore = Pick<B2Store, "put" | "get" | "versions">;

interface PlannedChunk {
  role: UploadRole;
  index: number;
  name: string;
  size: number;
  sha256: string;
  sha1: string;
}

interface ArchivePlan {
  role: UploadRole;
  format: UploadFormat;
  path: string;
  bytes: number;
  sha256: string;
  chunks: PlannedChunk[];
}

/** Journal chunk binding: the verified exact identities only. */
interface JournalChunk {
  role: UploadRole;
  index: number;
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  fileId: string;
  uploadTimestamp: number;
  reused: boolean;
  verifiedAtUtc: string;
}

interface JournalArchive {
  role: UploadRole;
  format: UploadFormat;
  path: string;
  bytes: number;
  sha256: string;
}

interface UploadJournal {
  schemaVersion: 1;
  generation: string;
  stageDirectory: string;
  startedAtUtc: string;
  archives: JournalArchive[];
  chunks: JournalChunk[];
}

interface StageInfo {
  uid: number;
}

interface UploadContext {
  store: UploadStore;
  generation: string;
  stage: StageInfo;
  journalPath: string;
  journal: UploadJournal;
  byName: Map<string, B2Object[]>;
  savedByRole: Map<UploadRole, JournalChunk[]>;
  processed: number;
  totalChunks: number;
  progress?: (record: UploadProgressRecord) => Promise<void>;
}

const FAIL_PREFIX = "Upload failed (";
const GENERATION_PATTERN =
  /^generation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA1_PATTERN = /^[0-9a-f]{40}$/;
const ABSOLUTE_PATH_PATTERN = /^\/[A-Za-z0-9/_.-]+$/;
const CHUNK_INDEX_PATTERN = /^[0-9]{8}$/;
const JOURNAL_VERSION = 1;
const JOURNAL_NAME = "upload-journal.json";
const MAX_JOURNAL_BYTES = 64 * 1024 * 1024;

function fail(label: string): never {
  throw new Error(`${FAIL_PREFIX}${label})`);
}

function isIsoUtc(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 &&
    Number.isFinite(Date.parse(value));
}

function expectedFormat(role: string): UploadFormat {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

function generationPrefix(generation: string): string {
  return `${DIRECT_PREFIX}generations/${generation}/`;
}

/** Deterministic chunk object name for a generation/role/index. */
export function generationChunkName(
  generation: string,
  role: string,
  index: number,
): string {
  if (!Number.isSafeInteger(index) || index < 0) fail("chunk-name:index");
  return `${generationPrefix(generation)}${role}/${
    String(index).padStart(8, "0")
  }`;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

/**
 * Pure CaptureResult validation: exact generation-UUID, live-file-copy with
 * sourceShutdown false, seven unique roles with their expected format,
 * archive path exactly stage + "/" + role + "." + format, positive safe
 * integer sizes and canonical lowercase SHA-256. No side effects.
 */
export function validateUploadCapture(capture: CaptureResult): void {
  if (typeof capture !== "object" || capture === null) fail("capture:shape");
  if (!GENERATION_PATTERN.test(capture.generation)) {
    fail("capture:generation");
  }
  if (capture.consistency !== "live-file-copy") fail("capture:consistency");
  if (capture.sourceShutdown !== false) fail("capture:source-shutdown");
  if (!isIsoUtc(capture.startedAtUtc) || !isIsoUtc(capture.finishedAtUtc)) {
    fail("capture:interval");
  }
  if (
    typeof capture.stageDirectory !== "string" ||
    !ABSOLUTE_PATH_PATTERN.test(capture.stageDirectory)
  ) {
    fail("capture:stage");
  }
  if (
    !Array.isArray(capture.archives) ||
    capture.archives.length !== UPLOAD_ROLE_ORDER.length
  ) {
    fail("capture:archives");
  }
  const seen = new Set<string>();
  for (const archive of capture.archives) {
    if (typeof archive !== "object" || archive === null) {
      fail("capture:archive");
    }
    if (typeof archive.role !== "string" || !ROLE_SET.has(archive.role)) {
      fail("capture:archive");
    }
    if (seen.has(archive.role)) fail("capture:archive");
    seen.add(archive.role);
    if (archive.format !== expectedFormat(archive.role)) fail("capture:format");
    const expectedPath =
      `${capture.stageDirectory}/${archive.role}.${archive.format}`;
    if (
      typeof archive.path !== "string" || archive.path !== expectedPath
    ) {
      fail("capture:path");
    }
    if (
      typeof archive.bytes !== "number" ||
      !Number.isSafeInteger(archive.bytes) ||
      archive.bytes <= 0
    ) {
      fail("capture:bytes");
    }
    if (
      typeof archive.sha256 !== "string" || !SHA256_PATTERN.test(archive.sha256)
    ) {
      fail("capture:hash");
    }
  }
  if (seen.size !== UPLOAD_ROLE_ORDER.length) fail("capture:archives");
}

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

async function assertArchiveFile(
  stage: StageInfo,
  archive: { path: string },
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(archive.path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("archive:missing");
    throw error;
  }
  if (info.isSymlink || !info.isFile) fail("archive:file");
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    fail("archive:permissions");
  }
  if (info.uid !== stage.uid) fail("archive:owner");
  let real: string;
  try {
    real = await Deno.realPath(archive.path);
  } catch {
    fail("archive:symlink");
  }
  if (real !== archive.path) fail("archive:symlink");
}

/**
 * Test-only seam for planArchive: the maximum number of bytes requested
 * from the archive file per read. Lowering it forces short nonfinal reads
 * through the real planning pipeline, proving that chunk boundaries depend
 * only on content counts and never on read request/return sizes. No
 * production caller changes this; the focused test restores it afterwards.
 */
export const planReadTestSeam: { maxBytes: number } = {
  maxBytes: MAX_CHUNK_BYTES,
};

/** Stream one archive locally: bounded chunks, per-chunk SHA-256/SHA-1 and
 * the full-archive SHA-256 compared to the capture descriptor. Every read
 * request is clamped to the bytes still needed for the current chunk, so
 * chunk boundaries are deterministic at exactly MAX_CHUNK_BYTES even when
 * the OS returns short reads. Sizes are checked before, during and after
 * the stream to catch drift and truncation. */
async function planArchive(
  stage: StageInfo,
  generation: string,
  archive: CaptureResult["archives"][number],
): Promise<ArchivePlan> {
  await assertArchiveFile(stage, archive);
  // validateUploadCapture ran before and proved the exact seven-role set.
  const role = archive.role as UploadRole;
  const format = archive.format as UploadFormat;
  let before: Deno.FileInfo;
  try {
    before = await Deno.stat(archive.path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("archive:missing");
    throw error;
  }
  if (before.size !== archive.bytes) fail("archive:size");
  const overall = createHash("sha256");
  let chunkHashes: { sha256: Hash; sha1: Hash } | null = null;
  let chunkBytes = 0;
  let index = 0;
  const chunks: PlannedChunk[] = [];
  const buffer = new Uint8Array(MAX_CHUNK_BYTES);
  let total = 0;
  let file: Deno.FsFile | null = null;
  try {
    try {
      file = await Deno.open(archive.path, { read: true });
    } catch {
      fail("archive:read");
    }
    while (true) {
      // Clamp the request to the bytes still needed for the current chunk:
      // a short read cannot shift the boundary and a following larger read
      // cannot cross it, so chunkBytes never exceeds MAX_CHUNK_BYTES and
      // flushes at exactly MAX_CHUNK_BYTES regardless of read sizes.
      const limit = Math.min(
        planReadTestSeam.maxBytes,
        MAX_CHUNK_BYTES - chunkBytes,
      );
      let n: number | null;
      try {
        n = await file.read(buffer.subarray(0, limit));
      } catch {
        fail("archive:read");
      }
      if (n === null) break;
      if (n === 0) fail("archive:read");
      const bytes = buffer.subarray(0, n);
      if (chunkHashes === null) {
        chunkHashes = {
          sha256: createHash("sha256"),
          sha1: createHash("sha1"),
        };
      }
      overall.update(bytes);
      chunkHashes.sha256.update(bytes);
      chunkHashes.sha1.update(bytes);
      chunkBytes += n;
      total += n;
      if (total > archive.bytes) fail("archive:size");
      if (chunkBytes === MAX_CHUNK_BYTES) {
        chunks.push({
          role,
          index,
          name: generationChunkName(generation, role, index),
          size: chunkBytes,
          sha256: chunkHashes.sha256.digest("hex"),
          sha1: chunkHashes.sha1.digest("hex"),
        });
        chunkHashes = null;
        chunkBytes = 0;
        index += 1;
      }
    }
  } finally {
    file?.close();
  }
  if (chunkHashes !== null) {
    chunks.push({
      role,
      index,
      name: generationChunkName(generation, role, index),
      size: chunkBytes,
      sha256: chunkHashes.sha256.digest("hex"),
      sha1: chunkHashes.sha1.digest("hex"),
    });
  }
  let after: Deno.FileInfo;
  try {
    after = await Deno.stat(archive.path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("archive:missing");
    throw error;
  }
  if (total !== archive.bytes || after.size !== archive.bytes) {
    fail("archive:size");
  }
  if (chunks.length === 0) fail("archive:empty");
  if (overall.digest("hex") !== archive.sha256) fail("archive:hash");
  return {
    role,
    format,
    path: archive.path,
    bytes: archive.bytes,
    sha256: archive.sha256,
    chunks,
  };
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

function asInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(label);
  }
  return value;
}

function asNonemptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) fail(label);
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

const JOURNAL_KEYS = new Set([
  "schemaVersion",
  "generation",
  "stageDirectory",
  "startedAtUtc",
  "archives",
  "chunks",
]);
const JOURNAL_ARCHIVE_KEYS = new Set([
  "role",
  "format",
  "path",
  "bytes",
  "sha256",
]);
const JOURNAL_CHUNK_KEYS = new Set([
  "role",
  "index",
  "name",
  "size",
  "sha256",
  "sha1",
  "fileId",
  "uploadTimestamp",
  "reused",
  "verifiedAtUtc",
]);

function asJournalArchive(
  value: unknown,
  label: string,
): JournalArchive {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(label);
  }
  const record = value as Record<string, unknown>;
  assertExactKeys(record, JOURNAL_ARCHIVE_KEYS, label);
  return {
    role: asRole(record.role, label),
    format: asFormat(record.format, label),
    path: asNonemptyString(record.path, label),
    bytes: asInteger(record.bytes, label),
    sha256: asNonemptyString(record.sha256, label),
  };
}

function asJournalChunk(value: unknown, label: string): JournalChunk {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(label);
  }
  const record = value as Record<string, unknown>;
  assertExactKeys(record, JOURNAL_CHUNK_KEYS, label);
  if (!SHA256_PATTERN.test(asNonemptyString(record.sha256, label))) {
    fail(label);
  }
  if (!SHA1_PATTERN.test(asNonemptyString(record.sha1, label))) {
    fail(label);
  }
  if (
    typeof record.reused !== "boolean" ||
    !isIsoUtc(record.verifiedAtUtc)
  ) {
    fail(label);
  }
  return {
    role: asRole(record.role, label),
    index: asInteger(record.index, label),
    name: asNonemptyString(record.name, label),
    size: asInteger(record.size, label),
    sha256: record.sha256 as string,
    sha1: record.sha1 as string,
    fileId: asNonemptyString(record.fileId, label),
    uploadTimestamp: asInteger(record.uploadTimestamp, label),
    reused: record.reused,
    verifiedAtUtc: record.verifiedAtUtc,
  };
}

function journalPath(stageDirectory: string): string {
  return `${stageDirectory}/${JOURNAL_NAME}`;
}

function expectedSequence(
  plans: ArchivePlan[],
): PlannedChunk[] {
  const flat: PlannedChunk[] = [];
  for (const plan of plans) flat.push(...plan.chunks);
  return flat;
}

/** Loaded journal content: the exact ordered saved chunk prefix plus the
 * original upload-operation start timestamp. */
interface LoadedJournal {
  chunks: JournalChunk[];
  /** Original journal.startedAtUtc (validated ISO UTC); null when no
   * journal exists yet and the caller must mint a fresh timestamp. */
  startedAtUtc: string | null;
}

/**
 * Load and strictly validate the fixed resume journal. The journal must be a
 * regular owner-only 0600 file; the generation and stage directory must
 * match the capture; every archive descriptor must equal the capture
 * descriptor; and the chunk entries must be an exact ordered prefix of the
 * chunks recomputed from the unchanged local ciphertext (role, index, name,
 * size, SHA-256, SHA-1 all equal; extra or unknown fields fail). Returns the
 * saved chunk prefix together with the journal's validated original
 * startedAtUtc, or { chunks: [], startedAtUtc: null } when the journal does
 * not exist yet.
 */
async function loadJournal(
  stage: StageInfo,
  capture: CaptureResult,
  plans: ArchivePlan[],
): Promise<LoadedJournal> {
  const path = journalPath(capture.stageDirectory);
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return { chunks: [], startedAtUtc: null };
    }
    throw error;
  }
  if (info.isSymlink || !info.isFile) fail("journal:file");
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    fail("journal:permissions");
  }
  if (info.uid !== stage.uid) fail("journal:owner");
  if (info.size > MAX_JOURNAL_BYTES) fail("journal:size");
  let text: string;
  try {
    text = await Deno.readTextFile(path);
  } catch {
    fail("journal:read");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail("journal:parse");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    fail("journal:shape");
  }
  const record = parsed as Record<string, unknown>;
  assertExactKeys(record, JOURNAL_KEYS, "journal:shape");
  if (record.schemaVersion !== JOURNAL_VERSION) fail("journal:version");
  if (record.generation !== capture.generation) fail("journal:generation");
  if (record.stageDirectory !== capture.stageDirectory) fail("journal:stage");
  const startedAtUtc = record.startedAtUtc;
  if (!isIsoUtc(startedAtUtc)) fail("journal:interval");
  if (!Array.isArray(record.archives) || !Array.isArray(record.chunks)) {
    fail("journal:shape");
  }
  if (record.archives.length !== UPLOAD_ROLE_ORDER.length) {
    fail("journal:archives");
  }
  const archiveByRole = new Map<UploadRole, JournalArchive>();
  for (const value of record.archives) {
    const entry = asJournalArchive(value, "journal:archives");
    if (archiveByRole.has(entry.role)) fail("journal:archives");
    archiveByRole.set(entry.role, entry);
  }
  for (const archive of capture.archives) {
    const entry = archiveByRole.get(archive.role as UploadRole);
    if (
      entry === undefined || entry.format !== archive.format ||
      entry.path !== archive.path || entry.bytes !== archive.bytes ||
      entry.sha256 !== archive.sha256
    ) {
      fail("journal:archives");
    }
  }
  if (archiveByRole.size !== UPLOAD_ROLE_ORDER.length) {
    fail("journal:archives");
  }
  const expected = expectedSequence(plans);
  const chunks = record.chunks.map((value) =>
    asJournalChunk(value, "journal:chunks")
  );
  if (chunks.length > expected.length) fail("journal:chunks");
  for (let i = 0; i < chunks.length; i += 1) {
    const entry = chunks[i];
    const expectedChunk = expected[i];
    if (
      entry.role !== expectedChunk.role ||
      entry.index !== expectedChunk.index ||
      entry.name !== expectedChunk.name || entry.size !== expectedChunk.size ||
      entry.sha256 !== expectedChunk.sha256 ||
      entry.sha1 !== expectedChunk.sha1
    ) {
      fail("journal:chunks");
    }
  }
  return { chunks, startedAtUtc };
}

async function syncDirectory(path: string): Promise<void> {
  let directory: Deno.FsFile | null = null;
  try {
    directory = await Deno.open(path, { read: true });
    await directory.sync();
  } catch {
    fail("journal:write");
  } finally {
    directory?.close();
  }
}

/** Owner-only atomic journal write: 0600 temp file in the same directory,
 * fsync, rename over the fixed path, directory fsync. */
async function writeJournal(
  path: string,
  journal: UploadJournal,
): Promise<void> {
  const slash = path.lastIndexOf("/");
  const directory = slash > 0 ? path.slice(0, slash) : ".";
  const temporary = `${directory}/.${JOURNAL_NAME}.${crypto.randomUUID()}.tmp`;
  try {
    const file = await Deno.open(temporary, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
    try {
      const bytes = new TextEncoder().encode(JSON.stringify(journal));
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
    await syncDirectory(directory);
  } catch (error) {
    try {
      await Deno.remove(temporary);
    } catch (cleanup) {
      if (!(cleanup instanceof Deno.errors.NotFound)) fail("journal:write");
    }
    if (
      typeof error === "object" && error !== null &&
      error instanceof Error && error.message.startsWith(FAIL_PREFIX)
    ) {
      throw error;
    }
    fail("journal:write");
  }
}

/** Full-version inventory restricted to the own generation. Every version
 * under generations/<generation>/ must parse as <role>/<8-digit-index> with a
 * known role and an upload action; start/hide markers and unexpected names
 * fail closed. Other generations and namespaces are left untouched. */
function classifyInventory(
  versions: B2Object[],
  generation: string,
): Map<string, B2Object[]> {
  const prefix = generationPrefix(generation);
  const byName = new Map<string, B2Object[]>();
  for (const version of versions) {
    if (!version.fileName.startsWith(prefix)) continue;
    const relative = version.fileName.slice(prefix.length);
    const slash = relative.indexOf("/");
    const role = slash > 0 ? relative.slice(0, slash) : "";
    const indexText = slash > 0 ? relative.slice(slash + 1) : "";
    if (
      slash <= 0 || !CHUNK_INDEX_PATTERN.test(indexText) ||
      !ROLE_SET.has(role)
    ) {
      fail("inventory:unexpected-object");
    }
    if (version.action !== "upload") fail("inventory:action");
    const list = byName.get(version.fileName) ?? [];
    list.push(version);
    byName.set(version.fileName, list);
  }
  return byName;
}

function asUploadIdentity(version: B2Object): UploadVersionIdentity {
  return {
    fileId: version.fileId,
    fileName: version.fileName,
    contentLength: version.contentLength,
    contentSha1: version.contentSha1,
    action: "upload",
    uploadTimestamp: version.uploadTimestamp,
  };
}

/** Every candidate must be an exact identical upload version (same length
 * and SHA-1); any conflicting version fails closed before any upload. */
function assertIdentical(
  candidates: B2Object[],
  chunk: PlannedChunk,
): void {
  for (const candidate of candidates) {
    if (candidate.action !== "upload") fail("chunk:conflict");
    if (
      candidate.contentLength !== chunk.size ||
      candidate.contentSha1 !== chunk.sha1
    ) {
      fail("chunk:conflict");
    }
  }
}

function assertReadback(
  chunk: PlannedChunk,
  readback: Uint8Array,
): void {
  if (
    readback.byteLength !== chunk.size || sha256Hex(readback) !== chunk.sha256
  ) {
    fail("chunk:readback");
  }
}

async function readChunkBytes(
  file: Deno.FsFile,
  size: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const buffer = new Uint8Array(size);
  let offset = 0;
  while (offset < size) {
    let n: number | null;
    try {
      n = await file.read(buffer.subarray(offset));
    } catch {
      fail("archive:read");
    }
    if (n === null || n === 0) fail("archive:truncated");
    offset += n;
  }
  return buffer;
}

function orderedIdentityVersions(
  versions: UploadVersionIdentity[],
): UploadVersionIdentity[] {
  return [...versions].sort((a, b) => {
    if (a.uploadTimestamp !== b.uploadTimestamp) {
      return b.uploadTimestamp - a.uploadTimestamp;
    }
    if (a.fileId < b.fileId) return 1;
    if (a.fileId > b.fileId) return -1;
    return 0;
  });
}

function reusableVersions(candidates: B2Object[]): UploadVersionIdentity[] {
  return orderedIdentityVersions(candidates.map(asUploadIdentity));
}

function verifiedChunk(
  chunk: PlannedChunk,
  primary: UploadVersionIdentity,
  reused: boolean,
  versions: UploadVersionIdentity[],
): UploadedChunk {
  return {
    role: chunk.role,
    index: chunk.index,
    name: chunk.name,
    size: chunk.size,
    sha256: chunk.sha256,
    sha1: chunk.sha1,
    fileId: primary.fileId,
    uploadTimestamp: primary.uploadTimestamp,
    verifiedAtUtc: new Date().toISOString(),
    reused,
    versions,
  };
}

/**
 * Verify one chunk: when identical versions already exist, reuse the exact
 * one after SHA-256 readback of the selected primary; otherwise upload and
 * verify by readback. A lost put response triggers exactly one inventory
 * refresh and reconciles the same expected object — an absent object
 * rethrows the original failure, a conflicting one fails closed. Saved
 * chunks prefer their journaled version id; a saved object missing from the
 * inventory may be put again after that reconciliation (and an ambiguous
 * re-put is reconciled the same way instead of being blindly retried).
 * Reported versions are the currently inventoried or successfully put
 * identities only — a journal identity absent from the inventory is never
 * listed as a duplicate.
 */
async function processChunk(
  chunk: PlannedChunk,
  buffer: Uint8Array<ArrayBuffer>,
  saved: JournalChunk | null,
  ctx: UploadContext,
): Promise<{ chunk: UploadedChunk; readback: Uint8Array }> {
  const localSha256 = sha256Hex(buffer);
  const localSha1 = sha1Hex(buffer);
  if (localSha256 !== chunk.sha256 || localSha1 !== chunk.sha1) {
    fail("archive:changed");
  }
  const candidates = ctx.byName.get(chunk.name) ?? [];
  if (candidates.length > 0) {
    assertIdentical(candidates, chunk);
    const versions = reusableVersions(candidates);
    let primary = versions[0];
    if (saved !== null) {
      const journaled = versions.find((version) =>
        version.fileId === saved.fileId
      );
      // A saved identity absent from the current inventory is deliberately
      // not listed: versions report only currently inventoried identities.
      if (journaled !== undefined) primary = journaled;
    }
    const readback = await ctx.store.get(identityToObject(primary, chunk));
    assertReadback(chunk, readback);
    return {
      chunk: verifiedChunk(chunk, primary, true, versions),
      readback,
    };
  }
  let put: B2Object;
  try {
    put = await ctx.store.put(chunk.name, buffer);
  } catch (error) {
    const refreshed = classifyInventory(
      await ctx.store.versions(),
      ctx.generation,
    );
    const reconciled = refreshed.get(chunk.name) ?? [];
    if (reconciled.length === 0) throw error;
    assertIdentical(reconciled, chunk);
    const versions = reusableVersions(reconciled);
    const primary = versions[0];
    const readback = await ctx.store.get(identityToObject(primary, chunk));
    assertReadback(chunk, readback);
    return {
      chunk: verifiedChunk(chunk, primary, true, versions),
      readback,
    };
  }
  const readback = await ctx.store.get(put);
  assertReadback(chunk, readback);
  // The saved journal identity is absent from the snapshot inventory (no
  // candidates at all), so only this successfully put identity is reported.
  const versions = [asUploadIdentity(put)];
  return {
    chunk: verifiedChunk(chunk, asUploadIdentity(put), false, versions),
    readback,
  };
}

function identityToObject(
  identity: UploadVersionIdentity,
  chunk: PlannedChunk,
): B2Object {
  if (
    identity.fileName !== chunk.name || identity.contentLength !== chunk.size ||
    identity.contentSha1 !== chunk.sha1
  ) {
    fail("chunk:conflict");
  }
  return {
    fileId: identity.fileId,
    fileName: identity.fileName,
    contentLength: identity.contentLength,
    contentSha1: identity.contentSha1,
    action: "upload",
    uploadTimestamp: identity.uploadTimestamp,
  };
}

function toJournalChunk(chunk: UploadedChunk): JournalChunk {
  return {
    role: chunk.role,
    index: chunk.index,
    name: chunk.name,
    size: chunk.size,
    sha256: chunk.sha256,
    sha1: chunk.sha1,
    fileId: chunk.fileId,
    uploadTimestamp: chunk.uploadTimestamp,
    reused: chunk.reused,
    verifiedAtUtc: chunk.verifiedAtUtc,
  };
}

async function uploadArchive(
  plan: ArchivePlan,
  ctx: UploadContext,
): Promise<UploadedArchive> {
  let file: Deno.FsFile | null = null;
  try {
    try {
      file = await Deno.open(plan.path, { read: true });
    } catch {
      fail("archive:read");
    }
    const readbackHash = createHash("sha256");
    let readbackBytes = 0;
    const chunks: UploadedChunk[] = [];
    const saved = ctx.savedByRole.get(plan.role) ?? [];
    for (let i = 0; i < plan.chunks.length; i += 1) {
      const planned = plan.chunks[i];
      const buffer = await readChunkBytes(file, planned.size);
      const savedEntry = i < saved.length ? saved[i] : null;
      const verified = await processChunk(planned, buffer, savedEntry, ctx);
      readbackHash.update(verified.readback);
      readbackBytes += verified.readback.byteLength;
      chunks.push(verified.chunk);
      const position = ctx.processed;
      ctx.processed += 1;
      if (position < ctx.journal.chunks.length) {
        ctx.journal.chunks[position] = toJournalChunk(verified.chunk);
      } else {
        ctx.journal.chunks.push(toJournalChunk(verified.chunk));
      }
      await writeJournal(ctx.journalPath, ctx.journal);
      await ctx.progress?.({
        role: plan.role,
        chunkIndex: planned.index,
        totalChunks: ctx.totalChunks,
      });
    }
    if (readbackBytes !== plan.bytes) fail("archive:readback");
    if (readbackHash.digest("hex") !== plan.sha256) fail("archive:hash");
    let after: Deno.FileInfo;
    try {
      after = await Deno.stat(plan.path);
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) fail("archive:missing");
      throw error;
    }
    if (after.size !== plan.bytes) fail("archive:drift");
    const last = chunks[chunks.length - 1];
    return {
      role: plan.role,
      format: plan.format,
      path: plan.path,
      bytes: plan.bytes,
      sha256: plan.sha256,
      chunks,
      verifiedAtUtc: last.verifiedAtUtc,
    };
  } finally {
    file?.close();
  }
}

/**
 * Upload and verify one finalized captured generation. See the module header
 * for the full contract; the result is an upload-integrity receipt only and
 * never an accepted restore point.
 */
export async function uploadCapturedGeneration(
  capture: CaptureResult,
  store: UploadStore,
  progress?: (record: UploadProgressRecord) => Promise<void>,
): Promise<UploadResult> {
  validateUploadCapture(capture);
  const stage = await assertStageDirectory(capture.stageDirectory);
  const plans: ArchivePlan[] = [];
  for (const role of UPLOAD_ROLE_ORDER) {
    const archive = capture.archives.find((candidate) =>
      candidate.role === role
    );
    if (archive === undefined) fail("capture:archives");
    plans.push(await planArchive(stage, capture.generation, archive));
  }
  const loaded = await loadJournal(stage, capture, plans);
  // A fresh invocation mints its own start; a resumed invocation keeps the
  // journal's original startedAtUtc so the receipt describes the same
  // upload operation without silently resetting its age. Controller job
  // deadlines remain separately owned.
  const startedAtUtc = loaded.startedAtUtc ?? new Date().toISOString();
  const saved = loaded.chunks;
  const savedByRole = new Map<UploadRole, JournalChunk[]>();
  for (const role of UPLOAD_ROLE_ORDER) {
    savedByRole.set(role, saved.filter((entry) => entry.role === role));
  }
  const storeVersions = await store.versions();
  const byName = classifyInventory(storeVersions, capture.generation);
  const totalChunks = plans.reduce((sum, plan) => sum + plan.chunks.length, 0);
  const journal: UploadJournal = {
    schemaVersion: 1,
    generation: capture.generation,
    stageDirectory: capture.stageDirectory,
    startedAtUtc,
    archives: plans.map((plan) => ({
      role: plan.role,
      format: plan.format,
      path: plan.path,
      bytes: plan.bytes,
      sha256: plan.sha256,
    })),
    chunks: saved,
  };
  const ctx: UploadContext = {
    store,
    generation: capture.generation,
    stage,
    journalPath: journalPath(capture.stageDirectory),
    journal,
    byName,
    savedByRole,
    processed: 0,
    totalChunks,
    progress,
  };
  const archiveResults: UploadedArchive[] = [];
  for (const plan of plans) {
    archiveResults.push(await uploadArchive(plan, ctx));
  }
  const duplicateVersions: UploadVersionIdentity[] = [];
  for (const archive of archiveResults) {
    for (const chunk of archive.chunks) {
      for (const version of chunk.versions) {
        if (version.fileId !== chunk.fileId) duplicateVersions.push(version);
      }
    }
  }
  return {
    generation: capture.generation,
    stageDirectory: capture.stageDirectory,
    archives: archiveResults,
    chunkCount: totalChunks,
    totalBytes: plans.reduce((sum, plan) => sum + plan.bytes, 0),
    duplicateVersions,
    startedAtUtc,
    finishedAtUtc: new Date().toISOString(),
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}
