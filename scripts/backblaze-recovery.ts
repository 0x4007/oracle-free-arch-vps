/**
 * m05-recovery: host-neutral library that reconstructs all seven ciphertext
 * archives of a validated portable RecoveryIndex into a caller-provided
 * recovery directory. It depends only on the validated index (m04) and the
 * exact-version download capability of the B2 store (m01); no source
 * capture/upload stage, journal, manifest or keyring file is read or
 * required, and no private key, decryption, acceptance marker, retention,
 * controller, CLI entrypoint or new storage interface is introduced.
 *
 * The caller supplies an EXISTING canonical absolute real directory that is
 * owner-only (mode 0700, no symlink anywhere on the path and owned by the
 * process that will own the reconstructed files). The directory is bound at
 * entry to its original POSIX device+inode plus owner and permission bits
 * (non-null dev/ino are required on the supported POSIX surface), and every
 * checkpoint rechecks that exact identity: a replacement directory that
 * merely has the same owner/mode is never accepted. The expected owner is
 * derived from that directory itself (no Deno.uid/sys permission probe):
 * every created file must be owned by that same uid, and an existing final
 * is never accepted as a same-name archive unless it is owned by it. The
 * host is never assumed: ancestor symlinks (for example macOS /var) are
 * rejected by requiring `realPath(directory) === directory`, and existing
 * paths are never chmodded, re-owned, rewritten or removed to make them
 * acceptable.
 *
 * The seven finals are named only from the validated roles:
 * `<role>.tar.zst.gpg` for the six filesystem archives and
 * `recovery.json.zst.gpg` for the recovery role. Every final is a regular
 * 0600 file with exactly one hardlink, owned by the directory owner. The
 * directory must contain nothing else: an unknown entry, a conflicting
 * same-name final (wrong identity or wrong full size/SHA-256) and an
 * abandoned `.partial` all fail clearly BEFORE any chunk is fetched (the
 * leftover partial is left untouched for explicit diagnosis and is never
 * removed or reused). A completed valid same-name final may coexist for
 * resume and is reused only after its identity is checked at open and its
 * full size/SHA-256 is stream-verified in bounded reads (no store get is
 * issued for it). Reuse and publish both retain a small verified identity
 * record (dev+inode, owner, mode, link count, size and mtime/ctime where
 * the platform provides them) that must be unchanged at every later
 * checkpoint and before the result is returned; in-place drift is detected
 * by comparing mtime/ctime where available. Nothing is ever overwritten or
 * removed except the task-owned partial just linked into the new final.
 *
 * Reconstruction is strictly sequential, one bounded chunk at a time. Each
 * chunk is fetched with store.get on the EXACT selected version identity
 * from the validated index (fileId, name, size, sha1, uploadTimestamp,
 * action "upload"); the returned bytes are independently validated for
 * type, length, SHA-256 and SHA-1 (the store additionally guarantees the
 * exact version headers and SHA-1) before any byte is written. Bytes are
 * appended to a fresh `createNew` 0600 partial whose open-handle identity
 * is bound immediately after creation: the handle and then the pathname are
 * re-checked against that original dev+inode after write/fsync, immediately
 * before the link and immediately before the partial removal; the
 * pathname is never chmodded (the createNew 0600 mode already satisfies the
 * guards). A visible progress loop continues on short writes and validates
 * every returned count (safe integer greater than zero, at most the
 * requested bytes); a zero/negative return fails immediately. The
 * incremental archive SHA-256 and a safe size accumulation must equal the
 * validated archive descriptor exactly; only then is the partial fsynced
 * and closed, and the final published with a create-new hard link followed
 * by removal of only the new owned partial after both paths are re-verified
 * to address the original inode with exactly two links. After the unlink
 * the final must be the original inode with exactly one link, and the
 * containing directory is synced through a handle that is itself bound to
 * the original directory identity. Finals are re-verified against their
 * retained identity records and the entries are rescanned at every
 * checkpoint and before the result is returned. A failed fetch or write
 * leaves the current partial in place for diagnosis, leaves already
 * completed earlier finals resumable, preserves every foreign or replaced
 * path and never claims completion: the returned result is produced only
 * when every archive is on disk, with ciphertextReconstructed true and
 * decryptedRestoreProved / machineBootRestoreProved false.
 *
 * Callers must keep exclusive control of the recovery directory; this is
 * detectable-drift defense against path replacement between the checks, not
 * a claim of race-free extraction from an untrusted directory. Errors never
 * expose provider response bodies or payload bytes: store failures and
 * filesystem failures are re-thrown as bounded module errors, and no
 * secret, credential or plaintext value is accepted or returned.
 */
import { createHash } from "node:crypto";

import {
  type IndexArchiveRecord,
  type IndexChunk,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "./backblaze-index.ts";
import type { B2Object, B2Store } from "./backblaze-storage.ts";

const FAIL_PREFIX = "Recovery failed (";
const READ_BUFFER_BYTES = 1024 * 1024;

/** One reconstructed ciphertext archive on disk (index order). */
export interface ReconstructedArchive extends IndexArchiveRecord {
  /** Absolute final path inside the recovery directory. */
  path: string;
}

/** Verified ciphertext reconstruction result; never an acceptance marker. */
export interface ReconstructedGeneration {
  generation: string;
  /** SHA-256 of JSON.stringify of the validated canonical index. */
  indexSha256: string;
  recipientFingerprint: string;
  recipientSha256: string;
  recoveryDirectory: string;
  archives: ReconstructedArchive[];
  ciphertextReconstructed: true;
  decryptedRestoreProved: false;
  machineBootRestoreProved: false;
}

/**
 * Original identity of the canonical recovery directory: POSIX device and
 * inode (both non-null on the supported surface) plus owner and permission
 * bits. A replacement directory with the same owner/mode is rejected.
 */
interface DirectoryIdentity {
  dev: number;
  ino: number;
  uid: number;
  /** Permission bits (0o777). */
  mode: number;
}

/**
 * Original open-handle identity of a freshly created partial, bound before
 * any fetch and re-checked after write/fsync and immediately before link
 * and removal. The pathname must always address this dev+inode with the
 * expected owner/mode/link-count/size; timestamps are intentionally not
 * bound because the partial's own writes change them.
 */
interface PartialBinding {
  dev: number;
  ino: number;
  uid: number;
  mode: number;
}

/**
 * Small verified identity record retained for an accepted final (reused or
 * newly published) and required unchanged at every later checkpoint.
 * mtime/ctime are epoch milliseconds where the platform provides them, so
 * in-place drift of an accepted final is detected.
 */
interface FileIdentityRecord {
  dev: number;
  ino: number;
  uid: number;
  mode: number;
  nlink: number;
  size: number;
  mtime: number | null;
  ctime: number | null;
}

function fail(label: string): never {
  throw new Error(`${FAIL_PREFIX}${label})`);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

/** Final file name derived only from the validated role and format. */
function archiveFileName(archive: IndexArchiveRecord): string {
  return `${archive.role}.${archive.format}`;
}

/**
 * Check the canonical owner-only recovery directory and return its original
 * identity. Non-null stable device and inode are required on the supported
 * POSIX surface; a directory without them is never accepted.
 */
async function assertRecoveryDirectory(
  path: string,
): Promise<DirectoryIdentity> {
  if (typeof path !== "string" || !path.startsWith("/")) {
    fail("directory:absolute");
  }
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("directory:missing");
    fail("directory:check");
  }
  if (info.isSymlink || !info.isDirectory) fail("directory:not-directory");
  if (info.mode === null || (info.mode & 0o777) !== 0o700) {
    fail("directory:permissions");
  }
  if (typeof info.uid !== "number") fail("directory:identity");
  if (info.dev === null || info.ino === null) fail("directory:identity");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("directory:realpath");
  }
  if (real !== path) fail("directory:realpath");
  return {
    dev: info.dev,
    ino: info.ino,
    uid: info.uid,
    mode: info.mode & 0o777,
  };
}

/**
 * Recheck that `path` still is the bound recovery directory: the full
 * canonical owner-only checks plus the exact original dev+ino+uid+mode.
 */
async function assertDirectoryIdentity(
  path: string,
  expected: DirectoryIdentity,
): Promise<void> {
  const actual = await assertRecoveryDirectory(path);
  if (
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode
  ) {
    fail("directory:identity");
  }
}

/**
 * Classify every directory entry: only the exact seven final names may
 * exist. A leftover task-owned `.partial` and any other entry fail clearly
 * before any chunk is fetched; nothing is removed, reused or cleaned.
 * Returns the set of final names currently present.
 */
async function assertOnlyExpectedEntries(
  recoveryDirectory: string,
  expected: Map<string, IndexArchiveRecord>,
): Promise<Set<string>> {
  const present = new Set<string>();
  try {
    for await (const entry of Deno.readDir(recoveryDirectory)) {
      if (expected.has(entry.name)) {
        present.add(entry.name);
        continue;
      }
      if (entry.name.endsWith(".partial")) fail("partial");
      fail("entry");
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("read");
  }
  return present;
}

/** Capture the stable identity record of an already-validated file stat. */
function recordFromFileInfo(info: Deno.FileInfo): FileIdentityRecord {
  return {
    dev: info.dev!,
    ino: info.ino!,
    uid: info.uid!,
    mode: (info.mode ?? 0) & 0o777,
    nlink: info.nlink!,
    size: info.size,
    mtime: info.mtime === null ? null : info.mtime.getTime(),
    ctime: info.ctime === null ? null : info.ctime.getTime(),
  };
}

/** Whether a fresh stat still addresses the retained record exactly. */
function matchesRecord(
  info: Deno.FileInfo,
  record: FileIdentityRecord,
): boolean {
  if (info.dev !== record.dev || info.ino !== record.ino) return false;
  if (info.uid !== record.uid) return false;
  if (info.mode === null || (info.mode & 0o777) !== record.mode) return false;
  if (info.nlink !== record.nlink) return false;
  if (info.size !== record.size) return false;
  if (
    record.mtime !== null &&
    (info.mtime === null || info.mtime.getTime() !== record.mtime)
  ) {
    return false;
  }
  if (
    record.ctime !== null &&
    (info.ctime === null || info.ctime.getTime() !== record.ctime)
  ) {
    return false;
  }
  return true;
}

/**
 * Recheck a retained final identity record on the pathname: regular file,
 * no symlink, exact dev+inode/owner/mode/link-count/size, mtime/ctime where
 * the record has them (in-place drift), and canonical path. A missing final
 * reports `final:changed`, any other drift `final:drift`.
 */
async function assertRecordedFinal(
  path: string,
  record: FileIdentityRecord,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("final:changed");
    fail("final:drift");
  }
  if (info.isSymlink || !info.isFile) fail("final:drift");
  if (!matchesRecord(info, record)) fail("final:drift");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("final:drift");
  }
  if (real !== path) fail("final:drift");
}

/**
 * Reuse verification of an existing same-name final: lstat identity is
 * preserved and compared with the opened fstat dev+inode; mode, owner,
 * link count, size and the full streamed SHA-256 must match the validated
 * descriptor, and after the read both the handle and the pathname must
 * still match the preserved identity and size (mtime/ctime where available
 * detect in-place drift). Any mismatch is a conflicting final and fails
 * before any store fetch. Returns the retained identity record.
 */
async function verifyExistingFinal(
  path: string,
  owner: number,
  archive: IndexArchiveRecord,
): Promise<FileIdentityRecord> {
  let before: Deno.FileInfo;
  try {
    before = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) fail("final:changed");
    fail("final:check");
  }
  if (before.isSymlink || !before.isFile) fail("final:identity");
  if (before.mode === null || (before.mode & 0o777) !== 0o600) {
    fail("final:permissions");
  }
  if (before.uid !== owner) fail("final:owner");
  if (before.nlink !== 1) fail("final:hardlink");
  if (before.dev === null || before.ino === null) fail("final:identity");
  if (before.size !== archive.bytes) fail("final:conflict");
  let real: string;
  try {
    real = await Deno.realPath(path);
  } catch {
    fail("final:identity");
  }
  if (real !== path) fail("final:identity");
  let file: Deno.FsFile;
  try {
    file = await Deno.open(path, { read: true });
  } catch {
    fail("final:read");
  }
  try {
    let openInfo: Deno.FileInfo;
    try {
      openInfo = await file.stat();
    } catch {
      fail("final:read");
    }
    if (!openInfo.isFile) fail("final:identity");
    if (openInfo.dev !== before.dev || openInfo.ino !== before.ino) {
      fail("final:identity");
    }
    if (openInfo.mode === null || (openInfo.mode & 0o777) !== 0o600) {
      fail("final:permissions");
    }
    if (openInfo.uid !== owner) fail("final:owner");
    if (openInfo.nlink !== 1) fail("final:hardlink");
    if (openInfo.size !== archive.bytes) fail("final:conflict");
    const hasher = createHash("sha256");
    const buffer = new Uint8Array(READ_BUFFER_BYTES);
    let total = 0;
    while (true) {
      let n: number | null;
      try {
        n = await file.read(buffer);
      } catch {
        fail("final:read");
      }
      if (n === null) break;
      if (n === 0) fail("final:read");
      total += n;
      if (total > archive.bytes) fail("final:conflict");
      hasher.update(buffer.subarray(0, n));
    }
    if (total !== archive.bytes) fail("final:conflict");
    if (hasher.digest("hex") !== archive.sha256) fail("final:conflict");
    const verified = recordFromFileInfo(before);
    let afterOpen: Deno.FileInfo;
    let afterPath: Deno.FileInfo;
    try {
      afterOpen = await file.stat();
      afterPath = await Deno.lstat(path);
    } catch {
      fail("final:drift");
    }
    if (!matchesRecord(afterOpen, verified)) fail("final:drift");
    if (!matchesRecord(afterPath, verified)) fail("final:drift");
  } finally {
    file.close();
  }
  return recordFromFileInfo(before);
}

/** Fetch one chunk with the exact selected version identity; validate
 * independently (type, length, SHA-256, SHA-1) before any write. Store
 * failures are surfaced as bounded module errors without provider bodies. */
async function fetchChunk(
  store: Pick<B2Store, "get">,
  chunk: IndexChunk,
): Promise<Uint8Array> {
  const object: B2Object = {
    fileId: chunk.fileId,
    fileName: chunk.name,
    contentLength: chunk.size,
    contentSha1: chunk.sha1,
    action: "upload",
    uploadTimestamp: chunk.uploadTimestamp,
  };
  let bytes: Uint8Array;
  try {
    bytes = await store.get(object);
  } catch {
    fail("get");
  }
  if (!(bytes instanceof Uint8Array)) fail("get:type");
  if (bytes.byteLength !== chunk.size) fail("get:length");
  if (sha256Hex(bytes) !== chunk.sha256) fail("get:sha256");
  if (sha1Hex(bytes) !== chunk.sha1) fail("get:sha1");
  return bytes;
}

/**
 * Write every byte with a visible progress loop: short writes continue, and
 * every returned count must be a safe integer strictly greater than zero and
 * no larger than the requested bytes. A zero/negative return is a progress
 * failure; a non-safe-integer or oversized count is a contract failure.
 */
async function writeProgress(
  file: Deno.FsFile,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const remaining = bytes.subarray(offset);
    let written: number;
    try {
      written = await file.write(remaining);
    } catch {
      fail("write");
    }
    if (!Number.isSafeInteger(written) || written > remaining.byteLength) {
      fail("write:count");
    }
    if (written <= 0) fail("write:progress");
    offset += written;
  }
}

/** Recheck the still-open handle against the bound partial identity. */
async function assertHandleIsBound(
  file: Deno.FsFile,
  binding: PartialBinding,
  size: number,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await file.stat();
  } catch {
    fail("partial:identity");
  }
  if (info.isSymlink || !info.isFile) fail("partial:identity");
  if (info.dev !== binding.dev || info.ino !== binding.ino) {
    fail("partial:identity");
  }
  if (info.uid !== binding.uid) fail("partial:owner");
  if (info.mode === null || (info.mode & 0o777) !== binding.mode) {
    fail("partial:permissions");
  }
  if (info.nlink !== 1) fail("partial:hardlink");
  if (info.size !== size) fail("partial:length");
}

/** Bind a pathname lstat to the original partial dev+inode. */
async function assertBoundPartial(
  path: string,
  binding: PartialBinding,
  nlink: number,
  size: number,
): Promise<void> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch {
    fail("partial:identity");
  }
  if (info.isSymlink || !info.isFile) fail("partial:identity");
  if (info.dev !== binding.dev || info.ino !== binding.ino) {
    fail("partial:identity");
  }
  if (info.uid !== binding.uid) fail("partial:owner");
  if (info.mode === null || (info.mode & 0o777) !== binding.mode) {
    fail("partial:permissions");
  }
  if (info.nlink !== nlink) fail("partial:hardlink");
  if (info.size !== size) fail("partial:length");
}

/** After the link both paths must address the original partial inode with
 * the expected owner/mode/size and exactly two links. */
async function assertLinkedPair(
  partialPath: string,
  finalPath: string,
  binding: PartialBinding,
  size: number,
): Promise<void> {
  let partialInfo: Deno.FileInfo;
  let finalInfo: Deno.FileInfo;
  try {
    partialInfo = await Deno.lstat(partialPath);
    finalInfo = await Deno.lstat(finalPath);
  } catch {
    fail("final:identity");
  }
  if (
    partialInfo.isSymlink || !partialInfo.isFile ||
    finalInfo.isSymlink || !finalInfo.isFile
  ) {
    fail("final:identity");
  }
  if (partialInfo.dev !== binding.dev || partialInfo.ino !== binding.ino) {
    fail("final:identity");
  }
  if (finalInfo.dev !== binding.dev || finalInfo.ino !== binding.ino) {
    fail("final:identity");
  }
  if (partialInfo.uid !== binding.uid || finalInfo.uid !== binding.uid) {
    fail("final:owner");
  }
  if (
    partialInfo.mode === null || finalInfo.mode === null ||
    (partialInfo.mode & 0o777) !== binding.mode ||
    (finalInfo.mode & 0o777) !== binding.mode
  ) {
    fail("final:permissions");
  }
  if (partialInfo.nlink !== 2 || finalInfo.nlink !== 2) {
    fail("final:hardlink");
  }
  if (partialInfo.size !== size || finalInfo.size !== size) {
    fail("final:identity");
  }
}

/** Sync the directory through a handle bound to the original identity. */
async function syncDirectory(
  path: string,
  identity: DirectoryIdentity,
): Promise<void> {
  let directory: Deno.FsFile | null = null;
  try {
    directory = await Deno.open(path, { read: true });
    const info = await directory.stat();
    if (info.dev !== identity.dev || info.ino !== identity.ino) {
      fail("directory:identity");
    }
    await directory.sync();
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("write");
  } finally {
    directory?.close();
  }
}

/**
 * Reconstruct one archive into a fresh 0600 partial and publish it as a
 * create-new final via hard link. The handle identity is bound immediately
 * after createNew and re-checked after write/fsync; the pathname lstat is
 * bound to that original dev+inode before the link and before the partial
 * removal; the directory is rechecked before open/link/remove and the
 * directory sync handle is bound to it. The partial is fsynced and closed
 * only after the full archive digest and size match; the final is linked
 * only when absent and never re-created from another path (no chmod is ever
 * applied to a pathname); the partial is removed only after both paths
 * address that original inode with exactly two links, and after the unlink
 * the final must be that inode with exactly one link. On any failure the
 * current partial and every foreign/replaced path are left in place.
 */
async function reconstructArchive(
  store: Pick<B2Store, "get">,
  directory: DirectoryIdentity,
  recoveryDirectory: string,
  archive: IndexArchiveRecord,
  partialPath: string,
  finalPath: string,
): Promise<FileIdentityRecord> {
  await assertDirectoryIdentity(recoveryDirectory, directory);
  let file: Deno.FsFile;
  try {
    file = await Deno.open(partialPath, {
      write: true,
      createNew: true,
      mode: 0o600,
    });
  } catch (error) {
    if (error instanceof Deno.errors.AlreadyExists) fail("partial:exists");
    fail("write");
  }
  // Bind the original created handle before any fetch.
  let binding: PartialBinding;
  try {
    let openInfo: Deno.FileInfo;
    try {
      openInfo = await file.stat();
    } catch {
      fail("partial:identity");
    }
    if (openInfo.isSymlink || !openInfo.isFile) fail("partial:identity");
    if (openInfo.mode === null || (openInfo.mode & 0o777) !== 0o600) {
      fail("partial:permissions");
    }
    if (openInfo.uid !== directory.uid) fail("partial:owner");
    if (openInfo.nlink !== 1) fail("partial:hardlink");
    if (openInfo.dev === null || openInfo.ino === null) {
      fail("partial:identity");
    }
    binding = {
      dev: openInfo.dev,
      ino: openInfo.ino,
      uid: openInfo.uid,
      mode: openInfo.mode & 0o777,
    };
  } catch (error) {
    file.close();
    if (error instanceof Error && error.message.startsWith(FAIL_PREFIX)) {
      throw error;
    }
    fail("partial:identity");
  }
  const hasher = createHash("sha256");
  let total = 0;
  try {
    for (const chunk of archive.chunks) {
      const bytes = await fetchChunk(store, chunk);
      // Safe size accumulation: never exceeds the validated archive bytes.
      if (chunk.size > archive.bytes - total) fail("archive:length");
      total += chunk.size;
      hasher.update(bytes);
      await writeProgress(file, bytes);
    }
    if (total !== archive.bytes) fail("archive:length");
    if (hasher.digest("hex") !== archive.sha256) fail("archive:hash");
    try {
      await file.sync();
    } catch {
      fail("write");
    }
    // The opened handle must still be the bound original partial, the
    // original directory must still be bound, and the pathname lstat must
    // address that original inode before the handle is closed or linked.
    await assertHandleIsBound(file, binding, total);
    await assertDirectoryIdentity(recoveryDirectory, directory);
    await assertBoundPartial(partialPath, binding, 1, total);
  } finally {
    file.close();
  }
  // Recheck the original directory and the bound pathname immediately
  // before the final is published.
  await assertDirectoryIdentity(recoveryDirectory, directory);
  await assertBoundPartial(partialPath, binding, 1, total);
  try {
    await Deno.link(partialPath, finalPath);
  } catch (error) {
    if (error instanceof Deno.errors.AlreadyExists) fail("final:exists");
    fail("write");
  }
  // After the link both paths address the original inode with exactly two
  // links; rechecked with the original directory identity immediately
  // before removing only this invocation's partial.
  await assertLinkedPair(partialPath, finalPath, binding, total);
  await assertDirectoryIdentity(recoveryDirectory, directory);
  await assertLinkedPair(partialPath, finalPath, binding, total);
  try {
    await Deno.remove(partialPath);
  } catch {
    fail("write");
  }
  // After the unlink the final must be the original inode, nlink 1.
  let finalInfo: Deno.FileInfo;
  try {
    finalInfo = await Deno.lstat(finalPath);
  } catch {
    fail("final:changed");
  }
  if (finalInfo.isSymlink || !finalInfo.isFile) fail("final:identity");
  if (finalInfo.dev !== binding.dev || finalInfo.ino !== binding.ino) {
    fail("final:identity");
  }
  if (finalInfo.uid !== binding.uid) fail("final:owner");
  if (finalInfo.mode === null || (finalInfo.mode & 0o777) !== binding.mode) {
    fail("final:permissions");
  }
  if (finalInfo.nlink !== 1) fail("final:hardlink");
  if (finalInfo.size !== total) fail("final:identity");
  let real: string;
  try {
    real = await Deno.realPath(finalPath);
  } catch {
    fail("final:identity");
  }
  if (real !== finalPath) fail("final:identity");
  await syncDirectory(recoveryDirectory, directory);
  return recordFromFileInfo(finalInfo);
}

function archiveResult(
  archive: IndexArchiveRecord,
  path: string,
): ReconstructedArchive {
  return {
    role: archive.role,
    format: archive.format,
    path,
    bytes: archive.bytes,
    sha256: archive.sha256,
    chunks: archive.chunks.map((chunk) => ({ ...chunk })),
  };
}

/**
 * Reconstruct every archive of the validated RecoveryIndex. The index is
 * validated and copied at entry (caller mutation across awaits cannot
 * change the selected identities or indexSha256), the output directory is
 * checked and bound to its original dev+ino+uid+mode before any side
 * effect, every retained final identity is rechecked at each checkpoint,
 * and the result is returned only after all seven finals are on disk,
 * still matching their retained identity records, and the entries are
 * rescanned.
 */
export async function reconstructGeneration(
  indexInput: RecoveryIndex,
  store: Pick<B2Store, "get">,
  recoveryDirectory: string,
): Promise<ReconstructedGeneration> {
  const index = validateRecoveryIndex(indexInput);
  const indexSha256 = sha256Hex(
    new TextEncoder().encode(JSON.stringify(index)),
  );
  const expected = new Map<string, IndexArchiveRecord>();
  for (const archive of index.archives) {
    expected.set(archiveFileName(archive), archive);
  }
  const directory = await assertRecoveryDirectory(recoveryDirectory);
  const owner = directory.uid;
  // Full pre-flight before any fetch: entries are classified (unknown
  // entries and abandoned partials fail) and every existing same-name final
  // is identity-checked and stream-verified, retaining its verified
  // identity record; a conflicting final fails before it is ever replaced
  // or re-fetched.
  const present = await assertOnlyExpectedEntries(recoveryDirectory, expected);
  const retained = new Map<string, FileIdentityRecord>();
  for (const archive of index.archives) {
    const name = archiveFileName(archive);
    if (!present.has(name)) continue;
    const finalPath = `${recoveryDirectory}/${name}`;
    retained.set(name, await verifyExistingFinal(finalPath, owner, archive));
  }
  const results: ReconstructedArchive[] = [];
  for (const archive of index.archives) {
    const name = archiveFileName(archive);
    const finalPath = `${recoveryDirectory}/${name}`;
    const reusable = retained.get(name);
    if (reusable !== undefined) {
      results.push(archiveResult(archive, finalPath));
      continue;
    }
    // Checkpoint before this archive's fetch/publish: the directory must
    // still be the bound original and contain only expected entries, and
    // every retained final identity must still be unchanged.
    await assertDirectoryIdentity(recoveryDirectory, directory);
    await assertOnlyExpectedEntries(recoveryDirectory, expected);
    for (const [completedName, identity] of retained) {
      await assertRecordedFinal(
        `${recoveryDirectory}/${completedName}`,
        identity,
      );
    }
    const identity = await reconstructArchive(
      store,
      directory,
      recoveryDirectory,
      archive,
      `${finalPath}.partial`,
      finalPath,
    );
    retained.set(name, identity);
    results.push(archiveResult(archive, finalPath));
  }
  // Final checkpoint before the result is returned: bound directory
  // identity, entry rescan (no unexpected file may have appeared) and every
  // retained final identity, so no replacement is accepted.
  await assertDirectoryIdentity(recoveryDirectory, directory);
  await assertOnlyExpectedEntries(recoveryDirectory, expected);
  for (const [name, identity] of retained) {
    await assertRecordedFinal(`${recoveryDirectory}/${name}`, identity);
  }
  return {
    generation: index.generation,
    indexSha256,
    recipientFingerprint: index.recipientFingerprint,
    recipientSha256: index.recipientSha256,
    recoveryDirectory,
    archives: results,
    ciphertextReconstructed: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}
