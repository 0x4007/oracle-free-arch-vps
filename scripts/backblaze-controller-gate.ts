/**
 * Owner-only gate persistence for the Backblaze controller foundation.
 *
 * All mutating APIs (writeActiveGate, bindInvocation, markOrphaned and
 * clearGateAfterProof) REQUIRE the caller to hold the existing shared
 * controller lock (`.private/backup-controller.lock`); every mutation
 * re-reads the gate, compares the caller's expected identity, and re-checks
 * the original parent, directory and file identity immediately before
 * changing anything. readGate is safe without the lock and is what a
 * read-only watchdog will use later.
 *
 * The gate file is owner-only POSIX data in one exclusive trusted parent
 * directory (0700, owner derived from the directory itself, without Deno.uid
 * or allow-sys), a regular 0600 file with exactly one hard link, never a
 * symlink, owned by the same owner as its parent, read through a bounded
 * (<= 64 KiB) handle whose device/inode/owner/mode/size identity is verified
 * before and after the read, with the original parent identity re-verified
 * before the read is returned. A missing final path is absence only after
 * the original parent identity is confirmed again; malformed or unsafe
 * state never means absence and always fails closed.
 *
 * Published replacements are written into a same-directory temp file whose
 * fstat-verified identity (dev/ino/uid/mode/size) is retained from the
 * original open handle and then rechecked against lstat before and after
 * every write, after sync, and immediately before the atomic rename or
 * create-new hard link. A replacement found after the handle is closed is
 * never trusted. After publication the final name is verified to be the
 * original temp inode with the required owner, mode and exactly one hard
 * link. Directory sync uses a handle that is proved to be the original
 * parent, and the identity is rechecked again after the sync.
 *
 * These checks bind identity but never claim race-free mutation of an
 * untrusted directory: they assume the exclusive trusted `.private`
 * directory and the caller-held controller lock remain prerequisites.
 */
import {
  type BackupControllerGate,
  gateIdentityEqual,
  ORPHAN_REASONS,
  type OrphanReason,
  validateGate,
  validateGateClearProof,
  validateUnitInvocationId,
} from "./backblaze-controller-contract.ts";

export { assertOracleMutationAllowed } from "./backblaze-controller-contract.ts";

export const DEFAULT_GATE_PATH = ".private/backup-controller-gate.json";
const MAX_GATE_BYTES = 64 * 1024;

interface ParentIdentity {
  path: string;
  base: string;
  dev: number;
  ino: number;
  mode: number;
  uid: number;
}

interface FileIdentity {
  dev: number;
  ino: number;
  nlink: number;
  mode: number;
  uid: number;
  size: number;
}

interface GateRead {
  gate: BackupControllerGate;
  parent: ParentIdentity;
  file: FileIdentity;
}

interface TempFile {
  path: string;
  /** Original handle-retained identity (dev/ino/uid/mode/size after write). */
  identity: FileIdentity;
}

function finalPathOf(parent: ParentIdentity): string {
  return `${parent.path}/${parent.base}`;
}

/** Canonical real parent directory, 0700, with its owner derived from the
 * directory itself. A missing parent is never treated as gate absence. */
async function resolveParent(path: string): Promise<ParentIdentity> {
  if (typeof path !== "string" || path === "") {
    throw new Error("Gate path must be a non-empty string");
  }
  if (path.includes("\0")) {
    throw new Error("Gate path must not contain NUL");
  }
  const slash = path.lastIndexOf("/");
  const parent = slash === -1 ? "." : path.slice(0, slash);
  const base = slash === -1 ? path : path.slice(slash + 1);
  if (!base || base === "." || base === "..") {
    throw new Error("Gate path must name a file inside a directory");
  }
  let canonical: string;
  try {
    canonical = await Deno.realPath(parent);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      throw new Error("Gate parent directory is missing");
    }
    throw error;
  }
  const info = await Deno.lstat(canonical);
  if (!info.isDirectory || info.isSymlink) {
    throw new Error("Gate parent must be a real directory");
  }
  if (
    info.mode === null || (info.mode & 0o777) !== 0o700 ||
    typeof info.dev !== "number" || typeof info.ino !== "number" ||
    typeof info.uid !== "number"
  ) {
    throw new Error("Gate parent must grant only owner access (0700)");
  }
  return {
    path: canonical,
    base,
    dev: info.dev,
    ino: info.ino,
    mode: info.mode,
    uid: info.uid,
  };
}

/** Fixed owner-only regular-file checks; a symlink is not a regular file. */
function assertGateFile(
  info: Deno.FileInfo,
  parent: ParentIdentity,
): FileIdentity {
  if (!info.isFile || info.isSymlink) {
    throw new Error("Gate must be a regular file, never a symlink");
  }
  if (info.nlink !== 1) {
    throw new Error("Gate must have exactly one hard link");
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    throw new Error("Gate must grant only owner access (0600)");
  }
  if (
    typeof info.dev !== "number" || typeof info.ino !== "number" ||
    typeof info.uid !== "number"
  ) {
    throw new Error("Gate ownership cannot be derived");
  }
  if (info.uid !== parent.uid) {
    throw new Error(
      "Gate must be owned by the same owner as its parent directory",
    );
  }
  return {
    dev: info.dev,
    ino: info.ino,
    nlink: info.nlink,
    mode: info.mode,
    uid: info.uid,
    size: info.size,
  };
}

function sameInode(
  a: { dev: number; ino: number },
  b: { dev: number; ino: number },
): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

/** Full retained identity comparison; the hard-link count is checked by the
 * caller because the gate temp legitimately gains a second link. Nullable
 * filesystem fields are never treated as identity matches. */
function sameFileState(
  a: {
    dev: number | null;
    ino: number | null;
    uid: number | null;
    mode: number | null;
    size: number;
  },
  b: FileIdentity,
): boolean {
  return a.dev !== null && a.ino !== null && a.uid !== null &&
    a.mode !== null && a.dev === b.dev && a.ino === b.ino &&
    a.uid === b.uid && a.mode === b.mode && a.size === b.size;
}

/** Inode/owner/mode comparison only; used for failure cleanup where a write
 * may have been interrupted and the size is not a trustworthy completion
 * marker. */
function sameOwnedInode(
  a: {
    dev: number | null;
    ino: number | null;
    uid: number | null;
    mode: number | null;
  },
  b: FileIdentity,
): boolean {
  return a.dev !== null && a.ino !== null && a.uid !== null &&
    a.mode !== null && a.dev === b.dev && a.ino === b.ino &&
    a.uid === b.uid && a.mode === b.mode;
}

function assertSameParent(
  a: ParentIdentity,
  b: ParentIdentity,
  why: string,
): void {
  if (
    a.dev !== b.dev || a.ino !== b.ino || a.mode !== b.mode ||
    a.uid !== b.uid
  ) {
    throw new Error(`Gate parent identity changed ${why}`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Full retained identity of one expected file (regular, 0600, owner mode,
 * exact dev/ino/uid/mode/size and the required hard-link count). */
function assertExpectedFile(
  info: Deno.FileInfo,
  expected: FileIdentity,
  nlink: number,
  what: string,
): FileIdentity {
  if (!info.isFile || info.isSymlink) {
    throw new Error(`${what} must be a regular file, never a symlink`);
  }
  if (info.nlink !== nlink) {
    throw new Error(`${what} must have exactly ${nlink} hard links`);
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    throw new Error(`${what} must grant only owner access (0600)`);
  }
  if (
    typeof info.dev !== "number" || typeof info.ino !== "number" ||
    typeof info.uid !== "number" || !sameFileState(info, expected)
  ) {
    throw new Error(`${what} identity changed; refusing to touch it`);
  }
  return {
    dev: info.dev,
    ino: info.ino,
    nlink: info.nlink,
    mode: info.mode,
    uid: info.uid,
    size: info.size,
  };
}

/** lstat one expected path and bind it to the retained identity, or fail
 * closed. A missing path is never silently treated as success here. */
async function statExpectedFile(
  path: string,
  expected: FileIdentity,
  nlink: number,
  what: string,
): Promise<FileIdentity> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      throw new Error(`${what} is missing before the guarded mutation`);
    }
    throw error;
  }
  return assertExpectedFile(info, expected, nlink, what);
}

/** Inode/owner/mode binding of one expected path with the required link
 * count; used only to clean up an interrupted temp, never to publish. */
function assertOwnedInode(
  info: Deno.FileInfo,
  expected: FileIdentity,
  nlink: number,
  what: string,
): void {
  if (!info.isFile || info.isSymlink) {
    throw new Error(`${what} must be a regular file, never a symlink`);
  }
  if (info.nlink !== nlink) {
    throw new Error(`${what} must have exactly ${nlink} hard links`);
  }
  if (info.mode === null || (info.mode & 0o777) !== 0o600) {
    throw new Error(`${what} must grant only owner access (0600)`);
  }
  if (!sameOwnedInode(info, expected)) {
    throw new Error(`${what} inode identity changed; refusing to remove it`);
  }
}

async function fsyncDir(path: string, expected: ParentIdentity): Promise<void> {
  let handle: Deno.FsFile;
  try {
    handle = await Deno.open(path, { read: true });
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      throw new Error("Gate parent directory is missing");
    }
    throw error;
  }
  try {
    const before = await handle.stat();
    if (
      !before.isDirectory || before.dev !== expected.dev ||
      before.ino !== expected.ino || before.uid !== expected.uid ||
      before.mode !== expected.mode
    ) {
      throw new Error("Directory sync handle is not the original parent");
    }
    await handle.sync();
    const after = await handle.stat();
    if (
      !after.isDirectory || after.dev !== expected.dev ||
      after.ino !== expected.ino || after.uid !== expected.uid ||
      after.mode !== expected.mode
    ) {
      throw new Error("Directory identity changed after sync");
    }
  } finally {
    handle.close();
  }
}

async function readGateInternal(path: string): Promise<GateRead | undefined> {
  const parent = await resolveParent(path);
  const finalPath = finalPathOf(parent);
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(finalPath);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      // A missing final path is absence only after the ORIGINAL parent is
      // confirmed again; a replaced parent must fail closed, and a gate
      // that appears during the confirmation cannot be ignored.
      const parentAgain = await resolveParent(path);
      assertSameParent(parentAgain, parent, "before absence was confirmed");
      try {
        await Deno.lstat(finalPathOf(parentAgain));
      } catch (recheck) {
        if (recheck instanceof Deno.errors.NotFound) return undefined;
        throw recheck;
      }
      throw new Error("Gate appeared while its absence was being confirmed");
    }
    throw error;
  }
  const file = assertGateFile(info, parent);
  if (file.size > MAX_GATE_BYTES) {
    throw new Error("Gate exceeds the 64 KiB read bound");
  }
  const handle = await Deno.open(finalPath, { read: true });
  let gate: BackupControllerGate | undefined;
  try {
    const opened = assertGateFile(await handle.stat(), parent);
    if (
      opened.dev !== file.dev || opened.ino !== file.ino ||
      opened.size !== file.size
    ) {
      throw new Error("Gate changed between lstat and open");
    }
    const data = new Uint8Array(file.size);
    let offset = 0;
    while (offset < file.size) {
      const read = await handle.read(data.subarray(offset));
      if (read === null || read === 0) break;
      offset += read;
    }
    if (offset !== file.size) {
      throw new Error("Gate changed while it was being read");
    }
    const afterLstat = await Deno.lstat(finalPath);
    const afterOpen = assertGateFile(await handle.stat(), parent);
    const afterParent = await resolveParent(path);
    assertSameParent(afterParent, parent, "before the read was returned");
    if (!sameFileState(afterLstat, file) || !sameFileState(afterOpen, file)) {
      throw new Error("Gate was replaced while it was being read");
    }
    let text = new TextDecoder().decode(data);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error("Gate file is not valid JSON");
    }
    gate = validateGate(parsed);
  } finally {
    handle.close();
  }
  return { gate, parent, file };
}

/** Read-only gate read; a missing file with a confirmed valid parent is null. */
export async function readGate(
  path: string = DEFAULT_GATE_PATH,
): Promise<BackupControllerGate | null> {
  const read = await readGateInternal(path);
  return read ? read.gate : null;
}

function serializeGate(gate: BackupControllerGate): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(gate, null, 2)}\n`);
}

function assertWriteCount(written: number, remaining: number): void {
  if (!Number.isSafeInteger(written) || written <= 0) {
    throw new Error("Gate temp write count is invalid or made no progress");
  }
  if (written > remaining) {
    throw new Error("Gate temp write count exceeds the requested length");
  }
}

/** Create the same-directory temp gate file and retain the ORIGINAL handle
 * identity; fstat and lstat are compared before and after every write and
 * after sync, and a replacement found after close is never trusted. On
 * failure only our own unlinked temp is removed, through the original
 * parent, and drifted paths are preserved. */
async function createTemp(
  path: string,
  parent: ParentIdentity,
  gate: BackupControllerGate,
): Promise<TempFile> {
  const tempPath = `${parent.path}/.${parent.base}.${crypto.randomUUID()}.tmp`;
  const handle = await Deno.open(tempPath, {
    createNew: true,
    write: true,
    mode: 0o600,
  });
  let retained: FileIdentity | undefined;
  try {
    const before = assertGateFile(await handle.stat(), parent);
    retained = before;
    await statExpectedFile(tempPath, before, 1, "Gate temp");
    const bytes = serializeGate(gate);
    let offset = 0;
    while (offset < bytes.length) {
      const written = await handle.write(bytes.subarray(offset));
      assertWriteCount(written, bytes.length - offset);
      offset += written;
    }
    await handle.sync();
    const after = assertGateFile(await handle.stat(), parent);
    if (!sameOwnedInode(after, before) || after.size !== bytes.length) {
      throw new Error("Gate temp identity changed while it was written");
    }
    await statExpectedFile(tempPath, after, 1, "Gate temp");
    retained = after;
  } catch (error) {
    handle.close();
    if (retained) {
      try {
        await removeUnlinkedTemp(
          { path: tempPath, identity: retained },
          path,
          parent,
        );
      } catch {
        // The original failure wins; drifted paths are preserved.
      }
    }
    throw error;
  }
  handle.close();
  return { path: tempPath, identity: retained };
}

/** Remove only our own unlinked temp (one hard link) through the ORIGINAL
 * parent. A replaced parent or a replaced temp is preserved. */
async function removeUnlinkedTemp(
  temp: TempFile,
  path: string,
  parent: ParentIdentity,
): Promise<void> {
  const current = await resolveParent(path);
  assertSameParent(current, parent, "before temp cleanup");
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(temp.path);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return;
    throw error;
  }
  assertOwnedInode(info, temp.identity, 1, "Gate temp");
  await Deno.remove(temp.path);
}

/** Create-new link cleanup: both the temp and the final name must be the
 * original temp inode with two hard links before only the temp name is
 * removed; the final name must then hold the same inode with one hard link.
 * Foreign or replaced paths on either name are preserved. */
async function removeLinkedTemp(
  temp: TempFile,
  path: string,
  parent: ParentIdentity,
): Promise<void> {
  const current = await resolveParent(path);
  assertSameParent(current, parent, "before temp link cleanup");
  const tempInfo = await statExpectedFile(
    temp.path,
    temp.identity,
    2,
    "Gate temp",
  );
  const finalPath = finalPathOf(parent);
  const finalInfo = await statExpectedFile(
    finalPath,
    temp.identity,
    2,
    "Gate final",
  );
  if (!sameInode(tempInfo, finalInfo)) {
    throw new Error("Gate final does not share the published temp inode");
  }
  await Deno.remove(temp.path);
  const after = await statExpectedFile(
    finalPath,
    temp.identity,
    1,
    "Gate final",
  );
  if (!sameInode(after, finalInfo)) {
    throw new Error("Gate final inode changed after the temp link was removed");
  }
}

/** Recheck the ORIGINAL final identity; failure is never absence. */
async function recheckFinal(
  parent: ParentIdentity,
  expected: FileIdentity,
): Promise<FileIdentity> {
  return await statExpectedFile(finalPathOf(parent), expected, 1, "Gate");
}

/** Atomic checked replacement under the caller's shared controller lock. */
async function replaceGate(
  path: string,
  read: GateRead,
  next: BackupControllerGate,
): Promise<void> {
  const parent = await resolveParent(path);
  assertSameParent(parent, read.parent, "before mutation");
  await recheckFinal(parent, read.file);
  const temp = await createTemp(path, parent, next);
  try {
    // Before rename: original parent, existing final identity and own
    // original temp identity are all rechecked.
    const parentBefore = await resolveParent(path);
    assertSameParent(parentBefore, read.parent, "before mutation");
    await recheckFinal(parentBefore, read.file);
    await statExpectedFile(temp.path, temp.identity, 1, "Gate temp");
    await Deno.rename(temp.path, finalPathOf(parentBefore));
  } catch (error) {
    try {
      await removeUnlinkedTemp(temp, path, read.parent);
    } catch (cleanupError) {
      throw new Error(
        `${errorMessage(error)}; cleanup refused (${
          errorMessage(cleanupError)
        })`,
      );
    }
    throw error;
  }
  // After publication the final must be the original temp inode with the
  // required mode, owner and exactly one hard link.
  await statExpectedFile(finalPathOf(parent), temp.identity, 1, "Gate");
  await fsyncDir(parent.path, parent);
}

/**
 * Create a new active gate with an unbound invocation. Any existing path is
 * refused; the file appears only through an atomic create-new link.
 */
export async function writeActiveGate(
  gate: BackupControllerGate,
  path: string = DEFAULT_GATE_PATH,
): Promise<BackupControllerGate> {
  // The validated gate is snapshotted before the first await; caller mutation
  // after the call starts cannot change what is authorized.
  const next = validateGate(gate);
  if (next.state !== "active" || next.unitInvocationId !== null) {
    throw new Error(
      "A new gate must be active with an unbound unit invocation",
    );
  }
  const parent = await resolveParent(path);
  const finalPath = finalPathOf(parent);
  let exists = false;
  try {
    await Deno.lstat(finalPath);
    exists = true;
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  if (exists) throw new Error("Gate already exists; refusing to overwrite");
  const temp = await createTemp(path, parent, next);
  try {
    // Parent, absence and own original temp identity are rechecked
    // immediately before the atomic create-new link.
    const parentAgain = await resolveParent(path);
    assertSameParent(parentAgain, parent, "before mutation");
    let present = false;
    try {
      await Deno.lstat(finalPathOf(parentAgain));
      present = true;
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
    if (present) throw new Error("Gate already exists; refusing to overwrite");
    await statExpectedFile(temp.path, temp.identity, 1, "Gate temp");
    await Deno.link(temp.path, finalPathOf(parentAgain));
  } catch (error) {
    try {
      await removeUnlinkedTemp(temp, path, parent);
    } catch (cleanupError) {
      throw new Error(
        `${errorMessage(error)}; cleanup refused (${
          errorMessage(cleanupError)
        })`,
      );
    }
    throw error;
  }
  await removeLinkedTemp(temp, path, parent);
  await fsyncDir(parent.path, parent);
  return next;
}

/**
 * Bind the exact systemd invocation id. Only a null -> specified bind or a
 * repeated bind to the same id is allowed; immutable identity fields and the
 * deadline are preserved.
 */
export async function bindInvocation(
  expected: BackupControllerGate,
  id: string,
  path: string = DEFAULT_GATE_PATH,
): Promise<BackupControllerGate> {
  const expectedSnapshot = validateGate(expected);
  const invocationId = validateUnitInvocationId(id);
  const read = await readGateInternal(path);
  if (!read) throw new Error("Gate is absent; cannot bind a unit invocation");
  if (!gateIdentityEqual(expectedSnapshot, read.gate)) {
    throw new Error(
      "Gate changed since it was read; re-bind under the shared controller lock",
    );
  }
  if (read.gate.unitInvocationId === invocationId) return read.gate;
  if (read.gate.unitInvocationId !== null) {
    throw new Error(
      "Gate unit invocation is already bound to a different id",
    );
  }
  const next = validateGate({
    ...read.gate,
    unitInvocationId: invocationId,
    updatedAtUtc: new Date().toISOString(),
  });
  await replaceGate(path, read, next);
  return next;
}

/** Mark the exact expected gate orphaned with the fixed reason; identity and
 * immutable fields are preserved. */
export async function markOrphaned(
  expected: BackupControllerGate,
  reason: OrphanReason,
  path: string = DEFAULT_GATE_PATH,
): Promise<BackupControllerGate> {
  if (!(ORPHAN_REASONS as readonly string[]).includes(reason)) {
    throw new Error("Unknown orphan reason");
  }
  const expectedSnapshot = validateGate(expected);
  const read = await readGateInternal(path);
  if (!read) throw new Error("Gate is absent; cannot mark it orphaned");
  if (!gateIdentityEqual(expectedSnapshot, read.gate)) {
    throw new Error(
      "Gate changed since it was read; re-read it under the shared controller lock",
    );
  }
  if (read.gate.state === "orphaned") {
    if (read.gate.orphanReason === reason) return read.gate;
    throw new Error("Gate is already orphaned for a different reason");
  }
  const next = validateGate({
    ...read.gate,
    state: "orphaned",
    orphanReason: reason,
    updatedAtUtc: new Date().toISOString(),
  });
  await replaceGate(path, read, next);
  return next;
}

/**
 * Clear the exact expected gate only after a strict, fresh terminal proof
 * against the re-read gate. The proof is process-overlap proof only: it
 * never accepts or prunes a restore point, and PENDING_VERIFIER may clear
 * because the worker process is gone. Returns the gate that was cleared.
 */
export async function clearGateAfterProof(
  expected: BackupControllerGate,
  proof: unknown,
  path: string = DEFAULT_GATE_PATH,
  now: Date = new Date(),
): Promise<BackupControllerGate> {
  // The expected gate, proof and comparison time are all snapshotted before
  // the first await; caller mutation cannot change authorization while the
  // gate is being re-read.
  const expectedSnapshot = validateGate(expected);
  const proofSnapshot = structuredClone(proof);
  const nowSnapshot = now.getTime();
  const read = await readGateInternal(path);
  if (!read) throw new Error("Gate is absent; nothing to clear");
  if (!gateIdentityEqual(expectedSnapshot, read.gate)) {
    throw new Error(
      "Gate changed since it was read; re-read it under the shared controller lock",
    );
  }
  void validateGateClearProof(proofSnapshot, read.gate, new Date(nowSnapshot));
  const parent = await resolveParent(path);
  assertSameParent(parent, read.parent, "before mutation");
  await recheckFinal(parent, read.file);
  await Deno.remove(finalPathOf(parent));
  await fsyncDir(parent.path, parent);
  return read.gate;
}
