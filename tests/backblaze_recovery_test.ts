/**
 * Focused m05-recovery tests: synthetic data in unique temporary
 * directories and an in-memory fake B2 store only. Nothing reaches the
 * network, no credential is read, no source capture/upload stage file is
 * needed or touched, and the production `/var/tmp/arch-vps-file-backup`
 * path is never accessed. Runtime cases (real fixtures and filesystem
 * guards) need read and write permissions and are explicitly ignored in the
 * default permissionless mode; the same cases must run with zero skips
 * under `deno test --allow-read --allow-write`. Short/zero/bad write return
 * values are exercised through test-local scoped instrumentation of
 * `Deno.FsFile.prototype.write` (and `Deno.open` for one swap case), each
 * restored in `finally`; no runtime seam or configuration surface is used.
 * A failed case deliberately leaves its task-owned partial in its unique
 * temporary directory for explicit diagnosis; cleanup is best-effort and
 * never touches files it did not create.
 */
import { createHash } from "node:crypto";
import { relative } from "node:path";

import type { B2Object } from "../scripts/backblaze-storage.ts";
import { MAX_CHUNK_BYTES } from "../scripts/backblaze-storage.ts";
import {
  type IndexArchiveRecord,
  type IndexChunk,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "../scripts/backblaze-index.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
  type UploadFormat,
  type UploadRole,
} from "../scripts/backblaze-upload.ts";
import {
  type ReconstructedGeneration,
  reconstructGeneration,
  streamRecoveryArchive,
} from "../scripts/backblaze-recovery.ts";

function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) throw new Error(message ?? "Assertion failed");
}

async function rejectWith(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("expected an Error");
  }
  throw new Error("expected a rejection");
}

function assertBytes(actual: Uint8Array, expected: Uint8Array): void {
  assert(actual.byteLength === expected.byteLength, "byte length mismatch");
  for (let i = 0; i < expected.byteLength; i += 1) {
    assert(actual[i] === expected[i], `byte ${i} mismatch`);
  }
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

/** Deterministic content without a large generator state. */
function filler(seed: number, length: number): Uint8Array {
  const base = new Uint8Array(65536);
  let state = (seed * 2654435761) >>> 0;
  for (let i = 0; i < base.length; i += 1) {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ (state << 5)) >>> 0;
    base[i] = state & 0xff;
  }
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += base.length) {
    out.set(base.subarray(0, Math.min(base.length, length - offset)), offset);
  }
  return out;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function formatFor(role: UploadRole): UploadFormat {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

const GENERATION = "generation-11111111-2222-3333-4444-555555555555";
const RECIPIENT_FINGERPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD";
const RECIPIENT_SHA256 = "ab".repeat(32);

interface IndexFixture {
  /** Canonical validated index (the shape the validator produces). */
  index: RecoveryIndex;
  /** Exact chunk bytes per role, in validated chunk order. */
  chunkBytes: Map<UploadRole, Uint8Array[]>;
}

/** Synthetic seven-archive index built from real bytes, then re-validated so
 * the fixture is exactly the canonical validated shape. */
function makeIndexFixture(
  options: { multiChunkRoot?: boolean } = {},
): IndexFixture {
  const chunkBytes = new Map<UploadRole, Uint8Array[]>();
  const archives: IndexArchiveRecord[] = UPLOAD_ROLE_ORDER.map(
    (role, roleIndex) => {
      const format = formatFor(role);
      const chunkCount = role === "root" && options.multiChunkRoot === true
        ? 2
        : 1;
      const roleChunks: Uint8Array[] = [];
      const chunks: IndexChunk[] = [];
      let total = 0;
      for (let i = 0; i < chunkCount; i += 1) {
        const size = chunkCount > 1
          ? i === chunkCount - 1 ? 123 : MAX_CHUNK_BYTES
          : 4096 + roleIndex * 137;
        const bytes = filler(1000 + roleIndex * 11 + i, size);
        roleChunks.push(bytes);
        total += size;
        chunks.push({
          index: i,
          name: generationChunkName(GENERATION, role, i),
          size,
          sha256: sha256Hex(bytes),
          sha1: sha1Hex(bytes),
          fileId: `file-${GENERATION}-${role}-${i}`,
          uploadTimestamp: 1_900_000_000_000 + roleIndex * 100 + i,
        });
      }
      chunkBytes.set(role, roleChunks);
      const hasher = createHash("sha256");
      for (const bytes of roleChunks) hasher.update(bytes);
      return {
        role,
        format,
        bytes: total,
        sha256: hasher.digest("hex"),
        chunks,
      };
    },
  );
  const candidate: RecoveryIndex = {
    schemaVersion: 1,
    generation: GENERATION,
    captureStartedAtUtc: "2026-09-06T01:00:00.000Z",
    captureFinishedAtUtc: "2026-09-06T01:01:00.000Z",
    uploadStartedAtUtc: "2026-09-06T01:01:00.000Z",
    uploadFinishedAtUtc: "2026-09-06T01:02:00.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    recipientSha256: RECIPIENT_SHA256,
    archives,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  return { index: validateRecoveryIndex(candidate), chunkBytes };
}

/** Deep copy helper for malformed-index cases. */
function cloneIndex(index: RecoveryIndex): RecoveryIndex {
  return JSON.parse(JSON.stringify(index)) as RecoveryIndex;
}

function expectedArchiveNames(index: RecoveryIndex): Set<string> {
  return new Set(
    index.archives.map((archive) => `${archive.role}.${archive.format}`),
  );
}

function expectedGetObjects(index: RecoveryIndex): B2Object[] {
  const calls: B2Object[] = [];
  for (const archive of index.archives) {
    for (const chunk of archive.chunks) {
      calls.push({
        fileId: chunk.fileId,
        fileName: chunk.name,
        contentLength: chunk.size,
        contentSha1: chunk.sha1,
        action: "upload",
        uploadTimestamp: chunk.uploadTimestamp,
      });
    }
  }
  return calls;
}

interface FakeStoreOptions {
  /**
   * Optional per-get hook that may run arbitrary test-local filesystem
   * actions (for example replacing a file between checks); returning
   * undefined falls through to the seeded bytes.
   */
  handler?: (
    object: B2Object,
  ) => Uint8Array | undefined | Promise<Uint8Array | undefined>;
  /** When false the store skips its own length/SHA-1 verification so the
   * module-level checks are what must reject corrupt/truncated bytes. */
  verifyHeaders?: boolean;
}

/** Exact-version download fake: records every get argument, returns the
 * registered version bytes and verifies length/SHA-1 exactly like the real
 * store when `verifyHeaders` is true; `get` is the only operation provided,
 * so a put/versions/remove call cannot even compile. */
class FakeGetStore {
  getCalls: B2Object[] = [];
  private readonly byId = new Map<string, Uint8Array>();
  private readonly handler:
    | ((
      object: B2Object,
    ) => Uint8Array | undefined | Promise<Uint8Array | undefined>)
    | null;
  private readonly verifyHeaders: boolean;

  constructor(options: FakeStoreOptions = {}) {
    this.handler = options.handler ?? null;
    this.verifyHeaders = options.verifyHeaders ?? true;
  }

  seed(fileId: string, bytes: Uint8Array): void {
    this.byId.set(fileId, bytes);
  }

  async get(object: B2Object): Promise<Uint8Array> {
    this.getCalls.push({ ...object });
    const found = this.handler ? await this.handler(object) : undefined;
    const bytes = found ?? this.byId.get(object.fileId);
    if (bytes === undefined) {
      return Promise.reject(new Error("get failed (HTTP 404)"));
    }
    if (this.verifyHeaders) {
      if (bytes.byteLength !== object.contentLength) {
        return Promise.reject(
          new Error("get failed: content length mismatch"),
        );
      }
      if (sha1Hex(bytes) !== object.contentSha1) {
        return Promise.reject(new Error("get failed: content sha1 mismatch"));
      }
    }
    return Promise.resolve(new Uint8Array(bytes));
  }
}

/** Test-local scoped override of Deno.FsFile.prototype.write, restored in
 * `finally`: `returns` receives the requested byte count and returns the
 * count the write should claim; positive safe counts within the request
 * really write that many bytes so the module's loop is exercised end to
 * end, every other return value is passed through untouched. */
async function withWriteReturns(
  returns: (requested: number) => number,
  fn: () => Promise<void>,
): Promise<void> {
  const originalWrite = Deno.FsFile.prototype.write;
  try {
    Deno.FsFile.prototype.write = function (
      this: Deno.FsFile,
      p: Uint8Array,
    ): Promise<number> {
      const result = returns(p.byteLength);
      if (result > 0 && result <= p.byteLength) {
        return originalWrite.call(this, p.subarray(0, result));
      }
      return Promise.resolve(result);
    };
    await fn();
  } finally {
    Deno.FsFile.prototype.write = originalWrite;
  }
}

/** Query-only permission probe: the default `deno test` task carries no
 * permissions, so runtime cases must skip there and only execute under the
 * explicit --allow-read/--allow-write invocation. */
async function runtimePermissionsGranted(): Promise<boolean> {
  const descriptors: Deno.PermissionDescriptor[] = [
    { name: "read" },
    { name: "write" },
  ];
  for (const descriptor of descriptors) {
    try {
      if ((await Deno.permissions.query(descriptor)).state !== "granted") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

const runtimePermitted = await runtimePermissionsGranted();

function runtimeTest(
  name: string,
  fn: (context: Deno.TestContext) => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

/** Unique canonical temporary directory (0700 unless a guard case lowers
 * it); macOS /var is canonicalized by the same realPath identity the module
 * requires. */
async function makeCanonicalDir(
  prefix: string,
  mode = 0o700,
): Promise<string> {
  const raw = await Deno.makeTempDir({ prefix });
  const dir = await Deno.realPath(raw);
  await Deno.chmod(dir, mode);
  return dir;
}

async function removeBestEffort(path: string): Promise<void> {
  try {
    await Deno.remove(path, { recursive: true });
  } catch {
    // Best effort only; never touch anything outside the case directory.
  }
}

async function writePrivate(
  path: string,
  bytes: Uint8Array | string,
  mode = 0o600,
): Promise<void> {
  const content = typeof bytes === "string"
    ? new TextEncoder().encode(bytes)
    : bytes;
  await Deno.writeFile(path, content);
  await Deno.chmod(path, mode);
}

async function modeOf(path: string): Promise<number> {
  const info = await Deno.lstat(path);
  return (info.mode ?? 0) & 0o777;
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

async function listNames(path: string): Promise<string[]> {
  const names: string[] = [];
  for await (const entry of Deno.readDir(path)) names.push(entry.name);
  return names.sort();
}

// ---------------------------------------------------------------------------
// Pure cases: run without any permission; the index validator must reject
// invalid selected identities before any filesystem or store action.
// ---------------------------------------------------------------------------

Deno.test("invalid selected ids, names and order are rejected through the validator before any I/O", async () => {
  const fixture = makeIndexFixture({ multiChunkRoot: true });
  const store = new FakeGetStore();
  const nonexistent = "/definitely/not/a/real/recovery/directory-m05";

  const wrongName = cloneIndex(fixture.index);
  wrongName.archives[2].chunks[0].name = "not-the-selected-name";

  const swappedOrder = cloneIndex(fixture.index);
  const first = swappedOrder.archives[0].chunks[0];
  const second = swappedOrder.archives[0].chunks[1];
  const swappedFirst = { ...first, index: second.index, name: second.name };
  const swappedSecond = { ...second, index: first.index, name: first.name };
  swappedOrder.archives[0].chunks = [swappedFirst, swappedSecond];

  const duplicateId = cloneIndex(fixture.index);
  duplicateId.archives[1].chunks[0].fileId =
    duplicateId.archives[0].chunks[0].fileId;

  const emptyId = cloneIndex(fixture.index);
  emptyId.archives[3].chunks[0].fileId = "";

  const wrongFormat = cloneIndex(fixture.index);
  wrongFormat.archives[0].format = "json.zst.gpg";

  const cases: [string, RecoveryIndex, string][] = [
    ["wrong selected name", wrongName, "Index failed (index:chunk)"],
    ["swapped chunk order", swappedOrder, "Index failed (index:chunks)"],
    [
      "duplicate selected file id",
      duplicateId,
      "Index failed (index:fileid-duplicate)",
    ],
    ["empty selected file id", emptyId, "Index failed (index:chunk)"],
    ["wrong role/format pairing", wrongFormat, "Index failed (index:format)"],
  ];
  for (const [label, malformed, expected] of cases) {
    const error = await rejectWith(
      reconstructGeneration(malformed, store, nonexistent),
    );
    assert(error.message === expected, `${label}: ${error.message}`);
  }
  assert(store.getCalls.length === 0, "no chunk may be fetched");
});

// ---------------------------------------------------------------------------
// Runtime cases: real filesystem fixtures and identity guards.
// ---------------------------------------------------------------------------

runtimeTest(
  "reconstructs all seven archives in order with exact get arguments and only expected outputs",
  async () => {
    const fixture = makeIndexFixture({ multiChunkRoot: true });
    const dir = await makeCanonicalDir("m05-full-");
    const store = new FakeGetStore();
    for (const archive of fixture.index.archives) {
      const roleBytes = fixture.chunkBytes.get(archive.role)!;
      for (let i = 0; i < archive.chunks.length; i += 1) {
        store.seed(archive.chunks[i].fileId, roleBytes[i]);
      }
    }
    try {
      const result: ReconstructedGeneration = await reconstructGeneration(
        fixture.index,
        store,
        dir,
      );
      assert(result.generation === GENERATION);
      assert(
        result.indexSha256 ===
          sha256Hex(new TextEncoder().encode(JSON.stringify(fixture.index))),
        "index sha256",
      );
      assert(result.recipientFingerprint === RECIPIENT_FINGERPRINT);
      assert(result.recipientSha256 === RECIPIENT_SHA256);
      assert(result.recoveryDirectory === dir);
      assert(result.archives.length === 7);
      assert(result.ciphertextReconstructed === true);
      assert(result.decryptedRestoreProved === false);
      assert(result.machineBootRestoreProved === false);
      // Only the seven finals exist; no partials or receipts.
      assert(
        JSON.stringify(await listNames(dir)) ===
          JSON.stringify([...expectedArchiveNames(fixture.index)].sort()),
        "directory output entries",
      );
      for (let i = 0; i < result.archives.length; i += 1) {
        const archive = fixture.index.archives[i];
        const reconstructed = result.archives[i];
        assert(reconstructed.role === archive.role);
        assert(reconstructed.format === archive.format);
        assert(
          reconstructed.path === `${dir}/${archive.role}.${archive.format}`,
        );
        assert(reconstructed.bytes === archive.bytes);
        assert(reconstructed.sha256 === archive.sha256);
        assert(reconstructed.chunks.length === archive.chunks.length);
        for (let j = 0; j < archive.chunks.length; j += 1) {
          const chunk = archive.chunks[j];
          const copied = reconstructed.chunks[j];
          assert(copied.index === chunk.index);
          assert(copied.name === chunk.name);
          assert(copied.size === chunk.size);
          assert(copied.sha256 === chunk.sha256);
          assert(copied.sha1 === chunk.sha1);
          assert(copied.fileId === chunk.fileId);
          assert(copied.uploadTimestamp === chunk.uploadTimestamp);
        }
        // Final file: regular 0600, one hardlink, owned by the directory.
        const info = await Deno.lstat(reconstructed.path);
        assert(info.isFile && !info.isSymlink, "final is a regular file");
        assert(((info.mode ?? 0) & 0o777) === 0o600, "final mode 0600");
        assert(info.nlink === 1, "final nlink 1");
        assert(info.uid === (await Deno.lstat(dir)).uid, "final owner");
        assert(
          (await Deno.realPath(reconstructed.path)) === reconstructed.path,
          "final canonical path",
        );
        const onDisk = await Deno.readFile(reconstructed.path);
        assertBytes(
          onDisk,
          concatBytes(fixture.chunkBytes.get(archive.role)!),
        );
      }
      // Exact ordered get arguments in index chunk order.
      const expectedCalls = expectedGetObjects(fixture.index);
      assert(store.getCalls.length === expectedCalls.length);
      for (let i = 0; i < expectedCalls.length; i += 1) {
        const call = store.getCalls[i];
        const expectedObject = expectedCalls[i];
        assert(call.fileId === expectedObject.fileId, `get ${i} fileId`);
        assert(call.fileName === expectedObject.fileName, `get ${i} fileName`);
        assert(
          call.contentLength === expectedObject.contentLength,
          `get ${i} contentLength`,
        );
        assert(
          call.contentSha1 === expectedObject.contentSha1,
          `get ${i} sha1`,
        );
        assert(call.action === "upload", `get ${i} action`);
        assert(
          call.uploadTimestamp === expectedObject.uploadTimestamp,
          `get ${i} uploadTimestamp`,
        );
      }
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a corrupt chunk is rejected before any write and the partial is left for diagnosis",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-corrupt-");
    const targetId = fixture.index.archives[1].chunks[0].fileId;
    const store = new FakeGetStore({
      verifyHeaders: false,
      handler: (object) => {
        if (object.fileId !== targetId) return undefined;
        const original = fixture.chunkBytes.get("efi")![0];
        const corrupted = new Uint8Array(original);
        corrupted[0] = corrupted[0] ^ 0xff;
        return corrupted;
      },
    });
    for (const archive of fixture.index.archives) {
      const roleBytes = fixture.chunkBytes.get(archive.role)!;
      for (let i = 0; i < archive.chunks.length; i += 1) {
        store.seed(archive.chunks[i].fileId, roleBytes[i]);
      }
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(error.message === "Recovery failed (get:sha256)", error.message);
      assert(
        await fileExists(`${dir}/efi.tar.zst.gpg.partial`),
        "partial left",
      );
      assert(!(await fileExists(`${dir}/efi.tar.zst.gpg`)), "no efi final");
      const names = await listNames(dir);
      assert(
        JSON.stringify(names) ===
          JSON.stringify(["efi.tar.zst.gpg.partial", "root.tar.zst.gpg"]),
        "earlier root final plus the diagnosis partial remain",
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a truncated chunk is rejected by the module check and leaves the partial",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-trunc-");
    const targetId = fixture.index.archives[1].chunks[0].fileId;
    const store = new FakeGetStore({
      verifyHeaders: false,
      handler: (object) => {
        if (object.fileId !== targetId) return undefined;
        const original = fixture.chunkBytes.get("efi")![0];
        return original.subarray(0, original.byteLength - 5);
      },
    });
    for (const archive of fixture.index.archives) {
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(error.message === "Recovery failed (get:length)", error.message);
      assert(
        await fileExists(`${dir}/efi.tar.zst.gpg.partial`),
        "partial left",
      );
      assert(!(await fileExists(`${dir}/efi.tar.zst.gpg`)), "no efi final");
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a wrong full archive hash is rejected after the full write and never published",
  async () => {
    const fixture = makeIndexFixture({ multiChunkRoot: true });
    const dir = await makeCanonicalDir("m05-archhash-");
    const store = new FakeGetStore();
    for (const archive of fixture.index.archives) {
      const roleBytes = fixture.chunkBytes.get(archive.role)!;
      for (let i = 0; i < archive.chunks.length; i += 1) {
        store.seed(archive.chunks[i].fileId, roleBytes[i]);
      }
    }
    const wrongArchiveHash = cloneIndex(fixture.index);
    wrongArchiveHash.archives[0].sha256 = "ab".repeat(32);
    try {
      const error = await rejectWith(
        reconstructGeneration(wrongArchiveHash, store, dir),
      );
      assert(error.message === "Recovery failed (archive:hash)", error.message);
      assert(
        await fileExists(`${dir}/root.tar.zst.gpg.partial`),
        "partial left after hash mismatch",
      );
      assert(!(await fileExists(`${dir}/root.tar.zst.gpg`)), "no final");
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "completed same-name finals are reused only after streamed verification and their gets are skipped",
  async () => {
    const fixture = makeIndexFixture({ multiChunkRoot: true });
    const dir = await makeCanonicalDir("m05-reuse-");
    const store = new FakeGetStore();
    for (const archive of fixture.index.archives) {
      if (archive.role === "root" || archive.role === "efi") continue;
      const roleBytes = fixture.chunkBytes.get(archive.role)!;
      for (let i = 0; i < archive.chunks.length; i += 1) {
        store.seed(archive.chunks[i].fileId, roleBytes[i]);
      }
    }
    // Pre-create valid root/efi finals; their fileIds are NOT in the store, so
    // any get would fail: reuse must be local verification only.
    for (const role of ["root", "efi"] as const) {
      const name = `${role}.tar.zst.gpg`;
      await writePrivate(
        `${dir}/${name}`,
        concatBytes(fixture.chunkBytes.get(role)!),
      );
    }
    try {
      const result = await reconstructGeneration(fixture.index, store, dir);
      assert(result.archives.length === 7);
      const expected = expectedGetObjects(fixture.index)
        .filter((object) =>
          !object.fileName.endsWith("/root/00000000") &&
          !object.fileName.endsWith("/root/00000001") &&
          !object.fileName.endsWith("/efi/00000000")
        );
      assert(
        store.getCalls.length === expected.length,
        "only missing roles are fetched",
      );
      for (let i = 0; i < expected.length; i += 1) {
        assert(store.getCalls[i].fileId === expected[i].fileId, `get ${i}`);
      }
      // Reused finals are byte-identical and still one-link 0600 files.
      for (const role of ["root", "efi"] as const) {
        const name = `${role}.tar.zst.gpg`;
        assertBytes(
          await Deno.readFile(`${dir}/${name}`),
          concatBytes(fixture.chunkBytes.get(role)!),
        );
        const info = await Deno.lstat(`${dir}/${name}`);
        assert(info.nlink === 1 && ((info.mode ?? 0) & 0o777) === 0o600);
      }
      assert(
        JSON.stringify(await listNames(dir)) ===
          JSON.stringify([...expectedArchiveNames(fixture.index)].sort()),
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a conflicting same-name final fails before any fetch and is left untouched",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-conflict-");
    const store = new FakeGetStore();
    const wrongBytes = filler(42, 999);
    await writePrivate(`${dir}/root.tar.zst.gpg`, wrongBytes);
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(
        error.message === "Recovery failed (final:conflict)",
        error.message,
      );
      assert(store.getCalls.length === 0, "no fetch before conflict failure");
      assertBytes(await Deno.readFile(`${dir}/root.tar.zst.gpg`), wrongBytes);
      assert(
        JSON.stringify(await listNames(dir)) ===
          JSON.stringify(["root.tar.zst.gpg"]),
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "an abandoned partial fails clearly and is never removed or reused",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-partial-");
    const store = new FakeGetStore();
    const leftovers = filler(7, 4096);
    await writePrivate(`${dir}/root.tar.zst.gpg.partial`, leftovers);
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(error.message === "Recovery failed (partial)", error.message);
      assert(store.getCalls.length === 0, "no fetch before partial failure");
      assertBytes(
        await Deno.readFile(`${dir}/root.tar.zst.gpg.partial`),
        leftovers,
      );
      assert(
        JSON.stringify(await listNames(dir)) ===
          JSON.stringify(["root.tar.zst.gpg.partial"]),
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest("unknown directory entries fail before any fetch", async () => {
  const fixture = makeIndexFixture();
  const dir = await makeCanonicalDir("m05-entries-");
  const store = new FakeGetStore();
  await writePrivate(`${dir}/notes.txt`, "not an archive");
  await writePrivate(`${dir}/.hidden`, "hidden");
  try {
    const error = await rejectWith(
      reconstructGeneration(fixture.index, store, dir),
    );
    assert(error.message === "Recovery failed (entry)", error.message);
    assert(store.getCalls.length === 0, "no fetch before entry failure");
    assert(
      JSON.stringify(await listNames(dir)) ===
        JSON.stringify([".hidden", "notes.txt"]),
    );
  } finally {
    await removeBestEffort(dir);
  }
});

runtimeTest(
  "relative, noncanonical and symlinked directories are rejected",
  async () => {
    const fixture = makeIndexFixture();
    const store = new FakeGetStore();
    // Relative path: rejected as not absolute before any other check.
    const relativeDir = await makeCanonicalDir("m05-relative-");
    const rel = relative(Deno.cwd(), relativeDir);
    try {
      const relError = await rejectWith(
        reconstructGeneration(fixture.index, store, rel),
      );
      assert(
        relError.message === "Recovery failed (directory:absolute)",
        relError.message,
      );
      assert(store.getCalls.length === 0);
    } finally {
      await removeBestEffort(relativeDir);
    }
    // Noncanonical spellings of a real canonical directory.
    const canonical = await makeCanonicalDir("m05-noncanon-");
    await Deno.mkdir(`${canonical}/sub`);
    try {
      for (const spelling of [`${canonical}/.`, `${canonical}/sub/..`]) {
        const error = await rejectWith(
          reconstructGeneration(fixture.index, store, spelling),
        );
        assert(
          error.message === "Recovery failed (directory:realpath)",
          `${spelling}: ${error.message}`,
        );
      }
      assert(store.getCalls.length === 0);
    } finally {
      await removeBestEffort(canonical);
    }
    // Symlinked directory: even pointing at a valid target.
    const target = await makeCanonicalDir("m05-symdir-target-");
    const link = `${target}-link`;
    await Deno.symlink(target, link);
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, link),
      );
      assert(
        error.message === "Recovery failed (directory:not-directory)",
        error.message,
      );
      assert(store.getCalls.length === 0);
      assert((await Deno.lstat(link)).isSymlink, "symlink left in place");
    } finally {
      await Deno.remove(link);
      await removeBestEffort(target);
    }
  },
);

runtimeTest("a non-0700 directory fails without being chmodded", async () => {
  const fixture = makeIndexFixture();
  const store = new FakeGetStore();
  const dir = await makeCanonicalDir("m05-mode-", 0o755);
  try {
    assert((await modeOf(dir)) === 0o755);
    const error = await rejectWith(
      reconstructGeneration(fixture.index, store, dir),
    );
    assert(
      error.message === "Recovery failed (directory:permissions)",
      error.message,
    );
    assert((await modeOf(dir)) === 0o755, "mode must not be changed");
    assert(store.getCalls.length === 0, "no fetch");
  } finally {
    await removeBestEffort(dir);
  }
});

runtimeTest(
  "symlinked, hardlinked and non-0600 finals are rejected without modification",
  async () => {
    const fixture = makeIndexFixture();
    const store = new FakeGetStore();

    // Symlink named as a final.
    const symlinkBase = await makeCanonicalDir("m05-finalsymlink-");
    const symlinkDir = `${symlinkBase}/out`;
    await Deno.mkdir(symlinkDir, { mode: 0o700 });
    await writePrivate(`${symlinkBase}/data`, filler(1, 64));
    await Deno.symlink(`${symlinkBase}/data`, `${symlinkDir}/root.tar.zst.gpg`);
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, symlinkDir),
      );
      assert(
        error.message === "Recovery failed (final:identity)",
        error.message,
      );
      assert((await Deno.lstat(`${symlinkDir}/root.tar.zst.gpg`)).isSymlink);
      assert(store.getCalls.length === 0);
    } finally {
      await removeBestEffort(symlinkBase);
    }

    // Hardlink with two links.
    const hardBase = await makeCanonicalDir("m05-finalhardlink-");
    const hardDir = `${hardBase}/out`;
    await Deno.mkdir(hardDir, { mode: 0o700 });
    await writePrivate(`${hardBase}/data`, filler(2, 64));
    await Deno.link(`${hardBase}/data`, `${hardDir}/root.tar.zst.gpg`);
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, hardDir),
      );
      assert(
        error.message === "Recovery failed (final:hardlink)",
        error.message,
      );
      assert((await Deno.lstat(`${hardDir}/root.tar.zst.gpg`)).nlink === 2);
      assert(store.getCalls.length === 0);
    } finally {
      await removeBestEffort(hardBase);
    }

    // Existing final with group/other permissions.
    const modeBase = await makeCanonicalDir("m05-finalmode-");
    const modeDir = `${modeBase}/out`;
    await Deno.mkdir(modeDir, { mode: 0o700 });
    await writePrivate(`${modeDir}/root.tar.zst.gpg`, filler(3, 64), 0o644);
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, modeDir),
      );
      assert(
        error.message === "Recovery failed (final:permissions)",
        error.message,
      );
      assert((await modeOf(`${modeDir}/root.tar.zst.gpg`)) === 0o644);
      assert(store.getCalls.length === 0);
    } finally {
      await removeBestEffort(modeBase);
    }
  },
);

runtimeTest(
  "reconstruction is independent of source stage files and writes nothing outside the recovery directory",
  async () => {
    const fixture = makeIndexFixture();
    const base = await makeCanonicalDir("m05-indep-");
    const out = `${base}/recovery`;
    const stage = `${base}/stage`;
    await Deno.mkdir(out, { mode: 0o700 });
    await Deno.mkdir(stage, { mode: 0o700 });
    // Decoy source-stage files: identical names but different bytes, plus
    // capture/upload artifacts the module must never read or write.
    const decoyRoot = filler(9, 4096);
    await writePrivate(`${stage}/root.tar.zst.gpg`, decoyRoot);
    await writePrivate(`${stage}/capture-result.json`, "{not-real}");
    await writePrivate(`${stage}/upload-journal.json`, "{not-real}");
    const store = new FakeGetStore();
    for (const archive of fixture.index.archives) {
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      await reconstructGeneration(fixture.index, store, out);
      assert(
        JSON.stringify(await listNames(out)) ===
          JSON.stringify([...expectedArchiveNames(fixture.index)].sort()),
      );
      assertBytes(await Deno.readFile(`${stage}/root.tar.zst.gpg`), decoyRoot);
      assert(
        JSON.stringify(await listNames(stage)) ===
          JSON.stringify([
            "capture-result.json",
            "root.tar.zst.gpg",
            "upload-journal.json",
          ]),
      );
    } finally {
      await removeBestEffort(base);
    }
  },
);

// ---------------------------------------------------------------------------
// Regression cases: detectable drift defense and real write-return values
// exercised through test-local scoped Deno instrumentation.
// ---------------------------------------------------------------------------

runtimeTest(
  "actual short write returns reconstruct the exact final bytes through the real write loop",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-shortwrite-");
    const store = new FakeGetStore();
    for (const archive of fixture.index.archives) {
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    const originalWrite = Deno.FsFile.prototype.write;
    const writeCalls: number[] = [];
    try {
      Deno.FsFile.prototype.write = async function (
        this: Deno.FsFile,
        p: Uint8Array,
      ): Promise<number> {
        const limit = Math.min(7, p.byteLength);
        const written = await originalWrite.call(this, p.subarray(0, limit));
        writeCalls.push(written);
        return written;
      };
      const result = await reconstructGeneration(fixture.index, store, dir);
      assert(result.archives.length === 7, "short writes reconstruct all");
      for (const archive of fixture.index.archives) {
        const name = `${archive.role}.${archive.format}`;
        const info = await Deno.lstat(`${dir}/${name}`);
        assert(
          info.nlink === 1 && ((info.mode ?? 0) & 0o777) === 0o600,
          `${name} final identity`,
        );
        assertBytes(
          await Deno.readFile(`${dir}/${name}`),
          concatBytes(fixture.chunkBytes.get(archive.role)!),
        );
      }
      assert(writeCalls.length > 7, "every chunk needed multiple writes");
      assert(
        writeCalls.every((n) => n > 0 && n <= 7),
        "only real short returns were observed",
      );
    } finally {
      Deno.FsFile.prototype.write = originalWrite;
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "zero, negative, non-finite and oversized write returns fail visibly and preserve the partial",
  async () => {
    const cases: [string, (requested: number) => number, string][] = [
      ["zero", () => 0, "write:progress"],
      ["negative", () => -3, "write:progress"],
      ["nan", () => Number.NaN, "write:count"],
      ["infinity", () => Number.POSITIVE_INFINITY, "write:count"],
      ["oversized", (requested) => requested + 5, "write:count"],
    ];
    for (const [label, returns, expected] of cases) {
      const fixture = makeIndexFixture();
      const dir = await makeCanonicalDir("m05-badwrite-");
      const store = new FakeGetStore();
      for (const archive of fixture.index.archives) {
        store.seed(
          archive.chunks[0].fileId,
          fixture.chunkBytes.get(archive.role)![0],
        );
      }
      try {
        await withWriteReturns(returns, async () => {
          const error = await rejectWith(
            reconstructGeneration(fixture.index, store, dir),
          );
          assert(
            error.message === `Recovery failed (${expected})`,
            `${label}: ${error.message}`,
          );
          assert(
            await fileExists(`${dir}/root.tar.zst.gpg.partial`),
            `${label}: partial preserved`,
          );
          assert(
            !(await fileExists(`${dir}/root.tar.zst.gpg`)),
            `${label}: no final published`,
          );
        });
      } finally {
        await removeBestEffort(dir);
      }
    }
  },
);

runtimeTest(
  "a same-owner/mode replacement directory during a fetch is rejected and nothing is written into it",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-swapdir-");
    const originalDir = `${dir}-swapped`;
    const store = new FakeGetStore({
      handler: async () => {
        await Deno.rename(dir, originalDir);
        await Deno.mkdir(dir, { mode: 0o700 });
        await Deno.chmod(dir, 0o700);
        return undefined;
      },
    });
    for (const archive of fixture.index.archives) {
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(
        error.message === "Recovery failed (directory:identity)",
        error.message,
      );
      assert(store.getCalls.length === 1, "one chunk fetched before replay");
      // Replacement has the same owner/mode but a different dev/inode: no
      // path may be created, chmodded or published inside it.
      const replacedInfo = await Deno.lstat(dir);
      const originalInfo = await Deno.lstat(originalDir);
      assert(
        replacedInfo.uid === originalInfo.uid &&
          replacedInfo.mode === originalInfo.mode,
        "same owner and mode",
      );
      assert(
        replacedInfo.dev !== originalInfo.dev ||
          replacedInfo.ino !== originalInfo.ino,
        "different device or inode",
      );
      assert(
        JSON.stringify(await listNames(dir)) === "[]",
        "replacement directory untouched",
      );
      assert((await modeOf(dir)) === 0o700, "replacement mode untouched");
      // The abandoned partial stays in the original directory.
      assert(
        await fileExists(`${originalDir}/root.tar.zst.gpg.partial`),
        "partial left in the original directory",
      );
      assert(
        !(await fileExists(`${originalDir}/root.tar.zst.gpg`)),
        "no final in the original directory",
      );
    } finally {
      await removeBestEffort(dir);
      await removeBestEffort(originalDir);
    }
  },
);

runtimeTest(
  "a replaced partial is preserved: no chmod, link or removal touches the replacement",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-swappartial-");
    const partialPath = `${dir}/root.tar.zst.gpg.partial`;
    const replacement = filler(21, 3333);
    const store = new FakeGetStore({
      handler: async () => {
        // Replace the task-owned partial while the module still holds the
        // original open handle: a different inode with a wider mode.
        await Deno.remove(partialPath);
        await writePrivate(partialPath, replacement, 0o644);
        return undefined;
      },
    });
    for (const archive of fixture.index.archives) {
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      // The open handle is still the original partial inode but it was
      // unlinked (the path now addresses a different inode), so the handle
      // identity check fails before any pathname is touched at all.
      assert(
        error.message === "Recovery failed (partial:hardlink)",
        error.message,
      );
      assert(store.getCalls.length === 1, "no fetch after the replacement");
      // The replacement path is preserved byte-exact with its own mode:
      // the module may not chmod another path to make it acceptable, and
      // may not link or remove it.
      assertBytes(await Deno.readFile(partialPath), replacement);
      assert(
        (await modeOf(partialPath)) === 0o644,
        "replacement mode preserved: no chmod occurred",
      );
      assert(
        !(await fileExists(`${dir}/root.tar.zst.gpg`)),
        "replacement never linked as a final",
      );
      assert(
        (await Deno.lstat(partialPath)).nlink === 1,
        "replacement still one link",
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "an existing final swapped between lstat and open is rejected and neither path is modified",
  async () => {
    const fixture = makeIndexFixture({ multiChunkRoot: true });
    const dir = await makeCanonicalDir("m05-swapfinal-");
    const finalPath = `${dir}/root.tar.zst.gpg`;
    const originalBytes = concatBytes(fixture.chunkBytes.get("root")!);
    await writePrivate(finalPath, originalBytes);
    // Same size and mode as the original so only dev/inode can reject it.
    const replacementBytes = filler(31, originalBytes.byteLength);
    const backPath = `${dir}/root.tar.zst.gpg.orig`;
    const store = new FakeGetStore();
    const originalOpen = Deno.open;
    let swapped = false;
    try {
      (Deno as unknown as { open: typeof Deno.open }).open = async (
        path: string | URL,
        options?: Deno.OpenOptions,
      ) => {
        if (!swapped && String(path) === finalPath) {
          swapped = true;
          await Deno.rename(finalPath, backPath);
          await writePrivate(finalPath, replacementBytes, 0o600);
        }
        return originalOpen(path, options);
      };
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(
        error.message === "Recovery failed (final:identity)",
        error.message,
      );
      assert(store.getCalls.length === 0, "no fetch after the swap");
      // Both the moved original and the replacement are preserved.
      assertBytes(await Deno.readFile(finalPath), replacementBytes);
      assertBytes(await Deno.readFile(backPath), originalBytes);
      assert((await modeOf(finalPath)) === 0o600);
      assert((await modeOf(backPath)) === 0o600);
    } finally {
      (Deno as unknown as { open: typeof Deno.open }).open = originalOpen;
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a verified final replaced at a later archive boundary is detected",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-laterdrift-");
    const rootPath = `${dir}/root.tar.zst.gpg`;
    const rootBytes = concatBytes(fixture.chunkBytes.get("root")!);
    await writePrivate(rootPath, rootBytes);
    // Same size and mode as the verified root final.
    const replacement = filler(41, rootBytes.byteLength);
    let replaced = false;
    const store = new FakeGetStore({
      handler: async () => {
        if (!replaced) {
          replaced = true;
          await Deno.remove(rootPath);
          await writePrivate(rootPath, replacement, 0o600);
        }
        return undefined;
      },
    });
    for (const archive of fixture.index.archives) {
      if (archive.role === "root") continue;
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(
        error.message === "Recovery failed (final:drift)",
        error.message,
      );
      assert(store.getCalls.length === 1, "efi only fetched before drift");
      // The replacement is preserved untouched; efi completed; no partial
      // was created for the archive whose boundary detected the drift.
      assertBytes(await Deno.readFile(rootPath), replacement);
      assert((await modeOf(rootPath)) === 0o600);
      assertBytes(
        await Deno.readFile(`${dir}/efi.tar.zst.gpg`),
        concatBytes(fixture.chunkBytes.get("efi")!),
      );
      assert(
        !(await fileExists(`${dir}/staging-boot.tar.zst.gpg.partial`)),
        "no partial for the next archive",
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a foreign entry appearing before the final result is rejected and preserved",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-foreign-");
    const foreign = "unexpected.txt";
    let dropped = false;
    const store = new FakeGetStore({
      handler: async (object) => {
        if (!dropped && object.fileName.includes("/recovery/")) {
          dropped = true;
          await writePrivate(`${dir}/${foreign}`, "intruder");
        }
        return undefined;
      },
    });
    for (const archive of fixture.index.archives) {
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(error.message === "Recovery failed (entry)", error.message);
      assert(dropped, "foreign entry was dropped during the last fetch");
      assert(store.getCalls.length === 7, "all seven archives were fetched");
      // The final entry rescan rejected the result: no final or foreign
      // path may be removed or rewritten.
      const expected = [...expectedArchiveNames(fixture.index), foreign]
        .sort();
      assert(
        JSON.stringify(await listNames(dir)) === JSON.stringify(expected),
        "seven finals plus the preserved foreign entry",
      );
      assertBytes(
        await Deno.readFile(`${dir}/${foreign}`),
        new TextEncoder().encode("intruder"),
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

runtimeTest(
  "a fetch failure leaves the current partial, earlier finals resumable, and never claims completion",
  async () => {
    const fixture = makeIndexFixture();
    const dir = await makeCanonicalDir("m05-failresume-");
    const missingId = fixture.index.archives[2].chunks[0].fileId;
    const store = new FakeGetStore();
    for (const archive of fixture.index.archives) {
      if (archive.role === "staging-boot") continue;
      store.seed(
        archive.chunks[0].fileId,
        fixture.chunkBytes.get(archive.role)![0],
      );
    }
    try {
      const error = await rejectWith(
        reconstructGeneration(fixture.index, store, dir),
      );
      assert(error.message === "Recovery failed (get)", error.message);
      // root and efi are complete; staging-boot keeps an explicit partial.
      assertBytes(
        await Deno.readFile(`${dir}/root.tar.zst.gpg`),
        fixture.chunkBytes.get("root")![0],
      );
      assertBytes(
        await Deno.readFile(`${dir}/efi.tar.zst.gpg`),
        fixture.chunkBytes.get("efi")![0],
      );
      assert(
        await fileExists(`${dir}/staging-boot.tar.zst.gpg.partial`),
        "partial left for diagnosis",
      );
      assert(!(await fileExists(`${dir}/staging-boot.tar.zst.gpg`)));
      const names = await listNames(dir);
      assert(
        JSON.stringify(names) === JSON.stringify([
          "efi.tar.zst.gpg",
          "root.tar.zst.gpg",
          "staging-boot.tar.zst.gpg.partial",
        ]),
        "no receipt or acceptance artifact",
      );
      // Caller explicitly removes the diagnosis partial, then resume reuses
      // root/efi (their gets are skipped) and completes the remaining roles.
      await Deno.remove(`${dir}/staging-boot.tar.zst.gpg.partial`);
      store.seed(missingId, fixture.chunkBytes.get("staging-boot")![0]);
      const resumed = await reconstructGeneration(fixture.index, store, dir);
      assert(resumed.archives.length === 7);
      const resumedIds = store.getCalls.slice(3).map((call) => call.fileId);
      const expectedRemaining = fixture.index.archives
        .filter((archive) => archive.role !== "root" && archive.role !== "efi")
        .map((archive) => archive.chunks[0].fileId);
      assert(
        JSON.stringify(resumedIds) === JSON.stringify(expectedRemaining),
        "reused finals are not re-fetched",
      );
      assert(
        JSON.stringify(await listNames(dir)) ===
          JSON.stringify([...expectedArchiveNames(fixture.index)].sort()),
      );
    } finally {
      await removeBestEffort(dir);
    }
  },
);

Deno.test("remote archive stream is lazy, version-bound and stops fetching on cancellation", async () => {
  const f = makeIndexFixture({ multiChunkRoot: true });
  const archive = f.index.archives.find((a) => a.role === "root")!;
  let requests = 0;
  const stream = streamRecoveryArchive(f.index, "root", {
    get(object) {
      const chunk = archive.chunks[requests];
      assert(object.fileId === chunk.fileId && object.fileName === chunk.name);
      return Promise.resolve(f.chunkBytes.get("root")![requests++]);
    },
  });
  await Promise.resolve();
  assert(requests === 0);
  const reader = stream.getReader();
  const first = await reader.read();
  assertBytes(first.value!, f.chunkBytes.get("root")![0]);
  assert(Number(requests) === 1);
  await reader.cancel();
  assert(Number(requests) === 1);
});

Deno.test("remote archive stream verifies chunks and aggregate before completion", async () => {
  const f = makeIndexFixture();
  for (const corruption of ["none", "chunk", "archive"]) {
    const index = cloneIndex(f.index);
    if (corruption === "archive") index.archives[0].sha256 = "00".repeat(32);
    let requests = 0;
    const stream = streamRecoveryArchive(index, "root", {
      get() {
        requests++;
        const bytes = f.chunkBytes.get("root")![0].slice();
        if (corruption === "chunk") bytes[0] ^= 1;
        return Promise.resolve(bytes);
      },
    });
    const received = new Response(stream).arrayBuffer();
    if (corruption === "none") {
      assertBytes(new Uint8Array(await received), f.chunkBytes.get("root")![0]);
    } else {assert(
        (await rejectWith(received)).message.includes(
          corruption === "chunk" ? "get:sha256" : "stream:archive",
        ),
      );}
    assert(requests === 1);
  }
});
