/** Focused m03-upload tests: synthetic local fixtures and an in-memory fake
 * B2 store only. Nothing reaches the network and no credential value is
 * read. Runtime checks (real temp fixtures and journal files) need read and
 * write permissions and are explicitly ignored in the default permissionless
 * mode; the same cases must run with zero skips under
 * `deno test --allow-read --allow-write`. The single module seam
 * (planReadTestSeam) only forces short nonfinal reads inside the real
 * planning pipeline and is restored by the test. */
import { createHash } from "node:crypto";
import type { CaptureResult } from "../scripts/backblaze-capture.ts";
import {
  type B2Object,
  MAX_CHUNK_BYTES,
} from "../scripts/backblaze-storage.ts";
import {
  generationChunkName,
  planReadTestSeam,
  UPLOAD_ROLE_ORDER,
  uploadCapturedGeneration,
  type UploadProgressRecord,
  type UploadRole,
  validateUploadCapture,
} from "../scripts/backblaze-upload.ts";

function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) throw new Error(message ?? "Assertion failed");
}

function assertThrows(fn: () => unknown): Error {
  try {
    fn();
  } catch (error) {
    if (error instanceof Error) return error;
    throw new Error("expected an Error");
  }
  throw new Error("expected a throw");
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

/** Query-only permission probe for the synthetic runtime checks; it never
 * requests a grant. The default `deno test` task carries no permissions, so
 * these cases must skip there and only execute under the explicit
 * --allow-read/--allow-write invocation. */
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

/** Runtime check registration: names carry a "runtime:" prefix so skipped
 * cases are unmistakably identified in every report. */
function runtimeTest(
  name: string,
  fn: (context: Deno.TestContext) => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

const GENERATION = "generation-11111111-2222-3333-4444-555555555555";
const JOURNAL_PATH = "upload-journal.json";

function formatFor(role: UploadRole): "tar.zst.gpg" | "json.zst.gpg" {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

/** Deterministic content without a large generator state; the short base is
 * repeated so multi-chunk fixtures stay cheap. */
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

interface FakeVersion {
  object: B2Object;
  bytes: Uint8Array;
}

/** In-memory B2Store replacement. The methods mirror B2Store semantics:
 * put echoes the object and stores bytes; get resolves the exact file id and
 * verifies the declared length and SHA-1; versions lists every version. A
 * configurable hook simulates an ambiguous put response (bytes stored but
 * the call throws) or corruption/truncation on readback, and a remove spy
 * proves the uploader never deletes anything. */
class FakeStore {
  private byName = new Map<string, FakeVersion[]>();
  private byId = new Map<string, Uint8Array>();
  private nextId = 1;
  private nextTimestamp = 1_800_000_000_000;
  putCalls = 0;
  getCalls: string[] = [];
  removeCalls = 0;
  versionsCalls = 0;
  putHandler:
    | ((fileName: string) => { error: Error; store: boolean } | undefined)
    | null = null;
  getHandler: ((fileId: string) => Uint8Array | undefined) | null = null;

  private createObject(
    fileName: string,
    bytes: Uint8Array,
    overrides: Partial<B2Object> = {},
  ): B2Object {
    const timestamp = overrides.uploadTimestamp ?? this.nextTimestamp;
    this.nextTimestamp += 1;
    return {
      fileId: overrides.fileId ??
        `file-${String(this.nextId++).padStart(6, "0")}`,
      fileName,
      contentLength: overrides.contentLength ?? bytes.byteLength,
      contentSha1: overrides.contentSha1 ?? sha1Hex(bytes),
      action: overrides.action ?? "upload",
      uploadTimestamp: timestamp,
    };
  }

  private store(object: B2Object, bytes: Uint8Array): void {
    const list = this.byName.get(object.fileName) ?? [];
    list.push({ object, bytes: new Uint8Array(bytes) });
    this.byName.set(object.fileName, list);
    this.byId.set(object.fileId, bytes);
  }

  put(fileName: string, bytes: Uint8Array<ArrayBuffer>): Promise<B2Object> {
    this.putCalls += 1;
    const handler = this.putHandler?.(fileName);
    const object = this.createObject(fileName, bytes);
    if (handler === undefined) {
      this.store(object, bytes);
      return Promise.resolve(object);
    }
    if (handler.store) this.store(object, bytes);
    return Promise.reject(handler.error);
  }

  get(object: B2Object): Promise<Uint8Array> {
    this.getCalls.push(object.fileId);
    const override = this.getHandler?.(object.fileId);
    const bytes = override ?? this.byId.get(object.fileId);
    if (bytes === undefined) {
      return Promise.reject(new Error("get failed (HTTP 404)"));
    }
    // Mirrors B2Store.get: exact version download verifies length and SHA-1.
    if (bytes.byteLength !== object.contentLength) {
      return Promise.reject(new Error("get failed: content length mismatch"));
    }
    if (sha1Hex(bytes) !== object.contentSha1) {
      return Promise.reject(new Error("get failed: content sha1 mismatch"));
    }
    return Promise.resolve(new Uint8Array(bytes));
  }

  versions(): Promise<B2Object[]> {
    this.versionsCalls += 1;
    const out: B2Object[] = [];
    for (const list of this.byName.values()) {
      for (const version of list) out.push(version.object);
    }
    return Promise.resolve(out);
  }

  /** Remove spy only: the uploader must never call this. */
  remove(): Promise<void> {
    this.removeCalls += 1;
    return Promise.resolve();
  }

  seed(
    fileName: string,
    bytes: Uint8Array,
    overrides: Partial<B2Object> = {},
  ): B2Object {
    const object = this.createObject(fileName, bytes, overrides);
    this.store(object, bytes);
    return object;
  }

  deleteVersion(fileId: string): void {
    for (const [name, list] of this.byName) {
      const index = list.findIndex((version) =>
        version.object.fileId === fileId
      );
      if (index >= 0) {
        list.splice(index, 1);
        if (list.length === 0) this.byName.delete(name);
        this.byId.delete(fileId);
        return;
      }
    }
  }

  countVersions(fileName: string): number {
    return this.byName.get(fileName)?.length ?? 0;
  }

  bytesForName(fileName: string): Uint8Array | null {
    const list = this.byName.get(fileName);
    if (list === undefined || list.length === 0) return null;
    const total = list.reduce((sum, version) => sum + version.bytes.length, 0);
    const joined = new Uint8Array(total);
    let offset = 0;
    for (const version of list) {
      joined.set(version.bytes, offset);
      offset += version.bytes.length;
    }
    return joined;
  }

  totalVersionCount(): number {
    let count = 0;
    for (const list of this.byName.values()) count += list.length;
    return count;
  }
}

interface Fixture {
  stage: string;
  capture: CaptureResult;
  bytesByRole: Map<UploadRole, Uint8Array>;
}

async function makeFixture(options: {
  generation?: string;
  rootBytes?: number;
} = {}): Promise<Fixture> {
  const generation = options.generation ?? GENERATION;
  const raw = await Deno.makeTempDir({ prefix: "b2-upload-test-" });
  const stage = await Deno.realPath(raw);
  await Deno.chmod(stage, 0o700);
  const bytesByRole = new Map<UploadRole, Uint8Array>();
  const archives: CaptureResult["archives"] = [];
  for (const role of UPLOAD_ROLE_ORDER) {
    const format = formatFor(role);
    const size = role === "root" && options.rootBytes !== undefined
      ? options.rootBytes
      : 4096 + role.length * 137;
    const seed = [...role].reduce(
      (sum, char) => sum + char.charCodeAt(0),
      0,
    );
    const bytes = filler(seed, size);
    const path = `${stage}/${role}.${format}`;
    await Deno.writeFile(path, bytes);
    await Deno.chmod(path, 0o600);
    bytesByRole.set(role, bytes);
    archives.push({
      role,
      path,
      bytes: size,
      sha256: sha256Hex(bytes),
      format,
    });
  }
  const capture: CaptureResult = {
    generation,
    stageDirectory: stage,
    archives,
    startedAtUtc: "2026-09-06T00:00:00.000Z",
    finishedAtUtc: "2026-09-06T00:00:01.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
  };
  return { stage, capture, bytesByRole };
}

async function removeFixture(fixture: Fixture): Promise<void> {
  try {
    await Deno.remove(fixture.stage, { recursive: true });
  } catch {
    // Best effort only; the test outcome is already decided.
  }
}

function rootName(capture: CaptureResult, index = 0): string {
  return generationChunkName(capture.generation, "root", index);
}

async function readJournal(
  fixture: Fixture,
): Promise<{
  schemaVersion: number;
  generation: string;
  stageDirectory: string;
  startedAtUtc: string;
  archives: unknown[];
  chunks: Record<string, unknown>[];
}> {
  const text = await Deno.readTextFile(
    `${fixture.stage}/${JOURNAL_PATH}`,
  );
  return JSON.parse(text) as {
    schemaVersion: number;
    generation: string;
    stageDirectory: string;
    startedAtUtc: string;
    archives: unknown[];
    chunks: Record<string, unknown>[];
  };
}

function journalObject(fixture: Fixture): Record<string, unknown> {
  const root = fixture.capture.archives.find((archive) =>
    archive.role === "root"
  )!;
  const rootBytes = fixture.bytesByRole.get("root")!;
  return {
    schemaVersion: 1,
    generation: fixture.capture.generation,
    stageDirectory: fixture.capture.stageDirectory,
    startedAtUtc: "2026-09-06T00:00:00.000Z",
    archives: UPLOAD_ROLE_ORDER.map((role) => {
      const archive = fixture.capture.archives.find((candidate) =>
        candidate.role === role
      )!;
      return {
        role: archive.role,
        format: archive.format,
        path: archive.path,
        bytes: archive.bytes,
        sha256: archive.sha256,
      };
    }),
    chunks: [{
      role: "root",
      index: 0,
      name: rootName(fixture.capture),
      size: root.bytes,
      sha256: root.sha256,
      sha1: sha1Hex(rootBytes),
      fileId: "file-journaled",
      uploadTimestamp: 1_800_000_000_000,
      reused: false,
      verifiedAtUtc: "2026-09-06T00:00:00.500Z",
    }],
  };
}

async function writeJournalFile(
  fixture: Fixture,
  journal: Record<string, unknown>,
): Promise<void> {
  const path = `${fixture.stage}/${JOURNAL_PATH}`;
  await Deno.writeFile(path, new TextEncoder().encode(JSON.stringify(journal)));
  await Deno.chmod(path, 0o600);
}

// ---------------------------------------------------------------------------
// Pure tests — no filesystem or store access.
// ---------------------------------------------------------------------------

Deno.test("chunk names are deterministic, zero-padded and extensionless", () => {
  assert(
    generationChunkName(GENERATION, "root", 0) ===
      `restic/direct-v1/generations/${GENERATION}/root/00000000`,
  );
  assert(
    generationChunkName(GENERATION, "recovery", 7) ===
      `restic/direct-v1/generations/${GENERATION}/recovery/00000007`,
  );
  assert(
    generationChunkName(GENERATION, "staging-efi", 42) ===
      `restic/direct-v1/generations/${GENERATION}/staging-efi/00000042`,
  );
  assert(
    assertThrows(() => generationChunkName(GENERATION, "root", -1))
      .message.includes("chunk-name:index"),
  );
  assert(
    assertThrows(() => generationChunkName(GENERATION, "root", 1.5))
      .message.includes("chunk-name:index"),
  );
  assert(
    assertThrows(() =>
      generationChunkName(GENERATION, "root", Number.MAX_SAFE_INTEGER + 2)
    ).message.includes("chunk-name:index"),
  );
});

function validCapture(): CaptureResult {
  const stageDirectory =
    "/var/tmp/arch-vps-file-backup/generation-11111111-2222-3333-4444-555555555555";
  return {
    generation: GENERATION,
    stageDirectory,
    archives: UPLOAD_ROLE_ORDER.map((role) => {
      const format = formatFor(role);
      return {
        role,
        path: `${stageDirectory}/${role}.${format}`,
        bytes: 65536,
        sha256: "a".repeat(64),
        format,
      };
    }),
    startedAtUtc: "2026-09-06T00:00:00.000Z",
    finishedAtUtc: "2026-09-06T00:00:01.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
  };
}

Deno.test("capture validation accepts the canonical seven-role shape", () => {
  validateUploadCapture(validCapture());
});

Deno.test("capture validation rejects every deviation", () => {
  const cases: Array<[string, (capture: CaptureResult) => void]> = [
    ["generation", (capture) => {
      capture.generation = "generation-not-a-uuid";
    }],
    ["consistency", (capture) => {
      capture.consistency = "atomic-snapshot" as never;
    }],
    ["sourceShutdown", (capture) => {
      capture.sourceShutdown = true as never;
    }],
    ["interval", (capture) => {
      capture.startedAtUtc = "not a date";
    }],
    ["stage", (capture) => {
      capture.stageDirectory = "relative/stage";
    }],
    ["count", (capture) => {
      capture.archives = capture.archives.slice(0, 6);
    }],
    ["duplicate role", (capture) => {
      capture.archives = [...capture.archives, capture.archives[0]];
    }],
    ["unknown role", (capture) => {
      capture.archives[0] = {
        ...capture.archives[0],
        role: "mystery" as never,
      };
    }],
    ["wrong format", (capture) => {
      capture.archives[0] = {
        ...capture.archives[0],
        format: "json.zst.gpg",
        path: capture.archives[0].path.replace(
          ".tar.zst.gpg",
          ".json.zst.gpg",
        ),
      };
    }],
    ["path", (capture) => {
      capture.archives[1] = {
        ...capture.archives[1],
        path: "/var/tmp/elsewhere/efi.tar.zst.gpg",
      };
    }],
    ["bytes zero", (capture) => {
      capture.archives[2] = { ...capture.archives[2], bytes: 0 };
    }],
    ["bytes non-safe", (capture) => {
      capture.archives[3] = { ...capture.archives[3], bytes: 1.5 };
    }],
    ["hash", (capture) => {
      capture.archives[4] = {
        ...capture.archives[4],
        sha256: "abcdef",
      };
    }],
  ];
  for (const [label, mutate] of cases) {
    const capture = validCapture();
    mutate(capture);
    const error = assertThrows(() => validateUploadCapture(capture));
    assert(
      error.message === `Upload failed (capture:${label})` ||
        error.message.includes("capture:"),
      `case ${label}: unexpected message ${error.message}`,
    );
  }
});

// ---------------------------------------------------------------------------
// Runtime tests — real fixtures, synthetic store only.
// ---------------------------------------------------------------------------

runtimeTest(
  "multi-chunk upload keeps order and verifies the whole archive",
  async () => {
    const short = 2 * 1024 * 1024;
    const fixture = await makeFixture({ rootBytes: MAX_CHUNK_BYTES + short });
    const store = new FakeStore();
    const progress: UploadProgressRecord[] = [];
    try {
      const result = await uploadCapturedGeneration(
        fixture.capture,
        store,
        (record): Promise<void> => {
          progress.push(record);
          return Promise.resolve();
        },
      );
      assert(result.uploadVerified === true);
      assert(result.decryptedRestoreProved === false);
      assert(result.machineBootRestoreProved === false);
      assert(result.generation === fixture.capture.generation);
      assert(result.chunkCount === UPLOAD_ROLE_ORDER.length + 1);
      assert(
        result.totalBytes === fixture.capture.archives.reduce(
          (sum, archive) => sum + archive.bytes,
          0,
        ),
      );
      assert(result.duplicateVersions.length === 0);
      assert(result.archives.length === UPLOAD_ROLE_ORDER.length);
      for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
        const archive = result.archives[i];
        const expected = fixture.bytesByRole.get(UPLOAD_ROLE_ORDER[i])!;
        assert(archive.role === UPLOAD_ROLE_ORDER[i]);
        assert(archive.sha256 === sha256Hex(expected));
        assert(
          archive.path === `${fixture.stage}/${archive.role}.${archive.format}`,
        );
        assert(
          archive.bytes === expected.byteLength &&
            archive.chunks.reduce((sum, chunk) => sum + chunk.size, 0) ===
              expected.byteLength,
        );
        for (let j = 0; j < archive.chunks.length; j += 1) {
          const chunk = archive.chunks[j];
          assert(chunk.index === j);
          assert(chunk.size > 0 && chunk.size <= MAX_CHUNK_BYTES);
          assert(
            chunk.name ===
              generationChunkName(fixture.capture.generation, archive.role, j),
          );
          const start = j * MAX_CHUNK_BYTES;
          const slice = expected.subarray(start, start + chunk.size);
          assert(chunk.sha256 === sha256Hex(slice));
          assert(chunk.sha1 === sha1Hex(slice));
          assert(chunk.reused === false);
        }
      }
      const root = result.archives[0];
      assert(root.chunks.length === 2);
      assert(root.chunks[0].size === MAX_CHUNK_BYTES);
      assert(root.chunks[1].size === short);
      // Ordered readback must reproduce the source ciphertext exactly.
      const readback = new Uint8Array(
        fixture.bytesByRole.get("root")!.byteLength,
      );
      let offset = 0;
      for (const chunk of root.chunks) {
        const bytes = store.bytesForName(chunk.name)!;
        assert(bytes.length === chunk.size);
        readback.set(bytes, offset);
        offset += bytes.length;
      }
      assertBytes(readback, fixture.bytesByRole.get("root")!);
      assert(store.putCalls === result.chunkCount);
      assert(store.getCalls.length === result.chunkCount);
      assert(store.removeCalls === 0);
      // Journal: committed after every verified chunk, 0600, exact bindings.
      const info = await Deno.lstat(`${fixture.stage}/${JOURNAL_PATH}`);
      assert((info.mode! & 0o777) === 0o600);
      const journal = await readJournal(fixture);
      assert(journal.schemaVersion === 1);
      assert(journal.generation === fixture.capture.generation);
      assert(journal.stageDirectory === fixture.stage);
      // A fresh invocation mints one start shared by journal and receipt.
      assert(journal.startedAtUtc === result.startedAtUtc);
      assert(journal.chunks.length === result.chunkCount);
      assert(
        journal.chunks[0].fileId === root.chunks[0].fileId &&
          journal.chunks[1].fileId === root.chunks[1].fileId,
      );
      assert(journal.archives.length === UPLOAD_ROLE_ORDER.length);
      // Progress records follow exact chunk order.
      const expectedProgress: UploadProgressRecord[] = [];
      for (const archive of UPLOAD_ROLE_ORDER) {
        const count = archive === "root" ? 2 : 1;
        for (let i = 0; i < count; i += 1) {
          expectedProgress.push({
            role: archive,
            chunkIndex: i,
            totalChunks: result.chunkCount,
          });
        }
      }
      assert(progress.length === expectedProgress.length);
      for (let i = 0; i < expectedProgress.length; i += 1) {
        assert(
          progress[i].role === expectedProgress[i].role &&
            progress[i].chunkIndex === expectedProgress[i].chunkIndex &&
            progress[i].totalChunks === expectedProgress[i].totalChunks,
        );
      }
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "lost put response is reconciled with one refresh and no reupload",
  async () => {
    const fixture = await makeFixture();
    const store = new FakeStore();
    store.putHandler = (fileName) =>
      fileName === rootName(fixture.capture)
        ? { error: new Error("put failed (network error)"), store: true }
        : undefined;
    try {
      const result = await uploadCapturedGeneration(fixture.capture, store);
      assert(result.uploadVerified === true);
      // The ambiguous chunk was never uploaded twice.
      assert(
        store.putCalls === UPLOAD_ROLE_ORDER.length,
        `expected one put per chunk, got ${store.putCalls}`,
      );
      const root = result.archives[0].chunks[0];
      assert(root.reused === true);
      assert(
        store.countVersions(rootName(fixture.capture)) === 1,
      );
      assert(root.versions.length === 1);
      assert(root.fileId === root.versions[0].fileId);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "ambiguous put with no object rethrows and never reuploads",
  async () => {
    const fixture = await makeFixture();
    const store = new FakeStore();
    store.putHandler = (fileName) =>
      fileName === rootName(fixture.capture)
        ? { error: new Error("put failed (network error)"), store: false }
        : undefined;
    try {
      const error = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(error.message === "put failed (network error)");
      assert(store.putCalls === 1, "no second upload after reconciliation");
      assert(store.totalVersionCount() === 0);
      let absent = false;
      try {
        await Deno.lstat(`${fixture.stage}/${JOURNAL_PATH}`);
      } catch (e) {
        absent = e instanceof Deno.errors.NotFound;
      }
      assert(absent, "failed chunk must not be journaled");
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "readback corruption and truncation fail closed without removal",
  async () => {
    for (
      const [label, override] of [
        [
          "corruption",
          (bytes: Uint8Array): Uint8Array => {
            const corrupted = new Uint8Array(bytes);
            corrupted[0] = corrupted[0] ^ 0xff;
            return corrupted;
          },
        ],
        [
          "truncation",
          (bytes: Uint8Array): Uint8Array =>
            bytes.subarray(0, bytes.length - 1),
        ],
      ] as const
    ) {
      const fixture = await makeFixture();
      const store = new FakeStore();
      store.getHandler = (fileId) => {
        // The first upload of the run is root/00000000 -> file-000001.
        if (fileId === "file-000001") {
          return override(fixture.bytesByRole.get("root")!);
        }
        return undefined;
      };
      try {
        const error = await rejectWith(
          uploadCapturedGeneration(fixture.capture, store),
        );
        assert(
          error.message.startsWith("get failed"),
          `${label}: ${error.message}`,
        );
        assert(store.removeCalls === 0, label);
        let absent = false;
        try {
          await Deno.lstat(`${fixture.stage}/${JOURNAL_PATH}`);
        } catch (e) {
          absent = e instanceof Deno.errors.NotFound;
        }
        assert(absent, `${label}: failed chunk must not be journaled`);
      } finally {
        await removeFixture(fixture);
      }
    }
  },
);

runtimeTest(
  "resume continues from the durable journal without re-upload",
  async () => {
    const fixture = await makeFixture({
      rootBytes: MAX_CHUNK_BYTES + 2 * 1024 * 1024,
    });
    const store = new FakeStore();
    store.putHandler = (fileName) =>
      fileName.endsWith("/00000001")
        ? { error: new Error("put failed (network error)"), store: false }
        : undefined;
    try {
      const first = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(first.message === "put failed (network error)");
      const journalAfterFirst = await readJournal(fixture);
      assert(journalAfterFirst.chunks.length === 1);
      assert(
        journalAfterFirst.chunks[0].name ===
          generationChunkName(fixture.capture.generation, "root", 0),
      );
      assert(store.countVersions(rootName(fixture.capture, 0)) === 1);
      assert(store.countVersions(rootName(fixture.capture, 1)) === 0);

      // Second run resumes: chunk 0 is reconciled/verified from inventory and
      // only the failed chunk 1 and the remaining roles are uploaded.
      store.putHandler = null;
      const result = await uploadCapturedGeneration(fixture.capture, store);
      assert(result.uploadVerified === true);
      // One failed put attempt in run 1 plus one put per final chunk; the
      // verified chunk 0 is never uploaded a second time.
      assert(
        store.putCalls === result.chunkCount + 1,
        `expected ${
          result.chunkCount + 1
        } put calls total, got ${store.putCalls}`,
      );
      assert(store.countVersions(rootName(fixture.capture, 0)) === 1);
      const chunks = result.archives[0].chunks;
      assert(chunks.length === 2);
      assert(chunks[0].reused === true);
      assert(
        chunks[0].fileId === journalAfterFirst.chunks[0].fileId,
      );
      assert(chunks[1].reused === false);
      const journalAfterSecond = await readJournal(fixture);
      assert(journalAfterSecond.chunks.length === result.chunkCount);
      assert(
        journalAfterSecond.chunks[0].fileId === chunks[0].fileId &&
          journalAfterSecond.chunks[1].fileId === chunks[1].fileId,
      );
      // The resumed receipt and journal keep the original start timestamp:
      // the upload operation's age is never silently reset.
      assert(result.startedAtUtc === journalAfterFirst.startedAtUtc);
      assert(
        journalAfterSecond.startedAtUtc === journalAfterFirst.startedAtUtc,
      );
      // Full ordered readback still matches the source ciphertext.
      const readback = new Uint8Array(
        fixture.bytesByRole.get("root")!.byteLength,
      );
      let offset = 0;
      for (const chunk of chunks) {
        const bytes = store.bytesForName(chunk.name)!;
        readback.set(bytes, offset);
        offset += bytes.length;
      }
      assertBytes(readback, fixture.bytesByRole.get("root")!);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest("corrupt journal fails closed before any upload", async () => {
  const cases: Array<[string, (journal: Record<string, unknown>) => void]> = [
    ["generation", (journal) => {
      journal.generation = "generation-99999999-9999-9999-9999-999999999999";
    }],
    ["architecture", (journal) => {
      const archives = journal.archives as Array<Record<string, unknown>>;
      archives[0].bytes = (archives[0].bytes as number) + 1;
    }],
    ["interval", (journal) => {
      journal.startedAtUtc = "not a date";
    }],
    ["chunks", (journal) => {
      const chunks = journal.chunks as Array<Record<string, unknown>>;
      chunks[0].sha256 = "0".repeat(64);
    }],
    ["accepted flag", (journal) => {
      journal.accepted = true;
    }],
  ];
  for (const [label, mutate] of cases) {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const journal = journalObject(fixture);
      mutate(journal);
      await writeJournalFile(fixture, journal);
      const error = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(
        error.message.startsWith("Upload failed (journal:"),
        `${label}: ${error.message}`,
      );
      assert(store.putCalls === 0, `${label}: upload must not start`);
      assert(store.getCalls.length === 0, `${label}: no readback allowed`);
      assert(store.removeCalls === 0, label);
    } finally {
      await removeFixture(fixture);
    }
  }
});

runtimeTest(
  "duplicate identical versions are accounted and reused",
  async () => {
    const fixture = await makeFixture();
    const store = new FakeStore();
    const name = rootName(fixture.capture);
    const rootBytes = fixture.bytesByRole.get("root")!;
    const older = store.seed(name, rootBytes, {
      fileId: "file-duplicate-older",
      uploadTimestamp: 1_800_000_000_000,
    });
    const newer = store.seed(name, rootBytes, {
      fileId: "file-duplicate-newer",
      uploadTimestamp: 1_800_000_000_100,
    });
    try {
      const result = await uploadCapturedGeneration(fixture.capture, store);
      assert(result.uploadVerified === true);
      // One put per remaining role only; the duplicate chunk is reused.
      assert(store.putCalls === UPLOAD_ROLE_ORDER.length - 1);
      const root = result.archives[0].chunks[0];
      assert(root.reused === true);
      assert(root.fileId === newer.fileId);
      assert(root.versions.length === 2);
      assert(root.versions[0].fileId === newer.fileId);
      assert(root.versions[1].fileId === older.fileId);
      for (const version of root.versions) {
        assert(version.fileName === name);
        assert(version.contentLength === rootBytes.byteLength);
        assert(version.contentSha1 === sha1Hex(rootBytes));
        assert(version.action === "upload");
      }
      assert(result.duplicateVersions.length === 1);
      assert(result.duplicateVersions[0].fileId === older.fileId);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest("conflicting content for a chunk name fails closed", async () => {
  const fixture = await makeFixture();
  const store = new FakeStore();
  const name = rootName(fixture.capture);
  const conflict = filler(7, 1024);
  store.seed(name, conflict);
  try {
    const error = await rejectWith(
      uploadCapturedGeneration(fixture.capture, store),
    );
    assert(error.message.includes("chunk:conflict"), error.message);
    assert(store.putCalls === 0);
    assert(store.removeCalls === 0);
  } finally {
    await removeFixture(fixture);
  }
});

runtimeTest("foreign versions are never read, altered or listed", async () => {
  const fixture = await makeFixture();
  const store = new FakeStore();
  const otherGeneration = "generation-99999999-9999-9999-9999-999999999999";
  const foreignChunk = generationChunkName(otherGeneration, "efi", 0);
  const foreignBytes = filler(11, 2048);
  const foreignSeed = store.seed(foreignChunk, foreignBytes, {
    fileId: "file-foreign-chunk",
  });
  const foreignManifest = store.seed(
    "restic/direct-v1/generations/some-other/README",
    filler(13, 512),
    { fileId: "file-foreign-manifest" },
  );
  try {
    const result = await uploadCapturedGeneration(fixture.capture, store);
    assert(result.uploadVerified === true);
    assert(store.putCalls === UPLOAD_ROLE_ORDER.length);
    for (const fileId of store.getCalls) {
      assert(
        fileId !== foreignSeed.fileId && fileId !== foreignManifest.fileId,
        `foreign version ${fileId} was read`,
      );
    }
    assert(result.duplicateVersions.length === 0);
    // Foreign versions are untouched and still listed in full inventory.
    assert(store.countVersions(foreignChunk) === 1);
    assert(store.countVersions(foreignManifest.fileName) === 1);
    assertBytes(store.bytesForName(foreignChunk)!, foreignBytes);
    assert(store.totalVersionCount() === UPLOAD_ROLE_ORDER.length + 2);
    assert(store.removeCalls === 0);
  } finally {
    await removeFixture(fixture);
  }
});

runtimeTest(
  "start or hide markers inside the generation fail closed",
  async () => {
    for (const action of ["hide", "start"] as const) {
      const fixture = await makeFixture();
      const store = new FakeStore();
      const name = rootName(fixture.capture);
      store.seed(name, new Uint8Array(0), {
        action,
        contentLength: 0,
        contentSha1: action === "hide" ? "0".repeat(40) : "",
        fileId: `file-marker-${action}`,
      });
      try {
        const error = await rejectWith(
          uploadCapturedGeneration(fixture.capture, store),
        );
        assert(
          error.message === "Upload failed (inventory:action)",
          error.message,
        );
        assert(store.putCalls === 0);
        assert(store.getCalls.length === 0);
        assert(store.removeCalls === 0);
      } finally {
        await removeFixture(fixture);
      }
    }
  },
);

runtimeTest(
  "unexpected objects inside the generation fail closed",
  async () => {
    const [label, fileName] = [
      "bad index",
      `restic/direct-v1/generations/${GENERATION}/root/0000000`,
    ] as const;
    const fixture = await makeFixture();
    const store = new FakeStore();
    store.seed(fileName, filler(17, 128), { fileId: "file-bad-index" });
    try {
      const error = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(
        error.message === "Upload failed (inventory:unexpected-object)",
        `${label}: ${error.message}`,
      );
      assert(store.putCalls === 0);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "missing saved object identical duplicate is reconciled",
  async () => {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const first = await uploadCapturedGeneration(fixture.capture, store);
      const originalFileId = first.archives[0].chunks[0].fileId;
      store.deleteVersion(originalFileId);
      const name = rootName(fixture.capture);
      const replacement = store.seed(
        name,
        fixture.bytesByRole.get("root")!,
        { fileId: "file-replacement", uploadTimestamp: 1_800_000_500_000 },
      );
      const second = await uploadCapturedGeneration(fixture.capture, store);
      assert(second.uploadVerified === true);
      assert(store.putCalls === UPLOAD_ROLE_ORDER.length, "no new uploads");
      const root = second.archives[0].chunks[0];
      assert(root.reused === true);
      assert(root.fileId === replacement.fileId);
      // The stale journal identity is absent from the current inventory, so
      // it is not listed: only currently inventoried identities are.
      assert(root.versions.length === 1);
      assert(root.versions[0].fileId === replacement.fileId);
      assert(second.duplicateVersions.length === 0);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "missing saved object reuploads the same ciphertext after reconciliation",
  async () => {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const first = await uploadCapturedGeneration(fixture.capture, store);
      const originalFileId = first.archives[0].chunks[0].fileId;
      store.deleteVersion(originalFileId);
      const second = await uploadCapturedGeneration(fixture.capture, store);
      assert(second.uploadVerified === true);
      // Exactly one re-upload: the missing root chunk; all other saved chunks
      // are verified from the current inventory.
      assert(store.putCalls === UPLOAD_ROLE_ORDER.length + 1);
      const root = second.archives[0].chunks[0];
      assert(root.reused === false);
      assert(root.fileId !== originalFileId);
      // The replaced journal identity vanished from the store and is not a
      // current inventory entry, so it is not reported as a duplicate.
      assert(root.versions.length === 1);
      assert(root.versions[0].fileId === root.fileId);
      assert(second.duplicateVersions.length === 0);
      assert(
        store.countVersions(rootName(fixture.capture)) === 1,
      );
      assertBytes(
        store.bytesForName(rootName(fixture.capture))!,
        fixture.bytesByRole.get("root")!,
      );
      // The journal is rebound to the new exact version.
      const journal = await readJournal(fixture);
      const rootEntry = journal.chunks.find((chunk) => chunk.role === "root")!;
      assert(rootEntry.fileId === root.fileId);
      assert(rootEntry.sha256 === root.sha256);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "short nonfinal reads keep planned chunk boundaries deterministic",
  async () => {
    const tail = 3 * 1024 * 1024;
    const fixture = await makeFixture({
      rootBytes: MAX_CHUNK_BYTES + tail,
    });
    const store = new FakeStore();
    // Force every planning read request to be short relative to the chunk,
    // with a cap that is not a divisor of MAX_CHUNK_BYTES: a request that is
    // not clamped to the exact remainder would overshoot the 64 MiB
    // boundary, so the real plan/upload pipeline must stay deterministic.
    const previous = planReadTestSeam.maxBytes;
    planReadTestSeam.maxBytes = 3 * 1024 * 1024;
    try {
      const result = await uploadCapturedGeneration(fixture.capture, store);
      assert(result.uploadVerified === true);
      const expected = fixture.bytesByRole.get("root")!;
      const root = result.archives[0];
      assert(root.chunks.length === 2);
      // Boundaries are at exact multiples of MAX_CHUNK_BYTES regardless of
      // the short reads forced by the seam.
      assert(root.chunks[0].size === MAX_CHUNK_BYTES);
      assert(root.chunks[1].size === tail);
      let start = 0;
      for (const [index, chunk] of root.chunks.entries()) {
        assert(chunk.index === index);
        assert(chunk.size > 0 && chunk.size <= MAX_CHUNK_BYTES);
        assert(
          start === index * MAX_CHUNK_BYTES,
          `chunk ${index} must start at the deterministic boundary`,
        );
        const slice = expected.subarray(start, start + chunk.size);
        assert(chunk.sha256 === sha256Hex(slice));
        assert(chunk.sha1 === sha1Hex(slice));
        assert(
          chunk.name ===
            generationChunkName(fixture.capture.generation, "root", index),
        );
        start += chunk.size;
      }
      assert(start === expected.byteLength);
      // Journaled sizes reflect the same deterministic boundaries.
      const journal = await readJournal(fixture);
      assert(journal.chunks[0].size === MAX_CHUNK_BYTES);
      assert(journal.chunks[1].size === tail);
      assert(store.putCalls === result.chunkCount);
      assert(store.getCalls.length === result.chunkCount);
      assert(store.removeCalls === 0);
    } finally {
      planReadTestSeam.maxBytes = previous;
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "vanished saved chunk ambiguous put refreshes once and lists no stale duplicate",
  async () => {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const first = await uploadCapturedGeneration(fixture.capture, store);
      const name = rootName(fixture.capture);
      const originalFileId = first.archives[0].chunks[0].fileId;
      // The durable saved chunk disappears from the fake store between runs.
      store.deleteVersion(originalFileId);
      assert(store.countVersions(name) === 0);
      // This run's put stores the bytes but loses the response.
      store.putHandler = (fileName) =>
        fileName === name
          ? { error: new Error("put failed (lost response)"), store: true }
          : undefined;
      const putsBefore = store.putCalls;
      const listingsBefore = store.versionsCalls;
      const second = await uploadCapturedGeneration(fixture.capture, store);
      assert(second.uploadVerified === true);
      // Everything else is reused from the current inventory, so the second
      // run attempts exactly one put: the vanished chunk's ambiguous put.
      // It is reconciled from one refresh and reused — never put twice.
      assert(
        store.putCalls === putsBefore + 1,
        `the vanished chunk must be uploaded exactly once, got ${
          store.putCalls - putsBefore
        }`,
      );
      assert(
        store.versionsCalls === listingsBefore + 2,
        `expected the initial inventory plus exactly one refresh, got ${
          store.versionsCalls - listingsBefore
        }`,
      );
      const root = second.archives[0].chunks[0];
      assert(root.reused === true);
      assert(root.fileId !== originalFileId);
      // Only the refreshed inventory identity is reported: the stale
      // journal id must be absent from chunk versions and duplicates.
      assert(root.versions.length === 1);
      assert(root.versions[0].fileId === root.fileId);
      for (const version of root.versions) {
        assert(version.fileId !== originalFileId);
      }
      assert(second.duplicateVersions.length === 0);
      assert(store.countVersions(name) === 1);
      assert(
        store.getCalls.filter((fileId) => fileId === root.fileId).length ===
          1,
        "the refreshed primary is read back exactly once",
      );
      // The journal is rebound to the refreshed identity.
      const journal = await readJournal(fixture);
      assert(journal.chunks[0].fileId === root.fileId);
      // Ordered readback still reproduces the source ciphertext.
      const readback = new Uint8Array(
        fixture.bytesByRole.get("root")!.byteLength,
      );
      let offset = 0;
      for (const chunk of second.archives[0].chunks) {
        const bytes = store.bytesForName(chunk.name)!;
        readback.set(bytes, offset);
        offset += bytes.length;
      }
      assertBytes(readback, fixture.bytesByRole.get("root")!);
      assert(store.removeCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest("stage and archive hardening rejects unsafe fixtures", async () => {
  // Stage not owner-only.
  {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      await Deno.chmod(fixture.stage, 0o755);
      const error = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(
        error.message === "Upload failed (stage:permissions)",
        error.message,
      );
      assert(store.putCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  }
  // Stage directory replaced by a symlink.
  {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const fakeStage = await Deno.makeTempDir({ prefix: "b2-upload-link-" });
      await Deno.remove(fakeStage);
      await Deno.symlink(fixture.stage, fakeStage, { type: "dir" });
      const capture = {
        ...fixture.capture,
        stageDirectory: fakeStage,
        archives: fixture.capture.archives.map((archive) => ({
          ...archive,
          path: `${fakeStage}/${archive.role}.${archive.format}`,
        })),
      };
      const error = await rejectWith(
        uploadCapturedGeneration(capture, store),
      );
      assert(
        error.message === "Upload failed (stage:not-directory)",
        error.message,
      );
      assert(store.putCalls === 0);
      await Deno.remove(fakeStage);
    } finally {
      await removeFixture(fixture);
    }
  }
  // Archive mode not 0600.
  {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const rootPath = fixture.capture.archives[0].path;
      await Deno.chmod(rootPath, 0o644);
      const error = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(
        error.message === "Upload failed (archive:permissions)",
        error.message,
      );
      assert(store.putCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  }
  // Archive file replaced by a symlink.
  {
    const fixture = await makeFixture();
    const store = new FakeStore();
    try {
      const rootPath = fixture.capture.archives[0].path;
      const elsewhere = `${fixture.stage}/elsewhere.bin`;
      await Deno.writeFile(elsewhere, new Uint8Array([1, 2, 3]));
      await Deno.remove(rootPath);
      await Deno.symlink(elsewhere, rootPath);
      const error = await rejectWith(
        uploadCapturedGeneration(fixture.capture, store),
      );
      assert(error.message === "Upload failed (archive:file)", error.message);
      assert(store.putCalls === 0);
    } finally {
      await removeFixture(fixture);
    }
  }
});
