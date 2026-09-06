/**
 * Focused m04-index tests: synthetic local fixtures and an in-memory fake B2
 * store only. Nothing reaches the network and no credential value is read.
 * Runtime checks (real fixtures, owner-only files, real gpg synthetic
 * keyring) need read, write and run permissions and are explicitly ignored in
 * the default permissionless mode; the same cases must run with zero skips
 * under `deno test --allow-read --allow-write --allow-run`. Runtime
 * fixtures live in unique generation subdirectories of the fixed production
 * staging base `/var/tmp/arch-vps-file-backup` (created 0700 when absent; a
 * pre-existing unsafe base fails the tests clearly and is never
 * re-permissioned or re-owned) and synthetic private keyrings stay in
 * separate short temp paths (one fresh pair per runtime case, removed with
 * its exact gpg agents at case end). No test mirrors the implementation:
 * fixtures
 * are built from real bytes and only observable results (files, store calls,
 * receipts, decrypted plaintext) are asserted.
 */
import { createHash } from "node:crypto";
import type { CaptureResult } from "../scripts/backblaze-capture.ts";
import type { B2Object } from "../scripts/backblaze-storage.ts";
import { MAX_CHUNK_BYTES } from "../scripts/backblaze-storage.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
  type UploadResult,
  type UploadRole,
} from "../scripts/backblaze-upload.ts";
import {
  buildRecoveryIndex,
  type IndexRecipient,
  type PublishedIndex,
  publishRecoveryIndex,
  type RecoveryIndex,
  validateRecoveryIndex,
} from "../scripts/backblaze-index.ts";

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

/** Query-only permission probe: the default `deno test` task carries no
 * permissions, so runtime cases must skip there and only execute under the
 * explicit --allow-read/--allow-write/--allow-run invocation. */
async function runtimePermissionsGranted(): Promise<boolean> {
  const descriptors: Deno.PermissionDescriptor[] = [
    { name: "read" },
    { name: "write" },
    { name: "run" },
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
  Deno.test({
    name: `runtime: ${name}`,
    ignore: !runtimePermitted,
    fn: async (context) => {
      try {
        await fn(context);
      } finally {
        // Release this case's synthetic key pair (exact agents killed, exact
        // homes removed, cache cleared) no matter how the case ended; the
        // next case regenerates its own short-lived pair.
        await disposeSyntheticKeys();
      }
    },
  });
}

const GENERATION = "generation-11111111-2222-3333-4444-555555555555";
const FAKE_STAGE =
  "/var/tmp/arch-vps-file-backup/generation-11111111-2222-3333-4444-555555555555";
/** Runtime fixture stage root; never removed or modified by the tests beyond
 * creating/removing their own unique generation subdirectories. */
const TEST_BASE = "/var/tmp/arch-vps-file-backup";

function indexObjectFor(generation: string): string {
  return `restic/direct-v1/indexes/${generation}/index.json.gpg`;
}

function formatFor(role: UploadRole): "tar.zst.gpg" | "json.zst.gpg" {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
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

interface PureFixture {
  stage: string;
  capture: CaptureResult;
  upload: UploadResult;
  recipient: IndexRecipient;
  bytesByRole: Map<UploadRole, Uint8Array>;
}

function makePureFixture(
  stage: string = FAKE_STAGE,
  options: { multiChunkRoot?: boolean; generation?: string } = {},
): PureFixture {
  const generation = options.generation ?? GENERATION;
  const bytesByRole = new Map<UploadRole, Uint8Array>();
  const captureArchives: CaptureResult["archives"] = [];
  const uploadArchives: UploadResult["archives"] = [];
  for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
    const role = UPLOAD_ROLE_ORDER[i];
    const format = formatFor(role);
    const path = `${stage}/${role}.${format}`;
    if (role === "root" && options.multiChunkRoot === true) {
      const chunkSizes = [MAX_CHUNK_BYTES, 123];
      const bytes = MAX_CHUNK_BYTES + 123;
      const chunks = chunkSizes.map((size, index) => ({
        role,
        index,
        name: generationChunkName(generation, role, index),
        size,
        sha256: index === 0 ? "ab".repeat(32) : "cd".repeat(32),
        sha1: index === 0 ? "12".repeat(20) : "34".repeat(20),
        fileId: `file-${role}-${index}`,
        uploadTimestamp: 1_800_000_000_000 + index,
        verifiedAtUtc: "2026-09-06T00:00:03.500Z",
        reused: false,
        versions: [{
          fileId: `file-${role}-${index}`,
          fileName: generationChunkName(generation, role, index),
          contentLength: size,
          contentSha1: index === 0 ? "12".repeat(20) : "34".repeat(20),
          action: "upload" as const,
          uploadTimestamp: 1_800_000_000_000 + index,
        }],
      }));
      captureArchives.push({
        role,
        path,
        bytes,
        sha256: "ef".repeat(32),
        format,
      });
      uploadArchives.push({
        role,
        format,
        path,
        bytes,
        sha256: "ef".repeat(32),
        chunks,
        verifiedAtUtc: "2026-09-06T00:00:03.500Z",
      });
      continue;
    }
    const bytes = filler(7 + i, 4096 + role.length * 137);
    const sha256 = sha256Hex(bytes);
    const sha1 = sha1Hex(bytes);
    const fileId = `file-${role}`;
    const name = generationChunkName(generation, role, 0);
    bytesByRole.set(role, bytes);
    captureArchives.push({
      role,
      path,
      bytes: bytes.byteLength,
      sha256,
      format,
    });
    uploadArchives.push({
      role,
      format,
      path,
      bytes: bytes.byteLength,
      sha256,
      chunks: [{
        role,
        index: 0,
        name,
        size: bytes.byteLength,
        sha256,
        sha1,
        fileId,
        uploadTimestamp: 1_800_000_000_000 + i,
        verifiedAtUtc: "2026-09-06T00:00:03.500Z",
        reused: false,
        versions: [{
          fileId,
          fileName: name,
          contentLength: bytes.byteLength,
          contentSha1: sha1,
          action: "upload",
          uploadTimestamp: 1_800_000_000_000 + i,
        }],
      }],
      verifiedAtUtc: "2026-09-06T00:00:03.500Z",
    });
  }
  const capture: CaptureResult = {
    generation,
    stageDirectory: stage,
    archives: captureArchives,
    startedAtUtc: "2026-09-06T00:00:00.000Z",
    finishedAtUtc: "2026-09-06T00:00:01.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
  };
  const upload: UploadResult = {
    generation,
    stageDirectory: stage,
    archives: uploadArchives,
    chunkCount: uploadArchives.reduce(
      (sum, archive) => sum + archive.chunks.length,
      0,
    ),
    totalBytes: uploadArchives.reduce((sum, archive) => sum + archive.bytes, 0),
    duplicateVersions: [],
    startedAtUtc: "2026-09-06T00:00:02.000Z",
    finishedAtUtc: "2026-09-06T00:00:03.000Z",
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  const recipient: IndexRecipient = {
    recipientFile: "/var/tmp/recipient.asc",
    recipientSha256: "a".repeat(64),
    recipientFingerprint: "A".repeat(40),
  };
  return { stage, capture, upload, recipient, bytesByRole };
}

function builtIndex(fixture: PureFixture): RecoveryIndex {
  return buildRecoveryIndex(fixture.capture, fixture.upload, fixture.recipient);
}

function canonicalText(fixture: PureFixture): string {
  return JSON.stringify(builtIndex(fixture));
}

// ---------------------------------------------------------------------------
// Pure tests — no filesystem or store access.
// ---------------------------------------------------------------------------

Deno.test("canonical index round-trips through strict validation", () => {
  const fixture = makePureFixture();
  const built = builtIndex(fixture);
  assert(built.schemaVersion === 1);
  assert(built.generation === GENERATION);
  assert(built.consistency === "live-file-copy");
  assert(built.sourceShutdown === false);
  assert(built.uploadVerified === true);
  assert(built.decryptedRestoreProved === false);
  assert(built.machineBootRestoreProved === false);
  assert(built.recipientSha256 === fixture.recipient.recipientSha256);
  assert(built.recipientFingerprint === fixture.recipient.recipientFingerprint);
  assert(built.archives.length === UPLOAD_ROLE_ORDER.length);
  for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
    assert(built.archives[i].role === UPLOAD_ROLE_ORDER[i]);
    const archive = fixture.upload.archives.find((entry) =>
      entry.role === UPLOAD_ROLE_ORDER[i]
    )!;
    assert(built.archives[i].format === archive.format);
    assert(built.archives[i].bytes === archive.bytes);
    assert(built.archives[i].sha256 === archive.sha256);
    assert(built.archives[i].chunks.length === archive.chunks.length);
  }
  // Restored unknown JSON validates identically and re-serializes canonically.
  const restored = validateRecoveryIndex(
    JSON.parse(canonicalText(fixture)),
  );
  assert(JSON.stringify(restored) === canonicalText(fixture));
});

Deno.test("portable index omits paths, stages and duplicate versions", () => {
  const fixture = makePureFixture();
  const text = canonicalText(fixture);
  assert(!text.includes(fixture.stage));
  for (
    const key of [
      '"path"',
      '"stageDirectory"',
      '"versions"',
      '"reused"',
      '"verifiedAtUtc"',
      '"duplicateVersions"',
      '"updateTimestamp"',
    ]
  ) {
    assert(!text.includes(key), `index must not contain ${key}`);
  }
  const parsed = JSON.parse(text) as Record<string, unknown>;
  assert(
    Object.keys(parsed).join(",") === [
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
    ].join(","),
  );
});

Deno.test("multi-chunk archive keeps contiguous full-size ordering", () => {
  const fixture = makePureFixture(FAKE_STAGE, { multiChunkRoot: true });
  const index = builtIndex(fixture);
  const root = index.archives.find((archive) => archive.role === "root")!;
  assert(root.bytes === MAX_CHUNK_BYTES + 123);
  assert(root.chunks.length === 2);
  assert(root.chunks[0].index === 0);
  assert(root.chunks[0].size === MAX_CHUNK_BYTES);
  assert(
    root.chunks[0].name ===
      generationChunkName(GENERATION, "root", 0),
  );
  assert(root.chunks[1].index === 1);
  assert(root.chunks[1].size === 123);
  assert(
    root.chunks[1].name ===
      generationChunkName(GENERATION, "root", 1),
  );
  const validated = validateRecoveryIndex(JSON.parse(JSON.stringify(index)));
  const validatedRoot = validated.archives.find((archive) =>
    archive.role === "root"
  )!;
  assert(validatedRoot.chunks[0].size === MAX_CHUNK_BYTES);
});

Deno.test("validateRecoveryIndex rejects every malformed deviation", () => {
  const base = (): Record<string, unknown> =>
    JSON.parse(canonicalText(makePureFixture())) as Record<string, unknown>;
  const chunk = (record: Record<string, unknown>): Record<string, unknown> => {
    const archives = record.archives as Array<Record<string, unknown>>;
    const chunks = archives[0].chunks as Array<Record<string, unknown>>;
    return chunks[0];
  };
  const mutators: Array<[string, (record: Record<string, unknown>) => void]> = [
    ["extra key", (record) => {
      record.extra = true;
    }],
    ["missing key", (record) => {
      delete record.consistency;
    }],
    ["schemaVersion", (record) => {
      record.schemaVersion = 2;
    }],
    ["generation", (record) => {
      record.generation = "generation-not-a-uuid";
    }],
    ["capture interval", (record) => {
      record.captureFinishedAtUtc = "2026-09-05T23:59:59.000Z";
    }],
    ["upload interval before capture", (record) => {
      record.uploadStartedAtUtc = "2026-09-06T00:00:00.500Z";
    }],
    ["upload interval reversed", (record) => {
      record.uploadStartedAtUtc = "2026-09-06T00:00:04.000Z";
    }],
    ["non-UTC timestamp", (record) => {
      record.captureStartedAtUtc = "2026-09-06T00:00:00+00:00";
    }],
    ["consistency", (record) => {
      record.consistency = "atomic-snapshot";
    }],
    ["sourceShutdown", (record) => {
      record.sourceShutdown = true;
    }],
    ["recipient fingerprint", (record) => {
      record.recipientFingerprint = "a".repeat(40);
    }],
    ["recipient hash", (record) => {
      record.recipientSha256 = "B".repeat(64);
    }],
    ["upload flag", (record) => {
      record.uploadVerified = false;
    }],
    ["restore flag", (record) => {
      record.decryptedRestoreProved = true;
    }],
    ["archive count", (record) => {
      record.archives = (record.archives as unknown[]).slice(0, 6);
    }],
    ["extra archive", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      record.archives = [...archives, archives[0]];
    }],
    ["role order", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      const tmp = archives[0];
      archives[0] = archives[1];
      archives[1] = tmp;
    }],
    ["unknown role", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].role = "mystery";
    }],
    ["wrong format", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].format = "json.zst.gpg";
    }],
    ["zero bytes", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].bytes = 0;
    }],
    ["non-integer bytes", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].bytes = 1.5;
    }],
    ["bad archive hash", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].sha256 = "abcdef";
    }],
    ["empty chunks", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].chunks = [];
    }],
    ["chunk index gap", (record) => {
      chunk(record).index = 1;
    }],
    ["chunk index jump", (record) => {
      chunk(record).index = 2;
    }],
    ["chunk name mismatch", (record) => {
      chunk(record).name = generationChunkName(GENERATION, "root", 1);
    }],
    ["chunk zero size", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      const chunks = archives[0].chunks as Array<Record<string, unknown>>;
      chunks[0].size = 0;
    }],
    ["chunk over cap", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      const chunks = archives[0].chunks as Array<Record<string, unknown>>;
      chunks[0].size = MAX_CHUNK_BYTES + 1;
      archives[0].bytes = MAX_CHUNK_BYTES + 1;
    }],
    ["nonlast chunk not full", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].bytes = MAX_CHUNK_BYTES + 5;
      archives[0].chunks = [
        {
          ...chunk(record),
          index: 0,
          size: MAX_CHUNK_BYTES - 1,
          sha256: "ab".repeat(32),
          sha1: "12".repeat(20),
        },
        {
          ...chunk(record),
          index: 1,
          name: generationChunkName(GENERATION, "root", 1),
          size: 6,
          sha256: "cd".repeat(32),
          sha1: "34".repeat(20),
        },
      ];
    }],
    ["bad chunk sha256", (record) => {
      chunk(record).sha256 = "xyz";
    }],
    ["bad chunk sha1", (record) => {
      chunk(record).sha1 = "xyz";
    }],
    ["empty fileId", (record) => {
      chunk(record).fileId = "";
    }],
    ["oversized fileId", (record) => {
      chunk(record).fileId = "x".repeat(513);
    }],
    ["negative timestamp", (record) => {
      chunk(record).uploadTimestamp = -1;
    }],
    ["fractional timestamp", (record) => {
      chunk(record).uploadTimestamp = 1.5;
    }],
    ["duplicate fileId across archives", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      const chunks = archives[1].chunks as Array<Record<string, unknown>>;
      chunks[0].fileId = chunk(record).fileId;
    }],
    ["duplicate fileId within an archive", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].bytes = MAX_CHUNK_BYTES + 5;
      archives[0].chunks = [
        {
          ...chunk(record),
          index: 0,
          size: MAX_CHUNK_BYTES,
          sha256: "ab".repeat(32),
          sha1: "12".repeat(20),
        },
        {
          ...chunk(record),
          index: 1,
          name: generationChunkName(GENERATION, "root", 1),
          size: 5,
          sha256: "cd".repeat(32),
          sha1: "34".repeat(20),
          fileId: chunk(record).fileId,
        },
      ];
    }],
    ["sum mismatch", (record) => {
      const archives = record.archives as Array<Record<string, unknown>>;
      archives[0].bytes = (archives[0].bytes as number) + 1;
    }],
  ];
  for (const [label, mutate] of mutators) {
    const record = base();
    mutate(record);
    const error = assertThrows(() => validateRecoveryIndex(record));
    assert(
      error.message.startsWith("Index failed ("),
      `case ${label}: unexpected message ${error.message}`,
    );
  }
  for (
    const [label, value] of [
      ["null", null],
      ["number", 42],
      ["string", "x"],
      ["array", []],
    ] as const
  ) {
    const error = assertThrows(() => validateRecoveryIndex(value));
    assert(
      error.message === "Index failed (index:shape)",
      `case ${label}: ${error.message}`,
    );
  }
});

Deno.test("buildRecoveryIndex rejects mismatched capture/upload receipts", () => {
  const mutators: Array<[string, (fixture: PureFixture) => void]> = [
    ["upload generation", (fixture) => {
      fixture.upload.generation =
        "generation-99999999-9999-9999-9999-999999999999";
    }],
    ["upload stage", (fixture) => {
      fixture.upload.stageDirectory = "/var/tmp/elsewhere";
      for (const archive of fixture.upload.archives) {
        archive.path = `/var/tmp/elsewhere/${archive.role}.${archive.format}`;
      }
    }],
    ["archive bytes", (fixture) => {
      const archive = fixture.upload.archives[0];
      archive.bytes = archive.bytes + 1;
      archive.chunks[0].size = archive.bytes;
      fixture.upload.totalBytes += 1;
    }],
    ["archive hash", (fixture) => {
      fixture.upload.archives[0].sha256 = "f".repeat(64);
    }],
    ["archive format", (fixture) => {
      const archive = fixture.upload.archives[0];
      archive.format = "json.zst.gpg";
      archive.path = `${fixture.stage}/${archive.role}.json.zst.gpg`;
    }],
    ["archive path", (fixture) => {
      fixture.upload.archives[0].path = `${fixture.stage}/moved.tar.zst.gpg`;
    }],
    ["duplicate role", (fixture) => {
      const archive = fixture.upload.archives[1];
      fixture.upload.archives[1] = {
        ...archive,
        role: "root",
        path: `${fixture.stage}/root.${archive.format}`,
      };
    }],
    ["extra archive", (fixture) => {
      fixture.upload.archives.push({ ...fixture.upload.archives[0] });
    }],
    ["chunk name", (fixture) => {
      fixture.upload.archives[0].chunks[0].name = generationChunkName(
        GENERATION,
        "efi",
        0,
      );
    }],
    ["chunk size sum", (fixture) => {
      fixture.upload.archives[0].chunks[0].size =
        fixture.upload.archives[0].chunks[0].size + 1;
    }],
    ["chunk timestamp mismatch", (fixture) => {
      fixture.upload.archives[0].chunks[0].uploadTimestamp = 1;
    }],
    ["shared selected fileId across archives", (fixture) => {
      const root = fixture.upload.archives[0].chunks[0];
      const target = fixture.upload.archives[1].chunks[0];
      target.fileId = root.fileId;
      target.versions = [{ ...target.versions[0], fileId: root.fileId }];
    }],
    ["chunk count", (fixture) => {
      fixture.upload.chunkCount += 1;
    }],
    ["total bytes", (fixture) => {
      fixture.upload.totalBytes += 1;
    }],
    ["upload flags", (fixture) => {
      fixture.upload.uploadVerified = false as never;
    }],
    ["restore flag", (fixture) => {
      fixture.upload.decryptedRestoreProved = true as never;
    }],
    ["upload interval", (fixture) => {
      fixture.upload.startedAtUtc = "2026-09-06T00:00:03.000Z";
      fixture.upload.finishedAtUtc = "2026-09-06T00:00:02.000Z";
    }],
    ["cross interval", (fixture) => {
      fixture.upload.startedAtUtc = "2026-09-06T00:00:00.500Z";
    }],
    ["capture interval", (fixture) => {
      fixture.capture.startedAtUtc = "2026-09-06T00:00:02.000Z";
    }],
    ["duplicate selection", (fixture) => {
      fixture.upload.duplicateVersions = [{
        fileId: fixture.upload.archives[0].chunks[0].fileId,
        fileName: fixture.upload.archives[0].chunks[0].name,
        contentLength: fixture.upload.archives[0].chunks[0].size,
        contentSha1: fixture.upload.archives[0].chunks[0].sha1,
        action: "upload",
        uploadTimestamp: 1,
      }];
    }],
    ["orphan duplicate", (fixture) => {
      fixture.upload.duplicateVersions = [{
        fileId: "file-orphan",
        fileName: "restic/direct-v1/generations/x/root/00000000",
        contentLength: 1,
        contentSha1: "a1".repeat(20),
        action: "upload",
        uploadTimestamp: 1,
      }];
    }],
  ];
  for (const [label, mutate] of mutators) {
    const fixture = makePureFixture();
    mutate(fixture);
    const error = assertThrows(() =>
      buildRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
      )
    );
    assert(
      error.message.startsWith("Index failed (") ||
        error.message.startsWith("Upload failed ("),
      `case ${label}: unexpected message ${error.message}`,
    );
  }
});

Deno.test("selected chunk membership excludes duplicate versions", () => {
  const fixture = makePureFixture();
  const chunk = fixture.upload.archives[0].chunks[0];
  const duplicate = {
    fileId: "file-duplicate-root",
    fileName: chunk.name,
    contentLength: chunk.size,
    contentSha1: chunk.sha1,
    action: "upload" as const,
    uploadTimestamp: 1_800_000_000_000 + 100,
  };
  fixture.upload.archives[0].chunks[0] = {
    ...chunk,
    versions: [chunk.versions[0], duplicate],
  };
  fixture.upload.duplicateVersions = [duplicate];
  const index = buildRecoveryIndex(
    fixture.capture,
    fixture.upload,
    fixture.recipient,
  );
  const root = index.archives.find((archive) => archive.role === "root")!;
  assert(root.chunks[0].fileId === chunk.fileId);
  assert(root.chunks[0].uploadTimestamp === chunk.uploadTimestamp);
  assert(
    root.chunks[0].fileId !== "file-duplicate-root",
    "duplicate version must not be recovery membership",
  );
  const text = canonicalText(fixture);
  assert(
    !text.includes("file-duplicate-root"),
    "duplicate version id must not appear in the portable index",
  );
});

// ---------------------------------------------------------------------------
// Runtime fixture helpers
// ---------------------------------------------------------------------------

interface RuntimeFixture extends PureFixture {
  /** The single synthetic public key bound into this fixture's stage. */
  recipientKey: SyntheticKey;
}

interface SyntheticKey {
  publicBytes: Uint8Array;
  fingerprint: string;
  /** Short gpg home holding the private half (agent socket path limits). */
  keyHome: string;
}

/** Synthetic keys cached for the in-flight runtime case only; released
 * (exact agents killed, exact homes removed) when the case finishes. */
let cachedKeys: { key1: SyntheticKey; key2: SyntheticKey } | null = null;

/** Best-effort kill of the gpg-agent bound to exactly this synthetic home,
 * then removal of exactly this test-owned home. Never touches the default
 * agent or any other home. */
async function killAndRemoveKeyHome(home: string): Promise<void> {
  try {
    const killed = new Deno.Command("gpgconf", {
      args: ["--homedir", home, "--kill", "gpg-agent"],
    });
    await killed.output();
  } catch {
    // No agent may be running for this home; best effort only.
  }
  try {
    await Deno.remove(home, { recursive: true });
  } catch {
    // Best effort only; cleanup must never mask the test outcome.
  }
}

/** Release the cached synthetic key pair, if any, for the current runtime
 * case: kill the two exact agents, remove the two exact homes and clear the
 * cache so no test-generated key home or agent survives the run. */
async function disposeSyntheticKeys(): Promise<void> {
  const keys = cachedKeys;
  cachedKeys = null;
  if (keys === null) return;
  for (const key of [keys.key1, keys.key2]) {
    await killAndRemoveKeyHome(key.keyHome);
  }
}

async function generateSyntheticKey(
  home: string,
  uidLabel: string,
): Promise<SyntheticKey> {
  const generate = new Deno.Command("gpg", {
    args: [
      "--batch",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      "",
      "--quick-gen-key",
      "--homedir",
      home,
      uidLabel,
      "rsa3072",
      "encr",
      "0",
    ],
  });
  const generated = await generate.output();
  assert(generated.code === 0, `keygen failed: ${generated.code}`);
  const listing = new Deno.Command("gpg", {
    args: ["--batch", "--with-colons", "--list-keys", "--homedir", home],
  });
  const listed = await listing.output();
  assert(listed.code === 0, "list-keys failed");
  const records = new TextDecoder().decode(listed.stdout).split("\n");
  const fingerprint = records.find((line) => line.startsWith("fpr:"))
    ?.split(":")[9] ?? "";
  assert(/^[0-9A-F]{40}$/.test(fingerprint), "no primary fingerprint");
  const exported = new Deno.Command("gpg", {
    args: ["--batch", "--armor", "--export", "--homedir", home],
  });
  const pub = await exported.output();
  assert(pub.code === 0 && pub.stdout.length > 0, "public export failed");
  const publicBytes = pub.stdout;
  assert(
    new TextDecoder().decode(publicBytes).includes(
      "BEGIN PGP PUBLIC KEY BLOCK",
    ),
    "export is not public armor",
  );
  return { publicBytes, fingerprint, keyHome: home };
}

/** Two real distinct synthetic keys (each in its own short home so gpg-agent
 * socket paths stay short); generated once per runtime case, whose finally
 * then kills the two exact agents, removes the two exact homes and clears
 * the cache. A key-generation failure cleans the exact homes created here
 * before the error propagates (cachedKeys stays null). */
async function ensureSyntheticKeys(): Promise<{
  key1: SyntheticKey;
  key2: SyntheticKey;
}> {
  if (cachedKeys !== null) return cachedKeys;
  const home1 = await Deno.makeTempDir({ prefix: "g4-" });
  await Deno.chmod(home1, 0o700);
  const home2 = await Deno.makeTempDir({ prefix: "g4b-" });
  await Deno.chmod(home2, 0o700);
  try {
    const key1 = await generateSyntheticKey(
      home1,
      "m04-fixture <m04@fixture.invalid>",
    );
    const key2 = await generateSyntheticKey(
      home2,
      "m04-fixture-2 <m04b@fixture.invalid>",
    );
    cachedKeys = { key1, key2 };
    return cachedKeys;
  } catch (error) {
    await killAndRemoveKeyHome(home1);
    await killAndRemoveKeyHome(home2);
    throw error;
  }
}

/**
 * The runtime stage root must be the real production base as a 0700
 * directory (never a symlink) owned by the current user. When absent it is
 * created 0700; an existing unsafe base fails clearly and is never
 * re-permissioned or re-owned. The expected uid is the one this process
 * actually owns, taken from the freshly-created synthetic key home (no sys
 * permission probe).
 */
async function ensureTestBase(expectedUid: number): Promise<string> {
  let info: Deno.FileInfo;
  try {
    info = await Deno.lstat(TEST_BASE);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      try {
        await Deno.mkdir(TEST_BASE, { mode: 0o700 });
      } catch (cause) {
        throw new Error(
          `cannot create test stage base ${TEST_BASE}: ${String(cause)}`,
        );
      }
      await Deno.chmod(TEST_BASE, 0o700);
      info = await Deno.lstat(TEST_BASE);
    } else {
      throw error;
    }
  }
  if (info.isSymlink || !info.isDirectory) {
    throw new Error(
      `unsafe test stage base ${TEST_BASE}: not a real directory`,
    );
  }
  if (((info.mode ?? 0) & 0o777) !== 0o700) {
    throw new Error(`unsafe test stage base ${TEST_BASE}: mode must be 0700`);
  }
  if (typeof info.uid !== "number" || info.uid !== expectedUid) {
    throw new Error(`unsafe test stage base ${TEST_BASE}: wrong owner`);
  }
  return await Deno.realPath(TEST_BASE);
}

async function makeRuntimeFixture(): Promise<RuntimeFixture> {
  const keys = await ensureSyntheticKeys();
  // The freshly-created synthetic key home is owned by this process, so its
  // uid is the expected owner of the fixed production base (no sys probe).
  const keyHomeInfo = await Deno.lstat(keys.key1.keyHome);
  assert(
    typeof keyHomeInfo.uid === "number",
    "synthetic key home owner unknown",
  );
  const canonicalBase = await ensureTestBase(keyHomeInfo.uid);
  const generation = `generation-${crypto.randomUUID()}`;
  const stage = `${canonicalBase}/${generation}`;
  await Deno.mkdir(stage, { mode: 0o700 });
  await Deno.chmod(stage, 0o700);
  const base = makePureFixture(stage, { generation });
  // Capture-stage retained pinned public file used for all seven archive
  // encryptions; the publisher must bind the supplied key to this file.
  await writePrivateFile(`${stage}/recipient.asc`, keys.key1.publicBytes);
  const source = `${stage}/recipient-source.asc`;
  await writePrivateFile(source, keys.key1.publicBytes);
  const recipient: IndexRecipient = {
    recipientFile: source,
    recipientSha256: sha256Hex(keys.key1.publicBytes),
    recipientFingerprint: keys.key1.fingerprint,
  };
  return {
    ...base,
    capture: { ...base.capture, generation, stageDirectory: stage },
    upload: { ...base.upload, generation, stageDirectory: stage },
    recipient,
    recipientKey: keys.key1,
  };
}

async function removeFixture(fixture: RuntimeFixture): Promise<void> {
  try {
    await Deno.remove(fixture.stage, { recursive: true });
  } catch {
    // Best effort only; the test outcome is already decided.
  }
}

async function writePrivateFile(
  path: string,
  bytes: Uint8Array | string,
): Promise<void> {
  const content = typeof bytes === "string"
    ? new TextEncoder().encode(bytes)
    : bytes;
  await Deno.writeFile(path, content);
  await Deno.chmod(path, 0o600);
}

/** Write a coherent owner-only local published state (plaintext, ciphertext,
 * capture recipient pin, staged recipient copy, public home and state
 * journal) exactly as a prior successful encryption+publish left it; the
 * resume path must accept it. */
async function prepareCraftedState(
  fixture: RuntimeFixture,
  options: {
    ciphertext?: Uint8Array;
    stateOverrides?: (state: Record<string, unknown>) => void;
    withReceipt?: boolean;
  } = {},
): Promise<{ ciphertext: Uint8Array }> {
  const ciphertext = options.ciphertext ??
    filler(202, 8192);
  const plaintext = canonicalText(fixture);
  const objectName = indexObjectFor(fixture.capture.generation);
  await writePrivateFile(
    `${fixture.stage}/recovery-index.json`,
    plaintext,
  );
  await writePrivateFile(
    `${fixture.stage}/recovery-index.json.gpg`,
    ciphertext,
  );
  await writePrivateFile(
    `${fixture.stage}/recipient.asc`,
    fixture.recipientKey.publicBytes,
  );
  await writePrivateFile(
    `${fixture.stage}/index-recipient.asc`,
    fixture.recipientKey.publicBytes,
  );
  const home = `${fixture.stage}/index-public-home`;
  await Deno.mkdir(home, { mode: 0o700 });
  await Deno.chmod(home, 0o700);
  const state: Record<string, unknown> = {
    schemaVersion: 1,
    generation: fixture.capture.generation,
    stageDirectory: fixture.stage,
    objectName,
    indexSha256: sha256Hex(new TextEncoder().encode(plaintext)),
    recipientSha256: fixture.recipient.recipientSha256,
    recipientFingerprint: fixture.recipient.recipientFingerprint,
    ciphertextBytes: ciphertext.byteLength,
    ciphertextSha256: sha256Hex(ciphertext),
    createdAtUtc: "2026-09-06T00:00:04.000Z",
  };
  options.stateOverrides?.(state);
  await writePrivateFile(
    `${fixture.stage}/recovery-index-state.json`,
    JSON.stringify(state),
  );
  if (options.withReceipt === true) {
    await writePrivateFile(
      `${fixture.stage}/recovery-index-receipt.json`,
      JSON.stringify({
        schemaVersion: 1,
        generation: fixture.capture.generation,
        stageDirectory: fixture.stage,
        objectName,
        indexSha256: sha256Hex(new TextEncoder().encode(plaintext)),
        ciphertextBytes: ciphertext.byteLength,
        ciphertextSha256: sha256Hex(ciphertext),
        recipientSha256: fixture.recipient.recipientSha256,
        recipientFingerprint: fixture.recipient.recipientFingerprint,
        fileId: "file-saved-version",
        uploadTimestamp: 1_800_000_000_000,
        publishedAtUtc: "2026-09-06T00:00:05.000Z",
        reused: false,
        uploadVerified: true,
        decryptedRestoreProved: false,
        machineBootRestoreProved: false,
      }),
    );
  }
  return { ciphertext };
}

interface FakeVersion {
  object: B2Object;
  bytes: Uint8Array;
}

class FakeStore {
  private byName = new Map<string, FakeVersion[]>();
  private byId = new Map<string, Uint8Array>();
  private nextId = 1;
  private nextTimestamp = 1_800_000_000_000;
  putCalls = 0;
  getCalls: string[] = [];
  versionsCalls = 0;
  putHandler:
    | ((fileName: string) => { error: Error; store: boolean } | undefined)
    | null = null;
  getHandler: ((fileId: string) => Uint8Array | undefined) | null = null;
  /** Raw inventory override (malformed entries included) for visible
   * rejection coverage. */
  versionsHandler: (() => B2Object[]) | null = null;
  /** When false the store skips its own length/SHA-1 verification so the
   * module-level SHA-256/byte readback check is what must fail. */
  verifyContent = true;

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
    this.byId.set(object.fileId, new Uint8Array(bytes));
  }

  put(fileName: string, bytes: Uint8Array): Promise<B2Object> {
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
    if (this.verifyContent) {
      if (bytes.byteLength !== object.contentLength) {
        return Promise.reject(new Error("get failed: content length mismatch"));
      }
      if (sha1Hex(bytes) !== object.contentSha1) {
        return Promise.reject(new Error("get failed: content sha1 mismatch"));
      }
    }
    return Promise.resolve(new Uint8Array(bytes));
  }

  versions(): Promise<B2Object[]> {
    this.versionsCalls += 1;
    if (this.versionsHandler !== null) {
      return Promise.resolve(this.versionsHandler());
    }
    const out: B2Object[] = [];
    for (const list of this.byName.values()) {
      for (const version of list) out.push(version.object);
    }
    return Promise.resolve(out);
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

async function fileMode(path: string): Promise<number> {
  const info = await Deno.lstat(path);
  return (info.mode ?? 0) & 0o777;
}

async function readReceipt(fixture: RuntimeFixture): Promise<{
  schemaVersion: number;
  fileId: string;
  uploadTimestamp: number;
  publishedAtUtc: string;
  reused: boolean;
  uploadVerified: boolean;
  decryptedRestoreProved: boolean;
  machineBootRestoreProved: boolean;
  indexSha256: string;
}> {
  const text = await Deno.readTextFile(
    `${fixture.stage}/recovery-index-receipt.json`,
  );
  return JSON.parse(text) as {
    schemaVersion: number;
    fileId: string;
    uploadTimestamp: number;
    publishedAtUtc: string;
    reused: boolean;
    uploadVerified: boolean;
    decryptedRestoreProved: boolean;
    machineBootRestoreProved: boolean;
    indexSha256: string;
  };
}

const LOCAL_FIXED_FILES = [
  "recovery-index.json",
  "recovery-index.json.gpg",
  "recovery-index-receipt.json",
  "recovery-index-state.json",
  "index-recipient.asc",
  "recovery-index.json.gpg.partial",
] as const;

/** Read-only snapshot of the fixed local files (null when absent). */
async function snapshotLocalState(
  fixture: RuntimeFixture,
): Promise<Map<string, Uint8Array | null>> {
  const snapshot = new Map<string, Uint8Array | null>();
  for (const name of LOCAL_FIXED_FILES) {
    const path = `${fixture.stage}/${name}`;
    try {
      snapshot.set(name, await Deno.readFile(path));
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) snapshot.set(name, null);
      else throw error;
    }
  }
  return snapshot;
}

/** A failed publish must not create, rewrite or delete any fixed local file
 * (no re-encryption, no partial leftovers, no silent cleanup). */
async function assertLocalStatePreserved(
  fixture: RuntimeFixture,
  before: Map<string, Uint8Array | null>,
): Promise<void> {
  for (const [name, bytes] of before) {
    const path = `${fixture.stage}/${name}`;
    let after: Uint8Array | null;
    try {
      after = await Deno.readFile(path);
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) after = null;
      else throw error;
    }
    if (bytes === null) {
      assert(after === null, `${name}: must not be created`);
    } else {
      assert(after !== null, `${name}: must not be deleted`);
      assertBytes(after, bytes);
    }
  }
}

// ---------------------------------------------------------------------------
// Runtime tests — real fixtures, synthetic store only.
// ---------------------------------------------------------------------------

runtimeTest(
  "real synthetic gpg encryption round trip with private-key decryption",
  async () => {
    // The private test keyring lives in a short directory of its own (never
    // in the long realpath'd stage) because the gpg-agent socket path is
    // limited on macOS; the module's own public-only gpg runs never start an
    // agent.
    const keys = await ensureSyntheticKeys();
    const fixture = await makeRuntimeFixture();
    try {
      const store = new FakeStore();
      const published = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(published.generation === fixture.capture.generation);
      assert(
        published.indexSha256 === sha256Hex(
          new TextEncoder().encode(canonicalText(fixture)),
        ),
      );
      assert(published.uploadVerified === true);
      assert(published.decryptedRestoreProved === false);
      assert(published.machineBootRestoreProved === false);
      assert(
        published.object.fileName ===
          indexObjectFor(fixture.capture.generation),
      );
      assert(published.object.action === "upload");
      // Plaintext file: canonical JSON, owner-only.
      const plaintextOnDisk = await Deno.readTextFile(
        `${fixture.stage}/recovery-index.json`,
      );
      assert(plaintextOnDisk === canonicalText(fixture));
      assert(
        (await fileMode(`${fixture.stage}/recovery-index.json`)) === 0o600,
      );
      // Ciphertext published and read back exactly; exact-ID readback.
      const localCipher = await Deno.readFile(
        `${fixture.stage}/recovery-index.json.gpg`,
      );
      assert(published.ciphertextBytes === localCipher.byteLength);
      assert(published.ciphertextSha256 === sha256Hex(localCipher));
      assert(
        published.object.contentLength === localCipher.byteLength &&
          published.object.contentSha1 === sha1Hex(localCipher),
      );
      assert(store.putCalls === 1);
      assert(store.getCalls.length === 1);
      assert(store.getCalls[0] === published.object.fileId);
      const stored = store.bytesForName(
        indexObjectFor(fixture.capture.generation),
      )!;
      assertBytes(stored, localCipher);
      assert(
        (await fileMode(
          `${fixture.stage}/recovery-index.json.gpg`,
        )) === 0o600,
      );
      assert(
        (await fileMode(
          `${fixture.stage}/recovery-index-state.json`,
        )) === 0o600,
      );
      assert(
        (await fileMode(
          `${fixture.stage}/recovery-index-receipt.json`,
        )) === 0o600,
      );
      const receipt = await readReceipt(fixture);
      assert(receipt.fileId === published.object.fileId);
      assert(receipt.reused === false);
      assert(receipt.indexSha256 === published.indexSha256);
      assert(receipt.schemaVersion === 1);
      // Real private-key decryption of the generated synthetic fixture only.
      const decrypted = new Deno.Command("gpg", {
        args: [
          "--batch",
          "--pinentry-mode",
          "loopback",
          "--passphrase",
          "",
          "--homedir",
          keys.key1.keyHome,
          "--decrypt",
          `${fixture.stage}/recovery-index.json.gpg`,
        ],
      });
      const out = await decrypted.output();
      assert(out.code === 0, `decrypt failed: ${out.code}`);
      assert(
        new TextDecoder().decode(out.stdout) === canonicalText(fixture),
        "decrypted plaintext must equal the canonical index JSON",
      );
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "lost put response is reconciled with one refresh and no reupload",
  async () => {
    const fixture = await makeRuntimeFixture();
    const { ciphertext } = await prepareCraftedState(fixture);
    const store = new FakeStore();
    store.putHandler = () => ({
      error: new Error("put failed (network error)"),
      store: true,
    });
    try {
      const published = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(published.uploadVerified === true);
      assert(store.putCalls === 1, "the ambiguous put must not repeat");
      assert(store.getCalls.length === 1);
      const receipt = await readReceipt(fixture);
      assert(receipt.reused === true);
      assert(receipt.fileId === published.object.fileId);
      const stored = store.bytesForName(
        indexObjectFor(fixture.capture.generation),
      )!;
      assertBytes(stored, ciphertext);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "ambiguous put with absent object rethrows and completes on retry",
  async () => {
    const fixture = await makeRuntimeFixture();
    await prepareCraftedState(fixture);
    const store = new FakeStore();
    store.putHandler = () => ({
      error: new Error("put failed (network error)"),
      store: false,
    });
    try {
      const putAttempts = (): number => store.putCalls;
      const error = await rejectWith(
        publishRecoveryIndex(
          fixture.capture,
          fixture.upload,
          fixture.recipient,
          store,
        ),
      );
      assert(error.message === "put failed (network error)");
      assert(putAttempts() === 1, "no second upload after reconciliation");
      assert(store.totalVersionCount() === 0);
      let absent = false;
      try {
        await Deno.lstat(`${fixture.stage}/recovery-index-receipt.json`);
      } catch (e) {
        absent = e instanceof Deno.errors.NotFound;
      }
      assert(absent, "no receipt before verified readback");
      // Corrected retry: fresh run puts it once and verifies by readback.
      store.putHandler = null;
      const published = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(published.uploadVerified === true);
      assert(putAttempts() === 2, "one fresh put on the retry");
      const receipt = await readReceipt(fixture);
      assert(receipt.reused === false);
      assert(receipt.fileId === published.object.fileId);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "retry reuses the identical ciphertext and never re-encrypts",
  async () => {
    const fixture = await makeRuntimeFixture();
    const { ciphertext } = await prepareCraftedState(fixture);
    const beforeGpg = await Deno.readFile(
      `${fixture.stage}/recovery-index.json.gpg`,
    );
    const beforeState = await Deno.readFile(
      `${fixture.stage}/recovery-index-state.json`,
    );
    const store = new FakeStore();
    store.seed(indexObjectFor(fixture.capture.generation), ciphertext);
    try {
      const published = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(published.uploadVerified === true);
      assert(
        store.putCalls === 0,
        "a matching version must be reused, not put",
      );
      assert(store.getCalls.length === 1);
      const afterGpg = await Deno.readFile(
        `${fixture.stage}/recovery-index.json.gpg`,
      );
      const afterState = await Deno.readFile(
        `${fixture.stage}/recovery-index-state.json`,
      );
      assertBytes(afterGpg, beforeGpg);
      assertBytes(afterState, beforeState);
      const receipt = await readReceipt(fixture);
      assert(receipt.reused === true);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "duplicate identical versions are preserved; saved version is preferred",
  async () => {
    const fixture = await makeRuntimeFixture();
    const { ciphertext } = await prepareCraftedState(fixture);
    const store = new FakeStore();
    const older = store.seed(
      indexObjectFor(fixture.capture.generation),
      ciphertext,
      {
        fileId: "file-older",
        uploadTimestamp: 1_800_000_000_000,
      },
    );
    const newer = store.seed(
      indexObjectFor(fixture.capture.generation),
      ciphertext,
      {
        fileId: "file-newer",
        uploadTimestamp: 1_800_000_000_100,
      },
    );
    try {
      // No receipt: newest identical version is selected as membership.
      const first = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(first.object.fileId === newer.fileId);
      assert(store.putCalls === 0);
      assert(store.totalVersionCount() === 2, "duplicates are preserved");
      const receipt = await readReceipt(fixture);
      assert(receipt.fileId === newer.fileId);
      // Receipt-saved version present: the saved exact version is selected.
      await writePrivateFile(
        `${fixture.stage}/recovery-index-receipt.json`,
        JSON.stringify({
          schemaVersion: 1,
          generation: fixture.capture.generation,
          stageDirectory: fixture.stage,
          objectName: indexObjectFor(fixture.capture.generation),
          indexSha256: sha256Hex(
            new TextEncoder().encode(canonicalText(fixture)),
          ),
          ciphertextBytes: ciphertext.byteLength,
          ciphertextSha256: sha256Hex(ciphertext),
          recipientSha256: fixture.recipient.recipientSha256,
          recipientFingerprint: fixture.recipient.recipientFingerprint,
          fileId: older.fileId,
          uploadTimestamp: older.uploadTimestamp,
          publishedAtUtc: "2026-09-06T00:00:05.000Z",
          reused: false,
          uploadVerified: true,
          decryptedRestoreProved: false,
          machineBootRestoreProved: false,
        }),
      );
      const second = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(second.object.fileId === older.fileId, "saved version preferred");
      assert(store.totalVersionCount() === 2, "duplicates still preserved");
      const receipt2 = await readReceipt(fixture);
      assert(receipt2.fileId === older.fileId);
      assert(
        receipt2.publishedAtUtc === "2026-09-06T00:00:05.000Z",
        "the same selected version keeps its original publication time",
      );
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "conflicting content, hide markers and unexpected names fail closed",
  async () => {
    const cases: Array<[
      string,
      (fixture: RuntimeFixture) => {
        bytes: Uint8Array;
        overrides?: Partial<B2Object>;
        name?: string;
      },
      string,
    ]> = [
      [
        "conflicting content",
        (_fixture) => ({ bytes: filler(301, 4096) }),
        "inventory:conflict",
      ],
      [
        "hide marker",
        (_fixture) => ({
          bytes: filler(302, 8192),
          overrides: { action: "hide" },
        }),
        "inventory:action",
      ],
      [
        "unexpected name",
        (fixture) => ({
          bytes: filler(303, 4096),
          name: indexObjectFor(fixture.capture.generation).replace(
            "index.json.gpg",
            "extra",
          ),
        }),
        "inventory:unexpected-object",
      ],
    ];
    for (const [label, seed, expected] of cases) {
      const fixture = await makeRuntimeFixture();
      const crafted = await prepareCraftedState(fixture);
      const store = new FakeStore();
      const seeded = seed(fixture);
      const objectName = indexObjectFor(fixture.capture.generation);
      if (seeded.name !== undefined) {
        store.seed(seeded.name, crafted.ciphertext);
      } else {
        store.seed(objectName, seeded.bytes, seeded.overrides);
      }
      try {
        const error = await rejectWith(
          publishRecoveryIndex(
            fixture.capture,
            fixture.upload,
            fixture.recipient,
            store,
          ),
        );
        assert(
          error.message.includes(expected),
          `${label}: ${error.message}`,
        );
        assert(store.putCalls === 0, `${label}: no put after failure`);
        assert(store.getCalls.length === 0, `${label}: no readback allowed`);
      } finally {
        await removeFixture(fixture);
      }
    }
  },
);

runtimeTest(
  "readback corruption is caught by module SHA-256 and byte equality",
  async () => {
    const fixture = await makeRuntimeFixture();
    const { ciphertext } = await prepareCraftedState(fixture);
    const store = new FakeStore();
    store.verifyContent = false;
    store.seed(indexObjectFor(fixture.capture.generation), ciphertext);
    const corrupted = new Uint8Array(ciphertext);
    corrupted[0] = corrupted[0] ^ 0xff;
    store.getHandler = () => corrupted;
    try {
      const error = await rejectWith(
        publishRecoveryIndex(
          fixture.capture,
          fixture.upload,
          fixture.recipient,
          store,
        ),
      );
      assert(error.message.includes("publish:readback"), error.message);
      assert(store.putCalls === 0);
      let absent = false;
      try {
        await Deno.lstat(`${fixture.stage}/recovery-index-receipt.json`);
      } catch (e) {
        absent = e instanceof Deno.errors.NotFound;
      }
      assert(absent, "no receipt without verified readback");
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "invalid durable state fails visibly before any store call",
  async () => {
    const scenarios: Array<[
      string,
      (fixture: RuntimeFixture) => Promise<void>,
      string,
    ]> = [
      [
        "ciphertext without state",
        async (fixture) => {
          await writePrivateFile(
            `${fixture.stage}/recovery-index.json.gpg`,
            filler(401, 4096),
          );
        },
        "state:incomplete",
      ],
      [
        "stale index hash",
        async (fixture) => {
          await prepareCraftedState(fixture, {
            stateOverrides: (state) => {
              state.indexSha256 = "0".repeat(64);
            },
          });
        },
        "state:index",
      ],
      [
        "changed recipient",
        async (fixture) => {
          await prepareCraftedState(fixture, {
            stateOverrides: (state) => {
              state.recipientSha256 = "f".repeat(64);
            },
          });
        },
        "state:recipient",
      ],
      [
        "missing ciphertext",
        async (fixture) => {
          await prepareCraftedState(fixture);
          await Deno.remove(`${fixture.stage}/recovery-index.json.gpg`);
        },
        "state:ciphertext",
      ],
      [
        "mismatched plaintext",
        async (fixture) => {
          await prepareCraftedState(fixture);
          await writePrivateFile(
            `${fixture.stage}/recovery-index.json`,
            "{not the canonical index}",
          );
        },
        "state:plaintext",
      ],
      [
        "wrong ciphertext size",
        async (fixture) => {
          const long = new Uint8Array(9000);
          long.set(filler(402, 8192), 0);
          await prepareCraftedState(fixture, { ciphertext: long });
          await writePrivateFile(
            `${fixture.stage}/recovery-index.json.gpg`,
            long.subarray(0, 8192),
          );
        },
        "state:ciphertext",
      ],
      [
        "conflicting receipt",
        async (fixture) => {
          await prepareCraftedState(fixture, { withReceipt: true });
          const receipt = JSON.parse(
            await Deno.readTextFile(
              `${fixture.stage}/recovery-index-receipt.json`,
            ),
          ) as Record<string, unknown>;
          receipt.indexSha256 = "1".repeat(64);
          await writePrivateFile(
            `${fixture.stage}/recovery-index-receipt.json`,
            JSON.stringify(receipt),
          );
        },
        "receipt:index",
      ],
      [
        "tampered receipt generation",
        async (fixture) => {
          await prepareCraftedState(fixture, { withReceipt: true });
          const receipt = JSON.parse(
            await Deno.readTextFile(
              `${fixture.stage}/recovery-index-receipt.json`,
            ),
          ) as Record<string, unknown>;
          receipt.generation =
            "generation-99999999-9999-9999-9999-999999999999";
          await writePrivateFile(
            `${fixture.stage}/recovery-index-receipt.json`,
            JSON.stringify(receipt),
          );
        },
        "receipt:generation",
      ],
      [
        "tampered receipt stage",
        async (fixture) => {
          await prepareCraftedState(fixture, { withReceipt: true });
          const receipt = JSON.parse(
            await Deno.readTextFile(
              `${fixture.stage}/recovery-index-receipt.json`,
            ),
          ) as Record<string, unknown>;
          receipt.stageDirectory = "/var/tmp/elsewhere";
          await writePrivateFile(
            `${fixture.stage}/recovery-index-receipt.json`,
            JSON.stringify(receipt),
          );
        },
        "receipt:stage",
      ],
      [
        "receipt without state",
        async (fixture) => {
          await prepareCraftedState(fixture, { withReceipt: true });
          await Deno.remove(`${fixture.stage}/recovery-index-state.json`);
        },
        "state:incomplete",
      ],
      [
        "plaintext-only interrupted preparation",
        async (fixture) => {
          // Exactly what an interruption between the plaintext write and the
          // encryption leaves behind: nothing but the canonical plaintext.
          await writePrivateFile(
            `${fixture.stage}/recovery-index.json`,
            canonicalText(fixture),
          );
        },
        "state:incomplete",
      ],
    ];
    for (const [label, prepare, expected] of scenarios) {
      const fixture = await makeRuntimeFixture();
      const store = new FakeStore();
      try {
        await prepare(fixture);
        const before = await snapshotLocalState(fixture);
        const error = await rejectWith(
          publishRecoveryIndex(
            fixture.capture,
            fixture.upload,
            fixture.recipient,
            store,
          ),
        );
        assert(
          error.message.includes(expected),
          `${label}: ${error.message}`,
        );
        assert(store.putCalls === 0, `${label}: no put`);
        assert(store.versionsCalls === 0, `${label}: no inventory`);
        assert(store.getCalls.length === 0, `${label}: no readback`);
        await assertLocalStatePreserved(fixture, before);
      } finally {
        await removeFixture(fixture);
      }
    }
  },
);

runtimeTest(
  "interrupted encryption partial fails clearly and is preserved",
  async () => {
    const fixture = await makeRuntimeFixture();
    const partial = `${fixture.stage}/recovery-index.json.gpg.partial`;
    await writePrivateFile(partial, filler(501, 2048));
    const store = new FakeStore();
    try {
      const error = await rejectWith(
        publishRecoveryIndex(
          fixture.capture,
          fixture.upload,
          fixture.recipient,
          store,
        ),
      );
      assert(error.message.includes("ciphertext:partial"), error.message);
      assert(store.putCalls === 0);
      const info = await Deno.lstat(partial);
      assert(info.isFile, "the task-owned partial must not be removed");
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest("filesystem mode and symlink protection", async () => {
  const scenarios: Array<[
    string,
    (fixture: RuntimeFixture) => Promise<void>,
    string,
  ]> = [
    [
      "stage group permissions",
      async (fixture) => {
        await Deno.chmod(fixture.stage, 0o755);
      },
      "stage:permissions",
    ],
    [
      "state symlink",
      async (fixture) => {
        await Deno.symlink(
          "missing-target",
          `${fixture.stage}/recovery-index-state.json`,
        );
      },
      "state:",
    ],
    [
      "ciphertext group permissions",
      async (fixture) => {
        await writePrivateFile(
          `${fixture.stage}/recovery-index.json.gpg`,
          filler(502, 2048),
        );
        await Deno.chmod(`${fixture.stage}/recovery-index.json.gpg`, 0o640);
      },
      "ciphertext:",
    ],
    [
      "receipt hardlink",
      async (fixture) => {
        const target = `${fixture.stage}/receipt-hard-target`;
        await writePrivateFile(target, "{}");
        await Deno.link(target, `${fixture.stage}/recovery-index-receipt.json`);
        // The target stays linked: nlink must be 2 when the module checks.
      },
      "receipt:",
    ],
    [
      "recipient source permissions",
      async (fixture) => {
        await writePrivateFile(
          `${fixture.stage}/recipient-source.asc`,
          fixture.recipientKey.publicBytes,
        );
        await Deno.chmod(`${fixture.stage}/recipient-source.asc`, 0o644);
      },
      "recipient:",
    ],
    [
      "capture recipient missing",
      async (fixture) => {
        await Deno.remove(`${fixture.stage}/recipient.asc`);
      },
      "recipient:capture",
    ],
    [
      "capture recipient hardlink",
      async (fixture) => {
        const target = `${fixture.stage}/capture-recipient-extra`;
        await Deno.link(`${fixture.stage}/recipient.asc`, target);
        // The extra name stays linked: nlink must be 2 when the module
        // checks the capture recipient.
      },
      "recipient:",
    ],
    [
      "capture recipient symlink",
      async (fixture) => {
        await Deno.remove(`${fixture.stage}/recipient.asc`);
        await Deno.symlink(
          "missing-target",
          `${fixture.stage}/recipient.asc`,
        );
      },
      "recipient:",
    ],
  ];
  for (const [label, prepare, expected] of scenarios) {
    const fixture = await makeRuntimeFixture();
    const store = new FakeStore();
    try {
      await prepare(fixture);
      const error = await rejectWith(
        publishRecoveryIndex(
          fixture.capture,
          fixture.upload,
          fixture.recipient,
          store,
        ),
      );
      assert(
        error.message.startsWith("Index failed (") &&
          error.message.includes(expected),
        `${label}: ${error.message}`,
      );
      assert(store.putCalls === 0, `${label}: no put`);
      assert(store.versionsCalls === 0, `${label}: no inventory`);
      assert(store.getCalls.length === 0, `${label}: no readback`);
    } finally {
      await removeFixture(fixture);
    }
  }
});

runtimeTest(
  "a different valid supplied key is rejected on fresh publish",
  async () => {
    const keys = await ensureSyntheticKeys();
    const fixture = await makeRuntimeFixture();
    const other = `${fixture.stage}/recipient-source-other.asc`;
    await writePrivateFile(other, keys.key2.publicBytes);
    fixture.recipient = {
      recipientFile: other,
      recipientSha256: sha256Hex(keys.key2.publicBytes),
      recipientFingerprint: keys.key2.fingerprint,
    };
    const store = new FakeStore();
    try {
      const error = await rejectWith(
        publishRecoveryIndex(
          fixture.capture,
          fixture.upload,
          fixture.recipient,
          store,
        ),
      );
      assert(error.message.includes("recipient:capture"), error.message);
      assert(store.putCalls === 0, "no put for a rejected key");
      assert(store.versionsCalls === 0, "no inventory for a rejected key");
      for (
        const name of [
          "recovery-index.json",
          "recovery-index.json.gpg",
          "recovery-index-state.json",
          "recovery-index-receipt.json",
          "index-recipient.asc",
          "recovery-index.json.gpg.partial",
        ]
      ) {
        let absent = false;
        try {
          await Deno.lstat(`${fixture.stage}/${name}`);
        } catch (e) {
          absent = e instanceof Deno.errors.NotFound;
        }
        assert(absent, `${name} must not be created`);
      }
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "a different valid supplied key is rejected on resume before store calls",
  async () => {
    const keys = await ensureSyntheticKeys();
    const fixture = await makeRuntimeFixture();
    // Switch the supplied recipient to the OTHER valid key first so the
    // crafted state/journal is coherent with it while the capture recipient
    // artifact still pins the ORIGINAL key.
    const other = `${fixture.stage}/recipient-source-other.asc`;
    await writePrivateFile(other, keys.key2.publicBytes);
    fixture.recipient = {
      recipientFile: other,
      recipientSha256: sha256Hex(keys.key2.publicBytes),
      recipientFingerprint: keys.key2.fingerprint,
    };
    await prepareCraftedState(fixture);
    const statePath = `${fixture.stage}/recovery-index-state.json`;
    const ciphertextPath = `${fixture.stage}/recovery-index.json.gpg`;
    const beforeState = await Deno.readFile(statePath);
    const beforeCiphertext = await Deno.readFile(ciphertextPath);
    const store = new FakeStore();
    try {
      const error = await rejectWith(
        publishRecoveryIndex(
          fixture.capture,
          fixture.upload,
          fixture.recipient,
          store,
        ),
      );
      assert(error.message.includes("recipient:capture"), error.message);
      assert(store.putCalls === 0, "no put for a rejected key");
      assert(store.versionsCalls === 0, "no inventory for a rejected key");
      assert(store.getCalls.length === 0, "no readback for a rejected key");
      assertBytes(await Deno.readFile(statePath), beforeState);
      assertBytes(await Deno.readFile(ciphertextPath), beforeCiphertext);
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "arbitrary staging paths are rejected before any side effect",
  async () => {
    const fixture = await makeRuntimeFixture();
    const temp = await Deno.makeTempDir({ prefix: "b2-index-stage-" });
    const store = new FakeStore();
    try {
      const capture = {
        ...fixture.capture,
        stageDirectory: temp,
        archives: fixture.capture.archives.map((archive) => ({
          ...archive,
          path: `${temp}/${archive.role}.${archive.format}`,
        })),
      };
      const upload = {
        ...fixture.upload,
        stageDirectory: temp,
        archives: fixture.upload.archives.map((archive) => ({
          ...archive,
          path: `${temp}/${archive.role}.${archive.format}`,
        })),
      };
      const error = await rejectWith(
        publishRecoveryIndex(capture, upload, fixture.recipient, store),
      );
      assert(error.message.includes("stage:namespace"), error.message);
      assert(store.putCalls === 0, "no put for a rejected stage");
      assert(store.versionsCalls === 0, "no inventory for a rejected stage");
      assert(store.getCalls.length === 0, "no readback for a rejected stage");
    } finally {
      try {
        await Deno.remove(temp, { recursive: true });
      } catch {
        // Best effort only; the test outcome is already decided.
      }
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "malformed inventory entries fail closed before receipt construction",
  async () => {
    const cases: Array<[
      string,
      (fixture: RuntimeFixture) => B2Object[],
      string,
    ]> = [
      ["non-object entry", () => [null as never], "inventory:shape"],
      [
        "non-string fileName",
        () => [{
          fileId: "file-bad",
          fileName: 42 as never,
          contentLength: 1,
          contentSha1: "a1".repeat(20),
          action: "upload",
          uploadTimestamp: 1,
        }],
        "inventory:shape",
      ],
      [
        "negative uploadTimestamp",
        (fixture) => [{
          fileId: "file-bad",
          fileName: indexObjectFor(fixture.capture.generation),
          contentLength: 1,
          contentSha1: "a1".repeat(20),
          action: "upload",
          uploadTimestamp: -1,
        }],
        "inventory:object",
      ],
      [
        "malformed sha1",
        (fixture) => [{
          fileId: "file-bad",
          fileName: indexObjectFor(fixture.capture.generation),
          contentLength: 1,
          contentSha1: "not-a-sha1",
          action: "upload",
          uploadTimestamp: 1,
        }],
        "inventory:object",
      ],
    ];
    for (const [label, make, expected] of cases) {
      const fixture = await makeRuntimeFixture();
      await prepareCraftedState(fixture);
      const store = new FakeStore();
      store.versionsHandler = () => make(fixture);
      try {
        const error = await rejectWith(
          publishRecoveryIndex(
            fixture.capture,
            fixture.upload,
            fixture.recipient,
            store,
          ),
        );
        assert(error.message.includes(expected), `${label}: ${error.message}`);
        assert(store.putCalls === 0, `${label}: no put`);
        assert(store.getCalls.length === 0, `${label}: no readback`);
        let absent = false;
        try {
          await Deno.lstat(`${fixture.stage}/recovery-index-receipt.json`);
        } catch (e) {
          absent = e instanceof Deno.errors.NotFound;
        }
        assert(absent, `${label}: no receipt after failure`);
      } finally {
        await removeFixture(fixture);
      }
    }
  },
);

runtimeTest(
  "saved version missing from inventory is re-uploaded after fresh inventory",
  async () => {
    const fixture = await makeRuntimeFixture();
    const { ciphertext } = await prepareCraftedState(fixture, {
      withReceipt: true,
    });
    const store = new FakeStore();
    try {
      const startedAt = Date.now();
      const published = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(published.uploadVerified === true);
      assert(store.putCalls === 1, "missing saved version is put once");
      assert(
        published.object.fileId !== "file-saved-version",
        "a fresh version must be selected",
      );
      assertBytes(
        store.bytesForName(indexObjectFor(fixture.capture.generation))!,
        ciphertext,
      );
      const receipt = await readReceipt(fixture);
      assert(receipt.fileId === published.object.fileId);
      assert(receipt.reused === false);
      assert(
        receipt.uploadTimestamp === published.object.uploadTimestamp,
        "receipt must carry the newly selected version's timestamp",
      );
      // The replaced missing version is a NEW publication: the stale
      // publication time must not survive and the new time is current.
      assert(receipt.publishedAtUtc !== "2026-09-06T00:00:05.000Z");
      assert(
        Date.parse(receipt.publishedAtUtc) >= startedAt,
        "replacement publication time must be current",
      );
    } finally {
      await removeFixture(fixture);
    }
  },
);

runtimeTest(
  "publish retains read-back exact identity in the receipt",
  async () => {
    const fixture = await makeRuntimeFixture();
    const { ciphertext } = await prepareCraftedState(fixture);
    const store = new FakeStore();
    store.seed(indexObjectFor(fixture.capture.generation), ciphertext, {
      fileId: "file-pinned",
    });
    try {
      const published = await publishRecoveryIndex(
        fixture.capture,
        fixture.upload,
        fixture.recipient,
        store,
      );
      assert(published.object.fileId === "file-pinned");
      assert(published.object.contentLength === ciphertext.byteLength);
      assert(published.object.contentSha1 === sha1Hex(ciphertext));
      assert(store.getCalls.length === 1);
      assert(store.getCalls[0] === "file-pinned");
      const receipt = await readReceipt(fixture);
      assert(receipt.fileId === "file-pinned");
      assert(receipt.uploadTimestamp >= 0);
    } finally {
      await removeFixture(fixture);
    }
  },
);

// Keep PublishedIndex referenced so type regressions surface at check time.
export type PublishedIndexType = PublishedIndex;
