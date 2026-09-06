/**
 * Focused m07-source-worker tests.
 *
 * Pure tests cover the canonical request envelope/hash, the six-role source
 * configuration hash, the strict status validation and the derived m06 gate
 * identity. Runtime tests use injected private dependency boundaries: fake
 * capture/upload/publish phase functions, a fake clock, a manual heartbeat
 * scheduler, the real OS lock and one unique temporary persistence root; no
 * network, credential or real payload is touched. They exercise real local
 * persistence ordering, same-request resume without recapture, partial and
 * invalid stage failure, changed-identity rejection before work, deadline
 * handling, terminal persistence after expiry, delayed heartbeats and the
 * absence of any accept/prune path.
 *
 * Permission-dependent runtime cases are explicitly skipped in the default
 * permissionless mode; under `deno test --allow-read --allow-write` the same
 * cases run with zero skips.
 */
import { createHash } from "node:crypto";
import type {
  CaptureResult,
  CaptureSettings,
} from "../scripts/backblaze-capture.ts";
import {
  REQUIRED_EXCLUSIONS,
  ROLE_ORDER,
} from "../scripts/backblaze-capture.ts";
import type {
  IndexRecipient,
  PublishedIndex,
} from "../scripts/backblaze-index.ts";
import { buildRecoveryIndex } from "../scripts/backblaze-index.ts";
import type { UploadResult, UploadRole } from "../scripts/backblaze-upload.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
} from "../scripts/backblaze-upload.ts";
import type { B2Object } from "../scripts/backblaze-storage.ts";
import { DIRECT_PREFIX } from "../scripts/backblaze-storage.ts";
import { withBackupLock } from "../scripts/backup-lock.ts";
import {
  canonicalRequestString,
  canonicalSourceConfig,
  CAPTURE_RESULT_FILE,
  deriveWorkerGate,
  type HeartbeatScheduler,
  INDEX_RESULT_FILE,
  isRetriableB2Error,
  MAX_PHASE_ATTEMPTS,
  requestSha256Of,
  RETRY_SPACING_MS,
  runSourceWorker,
  SerialStatusQueue,
  sourceConfigSha256,
  type SourceWorkerDependencies,
  type SourceWorkerInputs,
  type StatusWriteTarget,
  UPLOAD_RESULT_FILE,
  validateRequest,
  validateRequestEnvelope,
  validateStatus,
  WorkerRejection,
  type WorkerRequest,
  type WorkerRequestEnvelope,
  type WorkerState,
  type WorkerStatus,
  workerUnitName,
} from "../scripts/backblaze-source-worker.ts";

// ---------------------------------------------------------------------------
// Test primitives
// ---------------------------------------------------------------------------

function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) throw new Error(message ?? "Assertion failed");
}

function assertThrowsSync(
  run: () => unknown,
  messageIncludes?: string,
): string {
  try {
    run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert(
      !messageIncludes || message.includes(messageIncludes),
      `Expected error to include ${messageIncludes}, got ${message}`,
    );
    return message;
  }
  throw new Error("Expected the call to throw");
}

async function assertThrowsAsync(
  run: () => Promise<unknown>,
  messageIncludes?: string,
): Promise<string> {
  try {
    await run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert(
      !messageIncludes || message.includes(messageIncludes),
      `Expected error to include ${messageIncludes}, got ${message}`,
    );
    return message;
  }
  throw new Error("Expected the call to throw");
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

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
  fn: () => void | Promise<void>,
): void {
  Deno.test({ name: `runtime: ${name}`, ignore: !runtimePermitted, fn });
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const UUID = "681c4067-aec2-45d5-9afb-77ee530e3a97";
const GENERATION = `generation-${UUID}`;
const JOB_ID = `job-${UUID}`;
const PERIOD_KEY = "2026-09-06";
const REQUESTED_AT = "2026-09-06T04:00:00.000Z";
const DEADLINE_AT = "2026-09-06T10:00:00.000Z";
const CAPTURE_STARTED = "2026-09-06T04:05:00.000Z";
const CAPTURE_FINISHED = "2026-09-06T04:06:00.000Z";
const UPLOAD_STARTED = "2026-09-06T04:06:30.000Z";
const UPLOAD_FINISHED = "2026-09-06T04:08:00.000Z";
const INVOCATION_ID = "0123456789abcdef0123456789abcdef";
const SOURCE_REVISION = "a".repeat(40);
const RECIPIENT_FINGERPRINT = "A".repeat(40);
const RECIPIENT_FILE = "/var/tmp/recipient.asc";
const FAKE_RECIPIENT_BYTES = new TextEncoder().encode(
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake public key bytes only\n" +
    "-----END PGP PUBLIC KEY BLOCK-----\n",
);
const RECIPIENT_SHA256 = sha256Hex(FAKE_RECIPIENT_BYTES);
const HEARTBEAT_START = Date.parse(REQUESTED_AT) + 30 * 60_000; // 04:30:00Z

const FILESYSTEMS: Record<string, "ext4" | "xfs" | "vfat"> = {
  root: "ext4",
  efi: "vfat",
  "staging-boot": "xfs",
  "staging-efi": "vfat",
  "oracle-root": "xfs",
  "oracle-oled": "xfs",
};

function makeSettings(): CaptureSettings {
  return {
    sources: ROLE_ORDER.map((role, index) => ({
      name: role,
      uuid: `00000000-0000-0000-0000-${String(index + 1).padStart(12, "0")}`,
      filesystem: FILESYSTEMS[role],
      size: 50 * 1024 ** 3 * (role === "root" ? 3 : 1),
      ...(role === "root"
        ? { livePath: "/" as const }
        : role === "efi"
        ? { livePath: "/efi" as const }
        : {}),
    })),
    generation: GENERATION,
    recipientFile: RECIPIENT_FILE,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    exclusionsText: REQUIRED_EXCLUSIONS.join("\n"),
  };
}

function makeRequest(overrides: Partial<WorkerRequest> = {}): WorkerRequest {
  return {
    schemaVersion: 1,
    jobId: JOB_ID,
    periodKey: PERIOD_KEY,
    generation: GENERATION,
    requestedAtUtc: REQUESTED_AT,
    deadlineAtUtc: DEADLINE_AT,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    sourceRevision: SOURCE_REVISION,
    sourceConfigSha256: sourceConfigSha256(makeSettings()),
    ...overrides,
  };
}

function makeEnvelope(
  overrides: Partial<WorkerRequest> = {},
): WorkerRequestEnvelope {
  const request = makeRequest(overrides);
  return {
    request,
    requestSha256: requestSha256Of(request),
  };
}

function makeIndexRecipient(): IndexRecipient {
  return {
    recipientFile: RECIPIENT_FILE,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
  };
}

function formatFor(role: string): "tar.zst.gpg" | "json.zst.gpg" {
  return role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
}

function makeCaptureResult(stagePath: string): CaptureResult {
  const archives = UPLOAD_ROLE_ORDER.map((role, index) => {
    const bytes = 4096 + index * 137;
    return {
      role,
      path: `${stagePath}/${role}.${formatFor(role)}`,
      bytes,
      sha256: sha256Hex(new Uint8Array([index + 1])),
      format: formatFor(role),
    };
  });
  return {
    generation: GENERATION,
    stageDirectory: stagePath,
    archives,
    startedAtUtc: CAPTURE_STARTED,
    finishedAtUtc: CAPTURE_FINISHED,
    consistency: "live-file-copy",
    sourceShutdown: false,
  };
}

function makeUploadResult(capture: CaptureResult): UploadResult {
  const archives = UPLOAD_ROLE_ORDER.map((role, index) => {
    const cap = capture.archives.find((entry) => entry.role === role)!;
    const name = generationChunkName(GENERATION, role, 0);
    const sha1 = sha1Hex(new Uint8Array([index + 10]));
    return {
      role,
      format: cap.format,
      path: cap.path,
      bytes: cap.bytes,
      sha256: cap.sha256,
      chunks: [{
        role: role as UploadRole,
        index: 0,
        name,
        size: cap.bytes,
        sha256: cap.sha256,
        sha1,
        fileId: `file-${role}`,
        uploadTimestamp: 1_800_000_000_000 + index,
        verifiedAtUtc: UPLOAD_FINISHED,
        reused: false,
        versions: [{
          fileId: `file-${role}`,
          fileName: name,
          contentLength: cap.bytes,
          contentSha1: sha1,
          action: "upload" as const,
          uploadTimestamp: 1_800_000_000_000 + index,
        }],
      }],
      verifiedAtUtc: UPLOAD_FINISHED,
    };
  });
  return {
    generation: GENERATION,
    stageDirectory: capture.stageDirectory,
    archives,
    chunkCount: archives.length,
    totalBytes: archives.reduce((sum, archive) => sum + archive.bytes, 0),
    duplicateVersions: [],
    startedAtUtc: UPLOAD_STARTED,
    finishedAtUtc: UPLOAD_FINISHED,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}

function makePublishedIndex(
  capture: CaptureResult,
  upload: UploadResult,
  recipient: IndexRecipient,
): PublishedIndex {
  const index = buildRecoveryIndex(capture, upload, recipient);
  const indexSha256 = sha256Hex(
    new TextEncoder().encode(JSON.stringify(index)),
  );
  return {
    generation: GENERATION,
    object: {
      fileId: `file-index-${UUID}`,
      fileName: `${DIRECT_PREFIX}indexes/${GENERATION}/index.json.gpg`,
      contentLength: 512,
      contentSha1: "1".repeat(40),
      action: "upload",
      uploadTimestamp: 1_800_000_000_100,
    },
    ciphertextBytes: 512,
    ciphertextSha256: "2".repeat(64),
    indexSha256,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
}

/** In-memory store replacement with a remove spy; the worker must never
 * accept, prune or delete anything. */
class FakeStore {
  putCalls = 0;
  getCalls = 0;
  versionsCalls = 0;
  removeCalls = 0;

  put(_fileName: string, _bytes: Uint8Array): Promise<B2Object> {
    this.putCalls += 1;
    return Promise.resolve({
      fileId: "file-put",
      fileName: _fileName,
      contentLength: _bytes.byteLength,
      contentSha1: "0".repeat(40),
      action: "upload",
      uploadTimestamp: 0,
    });
  }

  get(_object: B2Object): Promise<Uint8Array> {
    this.getCalls += 1;
    return Promise.resolve(new Uint8Array());
  }

  versions(): Promise<B2Object[]> {
    this.versionsCalls += 1;
    return Promise.resolve([]);
  }

  remove(): Promise<void> {
    this.removeCalls += 1;
    return Promise.resolve();
  }
}

interface FakeClock {
  now: () => Date;
  set: (ms: number) => void;
  advance: (ms: number) => void;
  get: () => number;
}

function makeClock(startMs: number): FakeClock {
  let current = startMs;
  return {
    now: () => new Date(current),
    set: (ms: number) => {
      current = ms;
    },
    advance: (ms: number) => {
      current += ms;
    },
    get: () => current,
  };
}

interface HeartbeatController extends HeartbeatScheduler {
  fire: () => void;
  isStopped: () => boolean;
  activeCallbacks: number;
}

function makeHeartbeatController(): HeartbeatController {
  let callback: (() => void) | null = null;
  let stopped = false;
  return {
    start(cb: () => void): () => void {
      callback = cb;
      return () => {
        stopped = true;
        callback = null;
      };
    },
    fire: () => callback?.(),
    isStopped: () => stopped,
    activeCallbacks: 1,
  };
}

interface PhaseProbe {
  captureCalls: number;
  uploadCalls: number;
  publishCalls: number;
  captureArgs: CaptureSettings[];
  uploadArgs: CaptureResult[];
  publishArgs: {
    capture: CaptureResult;
    upload: UploadResult;
    recipient: IndexRecipient;
  }[];
  /** Every injected retry wait in milliseconds, in order. */
  sleepCalls: number[];
  /** Called inside the fake sleep before its clock advance. */
  sleepHook?: (ms: number) => void | Promise<void>;
  /** Called inside the fake capture before it creates the stage. */
  captureHook?: () => void | Promise<void>;
  /** Called inside the fake upload after the result is formed. */
  uploadHook?: (capture: CaptureResult) => void | Promise<void>;
  /** Called inside the fake publish after the result is formed. */
  publishHook?: (
    capture: CaptureResult,
    upload: UploadResult,
  ) => void | Promise<void>;
}

interface RunFixture {
  basePath: string;
  stagePath: string;
  jobsPath: string;
  statusPath: string;
  resultPath: string;
  requestPath: string;
  clock: FakeClock;
  heartbeat: HeartbeatController;
  store: FakeStore;
  probe: PhaseProbe;
  capture: SourceWorkerDependencies["capture"];
  upload: SourceWorkerDependencies["upload"];
  publish: SourceWorkerDependencies["publish"];
  inputs: (overrides?: Partial<SourceWorkerInputs>) => SourceWorkerInputs;
}

async function withTempBase(
  fn: (basePath: string, canonicalBase: string) => Promise<void>,
): Promise<void> {
  const dir = await Deno.makeTempDir({ prefix: "m07-worker-" });
  try {
    await Deno.chmod(dir, 0o700);
    await fn(dir, await Deno.realPath(dir));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

function makeRunFixture(canonicalBase: string): RunFixture {
  const clock = makeClock(HEARTBEAT_START);
  const heartbeat = makeHeartbeatController();
  const store = new FakeStore();
  const probe: PhaseProbe = {
    captureCalls: 0,
    uploadCalls: 0,
    publishCalls: 0,
    captureArgs: [],
    uploadArgs: [],
    publishArgs: [],
    sleepCalls: [],
  };
  const stagePath = `${canonicalBase}/${GENERATION}`;
  const jobsPath = `${canonicalBase}/jobs`;
  const statusPath = `${jobsPath}/${JOB_ID}/status.json`;
  const resultPath = `${jobsPath}/${JOB_ID}/result.json`;
  const requestPath = `${jobsPath}/${JOB_ID}/request.json`;

  const capture: SourceWorkerDependencies["capture"] = async (settings) => {
    probe.captureCalls += 1;
    probe.captureArgs.push(settings);
    await probe.captureHook?.();
    await Deno.mkdir(stagePath, { mode: 0o700 });
    await Deno.chmod(stagePath, 0o700);
    await Deno.writeFile(`${stagePath}/recipient.asc`, FAKE_RECIPIENT_BYTES, {
      mode: 0o600,
    });
    return makeCaptureResult(stagePath);
  };
  const upload: SourceWorkerDependencies["upload"] = async (
    captureResult,
  ) => {
    probe.uploadCalls += 1;
    probe.uploadArgs.push(captureResult);
    const result = makeUploadResult(captureResult);
    await probe.uploadHook?.(captureResult);
    return result;
  };
  const publish: SourceWorkerDependencies["publish"] = async (
    captureResult,
    uploadResult,
    recipient,
  ) => {
    probe.publishCalls += 1;
    probe.publishArgs.push({
      capture: captureResult,
      upload: uploadResult,
      recipient,
    });
    const result = makePublishedIndex(
      captureResult,
      uploadResult,
      recipient,
    );
    await probe.publishHook?.(captureResult, uploadResult);
    return result;
  };
  const sleep: SourceWorkerDependencies["sleep"] = async (ms) => {
    probe.sleepCalls.push(ms);
    await probe.sleepHook?.(ms);
    clock.advance(ms);
  };

  const baseDeps: SourceWorkerDependencies = {
    basePath: canonicalBase,
    now: clock.now,
    lock: (path, work) => withBackupLock(path, work),
    capture,
    upload,
    publish,
    heartbeatScheduler: heartbeat,
    sleep,
  };

  return {
    basePath: canonicalBase,
    stagePath,
    jobsPath,
    statusPath,
    resultPath,
    requestPath,
    clock,
    heartbeat,
    store,
    probe,
    capture,
    upload,
    publish,
    inputs: (overrides = {}) => {
      const { deps: depsOverride, ...rest } = overrides;
      return {
        envelope: makeEnvelope(),
        captureSettings: makeSettings(),
        indexRecipient: makeIndexRecipient(),
        sourceRevision: SOURCE_REVISION,
        invocationId: INVOCATION_ID,
        store,
        deps: { ...baseDeps, ...depsOverride },
        ...rest,
      };
    },
  };
}

async function readJsonStatus(path: string): Promise<WorkerStatus> {
  const text = await Deno.readTextFile(path);
  return JSON.parse(text) as WorkerStatus;
}

/** Bounded wait until the status file satisfies the predicate. */
async function waitForStatus(
  path: string,
  predicate: (status: WorkerStatus) => boolean,
): Promise<WorkerStatus> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const status = await readJsonStatus(path);
    if (predicate(status)) return status;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the status condition");
}

async function makeSeedStatus(
  state: WorkerState,
  path: string,
  overrides: Partial<WorkerStatus> = {},
): Promise<void> {
  await ensureJobDir(path.slice(0, path.lastIndexOf(`/${JOB_ID}`)));
  const status: WorkerStatus = {
    schemaVersion: 1,
    jobId: JOB_ID,
    periodKey: PERIOD_KEY,
    generation: GENERATION,
    requestSha256: requestSha256Of(makeRequest()),
    requestedAtUtc: REQUESTED_AT,
    deadlineAtUtc: DEADLINE_AT,
    invocationId: INVOCATION_ID,
    state,
    startedAtUtc: "2026-09-06T04:01:00.000Z",
    updatedAtUtc: "2026-09-06T04:02:00.000Z",
    heartbeatAtUtc: "2026-09-06T04:02:00.000Z",
    finishedAtUtc: null,
    ...overrides,
  };
  await Deno.writeFile(
    path,
    new TextEncoder().encode(`${JSON.stringify(status, null, 2)}\n`),
    { mode: 0o600 },
  );
}

async function writeSeedJson(path: string, value: unknown): Promise<void> {
  await Deno.writeFile(
    path,
    new TextEncoder().encode(`${JSON.stringify(value, null, 2)}\n`),
    { mode: 0o600 },
  );
}

async function fileMode(path: string): Promise<number> {
  const info = await Deno.lstat(path);
  assert(info.mode !== null, "mode is unavailable");
  return info.mode & 0o777;
}

/** Seed a valid capture stage (0700 dir + recipient.asc + capture result). */
async function seedStage(
  stagePath: string,
  extraStageFiles: Record<string, unknown> = {},
): Promise<void> {
  await Deno.mkdir(stagePath, { mode: 0o700 });
  await Deno.chmod(stagePath, 0o700);
  await Deno.writeFile(`${stagePath}/recipient.asc`, FAKE_RECIPIENT_BYTES, {
    mode: 0o600,
  });
  await writeSeedJson(
    `${stagePath}/${CAPTURE_RESULT_FILE}`,
    makeCaptureResult(stagePath),
  );
  for (const [name, value] of Object.entries(extraStageFiles)) {
    await writeSeedJson(`${stagePath}/${name}`, value);
  }
}

async function ensureJobDir(jobsPath: string): Promise<string> {
  await Deno.mkdir(jobsPath, { mode: 0o700, recursive: true });
  await Deno.chmod(jobsPath, 0o700);
  const jobPath = `${jobsPath}/${JOB_ID}`;
  try {
    await Deno.mkdir(jobPath, { mode: 0o700 });
  } catch (error) {
    if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
  }
  await Deno.chmod(jobPath, 0o700);
  return jobPath;
}

/** Seed the canonical persisted request bytes. */
async function seedRequest(
  requestPath: string,
  request: WorkerRequest,
): Promise<void> {
  await ensureJobDir(
    requestPath.slice(0, requestPath.lastIndexOf(`/${JOB_ID}`)),
  );
  await Deno.writeFile(
    requestPath,
    new TextEncoder().encode(canonicalRequestString(request)),
    { mode: 0o600 },
  );
}

// ---------------------------------------------------------------------------
// Pure tests — request envelope, config hash, status and gate derivation.
// ---------------------------------------------------------------------------

Deno.test("request envelope hashes the documented exact property order", () => {
  const envelope = makeEnvelope();
  assert(
    canonicalRequestString(envelope.request) ===
      `{"schemaVersion":1,"jobId":"${JOB_ID}","periodKey":"${PERIOD_KEY}",` +
        `"generation":"${GENERATION}","requestedAtUtc":"${REQUESTED_AT}",` +
        `"deadlineAtUtc":"${DEADLINE_AT}","recipientSha256":"${RECIPIENT_SHA256}",` +
        `"recipientFingerprint":"${RECIPIENT_FINGERPRINT}",` +
        `"sourceRevision":"${SOURCE_REVISION}",` +
        `"sourceConfigSha256":"${envelope.request.sourceConfigSha256}"}`,
  );
  assert(envelope.requestSha256 === requestSha256Of(envelope.request));
  // The hash depends on the exact order: a key order change alters it.
  const reordered = JSON.parse(
    canonicalRequestString(envelope.request),
  ) as Record<string, unknown>;
  assert(
    Object.keys(reordered).join(",") ===
      "schemaVersion,jobId,periodKey,generation,requestedAtUtc,deadlineAtUtc," +
        "recipientSha256,recipientFingerprint,sourceRevision,sourceConfigSha256",
  );
  // Round trip through JSON keeps the same canonical bytes and hash.
  const restored = JSON.parse(canonicalRequestString(envelope.request));
  assert(validateRequest(restored) !== undefined);
  assert(
    canonicalRequestString(validateRequest(restored)) ===
      canonicalRequestString(envelope.request),
  );
  // A hash that does not match the canonical bytes is rejected.
  assertThrowsSync(
    () =>
      validateRequestEnvelope({
        request: envelope.request,
        requestSha256: "0".repeat(64),
      }),
    "does not match",
  );
});

Deno.test("validateRequest rejects every malformed identity deviation", () => {
  const base = () => makeRequest();
  assertThrowsSync(() => validateRequest(undefined), "JSON object");
  const unknownKey = base() as unknown as Record<string, unknown>;
  (unknownKey as Record<string, unknown>)["extra"] = 1;
  assertThrowsSync(() => validateRequest(unknownKey), "unknown key");
  assertThrowsSync(
    () => validateRequest({ ...base(), jobId: `job-${UUID.toUpperCase()}` }),
    "jobId",
  );
  // 2026-09-05 is a Saturday.
  assertThrowsSync(
    () => validateRequest({ ...base(), periodKey: "2026-09-05" }),
    "Sunday",
  );
  assertThrowsSync(
    () =>
      validateRequest({
        ...base(),
        generation: `generation-${"a".repeat(36)}`,
      }),
    "generation",
  );
  assertThrowsSync(
    () =>
      validateRequest({
        ...base(),
        deadlineAtUtc: "2026-09-06T09:00:00.000Z",
      }),
    "6 hours",
  );
  assertThrowsSync(
    () => validateRequest({ ...base(), sourceRevision: "a".repeat(39) }),
    "sourceRevision",
  );
  assertThrowsSync(
    () => validateRequest({ ...base(), recipientFingerprint: "a".repeat(40) }),
    "recipientFingerprint",
  );
});

Deno.test("source config hash is six roles in fixed key order", () => {
  const settings = makeSettings();
  const text = canonicalSourceConfig(settings);
  const parsed = JSON.parse(text) as {
    sources: Record<string, unknown>[];
    exclusionsText: string;
  };
  assert(Object.keys(parsed).join(",") === "sources,exclusionsText");
  assert(parsed.sources.length === ROLE_ORDER.length);
  assert(
    parsed.sources.map((entry) => entry.name).join(",") ===
      "root,efi,staging-boot,staging-efi,oracle-root,oracle-oled",
  );
  // Fixed key order on every source: livePath only where it exists.
  for (const entry of parsed.sources) {
    const keys = Object.keys(entry);
    assert(
      entry.name === "root" || entry.name === "efi"
        ? keys.join(",") === "name,uuid,filesystem,size,livePath"
        : keys.join(",") === "name,uuid,filesystem,size",
    );
  }
  assert(parsed.exclusionsText === REQUIRED_EXCLUSIONS.join("\n"));
  // The hash is order-independent of the settings array, but not content.
  const shuffled = makeSettings();
  shuffled.sources = [...shuffled.sources].reverse();
  assert(sourceConfigSha256(shuffled) === sourceConfigSha256(settings));
  const changed = makeSettings();
  changed.sources = changed.sources.map((source) =>
    source.name === "root" ? { ...source, size: source.size + 1 } : source
  );
  assert(sourceConfigSha256(changed) !== sourceConfigSha256(settings));
  const missing = makeSettings();
  missing.sources = missing.sources.slice(1);
  assertThrowsSync(
    () => sourceConfigSha256(missing),
    "Persistent filesystem coverage changed",
  );
});

Deno.test("validateStatus enforces terminal fields and timestamp ordering", () => {
  const running: WorkerStatus = {
    schemaVersion: 1,
    jobId: JOB_ID,
    periodKey: PERIOD_KEY,
    generation: GENERATION,
    requestSha256: requestSha256Of(makeRequest()),
    requestedAtUtc: REQUESTED_AT,
    deadlineAtUtc: DEADLINE_AT,
    invocationId: INVOCATION_ID,
    state: "CAPTURING",
    startedAtUtc: "2026-09-06T04:01:00.000Z",
    updatedAtUtc: "2026-09-06T04:02:00.000Z",
    heartbeatAtUtc: "2026-09-06T04:02:00.000Z",
    finishedAtUtc: null,
  };
  assert(validateStatus(running).state === "CAPTURING");
  const pending: WorkerStatus = {
    ...running,
    state: "PENDING_VERIFIER",
    updatedAtUtc: "2026-09-06T04:20:00.000Z",
    finishedAtUtc: "2026-09-06T04:20:00.000Z",
    resultSha256: "ab".repeat(32),
  };
  assert(validateStatus(pending).resultSha256 === "ab".repeat(32));
  const failed: WorkerStatus = {
    ...running,
    state: "FAILED",
    updatedAtUtc: "2026-09-06T04:20:00.000Z",
    finishedAtUtc: "2026-09-06T04:20:00.000Z",
    errorCode: "CAPTURE_FAILED",
  };
  assert(validateStatus(failed).errorCode === "CAPTURE_FAILED");
  // Nonterminal with a finishedAtUtc is rejected.
  assertThrowsSync(
    () => validateStatus({ ...running, finishedAtUtc: REQUESTED_AT }),
    "nonterminal",
  );
  // Terminal without a finishedAtUtc is rejected.
  assertThrowsSync(
    () =>
      validateStatus({
        ...pending,
        finishedAtUtc: null,
        resultSha256: undefined,
      }),
    "terminal status requires",
  );
  // errorCode outside FAILED, resultSha256 outside PENDING_VERIFIER.
  assertThrowsSync(
    () => validateStatus({ ...running, errorCode: "CAPTURE_FAILED" }),
    "only valid on a FAILED",
  );
  assertThrowsSync(
    () => validateStatus({ ...running, resultSha256: "ab".repeat(32) }),
    "only valid on a PENDING_VERIFIER",
  );
  // Unknown state, unknown key, broken monotonic order.
  assertThrowsSync(
    () => validateStatus({ ...running, state: "ACCEPTED" }),
    "unsupported",
  );
  assertThrowsSync(
    () => validateStatus({ ...running, extra: true }),
    "unknown key",
  );
  assertThrowsSync(
    () =>
      validateStatus({
        ...running,
        heartbeatAtUtc: "2026-09-06T04:03:00.000Z",
      }),
    "monotonic",
  );
  assertThrowsSync(
    () =>
      validateStatus({
        ...running,
        startedAtUtc: "2026-09-06T03:30:00.000Z",
      }),
    "precede the request",
  );
});

Deno.test("deriveWorkerGate binds the m06 worker identity", () => {
  const request = makeRequest();
  const gate = deriveWorkerGate(request, requestSha256Of(request));
  assert(gate.state === "active");
  assert(gate.unitInvocationId === null);
  assert(gate.unitName === `arch-vps-b2-worker-${UUID}.service`);
  assert(gate.remoteHost === "codex@vps.pavlovcik.com");
  assert(gate.sourceLockPath === "/var/tmp/arch-vps-file-backup/source.lock");
  assert(gate.jobId === JOB_ID);
  assert(gate.generation === GENERATION);
  assert(gate.requestSha256 === requestSha256Of(request));
  assert(
    workerUnitName(GENERATION) === `arch-vps-b2-worker-${UUID}.service`,
  );
});

Deno.test("isRetriableB2Error accepts only exact B2 transport failures", () => {
  const operations = [
    "b2_authorize_account",
    "b2_get_upload_url",
    "b2_upload_file",
    "b2_download_file_by_id",
    "b2_list_file_versions",
  ];
  for (const operation of operations) {
    assert(
      isRetriableB2Error(new Error(`${operation} failed (network error)`)),
    );
    assert(isRetriableB2Error(new Error(`${operation} failed (HTTP 408)`)));
    assert(isRetriableB2Error(new Error(`${operation} failed (HTTP 429)`)));
    assert(isRetriableB2Error(new Error(`${operation} failed (HTTP 500)`)));
    assert(isRetriableB2Error(new Error(`${operation} failed (HTTP 599)`)));
    assert(
      isRetriableB2Error(
        new Error(`${operation} failed (HTTP 503): unreadable body`),
      ),
    );
    assert(
      isRetriableB2Error(
        new Error(`${operation} failed (HTTP 502): invalid body`),
      ),
    );
  }
  assert(
    isRetriableB2Error(
      new Error("b2_download_file_by_id failed: body read failed"),
    ),
  );
  // Scope/identity/other 4xx, other 5xx-adjacent classes and every non-B2
  // or malformed message stay immediate (never retried).
  assert(!isRetriableB2Error(new Error("b2_upload_file failed (HTTP 401)")));
  assert(
    !isRetriableB2Error(new Error("b2_authorize_account failed (HTTP 403)")),
  );
  assert(
    !isRetriableB2Error(
      new Error("b2_list_file_versions failed (HTTP 404): invalid body"),
    ),
  );
  assert(!isRetriableB2Error(new Error("b2_upload_file failed (HTTP 600)")));
  assert(!isRetriableB2Error(new Error("b2_upload_file failed (HTTP 300)")));
  assert(
    !isRetriableB2Error(
      new Error("b2_upload_file failed (HTTP 503): unreadable body extra"),
    ),
  );
  assert(
    !isRetriableB2Error(new Error("b2_upload_file failed (HTTP 503) extra")),
  );
  assert(
    !isRetriableB2Error(
      new Error("b2_upload_file failed: invalid response (fileId)"),
    ),
  );
  assert(
    !isRetriableB2Error(
      new Error("b2_download_file_by_id failed: invalid response"),
    ),
  );
  assert(
    !isRetriableB2Error(
      new Error(
        "b2_download_file_by_id failed: content length outside chunk bounds",
      ),
    ),
  );
  assert(!isRetriableB2Error(new Error("Index failed (publish:readback)")));
  assert(!isRetriableB2Error(new Error("Upload failed (archive:hash)")));
  assert(
    !isRetriableB2Error(new Error("put failed: chunk exceeds 67108864 bytes")),
  );
  assert(
    !isRetriableB2Error(new Error("remove failed: object is not an upload")),
  );
  assert(!isRetriableB2Error(undefined));
  assert(!isRetriableB2Error("b2_upload_file failed (HTTP 503)"));
});

/** Queue persist callback that records without an async body. */
function recordPersist(
  persisted: WorkerStatus[],
  status: WorkerStatus,
): Promise<void> {
  persisted.push(status);
  return Promise.resolve();
}

/** Minimal structural queue target that records every built delta. */
function makeQueueTarget(): {
  target: StatusWriteTarget;
  builds: { state: WorkerState; kind: string }[];
} {
  const builds: { state: WorkerState; kind: string }[] = [];
  const target: StatusWriteTarget = {
    build(delta, kind) {
      builds.push({ state: delta.state, kind });
      const status: WorkerStatus = {
        schemaVersion: 1,
        jobId: JOB_ID,
        periodKey: PERIOD_KEY,
        generation: GENERATION,
        requestSha256: requestSha256Of(makeRequest()),
        requestedAtUtc: REQUESTED_AT,
        deadlineAtUtc: DEADLINE_AT,
        invocationId: INVOCATION_ID,
        state: delta.state,
        startedAtUtc: REQUESTED_AT,
        updatedAtUtc: REQUESTED_AT,
        heartbeatAtUtc: REQUESTED_AT,
        finishedAtUtc: null,
      };
      return {
        ...status,
        ...(delta.errorCode === undefined
          ? {}
          : { errorCode: delta.errorCode }),
        ...(delta.resultSha256 === undefined
          ? {}
          : { resultSha256: delta.resultSha256 }),
      };
    },
  };
  return { target, builds };
}

Deno.test("serialized queue: heartbeat derives state at execution, not enqueue", async () => {
  const { target, builds } = makeQueueTarget();
  const queue = new SerialStatusQueue("UPLOADING");
  const persisted: WorkerStatus[] = [];
  let release!: () => void;
  const phaseGate = new Promise<void>((resolve) => {
    release = resolve;
  });
  // The delayed phase write is in flight when the heartbeat is queued with an
  // enqueue-time snapshot of UPLOADING; the heartbeat must execute with the
  // phase state that actually committed (UPLOAD_VERIFIED).
  const phase = queue.submit(
    { delta: { state: "UPLOAD_VERIFIED" }, kind: "phase" },
    target,
    async (status) => {
      await phaseGate;
      persisted.push(status);
    },
  );
  const heartbeat = queue.submit(
    { kind: "heartbeat" },
    target,
    (status) => recordPersist(persisted, status),
  );
  release();
  const phaseStatus = await phase;
  assert(phaseStatus?.state === "UPLOAD_VERIFIED");
  assert((await heartbeat)?.state === "UPLOAD_VERIFIED");
  assert(persisted.length === 2);
  assert(
    persisted[1].state === "UPLOAD_VERIFIED",
    "the queued heartbeat must report the committed phase, never the stale enqueue-time snapshot",
  );
  assert(builds[1].kind === "heartbeat");
  assert(builds[1].state === "UPLOAD_VERIFIED");
});

Deno.test("serialized queue: rejected write stays caller-visible and never poisons later writes", async () => {
  const { target } = makeQueueTarget();
  const queue = new SerialStatusQueue("UPLOADING");
  const persisted: WorkerStatus[] = [];
  const failing = queue.submit(
    { delta: { state: "UPLOAD_VERIFIED" }, kind: "phase" },
    target,
    () => Promise.reject(new Error("status write exploded")),
  );
  await assertThrowsAsync(() => failing, "status write exploded");
  const terminal = await queue.submit(
    {
      delta: { state: "FAILED", errorCode: "UPLOAD_FAILED" },
      kind: "terminal",
    },
    target,
    (status) => recordPersist(persisted, status),
  );
  assert(terminal?.state === "FAILED");
  assert(terminal?.errorCode === "UPLOAD_FAILED");
  assert(
    persisted.length === 1 && persisted[0].state === "FAILED",
    "the FAILED terminal must write after an earlier failed write",
  );
});

Deno.test("serialized queue: heartbeats queued after the terminal are skipped", async () => {
  const { target } = makeQueueTarget();
  const queue = new SerialStatusQueue("INDEXING");
  const persisted: WorkerStatus[] = [];
  const terminal = await queue.submit(
    {
      delta: { state: "PENDING_VERIFIER", resultSha256: "ab".repeat(32) },
      kind: "terminal",
    },
    target,
    (status) => recordPersist(persisted, status),
  );
  assert(terminal?.state === "PENDING_VERIFIER");
  const late = await queue.submit(
    { kind: "heartbeat" },
    target,
    (status) => recordPersist(persisted, status),
  );
  assert(late === undefined, "no heartbeat may write after a terminal");
  assert(persisted.length === 1);
});

// ---------------------------------------------------------------------------
// Runtime tests — real local persistence with injected fake phases.
// ---------------------------------------------------------------------------

runtimeTest(
  "fresh job reaches PENDING_VERIFIER with result-before-state ordering",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      // Phase-time probes: the state prefix must be recorded before each
      // phase runs, and result files must not exist before their state.
      fixture.probe.captureHook = async () => {
        const status = await readJsonStatus(fixture.statusPath);
        assert(status.state === "CAPTURING");
        assert(
          await Deno.stat(`${fixture.stagePath}/${CAPTURE_RESULT_FILE}`)
            .then(() => true, () => false) === false,
          "capture result must not exist during capture",
        );
      };
      fixture.probe.uploadHook = async (capture) => {
        const status = await readJsonStatus(fixture.statusPath);
        assert(
          status.state === "UPLOADING",
          "the upload phase must be recorded before the uploader runs",
        );
        assert(
          await Deno.stat(`${fixture.stagePath}/${CAPTURE_RESULT_FILE}`)
            .then(() => true),
          "capture result must exist before the upload phase",
        );
        assert(
          await Deno.stat(`${fixture.stagePath}/${UPLOAD_RESULT_FILE}`)
            .then(() => true, () => false) === false,
          "upload result must not exist during upload",
        );
        assert(capture.stageDirectory === fixture.stagePath);
      };
      fixture.probe.publishHook = async () => {
        const status = await readJsonStatus(fixture.statusPath);
        assert(status.state === "INDEXING");
        assert(
          await Deno.stat(fixture.resultPath).then(() => true, () => false) ===
            false,
          "job result must not exist before the final terminal phase",
        );
      };

      const terminal = await runSourceWorker(fixture.inputs());
      assert(
        terminal.state === "PENDING_VERIFIER",
        `got ${terminal.state} errorCode=${terminal.errorCode ?? "none"}`,
      );
      assert(terminal.finishedAtUtc !== null);
      assert(/^[0-9a-f]{64}$/.test(terminal.resultSha256 ?? ""));
      assert(fixture.probe.captureCalls === 1);
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.publishCalls === 1);
      assert(fixture.store.removeCalls === 0);

      // Result bytes hash exactly to status.resultSha256.
      const resultBytes = await Deno.readFile(fixture.resultPath);
      assert(sha256Hex(resultBytes) === terminal.resultSha256);
      const result = JSON.parse(
        new TextDecoder().decode(resultBytes),
      ) as Record<string, unknown>;
      assert(
        Object.keys(result).join(",") ===
          "envelope,capture,upload,publishedIndex",
      );
      assert(result.envelope !== undefined);
      const published = result.publishedIndex as Record<string, unknown>;
      assert(published.uploadVerified === true);
      assert(published.decryptedRestoreProved === false);
      assert(published.machineBootRestoreProved === false);

      // Durable files and owner-only modes.
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "PENDING_VERIFIER");
      assert(status.resultSha256 === terminal.resultSha256);
      assert(await fileMode(fixture.statusPath) === 0o600);
      assert(await fileMode(fixture.resultPath) === 0o600);
      assert(await fileMode(fixture.requestPath) === 0o600);
      assert(await fileMode(fixture.jobsPath) === 0o700);
      assert(await fileMode(fixture.stagePath) === 0o700);
      for (
        const name of [
          CAPTURE_RESULT_FILE,
          UPLOAD_RESULT_FILE,
          INDEX_RESULT_FILE,
        ]
      ) {
        assert(await fileMode(`${fixture.stagePath}/${name}`) === 0o600);
      }
      const requestBytes = await Deno.readFile(fixture.requestPath);
      assert(
        new TextDecoder().decode(requestBytes) ===
          canonicalRequestString(makeRequest()),
      );
    });
  },
);

runtimeTest(
  "same request resume returns the terminal without rework",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const first = await runSourceWorker(fixture.inputs());
      assert(first.state === "PENDING_VERIFIER");
      const second = await runSourceWorker(fixture.inputs());
      assert(second.state === "PENDING_VERIFIER");
      assert(second.resultSha256 === first.resultSha256);
      assert(fixture.probe.captureCalls === 1);
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.publishCalls === 1);
    });
  },
);

runtimeTest(
  "resume from a seeded CAPTURED status skips capture and continues",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      await seedRequest(fixture.requestPath, makeRequest());
      await seedStage(fixture.stagePath);
      await makeSeedStatus("CAPTURED", fixture.statusPath);
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "PENDING_VERIFIER");
      assert(fixture.probe.captureCalls === 0, "capture must not rerun");
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.publishCalls === 1);
    });
  },
);

runtimeTest(
  "resume from seeded UPLOADING with a valid upload result does not re-upload",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture = makeCaptureResult(fixture.stagePath);
      const upload = makeUploadResult(capture);
      const recipient = makeIndexRecipient();
      await seedRequest(fixture.requestPath, makeRequest());
      await seedStage(fixture.stagePath, {
        [UPLOAD_RESULT_FILE]: upload,
        [INDEX_RESULT_FILE]: makePublishedIndex(capture, upload, recipient),
      });
      await makeSeedStatus("UPLOADING", fixture.statusPath);
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "PENDING_VERIFIER");
      assert(fixture.probe.captureCalls === 0);
      assert(fixture.probe.uploadCalls === 0, "upload must not rerun");
      assert(fixture.probe.publishCalls === 0, "publish must not rerun");
    });
  },
);

runtimeTest(
  "resume from seeded INDEXING with a valid index result skips publish",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture = makeCaptureResult(fixture.stagePath);
      const upload = makeUploadResult(capture);
      const recipient = makeIndexRecipient();
      await seedRequest(fixture.requestPath, makeRequest());
      await seedStage(fixture.stagePath, {
        [UPLOAD_RESULT_FILE]: upload,
        [INDEX_RESULT_FILE]: makePublishedIndex(
          capture,
          upload,
          recipient,
        ),
      });
      await makeSeedStatus("INDEXING", fixture.statusPath);
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "PENDING_VERIFIER");
      assert(fixture.probe.publishCalls === 0);
      const resultBytes = await Deno.readFile(fixture.resultPath);
      assert(sha256Hex(resultBytes) === terminal.resultSha256);
    });
  },
);

runtimeTest(
  "existing partial or missing stage result is an explicit FAILED without recapture",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      await seedRequest(fixture.requestPath, makeRequest());
      // Existing stage with a missing capture result: never recapture.
      await Deno.mkdir(fixture.stagePath, { mode: 0o700 });
      await Deno.chmod(fixture.stagePath, 0o700);
      await Deno.writeFile(
        `${fixture.stagePath}/recipient.asc`,
        FAKE_RECIPIENT_BYTES,
        { mode: 0o600 },
      );
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "CAPTURE_RESULT_INVALID");
      assert(fixture.probe.captureCalls === 0, "no capture on partial stage");
      assert(fixture.probe.uploadCalls === 0);
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED");
      assert(status.errorCode === "CAPTURE_RESULT_INVALID");
      // A second identical invocation is a different invocation: rejected,
      // and the failed status never restarts capture.
      await assertThrowsAsync(
        () =>
          runSourceWorker(
            fixture.inputs({ invocationId: "f".repeat(32) }),
          ),
        "INVOCATION_MISMATCH",
      );
    });
  },
);

runtimeTest(
  "invalid saved capture result (wrong roles) is an explicit FAILED",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture = makeCaptureResult(fixture.stagePath);
      capture.archives = capture.archives.slice(0, 6);
      await seedRequest(fixture.requestPath, makeRequest());
      // The seed writes a valid result first; the invalid one replaces it in
      // the same seeding pass, proving the worker fails on the bytes on disk.
      await seedStage(fixture.stagePath, {
        [CAPTURE_RESULT_FILE]: capture,
      });
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "CAPTURE_RESULT_INVALID");
      assert(fixture.probe.captureCalls === 0);
    });
  },
);

runtimeTest(
  "changed request is rejected before any work and never overwrites",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const first = await runSourceWorker(fixture.inputs());
      assert(first.state === "PENDING_VERIFIER");
      // A different immutable request (different revision) for the same job;
      // the input revision matches the new request, so the persisted bytes
      // check surfaces the mismatch.
      const changedRevision = "b".repeat(40);
      const before = await Deno.readFile(fixture.statusPath);
      try {
        await runSourceWorker(
          fixture.inputs({
            envelope: makeEnvelope({ sourceRevision: changedRevision }),
            sourceRevision: changedRevision,
          }),
        );
        assert(false, "expected rejection");
      } catch (error) {
        assert(error instanceof WorkerRejection, "fixed rejection type");
        assert(error.code === "REQUEST_MISMATCH", (error as Error).message);
      }
      const after = await Deno.readFile(fixture.statusPath);
      assert(
        sha256Hex(after) === sha256Hex(before),
        "the saved status must not be overwritten",
      );
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.publishCalls === 1);
    });
  },
);

runtimeTest(
  "changed config, recipient, revision and invocation are rejected before work",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const changedSettings = makeSettings();
      changedSettings.sources = changedSettings.sources.map((source) =>
        source.name === "root" ? { ...source, size: 1 } : source
      );
      await assertThrowsAsync(
        () =>
          runSourceWorker(
            fixture.inputs({
              captureSettings: changedSettings,
            }),
          ),
        "CONFIG_MISMATCH",
      );
      const wrongRecipient = makeIndexRecipient();
      wrongRecipient.recipientSha256 = "c".repeat(64);
      await assertThrowsAsync(
        () =>
          runSourceWorker(
            fixture.inputs({ indexRecipient: wrongRecipient }),
          ),
        "RECIPIENT_MISMATCH",
      );
      await assertThrowsAsync(
        () =>
          runSourceWorker(
            fixture.inputs({
              sourceRevision: "b".repeat(40),
            }),
          ),
        "REVISION_MISMATCH",
      );
      // A different invocation cannot silently restart an old job.
      await seedRequest(fixture.requestPath, makeRequest());
      await makeSeedStatus("CAPTURED", fixture.statusPath, {
        invocationId: INVOCATION_ID,
      });
      await assertThrowsAsync(
        () =>
          runSourceWorker(
            fixture.inputs({ invocationId: "f".repeat(32) }),
          ),
        "INVOCATION_MISMATCH",
      );
      assert(
        fixture.probe.captureCalls === 0 && fixture.probe.uploadCalls === 0 &&
          fixture.probe.publishCalls === 0,
        "no phase may run after a rejection",
      );
    });
  },
);

runtimeTest(
  "deadline crossed during capture is FAILED without next phase",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      fixture.probe.captureHook = () => {
        fixture.clock.set(Date.parse(DEADLINE_AT) + 1_000);
      };
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "DEADLINE_EXCEEDED");
      assert(fixture.probe.uploadCalls === 0, "no next phase after expiry");
      assert(fixture.probe.publishCalls === 0);
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED");
      assert(status.errorCode === "DEADLINE_EXCEEDED");
    });
  },
);

runtimeTest(
  "deadline crossed during upload is FAILED before the index phase",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      fixture.probe.uploadHook = () => {
        fixture.clock.set(Date.parse(DEADLINE_AT) + 1_000);
      };
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "DEADLINE_EXCEEDED");
      assert(fixture.probe.publishCalls === 0, "no index after expiry");
      // The completed upload evidence was still persisted.
      assert(
        await Deno.stat(`${fixture.stagePath}/${UPLOAD_RESULT_FILE}`)
          .then(() => true, () => false),
      );
    });
  },
);

runtimeTest(
  "a FAILED terminal persists when the deadline already expired",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      fixture.clock.set(Date.parse(DEADLINE_AT) + 3_600_000);
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "DEADLINE_EXCEEDED");
      assert(fixture.probe.captureCalls === 0);
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED", "terminal status must be writable");
      assert(
        Date.parse(status.updatedAtUtc) >= Date.parse(DEADLINE_AT),
        "terminal write happens after the deadline",
      );
    });
  },
);

runtimeTest(
  "a delayed heartbeat can never overwrite the terminal status",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      // During the index phase, queue one heartbeat write, let it complete,
      // and prove it updates an INDEXING status. The terminal write is
      // enqueued afterwards and must win.
      fixture.probe.publishHook = async () => {
        fixture.clock.advance(5_000);
        fixture.heartbeat.fire();
        const during = await waitForStatus(
          fixture.statusPath,
          (status) =>
            status.state === "INDEXING" &&
            Date.parse(status.heartbeatAtUtc) >
              Date.parse(status.startedAtUtc),
        );
        assert(
          Date.parse(during.heartbeatAtUtc) > Date.parse(during.startedAtUtc),
          "the queued heartbeat must have written a newer heartbeat",
        );
      };
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "PENDING_VERIFIER");
      assert(fixture.heartbeat.isStopped(), "timer must be stopped in finally");
      // A heartbeat fired after the run cannot touch the terminal status.
      const after = await Deno.readFile(fixture.statusPath);
      fixture.heartbeat.fire();
      await new Promise((resolve) => setTimeout(resolve, 25));
      const final = await Deno.readFile(fixture.statusPath);
      assert(
        sha256Hex(final) === sha256Hex(after),
        "no heartbeat write may occur after the terminal status",
      );
    });
  },
);

runtimeTest(
  "a transient heartbeat write failure still persists a durable FAILED",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      fixture.probe.uploadHook = async () => {
        // Transient status write failure: the queued heartbeat builds its
        // status with a broken clock, so its write rejects once before the
        // clock is restored. The queue must recover for the FAILED terminal.
        const valid = fixture.clock.get();
        fixture.clock.set(Number.NaN);
        fixture.heartbeat.fire();
        await new Promise((resolve) => setTimeout(resolve, 0));
        fixture.clock.set(valid);
        // Fatal scope error: no retry, so the FAILED terminal must follow.
        throw new Error("b2_upload_file failed (HTTP 401)");
      };
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "UPLOAD_FAILED");
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED");
      assert(status.errorCode === "UPLOAD_FAILED");
      assert(
        !new TextDecoder().decode(await Deno.readFile(fixture.statusPath))
          .includes("PENDING_VERIFIER"),
        "no success claim after a failed heartbeat write",
      );
      assert(fixture.probe.uploadCalls === 1, "fatal errors must not retry");
    });
  },
);

runtimeTest(
  "a failed final result write persists a durable FAILED without a success claim",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      // Block the job result path with a directory: the terminal effect fails
      // after the index result write, and the FAILED terminal must still land.
      await ensureJobDir(fixture.jobsPath);
      await Deno.mkdir(fixture.resultPath, { mode: 0o700 });
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "RESULT_FAILED");
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED");
      assert(status.errorCode === "RESULT_FAILED");
      assert(
        !JSON.stringify(status).includes("PENDING_VERIFIER"),
        "no success claim after a failed final result write",
      );
      assert(
        (await Deno.lstat(fixture.resultPath)).isDirectory,
        "the blocked result path stays blocked (visible incomplete state)",
      );
      assert(fixture.probe.captureCalls === 1);
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.publishCalls === 1);
    });
  },
);

runtimeTest(
  "saved invalid upload descriptor is UPLOAD_RESULT_INVALID",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture = makeCaptureResult(fixture.stagePath);
      const upload = makeUploadResult(capture);
      upload.archives = upload.archives.slice(1); // missing roles
      await seedRequest(fixture.requestPath, makeRequest());
      await seedStage(fixture.stagePath, {
        [UPLOAD_RESULT_FILE]: upload,
      });
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "UPLOAD_RESULT_INVALID");
      assert(
        fixture.probe.uploadCalls === 0,
        "no re-upload for an invalid saved descriptor",
      );
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.errorCode === "UPLOAD_RESULT_INVALID");
    });
  },
);

runtimeTest(
  "saved invalid index descriptor (unknown key) is INDEX_RESULT_INVALID",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture = makeCaptureResult(fixture.stagePath);
      const upload = makeUploadResult(capture);
      const recipient = makeIndexRecipient();
      const published = makePublishedIndex(
        capture,
        upload,
        recipient,
      ) as unknown as Record<string, unknown>;
      published.accepted = true; // outside the PublishedIndex contract
      await seedRequest(fixture.requestPath, makeRequest());
      await seedStage(fixture.stagePath, {
        [UPLOAD_RESULT_FILE]: upload,
        [INDEX_RESULT_FILE]: published,
      });
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "INDEX_RESULT_INVALID");
      assert(
        fixture.probe.publishCalls === 0,
        "no publish for an invalid saved index descriptor",
      );
    });
  },
);

runtimeTest(
  "saved invalid index descriptor (object length mismatch) is INDEX_RESULT_INVALID",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture = makeCaptureResult(fixture.stagePath);
      const upload = makeUploadResult(capture);
      const recipient = makeIndexRecipient();
      const published = makePublishedIndex(capture, upload, recipient);
      (published.object as { contentLength: number }).contentLength =
        published.ciphertextBytes - 1;
      await seedRequest(fixture.requestPath, makeRequest());
      await seedStage(fixture.stagePath, {
        [UPLOAD_RESULT_FILE]: upload,
        [INDEX_RESULT_FILE]: published,
      });
      const terminal = await runSourceWorker(fixture.inputs());
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "INDEX_RESULT_INVALID");
      assert(
        fixture.probe.publishCalls === 0,
        "no publish for an invalid saved index descriptor",
      );
    });
  },
);

runtimeTest(
  "retry: a retriable upload transport failure retries the whole module and recovers",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      let failures = 0;
      const heartbeatDuringSleep: WorkerState[] = [];
      const upload: SourceWorkerDependencies["upload"] = (captureResult) => {
        fixture.probe.uploadCalls += 1;
        fixture.probe.uploadArgs.push(captureResult);
        failures += 1;
        if (failures === 1) {
          return Promise.reject(
            new Error("b2_upload_file failed (HTTP 503)"),
          );
        }
        return Promise.resolve(makeUploadResult(captureResult));
      };
      fixture.probe.sleepHook = async () => {
        // A heartbeat fires during the retry wait: it must stay alive and
        // keep reporting the committed phase (the uploader re-runs fully on
        // the next attempt).
        const before = await readJsonStatus(fixture.statusPath);
        fixture.clock.advance(1_000);
        fixture.heartbeat.fire();
        const after = await waitForStatus(
          fixture.statusPath,
          (status) =>
            status.state === "UPLOADING" &&
            Date.parse(status.heartbeatAtUtc) >
              Date.parse(before.heartbeatAtUtc),
        );
        heartbeatDuringSleep.push(after.state);
      };
      const terminal = await runSourceWorker(
        fixture.inputs({ deps: { upload } }),
      );
      assert(terminal.state === "PENDING_VERIFIER");
      assert(fixture.probe.uploadCalls === 2, "exactly two upload attempts");
      assert(fixture.probe.captureCalls === 1, "capture never reruns");
      assert(fixture.probe.sleepCalls.length === 1);
      assert(fixture.probe.sleepCalls[0] === RETRY_SPACING_MS);
      assert(heartbeatDuringSleep.length === 1);
      assert(
        heartbeatDuringSleep[0] === "UPLOADING",
        "the heartbeat must stay alive during the retry wait",
      );
      assert(
        fixture.probe.uploadArgs[0] === fixture.probe.uploadArgs[1],
        "every attempt receives the identical capture result",
      );
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.jobId === JOB_ID);
      assert(status.generation === GENERATION);
      assert(status.invocationId === INVOCATION_ID);
      assert(status.requestSha256 === requestSha256Of(makeRequest()));
      assert(status.deadlineAtUtc === DEADLINE_AT);
      assert(status.requestedAtUtc === REQUESTED_AT);
    });
  },
);

runtimeTest(
  "retry: three retriable upload failures exhaust attempts with a FAILED terminal",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const upload: SourceWorkerDependencies["upload"] = () => {
        fixture.probe.uploadCalls += 1;
        return Promise.reject(
          new Error("b2_list_file_versions failed (HTTP 500): invalid body"),
        );
      };
      const terminal = await runSourceWorker(
        fixture.inputs({ deps: { upload } }),
      );
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "UPLOAD_FAILED");
      assert(fixture.probe.uploadCalls === MAX_PHASE_ATTEMPTS);
      assert(fixture.probe.captureCalls === 1);
      assert(fixture.probe.sleepCalls.length === MAX_PHASE_ATTEMPTS - 1);
      assert(
        fixture.probe.sleepCalls.every((ms) => ms === RETRY_SPACING_MS),
      );
      const statusText = new TextDecoder().decode(
        await Deno.readFile(fixture.statusPath),
      );
      assert(
        !statusText.includes("b2_list_file_versions"),
        "raw B2 detail must never reach a status file",
      );
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED");
      assert(status.errorCode === "UPLOAD_FAILED");
    });
  },
);

runtimeTest(
  "retry: the wait never passes the deadline and expires the job",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      let adjusted = false;
      const upload: SourceWorkerDependencies["upload"] = () => {
        fixture.probe.uploadCalls += 1;
        if (!adjusted) {
          adjusted = true;
          fixture.clock.set(Date.parse(DEADLINE_AT) - 10 * 60_000);
        }
        return Promise.reject(
          new Error("b2_upload_file failed (network error)"),
        );
      };
      const terminal = await runSourceWorker(
        fixture.inputs({ deps: { upload } }),
      );
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "DEADLINE_EXCEEDED");
      assert(
        fixture.probe.uploadCalls === 2,
        "the second attempt starts exactly at the deadline and expires",
      );
      assert(fixture.probe.sleepCalls.length === 1);
      assert(
        fixture.probe.sleepCalls[0] === 10 * 60_000,
        "the wait is capped at the remaining deadline window",
      );
      const status = await readJsonStatus(fixture.statusPath);
      assert(status.state === "FAILED");
      assert(status.errorCode === "DEADLINE_EXCEEDED");
    });
  },
);

runtimeTest(
  "retry: a wait that overshoots the deadline fails immediately",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      let adjusted = false;
      fixture.probe.uploadHook = () => {
        if (!adjusted) {
          adjusted = true;
          fixture.clock.set(Date.parse(DEADLINE_AT) - 15 * 60_000);
        }
      };
      const upload: SourceWorkerDependencies["upload"] = async () => {
        fixture.probe.uploadCalls += 1;
        await fixture.probe.uploadHook?.(
          makeCaptureResult(fixture.stagePath),
        );
        throw new Error("b2_get_upload_url failed (HTTP 429)");
      };
      const sleep: SourceWorkerDependencies["sleep"] = (ms) => {
        fixture.probe.sleepCalls.push(ms);
        fixture.clock.advance(ms + 1_000); // the clock overshoots the deadline
        return Promise.resolve();
      };
      const terminal = await runSourceWorker(
        fixture.inputs({ deps: { upload, sleep } }),
      );
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "DEADLINE_EXCEEDED");
      assert(fixture.probe.uploadCalls === 1, "no attempt after the deadline");
      assert(fixture.probe.sleepCalls.length === 1);
      assert(fixture.probe.sleepCalls[0] === 15 * 60_000);
    });
  },
);

runtimeTest(
  "retry: fatal non-B2 scope failures never retry",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const upload: SourceWorkerDependencies["upload"] = () => {
        fixture.probe.uploadCalls += 1;
        return Promise.reject(new Error("b2_upload_file failed (HTTP 401)"));
      };
      const terminal = await runSourceWorker(
        fixture.inputs({ deps: { upload } }),
      );
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "UPLOAD_FAILED");
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.sleepCalls.length === 0);
      assert(fixture.probe.captureCalls === 1);
    });
  },
);

runtimeTest(
  "retry: publish retries the whole publisher and then succeeds",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      let failures = 0;
      const publish: SourceWorkerDependencies["publish"] = (
        captureResult,
        uploadResult,
        recipient,
      ) => {
        fixture.probe.publishCalls += 1;
        fixture.probe.publishArgs.push(
          { capture: captureResult, upload: uploadResult, recipient },
        );
        failures += 1;
        if (failures === 1) {
          return Promise.reject(
            new Error("b2_download_file_by_id failed: body read failed"),
          );
        }
        return Promise.resolve(
          makePublishedIndex(captureResult, uploadResult, recipient),
        );
      };
      const terminal = await runSourceWorker(
        fixture.inputs({ deps: { publish } }),
      );
      assert(terminal.state === "PENDING_VERIFIER");
      assert(terminal.resultSha256 !== undefined);
      assert(fixture.probe.publishCalls === 2, "exactly two publish attempts");
      assert(fixture.probe.uploadCalls === 1);
      assert(fixture.probe.captureCalls === 1);
      assert(fixture.probe.sleepCalls.length === 1);
      assert(fixture.probe.sleepCalls[0] === RETRY_SPACING_MS);
      assert(
        fixture.probe.publishArgs[0].capture ===
            fixture.probe.publishArgs[1].capture &&
          fixture.probe.publishArgs[0].upload ===
            fixture.probe.publishArgs[1].upload,
        "every publish attempt receives the identical capture/upload",
      );
    });
  },
);

runtimeTest(
  "underlying phase failure leaves no raw body or secret in the status",
  async () => {
    await withTempBase(async (_base, canonicalBase) => {
      const fixture = makeRunFixture(canonicalBase);
      const capture: SourceWorkerDependencies["capture"] = () => {
        fixture.probe.captureCalls += 1;
        throw new Error("raw stream exploded: SECRET-TOKEN-abcd1234");
      };
      const terminal = await runSourceWorker(
        fixture.inputs({
          deps: { capture },
        }),
      );
      assert(terminal.state === "FAILED");
      assert(terminal.errorCode === "CAPTURE_FAILED");
      const statusBytes = await Deno.readFile(fixture.statusPath);
      const text = new TextDecoder().decode(statusBytes);
      assert(!text.includes("SECRET-TOKEN"), "no raw body in status");
      assert(!text.includes("raw stream"), "no raw body in status");
      assert(fixture.store.removeCalls === 0);
    });
  },
);

runtimeTest("worker never accepts, prunes or deletes anything", async () => {
  await withTempBase(async (_base, canonicalBase) => {
    const fixture = makeRunFixture(canonicalBase);
    // Store spy types already omit remove, but a remove method is provided
    // anyway and must never be invoked by the worker path.
    const terminal = await runSourceWorker(fixture.inputs());
    assert(terminal.state === "PENDING_VERIFIER");
    assert(fixture.store.putCalls === 0);
    assert(fixture.store.getCalls === 0);
    assert(fixture.store.versionsCalls === 0);
    assert(fixture.store.removeCalls === 0);
    const result = JSON.parse(
      new TextDecoder().decode(await Deno.readFile(fixture.resultPath)),
    ) as Record<string, unknown>;
    const text = JSON.stringify(result);
    assert(!text.includes('"decryptedRestoreProved":true'));
    assert(!text.includes('"machineBootRestoreProved":true'));
    assert(!text.includes("accepted"));
    assert(!text.includes("prun"));
    const status = await readJsonStatus(fixture.statusPath);
    assert(!("accepted" in status) && !("prune" in status));
  });
});
