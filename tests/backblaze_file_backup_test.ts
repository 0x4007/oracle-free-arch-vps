/**
 * m09-controller focused tests.
 *
 * All orchestration wiring is injected: fake remote/B2/gate/private seams
 * drive the Pi step machine while the production seam functions remain
 * fixed-wired; fixtures are small one-chunk descriptors so no minute of real
 * work or network access is needed. Cases cover the immutable Sunday/DST
 * catch-up window, duplicate invocation reconciliation, SSH loss without a
 * replacement, terminal-proof mismatch orphaning, PENDING_VERIFIER
 * non-acceptance, corrupt receipt refusal, durable acceptance before
 * deletion, four-retained selection with pending/foreign/start preservation,
 * partial pruning resume and the retained-ID guard, the watchdog assessment
 * and the production command wiring. No payload, credential or live access
 * occurs here.
 */
import { createHash } from "node:crypto";
import type {
  WorkerRequest,
  WorkerStatus,
} from "../scripts/backblaze-source-worker.ts";
import {
  CAPTURE_RESULT_FILE,
  INDEX_RESULT_FILE,
  sourceConfigSha256,
  UPLOAD_RESULT_FILE,
  workerUnitName,
} from "../scripts/backblaze-source-worker.ts";
import type {
  BackupControllerGate,
  OrphanReason,
} from "../scripts/backblaze-controller-contract.ts";
import type { CaptureResult } from "../scripts/backblaze-capture.ts";
import type { UploadResult } from "../scripts/backblaze-upload.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
} from "../scripts/backblaze-upload.ts";
import type { B2Object } from "../scripts/backblaze-storage.ts";
import type {
  IndexRecipient,
  PublishedIndex,
  RecoveryIndex,
} from "../scripts/backblaze-index.ts";
import { buildRecoveryIndex } from "../scripts/backblaze-index.ts";
import type { FileSource } from "../scripts/backblaze-capture.ts";
import type { CommandResult } from "../scripts/oci.ts";
import type { DecryptedVerification } from "../scripts/backblaze-verifier.ts";
import {
  assertVerifierHeadroom,
  assessBackblazeWatchdog,
  buildCleanupScript,
  buildClearProof,
  buildRequestEnvelope,
  type CatalogEntry,
  cleanupAllowedName,
  cleanupGpgHomeAllowedName,
  CONTROLLER_LOCK_PATH,
  CONTROLLER_STATE_PATH,
  type ControllerPhase,
  type ControllerState,
  decideGpgStatus,
  deriveVerifierGate,
  entryVerifyText,
  entryWorkerText,
  type GateSeam,
  generationPrefixes,
  JOBS_RUNTIME_ROOT,
  type MetadataStore,
  newJobState,
  type ObservedUnit,
  type PiDeps,
  PIP_JOB_EVIDENCE_PATH,
  type PrivateSeam,
  PUBLIC_HOME_BASE,
  pumpGpgStdout,
  readVerifierAvailBytes,
  realPrivateSeam,
  realRemoteSeam,
  realTunnelSeam,
  type RemoteRunner,
  type RemoteSeam,
  resumePruneDeletions,
  retainedIdsPresent,
  revalidatePruneDeletions,
  runBackblazeCycle,
  selectPruneCandidates,
  SOURCE_HOST,
  stepBackupController,
  type TunnelChildFactory,
  tunnelForwardArgs,
  type TunnelHandle,
  type TunnelSeam,
  validateAcceptedReceipt,
  validateControllerState,
  validateReleaseManifest,
  validateSavedWorkerResult,
  validateTransportSettings,
  validateVerifierStatus,
  verifierCiphertextTotal,
  verifierHeadroomRequirement,
  verifyUnitName,
  type WatchdogAssessment,
  weekWindow,
  withinCatchUp,
  workerUnitNameOf,
} from "../scripts/backblaze-file-backup.ts";
import { shellQuote } from "../scripts/backup-guest.ts";

function assert(value: unknown, message?: string): asserts value {
  if (!value) throw new Error(message ?? "Assertion failed");
}

function sha256HexSync(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function uuidFor(seed: number): string {
  const hex = sha256HexSync(new TextEncoder().encode(`uuid:${seed}`))
    .slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${
    hex.slice(16, 20)
  }-${hex.slice(20, 32)}`;
}

const EXCLUSIONS_TEXT = [
  "/home/codex/repos",
  "/.swapfile",
  "/tmp",
  "/var/tmp",
  "/run",
  "/proc",
  "/sys",
  "/dev",
  "/home/codex/.cache",
  "/var/log",
].join("\n");

const RECIPIENT_TEXT = [
  "-----BEGIN PGP PUBLIC KEY BLOCK-----",
  "",
  "synthetic recipient used only by focused tests",
  "-----END PGP PUBLIC KEY BLOCK-----",
  "",
].join("\n");

/** Exact fixed diagnostic labels of the capture module's runBash children;
 * every one produces `${label.replaceAll(":", "-")}.stderr.log`. This pins
 * the cleanup contract independently of the controller internals. */
const CLEANUP_LABELS = [
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
const RECIPIENT_SHA256 = sha256HexSync(
  new TextEncoder().encode(RECIPIENT_TEXT),
);
const RECIPIENT_FINGERPRINT = "BB".repeat(20);
const REVISION = "41c9841624fca662beaaabeadc67636846ef4345";
const SOURCE_CONFIG_SHA256 = sourceConfigSha256({
  sources: sourceConfig(),
  generation: "generation-00000000-0000-0000-0000-000000000000",
  recipientFile: "/tmp/recipient.asc",
  recipientSha256: RECIPIENT_SHA256,
  recipientFingerprint: RECIPIENT_FINGERPRINT,
  exclusionsText: EXCLUSIONS_TEXT,
});

/** 2026-09-06 is a Sunday; local 00:05 is 04:05 UTC (EDT). */
const WINDOW_START = Date.parse("2026-09-06T04:05:00.000Z");
const INVOCATION_A = "11111111111111111111111111111111";
const INVOCATION_B = "22222222222222222222222222222222";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface GenerationFixture {
  jobId: string;
  generation: string;
  request: WorkerRequest;
  requestSha256: string;
  capture: CaptureResult;
  upload: UploadResult;
  publishedIndex: PublishedIndex;
  index: RecoveryIndex;
  indexSha256: string;
  receipt: DecryptedVerification;
  workerResult: Record<string, unknown>;
}

export type { WorkerStatus };

function generationFixture(
  seed: number,
  requestedAtMs: number,
): GenerationFixture {
  return generationFixtureFor(uuidFor(seed), requestedAtMs);
}

function generationFixtureFor(
  uuid: string,
  requestedAtMs: number,
): GenerationFixture {
  const seed = Number.parseInt(uuid.replaceAll("-", "").slice(0, 8), 16) %
    10_000;
  const jobId = `job-${uuid}`;
  const generation = `generation-${uuid}`;
  const stage = `/var/tmp/arch-vps-file-backup/${generation}`;
  const captureStarted = requestedAtMs + 3_600_000;
  const captureFinished = captureStarted + 120_000;
  const uploadStarted = captureFinished + 30_000;
  const uploadFinished = uploadStarted + 90_000;
  const archives: CaptureResult["archives"] = [];
  const uploadArchives: UploadResult["archives"] = [];
  let total = 0;
  for (let i = 0; i < UPLOAD_ROLE_ORDER.length; i += 1) {
    const role = UPLOAD_ROLE_ORDER[i];
    const format = role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
    const bytes = 4096 + seed * 1000 + i;
    const sha256 = sha256HexSync(new TextEncoder().encode(`${seed}:${role}`));
    const path = `${stage}/${role}.${format}`;
    archives.push({ role, path, bytes, sha256, format });
    const name = generationChunkName(generation, role, 0);
    const sha1 = createHash("sha1").update(new TextEncoder().encode(name))
      .digest("hex");
    const fileId = `file-${uuid.slice(0, 8)}-${i}`.padEnd(20, "0");
    const uploadTimestamp = uploadStarted + i;
    const chunk = {
      role,
      index: 0,
      name,
      size: bytes,
      sha256,
      sha1,
      fileId,
      uploadTimestamp,
      verifiedAtUtc: iso(uploadStarted + i),
      reused: false,
      versions: [{
        fileId,
        fileName: name,
        contentLength: bytes,
        contentSha1: sha1,
        action: "upload" as const,
        uploadTimestamp,
      }],
    };
    uploadArchives.push({
      role,
      format,
      path,
      bytes,
      sha256,
      chunks: [chunk],
      verifiedAtUtc: iso(uploadStarted + i),
    });
    total += bytes;
  }
  const capture: CaptureResult = {
    generation,
    stageDirectory: stage,
    archives,
    startedAtUtc: iso(captureStarted),
    finishedAtUtc: iso(captureFinished),
    consistency: "live-file-copy",
    sourceShutdown: false,
  };
  const upload: UploadResult = {
    generation,
    stageDirectory: stage,
    archives: uploadArchives,
    chunkCount: uploadArchives.length,
    totalBytes: total,
    duplicateVersions: [],
    startedAtUtc: iso(uploadStarted),
    finishedAtUtc: iso(uploadFinished),
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  const recipient: IndexRecipient = {
    recipientFile: "/tmp/recipient.asc",
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
  };
  const index = buildRecoveryIndex(capture, upload, recipient);
  const indexSha256 = sha256HexSync(
    new TextEncoder().encode(JSON.stringify(index)),
  );
  const indexObject: B2Object = {
    fileId: `index-${uuid.slice(0, 8)}`.padEnd(20, "0"),
    fileName: `${generationPrefixes(generation)[1]}index.json.gpg`,
    contentLength: 1024 + seed,
    contentSha1: "11".repeat(20),
    action: "upload",
    uploadTimestamp: uploadFinished + 1000,
  };
  const publishedIndex = {
    generation,
    object: indexObject,
    ciphertextBytes: indexObject.contentLength,
    ciphertextSha256: "22".repeat(32),
    indexSha256,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  } as PublishedIndex;
  const archiveReceipts = uploadArchives.map((archive, i) => ({
    role: archive.role,
    format: archive.format,
    ciphertextBytes: archive.bytes,
    ciphertextSha256: archive.sha256,
    compressedBytes: 64,
    compressedSha256: "33".repeat(32),
    ...(archive.role === "recovery" ? {} : { entries: 15 + i }),
  })) as DecryptedVerification["archives"];
  const receipt: DecryptedVerification = {
    schemaVersion: 1,
    generation,
    indexSha256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    recipientSha256: RECIPIENT_SHA256,
    verifiedAtUtc: iso(uploadFinished + 5000),
    archives: archiveReceipts,
    metadataSha256: "66".repeat(32),
    bootSamples: [{
      role: "root",
      member: "./boot/Image",
      bytes: 4096,
      sha256: "44".repeat(32),
    }, {
      role: "root",
      member: "./boot/initramfs-linux.img",
      bytes: 8192,
      sha256: "55".repeat(32),
    }, {
      role: "staging-boot",
      member: "./arch-vmlinuz",
      bytes: 4096,
      sha256: "44".repeat(32),
    }, {
      role: "staging-boot",
      member: "./arch-initrd.img",
      bytes: 8192,
      sha256: "55".repeat(32),
    }],
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
  const envelope = buildRequestEnvelope({
    jobUuid: uuid,
    periodKey: "2026-09-06",
    requestedAtUtc: iso(requestedAtMs),
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    sourceRevision: REVISION,
    sourceConfigSha256: SOURCE_CONFIG_SHA256,
  });
  return {
    jobId,
    generation,
    request: envelope.request,
    requestSha256: envelope.requestSha256,
    capture,
    upload,
    publishedIndex,
    index,
    indexSha256,
    receipt,
    workerResult: { envelope, capture, upload, publishedIndex },
  };
}

function catalogEntry(
  fixture: GenerationFixture,
  acceptedAtMs: number,
): CatalogEntry {
  return {
    index: fixture.index,
    publishedIndex: fixture.publishedIndex,
    receipt: fixture.receipt,
    acceptedAtUtc: iso(acceptedAtMs),
  };
}

function objectForChunk(fixture: GenerationFixture, role: string): B2Object {
  const archive = fixture.upload.archives.find((entry) => entry.role === role)!;
  const chunk = archive.chunks[0];
  return {
    fileId: chunk.fileId,
    fileName: chunk.name,
    contentLength: chunk.size,
    contentSha1: chunk.sha1,
    action: "upload",
    uploadTimestamp: chunk.uploadTimestamp,
  };
}

function inventoryFor(fixtures: GenerationFixture[]): B2Object[] {
  const objects: B2Object[] = [];
  for (const fixture of fixtures) {
    for (const role of UPLOAD_ROLE_ORDER) {
      objects.push(objectForChunk(fixture, role));
    }
    objects.push(fixture.publishedIndex.object);
  }
  return objects;
}

/** Terminal worker status whose timestamps stay within the proof window. */
function workerPendingStatus(
  fixture: GenerationFixture,
  invocationId: string,
): Record<string, unknown> {
  const request = fixture.request;
  const started = Date.parse(request.requestedAtUtc) + 1000;
  return {
    schemaVersion: 1,
    jobId: request.jobId,
    periodKey: request.periodKey,
    generation: request.generation,
    requestSha256: fixture.requestSha256,
    requestedAtUtc: request.requestedAtUtc,
    deadlineAtUtc: request.deadlineAtUtc,
    invocationId,
    state: "PENDING_VERIFIER",
    startedAtUtc: iso(started),
    updatedAtUtc: iso(started + 10_000),
    heartbeatAtUtc: iso(started + 9_000),
    finishedAtUtc: iso(started + 10_000),
    resultSha256: "77".repeat(32),
  };
}

function verifierAcceptedStatus(
  fixture: GenerationFixture,
  invocationId: string,
  receiptSha256: string,
): Record<string, unknown> {
  const request = fixture.request;
  const started = Date.parse(request.requestedAtUtc) + 1000;
  return {
    schemaVersion: 1,
    jobId: request.jobId,
    periodKey: request.periodKey,
    generation: request.generation,
    requestSha256: fixture.requestSha256,
    requestedAtUtc: request.requestedAtUtc,
    deadlineAtUtc: request.deadlineAtUtc,
    invocationId,
    state: "ACCEPTED",
    startedAtUtc: iso(started),
    updatedAtUtc: iso(started + 10_000),
    heartbeatAtUtc: iso(started + 9_000),
    finishedAtUtc: iso(started + 10_000),
    receiptSha256,
  };
}

function terminalObserved(
  status: Record<string, unknown>,
): ObservedUnit {
  const props = new Map<string, string>([
    ["LoadState", "loaded"],
    ["ActiveState", "active"],
    ["SubState", "exited"],
    ["Result", "success"],
    ["MainPID", "0"],
    ["ControlPID", "0"],
    ["ControlGroup", ""],
    ["InvocationID", String(status.invocationId)],
  ]);
  return { props, status, lockFree: true, reachable: true };
}

function stateWithJob(
  fixture: GenerationFixture,
  phase: ControllerPhase,
  overrides: Record<string, unknown> = {},
): ControllerState {
  const envelope = buildRequestEnvelope({
    jobUuid: fixture.request.jobId.slice("job-".length),
    periodKey: fixture.request.periodKey,
    requestedAtUtc: fixture.request.requestedAtUtc,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    sourceRevision: REVISION,
    sourceConfigSha256: SOURCE_CONFIG_SHA256,
  });
  const job = {
    ...newJobState(
      envelope,
      new Date(Date.parse(fixture.request.requestedAtUtc)),
    ),
    phase,
    ...overrides,
  };
  return validateControllerState({ schemaVersion: 1, catalog: [], job });
}

function sourceConfig(): FileSource[] {
  return [
    {
      name: "root",
      uuid: "11111111-1111-1111-1111-111111111111",
      filesystem: "ext4",
      size: 50,
      livePath: "/",
    },
    {
      name: "efi",
      uuid: "22222222-2222-2222-2222-222222222222",
      filesystem: "vfat",
      size: 10,
      livePath: "/efi",
    },
    {
      name: "staging-boot",
      uuid: "33333333-3333-3333-3333-333333333333",
      filesystem: "xfs",
      size: 20,
    },
    {
      name: "staging-efi",
      uuid: "44444444-4444-4444-4444-444444444444",
      filesystem: "vfat",
      size: 10,
    },
    {
      name: "oracle-root",
      uuid: "55555555-5555-5555-5555-555555555555",
      filesystem: "xfs",
      size: 100,
    },
    {
      name: "oracle-oled",
      uuid: "66666666-6666-6666-6666-666666666666",
      filesystem: "xfs",
      size: 2,
    },
  ];
}

function validSettings(fixture: GenerationFixture, runtimeDir: string) {
  return {
    schemaVersion: 1,
    envelope: {
      request: fixture.request,
      requestSha256: fixture.requestSha256,
    },
    captureSettings: {
      sources: sourceConfig(),
      generation: fixture.generation,
      recipientFile: `${runtimeDir}/recipient.asc`,
      recipientSha256: RECIPIENT_SHA256,
      recipientFingerprint: RECIPIENT_FINGERPRINT,
      exclusionsText: EXCLUSIONS_TEXT,
    },
    indexRecipient: {
      recipientFile: `${runtimeDir}/recipient.asc`,
      recipientSha256: RECIPIENT_SHA256,
      recipientFingerprint: RECIPIENT_FINGERPRINT,
    },
    B2Settings: {
      accessKeyId: "key",
      secretAccessKey: "secret",
      bucketId: "bucket",
      bucketName: "pavlovcik-arch-vps-backups",
    },
    sourceRevision: REVISION,
  };
}

// ---------------------------------------------------------------------------
// Harness with fully injected seams
// ---------------------------------------------------------------------------

interface Harness {
  deps: PiDeps;
  clock: { current: Date };
  privateMap: Map<string, unknown | Uint8Array>;
  events: string[];
  gate: { value: BackupControllerGate | null; orphaned: OrphanReason[] };
  store: MetadataStore & { versionsList: B2Object[]; removed: B2Object[] };
  launches: { unitName: string; runtimeDir: string; remainingSec: number }[];
  installs: unknown[];
  tunnels: string[];
  tunnelOpen: () => boolean;
  tunnelCloses: () => number;
}

interface HarnessOptions {
  now: Date;
  observed?: (unitName: string, jobId: string) => ObservedUnit;
  rootResponder?: (script: string) => CommandResult | undefined;
  launchUnitOverride?: (spec: {
    unitName: string;
    runtimeDir: string;
    remainingSec: number;
  }) => Promise<CommandResult>;
  versions?: B2Object[];
  gateValue?: BackupControllerGate | null;
  socket?: { socket: string; defaultSocket: string };
  socketResolver?: (
    publicHome: string,
  ) => Promise<{ socket: string; defaultSocket: string }>;
  seedPrivate?: (map: Map<string, unknown | Uint8Array>) => void;
}

function harness(options: HarnessOptions): Harness {
  const clock = { current: new Date(options.now) };
  const privateMap = new Map<string, unknown | Uint8Array>();
  privateMap.set("config/restic-excludes.txt", EXCLUSIONS_TEXT);
  privateMap.set(RECIPIENT_PATH_KEY, new TextEncoder().encode(RECIPIENT_TEXT));
  privateMap.set(B2_CONFIG_PATH_KEY, {
    accessKeyId: "key",
    secretAccessKey: "secret",
    bucketId: "bucket",
    bucketName: "pavlovcik-arch-vps-backups",
    repository:
      "s3:https://s3.us-east-005.backblazeb2.com/pavlovcik-arch-vps-backups/restic",
    createdAtUtc: iso(0),
    sources: sourceConfig(),
  });
  privateMap.set(DEPLOYMENT_PATH_KEY, {
    sourceRevision: REVISION,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
  });
  options.seedPrivate?.(privateMap);
  const events: string[] = [];
  const gate = {
    value: options.gateValue ?? null,
    orphaned: [] as OrphanReason[],
  };
  const store = {
    versionsList: options.versions ?? [],
    removed: [] as B2Object[],
    versions() {
      return Promise.resolve(structuredClone(this.versionsList));
    },
    remove(object: B2Object) {
      events.push(`remove:${object.fileId}`);
      this.removed.push(object);
      this.versionsList = this.versionsList.filter(
        (entry) => entry.fileId !== object.fileId,
      );
      return Promise.resolve();
    },
  };
  const launches: Harness["launches"] = [];
  const installs: unknown[] = [];
  const tunnels: string[] = [];
  const remote: RemoteSeam = {
    source(script) {
      events.push(`source:${script.slice(0, 40)}`);
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    },
    root(script) {
      events.push(`root:${script.slice(0, 40)}`);
      const responder = options.rootResponder?.(script);
      return Promise.resolve(
        responder ?? { code: 0, stdout: "", stderr: "" },
      );
    },
    installer(payload) {
      installs.push(payload);
      return Promise.resolve({ code: 0, stdout: "{}", stderr: "" });
    },
    launchUnit(spec) {
      launches.push({
        unitName: spec.unitName,
        runtimeDir: spec.runtimeDir,
        remainingSec: spec.remainingSec,
      });
      events.push(`launch:${spec.unitName}`);
      if (options.launchUnitOverride !== undefined) {
        return options.launchUnitOverride(spec);
      }
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    },
    observe: (unitName, jobId) =>
      Promise.resolve(
        options.observed?.(unitName, jobId) ?? {
          props: new Map(),
          status: null,
          lockFree: false,
          reachable: false,
        },
      ),
    resolveAgentSocket(publicHome) {
      if (options.socketResolver !== undefined) {
        return options.socketResolver(publicHome);
      }
      return Promise.resolve(
        options.socket ?? {
          socket: "/run/user/1002/gnupg/custom/S.gpg-agent",
          defaultSocket: "/run/user/1002/gnupg/S.gpg-agent",
        },
      );
    },
  };
  const privateSeam: PrivateSeam = {
    read<T>(path: string): Promise<T | undefined> {
      const value = privateMap.get(path);
      if (value === undefined) return Promise.resolve(undefined);
      if (typeof value === "string") {
        return Promise.resolve(JSON.parse(value) as T);
      }
      if (value instanceof Uint8Array) {
        return Promise.resolve(
          JSON.parse(new TextDecoder().decode(value)) as T,
        );
      }
      return Promise.resolve(value as T);
    },
    write(path, value) {
      const record = value as Record<string, unknown>;
      const plan = (record?.job as Record<string, unknown> | undefined)
        ?.prune as { plan?: unknown[] } | undefined;
      events.push(
        `write:${path}${plan?.plan?.length ? ":plan" : ""}`,
      );
      privateMap.set(path, structuredClone(value));
      return Promise.resolve();
    },
    readBytes(path, maxBytes) {
      const value = privateMap.get(path);
      if (value === undefined) return Promise.resolve(undefined);
      if (value instanceof Uint8Array) {
        if (value.byteLength > maxBytes) {
          return Promise.reject(new Error("exceeds bound"));
        }
        return Promise.resolve(value.slice());
      }
      const bytes = new TextEncoder().encode(
        typeof value === "string" ? value : JSON.stringify(value),
      );
      if (bytes.byteLength > maxBytes) {
        return Promise.reject(new Error("exceeds bound"));
      }
      return Promise.resolve(bytes);
    },
    writeBytes(path, bytes) {
      events.push(`writebytes:${path}`);
      privateMap.set(path, bytes.slice());
      return Promise.resolve();
    },
    async readText(path, maxBytes) {
      const bytes = await this.readBytes(path, maxBytes);
      return bytes === undefined ? undefined : new TextDecoder().decode(bytes);
    },
  };
  const gateSeam: GateSeam = {
    read() {
      return Promise.resolve(gate.value);
    },
    create(value) {
      if (gate.value !== null) {
        return Promise.reject(new Error("Gate already exists"));
      }
      gate.value = value;
      events.push("gate:create");
      return Promise.resolve();
    },
    bind(_expected, invocationId) {
      if (gate.value === null) return Promise.reject(new Error("Gate absent"));
      gate.value = { ...gate.value, unitInvocationId: invocationId };
      return Promise.resolve(gate.value);
    },
    orphan(_expected, reason) {
      if (gate.value === null) return Promise.reject(new Error("Gate absent"));
      gate.value = { ...gate.value, state: "orphaned", orphanReason: reason };
      gate.orphaned.push(reason);
      return Promise.resolve(gate.value);
    },
    clear() {
      if (gate.value === null) return Promise.reject(new Error("Gate absent"));
      gate.value = null;
      events.push("gate:clear");
      return Promise.resolve();
    },
  };
  const tunnelCurrent = { value: null as TunnelHandle | null, closes: 0 };
  const tunnel: TunnelSeam = {
    current() {
      return tunnelCurrent.value;
    },
    open(remoteSocket) {
      tunnels.push(remoteSocket);
      events.push(`tunnel:open:${remoteSocket}`);
      const close = () => {
        tunnelCurrent.closes += 1;
        if (tunnelCurrent.value === handle) tunnelCurrent.value = null;
        return Promise.resolve();
      };
      const handle = { close } as TunnelHandle;
      tunnelCurrent.value = handle;
      return Promise.resolve(handle);
    },
    close() {
      const handle = tunnelCurrent.value;
      tunnelCurrent.value = null;
      if (handle === null) return Promise.resolve();
      tunnelCurrent.closes += 1;
      return Promise.resolve();
    },
  };
  const deps: PiDeps = {
    now: () => new Date(clock.current),
    lock: (path, work) => {
      if (path !== CONTROLLER_LOCK_PATH) {
        throw new Error("Unexpected lock path");
      }
      return work();
    },
    private: privateSeam,
    remote,
    tunnel,
    metadataStore: () => store,
    gate: gateSeam,
    logger: () => {},
    sleep: async () => {},
  };
  return {
    deps,
    clock,
    privateMap,
    events,
    gate,
    store,
    launches,
    installs,
    tunnels,
    tunnelOpen: () => tunnelCurrent.value !== null,
    tunnelCloses: () => tunnelCurrent.closes,
  };
}

const RECIPIENT_PATH_KEY = ".private/file-backup/recipient.asc";
const B2_CONFIG_PATH_KEY = ".private/b2-file-backup.json";
const DEPLOYMENT_PATH_KEY = ".private/backblaze-deployment.json";

// ---------------------------------------------------------------------------
// Sunday/DST catch-up window
// ---------------------------------------------------------------------------

Deno.test("period: Sunday window and DST boundaries", () => {
  const start = weekWindow(new Date(WINDOW_START));
  assert(start.periodKey === "2026-09-06");
  assert(start.startAtUtc === "2026-09-06T04:05:00.000Z");
  assert(start.endAtUtc === "2026-09-06T10:05:00.000Z");
  assert(withinCatchUp(new Date(WINDOW_START)));
  assert(withinCatchUp(new Date(Date.parse(start.endAtUtc) - 1)));
  assert(!withinCatchUp(new Date(Date.parse(start.endAtUtc))));
  assert(!withinCatchUp(new Date("2026-09-05T23:00:00.000Z")));
  const spring = weekWindow(new Date("2026-03-08T05:05:00.000Z"));
  assert(spring.periodKey === "2026-03-08");
  assert(spring.startAtUtc === "2026-03-08T05:05:00.000Z");
  const fall = weekWindow(new Date("2026-11-01T04:05:00.000Z"));
  assert(fall.periodKey === "2026-11-01");
  assert(fall.startAtUtc === "2026-11-01T04:05:00.000Z");
  assert(
    weekWindow(new Date("2026-09-06T09:59:59.000Z")).periodKey === "2026-09-06",
  );
});

Deno.test("request: immutable envelope with a fixed six-hour deadline", () => {
  const parts = {
    jobUuid: uuidFor(1),
    periodKey: "2026-09-06",
    requestedAtUtc: iso(WINDOW_START),
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
    sourceRevision: REVISION,
    sourceConfigSha256: SOURCE_CONFIG_SHA256,
  };
  const first = buildRequestEnvelope(parts);
  const second = buildRequestEnvelope(parts);
  assert(first.requestSha256 === second.requestSha256);
  assert(
    Date.parse(first.request.deadlineAtUtc) -
        Date.parse(first.request.requestedAtUtc) === 6 * 3_600_000,
  );
  assert(
    first.request.generation.slice("generation-".length) ===
      first.request.jobId.slice("job-".length),
  );
  let threw = false;
  try {
    buildRequestEnvelope({ ...parts, periodKey: "2026-09-07" });
  } catch {
    threw = true;
  }
  assert(threw, "A non-Sunday period key must be rejected");
});

// ---------------------------------------------------------------------------
// Settings, release manifest, wrappers
// ---------------------------------------------------------------------------

Deno.test("settings: strict keys and recipient consistency", () => {
  const fixture = generationFixture(1, WINDOW_START);
  const runtimeDir = `${JOBS_RUNTIME_ROOT}/${fixture.jobId}`;
  const settings = validSettings(fixture, runtimeDir);
  assert(validateTransportSettings(settings).sourceRevision === REVISION);
  let threw = false;
  try {
    validateTransportSettings({ ...settings, deps: {} });
  } catch {
    threw = true;
  }
  assert(threw, "A settings deps field must be rejected");
  threw = false;
  try {
    validateTransportSettings({
      ...settings,
      indexRecipient: {
        ...settings.indexRecipient,
        recipientSha256: "99".repeat(32),
      },
    });
  } catch {
    threw = true;
  }
  assert(threw, "A mismatched recipient must be rejected");
  threw = false;
  try {
    validateTransportSettings({
      ...settings,
      B2Settings: { ...settings.B2Settings, bucketId: "" },
    });
  } catch {
    threw = true;
  }
  assert(threw, "An empty B2 bucket id must be rejected");
});

Deno.test("release: manifest path and hash validation", () => {
  const manifest = {
    sourceRevision: REVISION,
    files: [{
      path: "scripts/backblaze-file-backup.ts",
      sha256: "aa".repeat(32),
    }],
  };
  assert(validateReleaseManifest(manifest, REVISION).files.length === 1);
  let threw = false;
  try {
    validateReleaseManifest({
      ...manifest,
      files: [{ path: "config/x", sha256: "aa".repeat(32) }],
    }, REVISION);
  } catch {
    threw = true;
  }
  assert(threw, "A disallowed release path must be rejected");
  threw = false;
  try {
    validateReleaseManifest(manifest, "f".repeat(40));
  } catch {
    threw = true;
  }
  assert(threw, "A mismatched release revision must be rejected");
});

Deno.test("entry: generated wrappers bind a validated UUID and revision", () => {
  const fixture = generationFixture(2, WINDOW_START);
  const worker = entryWorkerText(fixture.jobId, REVISION);
  assert(worker.includes(`runRemoteWorker("${fixture.jobId}")`));
  assert(
    worker.includes(`/releases/${REVISION}/scripts/backblaze-file-backup.ts`),
  );
  const verify = entryVerifyText(fixture.jobId, REVISION);
  assert(verify.includes(`runRemoteVerifier("${fixture.jobId}")`));
  let threw = false;
  try {
    entryWorkerText("job-not-a-uuid", REVISION);
  } catch {
    threw = true;
  }
  assert(threw, "An unvalidated jobId must never be interpolated");
  threw = false;
  try {
    entryVerifyText(fixture.jobId, "not-a-revision");
  } catch {
    threw = true;
  }
  assert(threw, "An unvalidated revision must never be interpolated");
});

// ---------------------------------------------------------------------------
// Verifier status schema and GPG status parsing
// ---------------------------------------------------------------------------

Deno.test("verifier status: terminal proof fields", () => {
  const fixture = generationFixture(3, WINDOW_START);
  const base = {
    schemaVersion: 1,
    jobId: fixture.jobId,
    periodKey: fixture.request.periodKey,
    generation: fixture.generation,
    requestSha256: fixture.requestSha256,
    requestedAtUtc: fixture.request.requestedAtUtc,
    deadlineAtUtc: fixture.request.deadlineAtUtc,
    invocationId: INVOCATION_B,
    state: "ACCEPTED",
    startedAtUtc: iso(WINDOW_START + 1000),
    updatedAtUtc: iso(WINDOW_START + 2000),
    heartbeatAtUtc: iso(WINDOW_START + 1900),
    finishedAtUtc: iso(WINDOW_START + 2000),
    receiptSha256: "88".repeat(32),
  };
  assert(validateVerifierStatus(base).state === "ACCEPTED");
  let threw = false;
  try {
    validateVerifierStatus({ ...base, receiptSha256: undefined });
  } catch {
    threw = true;
  }
  assert(threw, "ACCEPTED requires a receipt hash");
  threw = false;
  try {
    validateVerifierStatus({
      ...base,
      state: "VERIFYING",
      finishedAtUtc: null,
    });
  } catch {
    threw = true;
  }
  assert(threw, "VERIFYING must be nonterminal");
  const failedBase: Record<string, unknown> = { ...base };
  delete failedBase.receiptSha256;
  assert(
    validateVerifierStatus({
      ...failedBase,
      state: "FAILED",
      finishedAtUtc: iso(WINDOW_START + 2000),
      errorCode: "DECRYPT_FAILED",
    }).errorCode === "DECRYPT_FAILED",
  );
});

Deno.test("gpg: status-line decisions", () => {
  assert(
    !decideGpgStatus([
      "[GNUPG:] DECRYPTION_OKAY",
      "[GNUPG:] GOODMDC",
    ]).rejected,
  );
  assert(
    !decideGpgStatus([
      "[GNUPG:] DECRYPTION_OKAY",
      "[GNUPG:] DECRYPTION_INFO 1 2 3",
    ]).rejected,
  );
  assert(
    decideGpgStatus([
      "[GNUPG:] DECRYPTION_OKAY",
      "[GNUPG:] BADMDC",
    ]).rejected,
  );
  assert(decideGpgStatus(["[GNUPG:] DECRYPTION_FAILED"]).rejected);
  assert(decideGpgStatus(["[GNUPG:] GOODMDC"]).rejected);
});

// ---------------------------------------------------------------------------
// Result and receipt binding
// ---------------------------------------------------------------------------

Deno.test("result: saved worker result identity binding", async () => {
  const fixture = generationFixture(4, WINDOW_START);
  const recipient = {
    recipientFile: "/tmp/recipient.asc",
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
  };
  const binding = {
    requestSha256: fixture.requestSha256,
    generation: fixture.generation,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
  };
  const saved = await validateSavedWorkerResult(
    fixture.workerResult,
    recipient,
    binding,
  );
  assert(saved.indexSha256 === fixture.indexSha256);
  let threw = false;
  try {
    await validateSavedWorkerResult(
      {
        ...fixture.workerResult,
        publishedIndex: {
          ...fixture.publishedIndex,
          indexSha256: "99".repeat(32),
        },
      },
      recipient,
      binding,
    );
  } catch {
    threw = true;
  }
  assert(threw, "A mismatched published index hash must be rejected");
  threw = false;
  try {
    await validateSavedWorkerResult(fixture.workerResult, recipient, {
      ...binding,
      requestSha256: "00".repeat(32),
    });
  } catch {
    threw = true;
  }
  assert(threw, "A mismatched request hash must be rejected");
});

Deno.test("acceptance: receipt identity binding", () => {
  const fixture = generationFixture(5, WINDOW_START);
  const binding = {
    generation: fixture.generation,
    indexSha256: fixture.indexSha256,
    recipientSha256: RECIPIENT_SHA256,
    recipientFingerprint: RECIPIENT_FINGERPRINT,
  };
  const receipt = validateAcceptedReceipt(
    fixture.receipt,
    fixture.index,
    binding,
  );
  assert(receipt.machineBootRestoreProved === false);
  let threw = false;
  try {
    validateAcceptedReceipt(
      { ...fixture.receipt, generation: `generation-${uuidFor(99)}` },
      fixture.index,
      binding,
    );
  } catch {
    threw = true;
  }
  assert(threw, "A receipt for another generation must be rejected");
  threw = false;
  try {
    validateAcceptedReceipt(
      {
        ...fixture.receipt,
        archives: fixture.receipt.archives.map((archive, i) =>
          i === 0 ? { ...archive, ciphertextSha256: "00".repeat(32) } : archive
        ),
      },
      fixture.index,
      binding,
    );
  } catch {
    threw = true;
  }
  assert(threw, "A drifting ciphertext identity must be rejected");
});

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

Deno.test("retention: keeps newest four, preserves pending/foreign/start", () => {
  const fixtures = [1, 2, 3, 4, 5].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const catalog = fixtures.map((fixture, i) =>
    catalogEntry(fixture, WINDOW_START + i * 1000)
  );
  const inventory = inventoryFor(fixtures);
  const pending = generationFixture(6, WINDOW_START + 6 * 3_600_000);
  inventory.push(...inventoryFor([pending]));
  inventory.push({
    fileId: "foreign000000000000",
    fileName: "restic/direct-v1/other/generation-11111/role/00000000",
    contentLength: 10,
    contentSha1: "11".repeat(20),
    action: "upload",
    uploadTimestamp: 1,
  });
  inventory.push({
    fileId: "start0000000000000",
    fileName: `${generationPrefixes(fixtures[1].generation)[0]}root/00000000`,
    contentLength: 1,
    contentSha1: "11".repeat(20),
    action: "start",
    uploadTimestamp: 1,
  });
  inventory.push({
    fileId: "hide00000000000000",
    fileName: `${generationPrefixes(fixtures[0].generation)[0]}root/00000000`,
    contentLength: 0,
    contentSha1: "11".repeat(20),
    action: "hide",
    uploadTimestamp: 1,
  });
  const oldestIds = new Set(
    fixtures[0].upload.archives.flatMap((archive) =>
      archive.chunks.map((chunk) => chunk.fileId)
    ).concat([fixtures[0].publishedIndex.object.fileId]),
  );
  const newestIds = new Set(
    fixtures.slice(1).flatMap((fixture) =>
      fixture.upload.archives.flatMap((archive) =>
        archive.chunks.map((chunk) => chunk.fileId)
      ).concat([fixture.publishedIndex.object.fileId])
    ),
  );
  const selection = selectPruneCandidates(inventory, catalog);
  assert(selection.toPrune.length === 1);
  assert(selection.toPrune[0] === fixtures[0].generation);
  assert(
    selection.toDelete.every((object) =>
      oldestIds.has(object.fileId) ||
      object.fileId === "hide00000000000000"
    ),
    "Only the oldest accepted generation may be selected",
  );
  assert(
    selection.toDelete.every((object) =>
      object.action !== "start" &&
      !object.fileName.includes("other/") &&
      !newestIds.has(object.fileId) &&
      !object.fileId.startsWith(
        `file-${
          pending.generation.slice(
            "generation-".length,
            "generation-".length + 8,
          )
        }-`,
      )
    ),
    "Pending, foreign and start markers must be preserved",
  );
  assert(
    !selection.retainedFileIds.some((id) => oldestIds.has(id)),
  );
  assert(retainedIdsPresent(inventory, selection.retainedFileIds));
  const fifthsId = fixtures[4].upload.archives[0].chunks[0].fileId;
  const missing = inventory.filter((object) => object.fileId !== fifthsId);
  assert(!retainedIdsPresent(missing, selection.retainedFileIds));
});

Deno.test("retention: partial deletion resume and retained-ID guard", () => {
  const fixtures = [1, 2, 3, 4, 5].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const catalog = fixtures.map((fixture, i) =>
    catalogEntry(fixture, WINDOW_START + i * 1000)
  );
  const inventory = inventoryFor(fixtures);
  const selection = selectPruneCandidates(inventory, catalog);
  const plan = [{
    generation: fixtures[0].generation,
    fileIds: selection.toDelete.map((object) => object.fileId),
  }];
  const half = Math.floor(plan[0].fileIds.length / 2);
  const halfway = inventory.filter((object) =>
    !plan[0].fileIds.slice(0, half).includes(object.fileId)
  );
  const resumed = resumePruneDeletions(halfway, plan);
  assert(resumed.remaining.length === plan[0].fileIds.length - half);
  assert(resumed.removed.length === half);
  assert(
    retainedIdsPresent(halfway, selection.retainedFileIds),
    "Retained IDs must remain present mid-prune",
  );
  const absentAll = inventory.filter((object) =>
    !plan[0].fileIds.includes(object.fileId)
  );
  const final = resumePruneDeletions(absentAll, plan);
  assert(final.remaining.length === 0);
  assert(final.removed.length === plan[0].fileIds.length);
});

// ---------------------------------------------------------------------------
// Watchdog assessment
// ---------------------------------------------------------------------------

Deno.test("watchdog: active/stale/orphan/pending/missed/complete", () => {
  const fixture = generationFixture(7, WINDOW_START);
  const orphanGate: BackupControllerGate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    state: "orphaned",
    orphanReason: "TERMINAL_PROOF_MISSING",
  };
  const orphaned = assessBackblazeWatchdog(
    stateWithJob(fixture, "VERIFIER_RUNNING"),
    orphanGate,
    new Date(WINDOW_START + 60_000),
  );
  assert(!orphaned.healthy);
  assert(orphaned.status.startsWith("B2_JOB_ORPHANED"));
  const workerGate: BackupControllerGate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const active = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
  });
  assert(
    assessBackblazeWatchdog(
      active,
      workerGate,
      new Date(WINDOW_START + 60_000),
    ).healthy,
  );
  const stale = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    // The source status heartbeat is old; a fresh Pi polling time in the
    // job heartbeat must never make the run look healthy.
    workerStatus: {
      ...workerPendingStatus(fixture, INVOCATION_A),
      heartbeatAtUtc: iso(WINDOW_START + 1_000),
      updatedAtUtc: iso(WINDOW_START + 11_000),
    },
  });
  stale.job!.heartbeatAtUtc = iso(WINDOW_START + 30_000);
  stale.job!.updatedAtUtc = iso(WINDOW_START + 30_000);
  assert(
    !assessBackblazeWatchdog(
      stale,
      workerGate,
      new Date(WINDOW_START + 300_000),
    ).healthy,
  );
  assert(
    !assessBackblazeWatchdog(
      active,
      workerGate,
      new Date(Date.parse(fixture.request.deadlineAtUtc) + 1000),
    ).healthy,
  );
  assert(
    !assessBackblazeWatchdog(
      stateWithJob(fixture, "WORKER_TERMINAL"),
      null,
      new Date(WINDOW_START + 60_000),
    ).healthy,
  );
  const complete = stateWithJob(fixture, "COMPLETE");
  assert(
    assessBackblazeWatchdog(
      complete,
      null,
      new Date(WINDOW_START + 60_000),
    ).healthy,
  );
  const previousPeriod = {
    ...complete,
    job: {
      ...complete.job!,
      envelope: {
        ...complete.job!.envelope,
        request: {
          ...complete.job!.envelope.request,
          periodKey: "2026-08-30",
        },
      },
    },
  } as ControllerState;
  const missed = assessBackblazeWatchdog(
    previousPeriod,
    null,
    new Date("2026-09-08T00:00:00.000Z"),
  );
  assert(!missed.healthy);
  assert(missed.status.startsWith("B2_PERIOD_MISSED"));
  // An unrecognized phase never looks healthy (last-resort branch).
  const unknown = {
    schemaVersion: 1 as const,
    catalog: [],
    job: {
      ...stateWithJob(fixture, "WORKER_RUNNING").job!,
      phase: "UNKNOWN",
    },
  };
  const assessment = assessBackblazeWatchdog(
    unknown as unknown as ControllerState,
    null,
    new Date(WINDOW_START),
  ) as WatchdogAssessment;
  assert(!assessment.healthy);
  assert(assessment.status.startsWith("B2_STATE_UNKNOWN"));
});

Deno.test(
  "watchdog: previous-period complete is current only with its exact catalog proof",
  () => {
    // The previous-period job completed, but its verification and acceptance
    // both happened inside the current Sunday window.
    const now = new Date(WINDOW_START + 2 * 3_600_000);
    const acceptedAt = WINDOW_START + 3_600_000;
    const fixture = generationFixture(23, WINDOW_START - 8 * 3_600_000);
    const complete = stateWithJob(fixture, "COMPLETE");
    const previousPeriod = {
      ...complete,
      job: {
        ...complete.job!,
        envelope: {
          ...complete.job!.envelope,
          request: {
            ...complete.job!.envelope.request,
            periodKey: "2026-08-30",
          },
        },
      },
    } as ControllerState;
    const entry = catalogEntry(fixture, acceptedAt);
    const proved = {
      ...previousPeriod,
      catalog: [{
        ...entry,
        receipt: { ...entry.receipt, verifiedAtUtc: iso(acceptedAt) },
      }],
    } as ControllerState;
    const current = assessBackblazeWatchdog(proved, null, now);
    assert(current.healthy);
    assert(current.status === `B2_BACKUP_CURRENT:${fixture.jobId}`);

    const missed = (state: ControllerState) => {
      const assessment = assessBackblazeWatchdog(state, null, now);
      assert(!assessment.healthy);
      assert(assessment.status.startsWith("B2_PERIOD_MISSED"));
    };
    // An acceptance from before the current window is not a current point.
    missed({
      ...previousPeriod,
      catalog: [{
        ...entry,
        receipt: { ...entry.receipt, verifiedAtUtc: iso(acceptedAt) },
        acceptedAtUtc: iso(WINDOW_START - 3_600_000),
      }],
    } as ControllerState);
    // An unrelated (newer) catalog generation never satisfies the old job.
    missed({
      ...previousPeriod,
      catalog: [
        catalogEntry(generationFixture(31, acceptedAt - 3_600_000), acceptedAt),
      ],
    } as ControllerState);
    // Future verification and acceptance timestamps are not in-window proof.
    missed({
      ...previousPeriod,
      catalog: [{
        ...entry,
        receipt: {
          ...entry.receipt,
          verifiedAtUtc: iso(now.getTime() + 3_600_000),
        },
      }],
    } as ControllerState);
    missed({
      ...previousPeriod,
      catalog: [{
        ...entry,
        receipt: { ...entry.receipt, verifiedAtUtc: iso(acceptedAt) },
        acceptedAtUtc: iso(now.getTime() + 3_600_000),
      }],
    } as ControllerState);
  },
);

Deno.test("watchdog: source heartbeat never falls back to Pi polling time", () => {
  const fixture = generationFixture(15, WINDOW_START);
  const workerGate: BackupControllerGate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  // A fresh Pi heartbeat with no bound source status at all is unhealthy.
  const missing = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
  });
  missing.job!.heartbeatAtUtc = iso(WINDOW_START + 30_000);
  missing.job!.updatedAtUtc = iso(WINDOW_START + 30_000);
  const missingAssessment = assessBackblazeWatchdog(
    missing,
    workerGate,
    new Date(WINDOW_START + 60_000),
  );
  assert(!missingAssessment.healthy);
  assert(
    missingAssessment.status.startsWith("B2_BACKUP_SOURCE_STATUS_MISSING"),
  );
  // An unreachable source stays unhealthy even with a fresh Pi heartbeat.
  const unreachable = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
  });
  unreachable.job!.heartbeatAtUtc = iso(WINDOW_START + 30_000);
  const unreachableAssessment = assessBackblazeWatchdog(
    unreachable,
    workerGate,
    new Date(WINDOW_START + 60_000),
    {
      observedAtUtc: iso(WINDOW_START + 60_000),
      reachable: false,
      invocationId: null,
      status: null,
    },
  );
  assert(!unreachableAssessment.healthy);
  assert(unreachableAssessment.status.startsWith("B2_SOURCE_UNREACHABLE"));
  // An altered status identity is rejected even when it is otherwise fresh:
  // a valid-but-different period key does not bind this request.
  const altered = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    workerStatus: {
      ...workerPendingStatus(fixture, INVOCATION_A),
      periodKey: "2026-09-13",
    },
  });
  altered.job!.heartbeatAtUtc = iso(WINDOW_START + 30_000);
  const alteredAssessment = assessBackblazeWatchdog(
    altered,
    workerGate,
    new Date(WINDOW_START + 60_000),
  );
  assert(!alteredAssessment.healthy);
  assert(alteredAssessment.status.startsWith("B2_BACKUP_SOURCE_MISMATCH"));
  // The live source status must bind the same request and invocation.
  const swapped = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
  });
  swapped.job!.heartbeatAtUtc = iso(WINDOW_START + 30_000);
  const swappedAssessment = assessBackblazeWatchdog(
    swapped,
    workerGate,
    new Date(WINDOW_START + 60_000),
    {
      observedAtUtc: iso(WINDOW_START + 60_000),
      reachable: true,
      invocationId: INVOCATION_B,
      status: workerPendingStatus(fixture, INVOCATION_A),
    },
  );
  assert(!swappedAssessment.healthy);
  assert(swappedAssessment.status.startsWith("B2_BACKUP_SOURCE_MISMATCH"));
  // A verifier live status in a worker phase is malformed for this phase.
  const wrongSchema = assessBackblazeWatchdog(
    swapped,
    workerGate,
    new Date(WINDOW_START + 60_000),
    {
      observedAtUtc: iso(WINDOW_START + 60_000),
      reachable: true,
      invocationId: INVOCATION_A,
      status: {
        ...workerPendingStatus(fixture, INVOCATION_A),
        state: "VERIFYING",
        receiptSha256: undefined,
      },
    },
  );
  assert(!wrongSchema.healthy);
});

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

Deno.test("orchestration: outside the catch-up window creates no job", async () => {
  const h = harness({ now: new Date("2026-09-05T23:00:00.000Z") });
  const report = await runBackblazeCycle(h.deps, 4);
  assert(report.status.startsWith("B2_SKIPPED"));
  assert(!report.healthy);
  assert(!h.privateMap.has(CONTROLLER_STATE_PATH));
});

Deno.test("orchestration: Oracle runtime is required before new work", async () => {
  const h = harness({ now: new Date(WINDOW_START + 1000) });
  const report = await runBackblazeCycle(h.deps, 4);
  assert(report.status.startsWith("B2_SKIPPED"));
  assert(!h.privateMap.has(CONTROLLER_STATE_PATH));
});

Deno.test("orchestration: duplicate invocation never creates a second job", async () => {
  const fixture = generationFixture(8, WINDOW_START);
  const state = stateWithJob(fixture, "REQUESTED");
  const h = harness({ now: new Date(WINDOW_START + 1000) });
  const first = await stepBackupController(state, h.deps, h.deps.now());
  assert(first.job!.envelope.request.jobId === fixture.jobId);
  assert(h.launches.length === 1);
  assert(h.installs.length === 1);
  assert(
    Date.parse(first.job!.updatedAtUtc) ===
        Date.parse(first.job!.envelope.request.requestedAtUtc) ||
      Date.parse(first.job!.updatedAtUtc) >=
        Date.parse("2026-09-06T04:05:01.000Z"),
  );
  const h2 = harness({ now: new Date(WINDOW_START + 2000) });
  const second = await stepBackupController(first, h2.deps, h2.deps.now());
  assert(second.job!.envelope.request.jobId === fixture.jobId);
  assert(
    Date.parse(second.job!.envelope.request.requestedAtUtc) ===
      Date.parse(first.job!.envelope.request.requestedAtUtc),
  );
  assert(h2.launches.length === 0, "A resume must not relaunch the unit");
});

Deno.test("orchestration: transient installer failure stays REQUESTED and retries the same request", async () => {
  const fixture = generationFixture(26, WINDOW_START);
  const state = stateWithJob(fixture, "REQUESTED");
  const h = harness({ now: new Date(WINDOW_START + 60_000) });
  let failed = true;
  const originalInstaller = h.deps.remote.installer.bind(h.deps.remote);
  h.deps.remote.installer = async (payload) => {
    if (failed) {
      failed = false;
      return { code: 1, stdout: "", stderr: "transport error" };
    }
    return await originalInstaller(payload);
  };
  const first = await stepBackupController(state, h.deps, h.deps.now());
  assert(first.job!.phase === "REQUESTED", `phase=${first.job!.phase}`);
  const launchCount = (): number => h.launches.length;
  const currentGate = () => h.gate.value;
  if (launchCount() !== 0) {
    throw new Error("no launch until the install succeeds");
  }
  if (currentGate() !== null) {
    throw new Error("no gate was created by a failed install");
  }
  const second = await stepBackupController(first, h.deps, h.deps.now());
  assert(second.job!.phase === "WORKER_LAUNCHED");
  assert(second.job!.envelope.request.jobId === fixture.jobId);
  if (launchCount() !== 1) {
    throw new Error("the retry launches after the same install succeeded");
  }
  const gateAfter = currentGate();
  if (gateAfter === null || gateAfter.jobId !== fixture.jobId) {
    throw new Error("the retry owns the exact worker gate");
  }
});

Deno.test("orchestration: launch loss after gate creation resumes without replacement or FAILED", async () => {
  const fixture = generationFixture(27, WINDOW_START);
  const state = stateWithJob(fixture, "REQUESTED");
  const h = harness({ now: new Date(WINDOW_START + 60_000) });
  let failed = true;
  h.deps.remote.launchUnit = (spec) => {
    if (failed) {
      failed = false;
      return Promise.reject(new Error("ssh lost after systemd-run"));
    }
    h.launches.push({
      unitName: spec.unitName,
      runtimeDir: spec.runtimeDir,
      remainingSec: spec.remainingSec,
    });
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const first = await stepBackupController(state, h.deps, h.deps.now());
  assert(first.job!.phase === "REQUESTED", `phase=${first.job!.phase}`);
  assert(
    h.gate.value !== null && h.gate.value.jobId === fixture.jobId,
    "the exact unbound gate survives the launch loss",
  );
  assert(
    h.events.filter((entry) => entry === "gate:create").length === 1,
    "the gate is created exactly once",
  );
  assert(h.gate.orphaned.length === 0, "no orphan on an uncertain launch");
  assert(
    first.job!.failure === undefined,
    "a lost launch response is never a terminal FAILED",
  );
  const observed = (): ObservedUnit => ({
    props: new Map<string, string>([
      ["LoadState", "loaded"],
      ["ActiveState", "active"],
      ["SubState", "running"],
      ["Result", "success"],
      ["MainPID", "123"],
      ["ControlPID", "0"],
      ["InvocationID", INVOCATION_A],
    ]),
    status: null,
    lockFree: false,
    reachable: true,
  });
  h.deps.remote.observe = () => Promise.resolve(observed());
  const second = await stepBackupController(first, h.deps, h.deps.now());
  assert(second.job!.phase === "WORKER_LAUNCHED");
  assert(h.launches.length === 1, "the retry relaunches the same unit");
  assert(
    h.events.filter((entry) => entry === "gate:create").length === 1,
    "the existing exact gate is never replaced",
  );
  const third = await stepBackupController(second, h.deps, h.deps.now());
  assert(third.job!.phase === "WORKER_RUNNING");
  assert(
    third.job!.workerInvocationId === INVOCATION_A,
    "the matching source observation binds the same job/unit invocation",
  );
});

Deno.test("orchestration: an expired request never installs or launches", async () => {
  const fixture = generationFixture(28, WINDOW_START);
  const state = stateWithJob(fixture, "REQUESTED");
  const h = harness({
    now: new Date(Date.parse(fixture.request.deadlineAtUtc) + 1000),
  });
  const next = await stepBackupController(state, h.deps, h.deps.now());
  assert(next.job!.phase === "FAILED", `phase=${next.job!.phase}`);
  assert(
    next.job!.failure!.code === "ORPHANED_SOURCE_UNREACHABLE_AT_DEADLINE",
    `code=${next.job!.failure!.code}`,
  );
  assert(h.installs.length === 0, "an expired request never installs");
  assert(h.launches.length === 0, "an expired request never launches");
});

Deno.test("orchestration: SSH loss after launch preserves gate and job", async () => {
  const fixture = generationFixture(9, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
  });
  const waiting = await stepBackupController(state, h.deps, h.deps.now());
  assert(waiting.job!.phase === "WORKER_RUNNING");
  assert(h.gate.value !== null);
  assert((h.gate.value!.state as string) === "active");
  assert(waiting.job!.envelope.request.jobId === fixture.jobId);
  h.clock.current = new Date(Date.parse(fixture.request.deadlineAtUtc) + 1000);
  const orphaned = await stepBackupController(waiting, h.deps, h.deps.now());
  assert(orphaned.job!.phase === "FAILED");
  assert((h.gate.value!.state as string) === "orphaned");
  assert(h.gate.orphaned.includes("SOURCE_UNREACHABLE_AT_DEADLINE"));
  assert(orphaned.job!.envelope.request.jobId === fixture.jobId);
});

Deno.test("orchestration: terminal proof mismatch orphans and never clears", async () => {
  const fixture = generationFixture(10, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_RUNNING", {
    workerInvocationId: INVOCATION_A,
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const observed = terminalObserved(
    workerPendingStatus(fixture, INVOCATION_B),
  );
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
    observed: () => observed,
  });
  const failed = await stepBackupController(state, h.deps, h.deps.now());
  assert(failed.job!.phase === "FAILED");
  assert(
    failed.job!.failure!.code === "ORPHANED_UNIT_IDENTITY_MISMATCH",
    `code=${failed.job!.failure!.code}`,
  );
  assert((h.gate.value!.state as string) === "orphaned");
  assert(h.gate.value!.orphanReason === "UNIT_IDENTITY_MISMATCH");
  assert(!h.events.includes("gate:clear"));
});

Deno.test("proof: recorded terminal units with unset TasksCurrent clear (live m09 recording)", () => {
  // Live recording 2026-09-06T02:03:00Z:
  // systemd-remount-fs.service ActiveState=active SubState=exited
  // RemainAfterExit=yes MainPID=0 ControlPID=0 ControlGroup empty
  // TasksCurrent=[not set]; the completed verify unit recorded the same
  // empty group with [not set] after its exited run.
  const fixture = generationFixture(31, WINDOW_START);
  const props = new Map<string, string>([
    ["LoadState", "loaded"],
    ["ActiveState", "active"],
    ["SubState", "exited"],
    ["Result", "success"],
    ["MainPID", "0"],
    ["ControlPID", "0"],
    ["ControlGroup", ""],
    ["TasksCurrent", "[not set]"],
    ["InvocationID", INVOCATION_A],
  ]);
  const checkedAtUtc = iso(WINDOW_START + 60_000);
  const timestamps = {
    updatedAtUtc: iso(WINDOW_START + 50_000),
    heartbeatAtUtc: iso(WINDOW_START + 49_000),
    finishedAtUtc: iso(WINDOW_START + 50_000),
  };
  for (
    const unitName of [
      workerUnitNameOf(fixture.generation),
      verifyUnitName(fixture.generation),
    ]
  ) {
    const gate = {
      ...deriveVerifierGate(fixture.request, fixture.requestSha256),
      unitName,
      unitInvocationId: INVOCATION_A,
    };
    const proof = buildClearProof(
      { props, lockFree: true, checkedAtUtc },
      gate,
      "PENDING_VERIFIER",
      timestamps,
    ) as { tasksCurrent: unknown; controlGroup: unknown };
    assert(proof.tasksCurrent === null, "[not set] maps to unset tasks");
    assert(proof.controlGroup === "", "the recorded empty group stays empty");
  }
});

Deno.test("proof: malformed task counts and nonempty groups stay rejected", () => {
  const fixture = generationFixture(32, WINDOW_START);
  const checkedAtUtc = iso(WINDOW_START + 60_000);
  const timestamps = {
    updatedAtUtc: iso(WINDOW_START + 50_000),
    heartbeatAtUtc: iso(WINDOW_START + 49_000),
    finishedAtUtc: iso(WINDOW_START + 50_000),
  };
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: verifyUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const base = new Map<string, string>([
    ["LoadState", "loaded"],
    ["ActiveState", "active"],
    ["SubState", "exited"],
    ["Result", "success"],
    ["MainPID", "0"],
    ["ControlPID", "0"],
    ["InvocationID", INVOCATION_A],
  ]);
  const cases: Map<string, string>[] = [
    new Map([...base, ["ControlGroup", ""], ["TasksCurrent", "not set"]]),
    new Map([...base, ["ControlGroup", ""], ["TasksCurrent", "3.14"]]),
    new Map([
      ...base,
      ["ControlGroup", `/system.slice/${verifyUnitName(fixture.generation)}`],
      ["TasksCurrent", "[not set]"],
    ]),
    new Map([...base, ["ControlGroup", ""], ["TasksCurrent", "-1"]]),
  ];
  for (const props of cases) {
    let threw = false;
    try {
      buildClearProof(
        { props, lockFree: true, checkedAtUtc },
        gate,
        "PENDING_VERIFIER",
        timestamps,
      );
    } catch {
      threw = true;
    }
    assert(
      threw,
      `only the exact [not set] marker may be unset: ${
        props.get("TasksCurrent")
      }`,
    );
  }
  // The canonical unit cgroup with zero tasks is the only nonempty-group
  // proof, and it must still clear.
  const zero = new Map([
    ...base,
    ["ControlGroup", `/system.slice/${verifyUnitName(fixture.generation)}`],
    ["TasksCurrent", "0"],
  ]);
  const proof = buildClearProof(
    { props: zero, lockFree: true, checkedAtUtc },
    gate,
    "PENDING_VERIFIER",
    timestamps,
  ) as { tasksCurrent: unknown };
  assert(proof.tasksCurrent === 0);
});

Deno.test("orchestration: worker PENDING_VERIFIER is never accepted", async () => {
  const fixture = generationFixture(11, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  const h = harness({ now: new Date(WINDOW_START + 60_000) });
  const next = await stepBackupController(state, h.deps, h.deps.now());
  assert(next.job!.phase === "VERIFIER_LAUNCHED");
  assert(h.tunnels.length === 1);
  const persisted = h.privateMap.get(CONTROLLER_STATE_PATH);
  const parsed = JSON.parse(
    persisted instanceof Uint8Array
      ? new TextDecoder().decode(persisted)
      : JSON.stringify(persisted),
  );
  assert(parsed.catalog.length === 0, "PENDING_VERIFIER is never accepted");
});

Deno.test("orchestration: corrupt verifier receipt is never accepted or pruned", async () => {
  const fixture = generationFixture(12, WINDOW_START);
  const corruptReceipt = JSON.stringify({
    ...fixture.receipt,
    generation: `generation-${uuidFor(99)}`,
  });
  const receiptSha256 = sha256HexSync(new TextEncoder().encode(corruptReceipt));
  const status = verifierAcceptedStatus(fixture, INVOCATION_B, receiptSha256);
  const state = stateWithJob(fixture, "VERIFIER_RUNNING", {
    verifierInvocationId: INVOCATION_B,
    verifierStatus: status,
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: verifyUnitName(fixture.generation),
    unitInvocationId: INVOCATION_B,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
    observed: () => terminalObserved(status),
    rootResponder: (script) =>
      script.includes("receipt.json")
        ? { code: 0, stdout: corruptReceipt, stderr: "" }
        : undefined,
    seedPrivate: (map) => {
      map.set(
        `${PIP_JOB_EVIDENCE_PATH}/${fixture.jobId}/result.json`,
        new TextEncoder().encode(JSON.stringify(fixture.workerResult)),
      );
    },
  });
  await h.deps.private.write(CONTROLLER_STATE_PATH, state);
  const report = await runBackblazeCycle(h.deps, 4);
  assert(report.status.startsWith("B2_BACKUP_FAILED"));
  assert(h.store.removed.length === 0, "No prune may run without acceptance");
  const persisted = h.privateMap.get(CONTROLLER_STATE_PATH);
  const after = JSON.parse(
    persisted instanceof Uint8Array
      ? new TextDecoder().decode(persisted)
      : JSON.stringify(persisted),
  );
  assert(after.catalog.length === 0);
  assert(after.job.phase === "FAILED");
});

Deno.test("orchestration: acceptance precedes deletion and prune is idempotent", async () => {
  const fixtures = [1, 2, 3, 4, 5].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const catalog = fixtures.map((fixture, i) =>
    catalogEntry(fixture, WINDOW_START + i * 1000)
  );
  const current = fixtures[4];
  const state = validateControllerState({
    schemaVersion: 1,
    catalog,
    job: {
      ...stateWithJob(current, "ACCEPTED").job!,
      workerStatus: workerPendingStatus(current, INVOCATION_A),
      resultSha256: "77".repeat(32),
    },
  });
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    versions: inventoryFor(fixtures),
  });
  let final = state;
  for (let step = 0; step < 6; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    if (final.job!.phase === "COMPLETE" || final.job!.phase === "FAILED") break;
  }
  assert(
    final.job!.phase === "COMPLETE",
    `phase=${final.job!.phase} events=${h.events.join("|")}`,
  );
  const planIndex = h.events.findIndex((entry) => entry.endsWith(":plan"));
  const firstRemove = h.events.findIndex((entry) =>
    entry.startsWith("remove:")
  );
  assert(planIndex !== -1, "The deletion plan must be persisted");
  assert(planIndex < firstRemove, "The plan is written before any removal");
  const oldestIds2 = new Set(
    fixtures[0].upload.archives.flatMap((archive) =>
      archive.chunks.map((chunk) => chunk.fileId)
    ).concat([fixtures[0].publishedIndex.object.fileId]),
  );
  assert(
    h.events.filter((entry) => entry.startsWith("remove:")).every((entry) =>
      oldestIds2.has(entry.slice("remove:".length))
    ),
    "Only the oldest generation may be deleted",
  );
  const persisted = h.privateMap.get(CONTROLLER_STATE_PATH);
  const after = JSON.parse(
    persisted instanceof Uint8Array
      ? new TextDecoder().decode(persisted)
      : JSON.stringify(persisted),
  );
  assert(
    after.catalog.length === 4,
    "Catalog membership shrinks only after the prune is proved",
  );
  assert(
    after.catalog.every((entry: { index: { generation: string } }) =>
      entry.index.generation !== fixtures[0].generation
    ),
  );
  assert(h.store.removed.length > 0);
  assert(
    h.store.versionsList.every((object) => !oldestIds2.has(object.fileId)),
    "Pruned IDs must be absent from the fresh inventory",
  );
});

Deno.test("orchestration: prune removal failure persists resumable PRUNING and resumes to completion", async () => {
  const fixtures = [1, 2, 3, 4, 5, 6].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const catalog = fixtures.map((fixture, i) =>
    catalogEntry(fixture, WINDOW_START + i * 1000)
  );
  const current = fixtures[5];
  const state = validateControllerState({
    schemaVersion: 1,
    catalog,
    job: {
      ...stateWithJob(current, "ACCEPTED").job!,
      workerStatus: workerPendingStatus(current, INVOCATION_A),
      resultSha256: "77".repeat(32),
    },
  });
  const inventory = inventoryFor(fixtures);
  const pending = generationFixture(7, WINDOW_START + 7 * 3_600_000);
  inventory.push(...inventoryFor([pending]));
  inventory.push({
    fileId: "foreign000000000000",
    fileName: "restic/direct-v1/other/generation-11111/role/00000000",
    contentLength: 10,
    contentSha1: "11".repeat(20),
    action: "upload",
    uploadTimestamp: 1,
  });
  inventory.push({
    fileId: "start0000000000000",
    fileName: `${generationPrefixes(fixtures[1].generation)[0]}root/00000000`,
    contentLength: 1,
    contentSha1: "11".repeat(20),
    action: "start",
    uploadTimestamp: 1,
  });
  inventory.push({
    fileId: "hide00000000000000",
    fileName: `${generationPrefixes(fixtures[0].generation)[0]}root/00000000`,
    contentLength: 0,
    contentSha1: "11".repeat(20),
    action: "hide",
    uploadTimestamp: 1,
  });
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    versions: inventory,
  });
  // The first removal throws (transient or an ambiguous already-removed
  // answer); every later removal succeeds.
  const originalRemove = h.store.remove.bind(
    h.store,
  ) as MetadataStore["remove"];
  let failOnce = true;
  h.store.remove = async (object) => {
    if (failOnce) {
      failOnce = false;
      throw new Error("remove failed: 500 transient");
    }
    return await originalRemove(object);
  };
  const expectedIds = new Set(
    inventoryFor([fixtures[0], fixtures[1]]).map((object) => object.fileId),
  );
  expectedIds.add("hide00000000000000");
  let final = state;
  for (let step = 0; step < 4; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    if (final.job!.prune?.failedAtUtc !== undefined) break;
    if (final.job!.phase === "COMPLETE" || final.job!.phase === "FAILED") break;
  }
  const failedPhase: ControllerPhase = final.job!.phase;
  assert(
    failedPhase === "PRUNING",
    `the removal failure must stay resumable, phase=${failedPhase}`,
  );
  assert(final.job!.prune!.failedAtUtc !== undefined);
  assert(
    final.catalog.length === 6,
    "the catalog is never discarded by a removal failure",
  );
  assert(
    JSON.stringify(final.job!.prune!.plan.map((entry) => entry.generation)) ===
      JSON.stringify([fixtures[0].generation, fixtures[1].generation]),
    "the existing plan is preserved",
  );
  const planIds = final.job!.prune!.plan.flatMap((entry) => entry.fileIds);
  assert(planIds.length === expectedIds.size);
  assert(
    planIds.every((id) => expectedIds.has(id)),
    "no planned id is dropped or replaced",
  );
  assert(
    (final.job!.prune!.evidence ?? "").length <= 300,
    "failure evidence is bounded",
  );
  assert(h.store.removed.length === 0, "the throwing removal deleted nothing");
  // A concurrent actor already removed one planned ID before the resume
  // inventory: it must be skipped, and the remaining IDs retried.
  const firstPlanned = planIds[0];
  h.store.versionsList = h.store.versionsList.filter(
    (object) => object.fileId !== firstPlanned,
  );
  for (let step = 0; step < 14; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    if (final.job!.phase === "COMPLETE" || final.job!.phase === "FAILED") break;
  }
  assert(
    final.job!.phase === "COMPLETE",
    `resume must complete, phase=${final.job!.phase}`,
  );
  assert(final.catalog.length === 4, "catalog shrinks to the newest four");
  for (const entry of final.catalog) {
    assert(
      entry.index.generation !== fixtures[0].generation &&
        entry.index.generation !== fixtures[1].generation,
    );
  }
  const removedIds = new Set(h.store.removed.map((object) => object.fileId));
  assert(
    removedIds.size === expectedIds.size - 1,
    "every still-present planned id was removed once",
  );
  assert(
    !removedIds.has(firstPlanned),
    "the already-absent id is not re-removed",
  );
  for (const id of expectedIds) {
    if (id !== firstPlanned) {
      assert(removedIds.has(id), `planned id ${id} must be removed`);
    }
  }
  const surviving = new Set(
    h.store.versionsList.map((object) => object.fileId),
  );
  const newestIds = new Set(
    fixtures.slice(2).flatMap((fixture) =>
      inventoryFor([fixture]).map((object) => object.fileId)
    ),
  );
  for (const id of newestIds) {
    assert(surviving.has(id), `newest id ${id} must survive`);
  }
  for (const fixture of [pending]) {
    for (const object of inventoryFor([fixture])) {
      assert(surviving.has(object.fileId), "pending data must survive");
    }
  }
  assert(surviving.has("foreign000000000000"), "foreign data must survive");
  assert(surviving.has("start0000000000000"), "start markers must survive");
});

Deno.test("orchestration: completed or failed period never creates a replacement", async () => {
  const fixture = generationFixture(13, WINDOW_START);
  for (const phase of ["COMPLETE", "FAILED"] as const) {
    const state = stateWithJob(fixture, phase);
    const h = harness({ now: new Date(WINDOW_START + 60_000) });
    const next = await stepBackupController(state, h.deps, h.deps.now());
    assert(next.job!.envelope.request.jobId === fixture.jobId);
    assert(next.job!.phase === phase);
    assert(h.launches.length === 0);
  }
});

// ---------------------------------------------------------------------------
// Production wiring
// ---------------------------------------------------------------------------

Deno.test("wiring: fixed launch unit properties and transport installer", async () => {
  const fixture = generationFixture(14, WINDOW_START);
  const calls: { command: string; args: string[]; input?: Uint8Array }[] = [];
  const runner: RemoteRunner = (command, args, input) => {
    calls.push({ command, args, input });
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const seam = realRemoteSeam(runner);
  await seam.root("true");
  const rootCall = calls.at(-1)!;
  assert(rootCall.command === "ssh");
  assert(rootCall.args.includes(SOURCE_HOST));
  assert(rootCall.args.includes("sudo"));
  await seam.launchUnit({
    unitName: workerUnitNameOf(fixture.generation),
    runtimeDir: `${JOBS_RUNTIME_ROOT}/${fixture.jobId}`,
    remainingSec: 12345,
    args: [
      "/usr/local/bin/deno",
      "run",
      "--allow-read",
      "--allow-write",
      "--allow-run",
      "--allow-env",
      "--allow-net",
      "entry-worker.ts",
    ],
  });
  const script = calls.at(-1)!.args.join(" ");
  assert(script.includes("systemd-run"));
  assert(
    script.includes(`arch-vps-b2-worker-${uuidFor(14)}.service`),
    script,
  );
  assert(script.includes("Type=exec"));
  assert(script.includes("RemainAfterExit=yes"));
  assert(script.includes("RuntimeMaxSec=12345"), script);
  assert(script.includes("MemoryMax=1G"));
  assert(script.includes("CPUQuota=100%"));
  assert(
    script.includes("WorkingDirectory=") &&
      script.includes(`${JOBS_RUNTIME_ROOT}/${fixture.jobId}`),
  );
  assert(script.includes("entry-worker.ts"));
  await seam.installer({
    jobId: fixture.jobId,
    sourceRevision: REVISION,
    files: [],
  });
  const installCall = calls.at(-1)!;
  assert(installCall.input !== undefined);
  const payload = JSON.parse(new TextDecoder().decode(installCall.input));
  assert(payload.jobId === fixture.jobId);
  assert(installCall.args.join(" ").includes("deno eval"));
});

Deno.test("wiring: installer source is quoted so the real ssh command survives remote-shell parsing", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("installer quoting: skipped without write/run permissions");
    return;
  }
  const fixture = generationFixture(29, WINDOW_START);
  const calls: { command: string; args: string[] }[] = [];
  const seam = realRemoteSeam((command, args) => {
    calls.push({ command, args });
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  });
  await seam.installer({
    jobId: fixture.jobId,
    sourceRevision: REVISION,
    files: [],
  });
  const installCall = calls.at(-1)!;
  assert(installCall.command === "ssh");
  assert(
    installCall.args.at(-1)!.startsWith("'"),
    "the installer source must be a single-quoted remote-shell argument",
  );
  // ssh joins its argv with spaces and the remote login shell parses the
  // result: prove that exact command line is valid shell syntax and that
  // the eval argument survives as one exact argv element.
  const remoteLine = installCall.args
    .slice(installCall.args.indexOf(SOURCE_HOST) + 1)
    .join(" ");
  const syntax = await new Deno.Command("/bin/bash", {
    args: ["-n", "-c", remoteLine],
  }).output();
  assert(syntax.success, new TextDecoder().decode(syntax.stderr));
  const dir = await Deno.makeTempDir({ prefix: "m09-ssh-argv-" });
  try {
    await Deno.writeTextFile(
      `${dir}/sudo`,
      '#!/bin/bash\nprintf "%s\\000" "$@" > "$RECORD"\n',
    );
    await Deno.chmod(`${dir}/sudo`, 0o755);
    const record = `${dir}/argv.bin`;
    const exec = await new Deno.Command("/bin/bash", {
      args: ["-c", remoteLine],
      env: { ...Deno.env.toObject(), PATH: dir, RECORD: record },
      stdout: "null",
      stderr: "piped",
    }).output();
    assert(exec.success, new TextDecoder().decode(exec.stderr));
    const parts = new TextDecoder().decode(await Deno.readFile(record))
      .split("\0");
    const argv = parts.at(-1) === "" ? parts.slice(0, -1) : parts;
    assert(
      argv.length === 4,
      `the remote shell must produce the sudo argv, got ${
        JSON.stringify(argv)
      }`,
    );
    assert(argv[0] === "-n");
    assert(argv[1] === "/usr/local/bin/deno");
    assert(argv[2] === "eval");
    assert(
      argv[3].startsWith("const payload") && argv[3].includes("\n") &&
        argv[3].includes("installed: true") && argv[3].endsWith("}));"),
      "the installer source must survive as one exact eval argument",
    );
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("wiring: agent socket setup prepares only the exact codex home before gpgconf", async () => {
  const fixture = generationFixture(30, WINDOW_START);
  const publicHome = `${PUBLIC_HOME_BASE}/${fixture.generation}`;
  const customSocket = "/run/user/1002/gnupg/verifier/S.gpg-agent";
  const defaultSocket = "/run/user/1002/gnupg/S.gpg-agent";
  const calls: { args: string[] }[] = [];
  const seam = realRemoteSeam((command, args) => {
    if (command !== "ssh") throw new Error("unexpected command");
    calls.push({ args });
    return Promise.resolve({
      code: 0,
      stdout: `socket=${customSocket}\ndefault=${defaultSocket}\n`,
      stderr: "",
    });
  });
  const resolved = await seam.resolveAgentSocket(publicHome);
  assert(resolved.socket === customSocket);
  assert(resolved.defaultSocket === defaultSocket);
  const rootCall = calls.at(-1)!;
  const script = rootCall.args.join(" ");
  const mkdirAt = script.indexOf("mkdir -p");
  const createAt = script.indexOf("--create-socketdir");
  const listAt = script.indexOf("--list-dirs");
  assert(mkdirAt !== -1 && createAt !== -1 && listAt !== -1, script);
  assert(
    mkdirAt < createAt && createAt < listAt,
    `prepare, validate and create-socketdir must precede resolution: ${script}`,
  );
  assert(
    script.includes("home=") && script.includes(PUBLIC_HOME_BASE),
    `only the exact validated home is prepared: ${script}`,
  );
  assert(
    script.includes(
      'sudo -n -u codex gpgconf --homedir "$home" --create-socketdir',
    ),
    "the socket directory is created as codex for the exact home",
  );
  assert(script.includes("AGENT_HOME_SYMLINK"), script);
  assert(script.includes("AGENT_HOME_NOT_CANONICAL"), script);
  assert(script.includes("AGENT_HOME_NOT_CODEX"), script);
  assert(script.includes("AGENT_HOME_MODE"), script);
  assert(
    script.includes("private-keys-v1.d") && script.includes("secring.gpg"),
    "private key entries must be rejected",
  );
  for (
    const bad of [
      "/home/evil",
      `${PUBLIC_HOME_BASE}/..`,
      `${PUBLIC_HOME_BASE}/generation-zz`,
      `${PUBLIC_HOME_BASE}/${fixture.generation}/nested`,
    ]
  ) {
    let threw = false;
    try {
      await seam.resolveAgentSocket(bad);
    } catch {
      threw = true;
    }
    assert(threw, `strict path rejection must refuse: ${bad}`);
  }
});

Deno.test("wiring: gate and catalog validation reject identity drift", () => {
  const fixture = generationFixture(16, WINDOW_START);
  const gate = deriveVerifierGate(fixture.request, fixture.requestSha256);
  assert(gate.unitName.startsWith("arch-vps-b2-verify-"));
  const entry = catalogEntry(fixture, WINDOW_START + 1000);
  validateControllerState({ schemaVersion: 1, catalog: [entry] });
  let threw = false;
  try {
    validateControllerState({
      schemaVersion: 1,
      catalog: [{
        ...entry,
        receipt: { ...entry.receipt, recipientSha256: "99".repeat(32) },
      }],
    });
  } catch {
    threw = true;
  }
  assert(threw, "A catalog entry with a different recipient must be rejected");
});

Deno.test("orchestration: end-to-end weekly generation is accepted then pruned", async () => {
  const oracleState = {
    policy: {
      source: {
        instanceId: "11111111-1111-1111-1111-111111111111",
        bootVolumeId: "22222222-2222-2222-2222-222222222222",
        rootVolumeId: "33333333-3333-3333-3333-333333333333",
        compartmentId: "44444444-4444-4444-4444-444444444444",
        region: "us-ashburn-1",
      },
      standingApproval: {
        approvedAtUtc: "2026-09-05T00:00:00.000Z",
        exactOperation: "weekly paired backup rotation",
        source: {
          instanceId: "11111111-1111-1111-1111-111111111111",
          bootVolumeId: "22222222-2222-2222-2222-222222222222",
          rootVolumeId: "33333333-3333-3333-3333-333333333333",
          compartmentId: "44444444-4444-4444-4444-444444444444",
          region: "us-ashburn-1",
        },
      },
      acceptedPair: {
        suffix: "20260830T000000Z",
        bootId: "55555555-5555-5555-5555-555555555555",
        rootId: "66666666-6666-6666-6666-666666666666",
      },
      retainPreviousPair: true,
      allowFifthSlot: false,
    },
    cycle: {
      source: {
        instanceId: "11111111-1111-1111-1111-111111111111",
        bootVolumeId: "22222222-2222-2222-2222-222222222222",
        rootVolumeId: "33333333-3333-3333-3333-333333333333",
        compartmentId: "44444444-4444-4444-4444-444444444444",
        region: "us-ashburn-1",
      },
      previousPair: {
        suffix: "20260830T000000Z",
        bootId: "55555555-5555-5555-5555-555555555555",
        rootId: "66666666-6666-6666-6666-666666666666",
      },
      suffix: "20260906T000000Z",
      phase: "complete",
      createdAtUtc: "2026-09-05T00:00:00.000Z",
      updatedAtUtc: "2026-09-05T03:00:00.000Z",
      sourceAcceptedAtUtc: "2026-09-05T03:00:00.000Z",
    },
  };
  const scheduledClaim = {
    windowId: "2026-09-06@America/New_York",
    status: "complete",
    updatedAtUtc: "2026-09-05T03:00:00.000Z",
  };
  const options: HarnessOptions = {
    now: new Date(WINDOW_START + 1000),
    seedPrivate: (map) => {
      map.set(".private/backup-runtime.json", oracleState);
      map.set(".private/backup-scheduled-window.json", scheduledClaim);
    },
  };
  const h = harness(options);
  const script = {
    fixture: undefined as GenerationFixture | undefined,
    workerStatus: undefined as Record<string, unknown> | undefined,
    verifierStatus: undefined as Record<string, unknown> | undefined,
    resultText: undefined as string | undefined,
    receiptText: undefined as string | undefined,
  };
  options.observed = (unitName) =>
    unitName.startsWith("arch-vps-b2-worker-")
      ? terminalObserved(script.workerStatus!)
      : terminalObserved(script.verifierStatus!);
  options.rootResponder = (remoteScript) => {
    if (remoteScript.includes("result.json")) {
      return { code: 0, stdout: script.resultText!, stderr: "" };
    }
    if (remoteScript.includes("receipt.json")) {
      return { code: 0, stdout: script.receiptText!, stderr: "" };
    }
    return undefined;
  };
  const created = await stepBackupController(undefined, h.deps, h.deps.now());
  const envelope = created.job!.envelope;
  script.fixture = generationFixtureFor(
    envelope.request.jobId.slice("job-".length),
    Date.parse(envelope.request.requestedAtUtc),
  );
  script.resultText = JSON.stringify(script.fixture.workerResult);
  script.receiptText = JSON.stringify(script.fixture.receipt);
  h.store.versionsList.push(...inventoryFor([script.fixture]));
  script.workerStatus = workerPendingStatus(script.fixture, "3".repeat(32));
  script.workerStatus.resultSha256 = sha256HexSync(
    new TextEncoder().encode(script.resultText),
  );
  const receiptSha256 = sha256HexSync(
    new TextEncoder().encode(script.receiptText),
  );
  script.verifierStatus = verifierAcceptedStatus(
    script.fixture,
    "4".repeat(32),
    receiptSha256,
  );
  h.clock.current = new Date(WINDOW_START + 60_000);
  let final = created;
  for (let step = 0; step < 40; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    if (["COMPLETE", "FAILED"].includes(final.job!.phase)) break;
  }
  assert(final.job!.phase === "COMPLETE", `phase=${final.job!.phase}`);
  const persisted = h.privateMap.get(CONTROLLER_STATE_PATH);
  const parsed = JSON.parse(
    persisted instanceof Uint8Array
      ? new TextDecoder().decode(persisted)
      : JSON.stringify(persisted),
  );
  assert(parsed.catalog.length === 1);
  assert(parsed.catalog[0].receipt.machineBootRestoreProved === false);
  assert(parsed.catalog[0].index.generation === script.fixture!.generation);
  assert(h.launches.length === 2, "One worker and one verifier unit launch");
  assert(h.gate.value === null, "Gates must be cleared after terminal proof");
  assert(h.tunnels.length === 1);
  assert(
    h.store.removed.length === 0,
    "A single generation has nothing to prune",
  );
});

// ---------------------------------------------------------------------------
// Review regressions: GPG pumping, tunnel lifetime, recurrence, retention
// revalidation, cleanup scope and service permission flags
// ---------------------------------------------------------------------------

const ORACLE_STATE_FIXTURE = {
  policy: {
    source: {
      instanceId: "11111111-1111-1111-1111-111111111111",
      bootVolumeId: "22222222-2222-2222-2222-222222222222",
      rootVolumeId: "33333333-3333-3333-3333-333333333333",
      compartmentId: "44444444-4444-4444-4444-444444444444",
      region: "us-ashburn-1",
    },
    standingApproval: {
      approvedAtUtc: "2026-09-05T00:00:00.000Z",
      exactOperation: "weekly paired backup rotation",
      source: {
        instanceId: "11111111-1111-1111-1111-111111111111",
        bootVolumeId: "22222222-2222-2222-2222-222222222222",
        rootVolumeId: "33333333-3333-3333-3333-333333333333",
        compartmentId: "44444444-4444-4444-4444-444444444444",
        region: "us-ashburn-1",
      },
    },
    acceptedPair: {
      suffix: "20260830T000000Z",
      bootId: "55555555-5555-5555-5555-555555555555",
      rootId: "66666666-6666-6666-6666-666666666666",
    },
    retainPreviousPair: true,
    allowFifthSlot: false,
  },
  cycle: {
    source: {
      instanceId: "11111111-1111-1111-1111-111111111111",
      bootVolumeId: "22222222-2222-2222-2222-222222222222",
      rootVolumeId: "33333333-3333-3333-3333-333333333333",
      compartmentId: "44444444-4444-4444-4444-444444444444",
      region: "us-ashburn-1",
    },
    previousPair: {
      suffix: "20260830T000000Z",
      bootId: "55555555-5555-5555-5555-555555555555",
      rootId: "66666666-6666-6666-6666-666666666666",
    },
    suffix: "20260906T000000Z",
    phase: "complete",
    createdAtUtc: "2026-09-05T00:00:00.000Z",
    updatedAtUtc: "2026-09-05T03:00:00.000Z",
    sourceAcceptedAtUtc: "2026-09-05T03:00:00.000Z",
  },
};

const SCHEDULED_CLAIM_FIXTURE = {
  windowId: "2026-09-06@America/New_York",
  status: "complete",
  updatedAtUtc: "2026-09-05T03:00:00.000Z",
};

async function fsPermissionsGranted(): Promise<boolean> {
  const [write, run] = await Promise.all([
    Deno.permissions.query({ name: "write" }),
    Deno.permissions.query({ name: "run" }),
  ]);
  return write.state === "granted" && run.state === "granted";
}

Deno.test("gpg: stdout pump writes real FsFile bytes across the stream boundary", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("gpg pump: skipped without write/run permissions");
    return;
  }
  const dir = await Deno.makeTempDir({ prefix: "m09-gpg-pump-" });
  let file: Deno.FsFile | null = null;
  try {
    const path = `${dir}/plain.zst`;
    file = await Deno.open(path, {
      createNew: true,
      write: true,
      mode: 0o600,
    });
    const payload = new TextEncoder().encode(
      "plaintext-chunk-".repeat(2048),
    );
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(payload.subarray(0, 137));
        controller.enqueue(payload.subarray(137, 4096));
        controller.enqueue(payload.subarray(4096));
        controller.close();
      },
    });
    const total = await pumpGpgStdout(stream, file);
    await file.sync();
    const info = await file.stat();
    assert(total === payload.byteLength, "pumped byte count must match");
    assert(
      info.size === payload.byteLength,
      "the file must not stay zero bytes after sync/stat",
    );
    file.close();
    file = null;
    const onDisk = await Deno.readFile(path);
    assert(onDisk.byteLength === payload.byteLength);
    for (let i = 0; i < payload.byteLength; i += 1) {
      if (onDisk[i] !== payload[i]) throw new Error("bytes differ on disk");
    }
  } finally {
    if (file !== null) {
      try {
        file.close();
      } catch {
        // Already closed by the pump path.
      }
    }
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("tunnel: forward argv drops -N and awaits the remote readiness acknowledgement", async () => {
  const remoteSocket = "/run/user/1002/gnupg/custom/S.gpg-agent";
  const localSocket =
    "/home/pi/ops/weekly-backup-controller/.private/file-backup/gnupg/S.gpg-agent.extra";
  const args = tunnelForwardArgs(remoteSocket, localSocket);
  assert(args.includes("ExitOnForwardFailure=yes"), args.join(" "));
  assert(
    !args.includes("-N"),
    "no -N: stdin-held lifetime and natural EOF close",
  );
  const rIndex = args.indexOf("-R");
  assert(
    rIndex !== -1 && args[rIndex + 1] === `${remoteSocket}:${localSocket}`,
  );
  assert(args.includes(SOURCE_HOST));
  const remoteCommand = args.at(-1)!;
  assert(remoteCommand.includes("TUNNEL_READY"), remoteCommand);
  assert(remoteCommand.includes("cat"), remoteCommand);
  assert(
    remoteCommand.includes(
      `trap ${shellQuote(`rm -f -- ${shellQuote(remoteSocket)}`)} EXIT`,
    ),
    `the EXIT trap must remove exactly the custom source socket: ${remoteCommand}`,
  );
  if (await fsPermissionsGranted()) {
    // The trap body + path must survive remote-shell parsing even with
    // punctuation in the socket path.
    const quoted = tunnelForwardArgs(
      `/run/user/1002/gnupg/ve'rif/ier/S.gpg-agent`,
      localSocket,
    ).at(-1)!;
    const syntax = await new Deno.Command("/bin/bash", {
      args: ["-n", "-c", quoted],
    }).output();
    assert(syntax.success, new TextDecoder().decode(syntax.stderr));
  }
  let threw = false;
  try {
    tunnelForwardArgs("", localSocket);
  } catch {
    threw = true;
  }
  assert(threw, "an empty remote socket must be rejected");
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** A small synthetic ssh child: the readiness acknowledgement (or silence),
 * a stderr line, and a status that settles only when stdin is closed, like
 * the real remote `cat` exiting on EOF. `streamError` makes the readiness
 * stream reject instead of delivering the acknowledgement. `manualExit`
 * leaves the status settlement to the caller (`settleStatus`) so a test can
 * reproduce a natural child exit after readiness. */
function syntheticTunnelChild(opts: {
  ack: boolean;
  statusError?: Error;
  streamError?: Error;
  manualExit?: boolean;
}): {
  factory: TunnelChildFactory;
  argv: string[];
  stdinClosed: Promise<void>;
  status: Promise<Deno.CommandStatus>;
  statusSettled: () => boolean;
  settleStatus: (code: number) => void;
} {
  const stdinClosed = deferred<void>();
  const argv: string[] = [];
  let settled = false;
  let settle: ((code: number) => void) | undefined;
  const status = new Promise<Deno.CommandStatus>((resolve, reject) => {
    settle = (code) => {
      settled = true;
      if (opts.statusError !== undefined) {
        reject(opts.statusError);
      } else {
        resolve({
          success: code === 0,
          code,
          signal: null,
        } as Deno.CommandStatus);
      }
    };
  });
  if (!opts.manualExit) {
    void stdinClosed.promise.then(() => settle?.(0));
  }
  const factory: TunnelChildFactory = (args) => {
    argv.push(...args);
    const stdin = new WritableStream<Uint8Array>({
      write() {},
      close() {
        stdinClosed.resolve();
      },
      abort() {
        stdinClosed.resolve();
      },
    });
    const stdout = new ReadableStream<Uint8Array>({
      start(controller) {
        if (opts.streamError !== undefined) {
          controller.error(opts.streamError);
        } else if (opts.ack) {
          controller.enqueue(new TextEncoder().encode("TUNNEL_READY\n"));
        }
      },
    });
    const stderr = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("warning: synthetic\n"));
        controller.close();
      },
    });
    return { stdin, stdout, stderr, status };
  };
  return {
    factory,
    argv,
    stdinClosed: stdinClosed.promise,
    status,
    statusSettled: () => settled,
    settleStatus: (code) => settle!(code),
  };
}

Deno.test("tunnel: close proves the natural exit and the EXIT trap owns the exact socket cleanup", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("tunnel close: skipped without write/run permissions");
    return;
  }
  const remoteSocket = "/run/user/1002/gnupg/verifier/S.gpg-agent";
  const runner: RemoteRunner = (command, args) => {
    if (command !== "gpgconf") throw new Error("unexpected command");
    const text = args.join(" ");
    if (text.includes("--launch")) {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (text.includes("agent-extra-socket")) {
      return Promise.resolve({
        code: 0,
        stdout: "/home/pi/keyring/S.gpg-agent.extra\n",
        stderr: "",
      });
    }
    return Promise.resolve({
      code: 0,
      stdout: "/home/pi/keyring/S.gpg-agent\n",
      stderr: "",
    });
  };
  const childFixture = syntheticTunnelChild({ ack: true });
  const dir = await Deno.makeTempDir({ prefix: "m09-tunnel-" });
  try {
    const seam = realTunnelSeam(
      runner,
      `${dir}/keyring`,
      childFixture.factory,
    );
    const started = Date.now();
    const handle = await seam.open(remoteSocket);
    assert(
      Date.now() - started < 5_000,
      "the acknowledgement must clear the readiness timer",
    );
    if (seam.current() !== handle) {
      throw new Error("the acknowledged handle must be the active one");
    }
    const remoteCommand = childFixture.argv.at(-1)!;
    assert(
      remoteCommand.includes(
        `trap ${shellQuote(`rm -f -- ${shellQuote(remoteSocket)}`)} EXIT`,
      ),
      remoteCommand,
    );
    assert(!remoteCommand.includes("sudo"), remoteCommand);
    assert(remoteCommand.includes("TUNNEL_READY"));
    assert(remoteCommand.includes("cat"));
    await seam.close();
    assert(
      childFixture.statusSettled(),
      "close must await the natural ssh exit, not a timer race",
    );
    if (seam.current() !== null) {
      throw new Error("one final close leaves no active handle");
    }
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("tunnel: a close failure propagates instead of silently claiming cleanup", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("tunnel close failure: skipped without write/run permissions");
    return;
  }
  const remoteSocket = "/run/user/1002/gnupg/verifier/S.gpg-agent";
  const runner: RemoteRunner = (command, args) => {
    if (command !== "gpgconf") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    const text = args.join(" ");
    return Promise.resolve({
      code: 0,
      stdout: text.includes("agent-extra-socket")
        ? "/home/pi/keyring/S.gpg-agent.extra\n"
        : "/home/pi/keyring/S.gpg-agent\n",
      stderr: "",
    });
  };
  const childFixture = syntheticTunnelChild({
    ack: true,
    statusError: new Error("ssh hung on exit"),
  });
  const dir = await Deno.makeTempDir({ prefix: "m09-tunnel-fail-" });
  try {
    const seam = realTunnelSeam(
      runner,
      `${dir}/keyring`,
      childFixture.factory,
    );
    const handle = await seam.open(remoteSocket);
    assert(seam.current() === handle);
    let threw = false;
    try {
      await seam.close();
    } catch {
      threw = true;
    }
    assert(threw, "a failed tunnel exit must never be swallowed");
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("tunnel: a natural child exit after readiness invalidates only its own handle and the next open creates a new tunnel", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("tunnel natural exit: skipped without write/run permissions");
    return;
  }
  const remoteSocket = "/run/user/1002/gnupg/verifier/S.gpg-agent";
  const runner: RemoteRunner = (command, args) => {
    if (command !== "gpgconf") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    const text = args.join(" ");
    return Promise.resolve({
      code: 0,
      stdout: text.includes("agent-extra-socket")
        ? "/home/pi/keyring/S.gpg-agent.extra\n"
        : "/home/pi/keyring/S.gpg-agent\n",
      stderr: "",
    });
  };
  const dead = syntheticTunnelChild({ ack: true, manualExit: true });
  const replacement = syntheticTunnelChild({ ack: true });
  const dir = await Deno.makeTempDir({ prefix: "m09-tunnel-exit-" });
  try {
    let spawned = 0;
    const seam = realTunnelSeam(runner, `${dir}/keyring`, (args) => {
      spawned += 1;
      return (spawned === 1 ? dead : replacement).factory(args);
    });
    const handle = await seam.open(remoteSocket);
    assert(seam.current() === handle, "the acknowledged handle is active");
    // The owned SSH transport dies after readiness (a disconnected SSH
    // exits 255 without any stdin close or signal).
    dead.settleStatus(255);
    const deadline = Date.now() + 5_000;
    while (seam.current() !== null && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert(
      seam.current() === null,
      "a terminal child exit must invalidate the dead active handle",
    );
    const reopened = await seam.open(remoteSocket);
    assert(
      spawned === 2,
      "a later open must create a second child after the terminal exit",
    );
    assert(
      replacement.statusSettled() === false,
      "the replacement is still connected before the explicit close",
    );
    assert(seam.current() === reopened, "the replacement handle is active");
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert(
      seam.current() === reopened,
      "a live tunnel stays open until an explicit close",
    );
    await seam.close();
    assert(seam.current() === null);
    assert(
      replacement.statusSettled(),
      "the explicit close proves the replacement natural exit",
    );
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("tunnel: readiness rejection closes stdin, awaits the natural exit and leaves no active handle", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log(
      "tunnel readiness rejection: skipped without write/run permissions",
    );
    return;
  }
  const remoteSocket = "/run/user/1002/gnupg/verifier/S.gpg-agent";
  const runner: RemoteRunner = (command, args) => {
    if (command !== "gpgconf") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    const text = args.join(" ");
    return Promise.resolve({
      code: 0,
      stdout: text.includes("agent-extra-socket")
        ? "/home/pi/keyring/S.gpg-agent.extra\n"
        : "/home/pi/keyring/S.gpg-agent\n",
      stderr: "",
    });
  };
  const streamError = new Error("ssh closed the readiness stream");
  const childFixture = syntheticTunnelChild({
    ack: false,
    streamError,
  });
  const dir = await Deno.makeTempDir({ prefix: "m09-tunnel-reject-" });
  try {
    const seam = realTunnelSeam(
      runner,
      `${dir}/keyring`,
      childFixture.factory,
    );
    let threw: unknown = null;
    try {
      await seam.open(remoteSocket);
    } catch (error) {
      threw = error;
    }
    assert(
      threw instanceof Error && threw.message.includes("readiness stream"),
      `the original readiness stream error must propagate: ${String(threw)}`,
    );
    await childFixture.stdinClosed;
    await Promise.race([
      childFixture.status,
      new Promise((_resolve) => setTimeout(() => {}, 10_000)),
    ]).catch(() => {});
    assert(
      childFixture.statusSettled(),
      "the owned child must be closed (stdin EOF) and awaited before the throw",
    );
    if (seam.current() !== null) {
      throw new Error("a rejected open leaves no active handle");
    }
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("tunnel: readiness precedes launch and the handle survives poll steps", async () => {
  const fixture = generationFixture(17, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  const h = harness({ now: new Date(WINDOW_START + 60_000) });
  const next = await stepBackupController(state, h.deps, h.deps.now());
  assert(next.job!.phase === "VERIFIER_LAUNCHED");
  const openAt = h.events.findIndex((entry) =>
    entry.startsWith("tunnel:open:")
  );
  const launchAt = h.events.findIndex((entry) => entry.startsWith("launch:"));
  assert(openAt !== -1 && launchAt !== -1 && openAt < launchAt);
  assert(h.tunnelOpen(), "the tunnel must stay open after a detached launch");
  assert(
    h.tunnelCloses() === 0,
    "no immediate close after the verifier launch",
  );
  const running = await stepBackupController(next, h.deps, h.deps.now());
  assert(running.job!.phase === "VERIFIER_RUNNING");
  assert(h.tunnelOpen());
  assert(h.tunnelCloses() === 0);
  assert(h.tunnels.length === 1, "one tunnel for the same verifier invocation");
});

Deno.test("tunnel: controller exit closes the handle in the outer finally", async () => {
  const fixture = generationFixture(18, WINDOW_START);
  const state = stateWithJob(fixture, "FAILED", {
    failure: { code: "X", atUtc: iso(WINDOW_START + 1000) },
  });
  const h = harness({ now: new Date(WINDOW_START + 60_000) });
  await h.deps.private.write(CONTROLLER_STATE_PATH, state);
  await h.deps.tunnel.open("/run/user/1002/gnupg/custom/S.gpg-agent");
  assert(h.tunnelOpen());
  const report = await runBackblazeCycle(h.deps, 3);
  assert(report.status.startsWith("B2_BACKUP_FAILED"));
  assert(h.tunnelCloses() === 1, "exactly one final close");
  assert(!h.tunnelOpen());
});

Deno.test("cycle: a step error after a durable bind resumes instead of failing", async () => {
  const fixture = generationFixture(22, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_LAUNCHED");
  const observed = (): ObservedUnit => ({
    props: new Map<string, string>([
      ["LoadState", "loaded"],
      ["ActiveState", "active"],
      ["SubState", "running"],
      ["Result", "success"],
      ["MainPID", "123"],
      ["ControlPID", "0"],
      ["InvocationID", INVOCATION_A],
    ]),
    status: null,
    lockFree: false,
    reachable: true,
  });
  const runningStatus = {
    ...workerPendingStatus(fixture, INVOCATION_A),
    state: "CAPTURING",
    finishedAtUtc: null,
    updatedAtUtc: iso(WINDOW_START + 20_000),
    heartbeatAtUtc: iso(WINDOW_START + 20_000),
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: {
      ...deriveVerifierGate(fixture.request, fixture.requestSha256),
      unitName: workerUnitName(fixture.generation),
      unitInvocationId: null,
    },
    observed,
    rootResponder: (script) =>
      script.includes("status.json")
        ? { code: 0, stdout: JSON.stringify(runningStatus), stderr: "" }
        : undefined,
  });
  await h.deps.private.write(CONTROLLER_STATE_PATH, state);
  // Commit the gate-binding persist, then fail the step as the controller
  // would on an IO error AFTER the durable write.
  const originalWrite = h.deps.private.write.bind(h.deps.private);
  let failedOnce = false;
  h.deps.private.write = (path, value) => {
    const record = value as Record<string, unknown>;
    const job = record?.job as Record<string, unknown> | undefined;
    if (
      !failedOnce && path === CONTROLLER_STATE_PATH &&
      job?.workerInvocationId === INVOCATION_A
    ) {
      failedOnce = true;
      return originalWrite(path, value).then(() => {
        throw new Error("io error after durable commit");
      });
    }
    return originalWrite(path, value);
  };
  const report = await runBackblazeCycle(h.deps, 4);
  assert(
    report.status.startsWith("B2_BACKUP_INCOMPLETE"),
    `${report.status} events=${h.events.join("|")}`,
  );
  const persisted = h.privateMap.get(CONTROLLER_STATE_PATH);
  const stateAfter = JSON.parse(
    persisted instanceof Uint8Array
      ? new TextDecoder().decode(persisted)
      : JSON.stringify(persisted),
  );
  assert(
    stateAfter.job.workerInvocationId === INVOCATION_A,
    "the saved gate binding must survive the step error",
  );
  assert(stateAfter.job.phase === "WORKER_RUNNING");
  assert(
    stateAfter.job.failure === undefined,
    "no terminal FAILED on uncertainty",
  );
  assert(h.tunnels.length === 0);
});

Deno.test("acceptance: idempotent replay keeps one catalog entry and the accepted state", async () => {
  const fixture = generationFixture(19, WINDOW_START);
  const receiptText = JSON.stringify(fixture.receipt);
  const receiptSha256 = sha256HexSync(new TextEncoder().encode(receiptText));
  const status = verifierAcceptedStatus(fixture, INVOCATION_B, receiptSha256);
  const base = stateWithJob(fixture, "VERIFIER_RUNNING", {
    verifierInvocationId: INVOCATION_B,
    verifierStatus: status,
  });
  // The durable catalog already holds this generation: a crash after the
  // accept persisted but before the ACCEPTED phase transition.
  const state = validateControllerState({
    schemaVersion: 1,
    catalog: [catalogEntry(fixture, WINDOW_START + 1000)],
    job: base.job,
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: verifyUnitName(fixture.generation),
    unitInvocationId: INVOCATION_B,
  };
  const options: HarnessOptions = {
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
    observed: () => terminalObserved(status),
    rootResponder: (script) =>
      script.includes("receipt.json")
        ? { code: 0, stdout: receiptText, stderr: "" }
        : undefined,
    seedPrivate: (map) => {
      map.set(
        `${PIP_JOB_EVIDENCE_PATH}/${fixture.jobId}/result.json`,
        new TextEncoder().encode(JSON.stringify(fixture.workerResult)),
      );
    },
  };
  const h = harness(options);
  const accepted = await stepBackupController(state, h.deps, h.deps.now());
  assert(accepted.job!.phase === "ACCEPTED");
  assert(accepted.catalog.length === 1, "the replay must not duplicate");
  assert(
    accepted.catalog[0].index.generation === fixture.generation,
    "the original accepted generation is preserved",
  );
});

/** A failed systemd proof observation (failed/failed with exit-code). */
function failedTerminalObserved(
  status: Record<string, unknown>,
): ObservedUnit {
  const props = new Map<string, string>([
    ["LoadState", "loaded"],
    ["ActiveState", "failed"],
    ["SubState", "failed"],
    ["Result", "exit-code"],
    ["MainPID", "0"],
    ["ControlPID", "0"],
    ["ControlGroup", ""],
    ["InvocationID", String(status.invocationId)],
  ]);
  return { props, status, lockFree: true, reachable: true };
}

Deno.test("orchestration: a surviving worker gate after the WORKER_TERMINAL persist is revalidated and cleared before the verifier launch", async () => {
  const fixture = generationFixture(40, WINDOW_START);
  const workerStatus = workerPendingStatus(fixture, INVOCATION_A);
  // The state the controller persisted BEFORE removing the worker gate:
  // a crash in that exact window resumes here.
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus,
    workerInvocationId: INVOCATION_A,
    resultSha256: "77".repeat(32),
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
    observed: () => terminalObserved(workerStatus),
  });
  const next = await stepBackupController(state, h.deps, h.deps.now());
  assert(
    next.job!.phase === "VERIFIER_LAUNCHED",
    `phase=${next.job!.phase}`,
  );
  assert(next.job!.failure === undefined, "no false failure on resume");
  const clearAt = h.events.indexOf("gate:clear");
  const createAt = h.events.indexOf("gate:create");
  const launchAt = h.events.findIndex((entry) => entry.startsWith("launch:"));
  assert(
    clearAt !== -1 && clearAt < createAt && createAt < launchAt,
    `fresh proof clears the surviving gate before the verifier is created: ${
      h.events.join("|")
    }`,
  );
  assert(h.launches.length === 1, "the worker unit is never relaunched");
  assert(
    h.launches[0].unitName.startsWith("arch-vps-b2-verify-"),
    h.launches[0].unitName,
  );
  assert(h.tunnels.length === 1);
});

Deno.test("orchestration: a transient verifier setup transport failure stays resumable in WORKER_TERMINAL with its exact gate", async () => {
  const fixture = generationFixture(45, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  let resolves = 0;
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    socketResolver: () => {
      resolves += 1;
      if (resolves === 1) return Promise.reject(new Error("transport down"));
      return Promise.resolve({
        socket: "/run/user/1002/gnupg/custom/S.gpg-agent",
        defaultSocket: "/run/user/1002/gnupg/S.gpg-agent",
      });
    },
  });
  const launches = h.launches;
  const assertLaunchCount = (expected: number, message: string): void => {
    if (launches.length !== expected) throw new Error(message);
  };
  const first = await stepBackupController(state, h.deps, h.deps.now());
  assert(
    first.job!.phase === "WORKER_TERMINAL",
    `a transient failure stays on the same phase: ${first.job!.phase}`,
  );
  assert(
    first.job!.failure === undefined,
    "no false FAILED on a transient setup transport failure",
  );
  assertLaunchCount(0, "no verifier launch before a resolved transport");
  assert(
    h.gate.value !== null && h.gate.value.jobId === fixture.request.jobId &&
      h.gate.value.unitName === verifyUnitName(fixture.generation) &&
      h.gate.value.state === "active",
    "the exact verifier gate survives the transient failure",
  );
  const second = await stepBackupController(first, h.deps, h.deps.now());
  assert(
    second.job!.phase === "VERIFIER_LAUNCHED",
    `the restored transport completes setup: ${second.job!.phase}`,
  );
  assert(second.job!.failure === undefined);
  assert(second.job!.envelope.request.jobId === fixture.request.jobId);
  assertLaunchCount(
    1,
    "exactly one verifier invocation, never a worker relaunch",
  );
  assert(
    launches[0].unitName === verifyUnitName(fixture.generation),
    launches[0].unitName,
  );
  assert(
    h.tunnels.length === 1,
    "the tunnel opens only after the transport returns",
  );
  // The run-level view must never produce a B2_BACKUP_FAILED report either.
  const report = await runBackblazeCycle(h.deps, 2);
  assert(
    report.status.startsWith("B2_BACKUP_INCOMPLETE") &&
      !report.status.includes("FAILED"),
    `no false FAILED report: ${report.status}`,
  );
  assertLaunchCount(1, "the resume never relaunches the verifier");
});

Deno.test("orchestration: an absent verifier invocation (empty or missing InvocationID) behind an already-open tunnel still launches exactly once", async () => {
  const fixture = generationFixture(33, WINDOW_START);
  // REAL VPS observation: a named but absent unit answers reachable=true
  // with LoadState=not-found and either an empty InvocationID or the
  // property missing entirely. Neither is a running invocation: the open
  // tunnel reconcile must not claim VERIFIER_LAUNCHED and skip the launch.
  const absentProps: Map<string, string>[] = [
    new Map<string, string>([
      ["LoadState", "not-found"],
      ["ActiveState", "inactive"],
      ["SubState", "dead"],
      ["Result", ""],
      ["MainPID", "0"],
      ["ControlPID", "0"],
      ["InvocationID", ""],
    ]),
    new Map<string, string>([
      ["LoadState", "not-found"],
      ["ActiveState", "inactive"],
      ["SubState", "dead"],
      ["Result", ""],
      ["MainPID", "0"],
      ["ControlPID", "0"],
    ]),
  ];
  for (const props of absentProps) {
    const state = stateWithJob(fixture, "WORKER_TERMINAL", {
      workerStatus: workerPendingStatus(fixture, INVOCATION_A),
      resultSha256: "77".repeat(32),
    });
    const h = harness({
      now: new Date(WINDOW_START + 60_000),
      gateValue: deriveVerifierGate(fixture.request, fixture.requestSha256),
      observed: (unitName) =>
        unitName.startsWith("arch-vps-b2-verify-")
          ? { props, status: null, lockFree: false, reachable: true }
          : {
            props: new Map(),
            status: null,
            lockFree: false,
            reachable: false,
          },
    });
    await h.deps.tunnel.open("/run/user/1002/gnupg/custom/S.gpg-agent");
    const next = await stepBackupController(state, h.deps, h.deps.now());
    assert(
      next.job!.phase === "VERIFIER_LAUNCHED",
      `the intended launch proceeds, never a false resume: ${next.job!.phase}`,
    );
    assert(next.job!.failure === undefined, "no false failure on the absence");
    assert(
      h.launches.length === 1,
      "the intended verifier launch happens exactly once",
    );
    assert(
      h.launches[0].unitName === verifyUnitName(fixture.generation),
      h.launches[0].unitName,
    );
    assert(
      h.gate.value !== null &&
        h.gate.value.state === "active" &&
        h.gate.value.jobId === fixture.request.jobId &&
        h.gate.value.unitName === verifyUnitName(fixture.generation) &&
        h.gate.value.unitInvocationId === null,
      "the exact saved verifier gate survives unbound",
    );
    assert(
      !h.events.includes("gate:create"),
      "the saved gate is never replaced",
    );
  }
});

Deno.test("orchestration: a real existing verifier invocation behind an already-open tunnel resumes with no new launch and binds the same id", async () => {
  const fixture = generationFixture(34, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: deriveVerifierGate(fixture.request, fixture.requestSha256),
    observed: (unitName) =>
      unitName.startsWith("arch-vps-b2-verify-")
        ? {
          props: new Map<string, string>([
            ["LoadState", "loaded"],
            ["ActiveState", "active"],
            ["SubState", "running"],
            ["Result", "success"],
            ["MainPID", "123"],
            ["ControlPID", "0"],
            ["InvocationID", INVOCATION_B],
          ]),
          status: null,
          lockFree: false,
          reachable: true,
        }
        : {
          props: new Map(),
          status: null,
          lockFree: false,
          reachable: false,
        },
  });
  await h.deps.tunnel.open("/run/user/1002/gnupg/custom/S.gpg-agent");
  const first = await stepBackupController(state, h.deps, h.deps.now());
  assert(
    first.job!.phase === "VERIFIER_LAUNCHED",
    `a real existing unit resumes as launched: ${first.job!.phase}`,
  );
  assert(h.launches.length === 0, "no new launch for a real invocation");
  assert(
    h.gate.value !== null && h.gate.value.state === "active",
    "the exact verifier gate is never replaced or cleared",
  );
  const second = await stepBackupController(first, h.deps, h.deps.now());
  assert(
    second.job!.phase === "VERIFIER_RUNNING",
    `phase=${second.job!.phase}`,
  );
  assert(
    second.job!.verifierInvocationId === INVOCATION_B,
    "the exact existing invocation binds",
  );
  assert(
    h.launches.length === 0,
    "the reconcile must never assume a second launch is needed",
  );
});

Deno.test("orchestration: a malformed nonempty verifier invocation fails closed without any launch or bind", async () => {
  const fixture = generationFixture(35, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: deriveVerifierGate(fixture.request, fixture.requestSha256),
    observed: (unitName) =>
      unitName.startsWith("arch-vps-b2-verify-")
        ? {
          props: new Map<string, string>([
            ["LoadState", "loaded"],
            ["ActiveState", "active"],
            ["SubState", "running"],
            ["Result", "success"],
            ["MainPID", "123"],
            ["ControlPID", "0"],
            ["InvocationID", "not-a-real-invocation-id"],
          ]),
          status: null,
          lockFree: false,
          reachable: true,
        }
        : {
          props: new Map(),
          status: null,
          lockFree: false,
          reachable: false,
        },
  });
  await h.deps.tunnel.open("/run/user/1002/gnupg/custom/S.gpg-agent");
  let threw = false;
  try {
    await stepBackupController(state, h.deps, h.deps.now());
  } catch {
    threw = true;
  }
  assert(threw, "a malformed nonempty invocation must fail closed");
  assert(h.launches.length === 0, "no launch may follow a malformed identity");
  assert(
    h.gate.value !== null && h.gate.value.unitInvocationId === null,
    "the gate is never silently bound to a malformed identity",
  );
});

Deno.test("orchestration: a lost verifier launch transport response reconciles the exact unit before any second launch", async () => {
  const fixture = generationFixture(47, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  let launchesAttempted = 0;
  const verifierObservation: ObservedUnit = {
    props: new Map<string, string>([
      ["LoadState", "loaded"],
      ["ActiveState", "active"],
      ["SubState", "running"],
      ["Result", "success"],
      ["MainPID", "123"],
      ["ControlPID", "0"],
      ["InvocationID", INVOCATION_B],
    ]),
    status: null,
    lockFree: false,
    reachable: true,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    observed: (unitName) =>
      unitName.startsWith("arch-vps-b2-verify-")
        ? verifierObservation
        : { props: new Map(), status: null, lockFree: false, reachable: false },
    launchUnitOverride: () => {
      launchesAttempted += 1;
      return Promise.reject(new Error("launch response lost"));
    },
  });
  const first = await stepBackupController(state, h.deps, h.deps.now());
  assert(
    first.job!.phase === "VERIFIER_LAUNCHED",
    `a confirmed existing unit resumes as launched: ${first.job!.phase}`,
  );
  assert(
    first.job!.failure === undefined,
    "no false FAILED on launch uncertainty",
  );
  assert(launchesAttempted === 1, "one launch attempt");
  assert(
    h.gate.value !== null &&
      h.gate.value.unitName === verifyUnitName(fixture.generation) &&
      h.gate.value.state === "active",
    "the exact verifier gate is never replaced or cleared",
  );
  const second = await stepBackupController(first, h.deps, h.deps.now());
  assert(
    second.job!.phase === "VERIFIER_RUNNING",
    `phase=${second.job!.phase}`,
  );
  assert(
    second.job!.verifierInvocationId === INVOCATION_B,
    "the exact existing named unit binds the invocation",
  );
  assert(
    launchesAttempted === 1,
    "the reconcile must never assume a second launch is needed",
  );
});

Deno.test("orchestration: a surviving verifier gate after the ACCEPTED persist is revalidated and cleared before pruning", async () => {
  const fixture = generationFixture(41, WINDOW_START);
  const receiptText = JSON.stringify(fixture.receipt);
  const receiptSha256 = sha256HexSync(new TextEncoder().encode(receiptText));
  const status = verifierAcceptedStatus(fixture, INVOCATION_B, receiptSha256);
  // The single recoverable acceptance state: catalog + ACCEPTED in one
  // durable write, with the verifier gate still alive (crash before clear).
  const state = validateControllerState({
    schemaVersion: 1,
    catalog: [catalogEntry(fixture, WINDOW_START + 1000)],
    job: {
      ...stateWithJob(fixture, "ACCEPTED", {
        verifierStatus: status,
        verifierInvocationId: INVOCATION_B,
        workerInvocationId: INVOCATION_A,
      }).job!,
    },
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: verifyUnitName(fixture.generation),
    unitInvocationId: INVOCATION_B,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
    observed: () => terminalObserved(status),
    versions: inventoryFor([fixture]),
    seedPrivate: (map) => {
      map.set(
        `${PIP_JOB_EVIDENCE_PATH}/${fixture.jobId}/result.json`,
        new TextEncoder().encode(JSON.stringify(fixture.workerResult)),
      );
    },
  });
  let final = state;
  for (let step = 0; step < 8; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    if (["COMPLETE", "FAILED"].includes(final.job!.phase)) break;
  }
  assert(final.job!.phase === "COMPLETE", `phase=${final.job!.phase}`);
  assert(final.job!.failure === undefined, "no false failure on resume");
  assert(final.catalog.length === 1, "exactly one catalog entry stays");
  assert(
    final.catalog[0].index.generation === fixture.generation,
    "the accepted generation is preserved, never duplicated",
  );
  assert(h.gate.value === null, "the surviving gate is cleared before prune");
  const clearAt = h.events.indexOf("gate:clear");
  const firstRemoval = h.events.findIndex((entry) =>
    entry.startsWith("remove:")
  );
  assert(
    clearAt !== -1 && (firstRemoval === -1 || clearAt < firstRemoval),
    "the gate is cleared before any prune removal",
  );
  assert(h.store.removed.length === 0, "nothing pruned for one generation");
});

Deno.test("orchestration: a foreign or mismatched surviving gate never clears and blocks the resume", async () => {
  const fixture = generationFixture(42, WINDOW_START);
  const foreign = generationFixture(43, WINDOW_START + 1000);
  const workerStatus = workerPendingStatus(fixture, INVOCATION_A);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus,
    workerInvocationId: INVOCATION_A,
    resultSha256: "77".repeat(32),
  });
  // The gate carries the foreign job identity but claims this worker unit.
  const foreignGate = {
    ...deriveVerifierGate(foreign.request, foreign.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: foreignGate,
    observed: () => terminalObserved(workerStatus),
  });
  let threw = false;
  try {
    await stepBackupController(state, h.deps, h.deps.now());
  } catch {
    threw = true;
  }
  assert(threw, "a foreign gate must fail closed");
  assert(h.gate.value !== null, "the foreign gate is never cleared");
  assert(!h.events.includes("gate:clear"));
  assert(h.launches.length === 0, "no launch may follow a foreign gate");
});

Deno.test("orchestration: a failed terminal unit resume revalidates and clears its surviving gate without losing failure evidence", async () => {
  const fixture = generationFixture(44, WINDOW_START);
  const raw = workerPendingStatus(fixture, INVOCATION_A);
  delete raw.resultSha256;
  const failedStatus = {
    ...raw,
    state: "FAILED",
    errorCode: "CAPTURE_FAILED",
  };
  const state = validateControllerState({
    schemaVersion: 1,
    catalog: [],
    job: {
      ...stateWithJob(fixture, "FAILED", {
        workerStatus: failedStatus,
        workerInvocationId: INVOCATION_A,
        failure: {
          code: "CAPTURE_FAILED",
          atUtc: iso(WINDOW_START + 60_000),
        },
      }).job!,
    },
  });
  const gate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    unitInvocationId: INVOCATION_A,
  };
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: gate,
    observed: () => failedTerminalObserved(failedStatus),
  });
  const after = await stepBackupController(state, h.deps, h.deps.now());
  assert(after.job!.phase === "FAILED");
  assert(
    after.job!.failure!.code === "CAPTURE_FAILED",
    "the original failure evidence is preserved",
  );
  assert(
    h.gate.value === null,
    "the failed terminal gate is cleared on resume",
  );
  assert(h.events.includes("gate:clear"));
  assert(h.launches.length === 0);
});

Deno.test("orchestration: prior period closes allow a fresh next Sunday job", async () => {
  const fixture = generationFixture(20, WINDOW_START);
  const catalog = [catalogEntry(fixture, WINDOW_START + 1000)];
  const nextSunday = WINDOW_START + 7 * 86_400_000;
  for (const phase of ["COMPLETE", "FAILED"] as const) {
    const closed = validateControllerState({
      schemaVersion: 1,
      catalog,
      job: {
        ...stateWithJob(fixture, phase).job!,
        ...(phase === "FAILED"
          ? { failure: { code: "X", atUtc: iso(WINDOW_START + 1000) } }
          : {}),
      },
    });
    const h = harness({
      now: new Date(nextSunday + 1000),
      seedPrivate: (map) => {
        map.set(".private/backup-runtime.json", ORACLE_STATE_FIXTURE);
        map.set(
          ".private/backup-scheduled-window.json",
          SCHEDULED_CLAIM_FIXTURE,
        );
      },
    });
    const created = await stepBackupController(closed, h.deps, h.deps.now());
    assert(created.job!.phase === "REQUESTED", `phase=${phase}`);
    assert(created.job!.envelope.request.periodKey === "2026-09-13", phase);
    assert(created.job!.envelope.request.jobId !== fixture.jobId, phase);
    assert(created.catalog.length === 1, "catalog is preserved across periods");
    // Same period: never a replacement.
    const sameHarness = harness({ now: new Date(WINDOW_START + 60_000) });
    const same = await stepBackupController(
      closed,
      sameHarness.deps,
      sameHarness.deps.now(),
    );
    assert(same.job!.phase === phase, "same period is never replaced");
    assert(sameHarness.launches.length === 0);
    // Clock rollback: never create an earlier-period replacement.
    const laterEnvelope = buildRequestEnvelope({
      jobUuid: uuidFor(21),
      periodKey: "2026-09-13",
      requestedAtUtc: iso(nextSunday),
      recipientSha256: RECIPIENT_SHA256,
      recipientFingerprint: RECIPIENT_FINGERPRINT,
      sourceRevision: REVISION,
      sourceConfigSha256: SOURCE_CONFIG_SHA256,
    });
    const rolledBack = validateControllerState({
      schemaVersion: 1,
      catalog,
      job: {
        ...newJobState(laterEnvelope, new Date(nextSunday)),
        phase,
        ...(phase === "FAILED"
          ? { failure: { code: "X", atUtc: iso(nextSunday + 1000) } }
          : {}),
      },
    });
    const rollbackHarness = harness({ now: new Date(WINDOW_START + 60_000) });
    const kept = await stepBackupController(
      rolledBack,
      rollbackHarness.deps,
      rollbackHarness.deps.now(),
    );
    assert(kept.job!.envelope.request.periodKey === "2026-09-13");
    assert(rollbackHarness.launches.length === 0);
  }
  // An active/orphaned gate blocks the replacement.
  const closed = validateControllerState({
    schemaVersion: 1,
    catalog,
    job: stateWithJob(fixture, "COMPLETE").job,
  });
  const blockingGate: BackupControllerGate = {
    ...deriveVerifierGate(fixture.request, fixture.requestSha256),
    unitName: workerUnitName(fixture.generation),
    state: "orphaned",
    orphanReason: "TERMINAL_PROOF_MISSING",
  };
  const blocked = harness({
    now: new Date(nextSunday + 1000),
    gateValue: blockingGate,
    seedPrivate: (map) => {
      map.set(".private/backup-runtime.json", ORACLE_STATE_FIXTURE);
      map.set(".private/backup-scheduled-window.json", SCHEDULED_CLAIM_FIXTURE);
    },
  });
  const unchanged = await stepBackupController(
    closed,
    blocked.deps,
    blocked.deps.now(),
  );
  assert(unchanged.job!.phase === "COMPLETE");
  assert(
    blocked.launches.length === 0,
    "an active gate must block replacement",
  );
});

Deno.test("cycle: a closed previous-week job must not cut the fresh next-Sunday run short", async () => {
  // Regression: runBackblazeCycle computed the deadline bound from the
  // PRE-step job, so a previous-week COMPLETE/FAILED (whose own deadline
  // long passed) made the cycle break immediately after the step allocated
  // the new REQUESTED next-Sunday job, returning B2_BACKUP_INCOMPLETE with
  // "Request deadline reached" before the new job was even installed or
  // launched. The bound must come from the resulting/current immutable job
  // identity, and the same run must continue through allocation to work.
  const nextSunday = WINDOW_START + 7 * 86_400_000;
  const workerInvocation = "3".repeat(32);
  const verifierInvocation = "4".repeat(32);
  for (const phase of ["COMPLETE", "FAILED"] as const) {
    const previous = generationFixture(72, WINDOW_START);
    const closed = validateControllerState({
      schemaVersion: 1,
      catalog: [catalogEntry(previous, WINDOW_START + 1000)],
      job: {
        ...stateWithJob(previous, phase).job!,
        ...(phase === "FAILED"
          ? { failure: { code: "X", atUtc: iso(WINDOW_START + 1000) } }
          : {}),
      },
    });
    let current: GenerationFixture | undefined;
    let resultText: string | undefined;
    let receiptText: string | undefined;
    const ensureFixture = (): GenerationFixture => {
      if (current === undefined) {
        const envelope =
          (h.privateMap.get(CONTROLLER_STATE_PATH) as ControllerState)
            .job!.envelope;
        const base = generationFixtureFor(
          envelope.request.jobId.slice("job-".length),
          Date.parse(envelope.request.requestedAtUtc),
        );
        current = {
          ...base,
          request: envelope.request,
          requestSha256: envelope.requestSha256,
          workerResult: {
            envelope,
            capture: base.capture,
            upload: base.upload,
            publishedIndex: base.publishedIndex,
          },
        };
        h.store.versionsList.push(...inventoryFor([current]));
        resultText = JSON.stringify(current.workerResult);
        receiptText = JSON.stringify(current.receipt);
      }
      return current;
    };
    const h: Harness = harness({
      now: new Date(nextSunday + 1000),
      observed: (unitName) => {
        // The allocation step runs at nextSunday+1000 with the terminal
        // status timestamps relative to the requested instant; poll the
        // work of the fresh job from a slightly later instant.
        h.clock.current = new Date(nextSunday + 60_000);
        const fixture = ensureFixture();
        if (unitName.startsWith("arch-vps-b2-worker-")) {
          const status = workerPendingStatus(fixture, workerInvocation);
          status.resultSha256 = sha256HexSync(
            new TextEncoder().encode(resultText!),
          );
          return terminalObserved(status);
        }
        return terminalObserved(verifierAcceptedStatus(
          fixture,
          verifierInvocation,
          sha256HexSync(new TextEncoder().encode(receiptText!)),
        ));
      },
      rootResponder: (script) => {
        if (script.includes("result.json")) {
          return { code: 0, stdout: resultText!, stderr: "" };
        }
        if (script.includes("receipt.json")) {
          return { code: 0, stdout: receiptText!, stderr: "" };
        }
        return undefined;
      },
      seedPrivate: (map) => {
        map.set(".private/backup-runtime.json", ORACLE_STATE_FIXTURE);
        map.set(
          ".private/backup-scheduled-window.json",
          SCHEDULED_CLAIM_FIXTURE,
        );
      },
    });
    h.store.versionsList.push(...inventoryFor([previous]));
    await h.deps.private.write(CONTROLLER_STATE_PATH, closed);
    const report = await runBackblazeCycle(h.deps);
    assert(
      report.status.startsWith("B2_BACKUP_COMPLETE"),
      `phase=${phase} status=${report.status} detail=${
        report.detail ?? "none"
      }`,
    );
    assert(report.jobId !== previous.jobId, `phase=${phase}`);
    const persisted = h.privateMap.get(
      CONTROLLER_STATE_PATH,
    ) as ControllerState;
    assert(
      persisted.job!.envelope.request.periodKey === "2026-09-13",
      `phase=${phase} fresh job period`,
    );
    assert(persisted.job!.phase === "COMPLETE", `phase=${phase}`);
    assert(
      persisted.catalog.some((entry) =>
        entry.index.generation === persisted.job!.envelope.request.generation
      ),
      `phase=${phase} the fresh generation is accepted`,
    );
    assert(
      persisted.catalog.some((entry) =>
        entry.index.generation === previous.generation
      ),
      `phase=${phase} the previous catalog entry is preserved`,
    );
    assert(
      h.launches.length === 2,
      `phase=${phase} the same run installs/launches the fresh job (launches=${h.launches.length})`,
    );
    assert(
      !report.status.includes("INCOMPLETE") &&
        !report.status.includes("FAILED"),
      `phase=${phase} report=${report.status}`,
    );
  }
});

Deno.test("retention: resume revalidates plan IDs and trims a zero-remaining plan", () => {
  const fixtures = [1, 2, 3, 4, 5, 6].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const inventory = inventoryFor(fixtures);
  const oldest = fixtures[0];
  const oldestIds = new Set(
    oldest.upload.archives.flatMap((archive) =>
      archive.chunks.map((c) => c.fileId)
    )
      .concat([oldest.publishedIndex.object.fileId]),
  );
  const plan = [{
    generation: oldest.generation,
    fileIds: [...oldestIds, "ffffffff-0000-0000-0000-000000000000"],
  }];
  const eligible = [oldest.generation];
  // A normal resume returns the still-present planned versions.
  const checked = revalidatePruneDeletions(inventory, plan, eligible, []);
  assert(checked.violation === null);
  assert(checked.pending.length === oldestIds.size);
  assert(checked.removed.includes("ffffffff-0000-0000-0000-000000000000"));
  // The plan is never trusted ID-only: a retained id is a violation.
  const retainedPlan = revalidatePruneDeletions(
    inventory,
    plan,
    eligible,
    [oldest.publishedIndex.object.fileId],
  );
  assert(retainedPlan.violation !== null);
  assert(retainedPlan.violation!.includes("retained"));
  // A foreign namespace/start action is a violation.
  const foreign = inventory.map((object) =>
    object.fileId === oldest.publishedIndex.object.fileId
      ? {
        ...object,
        fileName: `${generationPrefixes(fixtures[1].generation)[0]}other`,
        action: "start" as const,
      }
      : object
  );
  const foreignCheck = revalidatePruneDeletions(foreign, plan, eligible, []);
  assert(foreignCheck.violation !== null);
  // No eligible generation: the plan is entirely ineligible.
  const staleEligible = revalidatePruneDeletions(
    inventory,
    plan,
    [fixtures[1].generation],
    [],
  );
  assert(staleEligible.violation !== null);
});

Deno.test("retention: empty older inventory trims catalog to the four accepted", async () => {
  const fixtures = [1, 2, 3, 4, 5, 6].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const catalog = fixtures.map((fixture, i) =>
    catalogEntry(fixture, WINDOW_START + i * 1000)
  );
  const oldestIds = new Set(
    fixtures[0].upload.archives.flatMap((archive) =>
      archive.chunks.map((chunk) => chunk.fileId)
    ).concat([fixtures[0].publishedIndex.object.fileId]),
  );
  const freshWithoutOldest = inventoryFor(fixtures).filter((object) =>
    !oldestIds.has(object.fileId)
  );
  const current = fixtures[5];
  const state = validateControllerState({
    schemaVersion: 1,
    catalog,
    job: stateWithJob(current, "ACCEPTED").job,
  });
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    versions: freshWithoutOldest,
  });
  let final = state;
  for (let step = 0; step < 12; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    if (final.job!.phase === "COMPLETE" || final.job!.phase === "FAILED") break;
  }
  assert(final.job!.phase === "COMPLETE", `phase=${final.job!.phase}`);
  assert(
    final.catalog.length === 4,
    "catalog membership must shrink to the newest four",
  );
  for (const entry of final.catalog) {
    assert(
      entry.index.generation !== fixtures[0].generation &&
        entry.index.generation !== fixtures[1].generation,
    );
  }
  // Only the still-present second-oldest data may be removed; the oldest
  // generation had no data left (zero remaining plan IDs) yet its catalog
  // membership was still trimmed.
  const secondOldestIds = new Set(
    fixtures[1].upload.archives.flatMap((archive) =>
      archive.chunks.map((chunk) => chunk.fileId)
    ).concat([fixtures[1].publishedIndex.object.fileId]),
  );
  assert(
    h.store.removed.length === secondOldestIds.size,
    "only the second-oldest present data was removed",
  );
  assert(
    h.store.removed.every((object) => secondOldestIds.has(object.fileId)),
  );
});

Deno.test("cleanup: allowed names derive from the output contracts and reject foreign entries", () => {
  for (const role of UPLOAD_ROLE_ORDER) {
    const format = role === "recovery" ? "json.zst" : "tar.zst";
    assert(cleanupAllowedName(`${role}.${format}.gpg`, false), role);
    assert(cleanupAllowedName(`${role}.${format}.gpg.partial`, false), role);
    assert(cleanupAllowedName(`${role}.${format}`, false), role);
    assert(cleanupAllowedName(`${role}.${format}.partial`, false), role);
    assert(cleanupAllowedName(`${role}.du.txt`, false), role);
    assert(cleanupAllowedName(`space-${role}.stderr.log`, false), role);
    assert(cleanupAllowedName(`encrypt-${role}.stderr.log`, false), role);
    assert(cleanupAllowedName(`hash-${role}.stderr.log`, false), role);
  }
  assert(cleanupAllowedName("exclusions.txt", false));
  assert(cleanupAllowedName("recipient.asc", false));
  assert(cleanupAllowedName("manifest.json", false));
  assert(cleanupAllowedName("oracle-root.swapfile.stat", false));
  assert(cleanupAllowedName("lvm-ocivolume.vg", false));
  assert(cleanupAllowedName("capture-error.txt", false));
  assert(cleanupAllowedName("sample.root.Image", false));
  assert(
    cleanupAllowedName("sample.staging-boot.arch-initrd.img.partial", false),
  );
  for (const label of CLEANUP_LABELS) {
    assert(cleanupAllowedName(`${label}.stderr.log`, false), label);
  }
  // Uploader contract (backblaze-upload.ts).
  assert(cleanupAllowedName("upload-journal.json", false));
  // Index publisher contract (backblaze-index.ts).
  assert(cleanupAllowedName("recovery-index.json", false));
  assert(cleanupAllowedName("recovery-index.json.gpg", false));
  assert(cleanupAllowedName("recovery-index.json.gpg.partial", false));
  assert(cleanupAllowedName("recovery-index-receipt.json", false));
  assert(cleanupAllowedName("recovery-index-state.json", false));
  assert(cleanupAllowedName("index-recipient.asc", false));
  // Atomic temp convention of both modules (`.<name>.<v4 uuid>.tmp`).
  assert(
    cleanupAllowedName(
      `.upload-journal.json.${crypto.randomUUID()}.tmp`,
      false,
    ),
  );
  assert(
    cleanupAllowedName(
      `.recovery-index.json.${crypto.randomUUID()}.tmp`,
      false,
    ),
  );
  assert(
    cleanupAllowedName(
      `.recovery-index-receipt.json.${crypto.randomUUID()}.tmp`,
      false,
    ),
  );
  assert(
    cleanupAllowedName(
      `.recovery-index-state.json.${crypto.randomUUID()}.tmp`,
      false,
    ),
  );
  assert(
    cleanupAllowedName(
      `.index-recipient.asc.${crypto.randomUUID()}.tmp`,
      false,
    ),
  );
  assert(cleanupAllowedName("gpg-public-home", true));
  assert(cleanupAllowedName("index-public-home", true));
  assert(cleanupGpgHomeAllowedName("pubring.kbx"));
  assert(cleanupGpgHomeAllowedName("trustdb.gpg"));
  assert(cleanupGpgHomeAllowedName("S.gpg-agent.extra"));
  assert(cleanupGpgHomeAllowedName("private-keys-v1.d"));
  assert(!cleanupAllowedName("root.tar.zst.gpg.extra", false));
  assert(!cleanupAllowedName("root.tar.zst.gpg.partial.bak", false));
  assert(!cleanupAllowedName("evil", false));
  assert(!cleanupAllowedName("nested", true));
  assert(!cleanupAllowedName(".upload-journal.json.tmp", false));
  assert(
    !cleanupAllowedName(
      `.upload-journal.json.${crypto.randomUUID()}.bak`,
      false,
    ),
  );
  assert(
    !cleanupAllowedName(`.upload-journal.json.${"0".repeat(32)}.tmp`, false),
  );
  assert(!cleanupAllowedName(".secret.tmp", false));
  assert(!cleanupGpgHomeAllowedName("id_rsa"));
  assert(!cleanupGpgHomeAllowedName("private-keys-v1.d/key"));
});

Deno.test("cleanup: the three source-worker stage receipts are accepted, foreign result.json stays rejected", () => {
  const fixture = generationFixture(25, WINDOW_START);
  // Regression: a successful worker run persists exactly one receipt per
  // phase (capture, upload, index) into the generation stage, so omitting
  // them aborts the final scratch cleanup on UNEXPECTED_FILE.
  for (
    const name of [
      CAPTURE_RESULT_FILE,
      UPLOAD_RESULT_FILE,
      INDEX_RESULT_FILE,
    ]
  ) {
    assert(cleanupAllowedName(name, false), `worker stage receipt ${name}`);
  }
  // Only the exact producer names are whitelisted; an arbitrary foreign
  // `*-result.json` receipt must never be accepted.
  assert(!cleanupAllowedName("foreign-result.json", false));
  assert(!cleanupAllowedName("capture-result.json.bak", false));
  assert(!cleanupAllowedName("upload-result.json.extra", false));
  assert(!cleanupAllowedName("index-result.json.partial", false));
  const script = buildCleanupScript(fixture.generation);
  for (
    const name of [
      CAPTURE_RESULT_FILE,
      UPLOAD_RESULT_FILE,
      INDEX_RESULT_FILE,
    ]
  ) {
    assert(
      script.includes(name),
      `the emitted cleanup pattern includes ${name}`,
    );
  }
});

Deno.test("cleanup: script rejects mounts at/below, symlinks and unknown descendants", () => {
  const fixture = generationFixture(24, WINDOW_START);
  const script = buildCleanupScript(fixture.generation);
  assert(script.includes('substr($2, 1, length(p) + 1) == p "/"'));
  assert(script.includes("MOUNT_AT_OR_BELOW"));
  assert(script.includes("UNEXPECTED_ENTRY"));
  assert(script.includes("UNEXPECTED_SYMLINK"));
  assert(script.includes("UNEXPECTED_GPG_SYMLINK"));
  assert(script.includes("UNEXPECTED_FILE"));
  assert(script.includes("UNEXPECTED_DIR"));
  assert(script.includes("GPG_PRIVATE_KEYS"));
  assert(script.includes("UNEXPECTED_GPG_FILE"));
  assert(script.includes('rm -rf --one-file-system -- "$dir"'));
  assert(script.includes("gpg-public-home"));
  assert(script.includes("index-public-home"));
  assert(script.includes("root.tar.zst.gpg"));
  assert(script.includes("sample.root.Image"));
  assert(!script.includes("jobs/"), "only generation directories are removed");
  assert(script.includes("NOT_0700_BASE"));
  assert(script.includes("NOT_CANONICAL"));
  assert(
    script.includes('test -d "$dir"'),
    "a regular file at the generation path is rejected",
  );
  assert(script.includes("NOT_DIRECTORY"));
  assert(
    script.includes("-mindepth 1 -maxdepth 1 -printf"),
    "only direct children of the generation directory are validated",
  );
  assert(
    script.includes("upload-journal.json"),
    "the uploader resume journal is a known producer output",
  );
  assert(
    script.includes("recovery-index-receipt.json"),
    "the index publisher outputs are known producer outputs",
  );
  assert(
    script.includes(".upload-journal.json.") === false ||
      script.includes(".recovery-index.json."),
    "atomic temp names use the exact producer prefix convention",
  );
});

Deno.test("cleanup: a normal capture/upload/index directory is accepted; foreign, nested, symlink and private-key entries stay rejected", () => {
  const fixture = generationFixture(23, WINDOW_START);
  // Every output a fully successful capture + upload + index + verify run
  // leaves in its generation scratch directory.
  const normal: string[] = [
    "exclusions.txt",
    "recipient.asc",
    "oracle-root.swapfile.stat",
    "staging-boot.sha.before",
    "staging-boot.sha.after",
    "lvm-ocivolume.vg",
    "manifest.json",
    "capture-error.txt",
    ...CLEANUP_LABELS.map((label) => `${label}.stderr.log`),
    "sample.root.Image",
    "sample.root.initramfs-linux.img",
    "sample.staging-boot.arch-vmlinuz",
    "sample.staging-boot.arch-initrd.img",
    "sample.root.Image.partial",
    "upload-journal.json",
    "recovery-index.json",
    "recovery-index.json.gpg",
    "recovery-index.json.gpg.partial",
    "recovery-index-receipt.json",
    "recovery-index-state.json",
    "index-recipient.asc",
    `.upload-journal.json.${crypto.randomUUID()}.tmp`,
    `.recovery-index.json.${crypto.randomUUID()}.tmp`,
    `.recovery-index-receipt.json.${crypto.randomUUID()}.tmp`,
    `.recovery-index-state.json.${crypto.randomUUID()}.tmp`,
    `.index-recipient.asc.${crypto.randomUUID()}.tmp`,
  ];
  for (const role of UPLOAD_ROLE_ORDER) {
    const format = role === "recovery" ? "json.zst" : "tar.zst";
    normal.push(`${role}.${format}.gpg`);
    normal.push(`${role}.${format}.gpg.partial`);
    normal.push(`${role}.${format}`);
    normal.push(`${role}.${format}.partial`);
    normal.push(`${role}.du.txt`);
    normal.push(`space-${role}.stderr.log`);
    normal.push(`encrypt-${role}.stderr.log`);
    normal.push(`hash-${role}.stderr.log`);
  }
  for (const name of normal) {
    assert(cleanupAllowedName(name, false), `normal producer output ${name}`);
  }
  assert(cleanupAllowedName("gpg-public-home", true));
  assert(cleanupAllowedName("index-public-home", true));
  // A normal public-only home (capture and index key homes).
  for (
    const name of [
      "pubring.kbx",
      "pubring.kbx.lock",
      "trustdb.gpg",
      "trustdb.gpg.lock",
      "random_seed",
      "S.gpg-agent.extra",
      "private-keys-v1.d",
      "crls.d",
    ]
  ) {
    assert(cleanupGpgHomeAllowedName(name), `public home entry ${name}`);
  }
  // Foreign, nested, symlink and private-key contents are never a normal
  // accepted directory.
  assert(!cleanupAllowedName("id_rsa", false));
  assert(!cleanupAllowedName("jobs", true));
  assert(!cleanupAllowedName("nested-dir", true));
  assert(!cleanupAllowedName("notes.txt", false));
  assert(!cleanupAllowedName("private-keys-v1.d", false));
  assert(!cleanupAllowedName("recovery-index.json.gpg.old", false));
  assert(!cleanupGpgHomeAllowedName("secret-keys-v1.d"));
  assert(!cleanupGpgHomeAllowedName("secring.gpg"));
  // The script's direct-child and separate-home enumeration is generated
  // from those contracts.
  const script = buildCleanupScript(fixture.generation);
  assert(script.includes('find "$dir" -mindepth 1 -maxdepth 1'));
  assert(
    script.includes(
      "for publicName in gpg-public-home index-public-home; do",
    ),
  );
  assert(
    script.includes('test -z "$(find "$home/$name" -mindepth 1'),
    "nonempty private-keys-v1.d must stay rejected",
  );
});

/** NUL-separated synthetic `find -printf "%y %P\0"` records. */
function encodeNulRecords(records: string[]): Uint8Array {
  const parts = records.map((record) =>
    new TextEncoder().encode(`${record}\0`)
  );
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

Deno.test("cleanup: the emitted parser executes synthetic NUL records, accepting normal names and rejecting foreign whitespace/newline names", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("cleanup parser: skipped without write/run permissions");
    return;
  }
  const fixture = generationFixture(46, WINDOW_START);
  const emitted = buildCleanupScript(fixture.generation);
  const dir = await Deno.makeTempDir({ prefix: "m09-cleanup-parser-" });
  const stubDir = `${dir}/stubs`;
  await Deno.mkdir(`${dir}/base-backup`, { recursive: true });
  await Deno.mkdir(`${dir}/base-backup/${fixture.generation}`, {
    recursive: true,
  });
  await Deno.mkdir(
    `${dir}/base-backup/${fixture.generation}/gpg-public-home`,
    { recursive: true },
  );
  await Deno.mkdir(
    `${dir}/base-backup/${fixture.generation}/index-public-home`,
    { recursive: true },
  );
  try {
    // The parser under test is the EXACT emitted code; only the hardcoded
    // deployment bases are redirected into the sandbox, and find/stat/
    // readlink/flock/rm are stubs so synthetic NUL records drive the loop.
    const sandboxed = emitted
      .replaceAll("/var/tmp/arch-vps-file-backup", `${dir}/base-backup`)
      .replaceAll("/var/tmp/arch-vps-file-recovery", `${dir}/base-recovery`)
      .replaceAll(
        "/var/tmp/arch-vps-file-verification",
        `${dir}/base-verification`,
      );
    await Deno.mkdir(stubDir, { recursive: true });
    await Deno.writeTextFile(
      `${stubDir}/stat`,
      [
        "#!/bin/sh",
        'case "$2" in',
        "  %u) echo 0 ;;",
        "  %a) echo 700 ;;",
        "  *) exit 1 ;;",
        "esac",
      ].join("\n"),
    );
    await Deno.writeTextFile(
      `${stubDir}/readlink`,
      [
        "#!/bin/sh",
        'echo "$2"',
      ].join("\n"),
    );
    await Deno.writeTextFile(
      `${stubDir}/flock`,
      ["#!/bin/sh", "exit 0"].join("\n"),
    );
    for (const name of ["stat", "readlink", "flock"]) {
      await Deno.chmod(`${stubDir}/${name}`, 0o755);
    }
    const run = async (
      genRecords: string[],
      gpgRecords: string[],
    ): Promise<
      { code: number; stdout: string; stderr: string; rmLog: string }
    > => {
      const genPath = `${dir}/gen.records`;
      const gpgPath = `${dir}/gpg.records`;
      const rmLog = `${dir}/rm.log`;
      await Deno.writeFile(genPath, encodeNulRecords(genRecords));
      await Deno.writeFile(gpgPath, encodeNulRecords(gpgRecords));
      await Deno.writeTextFile(
        `${stubDir}/find`,
        [
          "#!/bin/sh",
          'case "$1" in',
          "  *private-keys-v1.d) exit 0 ;;",
          `  */gpg-public-home|*/index-public-home) cat ${
            shellQuote(gpgPath)
          } ;;`,
          `  *) cat ${shellQuote(genPath)} ;;`,
          "esac",
        ].join("\n"),
      );
      await Deno.writeTextFile(
        `${stubDir}/rm`,
        [
          "#!/bin/sh",
          `printf '%s\\n' "$*" >> ${shellQuote(rmLog)}`,
        ].join("\n"),
      );
      await Deno.remove(rmLog).catch(() => {});
      await Deno.chmod(`${stubDir}/find`, 0o755);
      await Deno.chmod(`${stubDir}/rm`, 0o755);
      await Deno.writeTextFile(`${dir}/cleanup.sh`, sandboxed);
      const child = new Deno.Command("/bin/bash", {
        args: ["cleanup.sh"],
        cwd: dir,
        env: { PATH: `${stubDir}:/usr/bin:/bin` },
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const output = await child.output();
      const status = await child.status;
      let rmLogText = "";
      try {
        rmLogText = await Deno.readTextFile(rmLog);
      } catch {
        // No removal was attempted.
      }
      return {
        code: status.code,
        stdout: new TextDecoder().decode(output.stdout),
        stderr: new TextDecoder().decode(output.stderr),
        rmLog: rmLogText,
      };
    };
    const normalGen = [
      "f exclusions.txt",
      "f recipient.asc",
      "f oracle-root.swapfile.stat",
      "f staging-boot.sha.before",
      "f staging-boot.sha.after",
      "f lvm-ocivolume.vg",
      "f manifest.json",
      "f capture-error.txt",
      "f boot-before.stderr.log",
      "f sample.root.Image",
      "f sample.root.Image.partial",
      "f root.tar.zst.gpg",
      "f root.tar.zst.gpg.partial",
      "f upload-journal.json",
      "f recovery-index.json",
      "f recovery-index.json.gpg",
      "f recovery-index.json.gpg.partial",
      "f recovery-index-receipt.json",
      "f recovery-index-state.json",
      "f index-recipient.asc",
      `f .upload-journal.json.${crypto.randomUUID()}.tmp`,
      "d gpg-public-home",
      "d index-public-home",
    ];
    const normalGpg = [
      "f pubring.kbx",
      "f pubring.kbx.lock",
      "f pubring.gpg",
      "f pubring.gpg.lock",
      "f trustdb.gpg",
      "f trustdb.gpg.lock",
      "f gpg.conf",
      "f common.conf",
      "f random_seed",
      "s S.gpg-agent",
      "s S.gpg-agent.extra",
      "f S.gpg-agent.lock",
      "f S.gpg-agent.bak",
      "d private-keys-v1.d",
    ];
    // A completely normal generation directory is accepted and removed.
    const accepted = await run(normalGen, normalGpg);
    assert(
      accepted.code === 0,
      `normal records must be accepted: ${accepted.stdout}${accepted.stderr}`,
    );
    assert(accepted.stdout.includes("CLEANUP_OK"), accepted.stdout);
    assert(
      accepted.rmLog.includes(fixture.generation),
      "the exact generation directory is the removal target",
    );
    assert(
      accepted.rmLog.split("\n").filter((line) => line !== "").length === 1,
      "only the one generation directory may be removed",
    );
    // Foreign plain, whitespace, newline and symlink names must each fail
    // the parser BEFORE any removal.
    const foreign = await run(
      ["f root.tar.zst.gpg", "f foreign.txt"],
      normalGpg,
    );
    assert(
      foreign.code === 9,
      `foreign.txt must be rejected: ${foreign.stdout}`,
    );
    assert(foreign.stdout.includes("UNEXPECTED_FILE"));
    assert(foreign.stdout.includes("foreign.txt"));
    assert(foreign.rmLog === "", "no removal after a foreign rejection");
    const spaced = await run(
      ["f root.tar.zst.gpg", "f evil name with spaces.txt"],
      normalGpg,
    );
    assert(
      spaced.code === 9 &&
        spaced.stdout.includes("evil name with spaces.txt"),
      `a whitespace-containing foreign name must be rejected whole: ${spaced.stdout}`,
    );
    assert(spaced.rmLog === "");
    const newlined = await run(
      ["f root.tar.zst.gpg", "f evil\nnewline.txt"],
      normalGpg,
    );
    assert(
      newlined.code === 9 && newlined.stdout.includes("UNEXPECTED_FILE") &&
        newlined.stdout.includes("evil\nnewline.txt"),
      `a newline-containing foreign name must be rejected whole: ${newlined.stdout}`,
    );
    assert(newlined.rmLog === "");
    const symlinked = await run(
      ["f root.tar.zst.gpg", "l sneaky-link"],
      normalGpg,
    );
    assert(
      symlinked.code === 9 &&
        symlinked.stdout.includes("UNEXPECTED_SYMLINK") &&
        symlinked.stdout.includes("sneaky-link"),
      symlinked.stdout,
    );
    assert(symlinked.rmLog === "");
    // The public-home loop uses the same NUL parser: a foreign gpg file
    // inside gpg-public-home is rejected too.
    const gpgForeign = await run(
      ["f root.tar.zst.gpg", "d gpg-public-home", "d index-public-home"],
      ["f pubring.kbx", "f secret.key"],
    );
    assert(
      gpgForeign.code === 9 &&
        gpgForeign.stdout.includes("UNEXPECTED_GPG_FILE") &&
        gpgForeign.stdout.includes("secret.key"),
      gpgForeign.stdout,
    );
    assert(gpgForeign.rmLog === "");
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("source config: the public exclusions read accepts 0644 while credentials stay strict", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log(
      "source config permissions: skipped without write/run permissions",
    );
    return;
  }
  const dir = await Deno.makeTempDir({ prefix: "m09-source-config-" });
  const previous = Deno.cwd();
  try {
    await Deno.mkdir(`${dir}/config`, { recursive: true });
    await Deno.mkdir(`${dir}/.private`, { recursive: true });
    await Deno.writeTextFile(`${dir}/config/restic-excludes.txt`, "/tmp\n");
    await Deno.chmod(`${dir}/config/restic-excludes.txt`, 0o644);
    const oversized = "/".repeat(64 * 1024 + 1);
    await Deno.writeTextFile(`${dir}/config/oversized.txt`, oversized);
    await Deno.chmod(`${dir}/config/oversized.txt`, 0o644);
    await Deno.writeTextFile(`${dir}/config/group-writable.txt`, "/tmp\n");
    await Deno.chmod(`${dir}/config/group-writable.txt`, 0o664);
    await Deno.writeTextFile(`${dir}/config/target.txt`, "/target\n");
    await Deno.writeTextFile(`${dir}/.private/cred.txt`, "s3cret");
    await Deno.chmod(`${dir}/.private/cred.txt`, 0o644);
    Deno.chdir(dir);
    const seam = realPrivateSeam();
    const exclusions = await seam.readText(
      "config/restic-excludes.txt",
      64 * 1024,
    );
    assert(
      exclusions === "/tmp\n",
      `a 0644 public exclusions file must read: ${exclusions}`,
    );
    let threw = false;
    try {
      await seam.readBytes("config/restic-excludes.txt", 64 * 1024);
    } catch {
      threw = true;
    }
    assert(
      threw,
      "the strict private readBytes path still rejects the 0644 exclusions",
    );
    threw = false;
    try {
      await seam.readText(".private/cred.txt", 64 * 1024);
    } catch {
      threw = true;
    }
    assert(threw, "0644 credentials must stay rejected by the strict path");
    threw = false;
    try {
      await seam.readText("config/oversized.txt", 64 * 1024);
    } catch {
      threw = true;
    }
    assert(threw, "an oversized public exclusions file must stay bounded");
    threw = false;
    try {
      await seam.readText("config/group-writable.txt", 64 * 1024);
    } catch {
      threw = true;
    }
    assert(threw, "group/world-writable public exclusions must be rejected");
    await Deno.remove("config/restic-excludes.txt");
    await Deno.symlink("target.txt", "config/restic-excludes.txt");
    threw = false;
    try {
      await seam.readText("config/restic-excludes.txt", 64 * 1024);
    } catch {
      threw = true;
    }
    assert(threw, "a symlinked public exclusions file must be rejected");
  } finally {
    Deno.chdir(previous);
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("service: permission flags grant the controller reads and host validation stays in B2Store", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("service permission: skipped without write/run permissions");
    return;
  }
  const dir = await Deno.makeTempDir({ prefix: "m09-service-" });
  try {
    await Deno.mkdir(`${dir}/.private`, { recursive: true });
    await Deno.mkdir(`${dir}/config`, { recursive: true });
    await Deno.writeTextFile(`${dir}/.private/f.json`, "secret");
    await Deno.writeTextFile(`${dir}/config/restic-excludes.txt`, "/tmp\n");
    const probe = [
      'await Deno.realPath(".");',
      'await Deno.readTextFile("config/restic-excludes.txt");',
      'await Deno.readTextFile(".private/f.json");',
      'await Deno.writeTextFile(".private/out.json", "{\\"ok\\":true}");',
      'console.log("PROBE_OK");',
    ].join("\n");
    await Deno.writeTextFile(`${dir}/probe.ts`, probe);
    const run = async (flags: string[]): Promise<
      Deno.CommandStatus & {
        stdout: string;
        stderr: string;
      }
    > => {
      const child = new Deno.Command("deno", {
        args: ["run", ...flags, "probe.ts"],
        cwd: dir,
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const output = await child.output();
      return {
        ...(await child.status),
        stdout: new TextDecoder().decode(output.stdout),
        stderr: new TextDecoder().decode(output.stderr),
      };
    };
    const oldFlags = [
      "--allow-read=.private",
      "--allow-write=.private",
      "--allow-run",
      "--allow-net=api.backblazeb2.com,backblazeb2.com,backblaze.com",
    ];
    const oldResult = await run(oldFlags);
    assert(oldResult.code !== 0, "old flags must deny the controller reads");
    const newFlags = [
      "--allow-read=.,.private",
      "--allow-write=.private",
      "--allow-run",
      "--allow-net",
    ];
    const newResult = await run(newFlags);
    assert(
      newResult.code === 0,
      `new flags must grant the controller reads: ${newResult.stderr}`,
    );
    const service = await Deno.readTextFile(
      "config/backblaze-file-backup.service",
    );
    assert(service.includes("--allow-read=.,.private"));
    assert(service.includes("--allow-net "), service);
    assert(!/scp|rsync|git clone|curl |wget /.test(service), service);
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Final review regressions: verifier headroom, run-loop lifetime, expired
// WORKER_TERMINAL launch prevention and prune inventory retries
// ---------------------------------------------------------------------------

Deno.test("verifier: headroom requirement derives from the validated index and fails closed on overflow", () => {
  const fixture = generationFixture(61, WINDOW_START);
  const total = fixture.upload.totalBytes;
  assert(total > 0, "fixture ciphertext total must be positive");
  assert(
    verifierCiphertextTotal(fixture.index) === total,
    "the index archive byte totals equal the upload ciphertext total",
  );
  // Another complete ciphertext copy + plaintext bound + scratch allowance
  // before reconstruction; after reconstruction only the remaining
  // plaintext/scratch requirement (the copy is already subtracted by df).
  assert(
    verifierHeadroomRequirement(fixture.index, false) === 3 * total,
    "before reconstruction three ciphertext-sized allowances are required",
  );
  assert(
    verifierHeadroomRequirement(fixture.index, true) === 2 * total,
    "after reconstruction the copy is not counted twice",
  );
  const overflow = {
    ...fixture.index,
    archives: [
      { ...fixture.index.archives[0], bytes: Number.MAX_SAFE_INTEGER },
      { ...fixture.index.archives[1], bytes: 2 },
    ],
  };
  let threw = false;
  try {
    verifierCiphertextTotal(overflow);
  } catch {
    threw = true;
  }
  assert(threw, "overflowing ciphertext totals must fail closed");
  const nonPositive = {
    ...fixture.index,
    archives: [{ ...fixture.index.archives[0], bytes: 0 }],
  };
  threw = false;
  try {
    verifierCiphertextTotal(nonPositive);
  } catch {
    threw = true;
  }
  assert(threw, "non-positive archive byte totals must fail closed");
});

Deno.test("verifier: the real df availability read is strict and the capacity gate keeps the 5 GiB + 512 MiB reserve", async () => {
  if (!(await fsPermissionsGranted())) {
    console.log("verifier headroom: skipped without write/run permissions");
    return;
  }
  const dir = await Deno.makeTempDir({ prefix: "m09-verifier-headroom-" });
  try {
    const recoveryDir = `${dir}/recovery`;
    const verificationDir = `${dir}/verification`;
    await Deno.mkdir(recoveryDir);
    await Deno.mkdir(verificationDir);
    const dfPath = `${dir}/df`;
    const writeDf = async (body: string, exitCode?: number): Promise<void> => {
      const lines = body.split("\n").map((line) => `printf '%s\\n' ${line}`)
        .join("\n");
      await Deno.writeTextFile(
        dfPath,
        `#!/bin/sh\n${lines}\n${
          exitCode === undefined ? "" : `exit ${exitCode}\n`
        }`,
      );
      await Deno.chmod(dfPath, 0o755);
    };
    const previousPath = Deno.env.get("PATH") ?? "";
    try {
      Deno.env.set("PATH", `${dir}:${previousPath}`);
      await writeDf("Avail\n123456789", 0);
      assert(
        await readVerifierAvailBytes(recoveryDir) === 123456789,
        "the GNU df avail column parses to bytes",
      );
      await writeDf("Avail\n0", 0);
      let threw = false;
      try {
        await readVerifierAvailBytes(recoveryDir);
      } catch {
        threw = true;
      }
      assert(threw, "a zero avail value must fail closed");
      await writeDf("Avail\nnot-a-number", 0);
      threw = false;
      try {
        await readVerifierAvailBytes(recoveryDir);
      } catch {
        threw = true;
      }
      assert(threw, "a non-numeric avail value must fail closed");
      await writeDf("Avail\n10\n20", 0);
      threw = false;
      try {
        await readVerifierAvailBytes(recoveryDir);
      } catch {
        threw = true;
      }
      assert(threw, "multiple filesystem rows must fail closed");
      await writeDf("Avail\n5", 3);
      threw = false;
      try {
        await readVerifierAvailBytes(recoveryDir);
      } catch {
        threw = true;
      }
      assert(threw, "a failing df must fail closed");
      const fixture = generationFixture(62, WINDOW_START);
      const requirement = verifierHeadroomRequirement(fixture.index, false);
      const reserve = 5 * 1024 ** 3 + 512 * 1024 ** 2;
      await writeDf(`Avail\n${requirement + reserve - 1}`, 0);
      threw = false;
      try {
        await assertVerifierHeadroom(
          recoveryDir,
          verificationDir,
          requirement,
        );
      } catch {
        threw = true;
      }
      assert(threw, "one byte below the requirement plus reserve must reject");
      await writeDf(`Avail\n${requirement + reserve + 1}`, 0);
      await assertVerifierHeadroom(recoveryDir, verificationDir, requirement);
    } finally {
      Deno.env.set("PATH", previousPath);
    }
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("orchestration: an expired WORKER_TERMINAL launches no verifier and reuses the deadline orphan", async () => {
  const fixture = generationFixture(63, WINDOW_START);
  const state = stateWithJob(fixture, "WORKER_TERMINAL", {
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    resultSha256: "77".repeat(32),
  });
  const expired = () =>
    new Date(Date.parse(fixture.request.deadlineAtUtc) + 1000);

  // No existing gate: the expiry orphans the job without any verifier gate,
  // tunnel or launch (no RuntimeMaxSec workaround either).
  const h = harness({ now: expired() });
  const next = await stepBackupController(state, h.deps, h.deps.now());
  assert(next.job!.phase === "FAILED", `phase=${next.job!.phase}`);
  assert(
    next.job!.failure!.code === "ORPHANED_SOURCE_UNREACHABLE_AT_DEADLINE",
    `code=${next.job!.failure!.code}`,
  );
  assert(h.launches.length === 0, "expired work is never launched");
  assert(h.tunnels.length === 0, "expired work never opens a tunnel");
  assert(!h.events.includes("gate:create"), "expired work creates no gate");
  assert(h.gate.value === null, "no gate is invented for expired work");

  // A matching existing verifier gate is orphaned, never cleared without
  // proof, and never launched through.
  const matching = harness({
    now: expired(),
    gateValue: deriveVerifierGate(
      fixture.request,
      fixture.requestSha256,
    ),
  });
  const orphaned = await stepBackupController(
    state,
    matching.deps,
    matching.deps.now(),
  );
  assert(orphaned.job!.phase === "FAILED");
  assert(
    matching.gate.value !== null &&
      (matching.gate.value.state as string) === "orphaned",
    "the exact matching gate is orphaned",
  );
  assert(
    matching.gate.orphaned.includes("SOURCE_UNREACHABLE_AT_DEADLINE"),
    matching.gate.orphaned.join(","),
  );
  assert(!matching.events.includes("gate:clear"));
  assert(matching.launches.length === 0);
  assert(matching.tunnels.length === 0);

  // A foreign gate is never touched: the step fails closed and the gate
  // stays active.
  const foreign = harness({
    now: expired(),
    gateValue: {
      ...deriveVerifierGate(fixture.request, fixture.requestSha256),
      jobId: "job-ffffffff-ffff-ffff-ffff-ffffffffffff",
    },
  });
  let threw = false;
  try {
    await stepBackupController(state, foreign.deps, foreign.deps.now());
  } catch {
    threw = true;
  }
  assert(threw, "a foreign gate at expiry must fail closed");
  assert(
    foreign.gate.value !== null &&
      (foreign.gate.value.state as string) === "active",
    "a foreign gate is never cleared or orphaned",
  );
  assert(!foreign.events.includes("gate:clear"));
});

Deno.test("cycle: the default step budget follows the request deadline past 400 polls and keeps the tunnel", async () => {
  const fixture = generationFixture(64, WINDOW_START);
  const receiptText = JSON.stringify(fixture.receipt);
  const receiptSha256 = sha256HexSync(new TextEncoder().encode(receiptText));
  const accepted = verifierAcceptedStatus(
    fixture,
    INVOCATION_B,
    receiptSha256,
  );
  const { receiptSha256: _receipt, ...acceptedBase } = accepted;
  const verifying = {
    ...acceptedBase,
    state: "VERIFYING",
    finishedAtUtc: null,
  };
  const runningProps = new Map<string, string>([
    ["LoadState", "loaded"],
    ["ActiveState", "active"],
    ["SubState", "running"],
    ["Result", "success"],
    ["MainPID", "123"],
    ["ControlPID", "0"],
    ["InvocationID", INVOCATION_B],
  ]);
  const state = stateWithJob(fixture, "VERIFIER_RUNNING", {
    workerInvocationId: INVOCATION_A,
    workerStatus: workerPendingStatus(fixture, INVOCATION_A),
    verifierInvocationId: INVOCATION_B,
    verifierStatus: verifying,
  });
  let verifierPolls = 0;
  const h = harness({
    // Beyond the old 400 * 30s default (200 min) but before the 6 h
    // immutable deadline: the default lifetime must keep polling.
    now: new Date(WINDOW_START + 3.5 * 3_600_000),
    gateValue: {
      ...deriveVerifierGate(fixture.request, fixture.requestSha256),
      unitInvocationId: INVOCATION_B,
    },
    versions: inventoryFor([fixture]),
    observed: (unitName) => {
      if (!unitName.startsWith("arch-vps-b2-verify-")) {
        throw new Error(`unexpected observed unit ${unitName}`);
      }
      verifierPolls += 1;
      if (verifierPolls > 406) return terminalObserved(accepted);
      return {
        props: runningProps,
        status: verifying,
        lockFree: false,
        reachable: true,
      };
    },
    rootResponder: (script) =>
      script.includes("receipt.json")
        ? { code: 0, stdout: receiptText, stderr: "" }
        : undefined,
    seedPrivate: (map) => {
      map.set(
        `${PIP_JOB_EVIDENCE_PATH}/${fixture.jobId}/result.json`,
        new TextEncoder().encode(JSON.stringify(fixture.workerResult)),
      );
    },
  });
  await h.deps.private.write(CONTROLLER_STATE_PATH, state);
  const report = await runBackblazeCycle(h.deps);
  assert(
    report.status.startsWith("B2_BACKUP_COMPLETE"),
    `status=${report.status}`,
  );
  assert(
    verifierPolls > 406,
    `the loop polled beyond the old 400-step cap (polls=${verifierPolls})`,
  );
  assert(
    h.tunnelCloses() === 1,
    `the tunnel closes exactly once at the end (closes=${h.tunnelCloses()})`,
  );
  assert(h.tunnels.length === 1, "one decrypt tunnel for the whole run");
});

Deno.test("cycle: an explicit small step budget still bounds the run before the deadline", async () => {
  const fixture = generationFixture(65, WINDOW_START);
  const {
    receiptSha256: _receipt,
    ...acceptedBase
  } = verifierAcceptedStatus(fixture, INVOCATION_B, "aa".repeat(32));
  const verifying = {
    ...acceptedBase,
    state: "VERIFYING",
    finishedAtUtc: null,
  };
  const state = stateWithJob(fixture, "VERIFIER_RUNNING", {
    verifierInvocationId: INVOCATION_B,
    verifierStatus: verifying,
  });
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    gateValue: {
      ...deriveVerifierGate(fixture.request, fixture.requestSha256),
      unitInvocationId: INVOCATION_B,
    },
  });
  await h.deps.private.write(CONTROLLER_STATE_PATH, state);
  const report = await runBackblazeCycle(h.deps, 3);
  assert(report.status.startsWith("B2_BACKUP_INCOMPLETE"), report.status);
  assert(
    report.detail === "Step budget exhausted",
    `detail=${report.detail}`,
  );
  assert(!report.status.includes("FAILED"));
});

Deno.test("cycle: the default run stays bounded at the request deadline with a persistently retrying job", async () => {
  const fixture = generationFixture(66, WINDOW_START);
  const state = validateControllerState({
    schemaVersion: 1,
    catalog: [catalogEntry(fixture, WINDOW_START + 1000)],
    job: {
      ...stateWithJob(fixture, "ACCEPTED", {
        workerStatus: workerPendingStatus(fixture, INVOCATION_A),
        verifierStatus: verifierAcceptedStatus(
          fixture,
          INVOCATION_B,
          "aa".repeat(32),
        ),
        resultSha256: "77".repeat(32),
      }).job!,
    },
  });
  let versionsCalls = 0;
  const h = harness({
    now: new Date(Date.parse(fixture.request.deadlineAtUtc) + 1000),
  });
  h.store.versions = () => {
    versionsCalls += 1;
    return Promise.reject(new Error("inventory transport down"));
  };
  await h.deps.private.write(CONTROLLER_STATE_PATH, state);
  const report = await runBackblazeCycle(h.deps);
  assert(report.status.startsWith("B2_BACKUP_INCOMPLETE"), report.status);
  assert(
    report.detail === "Request deadline reached",
    `detail=${report.detail}`,
  );
  assert(
    versionsCalls === 1,
    `one final expiry assessment only (calls=${versionsCalls})`,
  );
  const persisted = h.privateMap.get(CONTROLLER_STATE_PATH);
  const after = JSON.parse(
    persisted instanceof Uint8Array
      ? new TextDecoder().decode(persisted)
      : JSON.stringify(persisted),
  );
  assert(after.job.phase === "ACCEPTED", "no durable state is rewritten stale");
  assert(after.job.prune === undefined, "no invented prune plan");
  assert(after.catalog.length === 1, "the catalog is preserved");
});

Deno.test("orchestration: transient inventory failures before planning and after deletion stay resumable", async () => {
  const fixtures = [1, 2, 3, 4, 5, 6].map((seed) =>
    generationFixture(seed, WINDOW_START + seed * 3_600_000)
  );
  const catalog = fixtures.map((fixture, i) =>
    catalogEntry(fixture, WINDOW_START + i * 1000)
  );
  const current = fixtures[5];
  const state = validateControllerState({
    schemaVersion: 1,
    catalog,
    job: {
      ...stateWithJob(current, "ACCEPTED").job!,
      workerStatus: workerPendingStatus(current, INVOCATION_A),
      resultSha256: "77".repeat(32),
    },
  });
  const inventory = inventoryFor(fixtures);
  const pending = generationFixture(7, WINDOW_START + 7 * 3_600_000);
  inventory.push(...inventoryFor([pending]));
  inventory.push({
    fileId: "foreign000000000000",
    fileName: "restic/direct-v1/other/generation-11111/role/00000000",
    contentLength: 10,
    contentSha1: "11".repeat(20),
    action: "upload",
    uploadTimestamp: 1,
  });
  inventory.push({
    fileId: "start0000000000000",
    fileName: `${generationPrefixes(fixtures[1].generation)[0]}root/00000000`,
    contentLength: 1,
    contentSha1: "11".repeat(20),
    action: "start",
    uploadTimestamp: 1,
  });
  inventory.push({
    fileId: "hide00000000000000",
    fileName: `${generationPrefixes(fixtures[0].generation)[0]}root/00000000`,
    contentLength: 0,
    contentSha1: "11".repeat(20),
    action: "hide",
    uploadTimestamp: 1,
  });
  const expectedIds = new Set(
    inventoryFor([fixtures[0], fixtures[1]]).map((object) => object.fileId),
  );
  expectedIds.add("hide00000000000000");
  const h = harness({
    now: new Date(WINDOW_START + 60_000),
    versions: inventory,
  });
  const originalVersions = h.store.versions.bind(h.store) as () => Promise<
    B2Object[]
  >;
  let versionsCalls = 0;
  h.store.versions = async () => {
    versionsCalls += 1;
    // First call: before any prune plan exists. Fifth call: the post-delete
    // refresh after the partial deletions ran. Both must stay resumable.
    if (versionsCalls === 1 || versionsCalls === 5) {
      throw new Error("inventory transport down");
    }
    return await originalVersions();
  };
  const originalRemove = h.store.remove.bind(h.store) as (
    object: B2Object,
  ) => Promise<void>;
  let removeFailedOnce = false;
  h.store.remove = async (object) => {
    if (!removeFailedOnce) {
      removeFailedOnce = true;
      throw new Error("remove failed: 500 transient");
    }
    return await originalRemove(object);
  };
  let final = state;
  const phaseOf = (value: ControllerState): ControllerPhase => value.job!.phase;
  // Inventory failure before any plan: ACCEPTED and the pending plan
  // allocation are preserved; no empty completed plan drops membership.
  final = await stepBackupController(final, h.deps, h.deps.now());
  assert(phaseOf(final) === "ACCEPTED", `phase=${phaseOf(final)}`);
  assert(final.job!.prune === undefined, "no invented empty plan");
  assert(final.job!.failure === undefined, "no terminal FAILED");
  assert(final.catalog.length === 6, "the catalog is preserved");
  // Fresh inventory allocates the exact plan.
  final = await stepBackupController(final, h.deps, h.deps.now());
  assert(phaseOf(final) === "PRUNING", `phase=${phaseOf(final)}`);
  const planIds = final.job!.prune!.plan.flatMap((entry) => entry.fileIds);
  assert(planIds.length === expectedIds.size);
  assert(
    planIds.every((id) => expectedIds.has(id)),
    "the plan holds every eligible id",
  );
  // A removal failure leaves partial deletion: PRUNING and every planned id
  // survive with bounded remove evidence (the existing resumability).
  final = await stepBackupController(final, h.deps, h.deps.now());
  assert(phaseOf(final) === "PRUNING", `phase=${phaseOf(final)}`);
  assert(final.job!.prune!.failedAtUtc !== undefined);
  assert(final.job!.failure === undefined, "no terminal FAILED");
  assert(h.store.removed.length === 0, "the throwing removal deleted nothing");
  // The post-delete refresh then fails too: PRUNING, every planned id and
  // the catalog survive with bounded refresh evidence.
  final = await stepBackupController(final, h.deps, h.deps.now());
  assert(phaseOf(final) === "PRUNING", `phase=${phaseOf(final)}`);
  assert(final.job!.prune!.failedAtUtc !== undefined);
  assert(final.job!.failure === undefined, "no terminal FAILED");
  assert(final.catalog.length === 6, "catalog membership survives");
  assert(
    JSON.stringify(final.job!.prune!.plan.map((entry) => entry.generation)) ===
      JSON.stringify([fixtures[0].generation, fixtures[1].generation]),
    "the existing plan and its IDs are preserved",
  );
  assert(
    final.job!.prune!.plan.flatMap((entry) => entry.fileIds).every((id) =>
      expectedIds.has(id)
    ),
    "no planned id is dropped or replaced",
  );
  assert(
    (final.job!.prune!.evidence ?? "").length <= 300,
    "failure evidence is bounded",
  );
  assert(
    final.job!.prune!.evidence!.includes("refresh inventory failed"),
    final.job!.prune!.evidence,
  );
  assert(h.store.removed.length === expectedIds.size, "deletions ran");
  // Subsequent normal polls re-inventory fresh, prove the absent IDs and
  // complete; newest four, pending, foreign and start data stay intact.
  for (let step = 0; step < 12; step += 1) {
    final = await stepBackupController(final, h.deps, h.deps.now());
    const phase = phaseOf(final);
    if (phase === "COMPLETE" || phase === "FAILED") break;
  }
  assert(phaseOf(final) === "COMPLETE", `phase=${phaseOf(final)}`);
  assert(final.catalog.length === 4, "catalog shrinks to the newest four");
  const removedIds = new Set(h.store.removed.map((object) => object.fileId));
  assert(
    removedIds.size === expectedIds.size,
    "every still-present planned id was removed exactly once",
  );
  for (const id of expectedIds) {
    assert(removedIds.has(id), `planned id ${id} must be removed`);
  }
  const surviving = new Set(
    h.store.versionsList.map((object) => object.fileId),
  );
  for (const fixture of fixtures.slice(2)) {
    for (const object of inventoryFor([fixture])) {
      assert(surviving.has(object.fileId), "newest data must survive");
    }
  }
  for (const object of inventoryFor([pending])) {
    assert(surviving.has(object.fileId), "pending data must survive");
  }
  assert(surviving.has("foreign000000000000"), "foreign data must survive");
  assert(surviving.has("start0000000000000"), "start markers must survive");
});
