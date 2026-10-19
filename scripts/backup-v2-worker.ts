/** V2 source adapters. These never rewrite a v1 envelope or accept a catalog
 * entry; the independent controller owns acceptance and terminal custody. */
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { lstat, statfs } from "node:fs/promises";
import {
  type CaptureSettings,
  gpgArgs,
  prepareRecipient,
  recordToolVersions,
  validateCaptureSettings,
} from "./backblaze-capture.ts";
import { type B2Settings, validateB2Settings } from "./backblaze-storage.ts";
import {
  type BackupV2CaptureContext,
  type BackupV2CapturedRole,
  type BackupV2CaptureProgress,
  captureBackupV2Generation,
  createBackupV2RoleProducer,
} from "./backup-v2-capture.ts";
import {
  BACKUP_V2_ROLES,
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  type BackupV2Progress,
  type BackupV2PutIntent,
  type BackupV2Receipt,
  type BackupV2RoleManifest,
  type BackupV2TransferEpisode,
  backupV2TransferWindowMs,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2Receipt,
  validateBackupV2RoleManifest,
  validateBackupV2Root,
} from "./backup-v2-contract.ts";
import { BackupV2DocumentPublisher } from "./backup-v2-index.ts";
import { backupV2SourceConfigSha256 } from "./backup-v2-metadata.ts";
import type { BackupV2ReusedRole } from "./backup-v2-metadata.ts";
import {
  type BackupV2ReaderCapabilities,
  type BackupV2RootVerification,
  createBackupV2Reader,
  verifyBackupV2Root,
} from "./backup-v2-recovery.ts";
import {
  type BackupV2Execution,
  type BackupV2Gate,
  type BackupV2RequestEnvelope,
  type BackupV2Result,
  type BackupV2SelectedRoot,
  type BackupV2Status,
  validateBackupV2Gate,
  validateBackupV2RequestEnvelope,
  validateBackupV2Result,
} from "./backup-v2-runtime-contract.ts";
import type { BackupV2UploadIdentity } from "./backup-v2-upload.ts";
import type { BackupV2UploadRetryEpisode } from "./backup-v2-upload.ts";
import {
  BackupV2UploadJournal,
  createBackupV2UploadPacer,
  openBackupV2UploadJournal,
} from "./backup-v2-upload.ts";
import {
  assertBackupV2Directory,
  BackupV2Spool,
  createBackupV2FileSpoolStorage,
} from "./backup-v2-spool.ts";
import {
  BACKUP_V2_LIMITS,
  BACKUP_V2_PRODUCTION_WRITER_MARGIN_BYTES,
} from "./backup-v2-profile.ts";
import {
  BackupV2Store,
  BackupV2TransportError,
  createCurlBackupV2Wire,
} from "./backup-v2-store.ts";
import { createBackupV2FileObjectReader } from "./backup-v2-recovery.ts";
import {
  type BackupV2CapacityObservation,
  backupV2FailureEvidence,
  BackupV2Supervisor,
  type BackupV2SupervisorFailure,
  type BackupV2SupervisorObservation,
  createBackupV2Notifier,
} from "./backup-v2-supervisor.ts";
import {
  BACKUP_V2_RUNTIME_LEASE_BYTES,
  openBackupV2RuntimeLease,
} from "./backup-v2-runtime-lease.ts";
import {
  assertBackupV2StatusTransition,
  validateBackupV2Status,
} from "./backup-v2-runtime-contract.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_SOURCE_LOCK_PATH,
} from "./backblaze-controller-contract.ts";
import { withBackupLock } from "./backup-lock.ts";
import {
  BACKUP_V2_NATIVE_CUSTODY_FILE,
  backupV2NativeCustodyBytes,
  type BackupV2NativeCustodyRecord,
  parseBackupV2NativeCustody,
  validateBackupV2NativeCustodyRecord,
} from "./backup-v2-native-custody.ts";
import { createBackupV2MetadataRunner } from "./backup-v2-metadata.ts";
import { createBackupV2NativeProcessStarter } from "./backup-v2-native-process.ts";
import { spawnBackupV2GpgDecrypt } from "./backup-v2-decrypt.ts";
import {
  backupV2DeletedHandleBytes,
  type BackupV2KernelObservationOptions,
  observeBackupV2Kernel,
  readBackupV2KernelText,
} from "./backup-v2-kernel.ts";
import {
  BACKUP_V2_PROTECTION_SOURCE_BASE,
  type BackupV2ProtectionDescriptor,
  backupV2ProtectionPageName,
  backupV2ProtectionSourceDirectory,
  type BackupV2PruneInput,
  type BackupV2PruneResult,
  buildBackupV2Protection,
  validateBackupV2ProtectionDescriptor,
} from "./backup-v2-protection.ts";
import {
  BACKUP_BASE,
  backupV2ControlCacheDirectory,
  ensurePublicHome,
  JOBS_RUNTIME_ROOT,
  makeStreamDecryptArchive,
  PUBLIC_HOME_BASE,
  RELEASES_ROOT,
  validateCatalogEntry,
  validateReleaseManifest,
} from "./backblaze-file-backup.ts";
import { runBackupV2SourcePruner } from "./backup-v2-source-pruner.ts";
import {
  BACKUP_V2_PRUNE_TRANSACTIONS,
  createBackupV2PruneRuntime,
} from "./backup-v2-prune-runtime.ts";

export const BACKUP_V2_STATUS_FILE = "status.json";
export const BACKUP_V2_RESULT_FILE = "result.json";
export const BACKUP_V2_CHECKPOINT_FILE = "sealed-roles.json";
export const BACKUP_V2_GATE_FILE = "gate.json";
export { backupV2ControlCacheDirectory };
const encoder = new TextEncoder();
export const backupV2ArtifactBytes = (value: unknown) =>
  encoder.encode(JSON.stringify(value) + "\n");
export const backupV2ArtifactSha256 = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
function fail(): never {
  throw new Error("Backup v2 worker input or custody invalid");
}
function same(a: unknown, b: unknown): void {
  if (!isDeepStrictEqual(a, b)) fail();
}

export interface BackupV2WorkerSettings {
  schemaVersion: 2;
  format: "backup-v2";
  envelope: BackupV2RequestEnvelope;
  captureSettings: CaptureSettings;
  B2Settings: B2Settings;
  workerGate: BackupV2Gate;
  verifierGate: BackupV2Gate;
  publicationAttemptId: string;
}
export function validateBackupV2WorkerSettings(
  value: unknown,
): BackupV2WorkerSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  const fields = [
    "schemaVersion",
    "format",
    "envelope",
    "captureSettings",
    "B2Settings",
    "workerGate",
    "verifierGate",
    "publicationAttemptId",
  ];
  if (
    Object.keys(r).length !== fields.length ||
    fields.some((key) => !Object.hasOwn(r, key)) || r.schemaVersion !== 2 ||
    r.format !== "backup-v2"
  ) fail();
  const envelope = validateBackupV2RequestEnvelope(r.envelope),
    workerGate = validateBackupV2Gate(r.workerGate),
    verifierGate = validateBackupV2Gate(r.verifierGate);
  const captureSettings = structuredClone(r.captureSettings) as CaptureSettings;
  validateCaptureSettings(captureSettings);
  validateB2Settings(r.B2Settings as B2Settings);
  for (const gate of [workerGate, verifierGate]) same(gate.envelope, envelope);
  if (
    workerGate.kind !== "worker" || verifierGate.kind !== "verify" ||
    workerGate.gateId === verifierGate.gateId ||
    workerGate.sourceBootId !== verifierGate.sourceBootId ||
    captureSettings.generation !== envelope.request.captureId ||
    captureSettings.recipientSha256 !== envelope.request.recipientSha256 ||
    captureSettings.recipientFingerprint !==
      envelope.request.recipientFingerprint ||
    backupV2SourceConfigSha256(captureSettings) !==
      envelope.request.sourceConfigSha256 ||
    typeof r.publicationAttemptId !== "string" ||
    !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(
      r.publicationAttemptId,
    )
  ) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope,
    captureSettings,
    B2Settings: structuredClone(r.B2Settings) as B2Settings,
    workerGate,
    verifierGate,
    publicationAttemptId: r.publicationAttemptId,
  };
}
export interface BackupV2SealedRoleCheckpoint {
  capture: BackupV2CapturedRole;
  manifest: BackupV2RoleManifest;
  reference: BackupV2ManifestRef;
  /** M05 owns/validates the bounded original-role recovery snapshot. */
  recovery: unknown;
}
export interface BackupV2CaptureWorkerDependencies {
  context: BackupV2CaptureContext;
  publisher(identity: BackupV2UploadIdentity): BackupV2DocumentPublisher;
  checkpoint(value: BackupV2SealedRoleCheckpoint): Promise<void>;
  progress(
    value: BackupV2CaptureProgress,
    active: BackupV2Status["activeRoleAttempt"],
  ): void | Promise<void>;
  capture?: typeof captureBackupV2Generation;
  reused?: readonly BackupV2SealedRoleCheckpoint[];
  now(): Date;
}
function execution(gate: BackupV2Gate): BackupV2Execution {
  if (gate.state !== "ACTIVE" || !gate.custody) fail();
  return {
    gateId: gate.gateId,
    sourceBootId: gate.sourceBootId,
    custody: gate.custody,
  };
}
function roleManifest(
  value: BackupV2CapturedRole,
  pages: BackupV2RoleManifest["pages"],
): BackupV2RoleManifest {
  return validateBackupV2RoleManifest({
    schemaVersion: 2,
    captureId: value.captureId,
    attemptId: value.attemptId,
    role: value.role,
    format: value.format,
    ciphertextBytes: value.ciphertextBytes,
    ciphertextSha256: value.ciphertextSha256,
    sourceConfigSha256: value.sourceConfigSha256,
    compatibilitySha256: value.compatibilitySha256,
    recipientSha256: value.recipientSha256,
    recipientFingerprint: value.recipientFingerprint,
    captureStartedAtUtc: value.captureStartedAtUtc,
    captureFinishedAtUtc: value.captureFinishedAtUtc,
    uploadStartedAtUtc: value.uploadStartedAtUtc,
    uploadFinishedAtUtc: value.uploadFinishedAtUtc,
    pages,
    inventory: value.inventory,
    producer: value.producer,
    metadata: [],
  });
}

/** Actual M05 -> M04 -> M02 capture and M06 publication. Test injection stays
 * at the component boundary; production callers use the fixed M05 default. */
export async function captureBackupV2Worker(
  settingsInput: BackupV2WorkerSettings,
  gateInput: BackupV2Gate,
  deps: BackupV2CaptureWorkerDependencies,
): Promise<BackupV2Result> {
  const settings = validateBackupV2WorkerSettings(settingsInput),
    gate = validateBackupV2Gate(gateInput);
  same(gate.envelope, settings.envelope);
  if (gate.kind !== "worker" || gate.gateId !== settings.workerGate.gateId) {
    fail();
  }
  const owned = execution(gate),
    sealed = new Map<
      BackupV2CapturedRole["role"],
      BackupV2SealedRoleCheckpoint
    >();
  for (const value of deps.reused ?? []) {
    const manifest = validateBackupV2RoleManifest(value.manifest),
      reference = validateBackupV2ManifestRef(value.reference);
    if (
      sealed.has(manifest.role) ||
      value.capture.captureId !== settings.envelope.request.captureId ||
      manifest.captureId !== value.capture.captureId ||
      manifest.role !== value.capture.role ||
      manifest.attemptId !== value.capture.attemptId ||
      manifest.sourceConfigSha256 !==
        settings.envelope.request.sourceConfigSha256 ||
      manifest.recipientSha256 !== settings.envelope.request.recipientSha256
    ) fail();
    same(manifest.captureStartedAtUtc, value.capture.captureStartedAtUtc);
    same(manifest.captureFinishedAtUtc, value.capture.captureFinishedAtUtc);
    sealed.set(manifest.role, { ...value, manifest, reference });
  }
  let active: BackupV2Status["activeRoleAttempt"] = null;
  const createProducer = deps.context.createProducer ??
    createBackupV2RoleProducer;
  const captured = await (deps.capture ?? captureBackupV2Generation)(
    settings.captureSettings,
    {
      ...deps.context,
      reusedRoles: [...sealed.values()].map((
        { capture, recovery },
      ) => ({ capture, recovery } as BackupV2ReusedRole)),
      createProducer(params) {
        active = { role: params.role, attemptId: params.attemptId };
        return createProducer(params);
      },
      progress: (value) => deps.progress(value, active),
      onRole: async (value, recovery?: unknown) => {
        active = { role: value.role, attemptId: value.attemptId };
        const publisher = deps.publisher({
          captureId: value.captureId,
          attemptId: value.attemptId,
          role: value.role,
          kind: "manifest",
        });
        const manifest = roleManifest(
          value,
          await publisher.publishChunkPages(value.chunks),
        );
        const reference = await publisher.publishRole(manifest),
          checkpoint = { capture: value, manifest, reference, recovery };
        await deps.checkpoint(checkpoint);
        sealed.set(value.role, checkpoint);
      },
    },
  );
  if (
    sealed.size !== BACKUP_V2_ROLES.length ||
    captured.roles.length !== BACKUP_V2_ROLES.length
  ) fail();
  const publication = {
    captureId: settings.envelope.request.captureId,
    attemptId: settings.publicationAttemptId,
    role: "recovery" as const,
  };
  const metadataReference = await deps.publisher({
    ...publication,
    kind: "metadata",
  }).publishVerificationMetadata({
    schemaVersion: 2,
    format: "backup-v2-verification-metadata",
    captureId: settings.envelope.request.captureId,
    metadataSha256: captured.recovery.sha256,
    bootSamples: captured.recovery.bootSamples.map((sample) => ({
      role: sample.role,
      member: new TextDecoder("utf-8", { fatal: true }).decode(sample.member),
      bytes: sample.bytes,
      sha256: sample.sha256,
    })),
  });
  const request = settings.envelope.request;
  const root = validateBackupV2Root({
    schemaVersion: 2,
    format: "backup-v2",
    profile: request.profile,
    captureId: request.captureId,
    periodKey: request.periodKey,
    sourceRevision: request.sourceRevision,
    sourceConfigSha256: request.sourceConfigSha256,
    recipientSha256: request.recipientSha256,
    recipientFingerprint: request.recipientFingerprint,
    roles: BACKUP_V2_ROLES.map((role) => {
      const value = sealed.get(role)!;
      return {
        role,
        attemptId: value.capture.attemptId,
        manifest: value.reference,
        captureStartedAtUtc: value.capture.captureStartedAtUtc,
        captureFinishedAtUtc: value.capture.captureFinishedAtUtc,
      };
    }),
    metadata: [metadataReference.object],
  });
  const reference = await deps.publisher({ ...publication, kind: "manifest" })
    .publishRoot(root);
  return validateBackupV2Result({
    schemaVersion: 2,
    format: "backup-v2",
    envelope: settings.envelope,
    ...owned,
    finishedAtUtc: deps.now().toISOString(),
    selectedRoot: { reference, root },
  }, gate);
}

export interface BackupV2VerifiedResult extends BackupV2Execution {
  schemaVersion: 2;
  format: "backup-v2-verified";
  envelope: BackupV2RequestEnvelope;
  workerResultSha256: string;
  selectedRoot: BackupV2SelectedRoot;
  receipt: BackupV2Receipt;
  receiptReference: BackupV2ManifestRef;
  finishedAtUtc: string;
  nativeCustodySha256?: string;
  protectedGraph?: BackupV2ProtectionDescriptor;
}
export async function verifyBackupV2Worker(
  settingsInput: BackupV2WorkerSettings,
  gateInput: BackupV2Gate,
  workerResultInput: BackupV2Result,
  workerGateInput: BackupV2Gate,
  deps: {
    reader: BackupV2ReaderCapabilities;
    verification: BackupV2RootVerification;
    publisher: BackupV2DocumentPublisher;
    workerResultBytes: Uint8Array;
  },
): Promise<BackupV2VerifiedResult> {
  const settings = validateBackupV2WorkerSettings(settingsInput),
    gate = validateBackupV2Gate(gateInput);
  const workerGate = validateBackupV2Gate(workerGateInput),
    workerResult = validateBackupV2Result(workerResultInput, workerGate);
  same(gate.envelope, settings.envelope);
  same(workerResult.envelope, settings.envelope);
  if (
    gate.kind !== "verify" || gate.gateId !== settings.verifierGate.gateId ||
    workerGate.gateId !== settings.workerGate.gateId
  ) fail();
  same(
    JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(deps.workerResultBytes),
    ),
    workerResult,
  );
  const reader = await createBackupV2Reader(
    workerResult.selectedRoot.reference,
    deps.reader,
  );
  same(reader.root, workerResult.selectedRoot.root);
  const receipt = await verifyBackupV2Root(reader, deps.verification);
  const receiptReference = await deps.publisher.publishReceipt(receipt);
  return {
    schemaVersion: 2,
    format: "backup-v2-verified",
    envelope: settings.envelope,
    ...execution(gate),
    workerResultSha256: backupV2ArtifactSha256(deps.workerResultBytes),
    selectedRoot: workerResult.selectedRoot,
    receipt,
    receiptReference,
    finishedAtUtc: deps.verification.now().toISOString(),
  };
}

/** Kernel-bound controller parses this only together with its saved gate. */
export function validateBackupV2VerifiedResult(
  value: unknown,
  gate: BackupV2Gate,
  worker: BackupV2Result,
  workerResultSha256: string,
): BackupV2VerifiedResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>,
    fields = [
      "schemaVersion",
      "format",
      "envelope",
      "gateId",
      "sourceBootId",
      "custody",
      "workerResultSha256",
      "selectedRoot",
      "receipt",
      "receiptReference",
      "finishedAtUtc",
      ...(Object.hasOwn(value, "nativeCustodySha256")
        ? ["nativeCustodySha256"]
        : []),
      ...(Object.hasOwn(value, "protectedGraph") ? ["protectedGraph"] : []),
    ];
  if (
    Object.keys(r).length !== fields.length ||
    fields.some((key) => !Object.hasOwn(r, key)) || r.schemaVersion !== 2 ||
    r.format !== "backup-v2-verified" ||
    gate.kind !== "verify"
  ) fail();
  const checkedGate = validateBackupV2Gate(gate),
    receipt = validateBackupV2Receipt(r.receipt);
  same(r.envelope, checkedGate.envelope);
  same(r.selectedRoot, worker.selectedRoot);
  same(r.workerResultSha256, workerResultSha256);
  same(
    { gateId: r.gateId, sourceBootId: r.sourceBootId, custody: r.custody },
    execution(checkedGate),
  );
  same(receipt.root, worker.selectedRoot.reference);
  if (
    receipt.captureId !== checkedGate.envelope.request.captureId ||
    receipt.recipientSha256 !== checkedGate.envelope.request.recipientSha256 ||
    receipt.recipientFingerprint !==
      checkedGate.envelope.request.recipientFingerprint ||
    typeof r.finishedAtUtc !== "string" ||
    !Number.isFinite(Date.parse(r.finishedAtUtc)) ||
    r.finishedAtUtc < receipt.verifiedAtUtc
  ) fail();
  const receiptReference = validateBackupV2ManifestRef(r.receiptReference);
  const protectedGraph = Object.hasOwn(r, "protectedGraph")
    ? validateBackupV2ProtectionDescriptor(r.protectedGraph)
    : undefined;
  if (protectedGraph) same(protectedGraph.root, worker.selectedRoot.reference);
  if (
    Object.hasOwn(r, "nativeCustodySha256") &&
    (typeof r.nativeCustodySha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(r.nativeCustodySha256))
  ) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-verified",
    envelope: checkedGate.envelope,
    ...execution(checkedGate),
    workerResultSha256,
    selectedRoot: worker.selectedRoot,
    receipt,
    receiptReference,
    finishedAtUtc: r.finishedAtUtc,
    ...(Object.hasOwn(r, "nativeCustodySha256")
      ? { nativeCustodySha256: r.nativeCustodySha256 as string }
      : {}),
    ...(protectedGraph ? { protectedGraph } : {}),
  };
}

/** Cumulative counters originate in actual pipe/journal callbacks, never a
 * heartbeat or CPU sample. One instance belongs to one source invocation. */
export class BackupV2WorkerProgress {
  phase: BackupV2Progress["phase"] = "PREFLIGHT";
  activeRoleAttempt: BackupV2Status["activeRoleAttempt"] = null;
  readonly #values = {
    sourceBytes: 0,
    compressionInputBytes: 0,
    verifiedChunks: 0,
    decryptedBytes: 0,
    decodedBytes: 0,
    inventoryMembers: 0,
  };
  readonly #observed = new Map<string, number>();
  #advance(key: string, value: number): number {
    if (
      !Number.isSafeInteger(value) || value < (this.#observed.get(key) ?? 0)
    ) fail();
    const delta = value - (this.#observed.get(key) ?? 0);
    this.#observed.set(key, value);
    return delta;
  }
  capture(
    value: BackupV2CaptureProgress,
    active: BackupV2Status["activeRoleAttempt"],
  ): void {
    if (!active || active.role !== value.role) fail();
    this.phase = "CAPTURING_AND_UPLOADING";
    this.activeRoleAttempt = active;
    if (value.kind === "source") {
      const delta = this.#advance(`${active.attemptId}/source`, value.bytes);
      this.#values.sourceBytes += delta;
      this.#values.compressionInputBytes += delta;
    }
    if (value.kind === "inventory") {
      this.#values.inventoryMembers += this.#advance(
        `${active.attemptId}/members`,
        value.members,
      );
    }
    if (value.kind === "verified") {
      this.#advance(`${active.attemptId}/verified`, value.bytes);
      this.#values.verifiedChunks++;
    }
  }
  verification(
    value: { role: string; pass: number; kind: string; bytes: number },
  ): void {
    this.phase = "VERIFYING";
    const delta = this.#advance(
      `${value.role}/${value.pass}/${value.kind}`,
      value.bytes,
    );
    if (value.kind === "compressedPlaintext") {
      this.#values.decryptedBytes += delta;
    }
    if (value.kind === "decoded") {
      this.#values.decodedBytes += delta;
    }
  }
  verifiedObject(): void {
    this.#values.verifiedChunks++;
  }
  retention(inventoryMembers: number): void {
    this.phase = "PRUNING";
    this.#values.inventoryMembers += this.#advance(
      "retention",
      inventoryMembers,
    );
  }
  snapshot(observedMonotonicMs: number): BackupV2Progress {
    return { phase: this.phase, observedMonotonicMs, ...this.#values };
  }
}

export function backupV2GateDirectory(gateInput: BackupV2Gate): string {
  const gate = validateBackupV2Gate(gateInput);
  if (!gate.custody) fail();
  return `${BACKUP_BASE}/${gate.envelope.request.captureId}/v2-${gate.gateId}/${gate.custody.invocationId}`;
}
/** Bounded public control discovery on the VPS. No B2 settings or recipient
 * contents are read; old invocation artifacts remain intact for attribution. */
export async function discoverBackupV2SourceGates(): Promise<BackupV2Gate[]> {
  const gates: BackupV2Gate[] = [];
  let entries = 0;
  try {
    for await (const generation of Deno.readDir(BACKUP_BASE)) {
      if (++entries > BACKUP_V2_LIMITS.logicalObjects) fail();
      if (
        !generation.isDirectory ||
        !/^generation-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(
          generation.name,
        )
      ) continue;
      const base = `${BACKUP_BASE}/${generation.name}`;
      await assertBackupV2Directory(base);
      for await (const phase of Deno.readDir(base)) {
        if (
          !phase.isDirectory ||
          !/^v2-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(phase.name)
        ) continue;
        const parent = `${base}/${phase.name}`;
        await assertBackupV2Directory(parent);
        for await (const invocation of Deno.readDir(parent)) {
          if (
            !invocation.isDirectory || !/^[a-f0-9]{32}$/.test(invocation.name)
          ) fail();
          const directory = `${parent}/${invocation.name}`;
          await assertBackupV2Directory(directory);
          try {
            const gate = validateBackupV2Gate(
              JSON.parse(
                new TextDecoder("utf-8", { fatal: true }).decode(
                  await rootRead(`${directory}/${BACKUP_V2_GATE_FILE}`),
                ),
              ),
            );
            if (backupV2GateDirectory(gate) !== directory) fail();
            gates.push(gate);
            if (gates.length > 256) fail();
          } catch (e) {
            if (!(e instanceof Deno.errors.NotFound)) throw e;
          }
        }
      }
    }
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }
  return gates;
}
/** Read-only intent census. No failed or missing receipt erases a durable PUT. */
export async function discoverBackupV2UnresolvedPuts(): Promise<
  BackupV2PutIntent[]
> {
  const intents = new Map<string, BackupV2PutIntent>();
  let total = 0;
  for (const gate of await discoverBackupV2SourceGates()) {
    const path = `${backupV2GateDirectory(gate)}/journal/upload-journal.ndjson`;
    let bytes: Uint8Array;
    try {
      bytes = await rootRead(path, BACKUP_V2_LIMITS.journalBytes);
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) continue;
      throw error;
    }
    total += bytes.length;
    if (total > BACKUP_V2_LIMITS.journalBytes) fail();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text && !text.endsWith("\n")) fail();
    const records = text
      ? text.slice(0, -1).split("\n").map((line) => JSON.parse(line))
      : [];
    const journal = new BackupV2UploadJournal(
      gate.envelope.request.captureId,
      () => Promise.reject(new Error("Read-only journal")),
      records,
    );
    const reclaimed = new Set(
      journal.snapshot().flatMap((entry) =>
        entry.type === "reclaimed" ? [entry.name] : []
      ),
    );
    for (const record of journal.snapshot()) {
      if (record.type === "intent" && !reclaimed.has(record.intent.name)) {
        intents.set(record.intent.name, record.intent);
      }
    }
    if (
      backupV2ArtifactBytes([...intents.values()]).length >
        BACKUP_V2_LIMITS.controlResponseBytes
    ) fail();
  }
  return [...intents.values()];
}
async function rootRead(
  path: string,
  maximum = BACKUP_V2_LIMITS.controlResponseBytes,
): Promise<Uint8Array> {
  const before = await Deno.lstat(path);
  if (
    !before.isFile || before.isSymlink || before.uid !== 0 ||
    before.nlink !== 1 || before.mode === null ||
    (before.mode & 0o777) !== 0o600 || before.size > maximum
  ) fail();
  const bytes = await Deno.readFile(path), after = await Deno.lstat(path);
  if (
    bytes.length !== before.size || after.dev !== before.dev ||
    after.ino !== before.ino || after.size !== before.size ||
    bytes.length > maximum
  ) fail();
  return bytes;
}
/** Only ephemeral decoder/producer scratch is removed. Native/upload journals,
 * source results, failure evidence, checkpoints and protected graphs stay. */
export interface BackupV2ScratchCleanupReceipt {
  schemaVersion: 2;
  format: "backup-v2-scratch-cleanup";
  requestSha256: string;
  gates: BackupV2Gate[];
  entriesRemoved: number;
  logicalBytesRemoved: number;
  completedAtUtc: string;
}
export async function cleanupBackupV2Scratch(
  proofs: { gate: BackupV2Gate; options: BackupV2KernelObservationOptions }[],
  managedGate: BackupV2Gate,
): Promise<BackupV2ScratchCleanupReceipt> {
  if (
    managedGate.kind !== "prune" || !managedGate.custody ||
    managedGate.custody.mainPid !== Deno.pid
  ) fail();
  same((await ownExecution(managedGate)).custody, managedGate.custody);
  if (
    proofs.length !== 2 ||
    new Set(proofs.map((proof) => proof.gate.kind)).size !== 2
  ) fail();
  const gates = proofs.map(({ gate }) => validateBackupV2Gate(gate));
  if (
    !gates.some((gate) => gate.kind === "worker") ||
    !gates.some((gate) => gate.kind === "verify")
  ) fail();
  same(gates[0].envelope, gates[1].envelope);
  same(gates[0].envelope, managedGate.envelope);
  let entries = 0, logicalBytesRemoved = 0;
  const paths: { path: string; info: Deno.FileInfo }[] = [];
  // The managed pruner caller already holds the source lock.
  const prove = async () => {
    for (const proof of proofs) {
      if (
        !proof.options.retainedTerminalProof ||
        !proof.options.expectedCustodySha256
      ) fail();
      const observed = await observeBackupV2Kernel(
          proof.gate,
          undefined,
          proof.options,
        ),
        tree = observed.tree;
      if (
        observed.sourceBootId !== proof.gate.sourceBootId ||
        observed.nativeCustodySha256 !== proof.options.expectedCustodySha256 ||
        !tree || tree.mainPid !== 0 || tree.controlPid !== 0 ||
        tree.cgroupPopulated !== false || tree.descendants !== 0 ||
        tree.escapedProcesses !== 0 || tree.namespaceReferences !== 0 ||
        tree.openPipelineHandles !== 0 || tree.pendingOperations !== 0
      ) fail();
      same(observed.identity, proof.gate.custody);
    }
  };
  await prove();
  const walk = async (path: string, depth: number): Promise<void> => {
    if (++entries > 10_000 || depth > 32) fail();
    const info = await Deno.lstat(path);
    if (
      info.isSymlink || info.uid !== 0 ||
      !info.isDirectory && !info.isFile && !info.isFifo || info.mode === null ||
      (info.mode & 0o077) !== 0 || !info.isDirectory && info.nlink !== 1
    ) fail();
    if (info.isDirectory) {
      for await (const child of Deno.readDir(path)) {
        await walk(`${path}/${child.name}`, depth + 1);
      }
    } else {
      logicalBytesRemoved += info.size;
      if (logicalBytesRemoved > BACKUP_V2_LIMITS.workspaceBytes) fail();
    }
    paths.push({ path, info });
  };
  for (const gate of gates) {
    for (const name of ["stage", "spool", "read-slots"]) {
      const path = `${backupV2GateDirectory(gate)}/${name}`;
      try {
        await Deno.lstat(path);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) {
          throw error;
        }
        continue;
      }
      await walk(path, 0);
    }
  }
  await prove();
  for (const entry of paths) {
    const actual = await Deno.lstat(entry.path);
    if (
      actual.isSymlink || actual.dev !== entry.info.dev ||
      actual.ino !== entry.info.ino || actual.uid !== entry.info.uid ||
      actual.mode !== entry.info.mode ||
      !actual.isDirectory &&
        (actual.size !== entry.info.size || actual.nlink !== 1)
    ) fail();
    await Deno.remove(entry.path);
  }
  for (const gate of gates) {
    for (const name of ["stage", "spool", "read-slots"]) {
      try {
        await Deno.lstat(`${backupV2GateDirectory(gate)}/${name}`);
        fail();
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) {
          throw error;
        }
      }
    }
  }
  return {
    schemaVersion: 2,
    format: "backup-v2-scratch-cleanup",
    requestSha256: gates[0].envelope.requestSha256,
    gates,
    entriesRemoved: paths.length,
    logicalBytesRemoved,
    completedAtUtc: new Date().toISOString(),
  };
}
async function rootDirectory(path: string): Promise<void> {
  try {
    await Deno.mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
  }
  await assertBackupV2Directory(path);
}
/** One per-invocation append file. Registration resolves only after the exact
 * facts are durable; an uncertain write poisons later registration. */
export async function openBackupV2NativeCustody(
  directory: string,
  gate: BackupV2Gate,
) {
  await assertBackupV2Directory(directory);
  const path = `${directory}/${BACKUP_V2_NATIVE_CUSTODY_FILE}`;
  const file = await Deno.open(path, {
    createNew: true,
    read: true,
    write: true,
    mode: 0o600,
  });
  const identity = await file.stat();
  let bytesWritten = 0,
    serial = Promise.resolve(),
    poisoned: unknown,
    closed = false;
  const append = (input: BackupV2NativeCustodyRecord): Promise<void> => {
    const next = serial.then(async () => {
      if (poisoned !== undefined) throw poisoned;
      if (closed) fail();
      const record = validateBackupV2NativeCustodyRecord(input, gate),
        bytes = backupV2NativeCustodyBytes(record);
      if (
        bytes.length > 16 * 1024 ||
        bytesWritten + bytes.length > BACKUP_V2_LIMITS.journalBytes
      ) fail();
      const current = await Deno.lstat(path);
      if (
        !current.isFile || current.isSymlink || current.uid !== 0 ||
        current.nlink !== 1 || current.mode === null ||
        (current.mode & 0o777) !== 0o600 || current.dev !== identity.dev ||
        current.ino !== identity.ino || current.size !== bytesWritten
      ) fail();
      let at = 0;
      while (at < bytes.length) {
        const count = await file.write(bytes.subarray(at));
        if (count <= 0 || count > bytes.length - at) fail();
        at += count;
      }
      await file.sync();
      bytesWritten += bytes.length;
    }).catch((error) => {
      poisoned ??= error;
      throw error;
    });
    serial = next.catch(() => {});
    return next;
  };
  const flush = async () => {
    await serial;
    if (poisoned !== undefined) throw poisoned;
    const encoded = await rootRead(path, BACKUP_V2_LIMITS.journalBytes);
    return {
      ...parseBackupV2NativeCustody(encoded, gate),
      sha256: backupV2ArtifactSha256(encoded),
    };
  };
  try {
    await append({ type: "BOUND", schemaVersion: 1, gate });
    using parent = await Deno.open(directory, { read: true });
    await parent.sync();
  } catch (error) {
    file.close();
    throw error;
  }
  return {
    append,
    flush,
    async close() {
      await serial;
      if (!closed) {
        closed = true;
        file.close();
      }
      if (poisoned !== undefined) throw poisoned;
    },
  };
}
async function atomicArtifact(
  directory: string,
  name: string,
  value: unknown,
  immutable = false,
): Promise<string> {
  if (!/^[a-z0-9-]+\.json$/.test(name)) fail();
  await assertBackupV2Directory(directory);
  const bytes = backupV2ArtifactBytes(value), path = `${directory}/${name}`;
  if (
    bytes.length >
      (name === BACKUP_V2_CHECKPOINT_FILE
        ? 16 * 1024 * 1024
        : BACKUP_V2_LIMITS.controlResponseBytes)
  ) fail();
  if (immutable) {
    try {
      const old = await rootRead(path, bytes.length);
      if (backupV2ArtifactSha256(old) !== backupV2ArtifactSha256(bytes)) fail();
      return backupV2ArtifactSha256(old);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  }
  const temporary = `${path}.${crypto.randomUUID()}.tmp`;
  const file = await Deno.open(temporary, {
    createNew: true,
    write: true,
    mode: 0o600,
  });
  try {
    let at = 0;
    while (at < bytes.length) {
      const count = await file.write(bytes.subarray(at));
      if (count <= 0 || count > bytes.length - at) fail();
      at += count;
    }
    await file.sync();
  } finally {
    file.close();
  }
  await Deno.rename(temporary, path);
  using parent = await Deno.open(directory, { read: true });
  await parent.sync();
  return backupV2ArtifactSha256(bytes);
}
async function ownExecution(gate: BackupV2Gate): Promise<BackupV2Gate> {
  const boot = (await readBackupV2KernelText("/proc/sys/kernel/random/boot_id"))
    .trim();
  const cgroup = (await readBackupV2KernelText(`/proc/${Deno.pid}/cgroup`))
    .trim().split(
      "\n",
    ).find((line) => line.startsWith("0::"))?.slice(3);
  const process = await readBackupV2KernelText(`/proc/${Deno.pid}/stat`),
    mainStartTicks = process.slice(process.lastIndexOf(")") + 2).split(" ")[19];
  const invocationId = Deno.env.get("INVOCATION_ID");
  if (
    boot !== gate.sourceBootId ||
    cgroup !== `${GATE_BACKUP_CGROUP_ROOT}/${gate.unitName}`
  ) fail();
  return validateBackupV2Gate({
    ...gate,
    state: "ACTIVE",
    custody: {
      unitName: gate.unitName,
      invocationId,
      mainPid: Deno.pid,
      mainStartTicks,
      cgroup,
    },
    updatedAtUtc: new Date().toISOString(),
  });
}

/** An explicit controller resume launches a fresh invocation. Reuse only sealed
 * immutable roles from the same original request; an unfinished GPG stream is
 * never concatenated or resumed. M05 revalidates boot/package compatibility. */
async function previousSealedRoles(
  settings: BackupV2WorkerSettings,
  gate: BackupV2Gate,
  directory: string,
): Promise<BackupV2SealedRoleCheckpoint[]> {
  const parent = directory.slice(0, directory.lastIndexOf("/")),
    selected = new Map<string, BackupV2SealedRoleCheckpoint>();
  let count = 0;
  for await (const entry of Deno.readDir(parent)) {
    if (++count > 64) fail();
    if (entry.name === gate.custody!.invocationId) continue;
    if (!entry.isDirectory || !/^[a-f0-9]{32}$/.test(entry.name)) fail();
    const previous = `${parent}/${entry.name}`;
    await assertBackupV2Directory(previous);
    let bytes: Uint8Array;
    try {
      bytes = await rootRead(
        `${previous}/${BACKUP_V2_CHECKPOINT_FILE}`,
        16 * 1024 * 1024,
      );
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) continue;
      throw e;
    }
    const value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    if (
      !value || Object.keys(value).length !== 5 ||
      !Array.isArray(value.roles) || value.roles.length > BACKUP_V2_ROLES.length
    ) fail();
    const old = validateBackupV2Gate({
      ...settings.workerGate,
      state: "ACTIVE",
      custody: value.custody,
      updatedAtUtc: new Date().toISOString(),
    });
    same(value.envelope, settings.envelope);
    same(value.gateId, gate.gateId);
    same(value.sourceBootId, gate.sourceBootId);
    if (old.custody!.invocationId !== entry.name) fail();
    // A crash preserves its actual last nonterminal status. The explicit Pi
    // resume and current gate ack carry the independently proved settlement;
    // never rewrite that old status to fabricate a terminal timestamp.
    validateBackupV2Status(
      JSON.parse(
        new TextDecoder().decode(
          await rootRead(`${previous}/${BACKUP_V2_STATUS_FILE}`),
        ),
      ),
      old,
    );
    for (const checkpoint of value.roles as BackupV2SealedRoleCheckpoint[]) {
      const role = validateBackupV2RoleManifest(checkpoint.manifest).role,
        prior = selected.get(role);
      if (prior) same(prior, checkpoint);
      else selected.set(role, checkpoint);
    }
  }
  return BACKUP_V2_ROLES.flatMap((role) =>
    selected.has(role) ? [selected.get(role)!] : []
  );
}

export interface BackupV2CapacityIO {
  now?(): number;
  lstat(path: string): Promise<{
    blocks: bigint;
    dev: bigint;
    ino: bigint;
    isSymbolicLink(): boolean;
    isDirectory(): boolean;
  }>;
  entries(path: string): AsyncIterable<string>;
  statfs(
    path: string,
  ): Promise<{ bavail: bigint; bsize: bigint; ffree: bigint }>;
  deleted: typeof backupV2DeletedHandleBytes;
}
const capacityIO: BackupV2CapacityIO = {
  lstat: (path) => lstat(path, { bigint: true }),
  async *entries(path) {
    for await (const entry of Deno.readDir(path)) yield entry.name;
  },
  statfs: (path) => statfs(path, { bigint: true }),
  deleted: backupV2DeletedHandleBytes,
};
/** Only exact active roots, never the entire retained protection inventory. */
export function backupV2CapacityRoots(
  directory: string,
  additionalRoots: readonly string[] = [],
): string[] {
  const roots = [...new Set([directory, ...additionalRoots])];
  if (
    roots.some((path) =>
      !/^\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(path) ||
      path.split("/").some((part) => part === "." || part === "..")
    )
  ) fail();
  return roots.filter((path) =>
    !roots.some((parent) => parent !== path && path.startsWith(parent + "/"))
  );
}
/** Allocated blocks plus all unlinked files held by this managed cgroup.
 * Outside-gate unlinked files are conservatively charged once to workspace;
 * their original source counter also retains its independent safety check. */
export async function observeBackupV2Capacity(
  directory: string,
  cgroup: string,
  additionalRoots: readonly string[] = [],
  io: BackupV2CapacityIO = capacityIO,
): Promise<BackupV2CapacityObservation> {
  const clock = io.now ?? (() => performance.now()), deadline = clock() + 5000;
  const budget = () => {
    const now = clock();
    if (!Number.isFinite(now) || now < 0 || now >= deadline) fail();
  };
  const absent = (error: unknown) =>
    error instanceof Deno.errors.NotFound ||
    error instanceof Error && "code" in error && error.code === "ENOENT";
  let allocated = 0, entries = 0;
  const seen = new Set<string>();
  budget();
  const primary = await io.lstat(directory);
  if (!primary.isDirectory() || primary.isSymbolicLink()) fail();
  const assertPrimary = async () => {
    budget();
    const current = await io.lstat(directory);
    if (
      !current.isDirectory() || current.isSymbolicLink() ||
      current.dev !== primary.dev || current.ino !== primary.ino
    ) fail();
    budget();
  };
  const vanished = new Set<unknown>();
  const walk = async (path: string, depth: number): Promise<void> => {
    budget();
    if (++entries > 10_000 || depth > 32) fail();
    try {
      const info = await io.lstat(path);
      budget();
      if (
        info.isSymbolicLink() || info.dev !== primary.dev || info.blocks < 0n
      ) fail();
      const key = `${info.dev}:${info.ino}`;
      if (seen.has(key)) return;
      seen.add(key);
      allocated += Number(info.blocks * 512n);
      if (!Number.isSafeInteger(allocated)) fail();
      if (info.isDirectory()) {
        for await (const child of io.entries(path)) {
          if (
            !child || child.includes("/") || child === "." || child === ".."
          ) fail();
          await walk(`${path}/${child}`, depth + 1);
        }
      }
    } catch (error) {
      if (depth > 0 && absent(error)) vanished.add(error);
      throw error;
    }
  };
  const roots = backupV2CapacityRoots(directory, additionalRoots),
    present = new Set([directory]);
  for (let attempt = 0;; attempt++) {
    allocated = 0;
    seen.clear();
    vanished.clear();
    try {
      for (const root of roots) {
        budget();
        try {
          await io.lstat(root);
        } catch (error) {
          // A registered future root may not yet exist. An observed root
          // disappearing is never treated as an empty directory.
          if (!present.has(root) && absent(error)) continue;
          throw error;
        }
        present.add(root);
        await walk(root, 0);
      }
      await assertPrimary();
      break;
    } catch (error) {
      // WAL/shm removal restarts the entire walk with fresh inode accounting,
      // sharing one time/entry budget; no partial count is accepted.
      if (!vanished.has(error) || attempt >= 2) throw error;
      await assertPrimary();
    }
  }
  budget();
  const {
    workspaceHeldDeletedBytes: workspaceDeleted,
    sourceHeldDeletedBytes: sourceDeleted,
  } = await io.deleted(directory, cgroup);
  budget();
  if (
    ![workspaceDeleted, sourceDeleted].every((value) =>
      Number.isSafeInteger(value) && value >= 0
    )
  ) fail();
  const workspaceHeldDeletedBytes = workspaceDeleted + sourceDeleted;
  const fs = await io.statfs(directory);
  budget();
  const availableBytes = Number(fs.bavail * fs.bsize),
    freeInodes = Number(fs.ffree);
  if (
    ![
      allocated + workspaceHeldDeletedBytes + BACKUP_V2_RUNTIME_LEASE_BYTES,
      availableBytes,
      freeInodes,
    ].every((
      value,
    ) => Number.isSafeInteger(value) && value >= 0)
  ) fail();
  return {
    observedMonotonicMs: performance.now(),
    availableBytes,
    freeInodes,
    allocatedWorkspaceBytes: allocated + workspaceHeldDeletedBytes +
      BACKUP_V2_RUNTIME_LEASE_BYTES,
    workspaceHeldDeletedBytes,
    sourceHeldDeletedBytes: sourceDeleted,
  };
}
async function drainDiagnostics(
  stream: ReadableStream<Uint8Array>,
): Promise<void> {
  let bytes = 0;
  for await (const part of stream) {
    bytes += part.length;
    if (bytes > 64 * 1024) {
      throw new Error("Document diagnostics exceeded bound");
    }
  }
}
function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(new Error("Source operation cancelled"));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  });
}

/** Real source entrypoint used by the version-specific generated wrappers.
 * Heavy children are always inside the caller's proved finite managed unit. */
export async function runBackupV2RemoteWorker(
  jobId: string,
  kind: "worker" | "verify" | "prune",
): Promise<BackupV2Status> {
  if (!/^job-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(jobId)) fail();
  const runtime = `${JOBS_RUNTIME_ROOT}/${jobId}`;
  if (await Deno.realPath(Deno.cwd()) !== runtime) fail();
  const settings = validateBackupV2WorkerSettings(
    JSON.parse(
      new TextDecoder().decode(await rootRead(`${runtime}/settings.json`)),
    ),
  );
  if (settings.envelope.request.jobId !== jobId) fail();
  const request = settings.envelope.request,
    release = `${RELEASES_ROOT}/${request.sourceRevision}`;
  if (
    new URL(import.meta.url).pathname !==
      `${release}/scripts/backup-v2-worker.ts`
  ) fail();
  const manifest = validateReleaseManifest(
    JSON.parse(
      new TextDecoder().decode(await rootRead(`${release}/release.json`)),
    ),
    request.sourceRevision,
  );
  for (const entry of manifest.files) {
    if (
      backupV2ArtifactSha256(await rootRead(`${release}/${entry.path}`)) !==
        entry.sha256
    ) fail();
  }
  let prunePath: string | undefined;
  if (kind === "prune") {
    prunePath = `${runtime}/prune-execute-request.json`;
    try {
      await rootRead(prunePath);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
      prunePath = `${runtime}/prune-plan-request.json`;
    }
  }
  const readPrune = async (): Promise<BackupV2PruneInput> => {
    if (!prunePath) fail();
    const input = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        await rootRead(prunePath),
      ),
    ) as BackupV2PruneInput;
    const expected = validateBackupV2Gate(input.gate);
    if (expected.kind !== "prune") fail();
    same(expected.envelope, settings.envelope);
    return { ...input, gate: await ownExecution(expected) };
  };
  let pruneInput = kind === "prune" ? await readPrune() : null;
  const gate = await ownExecution(
      pruneInput
        ? pruneInput.gate
        : kind === "worker"
        ? settings.workerGate
        : settings.verifierGate,
    ),
    directory = backupV2GateDirectory(gate);
  if (pruneInput) pruneInput = { ...pruneInput, gate };
  await rootDirectory(BACKUP_BASE);
  await rootDirectory(`${BACKUP_BASE}/${request.captureId}`);
  await rootDirectory(`${BACKUP_BASE}/${request.captureId}/v2-${gate.gateId}`);
  await rootDirectory(directory);
  for await (const _entry of Deno.readDir(directory)) fail();
  await atomicArtifact(directory, BACKUP_V2_GATE_FILE, gate, true);
  return await withBackupLock(GATE_SOURCE_LOCK_PATH, async () => {
    const stage = `${directory}/stage`,
      spoolDirectory = `${directory}/spool`,
      journalDirectory = `${directory}/journal`;
    for (const path of [stage, spoolDirectory, journalDirectory]) {
      await rootDirectory(path);
    }
    const nativeCustody = await openBackupV2NativeCustody(directory, gate);
    const spool = new BackupV2Spool(
        await createBackupV2FileSpoolStorage(spoolDirectory),
      ),
      journal = await openBackupV2UploadJournal(
        journalDirectory,
        request.captureId,
      );
    const pace = createBackupV2UploadPacer(),
      work = new BackupV2WorkerProgress(),
      notifier = createBackupV2Notifier(),
      runtimeLease = openBackupV2RuntimeLease(gate.custody!);
    const startedAtUtc = new Date().toISOString();
    const activeRoots = new Set<string>([
      `${runtime}/deno-cache`,
      backupV2ControlCacheDirectory(jobId),
    ]);
    if (pruneInput) {
      activeRoots.add(
        `${BACKUP_V2_PRUNE_TRANSACTIONS}/${pruneInput.transactionId}`,
      );
    }
    let last: BackupV2Status | null = null,
      terminal = false,
      stopping: Promise<never> | null = null;
    let lastObservation: BackupV2SupervisorObservation | null = null,
      supervisorFailure: BackupV2SupervisorFailure | null = null;
    let statusWrites: Promise<unknown> = Promise.resolve();
    const writeStatus = (
      finishedAtUtc: string | null = null,
      resultSha256: string | null = null,
    ): Promise<BackupV2Status> => {
      const written = statusWrites.then(async () => {
        const now = performance.now(),
          lease = { ...supervisor.window(), observedMonotonicMs: now };
        const status = validateBackupV2Status({
          schemaVersion: 2,
          format: "backup-v2",
          envelope: settings.envelope,
          ...execution(gate),
          kind,
          phase: work.phase,
          activeRoleAttempt: work.activeRoleAttempt,
          startedAtUtc,
          updatedAtUtc: new Date().toISOString(),
          finishedAtUtc,
          progress: work.snapshot(now),
          lease,
          resultSha256,
        }, gate);
        if (last) assertBackupV2StatusTransition(last, status);
        await atomicArtifact(directory, BACKUP_V2_STATUS_FILE, status);
        last = status;
        return status;
      });
      statusWrites = written.catch(() => {});
      return written;
    };
    const cancel = (reason: unknown): Promise<never> => {
      if (!stopping) {
        stopping = (async () => {
          supervisor.cancel();
          work.phase = "CANCELLATION_BLOCKED";
          // Retain the MainPID so RemainAfterExit cannot disable the finite
          // runtime timer while a child/namespace is unproved. Never renew here.
          setInterval(() => {}, 1000);
          try {
            await atomicArtifact(
              directory,
              "failure.json",
              backupV2FailureEvidence({
                identity: gate.custody!,
                reason,
                supervisorFailure,
                observation: lastObservation,
                observedAtUtc: new Date().toISOString(),
                observedMonotonicMs: performance.now(),
              }),
              true,
            );
          } catch {
            console.error(
              "Backup v2 sanitized failure evidence persistence unproved",
            );
          }
          await writeStatus().catch(() => {});
          return await new Promise<never>(() => {});
        })();
      }
      return stopping;
    };
    const supervisor = new BackupV2Supervisor(gate.custody!, {
      startupGraceMs: 300_000,
      progressGraceMs: 300_000,
      notificationGraceMs: 30_000,
      observationTimeoutMs: 5000,
      maximumObservationAgeMs: 5000,
      productionWriterMarginBytes: BACKUP_V2_PRODUCTION_WRITER_MARGIN_BYTES,
      minimumFreeInodes: 256,
      maximumSourceHeldDeletedBytes: BACKUP_V2_LIMITS.workspaceBytes,
    }, {
      now: () => performance.now(),
      notifier,
      persistRuntimeLease: runtimeLease.persist,
      onFailure: (failure) => {
        supervisorFailure ??= failure;
      },
      async observe() {
        const sample = await observeBackupV2Capacity(
          directory,
          gate.custody!.cgroup,
          [...activeRoots],
        );
        lastObservation = {
          identity: gate.custody!,
          progress: work.snapshot(sample.observedMonotonicMs),
          capacity: sample,
        };
        return lastObservation;
      },
    });
    const processes = createBackupV2NativeProcessStarter({
      gate,
      append: nativeCustody.append,
      cancel,
    });
    const store = new BackupV2Store(
      settings.B2Settings,
      createCurlBackupV2Wire(undefined, processes.spawn),
    );
    const native = {
      async assertManaged() {
        const actual = await ownExecution(gate);
        same(actual.custody, gate.custody);
      },
      cancel,
      spawn: (command: string, args: string[]) => {
        const kind =
          command === "unshare" || command === "gpg" || command === "zstd" ||
            command === "tar"
            ? command
            : "metadata";
        return processes.spawn(kind, command, args, {
          signal: supervisor.signal,
          env: { TZ: "UTC", TMPDIR: stage },
        });
      },
      registerNamespace: processes.registerNamespace,
      registerChild: processes.registerChild,
    };
    let serial = Promise.resolve();
    const supervise = (change?: () => void) => {
      const next = serial.then(async () => {
        const decision = await supervisor.poll();
        if (decision.action !== "renew") await cancel(decision.reason);
        change?.();
        await writeStatus();
      });
      serial = next.catch(() => {});
      return next;
    };
    const onRetryEpisode = (episode: BackupV2UploadRetryEpisode) =>
      supervise(() => {
        supervisor.beginRetryEpisode({ ...episode, retryableTransport: true });
      });
    const onTransferEpisode = (episode: BackupV2TransferEpisode) =>
      supervise(() => {
        supervisor.beginTransferEpisode(episode);
      });
    const onTransferComplete = (operationId: string) =>
      supervise(() => {
        supervisor.completeTransferEpisode(operationId);
      });
    const documents: import("./backup-v2-index.ts").BackupV2DocumentBinding[] =
      [];
    const protectedObjects = new Map<string, BackupV2ObjectRef>();
    const remember = (input: BackupV2ObjectRef) => {
      const object = validateBackupV2ObjectRef(input),
        old = protectedObjects.get(object.fileId);
      if (old) same(old, object);
      protectedObjects.set(object.fileId, object);
      if (protectedObjects.size > BACKUP_V2_LIMITS.pruneCandidates) fail();
    };
    const encrypt = async (plaintext: Uint8Array, signal: AbortSignal) => {
      await native.assertManaged();
      const child = await processes.spawn(
        "gpg",
        "gpg",
        gpgArgs(
          `${stage}/gpg-public-home`,
          settings.captureSettings.recipientFile,
          "-",
          "-",
        ),
        { signal },
      );
      const input = (async () => {
        const writer = child.stdin.getWriter();
        try {
          await writer.write(plaintext);
          await writer.close();
        } finally {
          writer.releaseLock();
        }
      })();
      const stderr = (async () => {
        let bytes = 0;
        for await (const part of child.stderr) {
          bytes += part.length;
          if (bytes > 64 * 1024) {
            throw new Error("Document diagnostics exceeded bound");
          }
        }
      })();
      return {
        ciphertext: child.stdout,
        completed: Promise.all([input, stderr, child.status]).then(
          ([, , status]) => {
            if (!status.success) throw new Error("Document encryption failed");
          },
        ),
      };
    };
    const publisher = (identity: BackupV2UploadIdentity) => {
      if (kind === "worker") {
        work.phase = "CAPTURING_AND_UPLOADING";
        work.activeRoleAttempt = {
          role: identity.role,
          attemptId: identity.attemptId,
        };
      }
      return new BackupV2DocumentPublisher({
        upload: {
          identity,
          store,
          spool,
          journal,
          pace,
          signal: supervisor.signal,
          classifyFailure: (error) => ({
            retryable: error instanceof BackupV2TransportError &&
              error.retryable,
            mayHaveCommitted: error instanceof BackupV2TransportError &&
              error.putMayHaveCommitted,
          }),
          onVerified: (chunk) => {
            remember(chunk.object);
            work.verifiedObject();
          },
          onRetryEpisode,
          onTransferEpisode,
          onTransferComplete,
        },
        encrypt,
        bindings: documents,
        async persistBinding(binding) {
          documents.push(binding);
          const bytes = backupV2ArtifactBytes(binding),
            path = `${journalDirectory}/document-bindings.ndjson`;
          using file = await Deno.open(path, {
            create: true,
            append: true,
            write: true,
            mode: 0o600,
          });
          let at = 0;
          while (at < bytes.length) {
            const count = await file.write(bytes.subarray(at));
            if (count <= 0 || count > bytes.length - at) fail();
            at += count;
          }
          await file.sync();
        },
      });
    };
    const loopAbort = new AbortController();
    try {
      const unitNamespace = await processes.registerUnitNamespace();
      await supervise();
      const monitor = (async () => {
        while (!terminal) {
          await delay(1000, loopAbort.signal);
          if (!terminal) await supervise();
        }
      })().catch(async (error) => {
        if (!terminal) await cancel(error);
      });
      let verifyInput: {
        workerGate: BackupV2Gate;
        workerResult: BackupV2Result;
        workerResultBytes: number[];
      } | null = null;
      if (kind === "verify") {
        verifyInput = JSON.parse(
          new TextDecoder().decode(
            await rootRead(`${runtime}/verifier-request.json`),
          ),
        );
        if (!verifyInput) fail();
        verifyInput.workerGate = validateBackupV2Gate(verifyInput.workerGate);
        verifyInput.workerResult = validateBackupV2Result(
          verifyInput.workerResult,
          verifyInput.workerGate,
        );
        if (verifyInput.workerGate.gateId !== settings.workerGate.gateId) {
          fail();
        }
        same(verifyInput.workerResult.envelope, settings.envelope);
        same(
          JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(
              new Uint8Array(verifyInput.workerResultBytes),
            ),
          ),
          verifyInput.workerResult,
        );
      }
      // This fixed acknowledgement binds Pi custody before any producer starts.
      // No heartbeat can extend the startup grace while a controller is absent.
      while (true) {
        try {
          same(
            JSON.parse(
              new TextDecoder().decode(
                await rootRead(`${directory}/gate-bound.json`),
              ),
            ),
            {
              gateId: gate.gateId,
              requestSha256: settings.envelope.requestSha256,
              sourceBootId: gate.sourceBootId,
              custody: gate.custody,
            },
          );
          break;
        } catch (error) {
          if (!(error instanceof Deno.errors.NotFound)) throw error;
          await delay(250, supervisor.signal);
        }
      }
      const run = createBackupV2MetadataRunner(stage, native);
      if (kind === "verify") {
        await prepareRecipient(settings.captureSettings, stage, run);
      }
      let result:
        | BackupV2Result
        | BackupV2VerifiedResult
        | (BackupV2PruneResult & {
          scratchCleanup?: BackupV2ScratchCleanupReceipt;
        });
      if (kind === "worker") {
        const checkpoints = await previousSealedRoles(
          settings,
          gate,
          directory,
        );
        for (const checkpoint of checkpoints) {
          remember(checkpoint.reference.object);
          for (const page of checkpoint.manifest.pages) {
            remember(page.manifest.object);
          }
          for (const chunk of checkpoint.capture.chunks) remember(chunk.object);
          for (const object of checkpoint.manifest.metadata) remember(object);
        }
        if (checkpoints.length) {
          await atomicArtifact(directory, BACKUP_V2_CHECKPOINT_FILE, {
            envelope: settings.envelope,
            ...execution(gate),
            roles: checkpoints,
          });
        }
        result = await captureBackupV2Worker(settings, gate, {
          context: {
            stage,
            sourceConfigSha256: request.sourceConfigSha256,
            native,
            spool,
            journal,
            store,
            pace,
            signal: supervisor.signal,
            classifyFailure: (error) => ({
              retryable: error instanceof BackupV2TransportError &&
                error.retryable,
              mayHaveCommitted: error instanceof BackupV2TransportError &&
                error.putMayHaveCommitted,
            }),
            admit: () => supervise(),
            onRetryEpisode,
            onTransferEpisode,
            onTransferComplete,
          },
          publisher,
          reused: checkpoints,
          checkpoint: async (value) => {
            checkpoints.push(value);
            await atomicArtifact(directory, BACKUP_V2_CHECKPOINT_FILE, {
              envelope: settings.envelope,
              ...execution(gate),
              roles: checkpoints,
            });
          },
          progress: (value, active) => work.capture(value, active),
          now: () => new Date(),
        });
      } else if (kind === "verify") {
        if (!verifyInput) fail();
        const publicHome = `${PUBLIC_HOME_BASE}/${request.captureId}`;
        activeRoots.add(publicHome);
        await supervise();
        await ensurePublicHome(publicHome, run);
        const importChild = await spawnBackupV2GpgDecrypt(processes, [
          "--no-options",
          "--no-autostart",
          "--batch",
          "--no-tty",
          "--homedir",
          publicHome,
          "--import",
        ], supervisor.signal);
        const publicBytes = await rootRead(
          settings.captureSettings.recipientFile,
          64 * 1024,
        );
        const imported = await Promise.all([
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(publicBytes);
              controller.close();
            },
          }).pipeTo(importChild.stdin),
          drainDiagnostics(importChild.stdout),
          drainDiagnostics(importChild.stderr),
          importChild.status,
        ]);
        if (!imported[3].success) fail();
        const decrypt = makeStreamDecryptArchive(publicHome, {
          async command(args) {
            const result = await run("sudo", args);
            return {
              success: result.code === 0,
              stdout: encoder.encode(result.stdout),
            };
          },
          spawn: (args) =>
            spawnBackupV2GpgDecrypt(processes, args, supervisor.signal),
        });
        work.phase = "VERIFYING";
        let readSerial = 0;
        const readerStore = {
          async getExactToFile(
            ...args: Parameters<BackupV2Store["getExactToFile"]>
          ) {
            const [object] = args,
              operationId = `read-${++readSerial}-${object.fileId}`,
              startedAtMs = performance.now();
            const episode: BackupV2TransferEpisode = {
              kind: "SEALED_TRANSFER",
              operationId,
              phase: "READBACK",
              sealedObjectIdentity: object.fileName,
              retainedBytes: object.contentLength,
              startedAtMs,
              expiresAtMs: startedAtMs + backupV2TransferWindowMs("READBACK"),
            };
            const path = `${journalDirectory}/read-intents.ndjson`,
              bytes = backupV2ArtifactBytes({
                episode,
                reference: object,
                target: args[1],
                startedAtUtc: new Date().toISOString(),
              });
            using file = await Deno.open(path, {
              create: true,
              append: true,
              write: true,
              mode: 0o600,
            });
            let at = 0;
            while (at < bytes.length) {
              const count = await file.write(bytes.subarray(at));
              if (count <= 0) fail();
              at += count;
            }
            await file.sync();
            if ((await file.stat()).size > BACKUP_V2_LIMITS.journalBytes) {
              fail();
            }
            await onTransferEpisode(episode);
            await pace(object.contentLength);
            const slot = await store.getExactToFile(...args);
            remember(object);
            work.verifiedObject();
            await onTransferComplete(operationId);
            return slot;
          },
        };
        const readDirectory = `${directory}/read-slots`;
        await rootDirectory(readDirectory);
        const tools = await recordToolVersions(stage, run);
        result = await verifyBackupV2Worker(
          settings,
          gate,
          verifyInput.workerResult,
          verifyInput.workerGate,
          {
            reader: {
              objects: await createBackupV2FileObjectReader(
                readDirectory,
                readerStore,
              ),
              decryptDocument: decrypt,
              signal: supervisor.signal,
            },
            verification: {
              decrypt,
              native: {
                spawn: (command, args) =>
                  processes.spawn(command, `/usr/bin/${command}`, args, {
                    signal: supervisor.signal,
                  }),
                temporaryDirectory: stage,
                progress: (value) => {
                  work.verification(value);
                  return Promise.resolve();
                },
              },
              configurationSha256: request.sourceConfigSha256,
              verifierRevision: request.sourceRevision,
              tools: {
                tar: tools.tar.split("\n")[0],
                zstd: tools.zstd.split("\n")[0],
                gpg: tools.gpg.split("\n")[0],
              },
              now: () => new Date(),
            },
            publisher: publisher({
              captureId: request.captureId,
              attemptId: settings.publicationAttemptId,
              role: "recovery",
              kind: "receipt",
            }),
            workerResultBytes: new Uint8Array(verifyInput.workerResultBytes),
          },
        );
      } else {
        if (!pruneInput) fail();
        const scratchCleanup = pruneInput.stage === "PLAN"
          ? await cleanupBackupV2Scratch(
            JSON.parse(
              new TextDecoder("utf-8", { fatal: true }).decode(
                await rootRead(`${runtime}/prune-cleanup-proofs.json`),
              ),
            ),
            gate,
          )
          : undefined;
        if (scratchCleanup) {
          await atomicArtifact(
            directory,
            "scratch-cleanup.json",
            scratchCleanup,
            true,
          );
        }
        const caps = await createBackupV2PruneRuntime(pruneInput, {
          exactStore: store,
          async observeFresh() {
            await native.assertManaged();
            return await readPrune();
          },
          validateLegacy: validateCatalogEntry,
          async progress(value) {
            work.retention(value.inventoryMembers);
            await supervise();
          },
          now: () => new Date(),
          signal: supervisor.signal,
        });
        result = {
          ...await runBackupV2SourcePruner(pruneInput, caps),
          ...(scratchCleanup ? { scratchCleanup } : {}),
        };
      }
      if ("selectedRoot" in result) {
        for (const record of journal.snapshot()) {
          if (record.type === "selected") remember(record.object);
        }
        const graph = buildBackupV2Protection(result.selectedRoot.reference, [
          ...protectedObjects.values(),
        ]);
        await rootDirectory(BACKUP_V2_PROTECTION_SOURCE_BASE);
        const graphDirectory = backupV2ProtectionSourceDirectory(
          graph.descriptor.manifestSha256,
        );
        activeRoots.add(graphDirectory);
        await supervise();
        await rootDirectory(graphDirectory);
        for (const page of graph.pages) {
          await atomicArtifact(
            graphDirectory,
            backupV2ProtectionPageName(page.value.pageIndex),
            page.value,
            true,
          );
          await supervise();
        }
        await atomicArtifact(
          graphDirectory,
          "manifest.json",
          graph.manifest,
          true,
        );
        await supervise();
        await atomicArtifact(
          graphDirectory,
          "descriptor.json",
          graph.descriptor,
          true,
        );
        await supervise();
        result = { ...result, protectedGraph: graph.descriptor };
      }
      terminal = true;
      loopAbort.abort();
      await monitor;
      let nativeFacts = await nativeCustody.flush();
      if (
        !unitNamespace.privateMount &&
        !nativeFacts.mounts.some((mount) => mount.scope === "PRODUCER")
      ) {
        await processes.recordNoPrivateMount();
        nativeFacts = await nativeCustody.flush();
      }
      if (
        nativeFacts.children.some((child) => child.exit === null) ||
        nativeFacts.unresolvedNamespaceLeaders.length
      ) fail();
      const completedResult = {
        ...result,
        nativeCustodySha256: nativeFacts.sha256,
      };
      const resultSha256 = await atomicArtifact(
        directory,
        BACKUP_V2_RESULT_FILE,
        completedResult,
        true,
      );
      const partial = "state" in result && result.state === "PARTIAL";
      work.phase = kind === "worker"
        ? "CLOUD_COMPLETE"
        : kind === "verify"
        ? "ACCEPTED"
        : partial
        ? "FAILED"
        : "CLEANED";
      const status = await writeStatus(
        new Date().toISOString(),
        partial ? null : resultSha256,
      );
      journal.close();
      await nativeCustody.close();
      runtimeLease.close();
      notifier.close(); // No STOPPING: retain active/exited custody.
      return status;
    } catch (error) {
      return await cancel(error);
    }
  });
}

export type BackupV2PruneWorkerResult = BackupV2PruneResult & {
  nativeCustodySha256: string;
  scratchCleanup?: BackupV2ScratchCleanupReceipt;
};

// Maintenance uses the existing private JSON convention and no new CLI flag.
if (import.meta.main) {
  const status = await runBackupV2RemoteWorker(
    Deno.cwd().split("/").at(-1)!,
    "prune",
  );
  if (status.phase === "FAILED" || status.phase === "CANCELLATION_BLOCKED") {
    Deno.exitCode = 1;
  }
}
