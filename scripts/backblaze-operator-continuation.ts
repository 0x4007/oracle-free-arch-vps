/** Explicit operator recovery of one FAILED upload; never a new capture.
 * Original request/status bytes and deadline remain authoritative. The Pi
 * holds its controller lock; the detached source unit holds source.lock.
 * Only small JSON evidence traverses SSH. Payload and keys never do. */
import { createHash } from "node:crypto";
import type { CaptureResult } from "./backblaze-capture.ts";
import {
  canonicalRequestString,
  deriveWorkerGate,
  sourceConfigSha256,
  validateRequestEnvelope,
  validateStatus,
  type WorkerRequestEnvelope,
  type WorkerStatus,
  workerUnitName,
} from "./backblaze-source-worker.ts";
import {
  type GateClearProof,
  type OperatorProofBinding,
  validateGateClearProof,
  validateUnitInvocationId,
} from "./backblaze-controller-contract.ts";
import { clearGateAfterProof } from "./backblaze-controller-gate.ts";
import {
  assertVerifierHeadroom,
  BACKUP_BASE,
  buildClearProof,
  type CatalogEntry,
  CONTROLLER_LOCK_PATH,
  CONTROLLER_STATE_PATH,
  type ControllerState,
  deriveVerifierGate,
  ensurePublicHome,
  importRecipient,
  JOBS_RUNTIME_ROOT,
  loadRuntimeSettings,
  makeDecryptArchive,
  type PiDeps,
  PUBLIC_HOME_BASE,
  realPiDeps,
  RECOVERY_BASE,
  RELEASES_ROOT,
  SOURCE_LOCK_PATH,
  type TransportSettings,
  validateCatalogEntry,
  validateControllerState,
  validateJobId,
  validateReleaseManifest,
  validateRevision,
  VERIFICATION_BASE,
  verifierHeadroomRequirement,
  verifyUnitName,
} from "./backblaze-file-backup.ts";
import {
  buildRecoveryIndex,
  type IndexRecipient,
  type PublishedIndex,
  publishRecoveryIndex,
  type RecoveryIndex,
} from "./backblaze-index.ts";
import {
  type ReconstructedGeneration,
  reconstructGeneration,
} from "./backblaze-recovery.ts";
import { type B2Object, B2Store } from "./backblaze-storage.ts";
import {
  createTransferPacer,
  getExactObjectWithRetry,
  uploadCapturedGeneration,
  type UploadResult,
  validateUploadCapture,
} from "./backblaze-upload.ts";
import {
  type DecryptedVerification,
  verifyDecryptedGeneration,
} from "./backblaze-verifier.ts";
import { withBackupLock } from "./backup-lock.ts";
import { shellQuote } from "./backup-guest.ts";

const INTENT = "operator-intent.json";
const PROVENANCE = "operator-provenance.json";
const STATUS = "operator-status.json";
const RESULT = "operator-result.json";
const ENTRY = "entry-operator.ts";
const MAX_JSON = 2 * 1024 * 1024;
const HASH = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
export const operatorHash = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");
const jsonBytes = (value: unknown) =>
  encoder.encode(`${JSON.stringify(value, null, 2)}\n`);
const decode = (bytes: Uint8Array): unknown =>
  JSON.parse(new TextDecoder().decode(bytes));
const jobPath = (jobId: string) =>
  `${BACKUP_BASE}/jobs/${validateJobId(jobId)}`;
const runtimePath = (jobId: string) =>
  `${JOBS_RUNTIME_ROOT}/${validateJobId(jobId)}`;

export interface OperatorIntent {
  schemaVersion: 1;
  envelope: WorkerRequestEnvelope;
  predecessorStatus: WorkerStatus;
  predecessorProof: GateClearProof;
  originalStatusSha256: string;
  originalRequestSha256: string;
  captureSha256: string;
  settingsSha256: string;
  executorRevision: string;
  executorManifestSha256: string;
  preparedAtUtc: string;
}
export interface OperatorProvenance {
  schemaVersion: 1;
  intent: OperatorIntent;
  intentSha256: string;
  invocationId: string;
  startedAtUtc: string;
}
export interface OperatorStatus {
  schemaVersion: 1;
  jobId: string;
  requestSha256: string;
  invocationId: string;
  provenanceSha256: string;
  state: "RUNNING" | "ACCEPTED" | "FAILED";
  phase: string;
  startedAtUtc: string;
  updatedAtUtc: string;
  heartbeatAtUtc: string;
  finishedAtUtc: string | null;
  resultSha256?: string;
}

function exactKeys(
  value: unknown,
  keys: string[],
): asserts value is Record<string, unknown> {
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    Object.keys(value).sort().join() !== keys.sort().join()
  ) throw new Error("Operator record has invalid fields");
}
function timestamp(value: unknown): string {
  if (
    typeof value !== "string" || !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) throw new Error("Operator timestamp invalid");
  return value;
}
function digest(value: unknown): string {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new Error("Operator hash invalid");
  }
  return value;
}
export function validateOperatorIntent(input: unknown): OperatorIntent {
  exactKeys(input, [
    "schemaVersion",
    "envelope",
    "predecessorStatus",
    "predecessorProof",
    "originalStatusSha256",
    "originalRequestSha256",
    "captureSha256",
    "settingsSha256",
    "executorRevision",
    "executorManifestSha256",
    "preparedAtUtc",
  ]);
  if (input.schemaVersion !== 1) {
    throw new Error("Operator intent version invalid");
  }
  const envelope = validateRequestEnvelope(input.envelope);
  const predecessorStatus = validateStatus(input.predecessorStatus);
  const request = envelope.request;
  if (
    predecessorStatus.state !== "FAILED" ||
    predecessorStatus.errorCode !== "UPLOAD_FAILED" ||
    predecessorStatus.jobId !== request.jobId ||
    predecessorStatus.requestSha256 !== envelope.requestSha256 ||
    predecessorStatus.generation !== request.generation ||
    predecessorStatus.requestedAtUtc !== request.requestedAtUtc ||
    predecessorStatus.deadlineAtUtc !== request.deadlineAtUtc
  ) {
    throw new Error(
      "Operator continuation requires bound FAILED upload predecessor",
    );
  }
  const gate = {
    ...deriveWorkerGate(request, envelope.requestSha256),
    unitInvocationId: predecessorStatus.invocationId,
  };
  const preparedAtUtc = timestamp(input.preparedAtUtc);
  const predecessorProof = validateGateClearProof(
    input.predecessorProof,
    gate,
    new Date(preparedAtUtc),
  );
  if (
    predecessorProof.statusState !== "FAILED" ||
    predecessorProof.statusFinishedAtUtc !== predecessorStatus.finishedAtUtc ||
    Date.parse(preparedAtUtc) >= Date.parse(request.deadlineAtUtc)
  ) throw new Error("Operator predecessor proof or deadline invalid");
  return {
    schemaVersion: 1,
    envelope,
    predecessorStatus,
    predecessorProof,
    originalStatusSha256: digest(input.originalStatusSha256),
    originalRequestSha256: digest(input.originalRequestSha256),
    captureSha256: digest(input.captureSha256),
    settingsSha256: digest(input.settingsSha256),
    executorRevision: validateRevision(input.executorRevision),
    executorManifestSha256: digest(input.executorManifestSha256),
    preparedAtUtc,
  };
}
export function validateOperatorProvenance(
  input: unknown,
  intent: OperatorIntent,
): OperatorProvenance {
  exactKeys(input, [
    "schemaVersion",
    "intent",
    "intentSha256",
    "invocationId",
    "startedAtUtc",
  ]);
  const bound = validateOperatorIntent(input.intent);
  if (
    input.schemaVersion !== 1 ||
    JSON.stringify(bound) !== JSON.stringify(validateOperatorIntent(intent)) ||
    input.intentSha256 !== operatorHash(jsonBytes(intent))
  ) throw new Error("Operator provenance intent drift");
  const invocationId = validateUnitInvocationId(input.invocationId);
  const startedAtUtc = timestamp(input.startedAtUtc);
  if (
    invocationId === intent.predecessorStatus.invocationId ||
    Date.parse(startedAtUtc) < Date.parse(intent.preparedAtUtc) ||
    Date.parse(startedAtUtc) >=
      Date.parse(intent.envelope.request.deadlineAtUtc)
  ) throw new Error("Operator invocation or start invalid");
  return {
    schemaVersion: 1,
    intent: bound,
    intentSha256: input.intentSha256 as string,
    invocationId,
    startedAtUtc,
  };
}
export function validateOperatorStatus(
  input: unknown,
  provenance: OperatorProvenance,
  provenanceSha256: string,
): OperatorStatus {
  const value = input as OperatorStatus;
  exactKeys(input, [
    "schemaVersion",
    "jobId",
    "requestSha256",
    "invocationId",
    "provenanceSha256",
    "state",
    "phase",
    "startedAtUtc",
    "updatedAtUtc",
    "heartbeatAtUtc",
    "finishedAtUtc",
    ...(value?.resultSha256 === undefined ? [] : ["resultSha256"]),
  ]);
  if (
    value.schemaVersion !== 1 ||
    value.jobId !== provenance.intent.envelope.request.jobId ||
    value.requestSha256 !== provenance.intent.envelope.requestSha256 ||
    value.invocationId !== provenance.invocationId ||
    value.provenanceSha256 !== digest(provenanceSha256) ||
    value.startedAtUtc !== provenance.startedAtUtc ||
    !["RUNNING", "ACCEPTED", "FAILED"].includes(value.state) ||
    typeof value.phase !== "string"
  ) throw new Error("Operator status identity invalid");
  const updated = Date.parse(timestamp(value.updatedAtUtc));
  const heartbeat = Date.parse(timestamp(value.heartbeatAtUtc));
  if (
    updated < Date.parse(value.startedAtUtc) || heartbeat > updated ||
    heartbeat < Date.parse(value.startedAtUtc)
  ) throw new Error("Operator status time invalid");
  if (value.state === "RUNNING") {
    if (value.finishedAtUtc !== null || value.resultSha256 !== undefined) {
      throw new Error("Running operator has terminal fields");
    }
  } else {
    if (value.finishedAtUtc !== value.updatedAtUtc) {
      throw new Error("Operator terminal time invalid");
    }
    timestamp(value.finishedAtUtc);
    if (
      value.state === "ACCEPTED" &&
      (Date.parse(value.finishedAtUtc) >
          Date.parse(provenance.intent.envelope.request.deadlineAtUtc) ||
        value.resultSha256 === undefined)
    ) throw new Error("Operator acceptance past deadline or missing result");
  }
  if (value.resultSha256 !== undefined) digest(value.resultSha256);
  return structuredClone(value);
}

async function ownedDir(path: string): Promise<void> {
  const info = await Deno.lstat(path);
  if (
    !info.isDirectory || info.isSymlink || info.uid !== 0 ||
    info.mode === null || (info.mode & 0o777) !== 0o700 ||
    await Deno.realPath(path) !== path
  ) throw new Error("Unsafe operator directory");
}
async function readOwned(path: string, limit = MAX_JSON): Promise<Uint8Array> {
  await ownedDir(path.slice(0, path.lastIndexOf("/")));
  const info = await Deno.lstat(path);
  if (
    !info.isFile || info.isSymlink || info.uid !== 0 || info.nlink !== 1 ||
    info.mode === null || (info.mode & 0o777) !== 0o600 || info.size > limit
  ) throw new Error("Unsafe operator evidence file");
  const bytes = await Deno.readFile(path);
  const after = await Deno.lstat(path);
  if (
    info.dev !== after.dev || info.ino !== after.ino ||
    bytes.byteLength !== info.size
  ) throw new Error("Operator evidence changed during read");
  return bytes;
}
async function createOwned(path: string, bytes: Uint8Array): Promise<void> {
  await ownedDir(path.slice(0, path.lastIndexOf("/")));
  try {
    using file = await Deno.open(path, {
      createNew: true,
      write: true,
      mode: 0o600,
    });
    let offset = 0;
    while (offset < bytes.length) {
      const count = await file.write(bytes.subarray(offset));
      if (count <= 0) throw new Error("Operator write stalled");
      offset += count;
    }
    await file.sync();
  } catch (error) {
    if (
      !(error instanceof Deno.errors.AlreadyExists) ||
      operatorHash(await readOwned(path)) !== operatorHash(bytes)
    ) throw error;
  }
}
async function replaceStatus(
  path: string,
  value: OperatorStatus,
): Promise<void> {
  const temp = `${path}.${crypto.randomUUID()}.tmp`;
  await createOwned(temp, jsonBytes(value));
  try {
    await readOwned(path);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  await Deno.rename(temp, path);
}
async function validateExecutor(
  intent: Pick<OperatorIntent, "executorRevision" | "executorManifestSha256">,
): Promise<void> {
  const release = `${RELEASES_ROOT}/${intent.executorRevision}`;
  const manifestBytes = await readOwned(`${release}/release.json`);
  if (operatorHash(manifestBytes) !== intent.executorManifestSha256) {
    throw new Error("Operator executor manifest drift");
  }
  const manifest = validateReleaseManifest(
    decode(manifestBytes),
    intent.executorRevision,
  );
  if (manifest.sourceRevision !== intent.executorRevision) {
    throw new Error("Operator executor revision drift");
  }
  for (const item of manifest.files) {
    if (
      operatorHash(
        await readOwned(`${release}/${item.path}`, 16 * MAX_JSON),
      ) !== item.sha256
    ) throw new Error("Operator executor source drift");
  }
  if (
    !manifest.files.some((item) =>
      item.path === "scripts/backblaze-operator-continuation.ts"
    )
  ) throw new Error("Operator executor module absent");
  if (
    new URL(import.meta.url).pathname !==
      `${release}/scripts/backblaze-operator-continuation.ts`
  ) throw new Error("Wrong operator executor loaded");
}
async function originals(
  intent: OperatorIntent,
  settings: TransportSettings,
): Promise<CaptureResult> {
  const request = intent.envelope.request;
  if (
    JSON.stringify(settings.envelope) !== JSON.stringify(intent.envelope) ||
    sourceConfigSha256(settings.captureSettings) !== request.sourceConfigSha256
  ) throw new Error("Original operator settings identity drift");
  const checks: [string, string][] = [
    [`${jobPath(request.jobId)}/status.json`, intent.originalStatusSha256],
    [`${jobPath(request.jobId)}/request.json`, intent.originalRequestSha256],
    [`${runtimePath(request.jobId)}/settings.json`, intent.settingsSha256],
    [
      `${BACKUP_BASE}/${request.generation}/capture-result.json`,
      intent.captureSha256,
    ],
  ];
  let captureBytes: Uint8Array | undefined;
  for (const [path, hash] of checks) {
    const bytes = await readOwned(path);
    if (operatorHash(bytes) !== hash) {
      throw new Error("Original operator artifact drift");
    }
    if (path.endsWith("capture-result.json")) captureBytes = bytes;
  }
  const capture = decode(captureBytes!) as CaptureResult;
  validateUploadCapture(capture);
  if (
    capture.generation !== request.generation ||
    capture.stageDirectory !== `${BACKUP_BASE}/${request.generation}` ||
    Date.parse(capture.startedAtUtc) < Date.parse(request.requestedAtUtc) ||
    Date.parse(capture.finishedAtUtc) < Date.parse(capture.startedAtUtc) ||
    Date.parse(capture.finishedAtUtc) >
      Date.parse(intent.predecessorStatus.finishedAtUtc!)
  ) throw new Error("Original captured generation drift");
  if (
    operatorHash(
      await readOwned(`${capture.stageDirectory}/recipient.asc`, 65536),
    ) !== request.recipientSha256
  ) throw new Error("Capture recipient drift");
  return capture;
}

/** Runs as a bounded metadata operation before the managed heavy unit. */
export async function prepareRemoteOperatorIntent(
  jobId: string,
  executorRevision: string,
  predecessorProof: GateClearProof,
  executorManifestSha256: string,
): Promise<OperatorIntent> {
  validateJobId(jobId);
  validateRevision(executorRevision);
  digest(executorManifestSha256);
  const { settings } = await loadRuntimeSettings();
  if (settings.envelope.request.jobId !== jobId) {
    throw new Error("Operator prepare job mismatch");
  }
  if (
    Date.now() - Date.parse(predecessorProof.checkedAtUtc) > 30000 ||
    Date.parse(predecessorProof.checkedAtUtc) > Date.now()
  ) throw new Error("Operator predecessor observation is stale");
  return await withBackupLock(SOURCE_LOCK_PATH, async () => {
    if (Date.now() - Date.parse(predecessorProof.checkedAtUtc) > 30000) {
      throw new Error(
        "Operator predecessor observation expired waiting for source lock",
      );
    }
    const statusBytes = await readOwned(`${jobPath(jobId)}/status.json`);
    const requestBytes = await readOwned(`${jobPath(jobId)}/request.json`);
    if (
      new TextDecoder().decode(requestBytes) !==
        canonicalRequestString(settings.envelope.request)
    ) throw new Error("Original request bytes mismatch");
    const intent = validateOperatorIntent({
      schemaVersion: 1,
      envelope: settings.envelope,
      predecessorStatus: decode(statusBytes),
      predecessorProof,
      originalStatusSha256: operatorHash(statusBytes),
      originalRequestSha256: operatorHash(requestBytes),
      captureSha256: operatorHash(
        await readOwned(
          `${BACKUP_BASE}/${settings.envelope.request.generation}/capture-result.json`,
        ),
      ),
      settingsSha256: operatorHash(
        await readOwned(`${runtimePath(jobId)}/settings.json`),
      ),
      executorRevision,
      executorManifestSha256,
      preparedAtUtc: new Date().toISOString(),
    });
    await validateExecutor(intent);
    await originals(intent, settings);
    await createOwned(`${jobPath(jobId)}/${INTENT}`, jsonBytes(intent));
    return intent;
  });
}

export interface PayloadOperations {
  upload(capture: CaptureResult): Promise<UploadResult>;
  publish(
    capture: CaptureResult,
    upload: UploadResult,
    recipient: IndexRecipient,
  ): Promise<PublishedIndex>;
  get(object: B2Object): Promise<Uint8Array>;
  release(capture: CaptureResult, index: RecoveryIndex): Promise<void>;
  reconstruct(index: RecoveryIndex): Promise<ReconstructedGeneration>;
  verify(
    index: RecoveryIndex,
    reconstruction: ReconstructedGeneration,
  ): Promise<DecryptedVerification>;
  checkpoint(phase: string): Promise<void>;
}
/** No capture callback exists. Existing uploader rehashes all archives and
 * reconciles every saved chunk against fresh cloud inventory/readback. */
export async function executeOperatorPayload(
  capture: CaptureResult,
  recipient: IndexRecipient,
  operations: PayloadOperations,
): Promise<Omit<CatalogEntry, "acceptedAtUtc">> {
  validateUploadCapture(capture);
  await operations.checkpoint("upload");
  const upload = await operations.upload(capture);
  const index = buildRecoveryIndex(capture, upload, recipient);
  await operations.checkpoint("publish");
  const publishedIndex = await operations.publish(capture, upload, recipient);
  if (
    publishedIndex.generation !== capture.generation ||
    publishedIndex.indexSha256 !==
      operatorHash(encoder.encode(JSON.stringify(index))) ||
    !publishedIndex.uploadVerified ||
    operatorHash(await operations.get(publishedIndex.object)) !==
      publishedIndex.ciphertextSha256
  ) throw new Error("Operator cloud publication proof failed");
  await operations.checkpoint("release-source-cache");
  await operations.release(capture, index);
  await operations.checkpoint("reconstruct");
  const reconstruction = await operations.reconstruct(index);
  await operations.checkpoint("verify");
  const receipt = await operations.verify(index, reconstruction);
  const entry = validateCatalogEntry({
    index,
    publishedIndex,
    receipt,
    acceptedAtUtc: receipt.verifiedAtUtc,
  });
  return {
    index: entry.index,
    publishedIndex: entry.publishedIndex,
    receipt: entry.receipt,
  };
}

/** Fixed production source entry. Must be launched through the Pi supervisor
 * with the real unit's original-deadline RuntimeMaxSec and resource limits. */
export async function runRemoteOperatorContinuation(
  jobIdInput: unknown,
): Promise<OperatorStatus> {
  const jobId = validateJobId(jobIdInput);
  const { settings, recipientBytes } = await loadRuntimeSettings();
  const intent = validateOperatorIntent(
    decode(await readOwned(`${jobPath(jobId)}/${INTENT}`)),
  );
  if (intent.envelope.request.jobId !== jobId) {
    throw new Error("Operator job mismatch");
  }
  await validateExecutor(intent);
  const invocationId = validateUnitInvocationId(Deno.env.get("INVOCATION_ID"));
  return await withBackupLock(SOURCE_LOCK_PATH, async () => {
    const capture = await originals(intent, settings);
    const provenance = validateOperatorProvenance({
      schemaVersion: 1,
      intent,
      intentSha256: operatorHash(jsonBytes(intent)),
      invocationId,
      startedAtUtc: new Date().toISOString(),
    }, intent);
    const provenanceBytes = jsonBytes(provenance);
    const provenanceSha256 = operatorHash(provenanceBytes);
    await createOwned(`${jobPath(jobId)}/${PROVENANCE}`, provenanceBytes);
    let phase = "starting";
    let serial = Promise.resolve();
    const status = (
      state: OperatorStatus["state"],
      resultSha256?: string,
    ): OperatorStatus => {
      const at = new Date().toISOString();
      return validateOperatorStatus(
        {
          schemaVersion: 1,
          jobId,
          requestSha256: intent.envelope.requestSha256,
          invocationId,
          provenanceSha256,
          state,
          phase,
          startedAtUtc: provenance.startedAtUtc,
          updatedAtUtc: at,
          heartbeatAtUtc: at,
          finishedAtUtc: state === "RUNNING" ? null : at,
          ...(resultSha256 === undefined ? {} : { resultSha256 }),
        },
        provenance,
        provenanceSha256,
      );
    };
    const checkpoint = async (next: string) => {
      if (Date.now() >= Date.parse(intent.envelope.request.deadlineAtUtc)) {
        throw new Error("Operator original deadline expired");
      }
      phase = next;
      serial = serial.then(() =>
        replaceStatus(`${jobPath(jobId)}/${STATUS}`, status("RUNNING"))
      );
      await serial;
    };
    const heartbeat = setInterval(() => {
      serial = serial.then(() =>
        replaceStatus(`${jobPath(jobId)}/${STATUS}`, status("RUNNING"))
      ).catch(() => {});
    }, 30000);
    try {
      await checkpoint("starting");
      const deadline = AbortSignal.timeout(
        Math.max(
          1,
          Date.parse(intent.envelope.request.deadlineAtUtc) - Date.now(),
        ),
      );
      const raw = new B2Store(
        settings.B2Settings,
        (url, init) =>
          fetch(url, {
            ...init,
            signal: AbortSignal.any([
              deadline,
              ...(init?.signal ? [init.signal] : []),
            ]),
          }),
      );
      const pace = createTransferPacer();
      const readStore = {
        async get(object: B2Object) {
          const bytes = await getExactObjectWithRetry(raw, object, {
            phase: "verify",
          });
          await pace(bytes.length);
          return bytes;
        },
      };
      const publicHome = `${PUBLIC_HOME_BASE}/${capture.generation}`;
      await ensurePublicHome(publicHome);
      await importRecipient(publicHome, recipientBytes);
      const recoveryDir = `${RECOVERY_BASE}/${capture.generation}`;
      const verificationDir = `${VERIFICATION_BASE}/${capture.generation}`;
      const result = await executeOperatorPayload(
        capture,
        settings.indexRecipient,
        {
          upload: (value) => uploadCapturedGeneration(value, raw),
          publish: (value, upload, recipient) =>
            publishRecoveryIndex(value, upload, recipient, raw),
          get: readStore.get,
          checkpoint,
          async release(value, index) {
            await originals(intent, settings);
            await createOwned(
              `${jobPath(jobId)}/operator-capture-metadata.json`,
              jsonBytes({ capture: value, index, provenanceSha256 }),
            );
            const files: {
              path: string;
              dev: number | null;
              ino: number | null;
            }[] = [];
            for (const archive of value.archives) {
              const info = await Deno.lstat(archive.path);
              if (
                !info.isFile || info.isSymlink || info.uid !== 0 ||
                info.nlink !== 1 || info.size !== archive.bytes ||
                info.mode === null || (info.mode & 0o777) !== 0o600 ||
                await Deno.realPath(archive.path) !== archive.path
              ) throw new Error("Unsafe source cipher release");
              const hash = createHash("sha256");
              using file = await Deno.open(archive.path, { read: true });
              const buffer = new Uint8Array(1024 * 1024);
              for (;;) {
                const count = await file.read(buffer);
                if (count === null) break;
                if (count === 0) {
                  throw new Error("Source ciphertext hash stalled");
                }
                hash.update(buffer.subarray(0, count));
              }
              if (hash.digest("hex") !== archive.sha256) {
                throw new Error("Source ciphertext drift before release");
              }
              files.push({ path: archive.path, dev: info.dev, ino: info.ino });
            }
            await checkpoint("release-source-cache");
            for (const file of files) {
              const info = await Deno.lstat(file.path);
              if (
                info.dev !== file.dev || info.ino !== file.ino
              ) {
                throw new Error("Source ciphertext replaced before release");
              }
              await Deno.remove(file.path);
            }
            for (const path of [RECOVERY_BASE, VERIFICATION_BASE]) {
              try {
                await Deno.mkdir(path, { mode: 0o700 });
              } catch (error) {
                if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
              }
              await ownedDir(path);
            }
            await Deno.mkdir(recoveryDir, { mode: 0o700 });
            await assertVerifierHeadroom(
              recoveryDir,
              verificationDir,
              verifierHeadroomRequirement(index, false),
            );
          },
          reconstruct: (index) =>
            reconstructGeneration(index, readStore, recoveryDir),
          async verify(index, reconstruction) {
            await Deno.mkdir(verificationDir, { mode: 0o700 });
            await assertVerifierHeadroom(
              recoveryDir,
              verificationDir,
              verifierHeadroomRequirement(index, true),
            );
            return await verifyDecryptedGeneration(
              index,
              reconstruction,
              verificationDir,
              makeDecryptArchive(publicHome),
            );
          },
        },
      );
      await checkpoint("complete");
      const resultBytes = jsonBytes(result);
      await createOwned(`${jobPath(jobId)}/${RESULT}`, resultBytes);
      clearInterval(heartbeat);
      await serial;
      const accepted = status("ACCEPTED", operatorHash(resultBytes));
      await replaceStatus(`${jobPath(jobId)}/${STATUS}`, accepted);
      return accepted;
    } catch {
      clearInterval(heartbeat);
      await serial.catch(() => {});
      const failed = status("FAILED");
      await replaceStatus(`${jobPath(jobId)}/${STATUS}`, failed);
      Deno.exitCode = 1;
      return failed;
    } finally {
      clearInterval(heartbeat);
    }
  });
}

async function remoteJson(deps: PiDeps, path: string): Promise<Uint8Array> {
  const command = `p=${
    shellQuote(path)
  }\ntest "$(stat -c %u "$p")" = 0\ntest "$(stat -c %a "$p")" = 600\ntest "$(stat -c %h "$p")" = 1\ntest -f "$p"\ntest ! -L "$p"\ntest "$(readlink -f "$p")" = "$p"\ntest "$(stat -c %s "$p")" -le ${MAX_JSON}\ncat "$p"`;
  const result = await deps.remote.root(command);
  if (result.code !== 0) {
    throw new Error("Operator bounded remote evidence unavailable");
  }
  return encoder.encode(result.stdout);
}
function localIntentPath(jobId: string): string {
  return `.private/file-backup/jobs/${jobId}/${INTENT}`;
}
export function importOperatorRecovery(
  stateInput: ControllerState,
  provenance: OperatorProvenance,
  provenanceSha256: string,
  statusInput: OperatorStatus,
  resultBytes: Uint8Array,
): ControllerState {
  const state = validateControllerState(stateInput);
  const status = validateOperatorStatus(
    statusInput,
    provenance,
    provenanceSha256,
  );
  if (
    status.state !== "ACCEPTED" ||
    operatorHash(resultBytes) !== status.resultSha256 ||
    state.job?.phase !== "FAILED" ||
    state.job.envelope.requestSha256 !==
      provenance.intent.envelope.requestSha256 ||
    JSON.stringify(state.job.workerStatus) !==
      JSON.stringify(provenance.intent.predecessorStatus)
  ) throw new Error("Operator catalog import trust mismatch");
  const result = decode(resultBytes) as Omit<CatalogEntry, "acceptedAtUtc">;
  const entry = validateCatalogEntry({
    ...result,
    acceptedAtUtc: status.finishedAtUtc,
  });
  if (
    entry.index.generation !== provenance.intent.envelope.request.generation ||
    entry.index.recipientSha256 !==
      provenance.intent.envelope.request.recipientSha256 ||
    entry.index.recipientFingerprint !==
      provenance.intent.envelope.request.recipientFingerprint
  ) throw new Error("Operator receipt generation mismatch");
  const receiptSha256 = operatorHash(jsonBytes(entry.receipt));
  const catalog = state.catalog.filter((old) =>
    old.index.generation !== entry.index.generation
  );
  if (
    catalog.length !== state.catalog.length &&
    state.job.operatorRecovery?.provenanceSha256 !== provenanceSha256
  ) throw new Error("Operator catalog overwrite refused");
  return validateControllerState({
    ...state,
    catalog: [...catalog, entry],
    job: {
      ...state.job,
      operatorRecovery: {
        provenanceSha256,
        invocationId: status.invocationId,
        receiptSha256,
        indexSha256: entry.publishedIndex.indexSha256,
        acceptedAtUtc: entry.acceptedAtUtc,
      },
    },
  });
}

/** Runnable Pi orchestration; resume the SAME intent/unit after transport
 * uncertainty. Never relaunch a bound gate. The tunnel closes only after
 * terminal zero-process/source-lock proof or an unlaunched unit. */
export async function runOperatorContinuation(
  jobIdInput: unknown,
  executorRevisionInput: unknown,
  executorManifestSha256: string,
  deps: PiDeps = realPiDeps(),
): Promise<ControllerState> {
  const jobId = validateJobId(jobIdInput);
  const executorRevision = validateRevision(executorRevisionInput);
  digest(executorManifestSha256);
  return await deps.lock(CONTROLLER_LOCK_PATH, async () => {
    let state = validateControllerState(
      await deps.private.read(CONTROLLER_STATE_PATH),
    );
    if (
      state.job?.envelope.request.jobId !== jobId ||
      state.job.phase !== "FAILED" || state.job.workerStatus?.state !== "FAILED"
    ) throw new Error("Operator predecessor controller not FAILED");
    const request = state.job.envelope.request;
    const unitName = verifyUnitName(request.generation);
    let intent = await deps.private.read<OperatorIntent>(
      localIntentPath(jobId),
    );
    let gate = await deps.gate.read();
    if (intent === undefined) {
      if (gate !== null) {
        throw new Error("Operator predecessor gate still present");
      }
      const existing = await deps.remote.root(
        `p=${
          shellQuote(`${jobPath(jobId)}/${INTENT}`)
        }\nif test ! -e "$p" && test ! -L "$p"; then echo __MISSING__; else echo __PRESENT__; fi`,
      );
      if (existing.code !== 0) {
        throw new Error("Operator root intent presence unknown");
      }
      if (existing.stdout.trim() === "__PRESENT__") {
        intent = validateOperatorIntent(
          decode(await remoteJson(deps, `${jobPath(jobId)}/${INTENT}`)),
        );
        await deps.private.write(localIntentPath(jobId), intent);
        await deps.private.write(
          `.private/file-backup/jobs/${jobId}/operator-failed-controller.json`,
          state,
        );
      } else if (existing.stdout.trim() !== "__MISSING__") {
        throw new Error("Operator root intent presence ambiguous");
      }
    }
    if (intent === undefined) {
      const observed = await deps.remote.observe(
        workerUnitName(request.generation),
        jobId,
      );
      if (!observed.reachable) {
        throw new Error("Operator predecessor unreachable");
      }
      const status = validateStatus(observed.status);
      if (JSON.stringify(status) !== JSON.stringify(state.job.workerStatus)) {
        throw new Error("Operator predecessor changed");
      }
      const predecessorGate = {
        ...deriveWorkerGate(request, state.job.envelope.requestSha256),
        unitInvocationId: status.invocationId,
      };
      const proof = buildClearProof(
        {
          props: observed.props,
          lockFree: observed.lockFree,
          checkedAtUtc: deps.now().toISOString(),
        },
        predecessorGate,
        status.state,
        status,
      ) as GateClearProof;
      const call = `const m=await import(${
        JSON.stringify(
          `${RELEASES_ROOT}/${executorRevision}/scripts/backblaze-operator-continuation.ts`,
        )
      }); console.log(JSON.stringify(await m.prepareRemoteOperatorIntent(${
        JSON.stringify(jobId)
      },${JSON.stringify(executorRevision)},${JSON.stringify(proof)},${
        JSON.stringify(executorManifestSha256)
      })));`;
      const prepared = await deps.remote.root(
        `cd ${shellQuote(runtimePath(jobId))}\n/usr/local/bin/deno eval ${
          shellQuote(call)
        }`,
      );
      if (prepared.code !== 0) {
        throw new Error("Operator intent preparation failed");
      }
      intent = validateOperatorIntent(JSON.parse(prepared.stdout));
      await deps.private.write(localIntentPath(jobId), intent);
      await deps.private.write(
        `.private/file-backup/jobs/${jobId}/operator-failed-controller.json`,
        state,
      );
    }
    intent = validateOperatorIntent(intent);
    if (
      intent.executorRevision !== executorRevision ||
      intent.executorManifestSha256 !== executorManifestSha256 ||
      intent.envelope.requestSha256 !== state.job.envelope.requestSha256
    ) throw new Error("Operator immutable intent differs");
    if (
      operatorHash(await remoteJson(deps, `${jobPath(jobId)}/${INTENT}`)) !==
        operatorHash(jsonBytes(intent))
    ) throw new Error("Operator remote intent drift");
    if (gate === null && state.job.operatorRecovery !== undefined) return state;
    let settled = false;
    let mayHaveLaunched = gate !== null;
    try {
      const publicHome = `${PUBLIC_HOME_BASE}/${request.generation}`;
      const socket = await deps.remote.resolveAgentSocket(publicHome);
      await deps.tunnel.open(socket.socket);
      if (gate === null && state.job.operatorRecovery === undefined) {
        const before = await deps.remote.observe(unitName, jobId);
        if (
          !before.reachable || before.props.get("LoadState") !== "not-found"
        ) {
          throw new Error(
            "Operator verify unit already exists; reconcile exact terminal unit first",
          );
        }
        const remainingSec = Math.floor(
          (Date.parse(request.deadlineAtUtc) - deps.now().getTime()) / 1000,
        );
        if (remainingSec < 1) {
          throw new Error("Operator original deadline expired");
        }
        const wrapper = encoder.encode(
          `import { runRemoteOperatorContinuation } from "${RELEASES_ROOT}/${executorRevision}/scripts/backblaze-operator-continuation.ts"; await runRemoteOperatorContinuation("${jobId}");\n`,
        );
        const install = `const p=${
          JSON.stringify(`${runtimePath(jobId)}/${ENTRY}`)
        }; const b=new Uint8Array(${
          JSON.stringify(Array.from(wrapper))
        }); try{await Deno.writeFile(p,b,{createNew:true,mode:0o600});}catch(e){if(!(e instanceof Deno.errors.AlreadyExists))throw e; const a=await Deno.readFile(p);if(a.length!==b.length||a.some((v,i)=>v!==b[i]))throw Error("Operator wrapper differs");}`;
        const installed = await deps.remote.root(
          `/usr/local/bin/deno eval ${shellQuote(install)}`,
        );
        if (installed.code !== 0) {
          throw new Error("Operator wrapper install failed");
        }
        const derived = deriveVerifierGate(
          request,
          intent.envelope.requestSha256,
        );
        await deps.gate.create(derived);
        gate = derived;
        // An ambiguous response never permits a second launch. Reconcile only.
        mayHaveLaunched = true;
        try {
          await deps.remote.launchUnit({
            unitName,
            runtimeDir: runtimePath(jobId),
            remainingSec,
            args: [
              "/usr/local/bin/deno",
              "run",
              `--allow-read=${BACKUP_BASE},${JOBS_RUNTIME_ROOT},${RELEASES_ROOT},${PUBLIC_HOME_BASE},${RECOVERY_BASE},${VERIFICATION_BASE},/etc/passwd`,
              `--allow-write=${BACKUP_BASE},${PUBLIC_HOME_BASE},${RECOVERY_BASE},${VERIFICATION_BASE}`,
              "--allow-run=gpg,sudo,tar,zstd,df,chown,bash",
              "--allow-net",
              "--allow-env=INVOCATION_ID",
              `${runtimePath(jobId)}/${ENTRY}`,
            ],
          });
        } catch {
          deps.logger(
            "Operator launch response unavailable; reconciling exact unit",
          );
        }
      }
      for (;;) {
        const observed = await deps.remote.observe(unitName, jobId);
        if (!observed.reachable) {
          throw new Error("Operator source unreachable; gate retained");
        }
        const actual = observed.props.get("InvocationID");
        if (!actual) {
          throw new Error(
            "Operator unit invocation unavailable; gate retained",
          );
        }
        if (actual === intent.predecessorStatus.invocationId) {
          throw new Error("Operator adopted predecessor invocation");
        }
        gate = await deps.gate.read();
        if (gate === null) {
          if (state.job.operatorRecovery !== undefined) {
            settled = true;
            return state;
          }
          throw new Error("Operator gate vanished");
        }
        if (
          gate.unitName !== unitName ||
          gate.requestSha256 !== intent.envelope.requestSha256 ||
          gate.jobId !== jobId
        ) throw new Error("Operator gate changed");
        let provenanceBytes: Uint8Array;
        try {
          provenanceBytes = await remoteJson(
            deps,
            `${jobPath(jobId)}/${PROVENANCE}`,
          );
        } catch (error) {
          if (
            observed.props.get("ActiveState") === "active" &&
            observed.props.get("SubState") === "running" &&
            deps.now().getTime() < Date.parse(request.deadlineAtUtc)
          ) {
            await deps.sleep(1000);
            continue;
          }
          throw error;
        }
        const provenance = validateOperatorProvenance(
          decode(provenanceBytes),
          intent,
        );
        if (provenance.invocationId !== actual) {
          throw new Error("Operator actual invocation differs from provenance");
        }
        const provenanceSha256 = operatorHash(provenanceBytes);
        let statusBytes: Uint8Array;
        try {
          statusBytes = await remoteJson(deps, `${jobPath(jobId)}/${STATUS}`);
        } catch (error) {
          if (
            observed.props.get("ActiveState") === "active" &&
            observed.props.get("SubState") === "running" &&
            deps.now().getTime() < Date.parse(request.deadlineAtUtc)
          ) {
            await deps.sleep(1000);
            continue;
          }
          throw error;
        }
        const status = validateOperatorStatus(
          decode(statusBytes),
          provenance,
          provenanceSha256,
        );
        gate = await deps.gate.bind(gate, actual);
        await deps.private.writeBytes(
          `.private/file-backup/jobs/${jobId}/${PROVENANCE}`,
          provenanceBytes,
        );
        await deps.private.writeBytes(
          `.private/file-backup/jobs/${jobId}/${STATUS}`,
          statusBytes,
        );
        if (status.state === "RUNNING") {
          if (deps.now().getTime() > Date.parse(request.deadlineAtUtc)) {
            throw new Error(
              "Operator deadline expired; inspect bound unit/gate",
            );
          }
          await deps.sleep(30000);
          continue;
        }
        if (
          !observed.lockFree || observed.props.get("MainPID") !== "0" ||
          observed.props.get("ControlPID") !== "0"
        ) {
          if (deps.now().getTime() >= Date.parse(request.deadlineAtUtc)) {
            throw new Error(
              "Operator terminal process settlement exceeded original deadline; gate retained",
            );
          }
          await deps.sleep(1000);
          continue;
        }
        const normal = buildClearProof(
          {
            props: observed.props,
            lockFree: observed.lockFree,
            checkedAtUtc: deps.now().toISOString(),
          },
          gate,
          status.state,
          status,
        ) as GateClearProof;
        const proof = {
          ...normal,
          statusPath: `${jobPath(jobId)}/${STATUS}`,
          operatorProvenanceSha256: provenanceSha256,
        };
        const binding: OperatorProofBinding = {
          provenanceSha256,
          jobId,
          requestSha256: intent.envelope.requestSha256,
          invocationId: actual,
        };
        validateGateClearProof(proof, gate, deps.now(), binding);
        if (
          operatorHash(
              await remoteJson(deps, `${jobPath(jobId)}/status.json`),
            ) !== intent.originalStatusSha256 ||
          operatorHash(
              await remoteJson(deps, `${jobPath(jobId)}/request.json`),
            ) !== intent.originalRequestSha256
        ) throw new Error("Original failed identity changed");
        if (status.state === "ACCEPTED") {
          const resultBytes = await remoteJson(
            deps,
            `${jobPath(jobId)}/${RESULT}`,
          );
          const next = importOperatorRecovery(
            state,
            provenance,
            provenanceSha256,
            status,
            resultBytes,
          );
          await deps.private.writeBytes(
            `.private/file-backup/jobs/${jobId}/${RESULT}`,
            resultBytes,
          );
          await deps.private.write(CONTROLLER_STATE_PATH, next);
          state = next;
        }
        await clearGateAfterProof(gate, proof, undefined, deps.now(), binding);
        settled = true;
        if (status.state === "FAILED") {
          throw new Error(
            "Operator continuation FAILED; original attempt and catalog preserved",
          );
        }
        return state;
      }
    } finally {
      if (settled || !mayHaveLaunched) await deps.tunnel.close();
    }
  });
}
