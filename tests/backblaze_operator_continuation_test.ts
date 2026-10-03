import { createHash } from "node:crypto";
import {
  deriveWorkerGate,
  type WorkerStatus,
} from "../scripts/backblaze-source-worker.ts";
import {
  type GateClearProof,
  validateGateClearProof,
} from "../scripts/backblaze-controller-contract.ts";
import {
  assessBackblazeWatchdog,
  buildRequestEnvelope,
  type ControllerState,
  deriveVerifierGate,
  validateControllerState,
} from "../scripts/backblaze-file-backup.ts";
import {
  buildRecoveryIndex,
  type PublishedIndex,
} from "../scripts/backblaze-index.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
  type UploadResult,
} from "../scripts/backblaze-upload.ts";
import type { CaptureResult } from "../scripts/backblaze-capture.ts";
import type { DecryptedVerification } from "../scripts/backblaze-verifier.ts";
import {
  executeOperatorPayload,
  importOperatorRecovery,
  operatorHash,
  type OperatorStatus,
  validateOperatorIntent,
  validateOperatorProvenance,
  validateOperatorStatus,
} from "../scripts/backblaze-operator-continuation.ts";

const uuid = "8ffc28a8-fc35-4a98-8328-5490a713725f";
const generation = `generation-${uuid}`;
const jobId = `job-${uuid}`;
const oldInvocation = "1".repeat(32);
const invocationId = "2".repeat(32);
const sha = "a".repeat(64);
const encoder = new TextEncoder();
const bytes = (input: unknown) =>
  encoder.encode(`${JSON.stringify(input, null, 2)}\n`);
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function rejects(call: () => unknown): void {
  let failed = false;
  try {
    call();
  } catch {
    failed = true;
  }
  assert(failed);
}
async function rejectsAsync(call: () => Promise<unknown>): Promise<void> {
  let failed = false;
  try {
    await call();
  } catch {
    failed = true;
  }
  assert(failed);
}
function fixture() {
  const envelope = buildRequestEnvelope({
    jobUuid: uuid,
    periodKey: "2026-09-27",
    requestedAtUtc: "2026-10-03T04:21:00.000Z",
    recipientSha256: sha,
    recipientFingerprint: "B".repeat(40),
    sourceRevision: "1".repeat(40),
    sourceConfigSha256: sha,
  });
  const predecessorStatus: WorkerStatus = {
    schemaVersion: 1,
    jobId,
    periodKey: envelope.request.periodKey,
    generation,
    requestSha256: envelope.requestSha256,
    invocationId: oldInvocation,
    requestedAtUtc: envelope.request.requestedAtUtc,
    deadlineAtUtc: envelope.request.deadlineAtUtc,
    state: "FAILED",
    startedAtUtc: "2026-10-03T04:21:00.000Z",
    updatedAtUtc: "2026-10-03T08:02:50.460Z",
    heartbeatAtUtc: "2026-10-03T08:02:50.460Z",
    finishedAtUtc: "2026-10-03T08:02:50.460Z",
    errorCode: "UPLOAD_FAILED",
  };
  const predecessorProof: GateClearProof = {
    checkedAtUtc: "2026-10-03T08:30:00.000Z",
    unitName:
      deriveWorkerGate(envelope.request, envelope.requestSha256).unitName,
    unitInvocationId: oldInvocation,
    unitLoadState: "loaded",
    unitActiveState: "active",
    unitSubState: "exited",
    unitResult: "success",
    mainPid: 0,
    controlPid: 0,
    controlGroup: "",
    tasksCurrent: null,
    statusPath: `/var/tmp/arch-vps-file-backup/jobs/${jobId}/status.json`,
    statusState: "FAILED",
    statusJobId: jobId,
    statusPeriodKey: envelope.request.periodKey,
    statusGeneration: generation,
    statusRequestSha256: envelope.requestSha256,
    statusInvocationId: oldInvocation,
    statusUpdatedAtUtc: predecessorStatus.updatedAtUtc,
    statusHeartbeatAtUtc: predecessorStatus.heartbeatAtUtc,
    statusFinishedAtUtc: predecessorStatus.finishedAtUtc,
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
    sourceLockFree: true,
    clearBasis: "terminal",
  };
  const intent = validateOperatorIntent({
    schemaVersion: 1,
    envelope,
    predecessorStatus,
    predecessorProof,
    originalStatusSha256: sha,
    originalRequestSha256: sha,
    captureSha256: sha,
    settingsSha256: sha,
    executorRevision: "3".repeat(40),
    executorManifestSha256: sha,
    preparedAtUtc: predecessorProof.checkedAtUtc,
  });
  const provenance = validateOperatorProvenance({
    schemaVersion: 1,
    intent,
    intentSha256: operatorHash(bytes(intent)),
    invocationId,
    startedAtUtc: "2026-10-03T08:31:00.000Z",
  }, intent);
  const provenanceSha256 = operatorHash(bytes(provenance));
  const stageDirectory = `/var/tmp/arch-vps-file-backup/${generation}`;
  const capture = {
    generation,
    stageDirectory,
    consistency: "live-file-copy",
    sourceShutdown: false,
    startedAtUtc: "2026-10-03T04:22:00.000Z",
    finishedAtUtc: "2026-10-03T05:00:00.000Z",
    archives: UPLOAD_ROLE_ORDER.map((role) => {
      const format = role === "recovery"
        ? "json.zst.gpg" as const
        : "tar.zst.gpg" as const;
      return {
        role,
        format,
        path: `${stageDirectory}/${role}.${format}`,
        bytes: 64,
        sha256: sha,
      };
    }),
  } satisfies CaptureResult;
  const upload: UploadResult = {
    generation,
    stageDirectory,
    archives: capture.archives.map((archive, index) => {
      const name = generationChunkName(generation, archive.role, 0);
      const sha1 = createHash("sha1").update(name).digest("hex");
      const fileId = `fixture-file-${index}`;
      const uploadTimestamp = Date.parse("2026-10-03T09:00:00.000Z") + index;
      return {
        ...archive,
        verifiedAtUtc: "2026-10-03T09:01:00.000Z",
        chunks: [{
          role: archive.role,
          index: 0,
          name,
          size: archive.bytes,
          sha256: archive.sha256,
          sha1,
          fileId,
          uploadTimestamp,
          verifiedAtUtc: "2026-10-03T09:01:00.000Z",
          reused: true,
          versions: [{
            fileId,
            fileName: name,
            contentLength: archive.bytes,
            contentSha1: sha1,
            action: "upload" as const,
            uploadTimestamp,
          }],
        }],
      };
    }),
    chunkCount: 7,
    totalBytes: 448,
    duplicateVersions: [],
    startedAtUtc: "2026-10-03T05:01:00.000Z",
    finishedAtUtc: "2026-10-03T09:01:00.000Z",
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  const recipient = {
    recipientFile: "/tmp/recipient.asc",
    recipientSha256: sha,
    recipientFingerprint: "B".repeat(40),
  };
  const index = buildRecoveryIndex(capture, upload, recipient);
  const indexSha256 = operatorHash(encoder.encode(JSON.stringify(index)));
  const ciphertext = encoder.encode("fixture encrypted index");
  const publishedIndex: PublishedIndex = {
    generation,
    object: {
      fileId: "fixture-index",
      fileName: `arch-direct/indexes/${generation}/index.json.gpg`,
      contentLength: ciphertext.length,
      contentSha1: createHash("sha1").update(ciphertext).digest("hex"),
      action: "upload",
      uploadTimestamp: Date.parse(upload.finishedAtUtc),
    },
    ciphertextBytes: ciphertext.length,
    ciphertextSha256: operatorHash(ciphertext),
    indexSha256,
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  const receipt: DecryptedVerification = {
    schemaVersion: 1,
    generation,
    indexSha256,
    recipientSha256: sha,
    recipientFingerprint: recipient.recipientFingerprint,
    verifiedAtUtc: "2026-10-03T10:00:00.000Z",
    metadataSha256: sha,
    archives: capture.archives.map((archive) => ({
      role: archive.role,
      format: archive.format,
      ciphertextBytes: archive.bytes,
      ciphertextSha256: archive.sha256,
      compressedBytes: 32,
      compressedSha256: sha,
      ...(archive.role === "recovery" ? {} : { entries: 1 }),
    })),
    bootSamples: [{
      role: "root",
      member: "./boot/Image",
      bytes: 1,
      sha256: sha,
    }, {
      role: "root",
      member: "./boot/initramfs-linux.img",
      bytes: 1,
      sha256: sha,
    }, {
      role: "staging-boot",
      member: "./arch-vmlinuz",
      bytes: 1,
      sha256: sha,
    }, {
      role: "staging-boot",
      member: "./arch-initrd.img",
      bytes: 1,
      sha256: sha,
    }],
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
  const result = { index, publishedIndex, receipt };
  const status: OperatorStatus = {
    schemaVersion: 1,
    jobId,
    requestSha256: envelope.requestSha256,
    invocationId,
    provenanceSha256,
    state: "ACCEPTED",
    phase: "complete",
    startedAtUtc: provenance.startedAtUtc,
    updatedAtUtc: receipt.verifiedAtUtc,
    heartbeatAtUtc: receipt.verifiedAtUtc,
    finishedAtUtc: receipt.verifiedAtUtc,
    resultSha256: operatorHash(bytes(result)),
  };
  const state: ControllerState = validateControllerState({
    schemaVersion: 1,
    catalog: [],
    job: {
      envelope,
      phase: "FAILED",
      updatedAtUtc: predecessorStatus.updatedAtUtc,
      heartbeatAtUtc: predecessorStatus.heartbeatAtUtc,
      workerInvocationId: oldInvocation,
      verifierInvocationId: null,
      workerStatus: predecessorStatus,
      failure: { code: "UPLOAD_FAILED", atUtc: predecessorStatus.updatedAtUtc },
    },
  });
  return {
    intent,
    provenance,
    provenanceSha256,
    capture,
    upload,
    recipient,
    index,
    publishedIndex,
    ciphertext,
    receipt,
    result,
    status,
    state,
  };
}

Deno.test("operator continuation refuses active or non-upload predecessor and identity drift", () => {
  const f = fixture();
  rejects(() =>
    validateOperatorIntent({
      ...f.intent,
      predecessorStatus: {
        ...f.intent.predecessorStatus,
        state: "UPLOADING",
        errorCode: undefined,
        finishedAtUtc: null,
      },
    })
  );
  rejects(() =>
    validateOperatorIntent({
      ...f.intent,
      predecessorProof: { ...f.intent.predecessorProof, mainPid: 123 },
    })
  );
  rejects(() =>
    validateOperatorIntent({
      ...f.intent,
      predecessorProof: { ...f.intent.predecessorProof, sourceLockFree: false },
    })
  );
  rejects(() =>
    validateOperatorProvenance(
      { ...f.provenance, invocationId: oldInvocation },
      f.intent,
    )
  );
  rejects(() =>
    validateOperatorProvenance({
      ...f.provenance,
      intentSha256: "b".repeat(64),
    }, f.intent)
  );
  rejects(() =>
    validateOperatorProvenance({
      ...f.provenance,
      intent: { ...f.intent, captureSha256: "b".repeat(64) },
    }, f.intent)
  );
  rejects(() =>
    validateOperatorStatus(
      { ...f.status, requestSha256: sha },
      f.provenance,
      f.provenanceSha256,
    )
  );
});

Deno.test("operator separate status cannot clear ordinary gate or accept wrong provenance", () => {
  const f = fixture();
  const gate = {
    ...deriveVerifierGate(
      f.intent.envelope.request,
      f.intent.envelope.requestSha256,
    ),
    unitInvocationId: invocationId,
  };
  const proof = {
    ...f.intent.predecessorProof,
    checkedAtUtc: f.status.finishedAtUtc,
    unitName: gate.unitName,
    unitInvocationId: invocationId,
    statusPath:
      `/var/tmp/arch-vps-file-backup/jobs/${jobId}/operator-status.json`,
    statusState: "ACCEPTED",
    statusInvocationId: invocationId,
    statusUpdatedAtUtc: f.status.updatedAtUtc,
    statusHeartbeatAtUtc: f.status.heartbeatAtUtc,
    statusFinishedAtUtc: f.status.finishedAtUtc,
    operatorProvenanceSha256: f.provenanceSha256,
  };
  const binding = {
    jobId,
    requestSha256: f.intent.envelope.requestSha256,
    invocationId,
    provenanceSha256: f.provenanceSha256,
  };
  rejects(() =>
    validateGateClearProof(proof, gate, new Date(f.status.finishedAtUtc!))
  );
  rejects(() =>
    validateGateClearProof(proof, gate, new Date(f.status.finishedAtUtc!), {
      ...binding,
      provenanceSha256: sha,
    })
  );
  validateGateClearProof(
    proof,
    gate,
    new Date(f.status.finishedAtUtc!),
    binding,
  );
});

Deno.test("operator payload preserves capture and old upload start, releases only after cloud proof", async () => {
  const f = fixture();
  const original = JSON.stringify(f.capture);
  const phases: string[] = [];
  let uploadCalls = 0;
  const result = await executeOperatorPayload(f.capture, f.recipient, {
    checkpoint: (phase) => {
      phases.push(phase);
      return Promise.resolve();
    },
    upload: (capture) => {
      assert(capture === f.capture);
      uploadCalls++;
      return Promise.resolve(f.upload);
    },
    publish: (_capture, upload) => {
      assert(upload.startedAtUtc === f.upload.startedAtUtc);
      return Promise.resolve(f.publishedIndex);
    },
    get: () => {
      phases.push("cloud-readback");
      return Promise.resolve(f.ciphertext);
    },
    release: () => {
      assert(phases.includes("cloud-readback"));
      phases.push("released");
      return Promise.resolve();
    },
    reconstruct: () =>
      Promise.resolve(
        {
          generation,
          indexSha256: f.publishedIndex.indexSha256,
          directory: "/tmp/reconstruction",
          archives: [],
        } as unknown as import("../scripts/backblaze-recovery.ts").ReconstructedGeneration,
      ),
    verify: () => Promise.resolve(f.receipt),
  });
  assert(uploadCalls === 1 && original === JSON.stringify(f.capture));
  assert(
    result.receipt.decryptedRestoreProved &&
      phases.indexOf("cloud-readback") < phases.indexOf("released"),
  );
});

Deno.test("operator cloud mismatch prevents source release and catalog mutation", async () => {
  const f = fixture();
  let released = false;
  await rejectsAsync(() =>
    executeOperatorPayload(f.capture, f.recipient, {
      checkpoint: () => Promise.resolve(),
      upload: () => Promise.resolve(f.upload),
      publish: () => Promise.resolve(f.publishedIndex),
      get: () => Promise.resolve(new Uint8Array()),
      release: () => {
        released = true;
        return Promise.resolve();
      },
      reconstruct: () => Promise.reject(new Error("unreachable")),
      verify: () => Promise.resolve(f.receipt),
    })
  );
  assert(!released);
});

Deno.test("operator import preserves failed snapshot, requires genuine bound receipt, fixes current health", () => {
  const f = fixture();
  const before = JSON.stringify(f.state);
  const accepted = importOperatorRecovery(
    f.state,
    f.provenance,
    f.provenanceSha256,
    f.status,
    bytes(f.result),
  );
  assert(JSON.stringify(f.state) === before);
  assert(
    JSON.stringify(accepted.job!.workerStatus) ===
      JSON.stringify(f.state.job!.workerStatus),
  );
  assert(
    accepted.job!.phase === "FAILED" &&
      accepted.job!.failure?.code === "UPLOAD_FAILED",
  );
  assert(
    accepted.catalog.length === 1 &&
      accepted.job!.operatorRecovery?.invocationId === invocationId,
  );
  assert(
    assessBackblazeWatchdog(
      accepted,
      null,
      new Date("2026-10-03T10:01:00.000Z"),
    ).healthy,
  );
  rejects(() =>
    importOperatorRecovery(
      f.state,
      f.provenance,
      f.provenanceSha256,
      f.status,
      bytes({ ...f.result, receipt: { ...f.receipt, indexSha256: sha } }),
    )
  );
  rejects(() =>
    importOperatorRecovery(f.state, f.provenance, f.provenanceSha256, {
      ...f.status,
      invocationId: oldInvocation,
    }, bytes(f.result))
  );
  assert(JSON.stringify(f.state) === before);
});
