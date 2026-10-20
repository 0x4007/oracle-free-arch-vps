/** Remote-only bounded archive extraction for a RAM-rescue replacement. The
 * caller owns the approved mounted target and Pi GPG-agent tunnel. No archive
 * is staged in full; v2 uses bounded ciphertext slots and no private key. */
import { createHash } from "node:crypto";
import {
  type DecryptedRestoreArchive,
  restoreTarArgs,
} from "./backblaze-machine-restore.ts";
import {
  type RecoveryIndex,
  validateRecoveryIndex,
} from "./backblaze-index.ts";
import { streamRecoveryArchive } from "./backblaze-recovery.ts";
import type { B2Store } from "./backblaze-storage.ts";
import {
  CheckpointChannel,
  remoteCheckpoint,
} from "./pi-recovery-checkpoint.ts";
import {
  type RecoveryIsolationInput,
  recoveryIsolationPlan,
} from "./pi-recovery-isolation.ts";
import { executeCopiedRootIsolation } from "./pi-recovery-isolation-executor.ts";
import {
  type BackupV2ManifestRef,
  type BackupV2ObjectStore,
  type BackupV2Receipt,
  type BackupV2Role,
  validateBackupV2ManifestRef,
  validateBackupV2Receipt,
} from "./backup-v2-contract.ts";
import {
  type BackupV2CatalogEntry,
  validateBackupRuntimeCatalogEntry,
} from "./backup-v2-runtime-contract.ts";
import {
  type BackupV2ObjectReader,
  type BackupV2Reader,
  createBackupV2FileObjectReader,
  createBackupV2Reader,
} from "./backup-v2-recovery.ts";
import { verifyBackupStreamArchive } from "./backup-stream-verifier.ts";
import { backupV2ChildEnvironment } from "./backup-v2-supervisor.ts";

export type StreamDecrypt = (
  ciphertext: ReadableStream<Uint8Array>,
  destination: Pick<Deno.FsFile, "write">,
) => Promise<{ integrityChecked: true }>;

/** Tar can write partial target data before a later integrity failure. Such a
 * failure must leave the recovery journal incomplete and must never boot the
 * target. The machine-restorer owns mount/serial checks before this callback. */
export async function extractStreamedArchive(
  indexInput: RecoveryIndex,
  archive: DecryptedRestoreArchive,
  mountPath: string,
  store: Pick<B2Store, "get">,
  decrypt: StreamDecrypt,
  progress?: (bytes: number) => Promise<void>,
): Promise<void> {
  const index = validateRecoveryIndex(indexInput);
  const selected = index.archives.find((entry) => entry.role === archive.role);
  if (
    !selected || selected.bytes !== archive.ciphertextBytes ||
    selected.sha256 !== archive.ciphertextSha256 ||
    !Number.isSafeInteger(archive.bytes) || archive.bytes <= 0 ||
    !/^[0-9a-f]{64}$/.test(archive.sha256)
  ) {
    throw new Error("Stream restore archive binding failed");
  }
  return await extractCheckedStream(
    streamRecoveryArchive(index, archive.role, store),
    archive,
    mountPath,
    decrypt,
    progress,
  );
}

/** Both versions share the same target writer and complete plaintext proof. */
export async function extractCheckedStream(
  ciphertext: ReadableStream<Uint8Array>,
  archive: DecryptedRestoreArchive,
  mountPath: string,
  decrypt: StreamDecrypt,
  progress?: (bytes: number) => Promise<void>,
): Promise<void> {
  const args = [...restoreTarArgs("-", mountPath)];
  await progress?.(0);
  let lastProgressAt = Date.now();
  let reportedBytes = 0;
  const child = new Deno.Command("tar", {
    args,
    stdin: "piped",
    stdout: "null",
    stderr: "piped",
    clearEnv: true,
    env: backupV2ChildEnvironment({ PATH: "/usr/bin:/bin" }),
  }).spawn();
  const writer = child.stdin.getWriter();
  let diagnosticBytes = 0;
  const diagnostics = (async () => {
    for await (const bytes of child.stderr) diagnosticBytes += bytes.byteLength;
  })();
  const hash = createHash("sha256");
  let total = 0;
  const extraction = (async () => {
    try {
      const result = await decrypt(
        ciphertext,
        {
          async write(bytes) {
            total += bytes.byteLength;
            if (total > archive.bytes) {
              throw new Error("Stream plaintext exceeded expected length");
            }
            hash.update(bytes);
            await writer.write(bytes);
            if (progress && Date.now() - lastProgressAt >= 30_000) {
              await progress(total);
              reportedBytes = total;
              lastProgressAt = Date.now();
            }
            return bytes.byteLength;
          },
        },
      );
      if (
        result?.integrityChecked !== true || total !== archive.bytes ||
        hash.digest("hex") !== archive.sha256
      ) {
        throw new Error("Stream plaintext integrity failed");
      }
      await writer.close();
    } catch {
      try {
        await writer.abort();
      } catch { /* Preserve the pipeline failure. */ }
      throw new Error("Stream decryption or extraction failed");
    } finally {
      writer.releaseLock();
    }
  })();
  const settled = await Promise.allSettled([
    extraction,
    diagnostics,
    child.status,
  ]);
  if (
    settled.some((item) => item.status === "rejected") ||
    settled[2].status !== "fulfilled" || !settled[2].value.success ||
    diagnosticBytes > 256 * 1024
  ) {
    throw new Error("Stream archive pipeline did not complete successfully");
  }
  if (total > reportedBytes) await progress?.(total);
}

/** Only the small recovery metadata is buffered; filesystem archives never are. */
export async function readStreamedMetadata(
  catalog: import("./backblaze-file-backup.ts").CatalogEntry,
  store: Pick<B2Store, "get">,
  decrypt: StreamDecrypt,
) {
  const descriptor = catalog.receipt.archives.find((a) =>
    a.role === "recovery"
  );
  const limit = 8 * 1024 * 1024;
  if (!descriptor || descriptor.compressedBytes > limit) {
    throw new Error("Recovery metadata exceeds the RAM bound");
  }
  const compressed: Uint8Array[] = [];
  let total = 0;
  const hash = createHash("sha256");
  const integrity = await decrypt(
    streamRecoveryArchive(catalog.index, "recovery", store),
    {
      write(bytes) {
        total += bytes.byteLength;
        if (
          total > descriptor.compressedBytes || total > limit
        ) throw new Error("Recovery metadata overflow");
        hash.update(bytes);
        compressed.push(bytes.slice());
        return Promise.resolve(bytes.byteLength);
      },
    },
  );
  if (
    !integrity?.integrityChecked || total !== descriptor.compressedBytes ||
    hash.digest("hex") !== descriptor.compressedSha256
  ) {
    throw new Error("Recovery metadata plaintext integrity failed");
  }
  const child = new Deno.Command("zstd", {
    args: ["-d", "-c"],
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
    clearEnv: true,
    env: backupV2ChildEnvironment({ PATH: "/usr/bin:/bin" }),
  }).spawn();
  const writer = child.stdin.getWriter();
  const feed = (async () => {
    try {
      for (const bytes of compressed) await writer.write(bytes);
      await writer.close();
    } finally {
      writer.releaseLock();
    }
  })();
  const decoded = (async () => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const bytes of child.stdout) {
      size += bytes.byteLength;
      if (size > limit) throw new Error("Recovery metadata decoded overflow");
      chunks.push(bytes);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    if (
      createHash("sha256").update(bytes).digest("hex") !==
        catalog.receipt.metadataSha256
    ) throw new Error("Recovery metadata catalog hash differs");
    return JSON.parse(new TextDecoder().decode(bytes));
  })();
  const settled = await Promise.allSettled([feed, decoded, child.status]);
  if (
    settled[0].status !== "fulfilled" || settled[1].status !== "fulfilled" ||
    settled[2].status !== "fulfilled" || !settled[2].value.success
  ) throw new Error("Recovery metadata decompression failed");
  return settled[1].value;
}

/** Exact trusted receipt readback, with final crypto and canonical plaintext hash. */
export async function readV2RestoreReceipt(
  reference: BackupV2ManifestRef,
  objects: BackupV2ObjectReader,
  decrypt: StreamDecrypt,
): Promise<BackupV2Receipt> {
  reference = validateBackupV2ManifestRef(reference);
  if (reference.object.contentLength > 1024 * 1024) {
    throw Error("V2 receipt ciphertext exceeds document bound");
  }
  let complete = false, inputBytes = 0, outputBytes = 0;
  const output: Uint8Array[] = [];
  const input = (await objects.open(reference.object)).pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(bytes, sink) {
        inputBytes += bytes.length;
        sink.enqueue(bytes);
      },
      flush() {
        complete = true;
      },
    }),
  );
  try {
    const result = await decrypt(input, {
      write(bytes) {
        outputBytes += bytes.length;
        if (outputBytes > 1024 * 1024) {
          throw Error("V2 restore receipt exceeds document bound");
        }
        output.push(bytes.slice());
        return Promise.resolve(bytes.length);
      },
    });
    if (
      !complete || inputBytes !== reference.object.contentLength ||
      result.integrityChecked !== true
    ) throw Error("V2 receipt crypto input incomplete");
    const bytes = new Uint8Array(outputBytes);
    let offset = 0;
    for (const part of output) {
      bytes.set(part, offset);
      offset += part.length;
    }
    if (
      createHash("sha256").update(bytes).digest("hex") !==
        reference.plaintextSha256
    ) throw Error("V2 restore receipt anchor differs");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      receipt = validateBackupV2Receipt(JSON.parse(text));
    if (JSON.stringify(receipt) !== text) {
      throw Error("V2 restore receipt is noncanonical");
    }
    return receipt;
  } finally {
    if (!input.locked) await input.cancel();
  }
}

/** No source mount/cache capability is accepted by this restore reader. */
export async function openV2RestoreReader(
  catalog: BackupV2CatalogEntry,
  objects: BackupV2ObjectReader,
  decrypt: StreamDecrypt,
) {
  const reader = await createBackupV2Reader(catalog.selectedRoot.reference, {
    objects,
    decryptDocument: decrypt,
  });
  if (
    JSON.stringify(reader.root) !== JSON.stringify(catalog.selectedRoot.root)
  ) throw Error("V2 restore root differs from off-target anchor");
  const receipt = await readV2RestoreReceipt(
    catalog.receiptReference,
    objects,
    decrypt,
  );
  if (
    JSON.stringify(receipt) !== JSON.stringify(catalog.receipt) ||
    JSON.stringify(receipt.root) !== JSON.stringify(reader.rootRef)
  ) throw Error("V2 restore receipt differs from trusted catalog");
  return { reader, receipt };
}

export async function readV2StreamedMetadata(
  reader: BackupV2Reader,
  receipt: BackupV2Receipt,
  decrypt: StreamDecrypt,
  temporaryDirectory: string,
) {
  const metadata = await reader.verificationMetadata();
  if (metadata.metadataSha256 !== receipt.metadataSha256) {
    throw Error("V2 recovery metadata anchor differs");
  }
  const result = await verifyBackupStreamArchive(
    await reader.role("recovery"),
    { ciphertext: reader.ciphertext, decrypt, temporaryDirectory },
    { metadataSha256: receipt.metadataSha256 },
  );
  const expected = receipt.archives.find((item) => item.role === "recovery")!;
  if (
    !result.metadata ||
    result.proof.compressedBytes !== expected.compressedBytes ||
    result.proof.compressedSha256 !== expected.compressedSha256 ||
    result.proof.ciphertextBytes !== expected.ciphertextBytes ||
    result.proof.ciphertextSha256 !== expected.ciphertextSha256
  ) throw Error("V2 metadata differs from measured accepted receipt");
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(result.metadata),
  );
}

/** Assemble the accepted catalog, directly fetched recovery metadata and
 * target-only disk writer. This function never consults the source VPS. */
export async function restoreCatalogOnTarget(
  input: {
    catalog: unknown;
    requestId: string;
    loaderBootId: string;
    rescueManifestSha256: string;
    target: import("./backblaze-machine-restore.ts").MachineRestoreTarget;
    publicHome: string;
    isolation?: RecoveryIsolationInput;
  },
  store: Pick<B2Store, "get"> | Pick<BackupV2ObjectStore, "getExactToFile">,
  channel: CheckpointChannel,
) {
  const { validateCatalogEntry, makeStreamDecryptArchive } = await import(
    "./backblaze-file-backup.ts"
  );
  const { restoreMachine, machineRestoreIndexSha256 } = await import(
    "./backblaze-machine-restore.ts"
  );
  const raw = input.catalog as
    | { schemaVersion?: unknown; format?: unknown }
    | null;
  const selected = validateBackupRuntimeCatalogEntry(
    raw?.schemaVersion === 2 || raw?.format === "backup-v2" ||
      raw?.format === "backup-v1"
      ? input.catalog
      : { schemaVersion: 1, format: "backup-v1", entry: input.catalog },
    validateCatalogEntry,
  );
  // Check the execution host before requesting any archive chunk. The target
  // identity is the approved OCI instance, never a controller or home host.
  if (
    Deno.build.os !== "linux" || Deno.build.arch !== "aarch64" ||
    !input.target.targetId.startsWith("ocid1.instance.")
  ) {
    throw new Error(
      "Stream recovery must execute on the approved Oracle target",
    );
  }
  const response = await fetch("http://169.254.169.254/opc/v2/instance/", {
    headers: { Authorization: "Bearer Oracle" },
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  const instance = response.ok ? await response.json() : null;
  if (
    instance?.id !== input.target.targetId ||
    instance?.freeformTags?.uosRecoveryRequest !== input.requestId
  ) {
    throw new Error("Oracle target instance identity is not proved");
  }
  const { assertAcceptedRescueBoot } = await import("./pi-recovery-rescue.ts");
  const runtime = await assertAcceptedRescueBoot(input.target, {
    requestId: input.requestId,
    loaderBootId: input.loaderBootId,
    manifestSha256: input.rescueManifestSha256,
  });
  const binding = {
    requestId: input.requestId,
    instanceId: input.target.targetId,
    bootId: runtime.bootId,
    generation: selected.schemaVersion === 1
      ? selected.entry.index.generation
      : selected.selectedRoot.root.captureId,
    indexSha256: selected.schemaVersion === 1
      ? machineRestoreIndexSha256(selected.entry.index)
      : selected.selectedRoot.reference.plaintextSha256,
    bootDiskPath: input.target.bootDiskPath,
    rootDiskPath: input.target.rootDiskPath,
    bootDiskSerial: input.target.bootDiskSerial,
    rootDiskSerial: input.target.rootDiskSerial,
  };
  const checkpoint = remoteCheckpoint(channel, binding);
  const decrypt = makeStreamDecryptArchive(input.publicHome);
  const directory =
    `${input.target.workDirectory}/v2-reader-${input.requestId}`;
  let v2: Awaited<ReturnType<typeof openV2RestoreReader>> | undefined;
  if (selected.schemaVersion === 2) {
    if (!("getExactToFile" in store)) {
      throw Error("V2 restore requires exact-object transport");
    }
    try {
      await Deno.mkdir(directory, { mode: 0o700 });
    } catch (error) {
      if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
    }
    v2 = await openV2RestoreReader(
      selected,
      await createBackupV2FileObjectReader(directory, store),
      decrypt,
    );
  }
  const metadata = selected.schemaVersion === 2
    ? await readV2StreamedMetadata(v2!.reader, v2!.receipt, decrypt, directory)
    : await readStreamedMetadata(
      selected.entry,
      "get" in store ? store : (() => {
        throw Error("V1 transport missing");
      })(),
      decrypt,
    );
  const archives =
    (selected.schemaVersion === 2
      ? selected.receipt.archives
      : selected.entry.receipt.archives).filter((a) => a.role !== "recovery")
      .map((a) => ({
        role: a.role as DecryptedRestoreArchive["role"],
        bytes: a.compressedBytes,
        sha256: a.compressedSha256,
        ciphertextBytes: a.ciphertextBytes,
        ciphertextSha256: a.ciphertextSha256,
        verifierChecked: true as const,
      }));
  const machineInput = {
    index: selected.schemaVersion === 1 ? selected.entry.index : {
      schemaVersion: 2 as const,
      format: "backup-v2" as const,
      generation: selected.selectedRoot.root.captureId,
      root: v2!.reader.root,
      reference: v2!.reader.rootRef,
      receipt: v2!.receipt,
      receiptReference: selected.receiptReference,
    },
    indexSha256: binding.indexSha256,
    metadata,
    archives,
    target: input.target,
  };
  const result = await restoreMachine(
    machineInput,
    undefined,
    (archive, mount) =>
      selected.schemaVersion === 2
        ? extractCheckedStream(
          v2!.reader.ciphertext(archive.role as BackupV2Role),
          archive,
          mount,
          decrypt,
          (bytes) =>
            channel.send({
              kind: "recovery-archive-progress",
              binding,
              role: archive.role,
              bytes,
              expectedBytes: archive.bytes,
            }),
        )
        : extractStreamedArchive(
          selected.entry.index,
          archive,
          mount,
          "get" in store ? store : (() => {
            throw Error("V1 transport missing");
          })(),
          decrypt,
          (bytes) =>
            channel.send({
              kind: "recovery-archive-progress",
              binding,
              role: archive.role,
              bytes,
              expectedBytes: archive.bytes,
            }),
        ),
    checkpoint,
  );
  if (input.isolation) {
    const expected = input.isolation.preparation;
    if (
      expected.bootId !== runtime.bootId ||
      expected.requestId !== input.requestId ||
      expected.loaderBootId !== input.loaderBootId ||
      expected.rescueManifestSha256 !== input.rescueManifestSha256
    ) throw Error("Isolation plan differs from the current RAM boot");
    const plan = recoveryIsolationPlan(machineInput, input.isolation);
    await channel.send({
      kind: "recovery-isolation-plan",
      plan,
    });
    // Inspection only. No approval is supplied, so the executor cannot enter
    // its copied-filesystem write path. It returns only after releasing mounts.
    const inspected = await executeCopiedRootIsolation(
      plan,
      () => Promise.resolve(undefined),
      () => Promise.reject(Error("Isolation writes are not connected")),
    );
    await channel.send({
      kind: "recovery-isolation-inspection",
      inspection: inspected.inspection,
      mountsReleased: true,
      isolationApplied: false,
    });
  }
  if (v2) await Deno.remove(directory);
  return result;
}

if (import.meta.main) {
  const channel = new CheckpointChannel(
    Deno.stdin.readable,
    Deno.stdout.writable,
    // The Pi rechecks OCI ownership before acknowledging a durable stage.
    // Bound that control-plane round trip separately from archive progress.
    10 * 60 * 1000,
    () => {
      for (const file of [Deno.stdin, Deno.stdout]) {
        try {
          file.close();
        } catch (error) {
          if (!(error instanceof Deno.errors.BadResource)) throw error;
        }
      }
    },
  );
  try {
    const { readPrivateJson } = await import("./oci.ts");
    const { B2Store } = await import("./backblaze-storage.ts");
    const { BackupV2Store } = await import("./backup-v2-store.ts");
    const input = await readPrivateJson<
      Parameters<typeof restoreCatalogOnTarget>[0]
    >(".private/backblaze-machine-restore.json");
    const settings = await readPrivateJson<
      import("./backblaze-storage.ts").B2Settings
    >(".private/b2-file-backup.json");
    await channel.send({
      kind: "recovery-restore-result",
      result: await restoreCatalogOnTarget(
        input,
        (input.catalog as { schemaVersion?: unknown } | null)?.schemaVersion ===
            2
          ? new BackupV2Store(settings)
          : new B2Store(settings),
        channel,
      ),
    });
  } catch {
    console.error(
      "Remote stream restore failed; preserve its journal and do not boot the target",
    );
    Deno.exitCode = 1;
  } finally {
    await channel.close();
  }
}
