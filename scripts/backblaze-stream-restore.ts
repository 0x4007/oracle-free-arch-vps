/** Remote-only bounded archive extraction for a RAM-rescue replacement. The
 * caller owns the approved mounted target and Pi GPG-agent tunnel. No archive
 * scratch file or private key is created by this module. */
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
  const args = [...restoreTarArgs("-", mountPath)];
  await progress?.(0);
  let lastProgressAt = Date.now();
  let reportedBytes = 0;
  const child = new Deno.Command("tar", {
    args,
    stdin: "piped",
    stdout: "null",
    stderr: "piped",
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
        streamRecoveryArchive(index, archive.role, store),
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
  store: Pick<B2Store, "get">,
  channel: CheckpointChannel,
) {
  const { validateCatalogEntry, makeStreamDecryptArchive } = await import(
    "./backblaze-file-backup.ts"
  );
  const { restoreMachine, machineRestoreIndexSha256 } = await import(
    "./backblaze-machine-restore.ts"
  );
  const catalog = validateCatalogEntry(input.catalog);
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
    generation: catalog.index.generation,
    indexSha256: machineRestoreIndexSha256(catalog.index),
    bootDiskPath: input.target.bootDiskPath,
    rootDiskPath: input.target.rootDiskPath,
    bootDiskSerial: input.target.bootDiskSerial,
    rootDiskSerial: input.target.rootDiskSerial,
  };
  const checkpoint = remoteCheckpoint(channel, binding);
  const decrypt = makeStreamDecryptArchive(input.publicHome);
  const metadata = await readStreamedMetadata(catalog, store, decrypt);
  const archives = catalog.receipt.archives.filter((a) => a.role !== "recovery")
    .map((a) => ({
      role: a.role as DecryptedRestoreArchive["role"],
      bytes: a.compressedBytes,
      sha256: a.compressedSha256,
      ciphertextBytes: a.ciphertextBytes,
      ciphertextSha256: a.ciphertextSha256,
      verifierChecked: true as const,
    }));
  const machineInput = {
    index: catalog.index,
    indexSha256: machineRestoreIndexSha256(catalog.index),
    metadata,
    archives,
    target: input.target,
  };
  const result = await restoreMachine(
    machineInput,
    undefined,
    (archive, mount) =>
      extractStreamedArchive(
        catalog.index,
        archive,
        mount,
        store,
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
        new B2Store(settings),
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
