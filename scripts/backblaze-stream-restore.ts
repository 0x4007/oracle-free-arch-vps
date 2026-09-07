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
    target: import("./backblaze-machine-restore.ts").MachineRestoreTarget;
    publicHome: string;
  },
  store: Pick<B2Store, "get">,
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
  if (!response.ok || (await response.json()).id !== input.target.targetId) {
    throw new Error("Oracle target instance identity is not proved");
  }
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
  return await restoreMachine(
    {
      index: catalog.index,
      indexSha256: machineRestoreIndexSha256(catalog.index),
      metadata,
      archives,
      target: input.target,
    },
    undefined,
    (archive, mount) =>
      extractStreamedArchive(catalog.index, archive, mount, store, decrypt),
  );
}

if (import.meta.main) {
  try {
    const { readPrivateJson } = await import("./oci.ts");
    const { B2Store } = await import("./backblaze-storage.ts");
    const input = await readPrivateJson<
      Parameters<typeof restoreCatalogOnTarget>[0]
    >(".private/backblaze-machine-restore.json");
    const settings = await readPrivateJson<
      import("./backblaze-storage.ts").B2Settings
    >(".private/b2-file-backup.json");
    console.log(
      JSON.stringify(
        await restoreCatalogOnTarget(input, new B2Store(settings)),
      ),
    );
  } catch {
    console.error(
      "Remote stream restore failed; preserve its journal and do not boot the target",
    );
    Deno.exitCode = 1;
  }
}
