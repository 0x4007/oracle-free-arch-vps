import { createHash } from "node:crypto";
import {
  extractStreamedArchive,
  readStreamedMetadata,
} from "../scripts/backblaze-stream-restore.ts";
import { validateRecoveryIndex } from "../scripts/backblaze-index.ts";
import {
  generationChunkName,
  UPLOAD_ROLE_ORDER,
} from "../scripts/backblaze-upload.ts";

function hash(bytes: Uint8Array, algorithm = "sha256") {
  return createHash(algorithm).update(bytes).digest("hex");
}
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
const permissions = await Promise.all(
  ["read", "write", "run"].map((name) =>
    Deno.permissions.query({ name } as Deno.PermissionDescriptor)
  ),
);
Deno.test({
  name:
    "remote stream extraction uses GNU tar and refuses plaintext or decrypt failures",
  ignore: Deno.build.os !== "linux" ||
    permissions.some((p) => p.state !== "granted"),
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "uos-stream-fixture-" });
    try {
      await Deno.mkdir(dir + "/source");
      await Deno.writeTextFile(
        dir + "/source/sample.txt",
        "synthetic recovery fixture\n",
      );
      const packed = await new Deno.Command("tar", {
        args: ["-C", dir + "/source", "--zstd", "-cf", "-", "sample.txt"],
      }).output();
      assert(packed.success);
      const bytes = packed.stdout;
      const generation = "generation-11111111-2222-3333-4444-555555555555";
      const index = validateRecoveryIndex({
        schemaVersion: 1,
        generation,
        captureStartedAtUtc: "2026-09-06T01:00:00.000Z",
        captureFinishedAtUtc: "2026-09-06T01:01:00.000Z",
        uploadStartedAtUtc: "2026-09-06T01:01:00.000Z",
        uploadFinishedAtUtc: "2026-09-06T01:02:00.000Z",
        consistency: "live-file-copy",
        sourceShutdown: false,
        recipientFingerprint: "AABBCCDDEEFF00112233445566778899AABBCCDD",
        recipientSha256: "ab".repeat(32),
        uploadVerified: true,
        decryptedRestoreProved: false,
        machineBootRestoreProved: false,
        archives: UPLOAD_ROLE_ORDER.map((role) => ({
          role,
          format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
          bytes: bytes.length,
          sha256: hash(bytes),
          chunks: [{
            index: 0,
            name: generationChunkName(generation, role, 0),
            size: bytes.length,
            sha256: hash(bytes),
            sha1: hash(bytes, "sha1"),
            fileId: "fixture-" + role,
            uploadTimestamp: 1900000000000,
          }],
        })),
      });
      for (const mode of ["good", "digest", "decrypt"]) {
        const destination = dir + "/" + mode;
        await Deno.mkdir(destination);
        let failed = false;
        try {
          await extractStreamedArchive(
            index,
            {
              role: "root",
              bytes: bytes.length,
              sha256: mode === "digest" ? "00".repeat(32) : hash(bytes),
              ciphertextBytes: bytes.length,
              ciphertextSha256: hash(bytes),
            },
            destination,
            { get: () => Promise.resolve(bytes) },
            async (input, output) => {
              for await (const chunk of input) {
                if (mode === "decrypt") {
                  throw Error("synthetic decrypt failure");
                }
                await output.write(chunk);
              }
              return { integrityChecked: true };
            },
          );
        } catch {
          failed = true;
        }
        assert(failed === (mode !== "good"));
        if (mode === "good") {
          assert(
            await Deno.readTextFile(destination + "/sample.txt") ===
              "synthetic recovery fixture\n",
          );
        }
      }
      const metadataBytes = new TextEncoder().encode(
        JSON.stringify({ generation, fixture: true }),
      );
      const compressor = new Deno.Command("zstd", {
        args: ["-c"],
        stdin: "piped",
        stdout: "piped",
      }).spawn();
      const compression = compressor.output();
      const inputWriter = compressor.stdin.getWriter();
      await inputWriter.write(metadataBytes);
      await inputWriter.close();
      const metadataCompressed = (await compression).stdout;
      const metadataIndex = structuredClone(index);
      const record = metadataIndex.archives.find((a) => a.role === "recovery")!;
      record.bytes = metadataCompressed.length;
      record.sha256 = hash(metadataCompressed);
      record.chunks[0] = {
        ...record.chunks[0],
        size: metadataCompressed.length,
        sha256: hash(metadataCompressed),
        sha1: hash(metadataCompressed, "sha1"),
      };
      const catalog = {
        index: validateRecoveryIndex(metadataIndex),
        receipt: {
          metadataSha256: hash(metadataBytes),
          archives: [{
            role: "recovery",
            compressedBytes: metadataCompressed.length,
            compressedSha256: hash(metadataCompressed),
          }],
        },
      } as unknown as import("../scripts/backblaze-file-backup.ts").CatalogEntry;
      const decrypt = async (
        source: ReadableStream<Uint8Array>,
        destination: Pick<Deno.FsFile, "write">,
      ) => {
        for await (const chunk of source) await destination.write(chunk);
        return { integrityChecked: true as const };
      };
      const metadataStore = { get: () => Promise.resolve(metadataCompressed) };
      assert(
        (await readStreamedMetadata(catalog, metadataStore, decrypt))
          .generation === generation,
      );
      catalog.receipt.metadataSha256 = "00".repeat(32);
      let metadataFailed = false;
      try {
        await readStreamedMetadata(catalog, metadataStore, decrypt);
      } catch {
        metadataFailed = true;
      }
      assert(metadataFailed);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});
