import { createHash } from "node:crypto";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ArchiveProof,
  type BackupV2ManifestRef,
  backupV2ObjectName,
  type BackupV2ObjectRef,
  type BackupV2Role,
  type BackupV2RoleManifest,
  type BackupV2Root,
  validateBackupV2ObjectRef,
} from "../scripts/backup-v2-contract.ts";
import { createBackupV2InventorySummary } from "../scripts/backup-v2-inventory.ts";
import {
  type BackupV2ReaderCapabilities,
  backupV2RoleReferences,
  createBackupV2FileObjectReader,
  createBackupV2Reader,
  verifyBackupV2Root,
} from "../scripts/backup-v2-recovery.ts";
import type { verifyBackupStreamArchive } from "../scripts/backup-stream-verifier.ts";

const encoder = new TextEncoder(), decoder = new TextDecoder();
const C = "generation-00000000-0000-4000-8000-000000000001",
  SHA = "3".repeat(64),
  FINGERPRINT = "A".repeat(40);
const uuid = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const hash = (data: Uint8Array, kind = "sha256") =>
  createHash(kind).update(data).digest("hex");
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function equal(a: unknown, b: unknown) {
  assert(JSON.stringify(a) === JSON.stringify(b));
}
async function rejects(run: () => unknown) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed);
}
async function consume(source: ReadableStream<Uint8Array>) {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const part of source) {
    parts.push(part);
    total += part.length;
  }
  const result = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    result.set(part, at);
    at += part.length;
  }
  return result;
}
function graph(fault?: "page" | "role") {
  const blobs = new Map<string, Uint8Array>(),
    opened: string[] = [],
    payloads = new Map<BackupV2Role, Uint8Array>(),
    roles = new Map<BackupV2Role, BackupV2RoleManifest>();
  let serial = 10;
  const put = (
    value: unknown,
    kind: "data" | "manifest" | "metadata",
    attempt: string,
    ordinal: number,
  ): BackupV2ManifestRef => {
    const bytes = value instanceof Uint8Array
        ? value
        : encoder.encode(JSON.stringify(value)),
      id = uuid(serial++);
    const object = validateBackupV2ObjectRef({
      fileId: id,
      fileName: backupV2ObjectName(C, attempt, kind, ordinal, id),
      contentLength: bytes.length,
      contentSha1: hash(bytes, "sha1"),
      sha256: hash(bytes),
      action: "upload",
      uploadTimestamp: 1,
    });
    blobs.set(object.fileId, bytes);
    return { object, plaintextSha256: hash(bytes) };
  };
  const recoveryBytes = encoder.encode('{"fixture":1}');
  const metadata = {
    schemaVersion: 2,
    format: "backup-v2-verification-metadata",
    captureId: C,
    metadataSha256: hash(recoveryBytes),
    bootSamples: BACKUP_V2_BOOT_SAMPLES.map((sample, i) => ({
      ...sample,
      bytes: i % 2 + 1,
      sha256: String(i % 2 + 1).repeat(64),
    })),
  };
  const metadataRef = put(metadata, "metadata", uuid(9), 0),
    links: BackupV2Root["roles"] = [];
  for (const [index, role] of BACKUP_V2_ROLES.entries()) {
    const attemptId = uuid(index + 1),
      payload = role === "recovery"
        ? recoveryBytes
        : encoder.encode(`ciphertext-${role}`);
    payloads.set(role, payload);
    const data = put(payload, "data", attemptId, 0);
    const page = put(
      {
        schemaVersion: 2,
        captureId: C,
        attemptId,
        role,
        pageIndex: 0,
        startOrdinal: fault === "page" && index === 0 ? 1 : 0,
        startOffset: 0,
        chunks: [{ ordinal: 0, offset: 0, object: data.object }],
      },
      "manifest",
      attemptId,
      0,
    );
    const inventory = createBackupV2InventorySummary();
    inventory.add({ path: encoder.encode("./file") });
    const manifest: BackupV2RoleManifest = {
      schemaVersion: 2,
      captureId: C,
      attemptId,
      role: fault === "role" && index === 0 ? "efi" : role,
      format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
      ciphertextBytes: payload.length,
      ciphertextSha256: hash(payload),
      sourceConfigSha256: SHA,
      compatibilitySha256: SHA,
      recipientSha256: SHA,
      recipientFingerprint: FINGERPRINT,
      captureStartedAtUtc: "2026-10-18T10:00:00.000Z",
      captureFinishedAtUtc: "2026-10-18T10:01:00.000Z",
      uploadStartedAtUtc: "2026-10-18T10:00:01.000Z",
      uploadFinishedAtUtc: "2026-10-18T10:01:01.000Z",
      pages: [{
        manifest: page,
        firstOrdinal: 0,
        firstOffset: 0,
        chunkCount: 1,
        bytes: payload.length,
      }],
      inventory: role === "recovery" ? null : inventory.finish(),
      producer: {
        tarExitCode: 0,
        zstdExitCode: 0,
        gpgExitCode: 0,
        driftRecords: 0,
        driftSha256: SHA,
      },
      metadata: [],
    };
    roles.set(role, manifest);
    const reference = put(manifest, "manifest", attemptId, 1);
    links.push({
      role,
      attemptId,
      manifest: reference,
      captureStartedAtUtc: manifest.captureStartedAtUtc,
      captureFinishedAtUtc: manifest.captureFinishedAtUtc,
    });
  }
  const root: BackupV2Root = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: "backup-v2-20261018",
    captureId: C,
    periodKey: "2026-10-18",
    sourceRevision: "a".repeat(40),
    sourceConfigSha256: SHA,
    recipientSha256: SHA,
    recipientFingerprint: FINGERPRINT,
    roles: links,
    metadata: [metadataRef.object],
  };
  const reference = put(root, "manifest", uuid(9), 0);
  const caps: BackupV2ReaderCapabilities = {
    objects: {
      open(ref) {
        opened.push(ref.fileId);
        const bytes = blobs.get(ref.fileId);
        if (!bytes) throw new Error("Exact object missing");
        return Promise.resolve(
          new ReadableStream({
            start(c) {
              c.enqueue(bytes.slice());
              c.close();
            },
          }),
        );
      },
    },
    async decryptDocument(source, sink) {
      for await (const bytes of source) await sink.write(bytes);
      return { integrityChecked: true };
    },
  };
  return { reference, root, caps, blobs, opened, payloads, roles, metadata };
}

Deno.test("v2 cloud reader validates graph without payload reads and replays exact role bytes", async () => {
  const g = graph(), reader = await createBackupV2Reader(g.reference, g.caps);
  const refs = await reader.references();
  equal(refs.length, 23);
  assert(
    g.opened.every((id) =>
      !refs.find((ref) => ref.fileId === id)!.fileName.includes("/data/")
    ),
  );
  equal(
    decoder.decode(await consume(reader.ciphertext("root"))),
    decoder.decode(g.payloads.get("root")!),
  );
  equal(await consume(reader.ciphertext("root")), g.payloads.get("root"));
  const snapshot = reader.root;
  snapshot.roles.splice(0);
  equal(reader.root.roles.length, 7);
  equal(
    (await backupV2RoleReferences(g.root.roles[0].manifest, g.caps)).length,
    3,
  );
});
Deno.test("v2 cloud reader rejects false plaintext digests corrupt objects and invalid page/role binding", async () => {
  const g = graph();
  await rejects(() =>
    createBackupV2Reader(
      { ...g.reference, plaintextSha256: "f".repeat(64) },
      g.caps,
    )
  );
  const tampered = graph();
  tampered.blobs.get(tampered.reference.object.fileId)![0] ^= 1;
  await rejects(() => createBackupV2Reader(tampered.reference, tampered.caps));
  for (const fault of ["page", "role"] as const) {
    const bad = graph(fault);
    const reader = await createBackupV2Reader(bad.reference, bad.caps);
    await rejects(() => reader.references());
  }
});
Deno.test("v2 cloud documents require full input drain even when a codec claims integrity", async () => {
  const g = graph();
  g.caps.decryptDocument = async (_source, sink) => {
    await sink.write(g.blobs.get(g.reference.object.fileId)!);
    return { integrityChecked: true };
  };
  await rejects(() => createBackupV2Reader(g.reference, g.caps));
});
Deno.test("v2 independent receipt assembly binds measured role outputs metadata and all four samples", async () => {
  const g = graph(),
    reader = await createBackupV2Reader(g.reference, g.caps),
    seen: string[] = [];
  const verify: typeof verifyBackupStreamArchive = async (
    descriptor,
    dependencies,
    options,
  ) => {
    seen.push(descriptor.role);
    equal(
      await consume(dependencies.ciphertext(descriptor.role)),
      g.payloads.get(descriptor.role),
    );
    const proof: BackupV2ArchiveProof = {
      role: descriptor.role,
      format: descriptor.format,
      ciphertextBytes: descriptor.ciphertextBytes,
      ciphertextSha256: descriptor.ciphertextSha256,
      compressedBytes: 1,
      compressedSha256: SHA,
      inventory: g.roles.get(descriptor.role)!.inventory,
      inputComplete: true,
      integrityChecked: true,
      decompressionComplete: true,
      gpgExitCode: 0,
      zstdExitCode: 0,
      tarExitCode: 0,
    };
    const result = {
      proof,
      passes: [],
      samples: (options?.samples ?? []).map((sample) => ({
        member: sample.member,
        contentMember: sample.member,
        bytes: sample.bytes!,
        sha256: sample.sha256,
      })),
    };
    return descriptor.role === "recovery"
      ? { ...result, metadata: Uint8Array.from(g.payloads.get("recovery")!) }
      : { ...result, metadata: undefined };
  };
  const options = {
    decrypt: g.caps.decryptDocument,
    verifyArchive: verify,
    configurationSha256: SHA,
    verifierRevision: "b".repeat(40),
    tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4.9" },
    now: () => new Date("2026-10-18T11:00:00.000Z"),
  };
  const receipt = await verifyBackupV2Root(reader, options);
  equal(seen, [...BACKUP_V2_ROLES]);
  equal(receipt.bootSamples.length, 4);
  equal(receipt.root, g.reference);
  equal(receipt.machineBootRestoreProved, false);
  await rejects(() =>
    verifyBackupV2Root(reader, {
      ...options,
      verifyArchive: async (...args) => {
        const result = await verify(...args);
        return {
          ...result,
          proof: { ...result.proof, ciphertextSha256: "f".repeat(64) },
        };
      },
    })
  );
});

/** Sole operator native filesystem fixture; no cloud, GPG or tar claims.
 * Caller supplies one fresh managed root-owned0700 directory. */
export async function runBackupV2ReadSlotProof(directory: string) {
  const bytes = encoder.encode("bounded-native-slot");
  const ref: BackupV2ObjectRef = validateBackupV2ObjectRef({
    fileId: "native-slot",
    fileName: backupV2ObjectName(C, uuid(2), "data", 0, uuid(3)),
    contentLength: bytes.length,
    contentSha1: hash(bytes, "sha1"),
    sha256: hash(bytes),
    action: "upload",
    uploadTimestamp: 1,
  });
  const files = await createBackupV2FileObjectReader(directory, {
    async getExactToFile(object, target) {
      equal(object, ref);
      using file = await Deno.open(target.path, {
        createNew: true,
        write: true,
        mode: 0o600,
      });
      let at = 0;
      while (at < bytes.length) {
        const written = await file.write(bytes.subarray(at));
        assert(written > 0 && written <= bytes.length - at);
        at += written;
      }
      await file.sync();
      const info = await file.stat();
      return {
        ...target,
        device: info.dev!,
        inode: info.ino!,
        bytes: bytes.length,
        sha1: ref.contentSha1,
        sha256: ref.sha256,
        uid: 0,
        mode: 384,
        links: 1,
      };
    },
  });
  const a = await files.open(ref), b = await files.open(ref);
  await rejects(() => files.open(ref));
  equal(await consume(a), bytes);
  equal(await consume(b), bytes);
  const cancel = await files.open(ref);
  await cancel.cancel();
  const remaining: string[] = [];
  for await (const file of Deno.readDir(directory)) remaining.push(file.name);
  equal(remaining, []);
  return {
    fixture: "native-read-slot-only",
    denoPid: Deno.pid,
    boundedSlots: 2,
    readBytes: bytes.length * 2,
    filesRemaining: 0,
  };
}
