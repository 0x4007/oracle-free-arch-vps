import { createHash } from "node:crypto";
import {
  backupV2ObjectName,
  type BackupV2ObjectStore,
} from "../scripts/backup-v2-contract.ts";
import {
  type BackupV2DocumentBinding,
  BackupV2DocumentPublisher,
  validateBackupV2VerificationMetadata,
} from "../scripts/backup-v2-index.ts";
import { BACKUP_V2_LIMITS } from "../scripts/backup-v2-profile.ts";
import {
  BackupV2Spool,
  type BackupV2SpoolStorage,
} from "../scripts/backup-v2-spool.ts";
import {
  type BackupV2UploadIdentity,
  BackupV2UploadJournal,
} from "../scripts/backup-v2-upload.ts";

const C = "generation-00000000-0000-4000-8000-000000000001",
  A = "00000000-0000-4000-8000-000000000002",
  P = "00000000-0000-4000-8000-000000000003";
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
function metadata() {
  return {
    schemaVersion: 2 as const,
    format: "backup-v2-verification-metadata" as const,
    captureId: C,
    metadataSha256: "3".repeat(64),
    bootSamples: [
      {
        role: "root" as const,
        member: "./boot/Image",
        bytes: 1,
        sha256: "1".repeat(64),
      },
      {
        role: "root" as const,
        member: "./boot/initramfs-linux.img",
        bytes: 2,
        sha256: "2".repeat(64),
      },
      {
        role: "staging-boot" as const,
        member: "./arch-vmlinuz",
        bytes: 1,
        sha256: "1".repeat(64),
      },
      {
        role: "staging-boot" as const,
        member: "./arch-initrd.img",
        bytes: 2,
        sha256: "2".repeat(64),
      },
    ],
  };
}
function fixture(kind: "metadata" | "manifest" = "metadata") {
  const slots = new Map<number, Uint8Array>(),
    remote = new Map<string, Uint8Array>(),
    bindings: BackupV2DocumentBinding[] = [];
  let puts = 0, encryptions = 0;
  const storage: BackupV2SpoolStorage = {
    create(index) {
      slots.set(index, new Uint8Array());
      return Promise.resolve({
        write(part) {
          const old = slots.get(index)!,
            next = new Uint8Array(old.length + part.length);
          next.set(old);
          next.set(part, old.length);
          slots.set(index, next);
          return Promise.resolve(part.length);
        },
        sync: () => Promise.resolve(),
        close() {},
      });
    },
    seal(index, expected) {
      return Promise.resolve({
        index,
        path: `/var/tmp/fixture/slot-${index}`,
        device: 1,
        inode: index + 1,
        ...expected,
        uid: 0,
        mode: 384,
        links: 1,
      });
    },
    async read(slot, consume) {
      const bytes = slots.get(slot.index)!;
      assert(hash(bytes) === slot.sha256);
      await consume(bytes);
    },
    remove(slot) {
      slots.delete(slot.index);
      return Promise.resolve();
    },
    removeEmpty(index) {
      slots.delete(index);
      return Promise.resolve();
    },
  };
  const store: BackupV2ObjectStore = {
    putFileOnce(intent) {
      puts++;
      const bytes = slots.get(intent.slot.index)!.slice();
      remote.set(intent.name, bytes);
      return Promise.resolve({
        fileId: `id-${puts}`,
        fileName: intent.name,
        contentLength: bytes.length,
        contentSha1: hash(bytes, "sha1"),
        sha256: hash(bytes),
        action: "upload",
        uploadTimestamp: 1,
      });
    },
    verifyExactReadback(ref) {
      assert(hash(remote.get(ref.fileName)!) === ref.sha256);
      return Promise.resolve();
    },
    getExactToFile() {
      throw new Error("Not used by publication fixture");
    },
    versionsPage() {
      return Promise.resolve({ items: [], next: null });
    },
  };
  const identity: BackupV2UploadIdentity = {
    captureId: C,
    attemptId: A,
    role: "recovery",
    kind,
  };
  const context = {
    identity,
    spool: new BackupV2Spool(storage),
    journal: new BackupV2UploadJournal(C, () => Promise.resolve()),
    store,
    classifyFailure: () => ({ retryable: false, mayHaveCommitted: false }),
    pace: () => Promise.resolve(),
  };
  const capabilities = {
    upload: context,
    bindings,
    persistBinding(binding: BackupV2DocumentBinding) {
      bindings.push(structuredClone(binding));
      return Promise.resolve();
    },
    encrypt(bytes: Uint8Array, _signal: AbortSignal) {
      encryptions++;
      return Promise.resolve({
        ciphertext: new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(bytes);
            c.close();
          },
        }),
        completed: Promise.resolve(),
      });
    },
  };
  return {
    capabilities,
    remote,
    bindings,
    puts: () => puts,
    encryptions: () => encryptions,
  };
}

Deno.test("v2 document publication binds plaintext before one exact transaction and reuses selection", async () => {
  const f = fixture(),
    publisher = new BackupV2DocumentPublisher(f.capabilities);
  const first = await publisher.publishVerificationMetadata(metadata());
  equal(f.bindings.length, 1);
  equal(f.puts(), 1);
  equal(f.encryptions(), 1);
  equal(await publisher.publishVerificationMetadata(metadata()), first);
  equal(f.puts(), 1);
  equal(f.encryptions(), 1);
  const restored = new BackupV2DocumentPublisher({
    ...f.capabilities,
    bindings: f.bindings,
  });
  equal(await restored.publishVerificationMetadata(metadata()), first);
  await rejects(() =>
    restored.publishVerificationMetadata({
      ...metadata(),
      metadataSha256: "4".repeat(64),
    })
  );
  equal(f.puts(), 1);
});
Deno.test("v2 document publisher never uploads after failed persistence or encryption completion", async () => {
  const f = fixture();
  f.capabilities.persistBinding = () =>
    Promise.reject(new Error("fsync failure"));
  await rejects(() =>
    new BackupV2DocumentPublisher(f.capabilities).publishVerificationMetadata(
      metadata(),
    )
  );
  equal(f.puts(), 0);
  equal(f.encryptions(), 0);
  const other = fixture();
  const original = other.capabilities.encrypt;
  other.capabilities.encrypt = async (bytes, signal) => ({
    ...await original(bytes, signal),
    completed: Promise.reject(undefined),
  });
  await rejects(() =>
    new BackupV2DocumentPublisher(other.capabilities)
      .publishVerificationMetadata(metadata())
  );
  equal(other.puts(), 0);
});
Deno.test("v2 document ciphertext overhead is bounded before any wire PUT", async () => {
  const f = fixture();
  f.capabilities.encrypt = () =>
    Promise.resolve({
      ciphertext: new ReadableStream({
        start(c) {
          c.enqueue(new Uint8Array(BACKUP_V2_LIMITS.manifestBytes + 1));
          c.close();
        },
      }),
      completed: Promise.resolve(),
    });
  await rejects(() =>
    new BackupV2DocumentPublisher(f.capabilities).publishVerificationMetadata(
      metadata(),
    )
  );
  equal(f.puts(), 0);
});
Deno.test("v2 document resume cannot re-encrypt bytes over an unresolved intent", async () => {
  const f = fixture();
  f.capabilities.upload.store.verifyExactReadback = () =>
    Promise.reject(new Error("readback failed"));
  await rejects(() =>
    new BackupV2DocumentPublisher(f.capabilities).publishVerificationMetadata(
      metadata(),
    )
  );
  equal(f.puts(), 1);
  equal(f.encryptions(), 1);
  await rejects(() =>
    new BackupV2DocumentPublisher({ ...f.capabilities, bindings: f.bindings })
      .publishVerificationMetadata(metadata())
  );
  equal(f.puts(), 1);
  equal(f.encryptions(), 1);
});
Deno.test("v2 chunk pages retain original ordering offsets and bounded document ordinals", async () => {
  const f = fixture("manifest");
  f.capabilities.upload.identity.role = "root";
  const data = new Uint8Array([1]);
  const chunks = Array.from({ length: 257 }, (_, ordinal) => ({
    ordinal,
    offset: ordinal,
    object: {
      fileId: `data-${ordinal}`,
      fileName: backupV2ObjectName(C, A, "data", ordinal, P),
      contentLength: 1,
      contentSha1: hash(data, "sha1"),
      sha256: hash(data),
      action: "upload" as const,
      uploadTimestamp: 1,
    },
  }));
  const pages = await new BackupV2DocumentPublisher(f.capabilities)
    .publishChunkPages(chunks);
  equal(
    pages.map((
      page,
    ) => [page.firstOrdinal, page.firstOffset, page.chunkCount, page.bytes]),
    [[0, 0, 256, 256], [256, 256, 1, 1]],
  );
  equal(f.puts(), 2);
  const wrong = fixture("manifest");
  await rejects(() =>
    new BackupV2DocumentPublisher(wrong.capabilities).publishChunkPages([{
      ...chunks[0],
      offset: 1,
    }])
  );
  equal(wrong.puts(), 0);
});
Deno.test("v2 verification metadata rejects extras wrong sample order and boot parity loss", async () => {
  await rejects(() =>
    validateBackupV2VerificationMetadata({ ...metadata(), extra: 1 })
  );
  const wrong = metadata();
  wrong.bootSamples[2].sha256 = "4".repeat(64);
  await rejects(() => validateBackupV2VerificationMetadata(wrong));
  const swapped = metadata();
  swapped.bootSamples.reverse();
  await rejects(() => validateBackupV2VerificationMetadata(swapped));
});
