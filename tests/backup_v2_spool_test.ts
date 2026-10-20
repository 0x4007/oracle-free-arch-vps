// Async capability fakes intentionally complete synchronously without native IO.
// deno-lint-ignore-file require-await
import {
  BackupV2Spool,
  type BackupV2SpoolStorage,
  createBackupV2FileSpoolStorage,
  writeBackupV2All,
} from "../scripts/backup-v2-spool.ts";
import type { BackupV2SealedSlot } from "../scripts/backup-v2-contract.ts";
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
async function rejects(run: () => Promise<unknown>) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed);
}
async function hash(bytes: Uint8Array, algorithm: string) {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest(algorithm, new Uint8Array(bytes)),
    ),
  ].map((
    n,
  ) => n.toString(16).padStart(2, "0")).join("");
}
function memoryStorage() {
  const files = new Map<number, number[]>();
  let maximum = 0;
  const storage: BackupV2SpoolStorage = {
    async create(index) {
      assert(!files.has(index));
      files.set(index, []);
      maximum = Math.max(maximum, files.size);
      return {
        async write(bytes) {
          const n = Math.min(2, bytes.length);
          files.get(index)!.push(...bytes.subarray(0, n));
          return n;
        },
        async sync() {},
        close() {},
      };
    },
    async seal(index, expected) {
      const bytes = new Uint8Array(files.get(index)!);
      assert(
        bytes.length === expected.bytes &&
          await hash(bytes, "SHA-1") === expected.sha1 &&
          await hash(bytes, "SHA-256") === expected.sha256,
      );
      return {
        index,
        path: `/fixture/slot-${index}`,
        device: 1,
        inode: index + 1,
        ...expected,
        uid: 0,
        mode: 384,
        links: 1,
      };
    },
    async read(slot, consume) {
      await consume(new Uint8Array(files.get(slot.index)!));
    },
    async remove(slot) {
      assert(files.has(slot.index));
      files.delete(slot.index);
    },
    async removeEmpty(index) {
      assert(files.get(index)?.length === 0);
      files.delete(index);
    },
  };
  return { storage, files, maximum: () => maximum };
}
function stream(parts: number[][], pulled?: () => void) {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled?.();
      if (index === parts.length) controller.close();
      else controller.enqueue(new Uint8Array(parts[index++]));
    },
  }, { highWaterMark: 0 });
}
Deno.test("spool handles short writes and rejects zero or oversized write progress", async () => {
  const bytes: number[] = [];
  await writeBackupV2All({
    async write(value) {
      bytes.push(value[0]);
      return 1;
    },
  }, new Uint8Array([1, 2, 3]));
  assert(bytes.join() === "1,2,3");
  await rejects(() =>
    writeBackupV2All({
      async write() {
        return 0;
      },
    }, new Uint8Array([1]))
  );
  await rejects(() =>
    writeBackupV2All({
      async write() {
        return 2;
      },
    }, new Uint8Array([1]))
  );
});
Deno.test("two occupied slots block the source until verified reclaim releases one", async () => {
  const memory = memoryStorage(), spool = new BackupV2Spool(memory.storage, 4);
  let pulls = 0;
  const iterator = spool.sealed(
    stream([[1, 2, 3, 4], [5, 6, 7, 8], [9]], () => pulls++),
  );
  const first = (await iterator.next()).value as BackupV2SealedSlot;
  const second = (await iterator.next()).value as BackupV2SealedSlot;
  let advanced = false;
  const waiting = iterator.next().then((value) => {
    advanced = true;
    return value;
  });
  await Promise.resolve();
  await Promise.resolve();
  assert(!advanced && pulls === 2 && memory.maximum() === 2);
  const { index, ...retained } = first;
  await spool.reclaim({ ...retained, index });
  const third = (await waiting).value as BackupV2SealedSlot;
  assert(third.bytes === 1 && memory.maximum() === 2);
  await spool.reclaim(second);
  await spool.reclaim(third);
  await iterator.return(undefined);
  assert(memory.files.size === 0);
});
Deno.test("producer errors retain occupied bytes and abort wakes a blocked slot acquisition", async () => {
  const memory = memoryStorage(), spool = new BackupV2Spool(memory.storage, 2);
  const iterator = spool.sealed(stream([[1, 2], [3, 4], [5, 6]]));
  await iterator.next();
  await iterator.next();
  const waiting = iterator.next();
  await spool.abort(new Error("fixture failure"));
  await rejects(() => waiting);
  assert(memory.files.size === 2);
});
const native =
  (await Deno.permissions.query({ name: "read", path: "/var/tmp" })).state ===
    "granted" &&
  (await Deno.permissions.query({ name: "write", path: "/var/tmp" })).state ===
    "granted";
Deno.test({
  name:
    "native: guarded files seal/hash and reclaim without an extra payload copy",
  ignore: !native,
  async fn() {
    const dir = await Deno.makeTempDir({
      dir: "/var/tmp",
      prefix: "arch-vps-m04-spool-",
    });
    try {
      const spool = new BackupV2Spool(
        await createBackupV2FileSpoolStorage(dir),
        4,
      );
      let count = 0;
      for await (const slot of spool.sealed(stream([[1, 2, 3, 4, 5]]))) {
        await spool.read(slot, (bytes) => {
          count += bytes.length;
        });
        await spool.reclaim(slot);
      }
      assert(count === 5);
      assert((await Array.fromAsync(Deno.readDir(dir))).length === 0);
      await Deno.writeTextFile(`${dir}/foreign`, "preserve");
      await rejects(() => createBackupV2FileSpoolStorage(dir));
      assert(await Deno.readTextFile(`${dir}/foreign`) === "preserve");
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});
