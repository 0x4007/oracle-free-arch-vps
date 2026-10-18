// Async capability fakes intentionally complete synchronously without native IO.
// deno-lint-ignore-file require-await
import {
  BackupV2Spool,
  type BackupV2SpoolStorage,
  createBackupV2FileSpoolStorage,
} from "../scripts/backup-v2-spool.ts";
import {
  type BackupV2UploadContext,
  BackupV2UploadJournal,
  openBackupV2UploadJournal,
  uploadBackupV2Stream,
} from "../scripts/backup-v2-upload.ts";
import type {
  BackupV2ObjectRef,
  BackupV2ObjectStore,
  BackupV2PutIntent,
} from "../scripts/backup-v2-contract.ts";
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
const CAPTURE = "generation-00000000-0000-4000-8000-000000000001",
  ATTEMPT = "00000000-0000-4000-8000-000000000002";
const identity = {
  captureId: CAPTURE,
  attemptId: ATTEMPT,
  role: "root" as const,
  kind: "data" as const,
};
class Retryable extends Error {}
function fixture(
  fault?: "lost" | "readback" | "corrupt" | "marker" | "always",
) {
  const files = new Map<number, number[]>(),
    records: string[] = [],
    objects = new Map<string, BackupV2ObjectRef>();
  let nextId = 10,
    putCalls = 0,
    verifyCalls = 0,
    verified = 0,
    clock = 0,
    delayed: BackupV2PutIntent | undefined;
  const pace: number[] = [];
  const storage: BackupV2SpoolStorage = {
    async create(index) {
      assert(!files.has(index));
      files.set(index, []);
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
      assert(files.get(slot.index)?.length === slot.bytes);
      await consume(new Uint8Array(files.get(slot.index)!));
    },
    async remove(slot) {
      assert(records.some((line) => {
        const record = JSON.parse(line);
        return record.type === "selected" &&
          record.object.sha256 === slot.sha256;
      }));
      files.delete(slot.index);
    },
    async removeEmpty(index) {
      assert(files.get(index)?.length === 0);
      files.delete(index);
    },
  };
  const journal = new BackupV2UploadJournal(CAPTURE, async (bytes) => {
    records.push(new TextDecoder().decode(bytes));
  });
  const ref = (i: BackupV2PutIntent): BackupV2ObjectRef => ({
    fileId: i.putId,
    fileName: i.name,
    contentLength: i.slot.bytes,
    contentSha1: i.slot.sha1,
    sha256: i.slot.sha256,
    uploadTimestamp: 1,
    action: "upload",
  });
  const store: BackupV2ObjectStore = {
    async putFileOnce(intent) {
      putCalls++;
      assert(records.some((line) => {
        const record = JSON.parse(line);
        return record.type === "intent" && record.intent.name === intent.name;
      }));
      if ((fault === "lost" || fault === "marker") && putCalls === 1) {
        delayed = intent;
        throw new Retryable("lost response");
      }
      if (fault === "always") throw new Retryable("unavailable");
      if (delayed && fault === "lost") objects.set(delayed.name, ref(delayed));
      const object = ref(intent);
      objects.set(intent.name, object);
      return object;
    },
    async verifyExactReadback(object) {
      verifyCalls++;
      assert(files.size > 0 && objects.has(object.fileName));
      if (fault === "readback" && verifyCalls <= 2) {
        throw new Retryable("GET interrupted");
      }
      if (fault === "corrupt") throw new Error("integrity");
    },
    async getExactToFile() {
      throw new Error("a third payload slot is forbidden during upload");
    },
    async versionsPage(prefix) {
      if (fault === "marker") {
        return {
          items: [{
            fileId: "hide",
            fileName: prefix,
            action: "hide",
            contentLength: 0,
            contentSha1: "none",
            uploadTimestamp: 1,
          }],
          next: null,
        };
      }
      return {
        items: [...objects.values()].filter((object) =>
          object.fileName === prefix
        ).map(({ sha256: _hash, ...version }) => version),
        next: null,
      };
    },
  };
  const context: BackupV2UploadContext = {
    identity,
    spool: new BackupV2Spool(storage, 4),
    journal,
    store,
    classifyFailure: (error) => ({
      retryable: error instanceof Retryable,
      mayHaveCommitted: error instanceof Retryable,
    }),
    pace: async (bytes) => {
      pace.push(bytes);
    },
    sleep: async (ms) => {
      clock += ms;
    },
    now: () => new Date(Date.UTC(2026, 9, 18) + clock),
    monotonicNow: () => clock,
    newPutId: () =>
      `00000000-0000-4000-8000-${(nextId++).toString().padStart(12, "0")}`,
    onVerified: () => {
      verified++;
    },
  };
  const source = () =>
    new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
        c.close();
      },
    });
  return {
    context,
    files,
    records,
    objects,
    source,
    pace,
    calls: () => ({ putCalls, verifyCalls, verified }),
  };
}
Deno.test("transaction preserves intent/readback/journal/reclaim order and hashes logical bytes once", async () => {
  const f = fixture(),
    result = await uploadBackupV2Stream(f.source(), f.context);
  assert(result.ciphertextBytes === 9 && result.chunks.length === 3);
  const expected = [
    ...new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]),
      ),
    ),
  ].map((n) => n.toString(16).padStart(2, "0")).join("");
  assert(result.ciphertextSha256 === expected && f.files.size === 0);
  assert(f.calls().verified === 3 && f.calls().putCalls === 3);
  assert(
    f.pace.filter((bytes) => bytes <= 4).reduce((a, b) => a + b, 0) === 18,
  );
  await rejects(() => uploadBackupV2Stream(f.source(), f.context));
});
Deno.test("lost response retains unresolved physical intent and uses a fresh name for identical retry bytes", async () => {
  const f = fixture("lost"),
    result = await uploadBackupV2Stream(f.source(), f.context);
  const intents = f.records.map((line) => JSON.parse(line)).filter((r) =>
    r.type === "intent"
  ).map((r) => r.intent);
  assert(
    result.ciphertextBytes === 9 && f.calls().putCalls === 4 &&
      f.objects.size === 4,
  );
  assert(
    intents[0].name !== intents[1].name &&
      intents[0].slot.sha256 === intents[1].slot.sha256,
  );
  assert(
    f.records.filter((line) => JSON.parse(line).type === "selected").length ===
      3,
  );
  assert(
    f.context.journal.snapshot().filter((record) => record.type === "intent")
      .length === 4,
  );
});
Deno.test("transient exact GET readback retries without another PUT or payload file", async () => {
  const f = fixture("readback");
  await uploadBackupV2Stream(f.source(), f.context);
  assert(
    f.calls().putCalls === 3 && f.calls().verifyCalls === 5 &&
      f.calls().verified === 3 && f.files.size === 0,
  );
});
Deno.test("integrity rejection and conflicting hide marker retain bytes and never select or reclaim", async () => {
  for (const mode of ["corrupt", "marker"] as const) {
    const f = fixture(mode);
    await rejects(() => uploadBackupV2Stream(f.source(), f.context));
    assert(
      f.files.size > 0 &&
        !f.records.some((line) => JSON.parse(line).type === "selected"),
    );
  }
});
Deno.test("journal fsync failure prevents the first wire PUT and preserves original bytes", async () => {
  const f = fixture();
  f.context.journal = new BackupV2UploadJournal(CAPTURE, async (bytes) => {
    if (JSON.parse(new TextDecoder().decode(bytes)).type === "intent") {
      throw new Error("fsync failed");
    }
  });
  await rejects(() => uploadBackupV2Stream(f.source(), f.context));
  assert(f.calls().putCalls === 0 && f.files.size > 0);
});
Deno.test("retry episode and physical attempt budgets terminate failure without discarding bytes", async () => {
  const f = fixture("always");
  await rejects(() => uploadBackupV2Stream(f.source(), f.context));
  assert(
    f.calls().putCalls > 3 && f.calls().putCalls <= 16 && f.files.size > 0,
  );
  assert(
    f.context.journal.snapshot().filter((r) => r.type === "episode").length ===
      1,
  );
});
Deno.test("journal replay retains old unresolved intents and blocks producer-attempt restart", async () => {
  const f = fixture();
  await uploadBackupV2Stream(f.source(), f.context);
  const old = f.context.journal.snapshot(),
    replay = new BackupV2UploadJournal(CAPTURE, async () => {}, old);
  assert(replay.snapshot().length === old.length);
  await rejects(() => replay.append({ type: "begin", identity }));
});
const native =
  (await Deno.permissions.query({ name: "read", path: "/var/tmp" })).state ===
    "granted" &&
  (await Deno.permissions.query({ name: "write", path: "/var/tmp" })).state ===
    "granted";
Deno.test({
  name: "native: upload journal fsync/replay and actual slot reclaim",
  ignore: !native,
  async fn() {
    const directory = await Deno.makeTempDir({
      dir: "/var/tmp",
      prefix: "arch-vps-m04-upload-",
    });
    try {
      const spoolDir = `${directory}/spool`,
        journalDir = `${directory}/journal`;
      await Deno.mkdir(spoolDir, { mode: 0o700 });
      await Deno.mkdir(journalDir, { mode: 0o700 });
      const spool = new BackupV2Spool(
        await createBackupV2FileSpoolStorage(spoolDir),
        4,
      );
      const journal = await openBackupV2UploadJournal(journalDir, CAPTURE),
        f = fixture();
      const objects = new Map<string, Uint8Array>();
      const store: BackupV2ObjectStore = {
        ...f.context.store,
        async putFileOnce(i) {
          objects.set(i.name, await Deno.readFile(i.slot.path));
          return {
            fileId: i.putId,
            fileName: i.name,
            contentLength: i.slot.bytes,
            contentSha1: i.slot.sha1,
            sha256: i.slot.sha256,
            action: "upload",
            uploadTimestamp: 1,
          };
        },
        async verifyExactReadback(ref) {
          const data = objects.get(ref.fileName)!;
          assert(data.length === ref.contentLength);
        },
      };
      try {
        const result = await uploadBackupV2Stream(f.source(), {
          ...f.context,
          spool,
          journal,
          store,
        });
        assert(result.ciphertextBytes === 9);
      } finally {
        journal.close();
      }
      const reopened = await openBackupV2UploadJournal(journalDir, CAPTURE);
      try {
        assert(reopened.snapshot().some((record) => record.type === "eof"));
      } finally {
        reopened.close();
      }
      assert((await Array.fromAsync(Deno.readDir(spoolDir))).length === 0);
    } finally {
      await Deno.remove(directory, { recursive: true });
    }
  },
});
