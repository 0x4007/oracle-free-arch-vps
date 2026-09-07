import {
  CHECKPOINT_LIMIT,
  type CheckpointBinding,
  CheckpointChannel,
  makeCheckpoint,
  persistCheckpoint,
  type RecoveryCheckpoint,
  remoteCheckpoint,
} from "../scripts/pi-recovery-checkpoint.ts";
import {
  type RestoreJournal,
  STAGES,
} from "../scripts/backblaze-machine-restore.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(promise: Promise<unknown>, fragment: string) {
  try {
    await promise;
  } catch (error) {
    assert(error instanceof Error && error.message.includes(fragment));
    return;
  }
  throw Error("Expected rejection");
}
const binding: CheckpointBinding = {
  requestId: "recovery-681c4067-aec2-45d5-9afb-77ee530e3a97",
  instanceId: "ocid1.instance.oc1.test.replacement",
  bootId: "681c4067-aec2-45d5-9afb-77ee530e3a97",
  generation: "generation-681c4067-aec2-45d5-9afb-77ee530e3a97",
  indexSha256: "ab".repeat(32),
  bootDiskPath: "/dev/disk/by-id/scsi-boot",
  rootDiskPath: "/dev/disk/by-id/scsi-root",
  bootDiskSerial: "boot",
  rootDiskSerial: "root",
};
function journal(count = 1): RestoreJournal {
  return {
    schemaVersion: 2,
    targetId: binding.instanceId,
    architecture: "aarch64",
    bootDiskPath: binding.bootDiskPath,
    rootDiskPath: binding.rootDiskPath,
    bootDiskSerial: binding.bootDiskSerial,
    rootDiskSerial: binding.rootDiskSerial,
    bootDiskBytes: 50 * 1024 ** 3,
    rootDiskBytes: 150 * 1024 ** 3,
    approval: {
      targetId: binding.instanceId,
      bootDiskPath: binding.bootDiskPath,
      rootDiskPath: binding.rootDiskPath,
      bootDiskSerial: binding.bootDiskSerial,
      rootDiskSerial: binding.rootDiskSerial,
      approvedAtUtc: "2026-09-07T01:00:00.000Z",
    },
    generation: binding.generation,
    indexSha256: binding.indexSha256,
    startedAtUtc: "2026-09-07T01:00:00.000Z",
    updatedAtUtc: `2026-09-07T01:00:0${count}.000Z`,
    completedStages: STAGES.slice(0, count),
    lvmTextSha256: "cd".repeat(32),
    partitionDumpSha256: { boot: "ef".repeat(32), root: "01".repeat(32) },
    archives: [],
  };
}
function memoryStorage() {
  let value: RecoveryCheckpoint | null = null;
  let writes = 0;
  return {
    read: (_path: string) => {
      if (!value) return Promise.reject(new Deno.errors.NotFound());
      return Promise.resolve(structuredClone(value));
    },
    write: (_path: string, next: unknown) => {
      value = structuredClone(next as RecoveryCheckpoint);
      writes++;
      return Promise.resolve();
    },
    writes: () => writes,
  };
}

Deno.test("Pi acknowledges only after durable storage returns; duplicate replay is idempotent", async () => {
  const storage = memoryStorage();
  let release!: () => void;
  let completed = false;
  const first = makeCheckpoint(binding, journal());
  const operation = persistCheckpoint(first, binding, "unused", {
    read: storage.read,
    write: async (path, value) => {
      await new Promise<void>((resolve) => release = resolve);
      await storage.write(path, value);
    },
  }).then((ack) => {
    completed = true;
    return ack;
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(!completed);
  release();
  assert((await operation).sha256 === first.sha256);
  assert(
    (await persistCheckpoint(first, binding, "unused", storage)).sha256 ===
      first.sha256,
  );
  assert(storage.writes() === 1);
  await persistCheckpoint(
    makeCheckpoint(binding, journal(2)),
    binding,
    "unused",
    storage,
  );
  assert(storage.writes() === 2);
});

Deno.test("Pi refuses skipped/regressing stages and changed immutable journal", async () => {
  const storage = memoryStorage();
  await rejects(
    persistCheckpoint(
      makeCheckpoint(binding, journal(2)),
      binding,
      "unused",
      storage,
    ),
    "initial",
  );
  await persistCheckpoint(
    makeCheckpoint(binding, journal()),
    binding,
    "unused",
    storage,
  );
  await rejects(
    persistCheckpoint(
      makeCheckpoint(binding, journal(3)),
      binding,
      "unused",
      storage,
    ),
    "next bound stage",
  );
  await rejects(
    persistCheckpoint(
      makeCheckpoint(binding, {
        ...journal(2),
        lvmTextSha256: "00".repeat(32),
      }),
      binding,
      "unused",
      storage,
    ),
    "next bound stage",
  );
  await persistCheckpoint(
    makeCheckpoint(binding, journal(2)),
    binding,
    "unused",
    storage,
  );
  await rejects(
    persistCheckpoint(
      makeCheckpoint(binding, journal()),
      binding,
      "unused",
      storage,
    ),
    "next bound stage",
  );
  assert(storage.writes() === 2);
});

Deno.test("Pi refuses wrong request, RAM boot, target and digest before persistence", async () => {
  const storage = memoryStorage();
  const value = makeCheckpoint(binding, journal());
  for (const key of ["requestId", "instanceId", "bootId"] as const) {
    await rejects(
      persistCheckpoint(
        { ...value, binding: { ...binding, [key]: "wrong" } },
        binding,
        "unused",
        storage,
      ),
      "differs",
    );
  }
  await rejects(
    persistCheckpoint(
      { ...value, sha256: "00".repeat(32) },
      binding,
      "unused",
      storage,
    ),
    "hash differs",
  );
  assert(storage.writes() === 0);
});

Deno.test("failed Pi persistence produces no acknowledgement", async () => {
  const storage = memoryStorage();
  await rejects(
    persistCheckpoint(makeCheckpoint(binding, journal()), binding, "unused", {
      read: storage.read,
      write: () => Promise.reject(Error("fsync failed")),
    }),
    "fsync failed",
  );
  assert(storage.writes() === 0);
});

function channelWithInput(bytes?: Uint8Array, timeout = 1000) {
  let cancelled = false;
  const sent: Uint8Array[] = [];
  const channel = new CheckpointChannel(
    new ReadableStream<Uint8Array>({
      start(controller) {
        if (bytes) controller.enqueue(bytes);
      },
      cancel() {
        cancelled = true;
      },
    }),
    new WritableStream<Uint8Array>({
      write(value) {
        sent.push(value);
      },
    }),
    timeout,
  );
  return { channel, cancelled: () => cancelled, sent };
}
Deno.test("remote checkpoint waits for matching ack and rejects wrong ack", async () => {
  const checkpoint = makeCheckpoint(binding, journal());
  for (const valid of [true, false]) {
    const fixture = channelWithInput(new TextEncoder().encode(
      JSON.stringify({
        kind: "recovery-checkpoint-ack",
        sha256: valid ? checkpoint.sha256 : "00".repeat(32),
      }) + "\n",
    ));
    const exchange = remoteCheckpoint(fixture.channel, binding)(journal());
    if (valid) await exchange;
    else await rejects(exchange, "acknowledgement differs");
    assert(fixture.sent.length === 1);
    await fixture.channel.close();
    assert(fixture.cancelled());
  }
});
Deno.test("missing acknowledgement cancels outstanding read and stops restore", async () => {
  const fixture = channelWithInput(undefined, 10);
  await rejects(
    remoteCheckpoint(fixture.channel, binding)(journal()),
    "timed out",
  );
  assert(fixture.cancelled());
  await rejects(fixture.channel.receive(), "closed");
});
Deno.test("permanently stalled output cannot block the checkpoint deadline", async () => {
  let disposed = 0;
  const input = new ReadableStream<Uint8Array>();
  const output = new WritableStream<Uint8Array>({
    write: () => new Promise<void>(() => {}),
  });
  const channel = new CheckpointChannel(input, output, 10, () => {
    disposed++;
  });
  let guard: ReturnType<typeof setTimeout> | undefined;
  try {
    await rejects(
      Promise.race([
        channel.send({ kind: "blocked-write" }),
        new Promise<never>((_, reject) => {
          guard = setTimeout(
            () => reject(Error("deadline did not return")),
            500,
          );
        }),
      ]),
      "timed out",
    );
    assert(disposed === 1);
    assert(!input.locked && !output.locked);
    await rejects(channel.send({ kind: "retry" }), "closed");
  } finally {
    clearTimeout(guard);
    await channel.close();
  }
});
Deno.test("oversized control input and malformed JSON poison the channel", async () => {
  for (
    const [bytes, fragment] of [
      [new Uint8Array(CHECKPOINT_LIMIT + 1), "bound"],
      [new TextEncoder().encode("not json\n"), "JSON"],
    ] as const
  ) {
    const fixture = channelWithInput(bytes);
    await rejects(fixture.channel.receive(), fragment);
    assert(fixture.cancelled());
  }
});

Deno.test({
  name: "Pi checkpoint survives real private-file roundtrip",
  ignore:
    (await Deno.permissions.query({ name: "write" })).state !== "granted" ||
    (await Deno.permissions.query({ name: "read" })).state !== "granted",
  fn: async () => {
    const directory = await Deno.makeTempDir();
    try {
      const value = makeCheckpoint(binding, journal());
      const path = `${directory}/checkpoint.json`;
      await persistCheckpoint(value, binding, path);
      assert(JSON.parse(await Deno.readTextFile(path)).sha256 === value.sha256);
      assert(((await Deno.stat(path)).mode! & 0o777) === 0o600);
      assert(
        (await persistCheckpoint(value, binding, path)).sha256 === value.sha256,
      );
    } finally {
      await Deno.remove(directory, { recursive: true });
    }
  },
});
