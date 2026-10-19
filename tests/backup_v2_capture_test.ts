// Async capability fakes deliberately complete synchronously without host IO.
// deno-lint-ignore-file require-await
import { createHash } from "node:crypto";
import {
  type CaptureSettings,
  fsRelativeExclusions,
  prepareRecipient,
  REQUIRED_EXCLUSIONS,
  ROLE_ORDER,
  TAR_OPTIONS,
} from "../scripts/backblaze-capture.ts";
import {
  type BackupV2CaptureContext,
  backupV2NamespaceScript,
  type BackupV2RoleProducer,
  backupV2TarArguments,
  captureBackupV2Generation,
  classifyBackupV2TarDiagnostics,
  createBackupV2RoleProducer,
  pumpBackupV2Capture,
  trackBackupV2CaptureNamespace,
  uploadBackupV2RoleProducer,
} from "../scripts/backup-v2-capture.ts";
import {
  backupV2BootSamples,
  backupV2CompatibilitySha256,
  type BackupV2ReusedRole,
  backupV2SourceConfigSha256,
  createBackupV2MetadataRunner,
  encodeBackupV2RecoveryMetadata,
  restoreBackupV2RecoveryMetadata,
  validateBackupV2ReusedRoles,
} from "../scripts/backup-v2-metadata.ts";
import {
  BackupV2Spool,
  type BackupV2SpoolStorage,
  createBackupV2FileSpoolStorage,
} from "../scripts/backup-v2-spool.ts";
import {
  BackupV2UploadJournal,
  openBackupV2UploadJournal,
} from "../scripts/backup-v2-upload.ts";
import { type BackupV2ObjectStore } from "../scripts/backup-v2-contract.ts";
import { sourceConfigSha256 } from "../scripts/backblaze-source-worker.ts";
import { shellQuote } from "../scripts/backup-guest.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}
function equals(actual: unknown, expected: unknown) {
  assert(JSON.stringify(actual) === JSON.stringify(expected));
}
function throws(fn: () => unknown) {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error("Expected rejection");
}
async function rejects(fn: () => Promise<unknown>) {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error("Expected rejection");
}
const hash = (bytes: Uint8Array | string) =>
  createHash("sha256").update(bytes).digest("hex");
const nativeIdentity = {
  pid: 222,
  startTicks: "123",
  bootId: "00000000-0000-4000-8000-000000000001",
  cgroup: "/fixture",
  kind: "tar" as const,
};
Deno.test("v2 namespace records actual readiness and tar birth before controls and retains diagnostics", async () => {
  const events: string[] = [];
  const bytes = new TextEncoder().encode(
    "BACKUP_V2_NAMESPACE_READY\nBACKUP_V2_TAR_CHILD 222\nBACKUP_V2_TAR_ACK\ntar: diagnostic\nBACKUP_V2_TAR_EXIT 222 0\n",
  );
  const child = {
    pid: 111,
    stdin: new WritableStream<Uint8Array>({
      write(bytes) {
        events.push(new TextDecoder().decode(bytes).trim());
      },
    }),
    stdout: new ReadableStream<Uint8Array>({
      start(c) {
        c.close();
      },
    }),
    stderr: new ReadableStream<Uint8Array>({
      start(c) {
        for (const byte of bytes) c.enqueue(Uint8Array.of(byte));
        c.close();
      },
    }),
    status: Promise.resolve({ code: 0 }),
  };
  const tracked = trackBackupV2CaptureNamespace(child, {
    assertManaged: async () => {},
    cancel: async () => {},
    async registerNamespace(actual) {
      assert(actual === child);
      events.push("MOUNT_SYNC");
    },
    async registerChild(pid) {
      equals(pid, 222);
      events.push("CHILD_SYNC");
      return {
        identity: nativeIdentity,
        async exit(status) {
          equals(status.code, 0);
          events.push("EXIT_SYNC");
        },
      };
    },
  });
  const text = new Response(tracked.stderr).text();
  await tracked.ready;
  equals(await text, "tar: diagnostic\n");
  equals(events, [
    "MOUNT_SYNC",
    "CAPTURE",
    "CHILD_SYNC",
    "TAR_START",
    "EXIT_SYNC",
  ]);
});
Deno.test("v2 namespace refuses failed registration wrong tar identity and incomplete control", async () => {
  for (const fault of ["mount", "birth", "identity", "eof"]) {
    const input = fault === "eof"
      ? "BACKUP_V2_NAMESPACE_READY\n"
      : "BACKUP_V2_NAMESPACE_READY\nBACKUP_V2_TAR_CHILD 222\nBACKUP_V2_TAR_ACK\nBACKUP_V2_TAR_EXIT 223 0\n";
    const tracked = trackBackupV2CaptureNamespace({
      pid: 111,
      stdin: new WritableStream({ write() {} }),
      stdout: new ReadableStream({
        start(c) {
          c.close();
        },
      }),
      stderr: new ReadableStream({
        start(c) {
          c.enqueue(new TextEncoder().encode(input));
          c.close();
        },
      }),
      status: Promise.resolve({ code: 0 }),
    }, {
      assertManaged: async () => {},
      cancel: async () => {},
      async registerNamespace() {
        if (fault === "mount") throw Error("fsync");
      },
      async registerChild() {
        if (fault === "birth") throw Error("fsync");
        return {
          identity: nativeIdentity,
          async exit() {
            throw Error("wrong exit must not be recorded");
          },
        };
      },
    });
    const text = new Response(tracked.stderr).text();
    text.catch(() => {});
    if (fault !== "identity") await rejects(() => tracked.ready);
    else await tracked.ready;
    await rejects(() => text);
  }
});
Deno.test("v2 metadata awaits optional tracked spawn and closes stdin after ACK", async () => {
  const events: string[] = [];
  const run = createBackupV2MetadataRunner("/fixture", {
    async assertManaged() {
      events.push("MANAGED");
    },
    async cancel() {},
    async spawn(command, args) {
      equals(command, "bash");
      assert(args.includes('ulimit -f 2048 || exit 80; exec "$@"'));
      events.push("REGISTERED_ACK");
      return {
        stdin: new WritableStream({
          close() {
            events.push("EOF");
          },
        }),
        stdout: new ReadableStream({
          start(c) {
            c.enqueue(new TextEncoder().encode("metadata"));
            c.close();
          },
        }),
        stderr: new ReadableStream({
          start(c) {
            c.close();
          },
        }),
        status: Promise.resolve({ code: 0 }),
      };
    },
  });
  equals((await run("id", [])).stdout, "metadata");
  equals(events, ["MANAGED", "REGISTERED_ACK", "EOF"]);
});
const CAPTURE = "generation-00000000-0000-4000-8000-000000000001";
const ATTEMPT = "00000000-0000-4000-8000-000000000002";
const settings: CaptureSettings = {
  generation: CAPTURE,
  recipientFile: "/fixture/recipient.asc",
  recipientSha256: "a".repeat(64),
  recipientFingerprint: "A".repeat(40),
  exclusionsText: REQUIRED_EXCLUSIONS.join("\n") + "\n",
  sources: ROLE_ORDER.map((name, index) => ({
    name,
    uuid: `aaaaaaa${index}-1111-2222-3333-444444444444`,
    filesystem: name === "root"
      ? "ext4"
      : name.includes("efi")
      ? "vfat"
      : "xfs",
    size: 1024 * (index + 1),
    ...(name === "root"
      ? { livePath: "/" as const }
      : name === "efi"
      ? { livePath: "/efi" as const }
      : {}),
  })),
};

Deno.test("v2 preserves source hash encoding and rejects an altered settings binding before IO", async () => {
  equals(backupV2SourceConfigSha256(settings), sourceConfigSha256(settings));
  equals(
    backupV2SourceConfigSha256({
      ...settings,
      sources: [...settings.sources].reverse(),
    }),
    sourceConfigSha256(settings),
  );
  let touched = false;
  await rejects(() =>
    captureBackupV2Generation(settings, {
      sourceConfigSha256: "b".repeat(64),
      native: {
        async assertManaged() {
          touched = true;
        },
        async cancel() {},
      },
    } as unknown as BackupV2CaptureContext)
  );
  assert(!touched);
});

Deno.test("v2 compatibility binds source mappings, profile, recipient, packages and boot identity", () => {
  const before = {
    layout: [{
      path: "/dev/example",
      size: 1024,
      uuid: "a-b",
      type: "part",
      fstype: "ext4",
      mountpoints: ["/"],
    }],
    pacman: "kernel1\n",
    bootHashes: "boot1\n",
  };
  const original = backupV2CompatibilitySha256(settings, before);
  for (
    const changed of [
      { ...before, pacman: "kernel2\n" },
      { ...before, bootHashes: "boot2\n" },
      { ...before, layout: [{ ...before.layout[0], size: 1025 }] },
    ]
  ) assert(backupV2CompatibilitySha256(settings, changed) !== original);
  assert(
    backupV2CompatibilitySha256({
      ...settings,
      recipientSha256: "b".repeat(64),
    }, before) !== original,
  );
});

Deno.test("v2 native argv retains metadata and all exclusions without archive staging", () => {
  const excludes = fsRelativeExclusions(REQUIRED_EXCLUSIONS.slice());
  const args = backupV2TarArguments(excludes, "/fixture/inventory.fifo");
  for (const option of TAR_OPTIONS) assert(args.includes(option));
  for (const path of excludes) assert(args.includes(`--exclude=${path}`));
  assert(args.includes("--index-file=/fixture/inventory.fifo"));
  assert(args.includes("--quoting-style=c") && args.includes("--utc"));
  equals(args.slice(-2), ["--", "."]);
  for (const source of settings.sources) {
    const script = backupV2NamespaceScript({
      source,
      role: source.name as typeof ROLE_ORDER[number],
      stage: "/fixture/stage",
      index: "/fixture/index",
      status: "/fixture/status",
      exclusions: excludes,
    });
    assert(script.includes("mount --make-rprivate /"));
    assert(script.includes("exec 1>&-") && script.includes("RELEASE"));
    assert(!script.includes(".tar.zst.partial") && !script.includes("du -sx"));
    if (!source.livePath) {
      assert(script.includes(`/dev/disk/by-uuid/${source.uuid}`));
      assert(
        script.includes(source.filesystem === "xfs" ? "ro,norecovery" : "'ro'"),
      );
      assert(script.includes("blockdev --getsize64"));
    }
  }
});
Deno.test({
  name: "v2 generated cold cleanup leaves its cwd and preserves failures",
  ignore:
    (await Deno.permissions.query({ name: "run", command: "/usr/bin/bash" }))
      .state !== "granted",
  async fn() {
    const source = settings.sources.find((item) =>
      item.name === "staging-boot"
    )!;
    const cleanup = backupV2NamespaceScript({
      source,
      role: "staging-boot",
      stage: "/fixture",
      index: "/fixture/index",
      status: "/fixture/status",
      exclusions: [],
    }).split("\n").find((line) => line.startsWith("cleanup() {"));
    assert(cleanup);
    // These command fakes exercise the generated shell's status/ordering. The
    // separate operator fixture proves the real kernel mount/CWD behavior.
    for (const mode of ["success", "producer", "cd", "umount"] as const) {
      const result = await new Deno.Command("/usr/bin/bash", {
        args: [
          "-c",
          [
            "d=$PWD",
            `umount() { test "$PWD" != "$d" || return 32; printf 'umount\\n'; ${
              mode === "umount" ? "return 32;" : "return 0;"
            } }`,
            "rmdir() { printf 'rmdir\\n'; }",
            cleanup,
            "trap cleanup EXIT",
            ...(mode === "cd" ? ["cd() { return 1; }"] : []),
            `exit ${mode === "producer" ? 23 : 0}`,
          ].join("\n"),
        ],
        clearEnv: true,
        env: { PATH: "/usr/bin:/bin" },
        stdout: "piped",
        stderr: "piped",
      }).output();
      equals(
        result.code,
        mode === "success" ? 0 : mode === "producer" ? 23 : 79,
      );
      equals(
        new TextDecoder().decode(result.stdout),
        mode === "cd" ? "" : "umount\nrmdir\n",
      );
      equals(result.stderr.length, 0);
    }
  },
});

Deno.test("v2 drift classification rejects shrink, unreadable, unknown and cold-role drift", () => {
  const changed = "tar: ./volatile: file changed as we read it\n";
  const proof = classifyBackupV2TarDiagnostics("root", 1, changed);
  equals(proof.driftRecords, 1);
  equals(proof.driftSha256, hash(changed));
  for (
    const text of [
      "tar: ./missing: Cannot stat: No such file or directory\n",
      "tar: ./file: File shrank by 1 byte; padding with zeros\n",
      "unclassified\n",
      "",
    ]
  ) {
    throws(() => classifyBackupV2TarDiagnostics("root", 1, text));
  }
  throws(() => classifyBackupV2TarDiagnostics("staging-boot", 1, changed));
  throws(() => classifyBackupV2TarDiagnostics("root", 2, changed));
  throws(() =>
    classifyBackupV2TarDiagnostics("root", 0, "x".repeat(1024 * 1024 + 1))
  );
  equals(
    classifyBackupV2TarDiagnostics("root", 0, "tar: ./socket: socket ignored\n")
      .driftRecords,
    0,
  );
});
Deno.test("v2 one-filesystem boundaries do not count as drift or mask fatal diagnostics", () => {
  const boundary = [
    'tar: "./efi/": file is on a different filesystem; not dumped',
    'tar: "./var/lib/docker/rootfs/overlayfs/example/": file is on a different filesystem; not dumped',
  ].join("\n") + "\n";
  const changed = 'tar: "./live-data": file changed as we read it\n';
  const socket = 'tar: "./runtime.sock": socket ignored\n';
  for (const role of ROLE_ORDER) {
    const proof = classifyBackupV2TarDiagnostics(role, 0, boundary);
    equals(proof.driftRecords, 0);
    equals(proof.driftSha256, hash(""));
    throws(() => classifyBackupV2TarDiagnostics(role, 1, boundary));
    throws(() => classifyBackupV2TarDiagnostics(role, 2, boundary + changed));
    if (role !== "root") {
      throws(() => classifyBackupV2TarDiagnostics(role, 0, boundary + changed));
      throws(() => classifyBackupV2TarDiagnostics(role, 1, boundary + changed));
    }
  }
  const live = classifyBackupV2TarDiagnostics(
    "root",
    1,
    changed + socket + boundary,
  );
  equals(live.driftRecords, 1);
  equals(live.driftSha256, hash(changed));
  throws(() => classifyBackupV2TarDiagnostics("recovery", 0, boundary));
  for (
    const fatal of [
      "tar: ./missing: Cannot stat: No such file or directory\n",
      "tar: ./private: Cannot open: Permission denied\n",
      "tar: ./file: File shrank by 1 byte; padding with zeros\n",
      "tar: ./mount: file is on a different filesystem; not dumped: read error\n",
      "unclassified\n",
    ]
  ) {
    throws(() =>
      classifyBackupV2TarDiagnostics("root", 1, changed + boundary + fatal)
    );
  }
});

Deno.test("v2 pump waits for downstream writes and propagates input/write failures", async () => {
  let release!: () => void, written = 0, pulled = 0;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const source = new ReadableStream<Uint8Array>({
    pull(c) {
      pulled++;
      if (pulled <= 3) c.enqueue(new Uint8Array([pulled]));
      else c.close();
    },
  }, { highWaterMark: 0 });
  const sink = new WritableStream<Uint8Array>({
    async write() {
      written++;
      await gate;
    },
  });
  const task = pumpBackupV2Capture(source, sink);
  await new Promise((resolve) => setTimeout(resolve, 0));
  equals(written, 1);
  equals(pulled, 1);
  release();
  await task;
  equals(written, 3);
  let cancelled = false;
  await rejects(() =>
    pumpBackupV2Capture(
      new ReadableStream({
        pull(c) {
          c.enqueue(new Uint8Array([1]));
        },
        cancel() {
          cancelled = true;
        },
      }),
      new WritableStream({
        write() {
          throw new Error("sink failure");
        },
      }),
    )
  );
  assert(cancelled);
});

Deno.test("v2 recovery metadata binds exact boot names, byte lengths and both boot copies", () => {
  const h1 = "1".repeat(64), h2 = "2".repeat(64);
  const root = `${h1}  /boot/Image\n${h2}  /boot/initramfs-linux.img\n`;
  const stage = `${h1}  ./arch-vmlinuz\n${h2}  ./arch-initrd.img\n`;
  const boot = backupV2BootSamples(root, stage, [10, 20], [10, 20]);
  equals(boot.map((item) => new TextDecoder().decode(item.member)), [
    "./boot/Image",
    "./boot/initramfs-linux.img",
    "./arch-vmlinuz",
    "./arch-initrd.img",
  ]);
  throws(() => backupV2BootSamples(root, stage, [10, 20], [10, 21]));
  throws(() =>
    backupV2BootSamples(root.replace("/boot/Image", "/boot/other"), stage, [
      10,
      20,
    ], [10, 20])
  );
  const metadata = encodeBackupV2RecoveryMetadata({
    archives: [{
      role: "root",
      format: "tar.zst.gpg",
      ciphertextBytes: 20,
      ciphertextSha256: h1,
    }],
    boot,
  });
  equals(metadata.sha256, hash(metadata.bytes));
  assert(!new TextDecoder().decode(metadata.bytes).includes('"path":'));
  throws(() =>
    encodeBackupV2RecoveryMetadata({ text: "x".repeat(8 * 1024 * 1024) })
  );
});

function uploadFixture(fault?: "readback" | "native") {
  const files = new Map<number, Uint8Array>();
  let clock = 0,
    firstPut: string | undefined,
    complete!: (value: { captureFinishedAtUtc: string }) => void;
  let nativeFailure!: (error: Error) => void,
    cancelled = 0,
    released = 0,
    verified = 0;
  const now = () => new Date(Date.UTC(2026, 9, 18) + ++clock);
  const completion = new Promise<{ captureFinishedAtUtc: string }>(
    (resolve, reject) => {
      complete = resolve;
      nativeFailure = reject;
    },
  );
  const storage: BackupV2SpoolStorage = {
    async create(index) {
      files.set(index, new Uint8Array());
      return {
        async write(bytes) {
          const previous = files.get(index)!;
          const merged = new Uint8Array(previous.length + bytes.length);
          merged.set(previous);
          merged.set(bytes, previous.length);
          files.set(index, merged);
          return bytes.length;
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
      await consume(files.get(slot.index)!);
    },
    async remove(slot) {
      files.delete(slot.index);
    },
    async removeEmpty(index) {
      files.delete(index);
    },
  };
  const store: BackupV2ObjectStore = {
    async putFileOnce(intent) {
      firstPut ??= new Date(Date.UTC(2026, 9, 18) + clock).toISOString();
      if (fault === "native") nativeFailure(new Error("GPG truncated trailer"));
      else complete({ captureFinishedAtUtc: now().toISOString() });
      return {
        fileId: intent.putId,
        fileName: intent.name,
        action: "upload",
        contentLength: intent.slot.bytes,
        contentSha1: intent.slot.sha1,
        sha256: intent.slot.sha256,
        uploadTimestamp: 1,
      };
    },
    async verifyExactReadback() {
      if (fault === "readback") throw new Error("integrity");
      verified++;
    },
    async versionsPage() {
      return { items: [], next: null };
    },
    async getExactToFile() {
      throw new Error("readback staging forbidden");
    },
  };
  const producer: BackupV2RoleProducer = {
    ciphertext: new ReadableStream({
      start(c) {
        c.enqueue(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
        c.close();
      },
    }),
    completion,
    async release() {
      assert(verified === 2);
      released++;
      return {
        inventory: {
          encoding: "backup-v2-inventory-1",
          members: 1,
          pathBytes: 2,
          encodedBytes: 10,
          sha256: hash("./"),
        },
        producer: {
          tarExitCode: 0,
          zstdExitCode: 0,
          gpgExitCode: 0,
          driftRecords: 0,
          driftSha256: hash(""),
        },
      };
    },
    async cancel() {
      cancelled++;
      nativeFailure(new Error("cancelled"));
    },
  };
  let putNumber = 10;
  const context = {
    spool: new BackupV2Spool(storage, 4),
    journal: new BackupV2UploadJournal(CAPTURE, async () => {}),
    store,
    pace: async () => {},
    classifyFailure: () => ({ retryable: false, mayHaveCommitted: false }),
    now,
    sourceConfigSha256: backupV2SourceConfigSha256(settings),
    newPutId: () =>
      `00000000-0000-4000-8000-${String(putNumber++).padStart(12, "0")}`,
  };
  return {
    producer,
    context,
    state: () => ({
      firstPut,
      cancelled,
      released,
      verified,
      files: files.size,
    }),
  };
}
const params = {
  settings,
  role: "root" as const,
  attemptId: ATTEMPT,
  captureStartedAtUtc: "2026-10-18T00:00:00.000Z",
  compatibilitySha256: "b".repeat(64),
};

Deno.test("v2 role upload records first actual PUT and independent producer completion before release", async () => {
  const f = uploadFixture();
  const result = await uploadBackupV2RoleProducer({
    ...params,
    producer: f.producer,
  }, f.context);
  equals(result.uploadStartedAtUtc, f.state().firstPut);
  assert(result.captureStartedAtUtc < result.uploadStartedAtUtc);
  assert(result.uploadStartedAtUtc < result.captureFinishedAtUtc);
  assert(result.captureFinishedAtUtc < result.uploadFinishedAtUtc);
  equals(f.state().released, 1);
  equals(f.state().files, 0);
  equals(f.state().cancelled, 0);
  equals(result.chunks.length, 2);
  equals(result.ciphertextBytes, 8);
});

for (const fault of ["readback", "native"] as const) {
  Deno.test(`v2 role ${fault} failure cancels and never releases an accepted producer`, async () => {
    const f = uploadFixture(fault);
    await rejects(() =>
      uploadBackupV2RoleProducer({ ...params, producer: f.producer }, f.context)
    );
    equals(f.state().released, 0);
    equals(f.state().cancelled, 1);
  });
}

async function reuseFixture() {
  const f = uploadFixture();
  const capture = await uploadBackupV2RoleProducer({
    ...params,
    producer: f.producer,
  }, f.context);
  const before = {
    layout: settings.sources.map((source, index) => ({
      path: `/dev/fixture${index}`,
      type: "part",
      size: source.size,
      fstype: source.filesystem,
      uuid: source.uuid,
      mountpoints: source.livePath ? [source.livePath] : [null],
    })),
    pacman: "kernel 1\n",
    bootHashes: `${"1".repeat(64)}  /boot/Image\n${
      "2".repeat(64)
    }  /boot/initramfs-linux.img\n`,
  };
  capture.compatibilitySha256 = backupV2CompatibilitySha256(settings, before);
  const recovery = {
    role: "root" as const,
    initial: before,
    tools: {},
    bootBytes: [10, 20],
  };
  const entry: BackupV2ReusedRole = { capture, recovery };
  const validate = (entries: BackupV2ReusedRole[]) =>
    validateBackupV2ReusedRoles(
      entries,
      settings,
      before,
      {},
      [10, 20],
      "2026-10-18T00:01:00.000Z",
    );
  return { entry, before, validate };
}

Deno.test("v2 reuse preserves original intervals and attempts and detaches checkpoint aliases", async () => {
  const f = await reuseFixture();
  const old = JSON.stringify(f.entry.capture),
    reused = f.validate([f.entry]).get("root")!;
  equals(JSON.stringify(reused.capture), old);
  f.entry.capture.attemptId = "00000000-0000-4000-8000-000000000099";
  equals(reused.capture.attemptId, ATTEMPT);
  assert(
    reused.capture.captureFinishedAtUtc !== reused.capture.uploadFinishedAtUtc,
  );
});

Deno.test("v2 reuse rejects missing snapshots, changed identities, boot metadata, future intervals and duplicates", async () => {
  const f = await reuseFixture();
  for (
    const change of [
      (entry: BackupV2ReusedRole) => {
        entry.capture.compatibilitySha256 = "c".repeat(64);
      },
      (entry: BackupV2ReusedRole) => {
        entry.capture.recipientSha256 = "c".repeat(64);
      },
      (entry: BackupV2ReusedRole) => {
        entry.capture.sourceConfigSha256 = "c".repeat(64);
      },
      (entry: BackupV2ReusedRole) => {
        entry.capture.captureId =
          "generation-00000000-0000-4000-8000-000000000099";
      },
      (entry: BackupV2ReusedRole) => {
        entry.capture.uploadFinishedAtUtc = "2027-01-01T00:00:00.000Z";
      },
      (entry: BackupV2ReusedRole) => {
        if (entry.recovery.role === "root") entry.recovery.bootBytes[0]++;
      },
      (entry: BackupV2ReusedRole) => {
        if (entry.recovery.role === "root") {
          entry.recovery.initial.bootHashes = "changed";
        }
      },
    ]
  ) {
    const changed = structuredClone(f.entry);
    change(changed);
    throws(() => f.validate([changed]));
  }
  throws(() => f.validate([f.entry, f.entry]));
  throws(() =>
    f.validate([{ capture: f.entry.capture } as BackupV2ReusedRole])
  );
});

Deno.test("v2 reuse keeps cold-role original boot and swap metadata and rejects partial recovery reuse", async () => {
  const f = await reuseFixture();
  const staging: BackupV2ReusedRole = {
    capture: { ...f.entry.capture, role: "staging-boot" },
    recovery: {
      role: "staging-boot",
      beforeHashes: `${"1".repeat(64)}  ./arch-vmlinuz\n${
        "2".repeat(64)
      }  ./arch-initrd.img\n`,
      afterHashes: `${"1".repeat(64)}  ./arch-vmlinuz\n${
        "2".repeat(64)
      }  ./arch-initrd.img\n`,
      beforeBytes: "10\n20\n",
      afterBytes: "10\n20\n",
    },
  };
  assert(f.validate([staging]).has("staging-boot"));
  const changed = structuredClone(staging);
  if (changed.recovery.role === "staging-boot") {
    changed.recovery.afterBytes = "10\n21\n";
  }
  throws(() => f.validate([changed]));
  const oracle: BackupV2ReusedRole = {
    capture: { ...f.entry.capture, role: "oracle-root" },
    recovery: { role: "oracle-root", swapfileStat: "present 4096 600 0 0\n" },
  };
  equals(f.validate([oracle]).get("oracle-root")!.recovery, oracle.recovery);
  const original = {
    role: "recovery" as const,
    text: "{}",
    sha256: hash("{}"),
  };
  throws(() =>
    f.validate([{
      capture: {
        ...f.entry.capture,
        role: "recovery",
        format: "json.zst.gpg",
        inventory: null,
      },
      recovery: original,
    }])
  );
});

Deno.test("v2 complete recovery reuse preserves exact plaintext and rejects regenerated or incomplete metadata", async () => {
  const f = await reuseFixture(),
    boot = backupV2BootSamples(
      f.before.bootHashes,
      `${"1".repeat(64)}  ./arch-vmlinuz\n${
        "2".repeat(64)
      }  ./arch-initrd.img\n`,
      [10, 20],
      [10, 20],
    );
  const body = {
    schemaVersion: 2,
    format: "backup-v2-recovery",
    generation: CAPTURE,
    sourceConfigSha256: backupV2SourceConfigSha256(settings),
    compatibilitySha256: backupV2CompatibilitySha256(settings, f.before),
    recipient: {
      fingerprint: settings.recipientFingerprint,
      publicSha256: settings.recipientSha256,
    },
    startedAtUtc: params.captureStartedAtUtc,
    finishedAtUtc: f.entry.capture.uploadFinishedAtUtc,
    consistency: "live-file-copy",
    sourceShutdown: false,
    machineBootRestoreProved: false,
    captureMethod: "live-file-copy",
    sources: settings.sources,
    blockLayouts: { initial: f.before.layout, final: f.before.layout },
    mountMetadata: [],
    findmnt: {},
    partitionTables: [],
    lvm: {},
    packages: f.before.pacman,
    bootHashes: { root: f.before.bootHashes },
    finalChecks: {},
    exclusions: {},
    swapRecreation: {},
    procCmdline: "original",
    fstab: "original",
    tools: {},
    archiveOptions: {},
    efivars: {},
    archives: [f.entry.capture],
    bootSamples: boot.map((sample) => ({
      ...sample,
      member: new TextDecoder().decode(sample.member),
    })),
  };
  const original = {
    role: "recovery" as const,
    text: JSON.stringify(body),
    sha256: hash(JSON.stringify(body)),
  };
  const restored = restoreBackupV2RecoveryMetadata(
    original,
    settings,
    f.before,
    [f.entry.capture],
    boot,
  );
  equals(new TextDecoder().decode(restored.bytes), original.text);
  equals(restored.sha256, original.sha256);
  throws(() =>
    restoreBackupV2RecoveryMetadata(
      { ...original, text: original.text + " " },
      settings,
      f.before,
      [f.entry.capture],
      boot,
    )
  );
  throws(() =>
    restoreBackupV2RecoveryMetadata(original, settings, f.before, [], boot)
  );
  throws(() =>
    restoreBackupV2RecoveryMetadata(
      { role: "recovery", text: "{}", sha256: hash("{}") },
      settings,
      f.before,
      [f.entry.capture],
      boot,
    )
  );
});

// The sole operator supplies this public, task-local custody record. No keys
// are generated here; decryption uses the existing off-host agent adapter.
const NATIVE_ROOT = "/var/tmp/arch-vps-m05-fixture";
interface NativeInput {
  unitName: string;
  expectedCgroup: string;
  publicHome: string;
  recipientFile: string;
  recipientSha256: string;
  recipientFingerprint: string;
  oracleCommand: string[];
  fixtures: { source: string; oracle: string }[];
}
const native =
  (await Deno.permissions.query({ name: "run", command: "bash" })).state ===
    "granted" &&
  (await Deno.permissions.query({ name: "read", path: NATIVE_ROOT })).state ===
    "granted" &&
  (await Deno.permissions.query({ name: "write", path: NATIVE_ROOT })).state ===
    "granted";
async function nativeCustody() {
  const input = JSON.parse(
    await Deno.readTextFile(`${NATIVE_ROOT}/input.json`),
  ) as NativeInput;
  assert(
    /^arch-vps-b2-m05-fixture-[a-zA-Z0-9-]+\.service$/.test(input.unitName),
  );
  const assertManaged = async () => {
    const result = await new Deno.Command("cat", {
      args: ["/proc/self/cgroup"],
      stdout: "piped",
      stderr: "piped",
    }).output();
    assert(result.success);
    const actual = new TextDecoder().decode(result.stdout).trim();
    assert(
      actual === input.expectedCgroup && actual.endsWith(`/${input.unitName}`),
    );
  };
  await assertManaged();
  const cancel = async () => {
    await assertManaged();
    await new Deno.Command("systemctl", {
      args: ["--no-block", "stop", input.unitName],
      stdout: "null",
      stderr: "null",
    }).output();
    throw new Error("Task-owned native fixture unit cancellation requested");
  };
  return { input, custody: { assertManaged, cancel } };
}

Deno.test({
  name: "native: m05 tiny capture/list raw-name protocol",
  ignore: !native,
  async fn() {
    const { custody } = await nativeCustody();
    const directory = await Deno.makeTempDir({
      dir: NATIVE_ROOT,
      prefix: "protocol-",
    });
    const source = `${directory}/source`, index = `${directory}/index.txt`;
    await Deno.mkdir(source, { mode: 0o700 });
    const prep = await new Deno.Command("python3", {
      args: [
        "-c",
        "import os,sys; p=os.fsencode(sys.argv[1]); f=p+b'/name-'+bytes([255])+b'\\n'; open(f,'wb').write(b'fixture'); os.link(f,p+b'/hard'); os.symlink(b'hard',p+b'/sym'); os.setxattr(f,b'user.m05',b'value')",
        source,
      ],
      stdout: "piped",
      stderr: "piped",
    }).output();
    assert(prep.success);
    const acl = await new Deno.Command("setfacl", {
      args: ["-m", "u:65534:r--", `${source}/hard`],
      stdout: "piped",
      stderr: "piped",
    }).output();
    assert(acl.success);
    const create = new Deno.Command("tar", {
      args: backupV2TarArguments([], index),
      cwd: source,
      env: { LC_ALL: "C", TZ: "UTC" },
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const list = new Deno.Command("tar", {
      args: [
        "--list",
        "--verbose",
        "--numeric-owner",
        "--full-time",
        "--utc",
        "--quoting-style=c",
        "--file=-",
      ],
      env: { LC_ALL: "C", TZ: "UTC" },
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    try {
      const diagnostic = (async () => {
        let bytes = 0;
        for await (const part of create.stderr) {
          bytes += part.length;
          assert(bytes <= 65536);
        }
      })();
      const [_, made, listed] = await Promise.all([
        pumpBackupV2Capture(create.stdout, list.stdin),
        create.status,
        list.output(),
        diagnostic,
      ]);
      assert(made.success && listed.success && listed.stderr.length < 65536);
      const { consumeNativeTarListing, createTarInventory } = await import(
        "../scripts/backup-tar-consumers.ts"
      );
      const original = createTarInventory([], false),
        recovered = createTarInventory([], false);
      const createText = await Deno.readFile(index);
      assert(createText.length <= 65536 && listed.stdout.length <= 65536);
      const stream = (bytes: Uint8Array) =>
        new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(bytes);
            c.close();
          },
        });
      await consumeNativeTarListing(stream(createText), original.add);
      await consumeNativeTarListing(stream(listed.stdout), recovered.add);
      equals(original.finish().inventory, recovered.finish().inventory);
      console.log(
        JSON.stringify({
          proof: "create/list raw-name protocol",
          bytes: createText.length,
          source: "synthetic-only",
        }),
      );
    } catch (error) {
      await custody.cancel();
      throw error;
    }
  },
});

/** Fixture store is a separately labelled simulation, never a real B2 write. */
Deno.test({
  name: "native: m05 bounded capture upload and independent restore",
  ignore: !native,
  async fn() {
    const { input, custody } = await nativeCustody();
    assert(input.fixtures.length === 2 && input.oracleCommand.length > 0);
    const { verifyBackupStreamArchive } = await import(
      "../scripts/backup-stream-verifier.ts"
    );
    const { makeStreamDecryptArchive } = await import(
      "../scripts/backblaze-file-backup.ts"
    );
    const decrypt = makeStreamDecryptArchive(input.publicHome);
    const fileHash = async (path: string) => {
      const h = createHash("sha256"), file = await Deno.open(path);
      for await (const bytes of file.readable) h.update(bytes);
      return h.digest("hex");
    };
    const pointData: {
      role: Awaited<ReturnType<typeof uploadBackupV2RoleProducer>>;
      cloud: Map<string, string>;
      stage: string;
      oracle: string;
    }[] = [];
    const local = async (path: string) => {
      assert(
        path.startsWith(`${NATIVE_ROOT}/`) &&
          await Deno.realPath(path) === path,
      );
    };
    for (const [index, fixture] of input.fixtures.entries()) {
      await local(fixture.source);
      await local(fixture.oracle);
      const stage = `${NATIVE_ROOT}/stage-${index}`,
        remote = `${NATIVE_ROOT}/simulated-cloud-${index}`;
      await Deno.mkdir(stage, { mode: 0o700 });
      await Deno.mkdir(remote, { mode: 0o700 });
      const configured = {
        ...settings,
        generation: `generation-00000000-0000-4000-8000-${
          String(index + 1).padStart(12, "0")
        }`,
        recipientFile: input.recipientFile,
        recipientSha256: input.recipientSha256,
        recipientFingerprint: input.recipientFingerprint,
      };
      await prepareRecipient(
        configured,
        stage,
        createBackupV2MetadataRunner(stage, custody),
      );
      const spoolDirectory = `${stage}/spool`;
      await Deno.mkdir(spoolDirectory, { mode: 0o700 });
      const underlying = await createBackupV2FileSpoolStorage(spoolDirectory);
      let occupied = 0, peak = 0;
      const storage: BackupV2SpoolStorage = {
        ...underlying,
        async create(index) {
          const writer = await underlying.create(index);
          return {
            async write(bytes) {
              const count = await writer.write(bytes);
              occupied += count;
              peak = Math.max(peak, occupied);
              assert(peak <= 16 * 1024 * 1024);
              return count;
            },
            sync: () => writer.sync(),
            close: () => writer.close(),
          };
        },
        async remove(slot) {
          await underlying.remove(slot);
          occupied -= slot.bytes;
        },
      };
      const spool = new BackupV2Spool(storage, 8 * 1024 * 1024),
        journal = await openBackupV2UploadJournal(stage, configured.generation);
      const cloud = new Map<string, string>();
      const store: BackupV2ObjectStore = {
        async putFileOnce(intent) {
          const path = `${remote}/${intent.putId}`;
          await Deno.copyFile(intent.slot.path, path);
          cloud.set(intent.putId, path);
          return {
            fileId: intent.putId,
            fileName: intent.name,
            contentLength: intent.slot.bytes,
            contentSha1: intent.slot.sha1,
            sha256: intent.slot.sha256,
            action: "upload",
            uploadTimestamp: Date.now(),
          };
        },
        async verifyExactReadback(object) {
          const path = cloud.get(object.fileId)!;
          equals((await Deno.stat(path)).size, object.contentLength);
          equals(await fileHash(path), object.sha256);
        },
        async versionsPage() {
          return { items: [], next: null };
        },
        async getExactToFile() {
          throw new Error("Fixture upload must not allocate readback payload");
        },
      };
      const attemptId = crypto.randomUUID(),
        captureStartedAtUtc = new Date().toISOString();
      const producer = await createBackupV2RoleProducer({
        settings: configured,
        stage,
        role: "efi",
        attemptId,
        native: {
          ...custody,
          spawn(command, args) {
            if (command === "unshare") {
              assert(args[3].includes("cd '/efi' || exit 71"));
              args = [...args];
              args[3] = args[3].replace(
                "cd '/efi' || exit 71",
                `cd ${shellQuote(fixture.source)} || exit 71`,
              );
            }
            return new Deno.Command(command, {
              args,
              clearEnv: true,
              env: {
                PATH: "/usr/bin:/bin",
                LC_ALL: "C",
                TZ: "UTC",
                TMPDIR: stage,
              },
              stdin: "piped",
              stdout: "piped",
              stderr: "piped",
            }).spawn();
          },
        },
      });
      try {
        const role = await uploadBackupV2RoleProducer({
          settings: configured,
          role: "efi",
          attemptId,
          captureStartedAtUtc,
          compatibilitySha256: "b".repeat(64),
          producer,
        }, {
          spool,
          journal,
          store,
          pace: async () => {},
          classifyFailure: () => ({
            retryable: false,
            mayHaveCommitted: false,
          }),
          sourceConfigSha256: backupV2SourceConfigSha256(configured),
        });
        assert(
          role.ciphertextBytes > 128 * 1024 * 1024 && role.chunks.length > 16 &&
            occupied === 0,
        );
        pointData.push({ role, cloud, stage, oracle: fixture.oracle });
        console.log(
          JSON.stringify({
            proof: "native producer upload",
            role: "efi",
            simulatedCloud: true,
            ciphertextBytes: role.ciphertextBytes,
            payloadSlotPeakBytes: peak,
            payloadEnvelopeBytes: 24 * 1024 * 1024,
          }),
        );
      } finally {
        journal.close();
      }
    }
    // Neither source generation is available to verifier, extractor or oracle.
    for (const fixture of input.fixtures) {
      await Deno.rename(fixture.source, `${fixture.source}.unavailable`);
    }
    for (const [index, point] of pointData.entries()) {
      const ciphertext = (mode?: "truncated" | "corrupt") => {
        async function* bytes() {
          for (const [part, chunk] of point.role.chunks.entries()) {
            const path = point.cloud.get(chunk.object.fileId)!;
            const file = await Deno.open(path);
            let position = 0;
            for await (const raw of file.readable) {
              position += raw.length;
              let data = raw;
              if (
                mode && part === point.role.chunks.length - 1 &&
                position === chunk.object.contentLength
              ) {
                data = raw.slice();
                if (mode === "truncated") {
                  data = data.subarray(0, data.length - 1);
                } else data[data.length - 1] ^= 1;
              }
              if (data.length) {
                yield data;
              }
            }
          }
        }
        const iterator = bytes();
        return new ReadableStream<Uint8Array>({
          async pull(c) {
            const next = await iterator.next();
            if (next.done) c.close();
            else c.enqueue(next.value);
          },
          async cancel() {
            await iterator.return();
          },
        });
      };
      const proof = await verifyBackupStreamArchive(point.role, {
        ciphertext: () => ciphertext(),
        decrypt,
        temporaryDirectory: point.stage,
      }, { samples: [] });
      equals(proof.proof.inventory, point.role.inventory);
      for (const mode of ["truncated", "corrupt"] as const) {
        await rejects(() =>
          decrypt(ciphertext(mode), {
            async write(bytes) {
              return bytes.length;
            },
          })
        );
      }
      const target = `${NATIVE_ROOT}/restored-${index}`;
      await Deno.mkdir(target, { mode: 0o700 });
      const zstd = new Deno.Command("zstd", {
        args: ["--decompress", "--stdout", "--memory=128MiB"],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const tar = new Deno.Command("tar", {
        args: [
          "--extract",
          "--file=-",
          "--directory",
          target,
          "--numeric-owner",
          "--same-owner",
          "--same-permissions",
          "--acls",
          "--xattrs",
          "--xattrs-include=*",
          "--sparse",
        ],
        stdin: "piped",
        stdout: "null",
        stderr: "piped",
      }).spawn();
      const writer = zstd.stdin.getWriter();
      const feed = (async () => {
        try {
          await decrypt(ciphertext(), {
            async write(bytes) {
              await writer.write(bytes);
              return bytes.length;
            },
          });
          await writer.close();
        } finally {
          writer.releaseLock();
        }
      })();
      const draining = async (stream: ReadableStream<Uint8Array>) => {
        let n = 0;
        for await (const bytes of stream) {
          n += bytes.length;
          assert(n <= 1024 * 1024);
        }
      };
      try {
        const [, , , , zs, ts] = await Promise.all([
          feed,
          pumpBackupV2Capture(zstd.stdout, tar.stdin),
          draining(zstd.stderr),
          draining(tar.stderr),
          zstd.status,
          tar.status,
        ]);
        assert(zs.success && ts.success);
        const checked = await new Deno.Command(input.oracleCommand[0], {
          args: [...input.oracleCommand.slice(1), point.oracle, target],
          stdout: "piped",
          stderr: "piped",
        }).output();
        assert(
          checked.success && checked.stdout.length <= 1024 * 1024 &&
            checked.stderr.length <= 1024 * 1024,
        );
        console.log(
          JSON.stringify({
            proof: "source-unavailable independent restore",
            fixture: index,
            simulatedCloud: true,
            completeGpg: true,
            tailMutationsRejected: 2,
            inventory: proof.proof.inventory,
          }),
        );
      } catch (error) {
        await custody.cancel();
        throw error;
      }
    }
  },
});
