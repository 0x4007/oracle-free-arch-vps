import assert, { deepEqual, rejects } from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  type BackupV2NativeRawChild,
  createBackupV2NativeProcessStarter,
} from "../scripts/backup-v2-native-process.ts";
import {
  backupV2NativeCustodyBytes,
  type BackupV2NativeCustodyRecord,
  parseBackupV2NativeCustody,
} from "../scripts/backup-v2-native-custody.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2Gate,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import {
  readBackupV2KernelText,
  realBackupV2KernelCommand,
} from "../scripts/backup-v2-kernel.ts";
import {
  backupV2NamespaceScript,
  pumpBackupV2Capture,
  trackBackupV2CaptureNamespace,
} from "../scripts/backup-v2-capture.ts";
import { shellQuote } from "../scripts/backup-guest.ts";

const encoder = new TextEncoder();
const id = "00000000-0000-4000-8000-000000000001";
const other = "00000000-0000-4000-8000-000000000002";
const request: BackupV2Request = {
  schemaVersion: 2,
  format: "backup-v2",
  profile: BACKUP_V2_PROFILE_ID,
  jobId: `job-${id}`,
  captureId: `generation-${id}`,
  periodKey: "2026-10-18",
  requestedAtUtc: "2026-10-18T10:00:00.000Z",
  sourceRevision: "a".repeat(40),
  sourceConfigSha256: "a".repeat(64),
  recipientSha256: "b".repeat(64),
  recipientFingerprint: "C".repeat(40),
};
const unitName = `arch-vps-b2-v2-worker-${id}-${other}.service`;
const gate = validateBackupV2Gate({
  schemaVersion: 2,
  format: "backup-v2",
  owner: GATE_OWNER,
  envelope: { request, requestSha256: backupV2RequestSha256(request) },
  gateId: other,
  sourceBootId: id,
  kind: "worker",
  unitName,
  custody: {
    unitName,
    invocationId: "1".repeat(32),
    mainPid: 101,
    mainStartTicks: "123",
    cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`,
  },
  state: "ACTIVE",
  remoteHost: GATE_REMOTE_HOST,
  sourceLockPath: GATE_SOURCE_LOCK_PATH,
  createdAtUtc: request.requestedAtUtc,
  updatedAtUtc: request.requestedAtUtc,
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function collect(stream: ReadableStream<Uint8Array>, maximum = 65536) {
  const parts: Uint8Array[] = [];
  let size = 0;
  for await (const part of stream) {
    size += part.length;
    assert(size <= maximum);
    parts.push(part);
  }
  const result = new Uint8Array(size);
  let at = 0;
  for (const part of parts) {
    result.set(part, at);
    at += part.length;
  }
  return result;
}
function fixture(options: {
  append?: (record: BackupV2NativeCustodyRecord) => Promise<void>;
  ack?: string;
} = {}) {
  const records: BackupV2NativeCustodyRecord[] = [], events: string[] = [];
  const terminal = deferred<Deno.CommandStatus>();
  let errors!: ReadableStreamDefaultController<Uint8Array>;
  let output!: ReadableStreamDefaultController<Uint8Array>;
  let ended = false, first = true, namespaceReads = 0;
  const finish = (code = 0) => {
    if (ended) return;
    ended = true;
    try {
      errors.close();
    } catch { /* already cancelled */ }
    try {
      output.close();
    } catch { /* already cancelled */ }
    terminal.resolve({ success: code === 0, code, signal: null });
  };
  const raw: BackupV2NativeRawChild = {
    pid: 102,
    stdin: new WritableStream({
      write(bytes) {
        if (first) {
          first = false;
          events.push("START");
          assert(records.some((record) => record.type === "CHILD"));
          deepEqual(bytes, encoder.encode("START\n"));
          for (
            const byte of encoder.encode(options.ack ?? "BACKUP_V2_START_ACK\n")
          ) {
            errors.enqueue(Uint8Array.of(byte));
          }
          errors.enqueue(Uint8Array.of(0, 255, 10));
        } else {
          events.push("PAYLOAD");
          output.enqueue(bytes.slice());
        }
      },
      close() {
        finish();
      },
    }),
    stdout: new ReadableStream({
      start(controller) {
        output = controller;
      },
    }),
    stderr: new ReadableStream({
      start(controller) {
        errors = controller;
      },
    }),
    status: terminal.promise,
    kill() {
      finish(143);
    },
  };
  const starter = createBackupV2NativeProcessStarter({
    gate,
    async append(record) {
      await options.append?.(record);
      records.push(record);
      events.push(record.type);
    },
    cancel() {
      events.push("CANCEL");
      finish(143);
      return Promise.resolve();
    },
    launch(command, childOptions) {
      events.push("SPAWN");
      assert(command === "/usr/bin/bash");
      assert(childOptions.clearEnv && !childOptions.env?.NOTIFY_SOCKET);
      return raw;
    },
    run(command, args) {
      let stdout = "";
      if (command === "/usr/bin/stat") {
        const pid = Number(/\/proc\/(\d+)\//.exec(args.at(-1)!)![1]);
        stdout = `4 ${
          pid === 1 ? 1 : pid === 101 ? 10 : ++namespaceReads === 1 ? 10 : 11
        }\n`;
      } else {
        const path = args.at(-1)!;
        if (path.endsWith("boot_id")) stdout = id + "\n";
        else if (path.endsWith("cgroup")) {
          stdout = `0::${gate.custody!.cgroup}\n`;
        } else {
          const pid = Number(/\/proc\/(\d+)\//.exec(path)![1]);
          stdout = `${pid} (fixture) S 101 ${Array(17).fill("0").join(" ")} ${
            pid === 101 ? 123 : 124
          }\n`;
        }
      }
      return Promise.resolve({ code: 0, stdout, stderr: "" });
    },
  });
  return { starter, records, events, raw, finish };
}

Deno.test("native starter fsyncs birth before START and preserves split ACK binary bytes and EOF", async () => {
  const birth = deferred<void>(), exit = deferred<void>();
  const f = fixture({
    append: (record) =>
      record.type === "CHILD"
        ? birth.promise
        : record.type === "EXIT"
        ? exit.promise
        : Promise.resolve(),
  });
  const pending = f.starter.spawn("gpg", "gpg", [], {
    env: { NOTIFY_SOCKET: "private" },
  });
  await Promise.resolve();
  await Promise.resolve();
  assert(!f.events.includes("START"));
  birth.resolve();
  const child = await pending;
  const binary = Uint8Array.of(83, 84, 65, 82, 84, 10, 0, 255, 13, 10);
  const output = collect(child.stdout), diagnostics = collect(child.stderr);
  const writer = child.stdin.getWriter();
  await writer.write(binary.slice(0, 3));
  await writer.write(binary.slice(3));
  await writer.close();
  writer.releaseLock();
  let resolved = false;
  child.status.then(() => {
    resolved = true;
  });
  await Promise.resolve();
  assert(!resolved);
  exit.resolve();
  assert((await child.status).success);
  deepEqual(await output, binary);
  deepEqual(await diagnostics, Uint8Array.of(0, 255, 10));
  const recorded = f.records.find((record) => record.type === "EXIT");
  assert(
    recorded?.type === "EXIT" && recorded.identity.pid === child.pid &&
      recorded.identity.startTicks === "124",
  );
});
Deno.test("native starter registration failure and cancellation never release START", async () => {
  const f = fixture({ append: () => Promise.reject(Error("fsync failed")) });
  await rejects(f.starter.spawn("tar", "tar", []), /fsync failed/);
  assert(!f.events.includes("START") && f.events.includes("CANCEL"));
  const aborted = fixture();
  await rejects(
    aborted.starter.spawn("tar", "tar", [], { signal: AbortSignal.abort() }),
  );
  assert(aborted.events.length === 0);
  aborted.finish();
  const cancel = new AbortController();
  const during = fixture({
    append: () => {
      cancel.abort();
      return Promise.resolve();
    },
  });
  await rejects(
    during.starter.spawn("tar", "tar", [], { signal: cancel.signal }),
  );
  assert(!during.events.includes("START"));
});
Deno.test("native starter rejects an early child or wrong ACK and retains exact exit", async () => {
  const wrong = fixture({ ack: "WRONG\n" });
  await rejects(wrong.starter.spawn("zstd", "zstd", []));
  assert(
    wrong.records.some((record) =>
      record.type === "EXIT" && record.code === 143
    ),
  );
  const early = fixture();
  early.finish(7);
  await rejects(early.starter.spawn("zstd", "zstd", []));
  assert(
    early.records.some((record) => record.type === "EXIT" && record.code === 7),
  );
});
Deno.test("native namespace waits for actual producer inode beyond the private unit namespace", async () => {
  const f = fixture();
  assert((await f.starter.registerUnitNamespace()).privateMount);
  await f.starter.registerChild(102, "unshare");
  await f.starter.registerNamespace({ pid: 102 });
  const mounts = f.records.filter((record) => record.type === "MOUNT");
  assert(
    mounts.length === 2 && mounts[1].type === "MOUNT" &&
      mounts[1].namespace.inode === "11",
  );
  await rejects(f.starter.recordNoPrivateMount());
  f.finish();
});

const native = Deno.args.includes("--native");
Deno.test({
  name:
    "native: m09 tracked namespace tar zstd pipeline preserves binary fidelity and complete custody",
  ignore: !native,
  async fn() {
    const cgroup = (await readBackupV2KernelText(`/proc/${Deno.pid}/cgroup`))
      .trim().slice(3);
    const name = cgroup.split("/").at(-1)!;
    assert(name === unitName && cgroup === gate.custody!.cgroup);
    const properties = await realBackupV2KernelCommand("/usr/bin/systemctl", [
      "show",
      name,
      "--property=MainPID,InvocationID",
      "--no-pager",
    ]);
    assert(properties.code === 0);
    const mainPid = Number(
      /^MainPID=([1-9][0-9]*)$/m.exec(properties.stdout)![1],
    );
    const invocationId =
      /^InvocationID=([a-f0-9]{32})$/m.exec(properties.stdout)![1];
    const stat = await readBackupV2KernelText(`/proc/${mainPid}/stat`);
    const actualGate = validateBackupV2Gate({
      ...gate,
      sourceBootId:
        (await readBackupV2KernelText("/proc/sys/kernel/random/boot_id"))
          .trim(),
      custody: {
        ...gate.custody,
        mainPid,
        mainStartTicks:
          stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/)[19],
        invocationId,
      },
    });
    const directory = await Deno.makeTempDir({
      dir: "/var/tmp",
      prefix: "backup-v2-native-",
    });
    await Deno.chmod(directory, 0o700);
    const source = directory + "/source", restored = directory + "/restored";
    await Deno.mkdir(source);
    await Deno.mkdir(restored);
    const payload = new Uint8Array(1024 * 1024);
    for (let i = 0; i < payload.length; i++) payload[i] = i % 256;
    payload.set(encoder.encode("START\n"));
    await Deno.writeFile(source + "/binary", payload, { mode: 0o640 });
    await Deno.link(source + "/binary", source + "/hard");
    await Deno.symlink("binary", source + "/sym");
    await Deno.utime(
      source + "/binary",
      new Date("2026-10-18T00:00:00Z"),
      new Date("2026-10-18T00:00:00Z"),
    );
    const journalPath = directory + "/native-custody.ndjson";
    using journal = await Deno.open(journalPath, {
      createNew: true,
      write: true,
      mode: 0o600,
    });
    const append = async (record: BackupV2NativeCustodyRecord) => {
      const bytes = backupV2NativeCustodyBytes(record);
      let at = 0;
      while (at < bytes.length) {
        const n = await journal.write(bytes.subarray(at));
        assert(n > 0);
        at += n;
      }
      await journal.sync();
    };
    await append({ type: "BOUND", schemaVersion: 1, gate: actualGate });
    const starter = createBackupV2NativeProcessStarter({
      gate: actualGate,
      append,
      async cancel() {
        await realBackupV2KernelCommand("/usr/bin/systemctl", [
          "--no-block",
          "stop",
          name,
        ]);
        throw Error("Task-owned native fixture cancellation requested");
      },
    });
    await starter.registerUnitNamespace();
    const script = backupV2NamespaceScript({
      source: {
        name: "efi",
        livePath: "/efi",
        filesystem: "vfat",
        uuid: id,
        size: 1024,
      },
      role: "efi",
      stage: directory,
      index: directory + "/index",
      status: directory + "/status",
      exclusions: [],
      tracked: true,
    }).replace("cd '/efi' || exit 71", `cd ${shellQuote(source)} || exit 71`);
    const leader = await starter.spawn("unshare", "/usr/bin/unshare", [
      "--mount",
      "/usr/bin/bash",
      "-c",
      script,
    ]);
    const control = trackBackupV2CaptureNamespace(leader, {
      assertManaged: () => Promise.resolve(),
      cancel: () => Promise.reject(Error("Fixture failed")),
      registerNamespace: starter.registerNamespace,
      registerChild: starter.registerChild,
    });
    const logs = [collect(control.stderr)];
    await control.ready;
    const zip = await starter.spawn("zstd", "/usr/bin/zstd", [
      "-3",
      "-T1",
      "--check",
      "-c",
    ]);
    const unzip = await starter.spawn("zstd", "/usr/bin/zstd", ["-d", "-c"]);
    const extract = await starter.spawn("tar", "/usr/bin/tar", [
      "--extract",
      "--file=-",
      "--same-owner",
      "--same-permissions",
      "--acls",
      "--xattrs",
      "--sparse",
      "--directory",
      restored,
    ]);
    logs.push(
      collect(zip.stderr),
      collect(unzip.stderr),
      collect(extract.stderr),
      collect(extract.stdout),
    );
    await Promise.all([
      pumpBackupV2Capture(leader.stdout, zip.stdin),
      pumpBackupV2Capture(zip.stdout, unzip.stdin),
      pumpBackupV2Capture(unzip.stdout, extract.stdin),
    ]);
    assert(
      (await zip.status).success && (await unzip.status).success &&
        (await extract.status).success,
    );
    const writer = leader.stdin.getWriter();
    await writer.write(encoder.encode("RELEASE\n"));
    await writer.close();
    writer.releaseLock();
    assert((await leader.status).success);
    await Promise.all(logs);
    deepEqual(await Deno.readFile(restored + "/binary"), payload);
    const original = await Deno.stat(source + "/binary"),
      result = await Deno.stat(restored + "/binary");
    assert(
      (result.mode! & 0o777) === 0o640 &&
        result.mtime?.getTime() === original.mtime?.getTime(),
    );
    assert(
      (await Deno.stat(restored + "/hard")).ino === result.ino &&
        result.nlink === 2,
    );
    assert(await Deno.readLink(restored + "/sym") === "binary");
    const bytes = await Deno.readFile(journalPath),
      custody = parseBackupV2NativeCustody(bytes, actualGate);
    assert(
      custody.children.length === 5 &&
        custody.children.every((child) => child.exit !== null),
    );
    assert(
      custody.unresolvedNamespaceLeaders.length === 0 &&
        custody.mounts.length === 2,
    );
    console.log(
      JSON.stringify({
        proof: "tracked native pipeline",
        journalPath,
        journalSha256: createHash("sha256").update(bytes).digest("hex"),
        children: custody.children.length,
        payloadBytes: payload.length,
        byteForByte: true,
        hardlink: true,
        symlink: true,
        modeAndMtime: true,
      }),
    );
  },
});
