import {
  backupV2DeletedHandleBytes,
  type BackupV2KernelCancellationStopProof,
  type BackupV2KernelCommand,
  type BackupV2KernelCommandResult,
  BackupV2KernelEvidenceError,
  type BackupV2KernelRetainedTerminalProof,
  observeBackupV2Kernel,
  readBackupV2KernelText,
} from "../scripts/backup-v2-kernel.ts";
import {
  BACKUP_V2_NATIVE_CUSTODY_FILE,
  type BackupV2NativeCustodyRecord,
  backupV2NativeMain,
} from "../scripts/backup-v2-native-custody.ts";
import {
  type BackupV2Gate,
  type BackupV2Request,
  backupV2RequestSha256,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function equal(a: unknown, b: unknown) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw Error(`Mismatch: ${JSON.stringify(a)} / ${JSON.stringify(b)}`);
  }
}
async function rejects(
  work: () => Promise<unknown>,
  kind?: BackupV2KernelEvidenceError["kind"],
) {
  try {
    await work();
  } catch (error) {
    assert(error instanceof BackupV2KernelEvidenceError);
    if (kind) equal(error.kind, kind);
    return;
  }
  throw Error("Expected unknown or blocked kernel evidence");
}
const ID = "11111111-1111-1111-1111-111111111111",
  GATE = "22222222-2222-2222-2222-222222222222";
const request: BackupV2Request = {
  schemaVersion: 2,
  format: "backup-v2",
  profile: BACKUP_V2_PROFILE_ID,
  jobId: `job-${ID}`,
  captureId: `generation-${ID}`,
  periodKey: "2026-10-18",
  requestedAtUtc: "2026-10-18T16:00:00.000Z",
  sourceRevision: "a".repeat(40),
  sourceConfigSha256: "b".repeat(64),
  recipientSha256: "c".repeat(64),
  recipientFingerprint: "D".repeat(40),
};
const unitName = `arch-vps-b2-v2-worker-${ID}-${GATE}.service`,
  cgroup = `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`;
const gate: BackupV2Gate = {
  schemaVersion: 2,
  format: "backup-v2",
  owner: GATE_OWNER,
  envelope: { request, requestSha256: backupV2RequestSha256(request) },
  gateId: GATE,
  sourceBootId: ID,
  kind: "worker",
  unitName,
  custody: {
    unitName,
    invocationId: "a".repeat(32),
    mainPid: 123,
    mainStartTicks: "456",
    cgroup,
  },
  state: "ACTIVE",
  remoteHost: GATE_REMOTE_HOST,
  sourceLockPath: GATE_SOURCE_LOCK_PATH,
  createdAtUtc: request.requestedAtUtc,
  updatedAtUtc: request.requestedAtUtc,
};
const directory =
  `/var/tmp/arch-vps-file-backup/${request.captureId}/v2-${GATE}/${
    gate.custody!.invocationId
  }`;
const ok = (
  stdout: string,
  observerPid?: number,
): BackupV2KernelCommandResult => ({
  code: 0,
  stdout,
  stderr: "",
  observerPid,
});
const missing = (): BackupV2KernelCommandResult => ({
  code: 1,
  stdout: "",
  stderr: "No such file or directory",
});
function stat(pid: number, start = "456") {
  const fields = Array(20).fill("0");
  fields[0] = "S";
  fields[1] = "1";
  fields[19] = start;
  return `${pid} (native metadata) ${fields.join(" ")}\n`;
}
function fixture() {
  const state = {
    boot: ID,
    main: 123,
    control: 0,
    invocation: gate.custody!.invocationId,
    start: "456",
    active: "active",
    sub: "running",
    result: "success",
    load: "loaded",
    absent: false,
    unreadable: false,
    events: "populated 1\nfrozen 0\n",
    statCount: 0,
  };
  const calls: [string, string[]][] = [];
  const run: BackupV2KernelCommand = (command, args) => {
    calls.push([command, args]);
    if (command === "/usr/bin/systemctl") {
      return Promise.resolve(
        ok(
          `LoadState=${state.load}\nActiveState=${state.active}\nSubState=${state.sub}\nResult=${state.result}\nMainPID=${state.main}\nControlPID=${state.control}\nInvocationID=${state.invocation}\nControlGroup=${cgroup}\n`,
        ),
      );
    }
    const path = args.at(-1)!;
    if (command === "/usr/bin/cat") {
      if (path === "/proc/sys/kernel/random/boot_id") {
        return Promise.resolve(ok(state.boot + "\n"));
      }
      if (path === "/proc/123/stat") {
        return Promise.resolve(ok(stat(123, state.start)));
      }
      if (path === "/proc/123/cgroup") {
        return Promise.resolve(ok(`0::${cgroup}\n`));
      }
      if (path.endsWith("/cgroup.procs")) {
        return Promise.resolve(
          state.unreadable
            ? { code: 1, stdout: "", stderr: "Permission denied" }
            : state.absent
            ? missing()
            : ok(state.main ? "123\n9000\n" : "", 9000),
        );
      }
      if (path.endsWith("/cgroup.events")) {
        return Promise.resolve(ok(state.events));
      }
    }
    if (command === "/usr/bin/find") {
      if (args[0].endsWith("/fd")) {
        return Promise.resolve(ok("3\0" + "4\0" + "5\0"));
      }
      return Promise.resolve(
        state.absent
          ? missing()
          : state.unreadable
          ? { code: 1, stdout: "", stderr: "Permission denied" }
          : ok("\0"),
      );
    }
    if (command === "/usr/bin/stat") {
      if (path === gate.sourceLockPath) {
        return Promise.resolve(ok("1:2:0:600:1:regular empty file"));
      }
      if (path.startsWith("/sys/")) {
        return Promise.resolve(state.absent ? missing() : ok("directory"));
      }
      state.statCount++;
      return Promise.resolve(
        ok(
          "1:5:2:0:regular file\0" + "1:5:2:0:regular file\0" +
            "1:6:8:0:regular file\0",
        ),
      );
    }
    if (command === "/usr/bin/readlink") {
      return Promise.resolve(
        ok(
          `${directory}/spool/new\nline (deleted)\0${directory}/spool/alias (deleted)\0/var/log/old (deleted)\0`,
        ),
      );
    }
    if (command === "/bin/sh") return Promise.resolve(ok(""));
    throw Error("Unexpected native boundary");
  };
  return { state, calls, run };
}

Deno.test("kernel reader uses only exact validated cat metadata paths and preserves sparse counters", async () => {
  const calls: unknown[] = [];
  const run: BackupV2KernelCommand = (command, args) => {
    calls.push([command, args]);
    return Promise.resolve(ok("nr_periods 1\n"));
  };
  equal(
    await readBackupV2KernelText(`/sys/fs/cgroup${cgroup}/cpu.stat`, run),
    "nr_periods 1\n",
  );
  equal(calls[0], ["/usr/bin/cat", ["--", `/sys/fs/cgroup${cgroup}/cpu.stat`]]);
  for (
    const path of [
      "/proc/self/stat",
      "/proc/123/environ",
      "/proc/123/fd/3",
      "/etc/passwd",
      `/sys/fs/cgroup${cgroup}/../cpu.stat`,
      "/sys/fs/cgroup/unrelated.service/memory.current",
    ]
  ) await rejects(() => readBackupV2KernelText(path, run), "CUSTODY");
  equal(calls.length, 1);
});

Deno.test("kernel unknown and over-bound native replies never become zero", async () => {
  await rejects(
    () =>
      readBackupV2KernelText(
        "/proc/123/stat",
        () => Promise.resolve(missing()),
      ),
    "ABSENT",
  );
  await rejects(
    () =>
      readBackupV2KernelText(
        "/proc/123/stat",
        () =>
          Promise.resolve({ code: 1, stdout: "", stderr: "Permission denied" }),
      ),
    "UNREADABLE",
  );
  await rejects(
    () =>
      readBackupV2KernelText(
        "/proc/123/stat",
        () => Promise.resolve(ok("x".repeat(2 * 1024 * 1024 + 1))),
      ),
    "BOUNDED",
  );
});

Deno.test("kernel live observation binds actual boot, MainPID, start and original cgroup", async () => {
  const f = fixture(), observed = await observeBackupV2Kernel(gate, f.run);
  equal(observed.identity, gate.custody);
  equal(observed.tree?.descendants, 1);
  equal(observed.tree?.cgroupPopulated, true);
  equal(observed.tree?.sourceLockFree, true);
  equal(observed.tree?.escapedProcesses, null);
  equal(observed.tree?.namespaceReferences, null);
  equal(observed.tree?.openPipelineHandles, null);
  equal(observed.tree?.pendingOperations, null);
  assert(
    !f.calls.some(([, args]) =>
      args.some((arg) => arg.includes("cmdline") || arg.includes("environ"))
    ),
  );
});

Deno.test("kernel PID reuse is observed as actual changed identity and reboot rejects old custody", async () => {
  const reused = fixture();
  reused.state.start = "999";
  equal(
    (await observeBackupV2Kernel(gate, reused.run)).identity?.mainStartTicks,
    "999",
  );
  const reboot = fixture();
  reboot.state.boot = GATE;
  const observed = await observeBackupV2Kernel(gate, reboot.run);
  equal(observed.sourceBootId, GATE);
  equal(observed.identity, null);
  equal(observed.tree, null);
});

Deno.test("kernel absent unit alone has no identity or empty-tree proof", async () => {
  const f = fixture();
  f.state.load = "not-found";
  f.state.main = 0;
  f.state.invocation = "";
  const observed = await observeBackupV2Kernel(gate, f.run);
  equal(observed.unit, "ABSENT");
  equal(observed.identity, null);
  equal(observed.tree, null);
  assert(!f.calls.some(([command]) => command === "/usr/bin/find"));
});

Deno.test("kernel absent original cgroup proves empty only with exact retained successful exit", async () => {
  const f = fixture();
  f.state.main = 0;
  f.state.sub = "exited";
  f.state.absent = true;
  const observed = await observeBackupV2Kernel(gate, f.run);
  equal(observed.identity, gate.custody);
  equal(observed.tree?.descendants, 0);
  equal(observed.tree?.cgroupPopulated, false);
  equal(observed.tree?.namespaceReferences, null);
  f.state.result = "timeout";
  equal((await observeBackupV2Kernel(gate, f.run)).tree?.descendants, null);
});

Deno.test("kernel unreadable cgroup and sparse populated counter retain unknown facts", async () => {
  const f = fixture();
  f.state.unreadable = true;
  const unreadable = await observeBackupV2Kernel(gate, f.run);
  equal(unreadable.tree?.descendants, null);
  equal(unreadable.tree?.cgroupPopulated, null);
  f.state.unreadable = false;
  f.state.events = "frozen 0\n";
  const sparse = await observeBackupV2Kernel(gate, f.run);
  equal(sparse.tree?.descendants, 1);
  equal(sparse.tree?.cgroupPopulated, null);
});

Deno.test("kernel deleted handles count physical blocks once and preserve newline targets", async () => {
  const f = fixture();
  equal(await backupV2DeletedHandleBytes(directory, cgroup, f.run), {
    workspaceHeldDeletedBytes: 1024,
    sourceHeldDeletedBytes: 4096,
  });
  assert(
    f.calls.some(([command, args]) =>
      command === "/usr/bin/readlink" &&
      JSON.stringify(args.slice(0, 3)) === JSON.stringify(["-z", "-v", "--"])
    ),
  );
  assert(
    f.calls.some(([command, args]) =>
      command === "/usr/bin/stat" && args.includes("-L")
    ),
  );
});

Deno.test("kernel deleted accounting restarts the complete census after a disappearing child", async () => {
  const f = fixture();
  let samples = 0, metadata = 0;
  const churn: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/cat" && args.at(-1)!.endsWith("/cgroup.procs")) {
      return Promise.resolve(ok(++samples === 1 ? "123\n124\n" : "123\n"));
    }
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/124/stat") {
      return Promise.resolve(missing());
    }
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat") {
      metadata++;
    }
    return f.run(command, args);
  };
  equal(await backupV2DeletedHandleBytes(directory, cgroup, churn), {
    workspaceHeldDeletedBytes: 1024,
    sourceHeldDeletedBytes: 4096,
  });
  equal(samples, 3);
  equal(metadata, 4); // Earlier successful rows are sampled again, never reused.
});

Deno.test("kernel deleted accounting excludes only the exact reader PID even when it changes each sample", async () => {
  const f = fixture();
  let samples = 0;
  const readers: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/cat" && args.at(-1)!.endsWith("/cgroup.procs")) {
      const reader = 9000 + ++samples;
      return Promise.resolve(ok(`123\n${reader}\n`, reader));
    }
    return f.run(command, args);
  };
  equal(await backupV2DeletedHandleBytes(directory, cgroup, readers), {
    workspaceHeldDeletedBytes: 1024,
    sourceHeldDeletedBytes: 4096,
  });
  equal(samples, 2);
  assert(!f.calls.some(([, args]) => /^\/proc\/900[12]\//.test(args.at(-1)!)));
});

Deno.test("kernel deleted accounting retries a silent readlink failure only after proving its child exited", async () => {
  const f = fixture();
  let exited = false, samples = 0;
  const churn: BackupV2KernelCommand = (command, args) => {
    const path = args.at(-1)!;
    if (command === "/usr/bin/cat" && path.endsWith("/cgroup.procs")) {
      samples++;
      return Promise.resolve(ok(exited ? "123\n" : "123\n124\n"));
    }
    if (command === "/usr/bin/cat" && path === "/proc/124/stat") {
      return Promise.resolve(ok(stat(124)));
    }
    if (command === "/usr/bin/cat" && path === "/proc/124/cgroup") {
      return Promise.resolve(ok(`0::${cgroup}\n`));
    }
    if (command === "/usr/bin/readlink" && path.startsWith("/proc/124/fd/")) {
      exited = true;
      return Promise.resolve({ code: 1, stdout: "", stderr: "" });
    }
    return f.run(command, args);
  };
  equal(await backupV2DeletedHandleBytes(directory, cgroup, churn), {
    workspaceHeldDeletedBytes: 1024,
    sourceHeldDeletedBytes: 4096,
  });
  equal(samples, 4);
});

Deno.test("kernel deleted accounting retries a changed final PID list but bounds persistent churn", async () => {
  for (const persistent of [false, true]) {
    const f = fixture();
    let samples = 0, completed = 0;
    const churn: BackupV2KernelCommand = (command, args) => {
      if (
        command === "/usr/bin/cat" && args.at(-1)!.endsWith("/cgroup.procs")
      ) {
        samples++;
        const changed = samples % 2 === 0 && (persistent || samples === 2);
        return Promise.resolve(ok(changed ? "123\n124\n" : "123\n"));
      }
      if (command === "/usr/bin/readlink") completed++;
      return f.run(command, args);
    };
    if (persistent) {
      await rejects(
        () => backupV2DeletedHandleBytes(directory, cgroup, churn),
        "CUSTODY",
      );
      equal(samples, 16);
      equal(completed, 8);
    } else {
      equal(await backupV2DeletedHandleBytes(directory, cgroup, churn), {
        workspaceHeldDeletedBytes: 1024,
        sourceHeldDeletedBytes: 4096,
      });
      equal(samples, 4);
      equal(completed, 2);
    }
  }
});

Deno.test("kernel deleted accounting retries a closed descriptor within the same live PID using fresh complete facts", async () => {
  const f = fixture();
  let readlinks = 0, samples = 0, metadata = 0;
  const closing: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/cat" && args.at(-1)!.endsWith("/cgroup.procs")) {
      samples++;
    }
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat") {
      metadata++;
    }
    if (command === "/usr/bin/readlink" && ++readlinks === 1) {
      return Promise.resolve({
        code: 1,
        stdout: `${directory}/spool/partial (deleted)\0`,
        stderr: args.includes("-v")
          ? "readlink: /proc/123/fd/5: No such file or directory\n"
          : "",
      });
    }
    return f.run(command, args);
  };
  equal(await backupV2DeletedHandleBytes(directory, cgroup, closing), {
    workspaceHeldDeletedBytes: 1024,
    sourceHeldDeletedBytes: 4096,
  });
  equal(readlinks, 2);
  equal(samples, 3);
  equal(metadata, 3);
});

Deno.test("kernel deleted accounting exhausts eight whole censuses for persistent same-PID descriptor closure", async () => {
  const f = fixture();
  let readlinks = 0, samples = 0;
  const closing: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/cat" && args.at(-1)!.endsWith("/cgroup.procs")) {
      samples++;
    }
    if (command === "/usr/bin/readlink") {
      readlinks++;
      return Promise.resolve({
        code: 1,
        stdout: "",
        stderr: args.includes("-v")
          ? "readlink: /proc/123/fd/5: No such file or directory\n"
          : "",
      });
    }
    return f.run(command, args);
  };
  await rejects(
    () => backupV2DeletedHandleBytes(directory, cgroup, closing),
    "ABSENT",
  );
  equal(readlinks, 8);
  equal(samples, 8);
});

Deno.test("kernel census backoff survives three initial transient absences without resetting its original budget", async () => {
  const f = fixture(), delays: number[] = [];
  let now = 0, failed = 0;
  const transient: BackupV2KernelCommand = (command, args) => {
    if (
      command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat" &&
      failed++ < 3
    ) {
      return Promise.resolve(missing());
    }
    return f.run(command, args);
  };
  equal(
    await backupV2DeletedHandleBytes(directory, cgroup, transient, {
      now: () => now,
      sleep: (ms) => {
        delays.push(ms);
        now += ms;
        return Promise.resolve();
      },
    }),
    { workspaceHeldDeletedBytes: 1024, sourceHeldDeletedBytes: 4096 },
  );
  equal(delays, [25, 50, 100]);
  equal(now, 175);
});

Deno.test("kernel census persistent absence is bounded by both eight attempts and the original four-second clock", async () => {
  for (const overrun of [false, true]) {
    const f = fixture(), delays: number[] = [];
    let now = 0, attempts = 0;
    const missingPid: BackupV2KernelCommand = (command, args) => {
      if (command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat") {
        attempts++;
        return Promise.resolve(missing());
      }
      return f.run(command, args);
    };
    await rejects(
      () =>
        backupV2DeletedHandleBytes(directory, cgroup, missingPid, {
          now: () => now,
          sleep: (ms) => {
            delays.push(ms);
            now += overrun ? 4001 : ms;
            return Promise.resolve();
          },
        }),
      overrun ? "BOUNDED" : "ABSENT",
    );
    equal(attempts, overrun ? 1 : 8);
    equal(delays, overrun ? [25] : [25, 50, 100, 200, 400, 500, 500]);
  }
});

Deno.test("kernel verbose readlink permission failure in a stable live PID remains unreadable", async () => {
  const f = fixture();
  let readlinks = 0;
  const denied: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/readlink") {
      readlinks++;
      assert(args.includes("-v"));
      return Promise.resolve({
        code: 1,
        stdout: "",
        stderr: "readlink: /proc/123/fd/5: Permission denied\n",
      });
    }
    return f.run(command, args);
  };
  await rejects(
    () => backupV2DeletedHandleBytes(directory, cgroup, denied),
    "UNREADABLE",
  );
  equal(readlinks, 1);
});

Deno.test("kernel permission failure never enters backoff even when another PID changed", async () => {
  const f = fixture();
  let samples = 0, sleeps = 0;
  const denied: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/cat" && args.at(-1)!.endsWith("/cgroup.procs")) {
      return Promise.resolve(ok(++samples === 1 ? "123\n" : "123\n124\n"));
    }
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat") {
      return Promise.resolve({
        code: 1,
        stdout: "",
        stderr: "Permission denied",
      });
    }
    return f.run(command, args);
  };
  await rejects(() =>
    backupV2DeletedHandleBytes(directory, cgroup, denied, {
      now: () => 0,
      sleep: () => {
        sleeps++;
        return Promise.resolve();
      },
    }), "UNREADABLE");
  equal(samples, 1);
  equal(sleeps, 0);
});

Deno.test("kernel deleted accounting never retries permission failure as a topology race", async () => {
  const f = fixture();
  let denied = 0;
  const unreadable: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat") {
      denied++;
      return Promise.resolve({
        code: 1,
        stdout: "",
        stderr: "Permission denied",
      });
    }
    return f.run(command, args);
  };
  await rejects(
    () => backupV2DeletedHandleBytes(directory, cgroup, unreadable),
    "UNREADABLE",
  );
  equal(denied, 1);
});

Deno.test("kernel deleted accounting rejects another generation or gate before scanning", async () => {
  const f = fixture();
  await rejects(
    () =>
      backupV2DeletedHandleBytes(
        directory.replace(`generation-${ID}`, `generation-${GATE}`),
        cgroup,
        f.run,
      ),
    "CUSTODY",
  );
  await rejects(
    () =>
      backupV2DeletedHandleBytes(
        directory.replace(`v2-${GATE}`, `v2-${ID}`),
        cgroup,
        f.run,
      ),
    "CUSTODY",
  );
  equal(f.calls.length, 0);
});

Deno.test("kernel FD replacement, excessive enumeration and unavailable group block accounting", async () => {
  const f = fixture();
  let stats = 0;
  const race: BackupV2KernelCommand = (command, args) =>
    command === "/usr/bin/stat" && args.includes("-L")
      ? Promise.resolve(
        ok(
          ++stats === 1
            ? "1:5:2:0:regular file\0".repeat(3)
            : "1:9:2:0:regular file\0".repeat(3),
        ),
      )
      : f.run(command, args);
  await rejects(
    () => backupV2DeletedHandleBytes(directory, cgroup, race),
    "CUSTODY",
  );
  const many: BackupV2KernelCommand = (command, args) =>
    command === "/usr/bin/find" && args[0].endsWith("/fd")
      ? Promise.resolve(
        ok(Array.from({ length: 4097 }, (_, n) => `${n}\0`).join("")),
      )
      : f.run(command, args);
  await rejects(
    () => backupV2DeletedHandleBytes(directory, cgroup, many),
    "BOUNDED",
  );
  f.state.absent = true;
  await rejects(
    () => backupV2DeletedHandleBytes(directory, cgroup, f.run),
    "ABSENT",
  );
});

Deno.test("kernel deleted accounting accepts growing unlinked blocks without inventing a stable zero", async () => {
  const f = fixture();
  let calls = 0;
  const grow: BackupV2KernelCommand = (command, args) =>
    command === "/usr/bin/stat" && args.includes("-L")
      ? Promise.resolve(
        ok(
          ++calls === 1
            ? "1:5:2:0:regular file\0".repeat(3)
            : "1:5:4:0:regular file\0".repeat(3),
        ),
      )
      : f.run(command, args);
  equal(await backupV2DeletedHandleBytes(directory, cgroup, grow), {
    workspaceHeldDeletedBytes: 2048,
    sourceHeldDeletedBytes: 0,
  });
});

async function nativeFixture(
  options: {
    privateMount?: boolean;
    liveChild?: boolean;
    escaped?: boolean;
    missingExit?: boolean;
    unresolved?: boolean;
    reused?: boolean;
    noChildren?: boolean;
    omitNoPrivateMount?: boolean;
  } = {},
) {
  const base = fixture();
  base.state.main = options.liveChild ? 123 : 0;
  base.state.sub = options.liveChild ? "running" : "exited";
  base.state.absent = !options.liveChild;
  const state = {
    managerPin: options.privateMount === true,
    wrongOwner: false,
    changedHash: false,
  };
  const child = {
    pid: 124,
    startTicks: "789",
    bootId: ID,
    cgroup,
    kind: options.unresolved ? "unshare" as const : "gpg" as const,
  };
  const records: BackupV2NativeCustodyRecord[] = [
    { type: "BOUND", schemaVersion: 1, gate },
    {
      type: "MOUNT",
      namespace: {
        scope: "UNIT",
        leader: backupV2NativeMain(gate),
        device: "4",
        inode: options.privateMount ? "5000" : "1000",
        hostDevice: "4",
        hostInode: "1000",
      },
    },
  ];
  if (!options.noChildren) records.push({ type: "CHILD", identity: child });
  if (!options.noChildren && !options.liveChild && !options.missingExit) {
    records.push({ type: "EXIT", identity: child, code: 0, signal: null });
  }
  if (
    !options.privateMount && !options.unresolved && !options.omitNoPrivateMount
  ) {
    records.push({ type: "NO_PRIVATE_MOUNT" });
  }
  const body = records.map((record) => JSON.stringify(record)).join("\n") +
      "\n",
    journal = `${directory}/${BACKUP_V2_NATIVE_CUSTODY_FILE}`;
  const sha = async (text: string) =>
    Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
      ),
      (b) => b.toString(16).padStart(2, "0"),
    ).join("");
  const digest = await sha(body), resultDigest = await sha("{}\n");
  const calls: [string, string[]][] = [];
  const run: BackupV2KernelCommand = (command, args) => {
    calls.push([command, args]);
    const path = args.at(-1)!;
    if (command === "/usr/bin/readlink" && args[0] === "-e") {
      return Promise.resolve(ok(directory + "\n"));
    }
    if (command === "/usr/bin/stat" && args[0] === "--printf=%u:%a:%F") {
      return Promise.resolve(ok("0:700:directory"));
    }
    if (
      command === "/usr/bin/stat" && args[0] === "--printf=%d:%i:%u:%a:%h:%s:%F"
    ) {
      return Promise.resolve(
        ok(
          `1:99:${state.wrongOwner ? 1 : 0}:600:1:${
            path === journal ? new TextEncoder().encode(body).length : 3
          }:regular file`,
        ),
      );
    }
    if (command === "/usr/bin/sha256sum") {
      return Promise.resolve(
        ok(
          `${
            path === journal
              ? (state.changedHash ? "f".repeat(64) : digest)
              : resultDigest
          }  ${path}\n`,
        ),
      );
    }
    if (command === "/usr/bin/cat" && path === journal) {
      return Promise.resolve(ok(body));
    }
    if (command === "/usr/bin/find" && args[0] === "/proc") {
      return Promise.resolve(
        ok(
          "1\0" + (base.state.main ? "123\0" : "") +
            (!options.noChildren && (options.liveChild || options.reused)
              ? "124\0"
              : ""),
        ),
      );
    }
    if (command === "/usr/bin/cat" && path === "/proc/124/stat") {
      return Promise.resolve(ok(stat(124, options.reused ? "999" : "789")));
    }
    if (command === "/usr/bin/cat" && path === "/proc/124/cgroup") {
      return Promise.resolve(
        ok(`0::${options.escaped ? "/user.slice/session-99.scope" : cgroup}\n`),
      );
    }
    if (command === "/usr/bin/find" && /^\/proc\/[0-9]+\/fd$/.test(args[0])) {
      if (args.includes("mnt:[[]*[]]")) {
        return Promise.resolve(
          ok(args[0] === "/proc/1/fd" && state.managerPin ? "7\0" : ""),
        );
      }
      return Promise.resolve(ok("0\0" + "1\0"));
    }
    if (
      command === "/usr/bin/stat" && args[0] === "-L" &&
      args[1] === "--printf=%d:%i"
    ) {
      return Promise.resolve(
        ok(
          path === "/proc/1/fd/7" ||
            options.privateMount && path !== "/proc/1/ns/mnt" && !options.reused
            ? "4:5000"
            : "4:1000",
        ),
      );
    }
    if (
      command === "/usr/bin/cat" && path.endsWith("/cgroup.procs") &&
      !base.state.absent
    ) {
      return Promise.resolve(
        ok(
          "123\n" +
            (!options.noChildren && options.liveChild && !options.escaped
              ? "124\n"
              : ""),
        ),
      );
    }
    return base.run(command, args);
  };
  return { base, state, run, calls, digest, resultDigest, journal };
}

Deno.test("kernel verified complete journal turns absent physical actors and explicit shared namespace into zeros", async () => {
  const f = await nativeFixture();
  const observed = await observeBackupV2Kernel(gate, f.run, {
    expectedCustodySha256: f.digest,
  });
  equal(observed.nativeCustodySha256, f.digest);
  equal([
    observed.tree?.escapedProcesses,
    observed.tree?.namespaceReferences,
    observed.tree?.openPipelineHandles,
    observed.tree?.pendingOperations,
  ], [0, 0, 0, 0]);
  equal(observed.managerNamespaceReferences, 0);
});

Deno.test("kernel journal owner, content hash and unresolved exit/namespace evidence fail closed", async () => {
  const owner = await nativeFixture();
  owner.state.wrongOwner = true;
  equal(
    (await observeBackupV2Kernel(gate, owner.run)).tree?.escapedProcesses,
    null,
  );
  const changed = await nativeFixture();
  changed.state.changedHash = true;
  equal(
    (await observeBackupV2Kernel(gate, changed.run)).nativeCustodySha256,
    null,
  );
  const incomplete = await nativeFixture({ missingExit: true });
  equal(
    (await observeBackupV2Kernel(gate, incomplete.run)).tree?.pendingOperations,
    null,
  );
  const namespace = await nativeFixture({ unresolved: true });
  equal(
    (await observeBackupV2Kernel(gate, namespace.run)).tree
      ?.namespaceReferences,
    null,
  );
  const mismatch = await nativeFixture();
  equal(
    (await observeBackupV2Kernel(gate, mismatch.run, {
      expectedCustodySha256: "e".repeat(64),
    })).tree?.escapedProcesses,
    null,
  );
});

Deno.test("kernel current child placement and actual pipe/socket FD metadata report an escape", async () => {
  const f = await nativeFixture({ liveChild: true, escaped: true });
  const observed = await observeBackupV2Kernel(gate, f.run);
  equal(observed.tree?.escapedProcesses, 1);
  equal(observed.tree?.openPipelineHandles, 4);
  equal(observed.tree?.pendingOperations, null);
  assert(
    !f.calls.some(([, args]) =>
      args.some((arg) => arg.includes("cmdline") || arg.includes("environ"))
    ),
  );
});

Deno.test("kernel PID reuse never reads foreign payload FD targets or retains old liveness", async () => {
  const f = await nativeFixture({ reused: true });
  const observed = await observeBackupV2Kernel(gate, f.run);
  equal(observed.tree?.escapedProcesses, 0);
  assert(
    !f.calls.some(([command, args]) =>
      command === "/usr/bin/cat" && args.at(-1) === "/proc/124/cgroup"
    ),
  );
  assert(
    !f.calls.some(([command, args]) =>
      command === "/usr/bin/find" && args[0] === "/proc/124/fd" &&
      !args.includes("mnt:[[]*[]]")
    ),
  );
});

Deno.test("kernel exact manager namespace FD is counted then fresh post-stop proof establishes zero", async () => {
  const f = await nativeFixture({ privateMount: true });
  const before = await observeBackupV2Kernel(gate, f.run, {
    expectedCustodySha256: f.digest,
  });
  equal(before.tree?.namespaceReferences, 1);
  equal(before.managerNamespaceReferences, 1);
  equal(before.tree?.pendingOperations, 0);
  const proof: BackupV2KernelRetainedTerminalProof = {
    gate,
    observation: before,
    resultSha256: f.resultDigest,
    exactStop: {
      unitName: gate.unitName,
      invocationId: gate.custody!.invocationId,
      sourceBootId: gate.sourceBootId,
      completed: true,
    },
  };
  f.base.state.load = "not-found";
  f.base.state.invocation = "";
  f.state.managerPin = false;
  equal((await observeBackupV2Kernel(gate, f.run)).identity, null);
  const after = await observeBackupV2Kernel(gate, f.run, {
    expectedCustodySha256: f.digest,
    retainedTerminalProof: proof,
  });
  equal(after.unit, "ABSENT");
  equal(after.identity, gate.custody);
  equal([
    after.tree?.cgroupPopulated,
    after.tree?.descendants,
    after.tree?.escapedProcesses,
    after.tree?.namespaceReferences,
    after.tree?.openPipelineHandles,
    after.tree?.pendingOperations,
    after.tree?.sourceLockFree,
  ], [false, 0, 0, 0, 0, 0, true]);
});

Deno.test("kernel malformed exact-stop proof and another invocation cannot authorize absent-unit reconciliation", async () => {
  const f = await nativeFixture();
  const before = await observeBackupV2Kernel(gate, f.run);
  const proof: BackupV2KernelRetainedTerminalProof = {
    gate,
    observation: before,
    resultSha256: f.resultDigest,
    exactStop: {
      unitName: gate.unitName,
      invocationId: "f".repeat(32),
      sourceBootId: gate.sourceBootId,
      completed: true,
    },
  };
  f.base.state.load = "not-found";
  f.base.state.invocation = "";
  await rejects(
    () => observeBackupV2Kernel(gate, f.run, { retainedTerminalProof: proof }),
    "CUSTODY",
  );
});

async function cancelledFixture(
  options: Parameters<typeof nativeFixture>[0] = { liveChild: true },
) {
  const f = await nativeFixture(options),
    before = await observeBackupV2Kernel(gate, f.run);
  const proof: BackupV2KernelCancellationStopProof = {
    gate,
    observation: before,
    exactStop: {
      unitName: gate.unitName,
      invocationId: gate.custody!.invocationId,
      sourceBootId: gate.sourceBootId,
      completed: true,
      code: 0,
    },
  };
  f.base.state.main = 0;
  f.base.state.load = "not-found";
  f.base.state.invocation = "";
  f.base.state.absent = true;
  const run: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/find" && args[0] === "/proc") {
      return Promise.resolve(ok("1\0"));
    }
    if (
      command === "/usr/bin/cat" &&
      ["/proc/123/stat", "/proc/124/stat"].includes(args.at(-1)!)
    ) return Promise.resolve(missing());
    return f.run(command, args);
  };
  return { ...f, proof, after: run, before };
}

Deno.test("kernel cancellation proves fresh physical settlement after RUNNING stop without EXIT frames", async () => {
  const f = await cancelledFixture();
  equal(f.before.unit, "RUNNING");
  equal(f.before.tree?.mainPid, 123);
  equal((await observeBackupV2Kernel(gate, f.after)).tree, null);
  const after = await observeBackupV2Kernel(gate, f.after, {
    cancellationStopProof: f.proof,
  });
  equal([after.unit, after.identity, after.nativeCustodySha256], [
    "ABSENT",
    gate.custody,
    f.digest,
  ]);
  equal([
    after.tree?.mainPid,
    after.tree?.controlPid,
    after.tree?.descendants,
    after.tree?.escapedProcesses,
    after.tree?.namespaceReferences,
    after.tree?.openPipelineHandles,
    after.tree?.pendingOperations,
    after.tree?.sourceLockFree,
  ], [0, 0, 0, 0, 0, 0, 0, true]);
  // The same valid partial journal remains incomplete for ordinary success.
  f.base.state.load = "loaded";
  f.base.state.sub = "exited";
  f.base.state.invocation = gate.custody!.invocationId;
  equal(
    (await observeBackupV2Kernel(gate, f.after)).tree?.pendingOperations,
    null,
  );
  f.base.state.active = "inactive";
  f.base.state.sub = "dead";
  equal(
    (await observeBackupV2Kernel(gate, f.after, {
      cancellationStopProof: f.proof,
    })).tree?.pendingOperations,
    0,
  );
});

Deno.test("kernel cancellation settles a zero-child preflight without fabricating a mount record", async () => {
  const f = await cancelledFixture({
    liveChild: true,
    noChildren: true,
    omitNoPrivateMount: true,
  });
  const after = await observeBackupV2Kernel(gate, f.after, {
    cancellationStopProof: f.proof,
  });
  equal(after.unit, "ABSENT");
  equal(after.nativeCustodySha256, f.digest);
  equal([
    after.tree?.descendants,
    after.tree?.namespaceReferences,
    after.managerNamespaceReferences,
    after.tree?.pendingOperations,
  ], [0, 0, 0, 0]);
  f.base.state.load = "loaded";
  f.base.state.sub = "exited";
  f.base.state.invocation = gate.custody!.invocationId;
  equal(
    (await observeBackupV2Kernel(gate, f.after)).tree?.namespaceReferences,
    null,
  );
});

Deno.test("kernel exact cancellation settles a retained failed unit only after physical exit", async () => {
  const f = await cancelledFixture({
    liveChild: true,
    noChildren: true,
    omitNoPrivateMount: true,
  });
  f.base.state.load = "loaded";
  f.base.state.active = "failed";
  f.base.state.sub = "failed";
  f.base.state.result = "exit-code";
  f.base.state.invocation = gate.custody!.invocationId;
  const unproved = await observeBackupV2Kernel(gate, f.after);
  equal(unproved.unit, "FAILED");
  equal(unproved.tree?.descendants, null);
  equal(unproved.tree?.namespaceReferences, null);
  const after = await observeBackupV2Kernel(gate, f.after, {
    cancellationStopProof: f.proof,
  });
  equal(after.unit, "ABSENT");
  equal([
    after.tree?.mainPid,
    after.tree?.controlPid,
    after.tree?.cgroupPopulated,
    after.tree?.descendants,
    after.tree?.namespaceReferences,
    after.managerNamespaceReferences,
  ], [0, 0, false, 0, 0, 0]);
  f.base.state.invocation = "f".repeat(32);
  equal(
    (await observeBackupV2Kernel(gate, f.after, {
      cancellationStopProof: f.proof,
    })).identity,
    null,
  );
});

Deno.test("kernel zero-child cancellation exception rejects child history, live main and journal changes", async () => {
  const child = await cancelledFixture({
    liveChild: true,
    omitNoPrivateMount: true,
  });
  equal(
    (await observeBackupV2Kernel(gate, child.after, {
      cancellationStopProof: child.proof,
    })).tree?.namespaceReferences,
    null,
  );
  const f = await cancelledFixture({
    liveChild: true,
    noChildren: true,
    omitNoPrivateMount: true,
  });
  const live: BackupV2KernelCommand = (command, args) =>
    command === "/usr/bin/cat" && args.at(-1) === "/proc/123/stat"
      ? Promise.resolve(ok(stat(123)))
      : f.after(command, args);
  equal(
    (await observeBackupV2Kernel(gate, live, {
      cancellationStopProof: f.proof,
    })).tree,
    null,
  );
  let hashes = 0;
  const changed: BackupV2KernelCommand = (command, args) =>
    command === "/usr/bin/sha256sum" && args.at(-1) === f.journal &&
      ++hashes === 2
      ? Promise.resolve(ok(`${"f".repeat(64)}  ${f.journal}\n`))
      : f.after(command, args);
  equal(
    (await observeBackupV2Kernel(gate, changed, {
      cancellationStopProof: f.proof,
    })).tree?.namespaceReferences,
    null,
  );
});

Deno.test("kernel cancellation rejects mismatched stop/boot and never hides a live escaped actor", async () => {
  const f = await cancelledFixture();
  const bad = structuredClone(f.proof);
  bad.exactStop.invocationId = "f".repeat(32);
  await rejects(
    () => observeBackupV2Kernel(gate, f.after, { cancellationStopProof: bad }),
    "CUSTODY",
  );
  const boot = structuredClone(f.proof);
  boot.exactStop.sourceBootId = GATE;
  await rejects(
    () => observeBackupV2Kernel(gate, f.after, { cancellationStopProof: boot }),
    "CUSTODY",
  );
  const escaped: BackupV2KernelCommand = (command, args) => {
    if (command === "/usr/bin/find" && args[0] === "/proc") {
      return Promise.resolve(ok("1\0" + "124\0"));
    }
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/124/stat") {
      return Promise.resolve(ok(stat(124, "789")));
    }
    if (command === "/usr/bin/cat" && args.at(-1) === "/proc/124/cgroup") {
      return Promise.resolve(ok("0::/user.slice/session-999.scope\n"));
    }
    return f.after(command, args);
  };
  const blocked = await observeBackupV2Kernel(gate, escaped, {
    cancellationStopProof: f.proof,
  });
  equal(blocked.tree?.escapedProcesses, 1);
  equal(blocked.tree?.pendingOperations, null);
  const unknown = await cancelledFixture({
    unresolved: true,
    missingExit: true,
  });
  equal(
    (await observeBackupV2Kernel(gate, unknown.after, {
      cancellationStopProof: unknown.proof,
    })).tree?.namespaceReferences,
    null,
  );
  f.base.state.load = "loaded";
  f.base.state.active = "inactive";
  f.base.state.sub = "dead";
  f.base.state.invocation = "f".repeat(32);
  equal(
    (await observeBackupV2Kernel(gate, f.after, {
      cancellationStopProof: f.proof,
    })).identity,
    null,
  );
  f.base.state.boot = GATE;
  equal(
    (await observeBackupV2Kernel(gate, f.after, {
      cancellationStopProof: f.proof,
    })).identity,
    null,
  );
});
