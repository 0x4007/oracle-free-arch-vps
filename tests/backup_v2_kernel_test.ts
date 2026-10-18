import {
  backupV2DeletedHandleBytes,
  type BackupV2KernelCommand,
  type BackupV2KernelCommandResult,
  BackupV2KernelEvidenceError,
  observeBackupV2Kernel,
  readBackupV2KernelText,
} from "../scripts/backup-v2-kernel.ts";
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
      command === "/usr/bin/readlink" && args[0] === "-z"
    ),
  );
  assert(
    f.calls.some(([command, args]) =>
      command === "/usr/bin/stat" && args.includes("-L")
    ),
  );
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
