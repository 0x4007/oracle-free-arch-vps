import {
  backupV2BridgeEntrypoint,
  backupV2BridgeRuntimeCommand,
  type BackupV2BridgeRuntimeInput,
  backupV2BridgeRuntimePaths,
  backupV2BridgeSourceProgram,
  backupV2BridgeUserRunner,
  decodeBackupV2BridgeSource,
  realBackupV2BridgeRuntime,
} from "../scripts/backup-v2-bridge-runtime.ts";
import {
  type BackupV2Gate,
  type BackupV2Request,
  backupV2RequestSha256,
  type BackupV2Status,
} from "../scripts/backup-v2-runtime-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import type { PiDeps, RemoteRunner } from "../scripts/backblaze-file-backup.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function equal(a: unknown, b: unknown) {
  assert(JSON.stringify(a) === JSON.stringify(b));
}
function throws(work: () => unknown) {
  let rejected = false;
  try {
    work();
  } catch {
    rejected = true;
  }
  assert(rejected);
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
  requestedAtUtc: "2026-10-18T15:00:00.000Z",
  sourceRevision: "a".repeat(40),
  sourceConfigSha256: "b".repeat(64),
  recipientSha256: "c".repeat(64),
  recipientFingerprint: "D".repeat(40),
};
const sourceName = `arch-vps-b2-v2-verify-${ID}-${GATE}.service`;
const gate: BackupV2Gate = {
  schemaVersion: 2,
  format: "backup-v2",
  owner: GATE_OWNER,
  envelope: { request, requestSha256: backupV2RequestSha256(request) },
  gateId: GATE,
  sourceBootId: ID,
  kind: "verify",
  unitName: sourceName,
  custody: {
    unitName: sourceName,
    invocationId: "a".repeat(32),
    mainPid: 123,
    mainStartTicks: "456",
    cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${sourceName}`,
  },
  state: "ACTIVE",
  remoteHost: GATE_REMOTE_HOST,
  sourceLockPath: GATE_SOURCE_LOCK_PATH,
  createdAtUtc: request.requestedAtUtc,
  updatedAtUtc: request.requestedAtUtc,
};
const input: BackupV2BridgeRuntimeInput = {
  schemaVersion: 1,
  format: "backup-v2-bridge-runtime",
  gate,
  binding: {
    jobId: request.jobId,
    captureId: request.captureId,
    gateId: gate.gateId,
    requestSha256: gate.envelope.requestSha256,
    source: { ...gate.custody!, sourceBootId: ID },
    publicHome:
      `/home/codex/.local/share/arch-vps-verifier/${request.captureId}`,
    remoteSocket: "/run/user/1002/gnupg/d.fixture/S.gpg-agent",
    defaultSocket: "/run/user/1002/gnupg/S.gpg-agent",
  },
  sourceDirectory:
    `/var/tmp/arch-vps-file-backup/${request.captureId}/v2-${GATE}/${
      gate.custody!.invocationId
    }`,
  defaultSocketIdentity: "ABSENT",
};
const now = new Date("2026-10-18T15:01:00.000Z");
function status(terminal = false): BackupV2Status {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: gate.envelope,
    gateId: gate.gateId,
    sourceBootId: ID,
    custody: gate.custody!,
    kind: "verify",
    phase: terminal ? "ACCEPTED" : "VERIFYING",
    activeRoleAttempt: null,
    startedAtUtc: request.requestedAtUtc,
    updatedAtUtc: now.toISOString(),
    finishedAtUtc: terminal ? now.toISOString() : null,
    progress: {
      phase: terminal ? "ACCEPTED" : "VERIFYING",
      observedMonotonicMs: 1000,
      sourceBytes: 0,
      compressionInputBytes: 0,
      verifiedChunks: 1,
      decryptedBytes: 99,
      inventoryMembers: 1,
    },
    lease: {
      observedMonotonicMs: 1000,
      usefulProgressAtMs: 900,
      usefulProgressExpiresAtMs: 120900,
      retryEpisode: null,
    },
    resultSha256: terminal ? "e".repeat(64) : null,
  };
}
function stat(pid: number, ticks: string) {
  const fields = Array(20).fill("0");
  fields[0] = "S";
  fields[19] = ticks;
  return `${pid} (deno fixture) ${fields.join(" ")}`;
}
function observation(terminal = false, value = status(terminal)) {
  return `__PROPS__\nLoadState=loaded\nResult=success\nActiveState=active\nSubState=${
    terminal ? "exited" : "running"
  }\nMainPID=${terminal ? 0 : 123}\nControlPID=0\nInvocationID=${
    gate.custody!.invocationId
  }\nControlGroup=${gate.custody!.cgroup}\n__PROCESS__\n${
    terminal ? "" : stat(123, "456") + "\n0::" + gate.custody!.cgroup + "\n"
  }__CGROUP__\n${terminal ? "ABSENT" : "populated 1"}\n__STATUS__\n${
    JSON.stringify(value)
  }\n__RESULT__\n${terminal ? "e".repeat(64) : "MISSING"}\n__SOCKETS__\n${
    terminal ? "CUSTOM_ABSENT" : "CUSTOM_PRESENT"
  }\nABSENT\n`;
}

Deno.test("real bridge entrypoint imports existing factories, fixed keyring and actual runner", () => {
  const base =
    `file:///home/pi/ops/weekly-backup-controller/.private/file-backup/runtime/releases/${request.sourceRevision}/scripts/`;
  const code = backupV2BridgeEntrypoint(
    base,
    backupV2BridgeRuntimePaths(gate).settings,
  );
  for (
    const expected of [
      "runBackupV2BridgeRuntime",
      "realTunnelSeam",
      "PI_KEYRING_PATH",
      "backupV2GateDirectory",
      base,
    ]
  ) assert(code.includes(expected));
  assert(!code.includes("ssh -N"));
  throws(() =>
    backupV2BridgeEntrypoint("https://example.invalid/scripts/", "../foreign")
  );
});

Deno.test("real bridge launch retains safepi wrapper, finite native lease and equivalent Pi caps", () => {
  const args = backupV2BridgeRuntimeCommand(
    input,
    "/home/pi/ops/weekly-backup-controller",
  );
  equal(args.slice(0, 2), ["/usr/bin/systemd-run", "--user"]);
  for (
    const property of [
      "Type=notify",
      "NotifyAccess=main",
      "RemainAfterExit=yes",
      "RuntimeMaxSec=60000ms",
      "MemoryHigh=320M",
      "MemoryMax=380M",
      "MemorySwapMax=0",
      "CPUQuota=90%",
      "TasksMax=256",
      "Nice=10",
      "LimitCORE=0",
    ]
  ) assert(args.includes(`--property=${property}`));
  assert(args.includes("--allow-ffi=/lib/aarch64-linux-gnu/libsystemd.so.0"));
  assert(!args.includes("-A"));
  throws(() => backupV2BridgeRuntimeCommand(input, "/tmp/foreign"));
});

Deno.test("real user-manager adapter restores only standard bus coordinates after environment clearing", async () => {
  const calls: unknown[] = [];
  const runner: RemoteRunner = (command, args) => {
    calls.push([command, args]);
    return Promise.resolve({
      code: 0,
      stdout: command === "/usr/bin/id" ? "1000\n" : "",
      stderr: "",
    });
  };
  const run = await backupV2BridgeUserRunner(runner);
  await run("/usr/local/bin/safepi", ["/usr/bin/systemd-run", "--user"]);
  equal(calls[1], ["/usr/bin/env", [
    "XDG_RUNTIME_DIR=/run/user/1000",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    "/usr/local/bin/safepi",
    "/usr/bin/systemd-run",
    "--user",
  ]]);
});

Deno.test("real source program verifies actual boot, process, private status and exact custom socket", () => {
  const program = backupV2BridgeSourceProgram(input);
  for (
    const text of [
      "/proc/sys/kernel/random/boot_id",
      "/proc/123/stat",
      "/proc/123/cgroup",
      input.sourceDirectory,
      "0:600:1",
      "sha256sum",
      input.binding.remoteSocket,
      input.binding.defaultSocket,
    ]
  ) assert(program.includes(text));
  assert(!program.includes("rm -"));
});

Deno.test("real source decoder accepts only exact live custody and complete successful terminal result", () => {
  equal(
    decodeBackupV2BridgeSource(observation(), input, now).status.progress
      .decryptedBytes,
    99,
  );
  const terminal = decodeBackupV2BridgeSource(
    observation(true),
    input,
    new Date(now.getTime() + 3_600_000),
  );
  equal([terminal.terminal, terminal.cancelled, terminal.socketPresent], [
    true,
    false,
    false,
  ]);
  throws(() =>
    decodeBackupV2BridgeSource(
      observation(true).replace(
        "e".repeat(64) + "\n__SOCKETS__",
        "f".repeat(64) + "\n__SOCKETS__",
      ),
      input,
      now,
    )
  );
});

Deno.test("real source decoder rejects invocation, PID reuse, cgroup and stale-heartbeat faults", () => {
  for (
    const text of [
      observation().replace(
        `InvocationID=${gate.custody!.invocationId}`,
        `InvocationID=${"f".repeat(32)}`,
      ),
      observation().replace(stat(123, "456"), stat(123, "999")),
      observation().replace(`0::${gate.custody!.cgroup}`, "0::/foreign.scope"),
      observation().replace("MainPID=123", "MainPID=124"),
    ]
  ) throws(() => decodeBackupV2BridgeSource(text, input, now));
  throws(() =>
    decodeBackupV2BridgeSource(
      observation(),
      input,
      new Date(now.getTime() + 90_001),
    )
  );
});

Deno.test("real source cancellation preserves nonterminal status after exact process settlement", () => {
  const value = status();
  value.phase = "CANCELLATION_BLOCKED";
  value.progress.phase = value.phase;
  const text = observation(true, value).replace(
    "SubState=exited",
    "SubState=failed",
  );
  const result = decodeBackupV2BridgeSource(
    text,
    input,
    new Date(now.getTime() + 3_600_000),
  );
  equal([result.terminal, result.cancelled, result.status.finishedAtUtc], [
    true,
    true,
    null,
  ]);
});

Deno.test("real source waits for process exit after final status and rejects failed accepted units", () => {
  equal(
    decodeBackupV2BridgeSource(observation(false, status(true)), input, now)
      .terminal,
    false,
  );
  throws(() =>
    decodeBackupV2BridgeSource(
      observation(true).replace("Result=success", "Result=timeout"),
      input,
      now,
    )
  );
});

Deno.test("real bridge close stops only proved retained invocation and is idempotent", async () => {
  const paths = backupV2BridgeRuntimePaths(gate),
    records = new Map<string, unknown>();
  const keeper = {
    unitName: paths.unitName,
    invocationId: "d".repeat(32),
    mainPid: 777,
    mainStartTicks: "888",
    cgroup:
      `/user.slice/user-1000.slice/user@1000.service/app.slice/${paths.unitName}`,
  };
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(JSON.stringify(input) + "\n"),
    ),
  );
  const inputSha256 = Array.from(
    digest,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  records.set(paths.settings, input);
  records.set(paths.status, {
    schemaVersion: 1,
    inputSha256,
    keeperBootId: ID,
    updatedAtUtc: now.toISOString(),
    bridge: {
      state: "CLOSED",
      keeper,
      binding: input.binding,
      reason: "TERMINAL",
      lease: {
        observedMonotonicMs: 0,
        usefulProgressAtMs: 0,
        usefulProgressExpiresAtMs: 0,
        retryEpisode: null,
      },
      pendingOperations: 0,
    },
  });
  let stopped = false, stops = 0;
  const runner: RemoteRunner = (command, args) => {
    if (command === "/usr/bin/env") {
      command = args[2];
      args = args.slice(3);
    }
    let stdout = "";
    if (command === "/usr/bin/id") stdout = "1000\n";
    else if (command === "/usr/bin/cat") stdout = ID + "\n";
    else if (command === "/bin/sh") {
      if (args[1].includes("systemctl --user stop")) {
        assert(args[1].includes(keeper.invocationId));
        assert(args[1].includes(paths.unitName));
        stopped = true;
        stops++;
      } else stdout = "ABSENT\n";
    } else if (command === "/usr/bin/systemctl") {
      stdout = `LoadState=${stopped ? "not-found" : "loaded"}\nActiveState=${
        stopped ? "inactive" : "active"
      }\nSubState=${
        stopped ? "dead" : "exited"
      }\nResult=success\nMainPID=0\nControlPID=0\nInvocationID=${
        stopped ? "" : keeper.invocationId
      }\nControlGroup=\n`;
    } else throw Error("Unexpected native boundary");
    return Promise.resolve({ code: 0, stdout, stderr: "" });
  };
  const deps = {
    now: () => now,
    private: {
      read: (path: string) => Promise.resolve(records.get(path)),
      write: (path: string, value: unknown) => {
        records.set(path, value);
        return Promise.resolve();
      },
    },
    remote: {
      root: (_program: string) =>
        Promise.resolve({ code: 0, stdout: observation(true), stderr: "" }),
    },
  } as unknown as Pick<PiDeps, "private" | "remote" | "now">;
  const runtime = realBackupV2BridgeRuntime(deps, runner);
  equal(await runtime.close(gate), "CLOSED");
  assert(records.has(paths.settled));
  equal(await runtime.close(gate), "CLOSED");
  equal(stops, 1);
});

Deno.test("real bridge close refuses absent or mismatched custody without stopping anything", async () => {
  let stops = 0;
  const runner: RemoteRunner = (command, args) => {
    if (command === "/usr/bin/env") {
      command = args[2];
      args = args.slice(3);
    }
    if (args.includes("stop")) stops++;
    const stdout = command === "/usr/bin/id"
      ? "1000\n"
      : command === "/usr/bin/cat"
      ? ID + "\n"
      : "LoadState=not-found\nMainPID=0\nControlPID=0\nInvocationID=\nControlGroup=\n";
    return Promise.resolve({ code: 0, stdout, stderr: "" });
  };
  const deps = {
    now: () => now,
    private: { read: () => Promise.resolve(undefined) },
    remote: {},
  } as unknown as Pick<PiDeps, "private" | "remote" | "now">;
  equal(
    await realBackupV2BridgeRuntime(deps, runner).close(gate),
    "CANCELLATION_BLOCKED",
  );
  equal(stops, 0);
});
