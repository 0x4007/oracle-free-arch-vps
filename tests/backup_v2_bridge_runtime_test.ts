import { validateBackupV2LeaseWindow } from "../scripts/backup-v2-contract.ts";
import {
  backupV2BridgeEntrypoint,
  backupV2BridgeRuntimeCommand,
  type BackupV2BridgeRuntimeInput,
  backupV2BridgeRuntimePaths,
  backupV2BridgeSourceProgram,
  backupV2BridgeUserRunner,
  createBackupV2BridgeWaitProjection,
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
  type CaptureSettings,
  REQUIRED_EXCLUSIONS,
  ROLE_ORDER,
} from "../scripts/backblaze-capture.ts";
import { backupV2SourceConfigSha256 } from "../scripts/backup-v2-metadata.ts";
import type { BackupV2WorkerSettings } from "../scripts/backup-v2-worker.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import type { PiDeps, RemoteRunner } from "../scripts/backblaze-file-backup.ts";
import { shellQuote } from "../scripts/backup-guest.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function equal(a: unknown, b: unknown) {
  const observed = JSON.stringify(a), expected = JSON.stringify(b);
  if (observed !== expected) {
    throw Error(`Expected ${expected}, received ${observed}`);
  }
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
const captureSettings: CaptureSettings = {
  generation: `generation-${ID}`,
  recipientFile: "/fixture/recipient.asc",
  recipientSha256: "c".repeat(64),
  recipientFingerprint: "D".repeat(40),
  exclusionsText: REQUIRED_EXCLUSIONS.join("\n") + "\n",
  sources: ROLE_ORDER.map((name, i) => ({
    name,
    uuid: `aaaaaaa${i}-1111-2222-3333-444444444444`,
    filesystem: name === "root"
      ? "ext4"
      : name.includes("efi")
      ? "vfat"
      : "xfs",
    size: 1024 * (i + 1),
    ...(name === "root"
      ? { livePath: "/" as const }
      : name === "efi"
      ? { livePath: "/efi" as const }
      : {}),
  })),
};
const request: BackupV2Request = {
  schemaVersion: 2,
  format: "backup-v2",
  profile: BACKUP_V2_PROFILE_ID,
  jobId: `job-${ID}`,
  captureId: `generation-${ID}`,
  periodKey: "2026-10-18",
  requestedAtUtc: "2026-10-18T15:00:00.000Z",
  sourceRevision: "a".repeat(40),
  sourceConfigSha256: backupV2SourceConfigSha256(captureSettings),
  recipientSha256: captureSettings.recipientSha256,
  recipientFingerprint: captureSettings.recipientFingerprint,
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
const workerGateId = "33333333-3333-3333-3333-333333333333";
const settings: BackupV2WorkerSettings = {
  schemaVersion: 2,
  format: "backup-v2",
  envelope: gate.envelope,
  captureSettings,
  B2Settings: {
    accessKeyId: "fixture",
    secretAccessKey: "fixture",
    bucketId: "fixture",
    bucketName: "pavlovcik-arch-vps-backups",
  },
  verifierGate: { ...gate, state: "PENDING", custody: null },
  workerGate: {
    ...gate,
    kind: "worker",
    gateId: workerGateId,
    unitName: `arch-vps-b2-v2-worker-${ID}-${workerGateId}.service`,
    state: "PENDING",
    custody: null,
  },
  publicationAttemptId: "44444444-4444-4444-4444-444444444444",
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
Deno.test("source transfer projection preserves expiry across heartbeats and rejects rebinding", () => {
  const project = createBackupV2BridgeWaitProjection(), value = status();
  value.lease.transferEpisode = {
    kind: "SEALED_TRANSFER",
    operationId: "read/one",
    phase: "READBACK",
    sealedObjectIdentity: "sealed-one",
    retainedBytes: 64,
    startedAtMs: 900,
    expiresAtMs: 200000,
  };
  const first = project(value, now, 100);
  assert(first.transferEpisode !== null);
  value.lease.observedMonotonicMs += 10000;
  value.updatedAtUtc = new Date(now.getTime() + 10000).toISOString();
  const later = project(value, new Date(now.getTime() + 10000), 10100);
  equal(later.transferEpisode!.expiresAtMs, first.transferEpisode!.expiresAtMs);
  value.lease.transferEpisode.expiresAtMs++;
  throws(() => project(value, new Date(now.getTime() + 10000), 10100));
});
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
      "RuntimeMaxSec=300000ms",
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
  assert(args.includes("--v8-flags=--max-old-space-size=128,--expose-gc"));
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

Deno.test("clean source exit with a temporarily nonterminal status is bounded", () => {
  equal(
    decodeBackupV2BridgeSource(observation(true, status(false)), input, now)
      .terminalStatusPending,
    true,
  );
  equal(
    decodeBackupV2BridgeSource(
      observation(true, status(false)),
      input,
      new Date(now.getTime() + 90_001),
    ).terminalStatusPending,
    false,
  );
});

async function terminalBridgeFixture(
  nativeProof?: (
    program: string,
    keeper: { cgroup: string; invocationId: string },
  ) => ReturnType<RemoteRunner>,
) {
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
  const terminalStatus = {
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
  };
  records.set(paths.status, terminalStatus);
  let stopped = false,
    stops = 0,
    cgroup = "ABSENT\n",
    proofCode = 0,
    keeperRunning = false,
    failSettledWrite = false,
    remoteObservation = observation(true);
  const runner: RemoteRunner = async (command, args) => {
    if (command === "/usr/bin/env") {
      command = args[2];
      args = args.slice(3);
    }
    let stdout = "";
    if (command === "/usr/bin/id") stdout = "1000\n";
    else if (command === "/usr/bin/cat") {
      assert(args[0] === "/proc/sys/kernel/random/boot_id");
      stdout = ID + "\n";
    } else if (command === "/bin/sh") {
      const stopping = args[1].includes("systemctl --user stop");
      if (nativeProof && args[1].includes("cgroup.procs")) {
        const result = await nativeProof(args[1], keeper);
        if (stopping && result.code === 0 && !result.stdout.trim()) {
          stopped = true;
          stops++;
        }
        return result;
      }
      if (stopping) {
        assert(args[1].includes(keeper.invocationId));
        assert(args[1].includes(paths.unitName));
        assert(args[1].includes("cgroup.procs"));
        assert(args[1].includes("SubState=exited"));
        stopped = true;
        stops++;
      } else if (args[1].includes("cgroup.procs")) {
        assert(args[1].includes("--homedir"));
        assert(args[1].includes("/usr/bin/gpg-agent"));
        return Promise.resolve({ code: proofCode, stdout: "", stderr: "" });
      } else stdout = stopped ? "ABSENT\n" : cgroup;
    } else if (command === "/usr/bin/systemctl") {
      stdout = `LoadState=${stopped ? "not-found" : "loaded"}\nActiveState=${
        stopped ? "inactive" : "active"
      }\nSubState=${
        stopped ? "dead" : keeperRunning ? "running" : "exited"
      }\nResult=success\nMainPID=${
        !stopped && keeperRunning ? keeper.mainPid : 0
      }\nControlPID=0\nInvocationID=${
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
        if (path === paths.settled && failSettledWrite) {
          return Promise.reject(Error("Interrupted before settled receipt"));
        }
        records.set(path, value);
        return Promise.resolve();
      },
    },
    remote: {
      root: (_program: string) =>
        Promise.resolve({ code: 0, stdout: remoteObservation, stderr: "" }),
    },
  } as unknown as Pick<PiDeps, "private" | "remote" | "now">;
  const runtime = realBackupV2BridgeRuntime(deps, runner);
  return {
    runtime,
    paths,
    records,
    stops: () => stops,
    setRunning: (value: boolean) => {
      keeperRunning = value;
    },
    setActive: () =>
      records.set(paths.status, {
        ...terminalStatus,
        bridge: { ...terminalStatus.bridge, state: "ACTIVE", reason: null },
      }),
    setProof: (value: number) => {
      cgroup = "populated 1\n";
      proofCode = value;
    },
    setRemote: (value: string) => {
      remoteObservation = value;
    },
    failSettledWrite: (value: boolean) => {
      failSettledWrite = value;
    },
  };
}

Deno.test("real bridge close stops only proved retained invocation and is idempotent", async () => {
  const f = await terminalBridgeFixture();
  equal(await f.runtime.close(gate), "CLOSED");
  assert(f.records.has(f.paths.settled));
  equal(await f.runtime.close(gate), "CLOSED");
  equal(f.stops(), 1);
});

Deno.test("bridge readiness observes a clean exit before status publication without reading a vanishing keeper PID", async () => {
  const f = await terminalBridgeFixture();
  f.setActive();
  f.setRunning(true);
  f.setRemote(observation(true, status(false)));
  equal(await f.runtime.ensure(settings, gate), "PENDING");
  f.setRemote(observation(true));
  equal(await f.runtime.ensure(settings, gate), "PENDING");
  equal(f.stops(), 0);
  assert(!f.records.has(f.paths.close));
});

Deno.test("terminal bridge waits for verifier status and keeper exit before settling only an owned residual agent", async () => {
  const f = await terminalBridgeFixture();
  f.setRemote(observation(true, status(false)));
  equal(await f.runtime.close(gate), "PENDING");
  f.setRemote(observation(true));
  f.setRunning(true);
  equal(await f.runtime.close(gate), "PENDING");
  f.setRunning(false);
  f.setProof(1);
  equal(await f.runtime.close(gate), {
    state: "CANCELLATION_BLOCKED",
    reason: "BRIDGE_TERMINAL_PROCESSES_UNPROVED",
  });
  assert(!f.records.has(f.paths.settlementIntent));
  equal(f.stops(), 0);

  f.setProof(0);
  f.failSettledWrite(true);
  equal(await f.runtime.close(gate), {
    state: "CANCELLATION_BLOCKED",
    reason: "BRIDGE_EXACT_STOP_UNPROVED",
  });
  assert(f.records.has(f.paths.settlementIntent));
  assert(!f.records.has(f.paths.settled));
  f.failSettledWrite(false);
  equal(await f.runtime.close(gate), "CLOSED");
  assert(f.records.has(f.paths.settled));
  equal(f.stops(), 1);
});

const nativeBridgeProof = Deno.build.os === "linux" && (
  await Promise.all(
    ["/usr/bin/cc", "/usr/bin/bash", "/bin/sh"].map((command) =>
      Deno.permissions.query({ name: "run", command })
    ),
  )
).every((permission) => permission.state === "granted");

const listeningAgentFixture = String.raw`
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  const char *path = getenv("BACKUP_TEST_SOCKET");
  const char *hello = getenv("BACKUP_TEST_GREETING");
  if (!path || !hello || strlen(path) >= sizeof address.sun_path) return 1;
  strcpy(address.sun_path, path);
  int listener = socket(AF_UNIX, SOCK_STREAM, 0), ready[2];
  if (listener < 0 || bind(listener, (void *)&address, sizeof address) ||
      listen(listener, 4) || pipe(ready)) return 1;
  pid_t parent = getpid(), child = fork();
  if (child < 0) return 1;
  if (!child) {
    alarm(25);
    close(ready[0]);
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent ||
        prctl(PR_SET_DUMPABLE, 0) || write(ready[1], "1", 1) != 1) return 1;
    close(ready[1]);
    for (;;) {
      int peer = accept(listener, NULL, NULL);
      if (peer < 0) return 1;
      if (*hello) {
        send(peer, hello, 1, MSG_NOSIGNAL);
        usleep(20000);
        send(peer, hello + 1, strlen(hello) - 1, MSG_NOSIGNAL);
      }
      char ignored;
      recv(peer, &ignored, 1, 0);
      close(peer);
    }
  }
  close(listener);
  close(ready[1]);
  char byte;
  if (read(ready[0], &byte, 1) == 1) {
    printf("%d\n", child);
    fflush(stdout);
    read(STDIN_FILENO, &byte, 1);
  }
  close(ready[0]);
  kill(child, SIGTERM);
  return waitpid(child, NULL, 0) == child ? 0 : 1;
}
`;

Deno.test({
  name:
    "terminal settlement uses the nondumpable socket sender and leaves foreign agents running",
  ignore: !nativeBridgeProof,
  async fn() {
    const directory = await Deno.makeTempDir({ prefix: "bridge-peer." }),
      processDirectory = directory + "/cgroup",
      keyring = directory + "/keyring",
      socketSelection = directory + "/configured-socket",
      bootFile = directory + "/boot-id";
    const children: Deno.ChildProcess[] = [];
    try {
      await Deno.mkdir(processDirectory);
      await Deno.writeTextFile(bootFile, ID + "\n");
      await Deno.writeTextFile(directory + "/agent.c", listeningAgentFixture);
      const built = await new Deno.Command("/usr/bin/cc", {
        args: ["-o", directory + "/agent", directory + "/agent.c"],
      }).output();
      assert(built.success);
      await Deno.writeTextFile(
        directory + "/gpgconf",
        [
          "#!/bin/sh",
          'test "$#" = 4 && test "$1" = --homedir &&',
          `test "$2" = ${shellQuote(keyring)} &&`,
          'test "$3" = --list-dirs && test "$4" = agent-socket || exit 1',
          `cat ${shellQuote(socketSelection)}`,
          "",
        ].join("\n"),
        { mode: 0o700 },
      );
      const launch = async (
        argv0: string,
        n: number,
        greeting = "OK ready\n",
      ) => {
        const socket = `${directory}/agent-${n}.socket`;
        const child = new Deno.Command("/usr/bin/bash", {
          args: [
            "-c",
            'exec -a "$1" "$2" --homedir "$3" --use-standard-socket --daemon',
            "agent-fixture",
            argv0,
            directory + "/agent",
            keyring,
          ],
          clearEnv: true,
          env: { BACKUP_TEST_SOCKET: socket, BACKUP_TEST_GREETING: greeting },
          stdin: "piped",
          stdout: "piped",
        }).spawn();
        children.push(child);
        const reader = child.stdout.getReader();
        const { value } = await reader.read();
        reader.releaseLock();
        const pid = Number(new TextDecoder().decode(value).trim());
        assert(Number.isSafeInteger(pid) && pid > 1);
        const executable = await new Deno.Command("/bin/sh", {
          args: [
            "-c",
            'LC_ALL=C readlink -v "/proc/$1/exe"',
            "fixture",
            String(pid),
          ],
        }).output();
        if (
          executable.code !== 1 ||
          !new TextDecoder().decode(executable.stderr).includes(
            "Permission denied",
          )
        ) {
          throw Error("Expected EACCES for a same-user nondumpable process");
        }
        return { pid, socket };
      };
      const first = await launch("gpg-agent", 1),
        second = await launch("/usr/bin/gpg-agent", 2);
      const procGroup = await new Deno.Command("/bin/sh", {
        args: ["-c", 'cat "/proc/$1/cgroup"', "fixture", String(first.pid)],
      }).output();
      const membershipLine = new TextDecoder().decode(procGroup.stdout).trim();
      assert(procGroup.success && membershipLine.startsWith("0::/"));
      const group = membershipLine.slice(3);
      const membership = async (pids: number[], descendants = 0) => {
        await Deno.writeTextFile(
          processDirectory + "/cgroup.procs",
          pids.map((pid) => pid + "\n").join(""),
        );
        await Deno.writeTextFile(
          processDirectory + "/cgroup.events",
          `populated ${pids.length ? 1 : 0}\n`,
        );
        await Deno.writeTextFile(
          processDirectory + "/cgroup.stat",
          `nr_descendants ${descendants}\n`,
        );
      };
      const select = (socket: string) =>
        Deno.writeTextFile(socketSelection, socket);
      let betweenProofs: (() => Promise<void>) | undefined,
        managerGroup = group;
      const native: Parameters<typeof terminalBridgeFixture>[0] = async (
        program,
        keeper,
      ) => {
        const properties = [
          "LoadState=loaded",
          "ActiveState=active",
          "SubState=exited",
          "Result=success",
          "MainPID=0",
          "ControlPID=0",
          "KillMode=control-group",
          `InvocationID=${keeper.invocationId}`,
          `ControlGroup=${managerGroup}`,
        ].map(shellQuote).join(" ");
        const payload = "systemctl() {\n" +
          `case "$2" in show) printf '%s\\n' ${properties};; stop) :;; *) exit 1;; esac\n}\n` +
          program.replaceAll(keeper.cgroup, group)
            .replaceAll("/sys/fs/cgroup$group", processDirectory)
            .replaceAll("/proc/sys/kernel/random/boot_id", bootFile)
            .replaceAll(
              "/home/pi/ops/weekly-backup-controller/.private/file-backup/gnupg",
              keyring,
            )
            .replaceAll("/usr/bin/gpgconf", directory + "/gpgconf");
        const raw = await new Deno.Command("/bin/sh", {
          args: ["-c", payload],
        }).output();
        if (raw.success && !program.includes("systemctl --user stop")) {
          await betweenProofs?.();
        }
        const decoder = new TextDecoder();
        return {
          code: raw.code,
          stdout: decoder.decode(raw.stdout),
          stderr: decoder.decode(raw.stderr),
        };
      };
      const blocked = {
        state: "CANCELLATION_BLOCKED",
        reason: "BRIDGE_TERMINAL_PROCESSES_UNPROVED",
      };
      const f = await terminalBridgeFixture(native);
      await membership([first.pid]);
      await select(second.socket);
      equal(await f.runtime.close(gate), blocked);
      await select(first.socket);
      await membership([first.pid, second.pid]);
      equal(await f.runtime.close(gate), blocked);
      await membership([first.pid], 1);
      equal(await f.runtime.close(gate), blocked);
      await membership([first.pid]);
      assert(!f.records.has(f.paths.settlementIntent));

      betweenProofs = async () => {
        await membership([second.pid]);
        await select(second.socket);
      };
      equal(await f.runtime.close(gate), blocked);
      assert(f.records.has(f.paths.settlementIntent));
      assert(!f.records.has(f.paths.settled));
      equal(f.stops(), 0);
      betweenProofs = undefined;
      managerGroup = "";
      equal(await f.runtime.close(gate), {
        state: "CANCELLATION_BLOCKED",
        reason: "BRIDGE_EXACT_STOP_UNPROVED",
      });
      equal(f.stops(), 0);
      managerGroup = group;
      equal(await f.runtime.close(gate), "CLOSED");
      equal(f.stops(), 1);

      const commandName = await terminalBridgeFixture(native);
      await membership([first.pid]);
      await select(first.socket);
      equal(await commandName.runtime.close(gate), "CLOSED");
      const foreign = await launch("gpg-agent", 3, "ERR wrong protocol\n");
      const silent = await launch("gpg-agent", 4, "");
      for (const peer of [foreign, silent]) {
        await membership([peer.pid]);
        await select(peer.socket);
        const invalid = await terminalBridgeFixture(native);
        equal(await invalid.runtime.close(gate), blocked);
        equal(invalid.stops(), 0);
      }
      const outside = await terminalBridgeFixture(native);
      await membership([]);
      await Deno.remove(socketSelection);
      managerGroup = "";
      equal(await outside.runtime.close(gate), "CLOSED");
      for (const peer of [first, second, foreign, silent]) {
        const live = await new Deno.Command("/bin/sh", {
          args: ["-c", 'test -d "/proc/$1"', "fixture", String(peer.pid)],
        }).output();
        assert(live.success);
      }
    } finally {
      try {
        await Promise.all(children.map(async (child) => {
          await child.stdin.getWriter().close();
          assert((await child.status).success);
        }));
      } finally {
        await Deno.remove(directory, { recursive: true });
      }
    }
  },
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
    { state: "CANCELLATION_BLOCKED", reason: "BRIDGE_SETTINGS_UNPROVED" },
  );
  equal(stops, 0);
});

Deno.test("fractional source clocks never widen a projected transfer window", () => {
  for (const localNow of [16344.279672, 16343.417434, 20000, 40971.939949]) {
    const value = status();
    value.lease.observedMonotonicMs = 40971.939949;
    value.lease.transferEpisode = {
      kind: "SEALED_TRANSFER",
      operationId: "read/fractional",
      phase: "READBACK",
      sealedObjectIdentity: "sealed-fractional",
      retainedBytes: 67108864,
      startedAtMs: 36417.360805,
      expiresAtMs: 21786417.360805,
    };
    const projected = createBackupV2BridgeWaitProjection()(
      value,
      now,
      localNow,
    );
    validateBackupV2LeaseWindow({
      observedMonotonicMs: localNow,
      usefulProgressAtMs: 0,
      usefulProgressExpiresAtMs: localNow + 120000,
      ...projected,
    });
    const episode = projected.transferEpisode!;
    assert(episode.expiresAtMs - episode.startedAtMs <= 21750000);
  }
});
