import {
  backupV2ChildEnvironment,
  type BackupV2Notifier,
  BackupV2Supervisor,
  type BackupV2SupervisorIdentity,
  type BackupV2SupervisorObservation,
  backupV2SupervisorUnitProperties,
  type BackupV2TreeObservation,
  createBackupV2Notifier,
  encodeBackupV2Notification,
  evaluateBackupV2Lease,
  settleBackupV2Cancellation,
} from "../scripts/backup-v2-supervisor.ts";
import { BACKUP_V2_LIMITS } from "../scripts/backup-v2-profile.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function equal(actual: unknown, expected: unknown): void {
  assert(JSON.stringify(actual) === JSON.stringify(expected));
}
function throws(run: () => unknown): void {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
const identity: BackupV2SupervisorIdentity = {
  unitName: "backup-v2-fixture.service",
  invocationId: "a".repeat(32),
  mainPid: 1234,
  mainStartTicks: "5678",
  cgroup: "/fixture.slice/backup-v2-fixture.service",
};
function observation(now: number): BackupV2SupervisorObservation {
  return {
    identity: { ...identity },
    progress: {
      phase: "CAPTURING_AND_UPLOADING",
      observedMonotonicMs: now,
      sourceBytes: 0,
      compressionInputBytes: 0,
      verifiedChunks: 0,
      decryptedBytes: 0,
      inventoryMembers: 0,
    },
    capacity: {
      observedMonotonicMs: now,
      availableBytes: 10 * 1024 ** 3,
      freeInodes: 10_000,
      allocatedWorkspaceBytes: 0,
      workspaceHeldDeletedBytes: 0,
      sourceHeldDeletedBytes: 0,
    },
  };
}
function fixture() {
  let now = 0;
  const messages: (number | string)[] = [];
  const notifier: BackupV2Notifier = {
    ready: () => messages.push("ready"),
    extend: (usec) => messages.push(usec),
    stopping: () => messages.push("stopping"),
    close: () => messages.push("closed"),
  };
  const state = {
    sample: observation(0),
    messages,
    now: () => now,
    advance: (value: number) => {
      now = value;
      state.sample.progress.observedMonotonicMs = value;
      state.sample.capacity.observedMonotonicMs = value;
    },
  };
  const options = {
    progressGraceMs: 1000,
    notificationGraceMs: 100,
    observationTimeoutMs: 20,
    maximumObservationAgeMs: 100,
    productionWriterMarginBytes: 4096,
    minimumFreeInodes: 100,
    maximumSourceHeldDeletedBytes: 1024,
  };
  const capabilities = {
    now: state.now,
    notifier,
    observe: (_signal: AbortSignal) =>
      Promise.resolve(structuredClone(state.sample)),
  };
  return {
    state,
    options,
    capabilities,
    supervisor: new BackupV2Supervisor(identity, options, capabilities),
  };
}

Deno.test("supervisor notification encoding is bounded, whitelisted and singly NUL terminated", () => {
  const decoder = new TextDecoder();
  equal(
    decoder.decode(encodeBackupV2Notification({ kind: "ready" })),
    "READY=1\0",
  );
  equal(
    decoder.decode(encodeBackupV2Notification({ kind: "stopping" })),
    "STOPPING=1\0",
  );
  equal(
    decoder.decode(
      encodeBackupV2Notification({ kind: "extend", usec: 4_000_000 }),
    ),
    "EXTEND_TIMEOUT_USEC=4000000\0",
  );
  for (const usec of [0, -1, NaN, Infinity, 0.5, 60_000_001]) {
    throws(() => encodeBackupV2Notification({ kind: "extend", usec }));
  }
  throws(() => encodeBackupV2Notification({ kind: "MAINPID=1" } as never));
  const child = backupV2ChildEnvironment({
    PATH: "/usr/bin",
    NOTIFY_SOCKET: "private",
    WATCHDOG_USEC: "10",
    LISTEN_PID: "1",
  });
  equal(child, { PATH: "/usr/bin" });
  const properties = backupV2SupervisorUnitProperties(4000);
  equal(properties.RuntimeMaxSec, "4000ms");
  equal(properties.NotifyAccess, "main");
  equal(properties.TimeoutStopSec, "30s");
  assert(!("MemoryMax" in properties)); // Existing resource caps remain caller-owned.
  throws(() => backupV2SupervisorUnitProperties(Infinity));
});

Deno.test("supervisor absolute deadline shrinks rather than banking heartbeat grace", () => {
  const window = {
    observedMonotonicMs: 10,
    usefulProgressAtMs: 5,
    usefulProgressExpiresAtMs: 100,
    retryEpisode: null,
  };
  equal(evaluateBackupV2Lease(window, 10, 20), {
    action: "renew",
    absoluteDeadlineMs: 100,
    extendUsec: 20_000,
  });
  equal(evaluateBackupV2Lease(window, 95, 20), {
    action: "renew",
    absoluteDeadlineMs: 100,
    extendUsec: 5000,
  });
  equal(evaluateBackupV2Lease(window, 100, 20), {
    action: "cancel",
    reason: "LEASE_EXPIRED",
  });
  throws(() =>
    evaluateBackupV2Lease({ ...window, observedMonotonicMs: 101 }, 100, 20)
  );
});

Deno.test("supervisor checked progress extends application time while unchanged samples do not", async () => {
  const { state, supervisor } = fixture();
  equal((await supervisor.poll()).action, "renew");
  state.advance(50);
  state.sample.progress.sourceBytes = 1;
  equal((await supervisor.poll()).action, "renew");
  equal(supervisor.window().usefulProgressExpiresAtMs, 1050);
  state.advance(1000);
  const decision = await supervisor.poll();
  equal(decision, {
    action: "renew",
    absoluteDeadlineMs: 1050,
    extendUsec: 50_000,
  });
  equal(supervisor.window().usefulProgressAtMs, 50);
  const detached = supervisor.window();
  detached.usefulProgressExpiresAtMs = 1e9;
  equal(supervisor.window().usefulProgressExpiresAtMs, 1050);
  state.advance(1050);
  state.sample.progress.sourceBytes = 2; // Even late new work cannot revive an expired lease.
  equal(await supervisor.poll(), { action: "cancel", reason: "LEASE_EXPIRED" });
  assert(supervisor.signal.aborted);
  equal(state.messages.filter((message) => message === "ready").length, 1);
});

Deno.test("supervisor startup cannot be renewed by a phase change or heartbeat", async () => {
  const { state, supervisor } = fixture();
  await supervisor.poll();
  state.advance(99);
  state.sample.progress.phase = "VERIFYING";
  equal(await supervisor.poll(), {
    action: "renew",
    absoluteDeadlineMs: 100,
    extendUsec: 1000,
  });
  state.advance(100);
  equal((await supervisor.poll()).action, "cancel");
});

Deno.test("supervisor rejects future stale regressing and wrong-phase observations", async () => {
  for (
    const fault of [
      "future",
      "stale",
      "regress",
      "wrong-phase",
      "timestamp",
      "identity",
      "clock",
    ]
  ) {
    const { state, supervisor } = fixture();
    await supervisor.poll();
    state.advance(10);
    state.sample.progress.sourceBytes = 10;
    await supervisor.poll();
    state.advance(20);
    if (fault === "future") state.sample.progress.observedMonotonicMs = 21;
    if (fault === "stale") state.sample.progress.observedMonotonicMs = -100;
    if (fault === "regress") state.sample.progress.sourceBytes = 9;
    if (fault === "wrong-phase") state.sample.progress.decryptedBytes = 1;
    if (fault === "timestamp") {
      state.sample.progress.observedMonotonicMs = 10;
      state.sample.progress.sourceBytes = 11;
    }
    if (fault === "identity") state.sample.identity.mainStartTicks = "999";
    if (fault === "clock") state.advance(9);
    equal((await supervisor.poll()).action, "cancel");
    const count = state.messages.length;
    await supervisor.poll();
    equal(state.messages.length, count);
  }
});

Deno.test("supervisor fixed retry episode survives attempts but never grants six hours at once", async () => {
  const { state, supervisor } = fixture();
  await supervisor.poll();
  const evidence = {
    sealedObjectIdentity: "sealed-slot",
    retainedBytes: 64,
    retryableTransport: true as const,
  };
  const first = supervisor.beginRetryEpisode(evidence).retryEpisode!;
  state.advance(50);
  equal(supervisor.beginRetryEpisode(evidence).retryEpisode, first);
  state.advance(BACKUP_V2_LIMITS.blockedTransportMs - 1);
  equal(await supervisor.poll(), {
    action: "renew",
    absoluteDeadlineMs: first.expiresAtMs,
    extendUsec: 1000,
  });
  state.advance(BACKUP_V2_LIMITS.blockedTransportMs);
  throws(() => supervisor.beginRetryEpisode(evidence));
  equal((await supervisor.poll()).action, "cancel");
});

Deno.test("supervisor only new useful work can clear a retry episode", async () => {
  const { state, supervisor } = fixture();
  await supervisor.poll();
  const evidence = {
    sealedObjectIdentity: "sealed-slot",
    retainedBytes: 64,
    retryableTransport: true as const,
  };
  state.advance(10);
  await supervisor.poll();
  state.advance(20);
  supervisor.beginRetryEpisode(evidence);
  assert(supervisor.window().retryEpisode !== null);
  state.advance(30);
  state.sample.progress.sourceBytes++;
  state.sample.progress.observedMonotonicMs = 15; // Checked work predates the blockage.
  await supervisor.poll();
  assert(supervisor.window().retryEpisode !== null);
  state.advance(40);
  state.sample.progress.verifiedChunks++;
  await supervisor.poll();
  equal(supervisor.window().retryEpisode, null);
  equal(supervisor.beginRetryEpisode(evidence).retryEpisode!.startedAtMs, 40);
});

Deno.test("supervisor capacity includes held-deleted blocks and inode/production margin", async () => {
  for (
    const fault of [
      "blocks",
      "inodes",
      "workspace-held",
      "source-held",
      "unbounded",
      "unknown",
    ]
  ) {
    const { state, supervisor } = fixture();
    if (fault === "blocks") {
      state.sample.capacity.availableBytes =
        BACKUP_V2_LIMITS.protectedReserveBytes;
    }
    if (fault === "inodes") state.sample.capacity.freeInodes = 99;
    if (fault === "workspace-held") {
      state.sample.capacity.workspaceHeldDeletedBytes = 1;
    }
    if (fault === "source-held") {
      state.sample.capacity.sourceHeldDeletedBytes = 1025;
    }
    if (fault === "unbounded") {
      state.sample.capacity.allocatedWorkspaceBytes =
        BACKUP_V2_LIMITS.workspaceBytes + 1;
    }
    if (fault === "unknown") state.sample.capacity.freeInodes = NaN;
    equal((await supervisor.poll()).action, "cancel");
    equal(state.messages.length, 0);
  }
  const { state, supervisor } = fixture();
  state.sample.capacity.allocatedWorkspaceBytes =
    BACKUP_V2_LIMITS.workspaceBytes;
  state.sample.capacity.workspaceHeldDeletedBytes =
    BACKUP_V2_LIMITS.workspaceBytes;
  state.sample.capacity.availableBytes =
    BACKUP_V2_LIMITS.protectedReserveBytes + 4096;
  equal((await supervisor.poll()).action, "renew"); // Held blocks are already in allocated workspace, never credited as free.
});

Deno.test("supervisor aborts a stuck observer and cannot create overlapping renewers", async () => {
  const f = fixture();
  let aborted = false;
  f.capabilities.observe = (signal) =>
    new Promise((resolve) => {
      signal.addEventListener("abort", () => {
        aborted = true;
        resolve(f.state.sample);
      }, { once: true });
    });
  equal((await f.supervisor.poll()).action, "cancel");
  assert(aborted);
  equal(f.state.messages, []);
  const other = fixture();
  other.capabilities.observe = (signal) =>
    new Promise((resolve) =>
      signal.addEventListener("abort", () => resolve(other.state.sample), {
        once: true,
      })
    );
  const pending = other.supervisor.poll();
  equal(await other.supervisor.poll(), {
    action: "cancel",
    reason: "OVERLAPPING_OBSERVATION",
  });
  await pending;
  equal(other.state.messages, []);
});

Deno.test("supervisor notification failure and explicit cancellation stop all renewals", async () => {
  const f = fixture();
  f.capabilities.notifier.extend = () => {
    throw new Error("native send failed");
  };
  equal((await f.supervisor.poll()).action, "cancel");
  const other = fixture();
  other.supervisor.cancel("OPERATOR_CANCELLED");
  equal(await other.supervisor.poll(), {
    action: "cancel",
    reason: "OPERATOR_CANCELLED",
  });
  equal(other.state.messages, []);
});

function tree(now = 0): BackupV2TreeObservation {
  return {
    identity: { ...identity },
    observedMonotonicMs: now,
    mainPid: 0,
    controlPid: 0,
    cgroupPopulated: false,
    descendants: 0,
    escapedProcesses: 0,
    namespaceReferences: 0,
    openPipelineHandles: 0,
    pendingOperations: 0,
    sourceLockFree: true,
  };
}
Deno.test("supervisor external cancellation reconciles before stop and proves the entire tree", async () => {
  let now = 0, stops = 0;
  const calls: string[] = [];
  const result = await settleBackupV2Cancellation(identity, {
    now: () => now,
    observe: () => {
      calls.push("observe");
      return Promise.resolve(
        stops ? tree(now) : {
          ...tree(now),
          mainPid: identity.mainPid,
          cgroupPopulated: true,
          descendants: 2,
        },
      );
    },
    stop: (expected) => {
      equal(expected, identity);
      calls.push("stop");
      stops++;
      now++;
      return Promise.resolve();
    },
  });
  equal(result.state, "SETTLED");
  equal(calls, ["observe", "stop", "observe"]);
});

Deno.test("supervisor cancellation blocks on wrong identity without stopping another unit", async () => {
  let stopped = false;
  const result = await settleBackupV2Cancellation(identity, {
    now: () => 0,
    observe: () =>
      Promise.resolve({
        ...tree(),
        identity: { ...identity, invocationId: "b".repeat(32) },
      }),
    stop: () => {
      stopped = true;
      return Promise.resolve();
    },
  });
  equal(result.state, "CANCELLATION_BLOCKED");
  assert(!stopped);
});

Deno.test("supervisor cancellation never equates MainPID zero with full settlement", async () => {
  for (
    const fault of [
      { descendants: 1 },
      { escapedProcesses: 1 },
      { namespaceReferences: 1 },
      { openPipelineHandles: 1 },
      { pendingOperations: 1 },
      { sourceLockFree: false },
      { cgroupPopulated: null },
    ]
  ) {
    equal(
      (await settleBackupV2Cancellation(identity, {
        now: () => 0,
        observe: () => Promise.resolve({ ...tree(), ...fault }),
        stop: () => Promise.resolve(),
      })).state,
      "CANCELLATION_BLOCKED",
    );
  }
});

Deno.test("supervisor bounded stop failure preserves blocked custody", async () => {
  const result = await settleBackupV2Cancellation(identity, {
    now: () => 0,
    observe: () =>
      Promise.resolve({
        ...tree(),
        mainPid: identity.mainPid,
        cgroupPopulated: true,
      }),
    stop: (_identity, signal) =>
      new Promise((resolve) =>
        signal.addEventListener("abort", () => resolve(), { once: true })
      ),
  }, 5);
  equal(result.state, "CANCELLATION_BLOCKED");
});

/** Operator-only fixture, deliberately not a Deno.test: run inside an approved
 * notify unit via stdin import with exact FFI/env/run permissions. Pure tests
 * never open the library, socket or a child. This proves sender plumbing only. */
export async function runBackupV2DenoLeaseProof(): Promise<never> {
  const guard = setTimeout(() => Deno.exit(124), 20_000);
  const notifier = createBackupV2Notifier();
  const child = new Deno.Command("/usr/bin/python3", {
    args: [
      "-I",
      "-u",
      "-c",
      "import json,time; [(print(json.dumps({'sequence':i}),flush=True),time.sleep(1)) for i in range(7)]; time.sleep(30)",
    ],
    clearEnv: true,
    env: backupV2ChildEnvironment({}),
    stdin: "null",
    stdout: "piped",
    stderr: "null",
  }).spawn();
  const reader = child.stdout.getReader(), decoder = new TextDecoder();
  let buffered = "";
  const next = async () => {
    while (!buffered.includes("\n")) {
      const chunk = await reader.read();
      if (chunk.done || chunk.value.length > 1024) {
        throw new Error("Fixture pipe failed");
      }
      buffered += decoder.decode(chunk.value, { stream: true });
      if (buffered.length > 1024) throw new Error("Fixture record too large");
    }
    const at = buffered.indexOf("\n"), line = buffered.slice(0, at);
    buffered = buffered.slice(at + 1);
    return JSON.parse(line);
  };
  const started = performance.now();
  try {
    notifier.ready();
    for (let sequence = 0; sequence < 7; sequence++) {
      const record = await next();
      if (JSON.stringify(record) !== JSON.stringify({ sequence })) {
        throw new Error("Fixture sequence failed");
      }
      notifier.extend(4_000_000);
      console.log(
        JSON.stringify({
          event: "checked_progress",
          sequence,
          elapsed_seconds: (performance.now() - started) / 1000,
          pid: Deno.pid,
        }),
      );
    }
    console.log(
      JSON.stringify({
        event: "progress_stopped",
        renewal: false,
        elapsed_seconds: (performance.now() - started) / 1000,
      }),
    );
    await next();
    throw new Error("Deno lease was not enforced");
  } finally {
    clearTimeout(guard);
    reader.releaseLock();
    notifier.close();
  }
}
