import {
  backupV2ChildEnvironment,
  backupV2FailureEvidence,
  type BackupV2Notifier,
  BackupV2Supervisor,
  type BackupV2SupervisorFailure,
  type BackupV2SupervisorIdentity,
  type BackupV2SupervisorObservation,
  backupV2SupervisorUnitProperties,
  type BackupV2TreeObservation,
  classifyBackupV2Failure,
  createBackupV2Notifier,
  encodeBackupV2Notification,
  evaluateBackupV2Lease,
  pollBackupV2Settlement,
  settleBackupV2Cancellation,
} from "../scripts/backup-v2-supervisor.ts";
import {
  BACKUP_V2_LIMITS,
  BACKUP_V2_PRODUCTION_WRITER_MARGIN_BYTES,
} from "../scripts/backup-v2-profile.ts";
import {
  type BackupV2TransferEpisode,
  backupV2TransferWindowMs,
} from "../scripts/backup-v2-contract.ts";
import { BackupV2KernelEvidenceError } from "../scripts/backup-v2-kernel.ts";

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

Deno.test("READY precedes persisted reload lease and persistence time is subtracted before notify", async () => {
  const { state, options, capabilities } = fixture();
  const supervisor = new BackupV2Supervisor(identity, options, {
    ...capabilities,
    persistRuntimeLease: (deadline, signal) => {
      equal(state.messages, ["ready"]);
      signal.throwIfAborted();
      equal(deadline, 100);
      state.messages.push("persisted");
      state.advance(30);
      return Promise.resolve();
    },
  });
  const decision = await supervisor.poll();
  equal(state.messages, ["ready", "persisted", 70_000]);
  assert(decision.action === "renew" && decision.extendUsec === 70_000);
});

Deno.test("failed or expired persistence cannot send an extension or acquire a fresh grace", async () => {
  for (const fails of [false, true]) {
    const { state, options, capabilities } = fixture();
    const supervisor = new BackupV2Supervisor(identity, options, {
      ...capabilities,
      persistRuntimeLease: () => {
        state.advance(101);
        if (fails) throw new Error("rename failed");
        return Promise.resolve();
      },
    });
    equal((await supervisor.poll()).action, "cancel");
    equal(state.messages, ["ready"]);
    equal((await supervisor.poll()).action, "cancel");
    equal(state.messages, ["ready"]);
  }
});

Deno.test("supervisor preserves sanitized capacity guard causes without changing cancellation decisions", async () => {
  for (
    const guard of [
      "WORKSPACE_LIMIT",
      "FREE_SPACE",
      "FREE_INODES",
      "WORKSPACE_DELETED_ACCOUNTING",
      "SOURCE_DELETED_LIMIT",
    ]
  ) {
    const f = fixture(), failures: BackupV2SupervisorFailure[] = [];
    const capacity = f.state.sample.capacity;
    if (guard === "WORKSPACE_LIMIT") {
      capacity.allocatedWorkspaceBytes = BACKUP_V2_LIMITS.workspaceBytes + 1;
    }
    if (guard === "FREE_SPACE") capacity.availableBytes = 0;
    if (guard === "FREE_INODES") capacity.freeInodes = 0;
    if (guard === "WORKSPACE_DELETED_ACCOUNTING") {
      capacity.workspaceHeldDeletedBytes = 1;
    }
    if (guard === "SOURCE_DELETED_LIMIT") {
      capacity.sourceHeldDeletedBytes = 1025;
    }
    const supervisor = new BackupV2Supervisor(identity, f.options, {
      ...f.capabilities,
      onFailure: (failure) => failures.push(failure),
    });
    equal(await supervisor.poll(), {
      action: "cancel",
      reason: "OBSERVATION_OR_NOTIFICATION_UNPROVED",
    });
    equal(failures, [{
      stage: "capacity",
      errorClass: "BackupV2CapacityGuardError",
      kind: guard,
    }]);
    equal(f.state.messages, []);
  }
});

Deno.test("supervisor observer diagnostics retain only whitelisted kernel kind and ignore diagnostic callback failures", async () => {
  const f = fixture(), failures: BackupV2SupervisorFailure[] = [];
  const supervisor = new BackupV2Supervisor(identity, f.options, {
    ...f.capabilities,
    observe: () =>
      Promise.reject(new BackupV2KernelEvidenceError("UNREADABLE")),
    onFailure: (failure) => {
      failures.push(failure);
      throw Error("private callback token");
    },
  });
  equal(await supervisor.poll(), {
    action: "cancel",
    reason: "OBSERVATION_OR_NOTIFICATION_UNPROVED",
  });
  equal(failures, [{
    stage: "observation",
    errorClass: "BackupV2KernelEvidenceError",
    kind: "UNREADABLE",
  }]);
});

Deno.test("failure evidence drops exception text, private fields and unclassified reasons while preserving last observed counters", () => {
  const secret = "https://private.example/token?secret=PRIVATE_VALUE";
  const sample = observation(0);
  sample.progress.sourceBytes = 123;
  Object.assign(sample.capacity, { headers: secret });
  const error = Object.assign(new Error(secret), {
    stack: secret,
    headers: secret,
    kind: secret,
  });
  const evidence = backupV2FailureEvidence({
    identity: Object.assign({ ...identity }, { token: secret }),
    reason: error,
    supervisorFailure: null,
    observation: sample,
    observedAtUtc: "2026-10-18T22:10:00.000Z",
    observedMonotonicMs: 10,
  });
  assert(!JSON.stringify(evidence).includes(secret));
  equal(evidence.identity, identity);
  equal(evidence.reason, "UNCLASSIFIED_FAILURE");
  equal(evidence.errorClass, "Error");
  equal(evidence.kind, null);
  equal(evidence.capacityAgeMs, 10);
  equal(evidence.progressAgeMs, 10);
  equal(evidence.observation?.progress.sourceBytes, 123);
  equal(
    evidence.observation?.capacity.availableBytes,
    sample.capacity.availableBytes,
  );
  assert(new TextEncoder().encode(JSON.stringify(evidence)).length < 8192);
  equal(
    backupV2FailureEvidence({
      identity,
      reason: secret,
      supervisorFailure: null,
      observation: null,
      observedAtUtc: evidence.observedAtUtc,
      observedMonotonicMs: 10,
    }).observation,
    null,
  );
  class PrivateProviderError extends Error {
    kind = secret;
  }
  equal(classifyBackupV2Failure(new PrivateProviderError(secret)), {
    errorClass: "UNKNOWN",
    kind: null,
  });
});

Deno.test("failure evidence classifies exact builtin filesystem errors without retaining their messages", () => {
  const secret = "PRIVATE_PATH_OR_TOKEN";
  for (
    const error of [
      new Deno.errors.NotCapable(secret),
      new Deno.errors.NotFound(secret),
      new Deno.errors.PermissionDenied(secret),
      new Deno.errors.BadResource(secret),
    ]
  ) {
    const classified = classifyBackupV2Failure(error);
    equal(classified.errorClass, error.constructor.name);
    assert(!JSON.stringify(classified).includes(secret));
    equal(classified.kind, null);
  }
});

Deno.test("supervisor fixed initialization window is independent of short notification renewals", async () => {
  const f = fixture();
  const supervisor = new BackupV2Supervisor(identity, {
    ...f.options,
    notificationGraceMs: 30_000,
    startupGraceMs: 300_000,
    progressGraceMs: 300_000,
  }, f.capabilities);
  equal((await supervisor.poll()).action, "renew");
  f.state.advance(240_000);
  equal((await supervisor.poll()).action, "renew");
  f.state.advance(299_999);
  const last = await supervisor.poll();
  assert(last.action === "renew");
  equal(last.absoluteDeadlineMs, 300_000);
  equal(last.extendUsec, 1000);
  f.state.advance(300_000);
  equal((await supervisor.poll()).action, "cancel");
  throws(() =>
    new BackupV2Supervisor(
      identity,
      { ...f.options, startupGraceMs: 99 },
      f.capabilities,
    )
  );
});
Deno.test("supervisor adopts the original durable retry window without sliding it on repeat", async () => {
  const f = fixture();
  await f.supervisor.poll();
  f.state.advance(10);
  f.state.sample.progress.sourceBytes = 10;
  await f.supervisor.poll();
  const original = {
    sealedObjectIdentity: "sealed-object",
    retainedBytes: 64,
    retryableTransport: true as const,
    startedAtMs: 10,
    expiresAtMs: 10 + BACKUP_V2_LIMITS.blockedTransportMs,
  };
  equal(f.supervisor.beginRetryEpisode(original).retryEpisode, {
    startedAtMs: original.startedAtMs,
    expiresAtMs: original.expiresAtMs,
  });
  f.state.advance(20);
  await f.supervisor.poll();
  equal(f.supervisor.beginRetryEpisode(original).retryEpisode, {
    startedAtMs: original.startedAtMs,
    expiresAtMs: original.expiresAtMs,
  });
  throws(() =>
    f.supervisor.beginRetryEpisode({
      ...original,
      startedAtMs: 20,
      expiresAtMs: original.expiresAtMs + 10,
    })
  );
});

Deno.test("sealed transfer grants bounded pending wait without fake work or retry-based deadline refresh", async () => {
  const f = fixture();
  await f.supervisor.poll();
  const transfer: BackupV2TransferEpisode = {
    kind: "SEALED_TRANSFER",
    operationId: "sealed/PUT",
    phase: "PUT",
    sealedObjectIdentity: "sealed",
    retainedBytes: 64,
    startedAtMs: 0,
    expiresAtMs: backupV2TransferWindowMs("PUT"),
  };
  f.supervisor.beginTransferEpisode(transfer);
  f.state.advance(5000);
  const pending = await f.supervisor.poll();
  assert(pending.action === "renew");
  equal(pending.absoluteDeadlineMs, transfer.expiresAtMs);
  assert(pending.extendUsec <= 100_000);
  equal(f.state.sample.progress.sourceBytes, 0);
  throws(() =>
    f.supervisor.beginTransferEpisode({
      ...transfer,
      expiresAtMs: transfer.expiresAtMs + 1,
    })
  );
  f.state.advance(transfer.expiresAtMs);
  equal((await f.supervisor.poll()).action, "cancel");
});
Deno.test("real durable PUT-to-readback transition owns a separate fixed window and completion releases it", async () => {
  const f = fixture();
  await f.supervisor.poll();
  const put: BackupV2TransferEpisode = {
    kind: "SEALED_TRANSFER",
    operationId: "sealed/PUT",
    phase: "PUT",
    sealedObjectIdentity: "sealed",
    retainedBytes: 64,
    startedAtMs: 0,
    expiresAtMs: backupV2TransferWindowMs("PUT"),
  };
  f.supervisor.beginTransferEpisode(put);
  f.state.advance(20);
  await f.supervisor.poll();
  const read: BackupV2TransferEpisode = {
    ...put,
    operationId: "sealed/READBACK",
    phase: "READBACK",
    startedAtMs: 20,
    expiresAtMs: 20 + backupV2TransferWindowMs("READBACK"),
  };
  f.supervisor.beginTransferEpisode(read);
  equal(f.supervisor.window().transferEpisode, read);
  f.state.advance(30);
  f.state.sample.progress.verifiedChunks = 1;
  await f.supervisor.poll();
  f.supervisor.completeTransferEpisode(read.operationId);
  equal(f.supervisor.window().transferEpisode, null);
  equal((await f.supervisor.poll()).action, "renew");
});
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
      state.sample.capacity.availableBytes = BACKUP_V2_LIMITS.workspaceBytes;
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
  state.sample.capacity.availableBytes = 4096;
  equal((await supervisor.poll()).action, "renew"); // Held blocks are already in allocated workspace, never credited as free.
});

Deno.test("production capacity admits exactly 1.25 GiB and preserves allocated workspace credit", async () => {
  for (
    const allocated of [0, 128 * 1024 ** 2, BACKUP_V2_LIMITS.workspaceBytes]
  ) {
    for (const short of [false, true]) {
      const f = fixture();
      f.state.sample.capacity.allocatedWorkspaceBytes = allocated;
      f.state.sample.capacity.availableBytes = 1.25 * 1024 ** 3 - allocated -
        Number(short);
      const supervisor = new BackupV2Supervisor(identity, {
        ...f.options,
        productionWriterMarginBytes: BACKUP_V2_PRODUCTION_WRITER_MARGIN_BYTES,
      }, f.capabilities);
      equal((await supervisor.poll()).action, short ? "cancel" : "renew");
    }
  }
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

Deno.test("cancellation retries transient unknown after exactly one stop", async () => {
  let now = 0, reads = 0, stops = 0;
  const result = await settleBackupV2Cancellation(identity, {
    now: () => now,
    observe: () => {
      reads++;
      return Promise.resolve(
        reads === 1
          ? { ...tree(now), mainPid: identity.mainPid, cgroupPopulated: true }
          : reads === 2
          ? null
          : tree(now),
      );
    },
    stop: () => {
      stops++;
      return Promise.resolve();
    },
    wait: (ms) => {
      now += ms;
      return Promise.resolve();
    },
  });
  equal(result.state, "SETTLED");
  equal(stops, 1);
  equal(reads, 3);
});

Deno.test("cancellation never retries a changed identity after stop", async () => {
  let stops = 0, reads = 0;
  const result = await settleBackupV2Cancellation(identity, {
    now: () => 0,
    observe: () => {
      reads++;
      return Promise.resolve(
        stops
          ? { ...tree(), identity: { ...identity, mainStartTicks: "999" } }
          : { ...tree(), mainPid: identity.mainPid },
      );
    },
    stop: () => {
      stops++;
      return Promise.resolve();
    },
  });
  equal(result.state, "CANCELLATION_BLOCKED");
  equal(stops, 1);
  equal(reads, 2);
});

Deno.test("settlement polling has one finite budget and never converts unknown to success", async () => {
  let now = 0, reads = 0;
  const proved = await pollBackupV2Settlement(
    () => {
      reads++;
      return Promise.resolve(false);
    },
    300,
    () => now,
    (ms) => {
      now += ms;
      return Promise.resolve();
    },
  );
  equal(proved, false);
  equal(now, 300);
  equal(reads, 2);
  let aborted = false;
  try {
    await pollBackupV2Settlement((signal) =>
      new Promise((resolve) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          resolve(false);
        }, { once: true });
      }), 5);
    throw new Error("Expected observation deadline");
  } catch {
    assert(aborted);
  }
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
