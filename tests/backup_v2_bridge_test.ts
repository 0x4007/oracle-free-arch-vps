import {
  type BackupV2BridgeBinding,
  type BackupV2BridgeClosure,
  BackupV2BridgeKeeper,
  type BackupV2BridgeObservation,
  backupV2BridgeUnitProperties,
} from "../scripts/backup-v2-bridge.ts";
import type { TunnelHandle } from "../scripts/backblaze-file-backup.ts";
import type { BackupV2SupervisorIdentity } from "../scripts/backup-v2-supervisor.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function equal(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
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
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => resolve = r);
  return { promise, resolve };
}
const uuid = "11111111-1111-1111-1111-111111111111";
const keeper: BackupV2SupervisorIdentity = {
  unitName: "bridge-fixture.service",
  invocationId: "a".repeat(32),
  mainPid: 100,
  mainStartTicks: "123",
  cgroup: "/fixture/bridge-fixture.service",
};
const binding: BackupV2BridgeBinding = {
  jobId: `job-${uuid}`,
  captureId: `generation-${uuid}`,
  requestSha256: "b".repeat(64),
  gateId: "22222222-2222-2222-2222-222222222222",
  source: {
    unitName: "source-fixture.service",
    invocationId: "c".repeat(32),
    mainPid: 200,
    mainStartTicks: "456",
    cgroup: "/fixture/source-fixture.service",
    sourceBootId: "33333333-3333-3333-3333-333333333333",
  },
  publicHome: `/home/codex/.local/share/arch-vps-verifier/generation-${uuid}`,
  remoteSocket: "/run/user/1002/gnupg/d.custom/S.gpg-agent",
  defaultSocket: "/run/user/1002/gnupg/S.gpg-agent",
};
const options = {
  notificationGraceMs: 100,
  progressGraceMs: 1000,
  retryGraceMs: 5000,
  operationTimeoutMs: 20,
  maximumObservationAgeMs: 100,
};
function fixture() {
  let now = 0;
  let active: TunnelHandle | null = null;
  const events: (string | number)[] = [];
  const handle = { close: () => Promise.resolve() };
  const sample: BackupV2BridgeObservation = {
    keeper: structuredClone(keeper),
    binding: structuredClone(binding),
    observedMonotonicMs: 0,
    gate: "OWNED",
    progress: {
      phase: "VERIFYING",
      sourceBytes: 0,
      compressionInputBytes: 0,
      verifiedChunks: 0,
      decryptedBytes: 0,
      inventoryMembers: 0,
    },
  };
  const proof: BackupV2BridgeClosure = {
    keeper: structuredClone(keeper),
    binding: structuredClone(binding),
    observedMonotonicMs: 0,
    sshProcesses: 0,
    openStdinHandles: 0,
    remoteSocketPresent: false,
    defaultSocketUnchanged: true,
  };
  const caps = {
    now: () => now,
    notifier: {
      ready: () => {
        events.push("ready");
      },
      extend: (usec: number) => {
        events.push(usec);
      },
      stopping: () => {
        events.push("stopping");
      },
      close: () => {
        events.push("notifier-close");
      },
    },
    tunnel: {
      current: () => active,
      open: (socket: string) => {
        events.push(socket);
        active = handle;
        return Promise.resolve(handle);
      },
      close: () => {
        events.push("stdin-eof-and-exit");
        active = null;
        return Promise.resolve();
      },
    },
    observe: (_signal: AbortSignal) => Promise.resolve(structuredClone(sample)),
    observeClosure: (_signal: AbortSignal) =>
      Promise.resolve(structuredClone(proof)),
  };
  return {
    sample,
    proof,
    caps,
    events,
    handle,
    setActive: (value: TunnelHandle | null) => {
      active = value;
    },
    advance: (value: number) => {
      now = value;
      sample.observedMonotonicMs = value;
      proof.observedMonotonicMs = value;
    },
    make: () => new BackupV2BridgeKeeper(keeper, binding, options, caps),
  };
}

Deno.test("bridge properties retain finite main-only notify custody and Pi caps", () => {
  const properties = backupV2BridgeUnitProperties(1000);
  equal(properties.Type, "notify");
  equal(properties.NotifyAccess, "main");
  equal(properties.RuntimeMaxSec, "1000ms");
  equal(properties.RemainAfterExit, "yes");
  equal(properties.MemoryHigh, "320M");
  equal(properties.MemoryMax, "380M");
  equal(properties.LimitCORE, "0");
  throws(() => backupV2BridgeUnitProperties(Infinity));
});

Deno.test("bridge refuses wrong request, generation, boot, default and foreign socket boundaries", () => {
  for (
    const mutate of [
      (b: BackupV2BridgeBinding) => b.captureId = `capture-${uuid}`,
      (b: BackupV2BridgeBinding) => b.gateId = "invalid",
      (b: BackupV2BridgeBinding) => b.requestSha256 = "invalid",
      (b: BackupV2BridgeBinding) => b.source.sourceBootId = "invalid",
      (b: BackupV2BridgeBinding) => b.remoteSocket = b.defaultSocket,
      (b: BackupV2BridgeBinding) => b.remoteSocket = "/tmp/S.gpg-agent",
      (b: BackupV2BridgeBinding) =>
        b.defaultSocket = "/run/user/999/gnupg/S.gpg-agent",
      (b: BackupV2BridgeBinding) =>
        b.defaultSocket = "/run/user/1002/../S.gpg-agent",
      (b: BackupV2BridgeBinding) => b.publicHome += "/../foreign",
    ]
  ) {
    const changed = structuredClone(binding);
    mutate(changed);
    throws(() =>
      new BackupV2BridgeKeeper(keeper, changed, options, fixture().caps)
    );
  }
});

Deno.test("bridge opens exact custom socket, reports bounded snapshots, closes by owned seam", async () => {
  const f = fixture(), bridge = f.make();
  const started = await bridge.start();
  equal(started.state, "ACTIVE");
  equal(f.events[0], binding.remoteSocket);
  assert(f.events.includes("ready"));
  started.binding.source.mainPid++;
  equal(bridge.status().binding.source.mainPid, 200);
  assert(JSON.stringify(bridge.status()).length < 4096);
  equal((await bridge.close()).state, "CLOSED");
  assert(f.events.includes("stdin-eof-and-exit"));
});

Deno.test("bridge snapshots retain only the bounded custody fields", () => {
  const f = fixture();
  const oversized = { ...binding, unexpected: "x".repeat(64 * 1024) };
  const bridge = new BackupV2BridgeKeeper(keeper, oversized, options, f.caps);
  assert(JSON.stringify(bridge.status()).length < 4096);
});

Deno.test("bridge heartbeat cannot renew useful work and expired work cannot revive", async () => {
  const f = fixture(), bridge = f.make();
  await bridge.start();
  f.advance(50);
  f.sample.progress.decryptedBytes = 1;
  equal((await bridge.poll()).lease.usefulProgressExpiresAtMs, 1050);
  f.advance(500);
  equal((await bridge.poll()).lease.usefulProgressExpiresAtMs, 1050);
  f.advance(1050);
  f.sample.progress.decryptedBytes++;
  const ended = await bridge.poll();
  equal(ended.state, "CLOSED");
  equal(ended.reason, "LEASE_EXPIRED");
});

Deno.test("bridge's initial nonzero counters are a baseline, not fresh useful work", async () => {
  const f = fixture(), bridge = f.make();
  f.sample.progress.decryptedBytes = 999;
  await bridge.start();
  f.advance(100);
  equal((await bridge.poll()).reason, "LEASE_EXPIRED");
});

Deno.test("bridge fixed retry episode cannot reset through repeated retries", async () => {
  const f = fixture(), bridge = f.make();
  const retry = {
    sealedObjectIdentity: "sealed-sha256",
    retainedBytes: 64,
    retryableTransport: true as const,
  };
  await bridge.start();
  throws(() => bridge.beginRetryEpisode(retry));
  f.advance(50);
  f.sample.progress.decryptedBytes = 1;
  await bridge.poll();
  equal(bridge.beginRetryEpisode(retry).lease.retryEpisode?.expiresAtMs, 5050);
  f.advance(500);
  await bridge.poll();
  equal(bridge.beginRetryEpisode(retry).lease.retryEpisode?.expiresAtMs, 5050);
  f.advance(5050);
  equal((await bridge.poll()).reason, "LEASE_EXPIRED");
});

Deno.test("bridge cancels replacement source, source boot, gate or keeper custody", async () => {
  for (
    const mutate of [
      (s: BackupV2BridgeObservation) =>
        s.binding.source.invocationId = "d".repeat(32),
      (s: BackupV2BridgeObservation) => s.binding.source.sourceBootId = uuid,
      (s: BackupV2BridgeObservation) => s.binding.gateId = uuid,
      (s: BackupV2BridgeObservation) => s.keeper.mainStartTicks = "999",
    ]
  ) {
    const f = fixture(), bridge = f.make();
    await bridge.start();
    f.advance(50);
    mutate(f.sample);
    equal((await bridge.poll()).reason, "IDENTITY_CHANGED");
    assert(f.events.includes("stdin-eof-and-exit"));
  }
});

Deno.test("bridge rejects regressed counters, wrong-phase work and stale collections", async () => {
  for (const fault of ["regression", "phase", "stale", "future"] as const) {
    const f = fixture(), bridge = f.make();
    f.sample.progress.decryptedBytes = 1;
    await bridge.start();
    f.advance(50);
    if (fault === "regression") f.sample.progress.decryptedBytes = 0;
    if (fault === "phase") f.sample.progress.sourceBytes = 1;
    if (fault === "stale") f.sample.observedMonotonicMs = -1;
    if (fault === "future") f.sample.observedMonotonicMs = 51;
    equal((await bridge.poll()).state, "CLOSED");
  }
});

Deno.test("bridge terminal or cancellation observation closes without releasing the source gate", async () => {
  for (const gate of ["TERMINAL", "CANCELLED"] as const) {
    const f = fixture(), bridge = f.make();
    await bridge.start();
    f.advance(50);
    f.sample.gate = gate;
    const status = await bridge.poll();
    equal(status.state, "CLOSED");
    equal(status.reason, gate);
    equal(status.binding.gateId, binding.gateId);
  }
});

Deno.test("bridge unknown or contradictory closure retains custody until exact fresh proof", async () => {
  for (
    const mutate of [
      (p: BackupV2BridgeClosure) => p.sshProcesses = null,
      (p: BackupV2BridgeClosure) => p.openStdinHandles = 1,
      (p: BackupV2BridgeClosure) => p.remoteSocketPresent = true,
      (p: BackupV2BridgeClosure) => p.defaultSocketUnchanged = null,
      (p: BackupV2BridgeClosure) => p.keeper.invocationId = "d".repeat(32),
    ]
  ) {
    const f = fixture(), bridge = f.make();
    await bridge.start();
    mutate(f.proof);
    equal((await bridge.close()).state, "CANCELLATION_BLOCKED");
    Object.assign(f.proof, {
      keeper: structuredClone(keeper),
      sshProcesses: 0,
      openStdinHandles: 0,
      remoteSocketPresent: false,
      defaultSocketUnchanged: true,
    });
    equal((await bridge.close()).state, "CLOSED");
  }
});

Deno.test("bridge never adopts or closes a pre-existing foreign transport", async () => {
  const f = fixture(), bridge = f.make();
  f.setActive(f.handle);
  equal((await bridge.start()).state, "CANCELLATION_BLOCKED");
  assert(!f.events.includes("stdin-eof-and-exit"));
});

Deno.test("bridge closure still runs after notifier failure", async () => {
  const f = fixture(), bridge = f.make();
  f.caps.notifier.extend = () => {
    throw new Error("injected notify failure");
  };
  f.caps.notifier.stopping = () => {
    throw new Error("injected stop failure");
  };
  equal((await bridge.start()).state, "CLOSED");
  assert(f.events.includes("stdin-eof-and-exit"));
});

Deno.test("bridge deadline keeps late transport pending and closes its late stdin", async () => {
  const f = fixture(), bridge = f.make(), opening = deferred<TunnelHandle>();
  f.caps.tunnel.open = async () => {
    const handle = await opening.promise;
    f.setActive(handle);
    return handle;
  };
  const timedOut = await bridge.start();
  equal(timedOut.state, "CANCELLATION_BLOCKED");
  equal(timedOut.pendingOperations, 1);
  opening.resolve(f.handle);
  await opening.promise;
  await Promise.resolve();
  equal((await bridge.close()).state, "CLOSED");
  equal(f.caps.tunnel.current(), null);
});

Deno.test("bridge overlapping observations cancel and preserve unresolved collector custody", async () => {
  const f = fixture(),
    bridge = f.make(),
    reading = deferred<BackupV2BridgeObservation>();
  const entered = deferred<void>();
  await bridge.start();
  f.caps.observe = () => {
    entered.resolve();
    return reading.promise;
  };
  const first = bridge.poll();
  await entered.promise;
  const second = bridge.poll();
  const results = await Promise.all([first, second]);
  equal(results[1].reason, "OVERLAPPING_OPERATION");
  equal(results[1].state, "CANCELLATION_BLOCKED");
  reading.resolve(f.sample);
  await reading.promise;
  equal((await bridge.close()).state, "CLOSED");
});

Deno.test("bridge cannot report closure when EOF/exit seam rejects", async () => {
  const f = fixture(), bridge = f.make();
  await bridge.start();
  f.caps.tunnel.close = () =>
    Promise.reject(new Error("injected exit uncertainty"));
  equal((await bridge.close()).state, "CANCELLATION_BLOCKED");
});
