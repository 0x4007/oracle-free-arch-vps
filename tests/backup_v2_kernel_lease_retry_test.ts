import {
  backupV2KernelDiagnostic,
  BackupV2KernelEvidenceError,
  backupV2KernelSettlement,
  createBackupV2KernelCommand,
} from "../scripts/backup-v2-kernel.ts";
import {
  type BackupV2LeaseObservationContext,
  createBackupV2RuntimeLease,
  observeBackupV2RuntimeLease,
} from "../scripts/backup-v2-runtime-lease.ts";
import {
  backupV2FailureEvidence,
  BackupV2Supervisor,
} from "../scripts/backup-v2-supervisor.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
const identity = {
  unitName:
    "arch-vps-b2-v2-worker-00000000-0000-4000-8000-000000000001-00000000-0000-4000-8000-000000000002.service",
  invocationId: "a".repeat(32),
  mainPid: 1234,
  mainStartTicks: "5678",
  cgroup:
    "/weekly.slice/weekly-backup.slice/arch-vps-b2-v2-worker-00000000-0000-4000-8000-000000000001-00000000-0000-4000-8000-000000000002.service",
};
const success: Deno.CommandStatus = { code: 0, success: true, signal: null };
function fixture(fault = "deadline") {
  let now = 0, showCalls = 0, totalCalls = 0;
  const children: { release(): void }[] = [];
  let latestFault = false;
  let latestRelease = () => {};
  let latestOverflow = () => {};
  const encoder = new TextEncoder();
  const run = createBackupV2KernelCommand({
    now: () => now,
    spawn(command, args) {
      totalCalls++;
      const show = command.endsWith("systemctl");
      if (show) showCalls++;
      const delayed = fault !== "none" && show &&
        (showCalls === 1 || fault === "second" || fault === "pending");
      latestFault = delayed && !["stdout", "stderr"].includes(fault);
      const fields = new Array(20).fill("0");
      fields[0] = "S";
      fields[1] = "1";
      fields[19] = identity.mainStartTicks;
      const text = show
        ? `MainPID=1234\nInvocationID=${identity.invocationId}\nControlGroup=${identity.cgroup}\nActiveState=active\nSubState=running\nActiveEnterTimestampMonotonic=400000000\n`
        : args.at(-1)?.endsWith("/stat")
        ? `1234 (deno) ${fields.join(" ")}\n`
        : fault === "identity"
        ? "0::/different\n"
        : `0::${identity.cgroup}\n`;
      const terminal = Promise.withResolvers<Deno.CommandStatus>();
      let close: ReadableStreamDefaultController<Uint8Array>;
      const stdout = new ReadableStream<Uint8Array>({
        start(controller) {
          close = controller;
          controller.enqueue(encoder.encode(
            delayed && fault === "stdout"
              ? "x".repeat(2 * 1024 ** 2 + 1)
              : text,
          ));
          if (!latestFault) {
            controller.close();
          }
        },
      });
      const stderr = new ReadableStream<Uint8Array>({
        start(controller) {
          if (delayed && fault === "stderr") {
            controller.enqueue(encoder.encode("x".repeat(8193)));
          }
          controller.close();
        },
      });
      const release = () => {
        try {
          close.close();
        } catch { /* Reader already cancelled. */ }
        terminal.resolve(success);
      };
      children.push({ release });
      latestRelease = release;
      latestOverflow = () => {
        close.enqueue(encoder.encode("x".repeat(2 * 1024 ** 2 + 1)));
      };
      if (!latestFault) terminal.resolve(success);
      return {
        pid: 10000 + totalCalls,
        stdout,
        stderr,
        status: terminal.promise,
      };
    },
    setTimer(callback, milliseconds) {
      assert(milliseconds === 2000);
      const delayed = latestFault, release = latestRelease;
      const overflow = latestOverflow;
      if (delayed && fault !== "pending") {
        queueMicrotask(() => {
          now += 2000;
          callback();
          if (fault === "late-stdout") overflow();
          if (fault !== "unsettled") queueMicrotask(release);
        });
      }
      return setTimeout(() => {}, 0);
    },
    clearTimer: clearTimeout,
  });
  const context: BackupV2LeaseObservationContext = {
    phase: "BEFORE_WRITE",
    signal: new AbortController().signal,
    budget: { deadlineMs: 5000, retried: false },
  };
  return {
    run,
    context,
    now: () => now,
    counts: () => ({ showCalls, totalCalls }),
    advance: (value: number) => {
      now = value;
    },
    release: () => children.forEach((child) => child.release()),
  };
}
async function rejection(work: () => Promise<unknown>) {
  try {
    await work();
  } catch (error) {
    return error;
  }
  throw new Error("Expected failure");
}

Deno.test("metadata deadline retries one whole fresh snapshot only after private child and reader settlement", async () => {
  const f = fixture();
  const sample = await observeBackupV2RuntimeLease(
    identity,
    f.context,
    f.run,
    f.now,
  );
  assert(sample.running && sample.identity === identity);
  assert(f.counts().showCalls === 2 && f.counts().totalCalls === 6);
  assert(f.context.budget.deadlineMs === 5000 && f.context.budget.retried);
  f.release();
});

Deno.test("late successful metadata and persistence cannot outrun the original absolute budget", async () => {
  const f = fixture("none");
  await rejection(() =>
    observeBackupV2RuntimeLease(identity, f.context, async (command, args) => {
      const value = await f.run(command, args);
      f.advance(5000);
      return value;
    }, f.now)
  );
  assert(!f.context.budget.retried && f.counts().totalCalls === 3);
  f.release();
  for (const latePhase of ["observe", "persist"]) {
    let now = 0, persisted = 0;
    const persist = createBackupV2RuntimeLease(identity, {
      now: () => now,
      kernelNowUsec: () => 420_000_000n,
      observe: () => {
        if (latePhase === "observe") now = 5000;
        return Promise.resolve({
          identity,
          running: true,
          activeEnterUsec: 400_000_000n,
        });
      },
      persist: () => {
        persisted++;
        now = 5000;
        return Promise.resolve();
      },
    });
    await rejection(() => persist(30000, new AbortController().signal, 5000));
    assert(persisted === (latePhase === "observe" ? 0 : 1));
  }
});

Deno.test("a late persistence success cannot notify while the abort timer has not fired", async () => {
  let now = 0, extensions = 0;
  const supervisor = new BackupV2Supervisor(identity, {
    progressGraceMs: 300000,
    notificationGraceMs: 30000,
    observationTimeoutMs: 5000,
    maximumObservationAgeMs: 5000,
    productionWriterMarginBytes: 4096,
    minimumFreeInodes: 100,
    maximumSourceHeldDeletedBytes: 1024,
  }, {
    now: () => now,
    notifier: {
      ready() {},
      extend() {
        extensions++;
      },
      stopping() {},
      close() {},
    },
    persistRuntimeLease: (_deadline, signal, originalDeadline) => {
      assert(!signal.aborted && originalDeadline === 5000);
      now = 5000;
      return Promise.resolve();
    },
    observe: () =>
      Promise.resolve({
        identity,
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
          freeInodes: 1000,
          allocatedWorkspaceBytes: 0,
          workspaceHeldDeletedBytes: 0,
          sourceHeldDeletedBytes: 0,
        },
      }),
  });
  assert((await supervisor.poll()).action === "cancel" && extensions === 0);
});

Deno.test("deadline retry fails closed for unsettled, second, output, identity and exhausted-budget evidence", async () => {
  for (
    const fault of [
      "unsettled",
      "second",
      "stdout",
      "stderr",
      "identity",
      "budget",
    ]
  ) {
    const f = fixture(fault);
    if (fault === "budget") f.context.budget.deadlineMs = 3999;
    const error = await rejection(() =>
      observeBackupV2RuntimeLease(identity, f.context, f.run, f.now)
    );
    assert(error instanceof Error);
    assert(f.counts().showCalls === (fault === "second" ? 2 : 1));
    if (["stdout", "stderr"].includes(fault)) {
      assert(
        backupV2KernelDiagnostic(error)?.bound ===
          (fault === "stdout" ? "STDOUT_LIMIT" : "STDERR_LIMIT"),
      );
    }
    f.release();
  }
});

Deno.test("serialized settlement claims and exception secrets never establish retry provenance", async () => {
  const secret = "SYNTHETIC_PRIVATE_MARKER_0525";
  const fake = Object.assign(new BackupV2KernelEvidenceError("BOUNDED"), {
    message: secret,
    stack: secret,
    stdout: secret,
    stderr: secret,
    kernelEvidence: {
      bound: "DEADLINE",
      helper: "UNIT_SHOW",
      childSettled: true,
      readersSettled: true,
    },
  });
  assert(
    backupV2KernelSettlement(fake) === null &&
      backupV2KernelDiagnostic(fake) === undefined,
  );
  const evidence = backupV2FailureEvidence({
    identity,
    reason: fake,
    supervisorFailure: null,
    observation: null,
    observedAtUtc: "2026-10-19T18:00:00.000Z",
    observedMonotonicMs: 1,
  });
  assert(!JSON.stringify(evidence).includes(secret));
  const f = fixture("pending");
  let calls = 0;
  const error = await rejection(() =>
    observeBackupV2RuntimeLease(identity, f.context, () => {
      calls++;
      return Promise.reject(fake);
    }, f.now)
  );
  assert(error === fake && calls === 3 && !f.context.budget.retried);
  f.release();
});

Deno.test("a late output bound preserves the first deadline diagnostic and vetoes retry after settlement", async () => {
  const f = fixture("late-stdout");
  const error = await rejection(() =>
    observeBackupV2RuntimeLease(identity, f.context, f.run, f.now)
  );
  const detail = backupV2KernelDiagnostic(error);
  assert(detail?.bound === "DEADLINE");
  assert(detail.childSettled && detail.readersSettled);
  assert(await backupV2KernelSettlement(error) === false);
  assert(f.counts().showCalls === 1 && !f.context.budget.retried);
  f.release();
});

Deno.test("admission diagnostics distinguish concurrency and unsettled prior helpers", async () => {
  const f = fixture("pending");
  const pending = Array.from(
    { length: 16 },
    () => f.run("/usr/bin/systemctl", ["show"]),
  );
  const error = await rejection(() => f.run("/usr/bin/systemctl", ["show"]));
  assert(backupV2KernelDiagnostic(error)?.bound === "CONCURRENCY");
  f.release();
  await Promise.all(pending);
  const g = fixture("unsettled");
  const first = await rejection(() => g.run("/usr/bin/systemctl", ["show"]));
  const second = await rejection(() => g.run("/usr/bin/systemctl", ["show"]));
  assert(backupV2KernelDiagnostic(first)?.bound === "DEADLINE");
  assert(backupV2KernelDiagnostic(second)?.bound === "UNSETTLED");
  g.release();
  await backupV2KernelSettlement(first);
});

Deno.test("supervisor passes one original absolute budget across write and commit with no second retry or extension", async () => {
  const f = fixture();
  let writes = 0, extensions = 0, observedBudget = -1;
  const persist = createBackupV2RuntimeLease(identity, {
    now: f.now,
    kernelNowUsec: () => 420_000_000n + BigInt(f.now()) * 1000n,
    observe: (context) => {
      assert(context);
      observedBudget = context.budget.deadlineMs;
      return observeBackupV2RuntimeLease(identity, context, f.run, f.now);
    },
    persist: async (_text, _signal, context) => {
      assert(
        context && context.budget.retried &&
          context.budget.deadlineMs === observedBudget,
      );
      // A second phase deadline uses the same private backend, but never earns another retry.
      const delayed = fixture("second");
      await rejection(() =>
        observeBackupV2RuntimeLease(
          identity,
          { ...context, phase: "BEFORE_COMMIT" },
          delayed.run,
          f.now,
        )
      );
      delayed.release();
      throw new Error("commit custody unproved");
    },
  });
  const supervisor = new BackupV2Supervisor(identity, {
    progressGraceMs: 300000,
    notificationGraceMs: 30000,
    observationTimeoutMs: 5000,
    maximumObservationAgeMs: 5000,
    productionWriterMarginBytes: 4096,
    minimumFreeInodes: 100,
    maximumSourceHeldDeletedBytes: 1024,
  }, {
    now: f.now,
    notifier: {
      ready() {},
      extend() {
        extensions++;
      },
      stopping() {},
      close() {},
    },
    persistRuntimeLease: async (...args) => {
      await persist(...args);
      writes++;
    },
    observe: () =>
      Promise.resolve({
        identity,
        progress: {
          phase: "CAPTURING_AND_UPLOADING",
          observedMonotonicMs: f.now(),
          sourceBytes: 0,
          compressionInputBytes: 0,
          verifiedChunks: 0,
          decryptedBytes: 0,
          inventoryMembers: 0,
        },
        capacity: {
          observedMonotonicMs: f.now(),
          availableBytes: 10 * 1024 ** 3,
          freeInodes: 1000,
          allocatedWorkspaceBytes: 0,
          workspaceHeldDeletedBytes: 0,
          sourceHeldDeletedBytes: 0,
        },
      }),
  });
  assert((await supervisor.poll()).action === "cancel");
  assert(observedBudget === 5000 && writes === 0 && extensions === 0);
  f.release();
});
