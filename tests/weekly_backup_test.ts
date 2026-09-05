import {
  type BackupJournal,
  type BackupOperations,
  type BackupPolicy,
  type BackupSnapshot,
  needsSourceRecovery,
  newBackupJournal,
  runBackupCycle,
} from "../scripts/weekly-backup.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

function fixture() {
  const date = new Date("2026-09-06T08:00:00Z");
  const source = {
    instanceId: "instance",
    bootVolumeId: "boot",
    rootVolumeId: "root",
    compartmentId: "tenancy",
    region: "us-ashburn-1",
  };
  const policy: BackupPolicy = {
    source,
    standingApproval: {
      source: { ...source },
      approvedAtUtc: "2026-09-05T01:51:00Z",
      exactOperation: "weekly paired backup rotation",
    },
    acceptedPair: {
      suffix: "20260903T191507Z",
      bootId: "old-boot",
      rootId: "old-root",
    },
    allowFifthSlot: false,
    retainPreviousPair: false,
  };
  const backup = (kind: "boot" | "root", suffix: string, id: string) => ({
    id,
    "display-name": `arch-${
      kind === "boot" ? "stage" : "root"
    }-golden-${suffix}`,
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": kind === "boot" ? 50 : 150,
    type: "FULL",
    "compartment-id": "tenancy",
    "time-created": date.toISOString(),
    [kind === "boot" ? "boot-volume-id" : "volume-id"]: kind,
  });
  const state: BackupSnapshot = {
    source,
    instanceState: "RUNNING",
    bootBackups: [backup("boot", policy.acceptedPair.suffix, "old-boot")],
    rootBackups: [backup("root", policy.acceptedPair.suffix, "old-root")],
    allBackupCount: 2,
    freeBackupLimit: 5,
    sourceAttachmentsProved: true,
    freeEligibilityProved: true,
    writersAbsent: true,
  };
  const calls: string[] = [];
  const saves: BackupJournal[] = [];
  const ops: BackupOperations = {
    now: () => date,
    snapshot: () => Promise.resolve(structuredClone(state)),
    recoverySnapshot: () => Promise.resolve(structuredClone(state)),
    save: (journal) => {
      saves.push(journal);
      return Promise.resolve();
    },
    quiesce: () => {
      calls.push("quiesce");
      return Promise.resolve();
    },
    verifyQuiesced: () => Promise.resolve(),
    softStop: () => {
      calls.push("SOFTSTOP");
      state.instanceState = "STOPPED";
      state.stoppedEpoch = "stop-1";
      return Promise.resolve();
    },
    waitStopped: () => Promise.resolve(),
    createBackup: (kind, suffix) => {
      assert(
        saves.at(-1)?.[kind === "boot" ? "bootIntent" : "rootIntent"],
        "Intent must be durable before create",
      );
      calls.push(`create-${kind}`);
      (kind === "boot" ? state.bootBackups : state.rootBackups).push(
        backup(kind, suffix, `new-${kind}`),
      );
      state.allBackupCount++;
      return Promise.resolve(`new-${kind}`);
    },
    waitBackup: (kind) => {
      calls.push(`wait-${kind}`);
      return Promise.resolve();
    },
    start: () => {
      calls.push("START");
      state.instanceState = "RUNNING";
      return Promise.resolve();
    },
    acceptSource: () => {
      calls.push("accept");
      assert(state.instanceState === "RUNNING");
      return Promise.resolve();
    },
    deleteBackup: (kind, id) => {
      assert(saves.some((s) => s.phase === "source-accepted"));
      assert(id === `old-${kind}`);
      calls.push(`delete-${kind}`);
      const items = kind === "boot" ? state.bootBackups : state.rootBackups;
      items.splice(items.findIndex((item) => item.id === id), 1);
      state.allBackupCount--;
      return Promise.resolve();
    },
  };
  const journal = newBackupJournal(policy, date);
  return { policy, journal, state, ops, calls, saves };
}

async function rejected(run: () => Promise<void>) {
  let error = false;
  try {
    await run();
  } catch {
    error = true;
  }
  assert(error, "Expected refusal");
}

Deno.test("paired backup accepts source before retiring exact old pair", async () => {
  const f = fixture();
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.journal.phase === "complete");
  assert(
    f.calls.join() ===
      "quiesce,SOFTSTOP,create-boot,create-root,wait-boot,wait-root,START,accept,delete-boot,delete-root",
  );
  assert(f.state.allBackupCount === 2);
  const count = f.calls.length;
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.calls.length === count, "Completed run must not replay mutations");
});

Deno.test("first drill keeps the previous accepted pair", async () => {
  const f = fixture();
  f.policy.retainPreviousPair = true;
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.state.allBackupCount === 4);
  assert(!f.calls.some((c) => c.startsWith("delete")));
});

Deno.test("standing approval does not expire hourly but cannot change source", async () => {
  const f = fixture();
  f.policy.standingApproval.source.instanceId = "other";
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.calls.length === 0);
});

Deno.test("three occupied slots require separate fifth-slot authorization", async () => {
  const f = fixture();
  f.state.allBackupCount = 3;
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.calls.length === 0);
});

Deno.test("quiescence failure never stops source or creates backups", async () => {
  const f = fixture();
  f.ops.quiesce = () => Promise.reject(new Error("busy application"));
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!f.calls.includes("SOFTSTOP"));
  assert(f.journal.recoveryStatus === "running-accepted");
});

Deno.test("source attachment drift after quiescence blocks shutdown", async () => {
  const f = fixture();
  let reads = 0;
  f.ops.recoverySnapshot = () =>
    Promise.resolve({
      ...structuredClone(f.state),
      sourceAttachmentsProved: reads++ > 0,
    });
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.calls.join() === "quiesce,accept");
  assert(f.journal.recoveryStatus === "running-accepted");
});

Deno.test("ambiguous SOFTSTOP never falls back to hard stop or creates backups", async () => {
  const f = fixture();
  f.ops.softStop = () => {
    f.state.instanceState = "STOPPING";
    return Promise.reject(new Error("request timeout"));
  };
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!f.calls.includes("create-boot") && !f.calls.includes("START"));
  assert(f.journal.recoveryStatus === "failed");
});

Deno.test("partial pair failure recovers source and preserves old pair", async () => {
  const f = fixture();
  const create = f.ops.createBackup;
  f.ops.createBackup = (kind, suffix, epoch) =>
    kind === "root"
      ? Promise.reject(new Error("capacity"))
      : create(kind, suffix, epoch);
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.journal.bootId === "new-boot" && f.journal.rootIntent);
  assert(
    f.journal.phase === "failed" &&
      f.journal.recoveryStatus === "running-accepted",
  );
  assert(
    f.state.allBackupCount === 3 &&
      !f.calls.some((c) => c.startsWith("delete")),
  );
});

Deno.test("lost create response adopts exact observed object without duplicate", async () => {
  const f = fixture();
  const originalSave = f.ops.save;
  let interrupted: BackupJournal | undefined;
  f.ops.save = (journal) => {
    if (journal.bootId && !journal.rootIntent && !interrupted) {
      interrupted = structuredClone(journal);
      delete interrupted.bootId;
    }
    return originalSave(journal);
  };
  f.policy.retainPreviousPair = true;
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(interrupted);
  // Model a controller interruption after OCI creation, before the ID save.
  f.state.rootBackups = f.state.rootBackups.filter((b) => b.id !== "new-root");
  f.state.allBackupCount = 3;
  f.state.instanceState = "STOPPED";
  f.calls.length = 0;
  await runBackupCycle(f.policy, interrupted, f.ops);
  assert(!f.calls.includes("create-boot") && f.calls.includes("create-root"));
});

Deno.test("unobserved creation intent is not retried", async () => {
  const f = fixture();
  f.journal.phase = "backing-up";
  f.journal.bootIntent = true;
  f.journal.stoppedEpoch = "stop-1";
  f.state.instanceState = "STOPPED";
  f.state.stoppedEpoch = "stop-1";
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!f.calls.includes("create-boot"));
  assert(f.calls.includes("START"));
});

Deno.test("another stop epoch cannot create a mixed recovery pair", async () => {
  const f = fixture();
  f.journal.phase = "backing-up";
  f.journal.stoppedEpoch = "old-stop";
  f.state.instanceState = "STOPPED";
  f.state.stoppedEpoch = "new-stop";
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!f.calls.includes("create-boot"));
});

Deno.test("restart failure never accepts replacement or retires old pair", async () => {
  const f = fixture();
  f.ops.start = () => Promise.reject(new Error("start failed"));
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.journal.phase === "failed" && f.journal.recoveryStatus === "failed");
  assert(
    !f.calls.includes("accept") && !f.calls.some((c) => c.startsWith("delete")),
  );
});

Deno.test("active infrastructure writer prevents guest changes", async () => {
  const f = fixture();
  f.state.writersAbsent = false;
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.calls.length === 0);
});

Deno.test("journal storage failure still attempts source recovery", async () => {
  const f = fixture();
  const save = f.ops.save;
  f.ops.save = (journal) =>
    journal.bootId || journal.phase === "failed"
      ? Promise.reject(new Error("disk full"))
      : save(journal);
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(
    f.calls.includes("START") &&
      f.journal.recoveryStatus === "running-accepted",
  );
  assert(!f.calls.some((c) => c.startsWith("delete")));
});

Deno.test("changed stop epoch prevents automatic recovery start", async () => {
  const f = fixture();
  f.journal.phase = "backing-up";
  f.journal.stoppedEpoch = "our-stop";
  f.state.instanceState = "STOPPED";
  f.state.stoppedEpoch = "someone-elses-stop";
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!f.calls.includes("START") && f.journal.recoveryStatus === "failed");
});

Deno.test("resumed restart refuses a different stopped epoch", async () => {
  const f = fixture();
  f.journal.phase = "start-requested";
  f.journal.stoppedEpoch = "our-stop";
  f.state.instanceState = "STOPPED";
  f.state.stoppedEpoch = "later-stop";
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!f.calls.includes("START"));
  assert(f.journal.recoveryStatus === "failed");
});

Deno.test("unavailable backup eligibility evidence does not block original-source recovery", async () => {
  const f = fixture();
  const snapshot = f.ops.snapshot;
  f.ops.snapshot = () =>
    f.state.instanceState === "STOPPED"
      ? Promise.reject(new Error("Official terms unavailable"))
      : snapshot();
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(
    f.calls.includes("START") &&
      f.journal.recoveryStatus === "running-accepted",
  );
  assert(
    !f.calls.some((call) =>
      call.startsWith("create-") || call.startsWith("delete-")
    ),
  );
});

Deno.test("failed recheck preserves the previously accepted completed journal", async () => {
  const f = fixture();
  await runBackupCycle(f.policy, f.journal, f.ops);
  const saves = f.saves.length;
  f.ops.snapshot = () => Promise.reject(new Error("temporary API failure"));
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(f.journal.phase === "complete" && f.saves.length === saves);
});

Deno.test("window closing during inventory prevents quiescence", async () => {
  const f = fixture();
  let inventoried = false;
  const snapshot = f.ops.snapshot;
  f.ops.snapshot = () => {
    inventoried = true;
    return snapshot();
  };
  await rejected(() =>
    runBackupCycle(f.policy, f.journal, f.ops, {
      beforeQuiesce: () => {
        assert(inventoried, "Window must be rechecked after slow inventory");
        return Promise.reject(new Error("Window closed"));
      },
    })
  );
  assert(f.calls.length === 0);
});

Deno.test("recovery only restores interrupted outages without eligibility or backup mutations", async () => {
  for (
    const phase of [
      "quiescing",
      "quiesced",
      "stop-requested",
      "stopped",
      "backing-up",
      "pair-available",
      "start-requested",
      "failed",
    ] as const
  ) {
    const f = fixture();
    f.journal.phase = phase;
    if (phase === "failed") f.journal.recoveryStatus = "failed";
    f.journal.stoppedEpoch = "stop-1";
    f.state.stoppedEpoch = "stop-1";
    f.state.instanceState = phase === "quiescing" || phase === "quiesced"
      ? "RUNNING"
      : "STOPPED";
    f.ops.snapshot = () => Promise.reject(new Error("Eligibility unavailable"));
    await rejected(() =>
      runBackupCycle(f.policy, f.journal, f.ops, {
        recoveryOnly: true,
        beforeQuiesce: () => Promise.reject(new Error("Window closed")),
      })
    );
    assert(f.journal.recoveryStatus === "running-accepted", phase);
    assert(
      f.calls.join() ===
        (f.state.stoppedEpoch && !["quiescing", "quiesced"].includes(phase)
          ? "START,accept"
          : "accept"),
      phase,
    );
    assert(
      f.journal.phase === "failed",
      "Recovered abort must not claim a backup success",
    );
  }
});

Deno.test("recovery only cannot start a new cycle or retire an accepted pair", async () => {
  for (
    const phase of [
      "planned",
      "source-accepted",
      "retiring",
      "complete",
      "failed",
    ] as const
  ) {
    const f = fixture();
    f.journal.phase = phase;
    await rejected(() =>
      runBackupCycle(f.policy, f.journal, f.ops, { recoveryOnly: true })
    );
    assert(f.calls.length === 0);
    assert(f.saves.length === 0);
  }
});

Deno.test("recovery only preserves source identity and stopped epoch guards", async () => {
  for (const changed of ["source", "epoch", "writer", "attachments"]) {
    const f = fixture();
    f.journal.phase = "stopped";
    f.journal.stoppedEpoch = "our-stop";
    f.state.instanceState = "STOPPED";
    f.state.stoppedEpoch = changed === "epoch" ? "another-stop" : "our-stop";
    if (changed === "source") {
      f.state.source = { ...f.state.source, instanceId: "another-instance" };
    }
    if (changed === "writer") f.state.writersAbsent = false;
    if (changed === "attachments") f.state.sourceAttachmentsProved = false;
    await rejected(() =>
      runBackupCycle(f.policy, f.journal, f.ops, { recoveryOnly: true })
    );
    assert(f.calls.length === 0);
    assert(f.journal.recoveryStatus === "failed");
  }
});

Deno.test("durable failure marker survives a crash before source recovery", async () => {
  const f = fixture();
  f.ops.createBackup = () => Promise.reject(new Error("backup failed"));
  let interrupted: BackupJournal | undefined;
  const save = f.ops.save;
  f.ops.save = (journal) => {
    if (journal.phase === "failed" && !interrupted) {
      interrupted = structuredClone(journal);
    }
    return save(journal);
  };
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(interrupted && interrupted.recoveryStatus === "needed");
  assert(needsSourceRecovery(interrupted));
  f.state.instanceState = "STOPPED";
  f.calls.length = 0;
  await rejected(() =>
    runBackupCycle(f.policy, interrupted!, f.ops, { recoveryOnly: true })
  );
  assert(f.calls.join() === "START,accept");
  assert(!needsSourceRecovery(interrupted));
});

Deno.test("preflight failure does not authorize later source recovery", async () => {
  const f = fixture();
  f.ops.snapshot = () => Promise.reject(new Error("preflight failed"));
  await rejected(() => runBackupCycle(f.policy, f.journal, f.ops));
  assert(!needsSourceRecovery(f.journal));
  assert(!f.journal.recoveryStatus && f.calls.length === 0);
});
