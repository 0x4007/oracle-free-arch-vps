import type { SourceContinuityEvidence } from "../scripts/online-backup-contract.ts";
import { ONLINE_RETRY_POLICY } from "../scripts/online-backup-contract.ts";
import {
  type BackupJournal,
  type BackupOperations,
  type BackupPair,
  type BackupPolicy,
  type BackupSnapshot,
  newBackupJournal,
  OnlineBackupRetryableError,
  reconcileBackupGroupCreation,
  runBackupCycle,
  validateBackupPairForPolicy,
} from "../scripts/weekly-backup.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

const DATE = "2026-09-06T08:00:00.000Z";
const CAPTURE = "2026-09-06T08:00:01.000Z";
const source = {
  instanceId: "instance",
  bootVolumeId: "boot",
  rootVolumeId: "root",
  compartmentId: "tenancy",
  region: "us-ashburn-1",
};
const CONTINUITY: SourceContinuityEvidence = {
  bootId: "11111111-1111-1111-1111-111111111111",
  serviceInvocations: {
    "system:docker.service": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "system:caddy.service": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  },
  observedAtUtc: DATE,
};

function backup(
  kind: "boot" | "root",
  id: string,
  groupBackupId: string | null = null,
  timeCreated = CAPTURE,
) {
  return {
    id,
    "compartment-id": source.compartmentId,
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": kind === "boot" ? 50 : 150,
    type: "FULL",
    "time-created": timeCreated,
    "volume-group-backup-id": groupBackupId,
    [kind === "boot" ? "boot-volume-id" : "volume-id"]: kind === "boot"
      ? source.bootVolumeId
      : source.rootVolumeId,
  };
}

function groupBackup(
  id: string,
  bootId: string,
  rootId: string,
  timeCreated = CAPTURE,
  displaySuffix = timeCreated === CAPTURE
    ? "20260906T080001Z"
    : "20260905T080000Z",
) {
  return {
    id,
    "compartment-id": source.compartmentId,
    "volume-group-id": "volume-group",
    "volume-backup-ids": [bootId, rootId],
    "lifecycle-state": "AVAILABLE",
    type: "FULL",
    "time-created": timeCreated,
    "time-request-received": timeCreated,
    "display-name": `arch-online-golden-${displaySuffix}`,
  };
}

function policy(grouped = false, retainPreviousPair = false): BackupPolicy {
  const acceptedPair: BackupPair = {
    suffix: "20260905T080000Z",
    bootId: "old-boot",
    rootId: "old-root",
  };
  if (grouped) acceptedPair.volumeGroupBackupId = "old-group";
  return {
    source: structuredClone(source),
    volumeGroupId: "volume-group",
    standingApproval: {
      source: structuredClone(source),
      approvedAtUtc: "2026-09-05T01:51:00Z",
      exactOperation: "weekly paired backup rotation",
    },
    acceptedPair,
    retainPreviousPair,
    allowFifthSlot: true,
  };
}

function fixture(
  groupedPrevious = false,
  retainPreviousPair = false,
): {
  policy: BackupPolicy;
  journal: BackupJournal;
  state: BackupSnapshot;
  ops: BackupOperations;
  calls: string[];
  saves: BackupJournal[];
} {
  const selectedPolicy = policy(groupedPrevious, retainPreviousPair);
  const state: BackupSnapshot = {
    source: structuredClone(source),
    instanceState: "RUNNING",
    bootBackups: [
      backup(
        "boot",
        "old-boot",
        groupedPrevious ? "old-group" : null,
        groupedPrevious ? "2026-09-05T08:00:00.000Z" : CAPTURE,
      ),
    ],
    rootBackups: [
      backup(
        "root",
        "old-root",
        groupedPrevious ? "old-group" : null,
        groupedPrevious ? "2026-09-05T08:00:00.000Z" : CAPTURE,
      ),
    ],
    allBackupCount: 2,
    allVolumeGroupBackupCount: groupedPrevious ? 1 : 0,
    freeBackupLimit: 5,
    volumeGroups: [{
      id: "volume-group",
      "compartment-id": source.compartmentId,
      "availability-domain": "ad",
      "lifecycle-state": "AVAILABLE",
      "volume-ids": [source.bootVolumeId, source.rootVolumeId],
    }],
    volumeGroupBackups: groupedPrevious
      ? [
        groupBackup(
          "old-group",
          "old-boot",
          "old-root",
          "2026-09-05T08:00:00.000Z",
        ),
      ]
      : [],
    sourceAttachmentsProved: true,
    sourceVolumeGroupProved: true,
    groupAccountingProved: true,
    freeEligibilityProved: true,
    writersAbsent: true,
  };
  const calls: string[] = [];
  const saves: BackupJournal[] = [];
  let afterCapture = false;
  const ops: BackupOperations = {
    now: () => new Date(DATE),
    snapshot: () => Promise.resolve(structuredClone(state)),
    save: (journal) => {
      saves.push(structuredClone(journal));
      return Promise.resolve();
    },
    observeSource: () => {
      calls.push("observe");
      return Promise.resolve(structuredClone(CONTINUITY));
    },
    acceptSource: () => {
      calls.push("accept");
      assert(state.instanceState === "RUNNING");
      return Promise.resolve();
    },
    createBackupGroup: (suffix) => {
      calls.push("create-group");
      assert(
        saves.at(-1)?.volumeGroupBackupIntent === true,
        "Group intent must be durable before create",
      );
      assert(suffix === "20260906T080000Z");
      return Promise.resolve("new-group");
    },
    waitBackupGroup: (id) => {
      calls.push("wait-group");
      assert(id === "new-group");
      state.bootBackups.push(backup("boot", "new-boot", "new-group"));
      state.rootBackups.push(backup("root", "new-root", "new-group"));
      state.volumeGroupBackups!.push(
        groupBackup(
          "new-group",
          "new-boot",
          "new-root",
          CAPTURE,
          "20260906T080000Z",
        ),
      );
      state.allBackupCount = 4;
      state.allVolumeGroupBackupCount = (state.allVolumeGroupBackupCount ?? 0) +
        1;
      afterCapture = true;
      return Promise.resolve();
    },
    deleteBackupGroup: (id, members) => {
      calls.push("delete-group");
      assert(id === "old-group");
      assert(members.bootId === "old-boot" && members.rootId === "old-root");
      state.bootBackups = state.bootBackups.filter((item) =>
        item.id !== members.bootId
      );
      state.rootBackups = state.rootBackups.filter((item) =>
        item.id !== members.rootId
      );
      state.volumeGroupBackups = state.volumeGroupBackups!.filter((item) =>
        item.id !== id
      );
      state.allBackupCount -= 2;
      return Promise.resolve();
    },
    deleteBackup: (kind, id) => {
      calls.push(`delete-${kind}`);
      assert(id === (kind === "boot" ? "old-boot" : "old-root"));
      if (kind === "boot") {
        state.bootBackups = state.bootBackups.filter((item) => item.id !== id);
      } else {state.rootBackups = state.rootBackups.filter((item) =>
          item.id !== id
        );}
      state.allBackupCount--;
      return Promise.resolve();
    },
  };
  // Keep the flag referenced so the fixture documents the post-capture point.
  void afterCapture;
  const journal = newBackupJournal(selectedPolicy, new Date(DATE));
  return { policy: selectedPolicy, journal, state, ops, calls, saves };
}

async function rejects(run: () => Promise<unknown>, message: string) {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected, message);
}

Deno.test("online group capture accepts source without outage operations", async () => {
  const f = fixture();
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.journal.mode === "online");
  assert(f.journal.phase === "complete");
  assert(f.journal.captureIdentity?.volumeGroupBackupId === "new-group");
  assert(f.journal.bootId === "new-boot" && f.journal.rootId === "new-root");
  assert(
    f.calls.join(",") ===
      "observe,create-group,wait-group,observe,observe,accept,observe,delete-boot,delete-root",
  );
  assert(
    !f.calls.some((call) => /stop|start|quiesc|reboot|freeze|kill/i.test(call)),
  );
});

Deno.test("typed transient inventory failure persists backoff and resumes", async () => {
  const f = fixture();
  let nowMs = Date.parse(DATE);
  let snapshotCalls = 0;
  const snapshot = f.ops.snapshot;
  f.ops.now = () => new Date(nowMs);
  f.ops.snapshot = async () => {
    snapshotCalls++;
    if (snapshotCalls === 1) {
      throw new OnlineBackupRetryableError(
        "inventory transport failed",
        undefined,
        "external-read",
      );
    }
    return await snapshot();
  };

  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "the first transient failure must be reported",
  );
  assert(f.journal.phase === "failed");
  assert(f.journal.retry?.disposition === "retryable");
  assert(f.journal.retry?.resumePhase === "planned");
  assert(f.journal.retry?.attempts === 1);
  assert(
    Date.parse(f.journal.retry!.nextAttemptAtUtc) ===
      nowMs + ONLINE_RETRY_POLICY.initialDelayMs,
    "the first retry uses the durable initial delay",
  );
  const callsBeforeEarlyRetry = snapshotCalls;
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "a retry before its durable deadline must not run an operation",
  );
  assert(snapshotCalls === callsBeforeEarlyRetry);

  nowMs = Date.parse(f.journal.retry!.nextAttemptAtUtc);
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert((f.journal as BackupJournal).phase === "complete");
  assert(f.journal.retry === undefined);
});

Deno.test("retry burst cools down after the bounded deadline", async () => {
  const f = fixture();
  let nowMs = Date.parse(DATE);
  f.ops.now = () => new Date(nowMs);
  f.ops.snapshot = () =>
    Promise.reject(
      new OnlineBackupRetryableError(
        "inventory transport failed",
        undefined,
        "external-read",
      ),
    );

  for (
    let attempt = 1;
    attempt <= ONLINE_RETRY_POLICY.maximumAttempts;
    attempt++
  ) {
    await rejects(
      () => runBackupCycle(f.policy, f.journal, f.ops),
      `bounded attempt ${attempt} must remain observable`,
    );
    assert(f.journal.retry?.attempts === attempt);
    if (attempt < ONLINE_RETRY_POLICY.maximumAttempts) {
      nowMs = Date.parse(f.journal.retry!.nextAttemptAtUtc);
    }
  }
  assert(f.journal.phase === "failed");
  assert(f.journal.retry?.disposition === "retryable");
  assert(
    Date.parse(f.journal.retry!.nextAttemptAtUtc) >=
      nowMs + ONLINE_RETRY_POLICY.cooldownMs,
    "an exhausted burst must wait for a cooldown",
  );
  assert(
    Date.parse(f.journal.retry!.deadlineAtUtc) ===
      Date.parse(DATE) + ONLINE_RETRY_POLICY.burstDeadlineMs,
    "the burst deadline remains durable",
  );
});

Deno.test("failed journal without resume metadata stays blocked", async () => {
  const f = fixture();
  f.journal.phase = "failed";
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "an old ambiguous failure must not be replayed",
  );
  assert(f.calls.length === 0);
  assert(f.journal.retry === undefined);
});

Deno.test("lost create response reconciles the same group without a duplicate", async () => {
  const f = fixture();
  let createCalls = 0;
  f.ops.createBackupGroup = (suffix) => {
    createCalls++;
    assert(suffix === f.journal.suffix);
    assert(f.journal.volumeGroupBackupIntent === true);
    if (createCalls === 1) {
      f.state.bootBackups.push(backup("boot", "new-boot", "new-group"));
      f.state.rootBackups.push(backup("root", "new-root", "new-group"));
      f.state.volumeGroupBackups!.push(
        groupBackup(
          "new-group",
          "new-boot",
          "new-root",
          CAPTURE,
          f.journal.suffix,
        ),
      );
      f.state.allBackupCount = 4;
      f.state.allVolumeGroupBackupCount = 1;
      throw new OnlineBackupRetryableError(
        "create response was lost",
        "backing-up",
        "recorded-operation",
      );
    }
    throw new Error("duplicate create was attempted");
  };
  f.ops.waitBackupGroup = (id) => {
    f.calls.push("wait-group");
    assert(id === "new-group");
    return Promise.resolve();
  };

  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "lost create response must leave a retryable journal",
  );
  assert(f.journal.phase === "failed");
  assert(f.journal.retry?.resumePhase === "backing-up");
  const retryAt = f.journal.retry!.nextAttemptAtUtc;
  f.ops.now = () => new Date(retryAt);
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(createCalls === 1, "the reconciled group must be created once");
  assert((f.journal as BackupJournal).phase === "complete");
  assert(f.journal.volumeGroupBackupId === "new-group");
});

Deno.test("first online point keeps standalone previous pair until drill acceptance", async () => {
  const f = fixture(false, true);
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.journal.phase === "complete");
  assert(f.calls.filter((call) => call.startsWith("delete")).length === 0);
  assert(f.state.allBackupCount === 4);
});

Deno.test("grouped previous pair is retired through one cascading group delete", async () => {
  const f = fixture(true, false);
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.journal.phase === "complete");
  assert(f.calls.includes("delete-group"));
  assert(!f.calls.includes("delete-boot") && !f.calls.includes("delete-root"));
  assert(!f.state.volumeGroupBackups!.some((item) => item.id === "old-group"));
});

Deno.test("partial retention resumes from fresh evidence", async () => {
  const f = fixture(true, false);
  const deleteGroup = f.ops.deleteBackupGroup;
  let attempts = 0;
  f.ops.deleteBackupGroup = async (id, members) => {
    attempts++;
    if (attempts === 1) {
      f.calls.push("delete-group-started");
      f.state.volumeGroupBackups![0]["lifecycle-state"] = "TERMINATING";
      f.state.bootBackups[0]["lifecycle-state"] = "TERMINATING";
      f.state.rootBackups[0]["lifecycle-state"] = "TERMINATING";
      throw new OnlineBackupRetryableError(
        "retention response was lost",
        "retiring",
        "recorded-operation",
      );
    }
    await deleteGroup(id, members);
  };
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "partial retention must remain resumable",
  );
  assert(f.journal.phase === "failed");
  assert(f.journal.retry?.resumePhase === "retiring");
  const retryAt = f.journal.retry!.nextAttemptAtUtc;
  f.ops.now = () => new Date(retryAt);
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert((f.journal as BackupJournal).phase === "complete");
  assert(attempts === 2, "the second retention attempt uses fresh evidence");
  assert(!f.state.volumeGroupBackups!.some((item) => item.id === "old-group"));
});

Deno.test("boot or service invocation drift fails capture and never retires old data", async () => {
  const f = fixture();
  let observations = 0;
  f.ops.observeSource = () => {
    observations++;
    return Promise.resolve(
      observations === 2
        ? {
          ...structuredClone(CONTINUITY),
          bootId: "22222222-2222-2222-2222-222222222222",
        }
        : structuredClone(CONTINUITY),
    );
  };
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "drift must fail",
  );
  assert(f.journal.phase === "failed");
  assert(f.journal.retry?.disposition === "blocked");
  assert(f.journal.retry?.attempts === 1);
  assert(!f.calls.some((call) => call.startsWith("delete")));
  assert(f.state.instanceState === "RUNNING");
});

Deno.test("legacy outage journal is rejected before any provider operation", async () => {
  const f = fixture();
  const legacy = { ...f.journal, mode: undefined } as unknown as BackupJournal;
  await rejects(
    () => runBackupCycle(f.policy, legacy, f.ops),
    "legacy mode must be rejected",
  );
  assert(f.calls.length === 0);
});

Deno.test("retention preserves the old root if replacement disappears during boot deletion", async () => {
  const f = fixture(false, false);
  const remove = f.ops.deleteBackup;
  f.ops.deleteBackup = async (kind, id) => {
    await remove(kind, id);
    if (kind === "boot") {
      f.state.rootBackups = f.state.rootBackups.filter((item) =>
        item.id !== "new-root"
      );
    }
  };
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "replacement loss must stop retention",
  );
  assert(f.calls.includes("delete-boot"));
  assert(!f.calls.includes("delete-root"));
  assert(f.state.rootBackups.some((item) => item.id === "old-root"));
});

Deno.test("intent with empty inventory never creates a duplicate group backup", async () => {
  const f = fixture();
  f.journal.phase = "backing-up";
  f.journal.volumeGroupBackupIntent = true;
  f.ops.snapshot = () =>
    Promise.resolve({ ...structuredClone(f.state), volumeGroupBackups: [] });
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "ambiguous intent must fail closed",
  );
  assert(!f.calls.includes("create-group"));
});

Deno.test("wrong recorded create identity becomes a visible block", async () => {
  const f = fixture();
  f.journal.phase = "failed";
  f.journal.volumeGroupBackupIntent = true;
  f.journal.volumeGroupBackupId = "wrong-group";
  f.journal.retry = {
    disposition: "retryable",
    resumePhase: "backing-up",
    attempts: 1,
    firstFailureAtUtc: DATE,
    nextAttemptAtUtc: DATE,
    deadlineAtUtc: new Date(
      Date.parse(DATE) + ONLINE_RETRY_POLICY.burstDeadlineMs,
    ).toISOString(),
  };
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "a wrong recorded identity must block",
  );
  assert(f.journal.phase === "failed");
  assert(f.journal.retry?.disposition === "blocked");
  assert(!f.calls.includes("create-group"));
});

Deno.test("returned group ID is required before waiting", async () => {
  const f = fixture();
  let intentSaveIndex = -1;
  f.ops.save = (journal) => {
    if (journal.volumeGroupBackupIntent && !journal.volumeGroupBackupId) {
      intentSaveIndex = f.saves.length;
    }
    f.saves.push(structuredClone(journal));
    return Promise.resolve();
  };
  await runBackupCycle(f.policy, f.journal, f.ops);
  const idSaveIndex = f.saves.findIndex((journal) =>
    journal.volumeGroupBackupId === "new-group"
  );
  const waitIndex = f.calls.indexOf("wait-group");
  assert(intentSaveIndex >= 0 && idSaveIndex >= 0 && waitIndex >= 0);
});

Deno.test("reconcile helper refuses an empty inventory after intent", () => {
  const f = fixture();
  f.journal.volumeGroupBackupIntent = true;
  let refused = false;
  try {
    reconcileBackupGroupCreation(f.policy, f.journal, {
      ...f.state,
      volumeGroupBackups: [],
    });
  } catch {
    refused = true;
  }
  assert(refused);
});

Deno.test("grouped pair validator uses IDs and source metadata, never member display names", () => {
  const f = fixture();
  f.state.bootBackups.push(backup("boot", "group-boot", "group", CAPTURE));
  f.state.rootBackups.push(backup("root", "group-root", "group", CAPTURE));
  f.state.volumeGroupBackups!.push(
    groupBackup("group", "group-boot", "group-root"),
  );
  validateBackupPairForPolicy(
    f.state,
    {
      suffix: "20260906T080001Z",
      bootId: "group-boot",
      rootId: "group-root",
      volumeGroupBackupId: "group",
    },
    source,
    f.policy,
  );
  f.state.bootBackups.at(-1)!["display-name"] = "provider-generated-name";
  f.state.rootBackups.at(-1)!["display-name"] = "another-provider-name";
  validateBackupPairForPolicy(
    f.state,
    {
      suffix: "20260906T080001Z",
      bootId: "group-boot",
      rootId: "group-root",
      volumeGroupBackupId: "group",
    },
    source,
    f.policy,
  );
});

Deno.test("a failed final pre-create read withdraws only the unsent intent", async () => {
  const f = fixture();
  const create = f.ops.createBackupGroup;
  let attempts = 0;
  let now = Date.parse(DATE);
  f.ops.now = () => new Date(now);
  f.ops.createBackupGroup = async (suffix) => {
    if (++attempts === 1) {
      throw new OnlineBackupRetryableError(
        "final inventory unavailable",
        "backing-up",
        "external-read",
      );
    }
    return await create(suffix);
  };
  await rejects(
    () => runBackupCycle(f.policy, f.journal, f.ops),
    "the failed read must remain visible",
  );
  assert(f.journal.volumeGroupBackupIntent === false);
  assert(f.journal.retry?.disposition === "retryable");
  now = Date.parse(f.journal.retry!.nextAttemptAtUtc);
  await runBackupCycle(f.policy, f.journal, f.ops);
  assert(f.journal.phase === "complete");
  assert(f.calls.filter((call) => call === "create-group").length === 1);
});
