import {
  type GroupRestoreAcceptanceReceipt,
  type GroupRestoreExecutionPorts,
  type GroupRestoreExecutionResult,
} from "../scripts/oci-group-restore-executor.ts";
import {
  type GroupRestoreApproval,
  groupRestoreDisplayName,
  type GroupRestoreEvidence,
  type GroupRestoreJournal,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  type GroupRestoreRunner,
} from "../scripts/oci-group-restore-drill.ts";
import {
  GROUP_RESTORE_STATE_FILES,
  groupRestoreAttachIntentStateStore,
  type GroupRestoreRunConfig,
  type GroupRestoreRunDeps,
  parseGroupRestoreRunArgs,
  runGroupRestoreCycle,
  withGroupRestoreControllerGate,
} from "../scripts/oci-group-restore-run.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

async function rejects(run: () => unknown): Promise<void> {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed, "Expected the operation to reject");
}

const PRIVATE_DIR = ".private/group-restore";
const statePath = (name: string) => `${PRIVATE_DIR}/${name}`;

const plan: GroupRestorePlan = {
  source: {
    instanceId: "source-instance",
    bootVolumeId: "source-boot",
    rootVolumeId: "source-root",
    compartmentId: "tenancy",
    region: "us-ashburn-1",
  },
  availabilityDomain: "AD-1",
  volumeGroupId: "source-group",
  volumeGroupBackupId: "source-capture",
  bootMemberBackupId: "member-boot",
  rootMemberBackupId: "member-root",
  productionSubnetId: "production-subnet",
  productionVcnId: "production-vcn",
  productionReservedIpId: "production-ip",
  isolatedSubnetId: "isolated-subnet",
  isolatedVcnId: "isolated-vcn",
  controllerIpv4: "74.72.113.64",
  suffix: "20260908T140000Z",
  maxDurationHours: 4,
  spendingCapUsd: 0.5,
};

const evidence: GroupRestoreEvidence = {
  group: {
    id: plan.volumeGroupBackupId,
    "volume-group-id": plan.volumeGroupId,
    "compartment-id": plan.source.compartmentId,
    "lifecycle-state": "AVAILABLE",
    type: "FULL",
    "time-created": "2026-09-08T14:00:00Z",
    "volume-backup-ids": [
      plan.bootMemberBackupId,
      plan.rootMemberBackupId,
    ],
  },
  bootMember: {
    id: plan.bootMemberBackupId,
    "display-name": "provider-boot",
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": 50,
    type: "FULL",
    "compartment-id": plan.source.compartmentId,
    "volume-group-backup-id": plan.volumeGroupBackupId,
    "boot-volume-id": plan.source.bootVolumeId,
    "time-created": "2026-09-08T14:00:01Z",
  },
  rootMember: {
    id: plan.rootMemberBackupId,
    "display-name": "provider-root",
    "lifecycle-state": "AVAILABLE",
    "size-in-gbs": 150,
    type: "FULL",
    "compartment-id": plan.source.compartmentId,
    "volume-group-backup-id": plan.volumeGroupBackupId,
    "volume-id": plan.source.rootVolumeId,
    "time-created": "2026-09-08T14:00:01Z",
  },
};

const now = new Date("2026-09-08T14:30:00Z");
const runner: GroupRestoreRunner = {
  ociCliPath: "/home/pi/.venvs/oci/bin/oci",
  ociProfile: "DEFAULT",
  region: "us-ashburn-1",
  run: () => Promise.resolve({ code: 0, stdout: "", stderr: "" }),
};
const PLAN_SHA = await groupRestorePlanDigest(plan);
const approval: GroupRestoreApproval = {
  approvedAtUtc: "2026-09-08T14:00:00.000Z",
  expiresAtUtc: "2026-09-08T14:59:59.999Z",
  exactOperation: "one isolated trial-funded volume-group restore drill",
  planSha256: PLAN_SHA,
  subscriptionTier: "FREE_AND_TRIAL",
  paymentModel: "FREE_TRIAL",
  availableTrialCreditsUsd: 300,
  estimatedCostUsd: 0.05,
  trialExpiresAtUtc: "2026-09-29T23:59:59.999Z",
  observedAtUtc: "2026-09-08T14:20:00.000Z",
};

const SHA256 = "ab".repeat(32);
function receipt(): GroupRestoreAcceptanceReceipt {
  return {
    status: "RESTORE_DRILL_PROVED",
    observedAtUtc: now.toISOString(),
    suffix: plan.suffix,
    planSha256: PLAN_SHA,
    checks: {
      productionOnline: true,
      targetBooted: true,
      ssh: true,
      mounts: true,
      bootParity: true,
      representativeData: true,
      applications: true,
      desktop: true,
      isolation: true,
      metadataBlocked: true,
      duplicateJobsMasked: true,
    },
    rootUuid: "9f7e0d1c-2a3b-4c5d-8e9f-001122334455",
    stagingUuid: "1a2b3c4d-5e6f-4a7b-8c9d-001122334455",
    rootPartitionStartSector: 1050624,
    kernelSha256: SHA256,
    initramfsSha256: SHA256,
    grubSha256: SHA256,
  };
}

class MemoryStore {
  files = new Map<string, unknown>();
  writePaths: string[] = [];
  missing: Set<string> = new Set();
  /** Durable-like read failures that must never be treated as absence. */
  unreadable: Set<string> = new Set();
  malformed: Set<string> = new Set();

  readJson<T>(path: string): Promise<T> {
    // A present-but-broken durable file must surface its read error; check
    // these before the absence rule so no broken file is masked as missing.
    if (this.unreadable.has(path)) {
      return Promise.reject(new Error(`permission denied reading ${path}`));
    }
    if (this.malformed.has(path)) {
      return Promise.reject(
        new SyntaxError(`Unexpected token in JSON: ${path}`),
      );
    }
    if (this.missing.has(path) || !this.files.has(path)) {
      return Promise.reject(new Deno.errors.NotFound(`not found: ${path}`));
    }
    return Promise.resolve(this.files.get(path)! as T);
  }

  writeJson(path: string, value: unknown): Promise<void> {
    this.writePaths.push(path);
    this.files.set(path, structuredClone(value));
    return Promise.resolve();
  }
}

class FakePorts implements GroupRestoreExecutionPorts {
  verifyCalls = 0;
  deleteFailure = false;
  isolationFailure = false;
  deleteArgv: string[][] = [];
  resources: { id: string; displayName: string }[] = [];
  private clock: () => Date;

  constructor(clock: () => Date) {
    this.clock = clock;
  }

  now(): Date {
    return this.clock();
  }

  observe(
    request: { requestName: string },
  ): Promise<{ id: string; displayName: string }[]> {
    return Promise.resolve(
      this.resources.filter((resource) =>
        resource.displayName === request.requestName
      ),
    );
  }

  create(
    step: { kind: string; request: { requestName: string } },
  ): Promise<{ id: string; displayName: string }[]> {
    this.resources.push({
      id: `target-${step.kind}`,
      displayName: step.request.requestName,
    });
    return this.observe(step.request);
  }

  delete(
    _step: { kind: string },
    identity: { id: string },
    argv: string[],
  ): Promise<{ id: string; displayName: string }[]> {
    this.deleteArgv.push(argv);
    if (this.deleteFailure) {
      this.resources = this.resources.filter((resource) =>
        resource.id !== identity.id
      );
      return Promise.reject(new Error("simulated delete response loss"));
    }
    this.resources = this.resources.filter((resource) =>
      resource.id !== identity.id
    );
    return Promise.resolve([]);
  }

  verifyProduction(): Promise<void> {
    this.verifyCalls += 1;
    return Promise.resolve();
  }

  verifyPreBootIsolation(_targets: {
    bootVolumeId: string;
    rootVolumeId: string;
  }): Promise<void> {
    if (this.isolationFailure) {
      return Promise.reject(new Error("pre-boot isolation is not proved"));
    }
    return Promise.resolve();
  }
}

interface Harness {
  store: MemoryStore;
  ports: FakePorts;
  deps: GroupRestoreRunDeps;
  /** Advancing this clock also advances the fake ports' clock. */
  advance: (to: Date) => void;
  /** File-backed durable attachment-intent store over the same MemoryStore. */
  attachState: ReturnType<typeof groupRestoreAttachIntentStateStore>;
}

function harness(
  inputs: Partial<GroupRestoreRunConfig["inputs"]> = {},
): Harness {
  const store = new MemoryStore();
  let current = now;
  const ports = new FakePorts(() => current);
  const files = {
    planPath: ".private/inputs/plan.json",
    approvalPath: ".private/inputs/approval.json",
    evidencePath: ".private/inputs/evidence.json",
    acceptancePath: ".private/inputs/acceptance.json",
    ...inputs,
  };
  store.files.set(files.planPath!, plan);
  store.files.set(files.approvalPath!, approval);
  store.files.set(files.evidencePath!, evidence);
  store.files.set(files.acceptancePath!, receipt());
  const attachState = groupRestoreAttachIntentStateStore(
    PRIVATE_DIR,
    store.readJson.bind(store),
    store.writeJson.bind(store),
  );
  const deps: GroupRestoreRunDeps = {
    now: () => current,
    readJson: store.readJson.bind(store),
    writeJson: store.writeJson.bind(store),
    runner,
    makePorts: () => ports,
    attachStateStore: attachState,
    preBootIsolationReady: true,
  };
  return {
    store,
    ports,
    deps,
    advance: (to) => {
      current = to;
    },
    attachState,
  };
}

function config(
  action: GroupRestoreRunConfig["action"],
  inputs: Partial<GroupRestoreRunConfig["inputs"]> = {},
): GroupRestoreRunConfig {
  return {
    action,
    privateDir: PRIVATE_DIR,
    inputs: {
      planPath: ".private/inputs/plan.json",
      approvalPath: ".private/inputs/approval.json",
      evidencePath: ".private/inputs/evidence.json",
      acceptancePath: ".private/inputs/acceptance.json",
      ...inputs,
    },
  };
}

function persisted(name: string, store: MemoryStore): unknown {
  return store.files.get(statePath(name));
}

/** Exact reconciled create journal for the given drill resources, as the
 * create stage would persist it before a later failure. */
function createdJournal(
  kinds: Array<"boot-volume" | "root-volume" | "instance">,
): GroupRestoreJournal {
  return kinds.map((kind, index) => ({
    request: {
      suffix: plan.suffix,
      kind,
      requestName: groupRestoreDisplayName(kind, plan.suffix),
    },
    intent: "create",
    createdAtUtc: new Date(
      now.getTime() + (index + 1) * 60_000,
    ).toISOString(),
    identity: {
      id: `target-${kind}`,
      name: groupRestoreDisplayName(kind, plan.suffix),
    },
  }));
}

function lifetimeFrom(startedAtUtc: string): {
  startedAtUtc: string;
  deadlineAtUtc: string;
} {
  return {
    startedAtUtc,
    deadlineAtUtc: new Date(
      Date.parse(startedAtUtc) + plan.maxDurationHours * 3_600_000,
    ).toISOString(),
  };
}

Deno.test("run create persists the durable lifetime, journal and result", async () => {
  const { store, ports, deps } = harness();
  const result = await runGroupRestoreCycle(config("create"), deps);
  assert(result.state === "CREATED");
  assert(result.restoreDrillProved === false);
  assert(ports.verifyCalls === 1);
  assert(
    store.writePaths.every((path) => path.startsWith(PRIVATE_DIR + "/")),
    "Only the private state directory may be written",
  );
  const lifetime = persisted(GROUP_RESTORE_STATE_FILES.lifetime, store) as {
    startedAtUtc: string;
    deadlineAtUtc: string;
  };
  assert(lifetime.startedAtUtc === now.toISOString());
  assert(
    new Date(lifetime.deadlineAtUtc).getTime() -
        new Date(lifetime.startedAtUtc).getTime() ===
      plan.maxDurationHours * 3_600_000,
  );
  const journal = persisted(
    GROUP_RESTORE_STATE_FILES.journal,
    store,
  ) as GroupRestoreJournal;
  assert(journal.length === 3);
  const saved = persisted(
    GROUP_RESTORE_STATE_FILES.result,
    store,
  ) as GroupRestoreExecutionResult;
  assert(saved.state === "CREATED");
  assert(saved.lifetime.startedAtUtc === lifetime.startedAtUtc);
  const journalWrites = store.writePaths.filter((path) =>
    path === statePath(GROUP_RESTORE_STATE_FILES.journal)
  );
  assert(
    journalWrites.length >= 7,
    "create intents must be durable before each provider call",
  );
});

Deno.test("run create fails closed on missing inputs and placeholders", async () => {
  const { store, deps } = harness();
  store.missing.add(".private/inputs/plan.json");
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(config("create"), deps);
    } catch (error) {
      assert(
        String(error).includes("Plan input is missing or unreadable"),
        "missing plan must name the input",
      );
      throw error;
    }
  });
  await rejects(() =>
    runGroupRestoreCycle(
      config("create", { planPath: "<USER>/plan.json" }),
      harness().deps,
    )
  );
  const badDir = harness();
  await rejects(() =>
    runGroupRestoreCycle(
      { ...config("create"), privateDir: "/tmp/out-of-private" },
      badDir.deps,
    )
  );
  // Absolute paths under a .private-named directory and traversal segments
  // must fail closed; inputs outside .private are refused too.
  await rejects(() =>
    runGroupRestoreCycle(
      { ...config("create"), privateDir: "/tmp/.private" },
      badDir.deps,
    )
  );
  await rejects(() =>
    runGroupRestoreCycle(
      { ...config("create"), privateDir: ".private/../escape" },
      badDir.deps,
    )
  );
  await rejects(() =>
    runGroupRestoreCycle(
      config("create", { planPath: "inputs/plan.json" }),
      harness().deps,
    )
  );
  await rejects(() =>
    runGroupRestoreCycle(
      config("create", { planPath: "./.private/inputs/plan.json" }),
      harness().deps,
    )
  );
});

Deno.test("run create refuses ambiguous or expired durable state", async () => {
  const first = harness();
  const result = await runGroupRestoreCycle(config("create"), first.deps);
  assert(result.state === "CREATED");
  // A second create sees the durable result and refuses.
  await rejects(() => runGroupRestoreCycle(config("create"), first.deps));
  // A resume without the durable lifetime refuses.
  const second = harness();
  const journal = first.store.files.get(
    statePath(GROUP_RESTORE_STATE_FILES.journal),
  ) as GroupRestoreJournal;
  assert(journal.length === 3);
  second.store.files.set(statePath(GROUP_RESTORE_STATE_FILES.journal), journal);
  await rejects(() => runGroupRestoreCycle(config("create"), second.deps));
  // An elapsed durable lifetime refuses the resumed create.
  const third = harness();
  third.store.files.set(statePath(GROUP_RESTORE_STATE_FILES.journal), journal);
  third.store.files.set(statePath(GROUP_RESTORE_STATE_FILES.lifetime), {
    startedAtUtc: "2026-09-08T10:30:00.000Z",
    deadlineAtUtc: "2026-09-08T14:30:00.000Z",
  });
  await rejects(() => runGroupRestoreCycle(config("create"), third.deps));
});

Deno.test("run create refuses before any read or provider call without a configured pre-boot isolation verifier", async () => {
  const { store, deps, ports } = harness();
  let reads = 0;
  const unverified: GroupRestoreRunDeps = {
    ...deps,
    preBootIsolationReady: false,
    readJson: <T>(path: string) => {
      reads += 1;
      return (store.readJson as (path: string) => Promise<T>)(path);
    },
  };
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(config("create"), unverified);
    } catch (error) {
      assert(
        String(error).includes(
          "requires a configured pre-boot isolation verifier",
        ),
        "the refusal must name the missing pre-boot isolation verifier",
      );
      throw error;
    }
  });
  assert(reads === 0, "create must refuse before any input or state read");
  assert(store.writePaths.length === 0, "create must refuse before any write");
  assert(
    ports.verifyCalls === 0,
    "create must refuse before any provider call",
  );
});

Deno.test("run create refuses at the pre-boot gate before any instance create", async () => {
  const { store, deps, ports } = harness();
  ports.isolationFailure = true;
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(config("create"), deps);
    } catch (error) {
      assert(
        String(error).includes("pre-boot isolation is not proved"),
        "the pre-boot isolation gate refusal must propagate",
      );
      throw error;
    }
  });
  const journal = persisted(
    GROUP_RESTORE_STATE_FILES.journal,
    store,
  ) as GroupRestoreJournal;
  assert(
    journal.length === 2,
    "only the two restored volumes may be journaled before the gate",
  );
  assert(
    journal.every((entry) => entry.request.kind !== "instance"),
    "the instance create must be refused before the pre-boot gate",
  );
  assert(
    store.files.get(statePath(GROUP_RESTORE_STATE_FILES.result)) === undefined,
    "no durable result may exist while the clone launch is refused",
  );
});

Deno.test("run accept and cleanup still run without the pre-boot isolation verifier", async () => {
  const { deps, store } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  await runGroupRestoreCycle(config("accept"), deps);
  const cleaned = await runGroupRestoreCycle(config("cleanup"), {
    ...deps,
    preBootIsolationReady: false,
  });
  assert(cleaned.state === "CLEANED");
  assert(
    (persisted(
      GROUP_RESTORE_STATE_FILES.result,
      store,
    ) as GroupRestoreExecutionResult).state === "CLEANED",
  );
});

Deno.test("run create rejects an unreadable or malformed durable result rather than treating it as absent", async () => {
  // A durable result that exists but cannot be read must fail closed: a
  // create resumed over it would issue fresh provider mutations and could
  // overwrite the surviving durable record.
  const unreadable = harness();
  unreadable.store.files.set(
    statePath(GROUP_RESTORE_STATE_FILES.result),
    { state: "CREATED" },
  );
  unreadable.store.unreadable.add(
    statePath(GROUP_RESTORE_STATE_FILES.result),
  );
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(config("create"), unreadable.deps);
    } catch (error) {
      assert(
        String(error).includes("permission denied"),
        "the unreadable durable result error must propagate",
      );
      throw error;
    }
  });
  assert(
    unreadable.store.writePaths.length === 0,
    "no durable write may proceed over an unreadable result",
  );
  const malformed = harness();
  malformed.store.files.set(
    statePath(GROUP_RESTORE_STATE_FILES.result),
    { state: "CREATED" },
  );
  malformed.store.malformed.add(statePath(GROUP_RESTORE_STATE_FILES.result));
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(config("create"), malformed.deps);
    } catch (error) {
      assert(
        String(error).includes("Unexpected token in JSON"),
        "the malformed durable result error must propagate",
      );
      throw error;
    }
  });
  assert(
    malformed.store.writePaths.length === 0,
    "no durable write may proceed over a malformed result",
  );
  // Genuine absence of the same optional state still resumes cleanly.
  const fresh = harness();
  const result = await runGroupRestoreCycle(config("create"), fresh.deps);
  assert(result.state === "CREATED");
});

Deno.test("run accept requires the operator receipt and the created state", async () => {
  const { store, deps } = harness();
  await rejects(() => runGroupRestoreCycle(config("accept"), deps));
  await runGroupRestoreCycle(config("create"), deps);
  // Acceptance without the separate operator receipt refuses.
  await rejects(() => runGroupRestoreCycle(config("cleanup"), deps) // cleanup needs receipt? it has one; accept first
  );
  await rejects(() =>
    runGroupRestoreCycle(
      config("create"), // already created
      deps,
    )
  );
  const accepted = await runGroupRestoreCycle(config("accept"), deps);
  assert(accepted.state === "RESTORE_DRILL_PROVED");
  assert(accepted.restoreDrillProved === true);
  assert(accepted.acceptance !== undefined);
  assert(
    (persisted(
      GROUP_RESTORE_STATE_FILES.result,
      store,
    ) as GroupRestoreExecutionResult).state === "RESTORE_DRILL_PROVED",
  );
  // Receipt file for nothing: accept again refuses.
  await rejects(() => runGroupRestoreCycle(config("accept"), deps));
});

Deno.test("run cleanup requires the exact durable acceptance", async () => {
  const { store, deps, ports } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  await runGroupRestoreCycle(config("accept"), deps);
  const cleaned = await runGroupRestoreCycle(config("cleanup"), deps);
  assert(cleaned.state === "CLEANED");
  assert(cleaned.deadlineExceeded === false);
  assert(ports.verifyCalls === 2);
  const saved = persisted(
    GROUP_RESTORE_STATE_FILES.result,
    store,
  ) as GroupRestoreExecutionResult;
  assert(saved.state === "CLEANED");
  // A changed operator receipt differs from the durable acceptance.
  const second = harness();
  await runGroupRestoreCycle(config("create"), second.deps);
  await runGroupRestoreCycle(config("accept"), second.deps);
  second.store.files.set(
    ".private/inputs/acceptance.json",
    { ...receipt(), rootUuid: "11111111-2222-3333-4444-555555555555" },
  );
  await rejects(() => runGroupRestoreCycle(config("cleanup"), second.deps));
  // Cleanup after the deadline still runs and reports the condition.
  const late = harness();
  await runGroupRestoreCycle(config("create"), late.deps);
  await runGroupRestoreCycle(config("accept"), late.deps);
  late.advance(new Date("2026-09-08T18:30:00Z"));
  const lateCleaned = await runGroupRestoreCycle(config("cleanup"), late.deps);
  assert(lateCleaned.state === "CLEANED");
  assert(lateCleaned.deadlineExceeded === true);
});

Deno.test("run cleanup resumes a delete whose intent survived provider loss", async () => {
  const { store, deps, ports } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  await runGroupRestoreCycle(config("accept"), deps);
  ports.deleteFailure = true;
  await rejects(() => runGroupRestoreCycle(config("cleanup"), deps));
  const journalAfterLoss = persisted(
    GROUP_RESTORE_STATE_FILES.journal,
    store,
  ) as GroupRestoreJournal;
  assert(
    journalAfterLoss.some((entry) =>
      entry.intent === "delete" && entry.request.kind === "instance"
    ),
  );
  ports.deleteFailure = false;
  const cleaned = await runGroupRestoreCycle(config("cleanup"), deps);
  assert(cleaned.state === "CLEANED");
});

Deno.test("run cleanup refuses acceptance state derived from nothing", async () => {
  const { store, deps } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  const createdResult = persisted(
    GROUP_RESTORE_STATE_FILES.result,
    store,
  ) as GroupRestoreExecutionResult;
  store.files.set(
    statePath(GROUP_RESTORE_STATE_FILES.result),
    {
      ...createdResult,
      state: "RESTORE_DRILL_PROVED",
      restoreDrillProved: true,
    },
  );
  await rejects(() => runGroupRestoreCycle(config("cleanup"), deps));
});

Deno.test("run cleanup aborts an expired unaccepted CREATED drill without a receipt", async () => {
  const { store, deps, ports, advance } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  assert(
    (persisted(
      GROUP_RESTORE_STATE_FILES.result,
      store,
    ) as GroupRestoreExecutionResult).state === "CREATED",
  );
  // The durable window elapses before any acceptance; the receipt file stays
  // unused and the cleanup never invents acceptance.
  advance(new Date("2026-09-08T18:30:00Z"));
  const cleaned = await runGroupRestoreCycle(
    config("cleanup", { acceptancePath: undefined }),
    deps,
  );
  assert(cleaned.state === "CLEANED");
  assert(cleaned.restoreDrillProved === false);
  assert(cleaned.acceptance === undefined);
  assert(cleaned.deadlineExceeded === true);
  assert(ports.verifyCalls === 2);
  const saved = persisted(
    GROUP_RESTORE_STATE_FILES.result,
    store,
  ) as GroupRestoreExecutionResult;
  assert(saved.state === "CLEANED");
  assert(saved.restoreDrillProved === false);
  assert(saved.acceptance === undefined);
  assert(saved.deadlineExceeded === true);
  const journal = persisted(
    GROUP_RESTORE_STATE_FILES.journal,
    store,
  ) as GroupRestoreJournal;
  assert(journal.filter((entry) => entry.intent === "delete").length === 3);
  assert(
    journal.every((entry) =>
      entry.intent === "create" || entry.completedAtUtc !== undefined
    ),
    "every abort delete intent must be durably completed",
  );
});

Deno.test("run cleanup refuses a receipt-free abort before the deadline", async () => {
  const { store, deps, ports } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  assert(
    (persisted(
      GROUP_RESTORE_STATE_FILES.result,
      store,
    ) as GroupRestoreExecutionResult).deadlineExceeded === false,
  );
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(
        config("cleanup", { acceptancePath: undefined }),
        deps,
      );
    } catch (error) {
      assert(
        String(error).includes("before the drill deadline"),
        "an unaccepted cleanup before the deadline must name the deadline",
      );
      throw error;
    }
  });
  assert(
    (persisted(
      GROUP_RESTORE_STATE_FILES.result,
      store,
    ) as GroupRestoreExecutionResult).state === "CREATED",
    "an unaccepted drill must stay intact before the deadline",
  );
  assert(
    ports.deleteArgv.length === 0,
    "no provider delete may run before the deadline",
  );
});

Deno.test("run cleanup aborts the exact partial journal left by a failed create", async () => {
  const { store, deps, ports, advance } = harness();
  // The create stage fails after both volumes are reconciled, before the
  // isolation proof or the clone launch.
  ports.isolationFailure = true;
  await rejects(() => runGroupRestoreCycle(config("create"), deps));
  assert(
    store.files.get(statePath(GROUP_RESTORE_STATE_FILES.result)) === undefined,
    "a failed create must never write a fake CREATED result",
  );
  const journal = persisted(
    GROUP_RESTORE_STATE_FILES.journal,
    store,
  ) as GroupRestoreJournal;
  assert(journal.length === 2, "both created volumes must be journaled");
  assert(
    journal.every((entry) => Boolean(entry.identity)),
    "both journaled volumes must carry exact reconciled identities",
  );
  assert(
    persisted(GROUP_RESTORE_STATE_FILES.lifetime, store) !== undefined,
    "the durable lifetime must survive the failed create",
  );
  // Only after the durable window elapsed may the exact partial journal be
  // aborted, receipt-free, deleting root then boot and never the instance.
  advance(new Date("2026-09-08T18:31:00.000Z"));
  const cleaned = await runGroupRestoreCycle(
    config("cleanup", { acceptancePath: undefined }),
    deps,
  );
  assert(cleaned.state === "CLEANED");
  assert(cleaned.restoreDrillProved === false);
  assert(cleaned.acceptance === undefined);
  assert(cleaned.deadlineExceeded === true);
  assert(ports.verifyCalls === 2);
  assert(ports.deleteArgv.length === 2);
  assert(ports.deleteArgv[0]!.includes("target-root-volume"));
  assert(ports.deleteArgv[1]!.includes("target-boot-volume"));
  const saved = persisted(
    GROUP_RESTORE_STATE_FILES.result,
    store,
  ) as {
    state: string;
    restoreDrillProved: boolean;
    deadlineExceeded: boolean;
    acceptance?: unknown;
  };
  assert(saved.state === "CLEANED");
  assert(saved.restoreDrillProved === false);
  assert(saved.acceptance === undefined);
  assert(saved.deadlineExceeded === true);
  const savedJournal = persisted(
    GROUP_RESTORE_STATE_FILES.journal,
    store,
  ) as GroupRestoreJournal;
  assert(
    savedJournal.filter((entry) => entry.intent === "delete").length === 2,
    "every partial delete intent must be durably persisted",
  );
  assert(
    savedJournal.every((entry) =>
      entry.intent === "create" || entry.completedAtUtc !== undefined
    ),
    "every partial delete intent must be durably completed",
  );
  // The CLEANED partial state stays terminal: neither acceptance nor another
  // cleanup may run over the persisted result.
  await rejects(() => runGroupRestoreCycle(config("accept"), deps));
  await rejects(() =>
    runGroupRestoreCycle(
      config("cleanup", { acceptancePath: undefined }),
      deps,
    )
  );
});

Deno.test("run cleanup refuses a receipt-free partial abort before the drill deadline", async () => {
  const { store, deps, ports } = harness();
  store.files.set(
    statePath(GROUP_RESTORE_STATE_FILES.lifetime),
    lifetimeFrom("2026-09-08T14:30:00.000Z"),
  );
  store.files.set(
    statePath(GROUP_RESTORE_STATE_FILES.journal),
    createdJournal(["boot-volume", "root-volume"]),
  );
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(
        config("cleanup", { acceptancePath: undefined }),
        deps,
      );
    } catch (error) {
      assert(
        String(error).includes("before the drill deadline"),
        "a partial abort before the deadline must name the deadline",
      );
      throw error;
    }
  });
  assert(
    ports.deleteArgv.length === 0,
    "no partial delete may run before the deadline",
  );
  assert(
    store.files.get(statePath(GROUP_RESTORE_STATE_FILES.result)) === undefined,
    "a refused partial abort must not write a durable result",
  );
});

Deno.test("run cleanup refuses a mismatched or ambiguous partial journal after the deadline", async () => {
  const expired = lifetimeFrom("2026-09-08T10:30:00.000Z");
  const bootRequest = {
    suffix: plan.suffix,
    kind: "boot-volume" as const,
    requestName: groupRestoreDisplayName("boot-volume", plan.suffix),
  };
  const bind = (id: string) => ({ id, name: bootRequest.requestName });
  const cases: GroupRestoreJournal[] = [
    // Nothing was ever reconciled: there is no exact target set.
    [],
    // An unresolved create intent has no exact identity to clean.
    [{
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: "2026-09-08T14:31:00.000Z",
    }],
    // Two create intents for one resource: ambiguous.
    [{
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: "2026-09-08T14:31:00.000Z",
      identity: bind("target-boot-volume"),
    }, {
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: "2026-09-08T14:32:00.000Z",
      identity: bind("target-boot-volume"),
    }],
    // The journaled create identity is a protected production volume.
    [{
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: "2026-09-08T14:31:00.000Z",
      identity: bind(plan.source.bootVolumeId),
    }],
    // The delete identity differs from the recorded create identity.
    [
      ...createdJournal(["boot-volume"]),
      {
        request: bootRequest,
        intent: "delete" as const,
        createdAtUtc: "2026-09-08T17:00:00.000Z",
        identity: bind("other-volume"),
      },
    ],
    // A stale request name is not bound to the reviewed drill.
    [{
      request: {
        suffix: plan.suffix,
        kind: "boot-volume",
        requestName: "other-name",
      },
      intent: "create" as const,
      createdAtUtc: "2026-09-08T14:31:00.000Z",
      identity: { id: "other-boot", name: "other-name" },
    }],
  ];
  for (const journal of cases) {
    const { store, deps, ports } = harness();
    store.files.set(
      statePath(GROUP_RESTORE_STATE_FILES.lifetime),
      expired,
    );
    store.files.set(statePath(GROUP_RESTORE_STATE_FILES.journal), journal);
    await rejects(() =>
      runGroupRestoreCycle(
        config("cleanup", { acceptancePath: undefined }),
        deps,
      )
    );
    assert(
      ports.deleteArgv.length === 0,
      "no partial delete may run for a mismatched or ambiguous journal",
    );
    assert(
      store.files.get(statePath(GROUP_RESTORE_STATE_FILES.result)) ===
        undefined,
      "a refused partial abort must not write a durable result",
    );
  }
});

Deno.test("run cleanup still requires the operator receipt for an accepted drill", async () => {
  const { store, deps } = harness();
  await runGroupRestoreCycle(config("create"), deps);
  await runGroupRestoreCycle(config("accept"), deps);
  await rejects(() =>
    runGroupRestoreCycle(
      config("cleanup", { acceptancePath: undefined }),
      deps,
    )
  );
  assert(
    (persisted(
      GROUP_RESTORE_STATE_FILES.result,
      store,
    ) as GroupRestoreExecutionResult).state === "RESTORE_DRILL_PROVED",
    "an accepted drill must survive a refused receipt-free cleanup",
  );
});

const GATE_UUID = "4b3f5c6d-1e2a-4b8c-9d0e-0123456789ab";

function controllerGate(): unknown {
  return {
    schemaVersion: 1,
    owner: "backblaze-direct",
    state: "active",
    jobId: `job-${GATE_UUID}`,
    periodKey: "2026-09-06",
    generation: `generation-${GATE_UUID}`,
    requestSha256: "0f".repeat(32),
    requestedAtUtc: "2026-09-06T04:00:00.000Z",
    deadlineAtUtc: "2026-09-06T10:00:00.000Z",
    createdAtUtc: "2026-09-06T04:00:01.000Z",
    updatedAtUtc: "2026-09-06T04:00:02.000Z",
    remoteHost: "codex@vps.pavlovcik.com",
    unitName: `arch-vps-b2-worker-${GATE_UUID}.service`,
    unitInvocationId: null,
    sourceLockPath: "/var/tmp/arch-vps-file-backup/source.lock",
  };
}

Deno.test("executable gate wrapper holds the lock, reads the gate and only then runs the cycle", async () => {
  const events: string[] = [];
  const result = await withGroupRestoreControllerGate(() => {
    events.push("work");
    return Promise.resolve("accepted");
  }, {
    lock: async (_path, work) => {
      events.push("lock");
      return await work();
    },
    gate: () => {
      events.push("gate");
      return Promise.resolve(null);
    },
  });
  assert(result === "accepted");
  assert(
    JSON.stringify(events) === JSON.stringify(["lock", "gate", "work"]),
    "the gate must be checked inside the lock and before the cycle",
  );
});

Deno.test("executable gate wrapper refuses the cycle while a controller gate blocks", async () => {
  let calls = 0;
  await rejects(async () => {
    try {
      await withGroupRestoreControllerGate(() => {
        calls += 1;
        return Promise.resolve();
      }, {
        lock: async (_path, work) => await work(),
        gate: () => Promise.resolve(controllerGate()),
      });
    } catch (error) {
      assert(
        String(error).includes("Oracle mutation is blocked"),
        "a valid gate must block the cycle",
      );
      throw error;
    }
  });
  assert(calls === 0, "the cycle must not run while the gate blocks");
});

Deno.test("run entry-point args fail closed without the exact action", async () => {
  await rejects(() => parseGroupRestoreRunArgs([]));
  await rejects(() => parseGroupRestoreRunArgs(["--action", "create"]));
  await rejects(() =>
    parseGroupRestoreRunArgs(["--action", "plan", "--plan", "p"])
  );
  await rejects(() =>
    parseGroupRestoreRunArgs([
      "--action",
      "create",
      "--state-dir",
      ".private/group-restore",
      "--plan",
      "/tmp/plan.json",
      "--approval",
      ".private/inputs/approval.json",
      "--evidence",
      ".private/inputs/evidence.json",
      "--runner",
      ".private/inputs/runner.json",
    ])
  );
  await rejects(() =>
    parseGroupRestoreRunArgs([
      "--action",
      "create",
      "--state-dir",
      ".private/group-restore",
      "--plan",
      ".private/inputs/plan.json",
      "--approval",
      ".private/inputs/approval.json",
      "--evidence",
      ".private/inputs/evidence.json",
      "--runner",
      ".private/inputs/runner.json",
      "--unknown",
      "value",
    ])
  );
  await rejects(() =>
    parseGroupRestoreRunArgs([
      "--action",
      "create",
      "--state-dir",
      ".private/group-restore",
      "--plan",
      ".private/inputs/plan.json",
      "--approval",
      ".private/inputs/approval.json",
      "--evidence",
      ".private/inputs/evidence.json",
      "--runner",
      ".private/inputs/runner.json",
      "--runner",
      ".private/inputs/runner.json",
    ])
  );
  await rejects(() =>
    parseGroupRestoreRunArgs([
      "--action",
      "create",
      "--state-dir",
      ".private/group-restore",
      "--plan",
      ".private/inputs/plan.json",
      "--approval",
      ".private/inputs/approval.json",
      "--evidence",
      ".private/inputs/evidence.json",
      "--runner",
      ".private/../runner.json",
    ])
  );
  const parsed = parseGroupRestoreRunArgs([
    "--action",
    "create",
    "--state-dir",
    ".private/group-restore",
    "--plan",
    ".private/inputs/plan.json",
    "--approval",
    ".private/inputs/approval.json",
    "--evidence",
    ".private/inputs/evidence.json",
    "--preparation",
    ".private/inputs/preparation.json",
    "--runner",
    ".private/inputs/runner.json",
  ]);
  assert(parsed.config.action === "create");
  assert(parsed.config.inputs.acceptancePath === undefined);
  assert(
    parsed.config.inputs.preparationPath === ".private/inputs/preparation.json",
  );
  assert(parsed.runnerPath === ".private/inputs/runner.json");
});

Deno.test("run entry-point create fails closed without a bound preparation configuration", async () => {
  await rejects(() => {
    try {
      parseGroupRestoreRunArgs([
        "--action",
        "create",
        "--state-dir",
        ".private/group-restore",
        "--plan",
        ".private/inputs/plan.json",
        "--approval",
        ".private/inputs/approval.json",
        "--evidence",
        ".private/inputs/evidence.json",
        "--runner",
        ".private/inputs/runner.json",
      ]);
    } catch (error) {
      assert(
        String(error).includes(
          "A bound --preparation private configuration path is required",
        ),
        "create must name the missing preparation configuration",
      );
      throw error;
    }
  });
  await rejects(() =>
    parseGroupRestoreRunArgs([
      "--action",
      "create",
      "--state-dir",
      ".private/group-restore",
      "--plan",
      ".private/inputs/plan.json",
      "--approval",
      ".private/inputs/approval.json",
      "--evidence",
      ".private/inputs/evidence.json",
      "--preparation",
      "/tmp/preparation.json",
      "--runner",
      ".private/inputs/runner.json",
    ])
  );
  await rejects(() =>
    parseGroupRestoreRunArgs([
      "--action",
      "create",
      "--state-dir",
      ".private/group-restore",
      "--plan",
      ".private/inputs/plan.json",
      "--approval",
      ".private/inputs/approval.json",
      "--evidence",
      ".private/inputs/evidence.json",
      "--preparation",
      ".private/../preparation.json",
      "--runner",
      ".private/inputs/runner.json",
    ])
  );
  // Non-create actions do not require the preparation configuration.
  const cleanup = parseGroupRestoreRunArgs([
    "--action",
    "cleanup",
    "--state-dir",
    ".private/group-restore",
    "--plan",
    ".private/inputs/plan.json",
    "--approval",
    ".private/inputs/approval.json",
    "--evidence",
    ".private/inputs/evidence.json",
    "--acceptance",
    ".private/inputs/acceptance.json",
    "--runner",
    ".private/inputs/runner.json",
  ]);
  assert(cleanup.config.inputs.preparationPath === undefined);
});

Deno.test("run create wires the durable attachment-intent store into port construction", async () => {
  const { deps } = harness();
  let received: unknown[] | undefined;
  const forwarded: GroupRestoreRunDeps = {
    ...deps,
    makePorts: (...args) => {
      received = args;
      return deps.makePorts(...args);
    },
  };
  const result = await runGroupRestoreCycle(config("create"), forwarded);
  assert(result.state === "CREATED");
  assert(
    received![2] === deps.attachStateStore,
    "the cycle must forward the durable attachment-intent store to port construction",
  );
});

Deno.test("run attachment-intent store persists the deterministic private file and fails closed on malformed state", async () => {
  const { attachState, store } = harness();
  const key = {
    planSha256: PLAN_SHA,
    helperInstanceId: "helper-instance",
    kind: "boot" as const,
    volumeId: "target-boot-volume",
  };
  const intent = {
    schemaVersion: 1 as const,
    ...key,
    attachRequestedAtUtc: now.toISOString(),
    attachmentId: "boot-attachment",
    attachmentState: "ATTACHED" as const,
    preparationStarted: true,
  };
  await attachState.write(intent);
  const path = statePath(GROUP_RESTORE_STATE_FILES.attachIntents);
  assert(
    store.writePaths.includes(path),
    "the durable intent must land in the deterministic private state file",
  );
  assert(
    JSON.stringify(await attachState.read(key)) === JSON.stringify(intent),
    "the exact helper/plan/kind/volume key must read back the durable intent",
  );
  assert(
    (await attachState.read({ ...key, volumeId: "target-root-volume" })) ===
      undefined,
    "a different exact key is genuinely absent and must never match",
  );
  // Malformed content never reads as absence: the resumed create must fail
  // closed instead of adopting or re-attaching unknown state.
  store.files.set(path, { not: "a list" });
  await rejects(() => attachState.read(key));
  store.malformed.add(path);
  await rejects(() => attachState.read(key));
  // A record with unknown or missing fields is malformed too.
  store.malformed.delete(path);
  store.files.set(path, [{ ...intent, unknownField: "x" }]);
  await rejects(() => attachState.read(key));
  store.files.set(path, [{ ...intent, schemaVersion: 2 }]);
  await rejects(() => attachState.write(intent));
  // Restore a clean file; the malformed earlier content must stay refused
  // rather than being silently discarded.
  store.files.set(path, [{ ...intent }]);
  // A completed record stays for audit under the same exact key rather than
  // being silently dropped by a later write of another key.
  await attachState.write({
    ...intent,
    releaseProvedAtUtc: now.toISOString(),
    detachedAtUtc: now.toISOString(),
  });
  await attachState.write({
    ...intent,
    volumeId: "target-root-volume",
  });
  const records = store.files.get(path) as unknown[];
  assert(
    records.length === 2,
    "other-key writes must preserve the completed audit record",
  );
  assert(
    JSON.stringify(await attachState.read(key)) !== undefined,
    "the completed record must remain readable for audit",
  );
});

Deno.test("run create refuses without a durable attachment-intent store before any read or provider call", async () => {
  const { store, deps, ports } = harness();
  let reads = 0;
  const unbacked: GroupRestoreRunDeps = {
    ...deps,
    attachStateStore:
      undefined as unknown as GroupRestoreRunDeps["attachStateStore"],
    readJson: <T>(path: string) => {
      reads += 1;
      return (store.readJson as (path: string) => Promise<T>)(path);
    },
  };
  await rejects(async () => {
    try {
      await runGroupRestoreCycle(config("create"), unbacked);
    } catch (error) {
      assert(
        String(error).includes("a durable attachment-intent store is required"),
        "the refusal must name the missing attachment-intent store",
      );
      throw error;
    }
  });
  assert(reads === 0, "create must refuse before any input or state read");
  assert(store.writePaths.length === 0, "create must refuse before any write");
  assert(
    ports.verifyCalls === 0,
    "create must refuse before any provider call",
  );
});
