import {
  abortPartialGroupRestoreExecution,
  acceptGroupRestoreExecution,
  buildGroupRestoreDeleteRequest,
  cleanupGroupRestoreExecution,
  DELETE_POLL_BUDGET_MS,
  executeGroupRestoreCreates,
  type GroupRestoreAcceptanceReceipt,
  groupRestoreDeletePollBudgetMs,
  type GroupRestoreExecutionInput,
  type GroupRestoreExecutionPorts,
  type GroupRestoreProductionObservation,
  groupRestoreProductionProbes,
  ociGroupRestorePorts,
  validateGroupRestoreAcceptance,
  verifyGroupRestoreProduction,
} from "../scripts/oci-group-restore-executor.ts";
import {
  type GroupRestoreApproval,
  type GroupRestoreCleanupStep,
  groupRestoreDisplayName,
  type GroupRestoreEvidence,
  type GroupRestoreJournal,
  groupRestoreLifetime,
  type GroupRestoreObservedResource,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  type GroupRestoreResourceRequest,
  type GroupRestoreRunner,
  journalGroupRestoreIntent,
  reconcileGroupRestoreResource,
} from "../scripts/oci-group-restore-drill.ts";
import type { CommandRunner } from "../scripts/oci.ts";

function assert(value: unknown, message = "Assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
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
const approval: GroupRestoreApproval = {
  approvedAtUtc: "2026-09-08T14:00:00.000Z",
  expiresAtUtc: "2026-09-08T14:59:59.999Z",
  exactOperation: "one isolated trial-funded volume-group restore drill",
  planSha256: "pending",
  subscriptionTier: "FREE_AND_TRIAL",
  paymentModel: "FREE_TRIAL",
  availableTrialCreditsUsd: 300,
  estimatedCostUsd: 0.05,
  trialExpiresAtUtc: "2026-09-29T23:59:59.999Z",
  observedAtUtc: "2026-09-08T14:20:00.000Z",
};
const PLAN_SHA = await groupRestorePlanDigest(plan);
approval.planSha256 = PLAN_SHA;

function input(journal: GroupRestoreJournal = []): GroupRestoreExecutionInput {
  return {
    plan,
    approval,
    evidence,
    journal,
    now,
    lifetime: groupRestoreLifetime(now, plan),
  };
}

function requestFor(
  kind: "boot-volume" | "root-volume" | "instance",
): GroupRestoreResourceRequest {
  return {
    suffix: plan.suffix,
    kind,
    requestName: groupRestoreDisplayName(kind, plan.suffix),
  };
}

function trueChecks() {
  return {
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
  };
}

const ROOT_UUID = "9f7e0d1c-2a3b-4c5d-8e9f-001122334455";
const STAGING_UUID = "1a2b3c4d-5e6f-4a7b-8c9d-001122334455";
const SHA256 = "ab".repeat(32);

function receipt(
  observedAtUtc: string = now.toISOString(),
): GroupRestoreAcceptanceReceipt {
  return {
    status: "RESTORE_DRILL_PROVED",
    observedAtUtc,
    suffix: plan.suffix,
    planSha256: PLAN_SHA,
    checks: trueChecks(),
    rootUuid: ROOT_UUID,
    stagingUuid: STAGING_UUID,
    rootPartitionStartSector: 1050624,
    kernelSha256: SHA256,
    initramfsSha256: SHA256,
    grubSha256: SHA256,
  };
}

class FakePorts implements GroupRestoreExecutionPorts {
  resources: GroupRestoreObservedResource[] = [];
  createKinds: string[] = [];
  deleteArgv: string[][] = [];
  verifyCalls = 0;
  isolationCalls: { bootVolumeId: string; rootVolumeId: string }[] = [];
  isolationFailure = false;
  duplicateName?: string;
  private clock: () => Date;

  constructor(clock: () => Date = () => now) {
    this.clock = clock;
  }

  now(): Date {
    return this.clock();
  }

  observe(
    request: GroupRestoreResourceRequest,
  ): Promise<GroupRestoreObservedResource[]> {
    const matching = this.resources.filter((resource) =>
      resource.displayName === request.requestName
    );
    if (this.duplicateName === request.requestName) {
      return Promise.resolve([
        ...matching,
        { id: "duplicate", displayName: request.requestName },
      ]);
    }
    return Promise.resolve(matching);
  }

  create(
    step: {
      kind: string;
      request: GroupRestoreResourceRequest;
      argv: string[];
    },
  ): Promise<GroupRestoreObservedResource[]> {
    this.createKinds.push(step.kind);
    const resource = {
      id: `target-${step.kind}`,
      displayName: step.request.requestName,
    };
    this.resources.push(resource);
    return this.observe(step.request);
  }

  delete(
    step: GroupRestoreCleanupStep,
    identity: { id: string; name: string },
    argv: string[],
  ): Promise<GroupRestoreObservedResource[]> {
    this.deleteArgv.push(argv);
    this.resources = this.resources.filter((resource) =>
      resource.id !== identity.id
    );
    return this.observe(requestFor(step.kind));
  }

  verifyProduction(): Promise<void> {
    this.verifyCalls += 1;
    return Promise.resolve();
  }

  verifyPreBootIsolation(targets: {
    bootVolumeId: string;
    rootVolumeId: string;
  }): Promise<void> {
    if (this.isolationFailure) {
      return Promise.reject(new Error("pre-boot isolation is not proved"));
    }
    this.isolationCalls.push(targets);
    return Promise.resolve();
  }
}

async function created(
  ports = new FakePorts(),
  createdInput: GroupRestoreExecutionInput = input(),
) {
  const result = await executeGroupRestoreCreates(createdInput, runner, ports);
  return { result, ports };
}

Deno.test("executor creates the two volumes then the clone and gates proof", async () => {
  const { result, ports } = await created();
  assert(result.state === "CREATED");
  assert(result.restoreDrillProved === false);
  assert(result.deadlineExceeded === false);
  assert(ports.verifyCalls === 1);
  assert(ports.isolationCalls.length === 1);
  assert(ports.createKinds.indexOf("instance") > 1);
  assert(
    JSON.stringify(ports.createKinds) === JSON.stringify([
      "boot-volume",
      "root-volume",
      "instance",
    ]),
  );
  assert(
    result.lifetime.startedAtUtc === now.toISOString() &&
      result.lifetime.deadlineAtUtc ===
        groupRestoreLifetime(now, plan).deadlineAtUtc,
  );
  const accepted = await acceptGroupRestoreExecution(
    result,
    plan,
    now,
    receipt(),
  );
  assert(accepted.state === "RESTORE_DRILL_PROVED");
  assert(accepted.restoreDrillProved === true);
  assert(accepted.acceptance !== undefined);
});

Deno.test("executor emits deterministic safe create requests", async () => {
  const { result } = await created();
  const entries = result.journal.filter((entry) => entry.intent === "create");
  assert(entries.length === 3);
  const clone = entries.find((entry) => entry.request.kind === "instance");
  assert(clone?.identity?.id === "target-instance");
  const prepared = result.targets;
  assert(prepared.bootVolumeId === "target-boot-volume");
  assert(prepared.rootVolumeId === "target-root-volume");
  assert(prepared.instanceId === "target-instance");
});

Deno.test("executor refuses a clone when pre-boot isolation is not proved", async () => {
  const ports = new FakePorts();
  ports.isolationFailure = true;
  await rejects(() => executeGroupRestoreCreates(input(), runner, ports));
  assertEquals(ports.createKinds, ["boot-volume", "root-volume"]);
  assert(ports.isolationCalls.length === 0);
});

Deno.test("executor rechecks approval immediately before a create", async () => {
  let clock = now.getTime();
  const ports = new FakePorts(() => new Date(clock));
  const originalObserve = ports.observe.bind(ports);
  ports.observe = async (request) => {
    const result = await originalObserve(request);
    clock = Date.parse("2026-09-08T15:00:00.000Z");
    return result;
  };
  await rejects(() => executeGroupRestoreCreates(input(), runner, ports));
  assert(ports.createKinds.length === 0);
});

Deno.test("executor publishes create intent before invoking the provider", async () => {
  const events: string[] = [];
  const ports = new FakePorts();
  const originalCreate = ports.create.bind(ports);
  ports.create = async (step) => {
    events.push(`provider:${step.kind}`);
    return await originalCreate(step);
  };
  const writes: GroupRestoreJournal[] = [];
  await executeGroupRestoreCreates(
    input(),
    runner,
    ports,
    (journal) => {
      writes.push(structuredClone(journal));
      events.push(
        `journal:${journal.length}:${
          journal.at(-1)?.identity ? "identity" : "intent"
        }`,
      );
      return Promise.resolve();
    },
  );
  assert(events[0] === "journal:1:intent");
  assert(events[1] === "provider:boot-volume");
  assert(
    writes.some((journal) => journal.length === 1 && journal[0]!.identity),
  );
  assert(writes.length >= 6);
});

Deno.test("executor resumes a settled create without issuing it again", async () => {
  const request = requestFor("boot-volume");
  let journal = journalGroupRestoreIntent(
    [],
    request,
    "create",
    now.toISOString(),
  );
  journal = reconcileGroupRestoreResource(
    journal,
    request,
    "create",
    [{ id: "target-boot-volume", displayName: request.requestName }],
    now.toISOString(),
  );
  const ports = new FakePorts();
  ports.resources.push({
    id: "target-boot-volume",
    displayName: request.requestName,
  });
  const result = await executeGroupRestoreCreates(
    input(journal),
    runner,
    ports,
  );
  assert(result.state === "CREATED");
  assert(
    JSON.stringify(ports.createKinds) === JSON.stringify([
      "root-volume",
      "instance",
    ]),
  );
});

Deno.test("executor refuses stale or changed approvals", async () => {
  await rejects(() =>
    executeGroupRestoreCreates(
      { ...input(), now: new Date("2026-09-08T15:00:00Z") },
      runner,
      new FakePorts(),
    )
  );
  await rejects(() =>
    executeGroupRestoreCreates(
      { ...input(), approval: { ...approval, planSha256: "0".repeat(64) } },
      runner,
      new FakePorts(),
    )
  );
});

Deno.test("executor refuses duplicate names and unresolved intents", async () => {
  const duplicate = new FakePorts();
  duplicate.duplicateName = groupRestoreDisplayName("boot-volume", plan.suffix);
  await rejects(() => executeGroupRestoreCreates(input(), runner, duplicate));
  const unresolved = [{
    request: requestFor("boot-volume"),
    intent: "create" as const,
    createdAtUtc: now.toISOString(),
  }];
  await rejects(() =>
    executeGroupRestoreCreates(input(unresolved), runner, new FakePorts())
  );
});

Deno.test("executor refuses a resumed create once the lifetime elapsed", async () => {
  const request = requestFor("boot-volume");
  const journal = journalGroupRestoreIntent(
    [],
    request,
    "create",
    "2026-09-08T12:00:00.000Z",
  );
  const elapsed = {
    startedAtUtc: "2026-09-08T10:30:00.000Z",
    deadlineAtUtc: "2026-09-08T14:30:00.000Z",
  };
  await rejects(() =>
    executeGroupRestoreCreates(
      { ...input(journal), lifetime: elapsed },
      runner,
      new FakePorts(),
    )
  );
});

Deno.test("acceptance refuses after the lifetime elapsed", async () => {
  const { result } = await created();
  await rejects(() =>
    acceptGroupRestoreExecution(
      result,
      plan,
      new Date("2026-09-08T18:30:00Z"),
      receipt("2026-09-08T18:00:00.000Z"),
    )
  );
});

Deno.test("acceptance refuses an observation that predates the drill window", async () => {
  const { result } = await created();
  await rejects(() =>
    acceptGroupRestoreExecution(
      result,
      plan,
      now,
      receipt("2026-09-08T10:00:00.000Z"),
    )
  );
});

Deno.test("acceptance validator requires the exact typed receipt", async () => {
  await validateGroupRestoreAcceptance(receipt(), plan, now);
  const missing = {
    ...receipt(),
    checks: { ...receipt().checks },
  } as unknown as Record<string, unknown>;
  delete (missing.checks as Record<string, unknown>)["ssh"];
  await rejects(() =>
    validateGroupRestoreAcceptance(
      missing as unknown as GroupRestoreAcceptanceReceipt,
      plan,
      now,
    )
  );
  const falseCheck = {
    ...receipt(),
    checks: { ...receipt().checks },
  } as unknown as Record<string, unknown>;
  (falseCheck.checks as Record<string, unknown>)["ssh"] = false;
  await rejects(() =>
    validateGroupRestoreAcceptance(
      falseCheck as unknown as GroupRestoreAcceptanceReceipt,
      plan,
      now,
    )
  );
  const extraCheck = receipt() as unknown as Record<string, unknown>;
  (extraCheck.checks as Record<string, unknown>)["runtime"] = true;
  await rejects(() =>
    validateGroupRestoreAcceptance(
      extraCheck as unknown as GroupRestoreAcceptanceReceipt,
      plan,
      now,
    )
  );
  const extraReceipt = receipt() as unknown as Record<string, unknown>;
  extraReceipt["invented"] = true;
  await rejects(() =>
    validateGroupRestoreAcceptance(
      extraReceipt as unknown as GroupRestoreAcceptanceReceipt,
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), observedAtUtc: "2026-09-08T14:31:00.000Z" },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), suffix: "20260101T000000Z" },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), planSha256: "0".repeat(64) },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      {
        ...receipt(),
        status: "METADATA_PROVED",
      } as unknown as GroupRestoreAcceptanceReceipt,
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), rootUuid: "not-a-uuid" },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), stagingUuid: "not-a-uuid" },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), rootPartitionStartSector: -1 },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), rootPartitionStartSector: 1050624.5 },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), kernelSha256: "ab".repeat(31) + "c" },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), initramfsSha256: "ab".repeat(33) },
      plan,
      now,
    )
  );
  await rejects(() =>
    validateGroupRestoreAcceptance(
      { ...receipt(), grubSha256: "AB".repeat(32) },
      plan,
      now,
    )
  );
});

Deno.test("acceptance refuses a forged persisted CREATED result", async () => {
  const { result } = await created();
  await rejects(() =>
    acceptGroupRestoreExecution(
      { ...result, suffix: "20260101T000000Z" },
      plan,
      now,
      receipt(),
    )
  );
  await rejects(() =>
    acceptGroupRestoreExecution(
      {
        ...result,
        targets: { ...result.targets, instanceId: "other-instance" },
      },
      plan,
      now,
      receipt(),
    )
  );
  await rejects(() =>
    acceptGroupRestoreExecution(
      {
        ...result,
        journal: result.journal.slice(0, 2),
      },
      plan,
      now,
      receipt(),
    )
  );
});

Deno.test("cleanup requires proof, uses reverse order and exact identities", async () => {
  const { result, ports } = await created();
  await rejects(() =>
    cleanupGroupRestoreExecution(
      result,
      plan,
      approval,
      evidence,
      runner,
      ports,
      now,
    )
  );
  const accepted = await acceptGroupRestoreExecution(
    result,
    plan,
    now,
    receipt(),
  );
  const cleaned = await cleanupGroupRestoreExecution(
    accepted,
    plan,
    approval,
    evidence,
    runner,
    ports,
    now,
  );
  assert(cleaned.state === "CLEANED");
  assert(cleaned.deadlineExceeded === false);
  assert(ports.verifyCalls === 2);
  assert(ports.deleteArgv.length === 3);
  assert(ports.deleteArgv[0]!.includes("target-instance"));
  assert(ports.deleteArgv[1]!.includes("target-root-volume"));
  assert(ports.deleteArgv[2]!.includes("target-boot-volume"));
  assert(ports.resources.length === 0);
});

Deno.test("cleanup publishes each delete intent before the provider call", async () => {
  const { result, ports } = await created();
  const accepted = await acceptGroupRestoreExecution(
    result,
    plan,
    now,
    receipt(),
  );
  const events: string[] = [];
  const originalDelete = ports.delete.bind(ports);
  ports.delete = async (step, identity, argv) => {
    events.push(`provider:${step.kind}`);
    return await originalDelete(step, identity, argv);
  };
  const writes: GroupRestoreJournal[] = [];
  await cleanupGroupRestoreExecution(
    accepted,
    plan,
    approval,
    evidence,
    runner,
    ports,
    now,
    (journal) => {
      writes.push(structuredClone(journal));
      events.push(
        `journal:${journal.at(-1)?.intent}:${journal.at(-1)?.request.kind}`,
      );
      return Promise.resolve();
    },
  );
  assert(events[0] === "journal:delete:instance");
  assert(events[1] === "provider:instance");
  assert(
    writes.some((journal) =>
      journal.at(-1)?.intent === "delete" && !journal.at(-1)?.completedAtUtc
    ),
  );
  assert(writes.length >= 6);
});

Deno.test("cleanup stays allowed after the deadline and reports it", async () => {
  // The live adapter clock reports the deadline as elapsed; cleanup remains
  // allowed and reports the condition in the result.
  let elapsed = false;
  const ports = new FakePorts(() =>
    elapsed ? new Date("2026-09-08T18:30:00Z") : now
  );
  const { result } = await created(ports);
  const accepted = await acceptGroupRestoreExecution(
    result,
    plan,
    now,
    receipt(),
  );
  elapsed = true;
  const cleaned = await cleanupGroupRestoreExecution(
    accepted,
    plan,
    approval,
    evidence,
    runner,
    ports,
    new Date("2026-09-08T18:30:00Z"),
  );
  assert(cleaned.state === "CLEANED");
  assert(cleaned.deadlineExceeded === true);
  assert(ports.resources.length === 0);
});

Deno.test("cleanup refuses without the explicit acceptance state", async () => {
  const { result, ports } = await created();
  const forged = { ...result, state: "RESTORE_DRILL_PROVED" as const };
  await rejects(() =>
    cleanupGroupRestoreExecution(
      forged,
      plan,
      approval,
      evidence,
      runner,
      ports,
      now,
    )
  );
});

Deno.test("abort cleanup deletes an expired unaccepted CREATED drill without a receipt", async () => {
  let clock = now;
  const ports = new FakePorts(() => clock);
  const { result } = await created(ports);
  assert(result.state === "CREATED");
  assert(result.restoreDrillProved === false);
  clock = new Date("2026-09-08T18:30:00Z");
  const cleaned = await cleanupGroupRestoreExecution(
    result,
    plan,
    approval,
    evidence,
    runner,
    ports,
    clock,
  );
  assert(cleaned.state === "CLEANED");
  assert(cleaned.restoreDrillProved === false);
  assert(cleaned.acceptance === undefined);
  assert(
    cleaned.journal.every((entry) =>
      entry.intent === "create" || entry.completedAtUtc !== undefined
    ),
  );
  assert(cleaned.deadlineExceeded === true);
  assert(ports.verifyCalls === 2);
  assert(ports.resources.length === 0);
  assert(ports.deleteArgv.length === 3);
  assert(ports.deleteArgv[0]!.includes("target-instance"));
  assert(ports.deleteArgv[1]!.includes("target-root-volume"));
  assert(ports.deleteArgv[2]!.includes("target-boot-volume"));
});

Deno.test("abort cleanup publishes each delete intent before the provider call", async () => {
  let clock = now;
  const ports = new FakePorts(() => clock);
  const { result } = await created(ports);
  clock = new Date("2026-09-08T18:30:00Z");
  const events: string[] = [];
  const originalDelete = ports.delete.bind(ports);
  ports.delete = async (step, identity, argv) => {
    events.push(`provider:${step.kind}`);
    return await originalDelete(step, identity, argv);
  };
  const writes: GroupRestoreJournal[] = [];
  await cleanupGroupRestoreExecution(
    result,
    plan,
    approval,
    evidence,
    runner,
    ports,
    clock,
    (journal) => {
      writes.push(structuredClone(journal));
      events.push(
        `journal:${journal.at(-1)?.intent}:${journal.at(-1)?.request.kind}`,
      );
      return Promise.resolve();
    },
  );
  assert(events[0] === "journal:delete:instance");
  assert(events[1] === "provider:instance");
  assert(
    writes.some((journal) =>
      journal.at(-1)?.intent === "delete" && !journal.at(-1)?.completedAtUtc
    ),
  );
  assert(writes.length >= 6);
});

Deno.test("abort cleanup refuses an unaccepted CREATED drill before the deadline", async () => {
  const { result, ports } = await created();
  await rejects(async () => {
    try {
      await cleanupGroupRestoreExecution(
        result,
        plan,
        approval,
        evidence,
        runner,
        ports,
        now,
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
    ports.deleteArgv.length === 0,
    "no delete may run for an unaccepted drill before the deadline",
  );
});

Deno.test("abort cleanup validates the exact created target identities", async () => {
  let clock = now;
  const ports = new FakePorts(() => clock);
  const { result } = await created(ports);
  clock = new Date("2026-09-08T18:30:00Z");
  await rejects(() =>
    cleanupGroupRestoreExecution(
      {
        ...result,
        targets: { ...result.targets, instanceId: "other-instance" },
      },
      plan,
      approval,
      evidence,
      runner,
      ports,
      clock,
    )
  );
  assert(
    ports.deleteArgv.length === 0,
    "no delete may run for an unproved target identity",
  );
});

Deno.test("abort cleanup refuses invented acceptance on a CREATED result", async () => {
  let clock = now;
  const ports = new FakePorts(() => clock);
  const { result } = await created(ports);
  clock = new Date("2026-09-08T18:30:00Z");
  await rejects(() =>
    cleanupGroupRestoreExecution(
      { ...result, acceptance: receipt() },
      plan,
      approval,
      evidence,
      runner,
      ports,
      clock,
    )
  );
  assert(
    ports.deleteArgv.length === 0,
    "no delete may run under an invented acceptance",
  );
});

function partialJournal(
  kinds: Array<"boot-volume" | "root-volume" | "instance">,
): GroupRestoreJournal {
  let journal: GroupRestoreJournal = [];
  for (const kind of kinds) {
    const request = requestFor(kind);
    journal = journalGroupRestoreIntent(
      journal,
      request,
      "create",
      now.toISOString(),
    );
    journal = reconcileGroupRestoreResource(
      journal,
      request,
      "create",
      [{ id: `target-${kind}`, displayName: request.requestName }],
      now.toISOString(),
    );
  }
  return journal;
}

Deno.test("partial abort refuses before the deadline and runs nothing", async () => {
  const clock = now;
  const ports = new FakePorts(() => clock);
  const journal = partialJournal(["boot-volume", "root-volume"]);
  const lifetime = groupRestoreLifetime(now, plan);
  await rejects(async () => {
    try {
      await abortPartialGroupRestoreExecution(
        plan,
        evidence,
        runner,
        ports,
        lifetime,
        journal,
        now,
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
});

Deno.test("partial abort deletes only exact journaled resources after the deadline", async () => {
  const clock = new Date("2026-09-08T18:31:00.000Z");
  const ports = new FakePorts(() => clock);
  const journal = partialJournal(["boot-volume", "root-volume"]);
  const cleaned = await abortPartialGroupRestoreExecution(
    plan,
    evidence,
    runner,
    ports,
    groupRestoreLifetime(now, plan),
    journal,
    clock,
  );
  assert(cleaned.state === "CLEANED");
  assert(cleaned.restoreDrillProved === false);
  assert(cleaned.acceptance === undefined);
  assert(cleaned.deadlineExceeded === true);
  assert(cleaned.targets.bootVolumeId === "target-boot-volume");
  assert(cleaned.targets.rootVolumeId === "target-root-volume");
  assert(cleaned.targets.instanceId === undefined);
  assert(ports.deleteArgv.length === 2);
  assert(ports.deleteArgv[0]!.includes("target-root-volume"));
  assert(ports.deleteArgv[1]!.includes("target-boot-volume"));
  assert(ports.verifyCalls === 1);
  assert(
    cleaned.journal.every((entry) =>
      entry.intent === "create" || entry.completedAtUtc !== undefined
    ),
    "every partial delete intent must be durably completed",
  );
});

Deno.test("partial abort deletes the instance first when it is journaled", async () => {
  let clock = now;
  const ports = new FakePorts(() => clock);
  const journal = partialJournal(["boot-volume", "root-volume", "instance"]);
  const lifetime = groupRestoreLifetime(now, plan);
  clock = new Date("2026-09-08T18:31:00.000Z");
  const cleaned = await abortPartialGroupRestoreExecution(
    plan,
    evidence,
    runner,
    ports,
    lifetime,
    journal,
    clock,
  );
  assert(ports.deleteArgv.length === 3);
  assert(ports.deleteArgv[0]!.includes("target-instance"));
  assert(ports.deleteArgv[1]!.includes("target-root-volume"));
  assert(ports.deleteArgv[2]!.includes("target-boot-volume"));
  assert(cleaned.targets.instanceId === "target-instance");
});

Deno.test("partial abort reconciles a surviving delete intent before continuing", async () => {
  let clock = now;
  const ports = new FakePorts(() => clock);
  const rootRequest = requestFor("root-volume");
  const journal: GroupRestoreJournal = [
    ...partialJournal(["boot-volume", "root-volume"]),
    {
      request: rootRequest,
      intent: "delete",
      createdAtUtc: "2026-09-08T17:00:00.000Z",
      identity: {
        id: "target-root-volume",
        name: rootRequest.requestName,
      },
    },
  ];
  // The earlier provider delete already removed the root volume; only the
  // response was lost, so the surviving intent must be reconciled first.
  ports.resources.push({
    id: "target-boot-volume",
    displayName: requestFor("boot-volume").requestName,
  });
  clock = new Date("2026-09-08T18:31:00.000Z");
  const cleaned = await abortPartialGroupRestoreExecution(
    plan,
    evidence,
    runner,
    ports,
    groupRestoreLifetime(now, plan),
    journal,
    clock,
  );
  assert(cleaned.state === "CLEANED");
  assert(ports.deleteArgv.length === 1);
  assert(ports.deleteArgv[0]!.includes("target-boot-volume"));
  assert(
    cleaned.journal.filter((entry) => entry.intent === "delete").length === 2,
  );
  assert(
    cleaned.journal.every((entry) =>
      entry.intent === "create" || entry.completedAtUtc !== undefined
    ),
  );
});

Deno.test("partial abort refuses mismatched, ambiguous or protected journals", async () => {
  const after = new Date("2026-09-08T18:31:00.000Z");
  const createdEntries = partialJournal(["boot-volume"]);
  const bootRequest = requestFor("boot-volume");
  const binding = (id: string) => ({
    id,
    name: bootRequest.requestName,
  });
  const cases: GroupRestoreJournal[] = [
    // Nothing was ever reconciled: there is no exact target set.
    [],
    // An unresolved create intent has no exact identity to clean.
    [{
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: now.toISOString(),
    }],
    // Two create intents for one resource: ambiguous.
    [...createdEntries, {
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: now.toISOString(),
      identity: binding("target-boot-volume"),
    }],
    // The journaled create identity is a protected production volume.
    [{
      request: bootRequest,
      intent: "create" as const,
      createdAtUtc: now.toISOString(),
      identity: binding(plan.source.bootVolumeId),
    }],
    // The delete identity differs from the recorded create identity.
    [...createdEntries, {
      request: bootRequest,
      intent: "delete" as const,
      createdAtUtc: now.toISOString(),
      identity: binding("other-volume"),
    }],
    // A stale request name is not bound to the reviewed drill.
    [{
      request: {
        suffix: plan.suffix,
        kind: "boot-volume",
        requestName: "other-name",
      },
      intent: "create" as const,
      createdAtUtc: now.toISOString(),
      identity: { id: "other-boot", name: "other-name" },
    }],
    // The journal for another drill suffix is not this plan's journal.
    [{
      request: {
        suffix: "20260101T000000Z",
        kind: "boot-volume",
        requestName: "arch-oracle-drill-boot-20260101T000000Z",
      },
      intent: "create" as const,
      createdAtUtc: now.toISOString(),
      identity: {
        id: "other-drill-boot",
        name: "arch-oracle-drill-boot-20260101T000000Z",
      },
    }],
  ];
  for (const journal of cases) {
    const ports = new FakePorts(() => after);
    await rejects(() =>
      abortPartialGroupRestoreExecution(
        plan,
        evidence,
        runner,
        ports,
        groupRestoreLifetime(now, plan),
        journal,
        after,
      )
    );
    assert(
      ports.deleteArgv.length === 0,
      "no partial delete may run for a mismatched or ambiguous journal",
    );
  }
  // The evidence binding is still validated before any delete.
  const ports = new FakePorts(() => after);
  await rejects(() =>
    abortPartialGroupRestoreExecution(
      plan,
      { ...evidence, group: { ...evidence.group, id: "other-capture" } },
      runner,
      ports,
      groupRestoreLifetime(now, plan),
      partialJournal(["boot-volume"]),
      after,
    )
  );
  assert(ports.deleteArgv.length === 0);
});

Deno.test("cleanup refuses a wrong live identity and protected delete IDs", async () => {
  const { result, ports } = await created();
  const accepted = await acceptGroupRestoreExecution(
    result,
    plan,
    now,
    receipt(),
  );
  ports.resources = ports.resources.map((resource) =>
    resource.displayName === groupRestoreDisplayName("instance", plan.suffix)
      ? { id: "wrong-instance", displayName: resource.displayName }
      : resource
  );
  await rejects(() =>
    cleanupGroupRestoreExecution(
      accepted,
      plan,
      approval,
      evidence,
      runner,
      ports,
      now,
    )
  );
  await rejects(() =>
    buildGroupRestoreDeleteRequest(
      plan,
      groupRestoreCleanupOrderFor("instance"),
      {
        id: plan.source.instanceId,
        name: groupRestoreDisplayName("instance", plan.suffix),
      },
      runner,
    )
  );
});

function groupRestoreCleanupOrderFor(
  kind: "instance" | "root-volume" | "boot-volume",
): GroupRestoreCleanupStep {
  return {
    kind,
    requestName: groupRestoreDisplayName(kind, plan.suffix),
    action: "delete",
  };
}

function capturingRunner(
  responses: Record<string, { data: unknown }>,
): { runner: GroupRestoreRunner; calls: string[][] } {
  const calls: string[][] = [];
  const run: CommandRunner = (_command, args) => {
    calls.push(args);
    const joined = args.join(" ");
    const key = Object.keys(responses).find((name) => joined.includes(name));
    const response = key ? responses[key] : { data: [] };
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify(response),
      stderr: "",
    });
  };
  return { runner: { ...runner, run }, calls };
}

Deno.test("adapter calls carry bounded no-retry discipline and JSON output", async () => {
  const captured = capturingRunner({ "boot-volume": { data: [] } });
  const ports = ociGroupRestorePorts(plan, captured.runner);
  const observed = await ports.observe(requestFor("boot-volume"));
  assert(observed.length === 0);
  assert(captured.calls.length === 1);
  const argv = captured.calls[0]!;
  const list = argv.indexOf("bv");
  for (const flag of ["--no-retry", "--connection-timeout", "--read-timeout"]) {
    assert(argv.includes(flag), `missing ${flag}`);
    assert(argv.indexOf(flag) < list, `${flag} must precede the subcommand`);
  }
  assert(argv[argv.length - 2] === "--output");
  assert(argv[argv.length - 1] === "json");
  for (
    const forbidden of ["--opc-retry-token", "--opc-request-id"]
  ) {
    assert(!argv.includes(forbidden), `unexpected ${forbidden}`);
  }
  await rejects(() =>
    ports.verifyPreBootIsolation({
      bootVolumeId: "target-boot-volume",
      rootVolumeId: "target-root-volume",
    })
  );
});

Deno.test("delete polling is bounded by a short lifetime-derived budget", async () => {
  assert(
    groupRestoreDeletePollBudgetMs(plan, undefined, 0) ===
      DELETE_POLL_BUDGET_MS,
  );
  const far = {
    startedAtUtc: "2026-09-08T14:00:00.000Z",
    deadlineAtUtc: "2026-09-09T14:00:00.000Z",
  };
  assert(
    groupRestoreDeletePollBudgetMs(plan, far, 0) === DELETE_POLL_BUDGET_MS,
  );
  const near = {
    startedAtUtc: "2026-09-08T14:00:00.000Z",
    deadlineAtUtc: "2026-09-08T14:00:30.000Z",
  };
  assert(
    groupRestoreDeletePollBudgetMs(
      plan,
      near,
      Date.parse(near.startedAtUtc),
    ) ===
      30_000,
  );
  assert(
    groupRestoreDeletePollBudgetMs(
      plan,
      near,
      Date.parse(near.deadlineAtUtc),
    ) ===
      0,
  );
  let clock = Date.parse("2026-09-08T14:00:00.000Z");
  const lingering = capturingRunner({
    "volume list": {
      data: [{
        id: "target-root-volume",
        "display-name": groupRestoreDisplayName("root-volume", plan.suffix),
        "lifecycle-state": "AVAILABLE",
      }],
    },
  });
  const lingeringPorts = ociGroupRestorePorts(plan, lingering.runner, {
    lifetime: near,
    now: () => {
      clock += 10_000;
      return clock;
    },
    sleep: () => Promise.resolve(),
  });
  const live = await lingeringPorts.delete(
    groupRestoreCleanupOrderFor("root-volume"),
    {
      id: "target-root-volume",
      name: groupRestoreDisplayName("root-volume", plan.suffix),
    },
    ["delete"],
  );
  assert(
    live.length === 1,
    "delete poll must stay bounded and return live rows",
  );
  assert(
    lingering.calls.length < 10,
    "a lingering delete must not poll forever",
  );
});

function goodObservation(): GroupRestoreProductionObservation {
  return {
    instance: {
      id: plan.source.instanceId,
      "compartment-id": plan.source.compartmentId,
      "lifecycle-state": "RUNNING",
      shape: "VM.Standard.A1.Flex",
      "shape-config": { ocpus: 2, "memory-in-gbs": 12 },
      "availability-domain": plan.availabilityDomain,
    },
    bootAttachments: [{
      "boot-volume-id": plan.source.bootVolumeId,
      "instance-id": plan.source.instanceId,
      "lifecycle-state": "ATTACHED",
    }],
    volumeAttachments: [{
      "volume-id": plan.source.rootVolumeId,
      "instance-id": plan.source.instanceId,
      "attachment-type": "paravirtualized",
      "lifecycle-state": "ATTACHED",
    }],
    vnicAttachments: [{
      "vnic-id": "source-vnic",
      "instance-id": plan.source.instanceId,
      "lifecycle-state": "ATTACHED",
    }],
    bootVolume: {
      id: plan.source.bootVolumeId,
      "compartment-id": plan.source.compartmentId,
      "size-in-gbs": 50,
    },
    rootVolume: {
      id: plan.source.rootVolumeId,
      "compartment-id": plan.source.compartmentId,
      "size-in-gbs": 150,
    },
    publicIps: [{
      id: plan.productionReservedIpId,
      "lifecycle-state": "ASSIGNED",
      "private-ip-id": "source-private-ip",
    }],
    privateIps: [{
      id: "source-private-ip",
      "vnic-id": "source-vnic",
      "compartment-id": plan.source.compartmentId,
      "subnet-id": plan.productionSubnetId,
    }],
    volumeGroup: {
      id: plan.volumeGroupId,
      "volume-ids": [plan.source.bootVolumeId, plan.source.rootVolumeId],
    },
  };
}

Deno.test("production probes carry the exact supported read-only CLI syntax", () => {
  const probes = groupRestoreProductionProbes(plan);
  const byName = Object.fromEntries(probes.map((probe) => [
    probe.name,
    probe,
  ]));
  assertEquals(
    byName["instance"].args,
    ["compute", "instance", "get", "--instance-id", plan.source.instanceId],
  );
  // Reserved public IPs require REGION scope with no availability domain and
  // the RESERVED lifetime filter; ephemeral IPs are availability-domain scoped.
  assertEquals(
    byName["publicIps"].args,
    [
      "network",
      "public-ip",
      "list",
      "--compartment-id",
      plan.source.compartmentId,
      "--scope",
      "REGION",
      "--lifetime",
      "RESERVED",
      "--all",
    ],
  );
  // The VNIC attachment list is scoped to the reviewed instance (the existing
  // repository form); the private-IP list is scoped to the reviewed production
  // subnet because private-ip list only supports the exact subnet/vnic filter
  // (there is no tenancy-wide unscoped or compartment filter), and the
  // verifier still proves the compartment binding of each returned row. No
  // probe may depend on a live private-IP identity it has not read yet.
  assertEquals(
    byName["vnicAttachments"].args,
    [
      "compute",
      "vnic-attachment",
      "list",
      "--compartment-id",
      plan.source.compartmentId,
      "--instance-id",
      plan.source.instanceId,
      "--all",
    ],
  );
  assertEquals(
    byName["privateIps"].args,
    [
      "network",
      "private-ip",
      "list",
      "--subnet-id",
      plan.productionSubnetId,
      "--all",
    ],
  );
  assert(
    !JSON.stringify(probes).includes("--private-ip-id"),
    "probes must not carry a dynamic, unbound private-IP argument",
  );
  // There is no OCI CLI volume-group-member command: member accounting is
  // proved from the volume group object's volume-ids list.
  assertEquals(
    byName["volumeGroup"].args,
    ["bv", "volume-group", "get", "--volume-group-id", plan.volumeGroupId],
  );
  assert(
    !JSON.stringify(probes).includes("volume-group-member"),
    "probes must not use a nonexistent volume-group-member command",
  );
  for (const probe of probes) {
    assert(
      probe.kind === "object" || probe.kind === "array",
      "probe kinds must stay object/array",
    );
  }
});

Deno.test("executor re-checks the lifetime with the live clock at each create boundary", async () => {
  let clock = Date.parse(now.toISOString());
  const ports = new FakePorts(() => new Date(clock));
  const originalCreate = ports.create.bind(ports);
  ports.create = async (step) => {
    const created = await originalCreate(step);
    // The first long provider create crosses the durable deadline while the
    // run-start input.now is still well inside the window.
    clock = Date.parse("2026-09-08T18:31:00.000Z");
    return created;
  };
  await rejects(() => executeGroupRestoreCreates(input(), runner, ports));
  assert(
    JSON.stringify(ports.createKinds) === JSON.stringify(["boot-volume"]),
    "the second create must be refused once the live clock passed the deadline",
  );
});

Deno.test("production verifier never weakens the online invariant", async () => {
  verifyGroupRestoreProduction(plan, goodObservation());
  const cases: GroupRestoreProductionObservation[] = [
    {
      ...goodObservation(),
      instance: {
        ...goodObservation().instance,
        "lifecycle-state": "STOPPED",
      },
    },
    {
      ...goodObservation(),
      instance: {
        ...goodObservation().instance,
        "shape-config": { ocpus: 4, "memory-in-gbs": 24 },
      },
    },
    {
      ...goodObservation(),
      instance: {
        ...goodObservation().instance,
        "availability-domain": "AD-2",
      },
    },
    {
      ...goodObservation(),
      volumeAttachments: [],
    },
    {
      ...goodObservation(),
      bootVolume: { ...goodObservation().rootVolume, id: "other" },
    },
    {
      ...goodObservation(),
      rootVolume: {
        ...goodObservation().rootVolume,
        "size-in-gbs": 100,
      },
    },
    {
      ...goodObservation(),
      publicIps: [{
        id: plan.productionReservedIpId,
        "lifecycle-state": "ASSIGNED",
      }, {
        id: "extra-ip",
        "lifecycle-state": "ASSIGNED",
      }],
    },
    {
      ...goodObservation(),
      volumeGroup: {
        id: plan.volumeGroupId,
        "volume-ids": [plan.source.bootVolumeId],
      },
    },
    {
      ...goodObservation(),
      volumeGroup: { id: plan.volumeGroupId },
    },
    {
      ...goodObservation(),
      bootAttachments: [{
        "boot-volume-id": "other-boot",
        "instance-id": plan.source.instanceId,
      }],
    },
    {
      // A detached source boot attachment must fail the ATTACHED requirement.
      ...goodObservation(),
      bootAttachments: [{
        "boot-volume-id": plan.source.bootVolumeId,
        "instance-id": plan.source.instanceId,
        "lifecycle-state": "DETACHED",
      }],
    },
    {
      // A detached source root attachment must fail the ATTACHED requirement.
      ...goodObservation(),
      volumeAttachments: [{
        "volume-id": plan.source.rootVolumeId,
        "instance-id": plan.source.instanceId,
        "attachment-type": "paravirtualized",
        "lifecycle-state": "DETACHED",
      }],
    },
    {
      // The reserved IP record without a bound private-ip-id is not proof.
      ...goodObservation(),
      publicIps: [{
        id: plan.productionReservedIpId,
        "lifecycle-state": "ASSIGNED",
      }],
    },
    {
      ...goodObservation(),
      publicIps: [{
        id: plan.productionReservedIpId,
        "lifecycle-state": "ASSIGNED",
        "private-ip-id": "",
      }],
    },
    {
      // No private IP matches the reserved IP binding.
      ...goodObservation(),
      privateIps: [],
    },
    {
      // Two private IP rows claim the same matching identity: ambiguous.
      ...goodObservation(),
      privateIps: [
        {
          id: "source-private-ip",
          "vnic-id": "source-vnic",
          "compartment-id": plan.source.compartmentId,
        },
        {
          id: "source-private-ip",
          "vnic-id": "other-vnic",
          "compartment-id": plan.source.compartmentId,
        },
      ],
    },
    {
      // The matching private IP lives outside the reviewed compartment: the
      // observation must stay scoped to the reviewed compartment.
      ...goodObservation(),
      privateIps: [{
        id: "source-private-ip",
        "vnic-id": "source-vnic",
        "compartment-id": "other-compartment",
      }],
    },
    {
      ...goodObservation(),
      privateIps: [{
        id: "source-private-ip",
      }],
    },
    {
      // The private IP's VNIC has no ATTACHED attachment on the reviewed
      // instance: the reserved IP is effectively reassigned away.
      ...goodObservation(),
      vnicAttachments: [{
        "vnic-id": "source-vnic",
        "instance-id": plan.source.instanceId,
        "lifecycle-state": "DETACHED",
      }],
    },
    {
      ...goodObservation(),
      vnicAttachments: [{
        "vnic-id": "source-vnic",
        "instance-id": "other-instance",
        "lifecycle-state": "ATTACHED",
      }],
    },
    {
      // Two ATTACHED attachments may not claim the same VNIC.
      ...goodObservation(),
      vnicAttachments: [{
        "vnic-id": "source-vnic",
        "instance-id": plan.source.instanceId,
        "lifecycle-state": "ATTACHED",
      }, {
        "vnic-id": "source-vnic",
        "instance-id": plan.source.instanceId,
        "lifecycle-state": "ATTACHED",
      }],
    },
  ];
  for (const bad of cases) {
    await rejects(() => verifyGroupRestoreProduction(plan, bad));
  }
});
