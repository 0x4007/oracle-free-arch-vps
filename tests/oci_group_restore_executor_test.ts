import {
  acceptGroupRestoreExecution,
  buildGroupRestoreDeleteRequest,
  cleanupGroupRestoreExecution,
  executeGroupRestoreCreates,
  type GroupRestoreAcceptanceEvidence,
  type GroupRestoreExecutionInput,
  type GroupRestoreExecutionPorts,
} from "../scripts/oci-group-restore-executor.ts";
import {
  type GroupRestoreApproval,
  type GroupRestoreCleanupStep,
  groupRestoreDisplayName,
  type GroupRestoreEvidence,
  type GroupRestoreJournal,
  type GroupRestoreObservedResource,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  type GroupRestoreResourceRequest,
  type GroupRestoreRunner,
  journalGroupRestoreIntent,
  reconcileGroupRestoreResource,
} from "../scripts/oci-group-restore-drill.ts";

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
  planSha256: await groupRestorePlanDigest(plan),
};

function input(journal: GroupRestoreJournal = []): GroupRestoreExecutionInput {
  return { plan, approval, evidence, journal, now };
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

class FakePorts implements GroupRestoreExecutionPorts {
  resources: GroupRestoreObservedResource[] = [];
  createKinds: string[] = [];
  deleteArgv: string[][] = [];
  duplicateName?: string;

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
}

async function created(
  ports = new FakePorts(),
) {
  const result = await executeGroupRestoreCreates(input(), runner, ports);
  return { result, ports };
}

Deno.test("executor creates the two volumes then the clone and gates proof", async () => {
  const { result, ports } = await created();
  assert(result.state === "CREATED");
  assert(result.restoreDrillProved === false);
  assert(
    JSON.stringify(ports.createKinds) === JSON.stringify([
      "boot-volume",
      "root-volume",
      "instance",
    ]),
  );
  const accepted = await acceptGroupRestoreExecution(
    result,
    now,
    (): Promise<GroupRestoreAcceptanceEvidence> =>
      Promise.resolve({
        status: "RESTORE_DRILL_PROVED",
        observedAtUtc: now.toISOString(),
        checks: { ssh: true, mounts: true, applications: true },
      }),
  );
  assert(accepted.state === "RESTORE_DRILL_PROVED");
  assert(accepted.restoreDrillProved === true);
});

Deno.test("executor emits deterministic safe create requests", async () => {
  const { result } = await created();
  const entries = result.journal.filter((entry) => entry.intent === "create");
  assert(entries.length === 3);
  const clone = entries.find((entry) => entry.request.kind === "instance");
  assert(clone?.identity?.id === "target-instance");
  // The launch request is built only after the restored volume identities exist.
  const prepared = result.targets;
  assert(prepared.bootVolumeId === "target-boot-volume");
  assert(prepared.rootVolumeId === "target-root-volume");
  assert(prepared.instanceId === "target-instance");
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
  const { result } = await createdWithJournal(journal, ports);
  assert(result.state === "CREATED");
  assert(
    JSON.stringify(ports.createKinds) === JSON.stringify([
      "root-volume",
      "instance",
    ]),
  );
});

async function createdWithJournal(
  journal: GroupRestoreJournal,
  ports: FakePorts,
) {
  return {
    result: await executeGroupRestoreCreates(input(journal), runner, ports),
    ports,
  };
}

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
    now,
    () =>
      Promise.resolve({
        status: "RESTORE_DRILL_PROVED",
        observedAtUtc: now.toISOString(),
        checks: { runtime: true },
      }),
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
  assert(ports.deleteArgv.length === 3);
  assert(ports.deleteArgv[0]!.includes("target-instance"));
  assert(ports.deleteArgv[1]!.includes("target-root-volume"));
  assert(ports.deleteArgv[2]!.includes("target-boot-volume"));
  assert(ports.resources.length === 0);
});

Deno.test("cleanup refuses a wrong live identity and protected delete IDs", async () => {
  const { result, ports } = await created();
  const accepted = await acceptGroupRestoreExecution(
    result,
    now,
    () =>
      Promise.resolve({
        status: "RESTORE_DRILL_PROVED",
        observedAtUtc: now.toISOString(),
        checks: { runtime: true },
      }),
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
