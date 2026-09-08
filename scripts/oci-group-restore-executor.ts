/**
 * Journaled execution ports for an isolated Oracle volume-group restore drill.
 *
 * The provider calls are injected so the state machine can be tested without
 * credentials or a cloud side effect. The Pi supplies the OCI adapter at run
 * time. This module never treats a returned plan or metadata check as a live
 * restore proof; only the explicit acceptance callback can do that.
 */
import {
  buildGroupRestoreLaunchRequest,
  buildRestoredBootVolumeRequest,
  buildRestoredRootVolumeRequest,
  type GroupRestoreApproval,
  groupRestoreCleanupOrder,
  type GroupRestoreCleanupStep,
  groupRestoreCliArgs,
  groupRestoreDisplayName,
  type GroupRestoreEvidence,
  type GroupRestoreIdentity,
  type GroupRestoreJournal,
  type GroupRestoreObservedResource,
  type GroupRestorePlan,
  type GroupRestoreResourceKind,
  type GroupRestoreResourceRequest,
  type GroupRestoreRunner,
  type GroupRestoreRunStep,
  type GroupRestoreTargetResources,
  journalGroupRestoreIntent,
  reconcileGroupRestoreResource,
  validateGroupRestoreApproval,
  validateGroupRestoreEvidence,
  validateGroupRestoreJournal,
  validateGroupRestorePlan,
  validateGroupRestoreTargets,
} from "./oci-group-restore-drill.ts";
import { dataArray, type JsonRecord, redactOcid } from "./oci.ts";

export interface GroupRestoreExecutionInput {
  plan: GroupRestorePlan;
  approval: GroupRestoreApproval;
  evidence: GroupRestoreEvidence;
  journal: GroupRestoreJournal;
  now: Date;
}

export interface GroupRestoreAcceptanceEvidence {
  status: "RESTORE_DRILL_PROVED";
  observedAtUtc: string;
  checks: Record<string, unknown>;
}

export interface GroupRestorePreparedRun {
  state: "RUN_READY";
  suffix: string;
  restoreDrillProved: false;
  steps: GroupRestoreRunStep[];
  cleanup: GroupRestoreCleanupStep[];
}

export interface GroupRestoreExecutionResult {
  state: "CREATED" | "RESTORE_DRILL_PROVED" | "CLEANED";
  suffix: string;
  restoreDrillProved: boolean;
  journal: GroupRestoreJournal;
  targets: GroupRestoreTargetResources;
  acceptance?: GroupRestoreAcceptanceEvidence;
}

export interface GroupRestoreExecutionPorts {
  /** Observe only resources with the exact display name for this request. */
  observe(
    request: GroupRestoreResourceRequest,
  ): Promise<GroupRestoreObservedResource[]>;
  /** Execute one already-reviewed create request, then return a fresh list. */
  create(step: GroupRestoreRunStep): Promise<GroupRestoreObservedResource[]>;
  /** Execute one exact delete request, then return a fresh list. */
  delete(
    step: GroupRestoreCleanupStep,
    identity: GroupRestoreIdentity,
    argv: string[],
  ): Promise<GroupRestoreObservedResource[]>;
}

function requestFor(
  plan: GroupRestorePlan,
  kind: GroupRestoreResourceKind,
): GroupRestoreResourceRequest {
  return {
    suffix: plan.suffix,
    kind,
    requestName: groupRestoreDisplayName(kind, plan.suffix),
  };
}

function sameRequest(
  left: GroupRestoreResourceRequest,
  right: GroupRestoreResourceRequest,
): boolean {
  return left.suffix === right.suffix && left.kind === right.kind &&
    left.requestName === right.requestName;
}

function entriesFor(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
) {
  return journal.filter((entry) => sameRequest(entry.request, request));
}

function createEntry(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
) {
  const entries = entriesFor(journal, request).filter((entry) =>
    entry.intent === "create"
  );
  if (entries.length !== 1) {
    throw new Error("Exact drill create identity is missing or ambiguous");
  }
  return entries[0]!;
}

function exactCreatedIdentity(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
): GroupRestoreIdentity {
  const identity = createEntry(journal, request).identity;
  if (!identity || identity.name !== request.requestName || !identity.id) {
    throw new Error("Exact drill create identity is incomplete");
  }
  return identity;
}

function assertSafeTargetId(plan: GroupRestorePlan, id: string): void {
  const forbidden = [
    plan.source.instanceId,
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.volumeGroupId,
    plan.volumeGroupBackupId,
    plan.bootMemberBackupId,
    plan.rootMemberBackupId,
    plan.productionSubnetId,
    plan.productionVcnId,
    plan.productionReservedIpId,
    plan.isolatedSubnetId,
    plan.isolatedVcnId,
  ];
  if (!id || forbidden.includes(id)) {
    throw new Error("Drill cleanup identity references a protected resource");
  }
}

/** Build the only delete forms accepted by this executor. */
export function buildGroupRestoreDeleteRequest(
  plan: GroupRestorePlan,
  step: GroupRestoreCleanupStep,
  identity: GroupRestoreIdentity,
  runner: GroupRestoreRunner,
): string[] {
  validateGroupRestorePlan(plan);
  const request = requestFor(plan, step.kind);
  if (
    step.action !== "delete" || step.requestName !== request.requestName
  ) {
    throw new Error("Cleanup request is not bound to the reviewed drill");
  }
  if (identity.name !== request.requestName) {
    throw new Error("Cleanup identity name differs from the reviewed drill");
  }
  assertSafeTargetId(plan, identity.id);
  const args = step.kind === "instance"
    ? [
      "compute",
      "instance",
      "terminate",
      "--instance-id",
      identity.id,
      "--preserve-boot-volume",
      "true",
      "--preserve-data-volumes-created-at-launch",
      "true",
      "--force",
    ]
    : step.kind === "boot-volume"
    ? [
      "bv",
      "boot-volume",
      "delete",
      "--boot-volume-id",
      identity.id,
      "--force",
    ]
    : [
      "bv",
      "volume",
      "delete",
      "--volume-id",
      identity.id,
      "--force",
    ];
  const argv = groupRestoreCliArgs(runner, args);
  if (
    argv.includes(plan.source.instanceId) ||
    argv.includes(plan.source.bootVolumeId) ||
    argv.includes(plan.source.rootVolumeId) ||
    argv.includes(plan.productionReservedIpId)
  ) {
    throw new Error("Cleanup request contains a production identity");
  }
  return argv;
}

function assertDate(value: Date): void {
  if (!Number.isFinite(value.getTime())) throw new Error("Run time is invalid");
}

/** Validate the reviewed plan before any provider call. */
export async function prepareGroupRestoreExecution(
  input: GroupRestoreExecutionInput,
  runner: GroupRestoreRunner,
): Promise<GroupRestorePreparedRun> {
  assertDate(input.now);
  validateGroupRestorePlan(input.plan);
  await validateGroupRestoreApproval(input.plan, input.approval, input.now);
  validateGroupRestoreEvidence(input.plan, input.evidence);
  validateGroupRestoreJournal(input.journal, input.plan);
  groupRestoreCliArgs(runner, []);
  const steps: GroupRestoreRunStep[] = [
    {
      kind: "boot-volume",
      request: requestFor(input.plan, "boot-volume"),
      intent: "create",
      ociCliPath: runner.ociCliPath,
      argv: groupRestoreCliArgs(
        runner,
        buildRestoredBootVolumeRequest(input.plan),
      ),
    },
    {
      kind: "root-volume",
      request: requestFor(input.plan, "root-volume"),
      intent: "create",
      ociCliPath: runner.ociCliPath,
      argv: groupRestoreCliArgs(
        runner,
        buildRestoredRootVolumeRequest(input.plan),
      ),
    },
  ];
  return {
    state: "RUN_READY",
    suffix: input.plan.suffix,
    restoreDrillProved: false,
    steps,
    cleanup: groupRestoreCleanupOrder(input.plan),
  };
}

async function executeCreate(
  journal: GroupRestoreJournal,
  step: GroupRestoreRunStep,
  nowUtc: string,
  ports: GroupRestoreExecutionPorts,
): Promise<GroupRestoreJournal> {
  const existing = entriesFor(journal, step.request);
  const existingCreate = existing.filter((entry) => entry.intent === "create");
  if (existingCreate.length > 1) {
    throw new Error("Ambiguous create intent for drill resource");
  }
  if (existingCreate.length === 1) {
    if (!existingCreate[0]!.identity) {
      throw new Error("Unresolved create intent cannot be retried");
    }
    const live = await ports.observe(step.request);
    return reconcileGroupRestoreResource(
      journal,
      step.request,
      "create",
      live,
      nowUtc,
    );
  }
  const before = await ports.observe(step.request);
  const intent = journalGroupRestoreIntent(
    journal,
    step.request,
    "create",
    nowUtc,
    before,
  );
  const after = await ports.create(step);
  return reconcileGroupRestoreResource(
    intent,
    step.request,
    "create",
    after,
    nowUtc,
  );
}

function targetsFromJournal(
  plan: GroupRestorePlan,
  journal: GroupRestoreJournal,
): GroupRestoreTargetResources {
  const { bootVolumeId, rootVolumeId } = restoredVolumesFromJournal(
    plan,
    journal,
  );
  const instanceId = exactCreatedIdentity(
    journal,
    requestFor(plan, "instance"),
  ).id;
  const targets = { bootVolumeId, rootVolumeId, instanceId };
  validateGroupRestoreTargets(plan, targets);
  return targets;
}

function restoredVolumesFromJournal(
  plan: GroupRestorePlan,
  journal: GroupRestoreJournal,
): Pick<GroupRestoreTargetResources, "bootVolumeId" | "rootVolumeId"> {
  const bootVolumeId = exactCreatedIdentity(
    journal,
    requestFor(plan, "boot-volume"),
  ).id;
  const rootVolumeId = exactCreatedIdentity(
    journal,
    requestFor(plan, "root-volume"),
  ).id;
  return { bootVolumeId, rootVolumeId };
}

/** Create or safely resume the two restored volumes and the isolated clone. */
export async function executeGroupRestoreCreates(
  input: GroupRestoreExecutionInput,
  runner: GroupRestoreRunner,
  ports: GroupRestoreExecutionPorts,
): Promise<GroupRestoreExecutionResult> {
  const prepared = await prepareGroupRestoreExecution(input, runner);
  const nowUtc = input.now.toISOString();
  let journal = input.journal;
  for (const step of prepared.steps) {
    journal = await executeCreate(journal, step, nowUtc, ports);
  }
  const volumes = restoredVolumesFromJournal(input.plan, journal);
  const launch: GroupRestoreRunStep = {
    kind: "instance",
    request: requestFor(input.plan, "instance"),
    intent: "create",
    ociCliPath: runner.ociCliPath,
    argv: groupRestoreCliArgs(
      runner,
      buildGroupRestoreLaunchRequest(
        input.plan,
        volumes.bootVolumeId,
        volumes.rootVolumeId,
      ),
    ),
  };
  journal = await executeCreate(journal, launch, nowUtc, ports);
  const targets = targetsFromJournal(input.plan, journal);
  return {
    state: "CREATED",
    suffix: input.plan.suffix,
    restoreDrillProved: false,
    journal,
    targets,
  };
}

function validateAcceptance(
  proof: GroupRestoreAcceptanceEvidence,
  now: Date,
): void {
  if (
    proof.status !== "RESTORE_DRILL_PROVED" ||
    !proof.checks || Object.keys(proof.checks).length === 0
  ) {
    throw new Error("Explicit restored-guest acceptance evidence is required");
  }
  const observed = Date.parse(proof.observedAtUtc);
  if (!Number.isFinite(observed) || observed > now.getTime()) {
    throw new Error("Restored-guest acceptance timestamp is invalid");
  }
}

/** Gate the live proof on an explicit, non-empty acceptance receipt. */
export async function acceptGroupRestoreExecution(
  result: GroupRestoreExecutionResult,
  now: Date,
  acceptance: () => Promise<GroupRestoreAcceptanceEvidence>,
): Promise<GroupRestoreExecutionResult> {
  assertDate(now);
  if (result.state !== "CREATED" || result.restoreDrillProved !== false) {
    throw new Error("The drill must have created targets before acceptance");
  }
  const proof = await acceptance();
  validateAcceptance(proof, now);
  return {
    ...result,
    state: "RESTORE_DRILL_PROVED",
    restoreDrillProved: true,
    acceptance: proof,
  };
}

function deleteEntryCompleted(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
): boolean {
  return entriesFor(journal, request).some((entry) =>
    entry.intent === "delete" && Boolean(entry.completedAtUtc)
  );
}

/** Delete only the exact accepted drill resources, in reverse dependency order. */
export async function cleanupGroupRestoreExecution(
  result: GroupRestoreExecutionResult,
  plan: GroupRestorePlan,
  approval: GroupRestoreApproval,
  evidence: GroupRestoreEvidence,
  runner: GroupRestoreRunner,
  ports: GroupRestoreExecutionPorts,
  now: Date,
): Promise<GroupRestoreExecutionResult> {
  assertDate(now);
  if (
    result.state !== "RESTORE_DRILL_PROVED" ||
    result.restoreDrillProved !== true || !result.acceptance
  ) {
    throw new Error("Cleanup requires explicit restored-guest acceptance");
  }
  await prepareGroupRestoreExecution({
    plan,
    approval,
    evidence,
    journal: result.journal,
    now,
  }, runner);
  let journal = result.journal;
  const nowUtc = now.toISOString();
  for (const step of groupRestoreCleanupOrder(plan)) {
    const request = requestFor(plan, step.kind);
    if (step.requestName !== request.requestName) {
      throw new Error("Cleanup request name differs from the reviewed drill");
    }
    const identity = exactCreatedIdentity(journal, request);
    const entries = entriesFor(journal, request);
    if (deleteEntryCompleted(journal, request)) continue;
    const unresolved = entries.find((entry) => entry.intent === "delete");
    if (unresolved) {
      const live = await ports.observe(request);
      journal = reconcileGroupRestoreResource(
        journal,
        request,
        "delete",
        live,
        nowUtc,
      );
      if (!deleteEntryCompleted(journal, request)) {
        throw new Error("Unresolved delete intent cannot be retried");
      }
      continue;
    }
    journal = journalGroupRestoreIntent(
      journal,
      request,
      "delete",
      nowUtc,
    );
    const argv = buildGroupRestoreDeleteRequest(plan, step, identity, runner);
    const after = await ports.delete(step, identity, argv);
    journal = reconcileGroupRestoreResource(
      journal,
      request,
      "delete",
      after,
      nowUtc,
    );
    if (!deleteEntryCompleted(journal, request)) {
      throw new Error("Provider delete was not confirmed absent");
    }
  }
  return {
    ...result,
    state: "CLEANED",
    journal,
  };
}

/** OCI adapter used by the Pi. It performs no calls until a state-machine
 * function invokes one of its methods. */
export function ociGroupRestorePorts(
  plan: GroupRestorePlan,
  runner: GroupRestoreRunner,
): GroupRestoreExecutionPorts {
  const call = async (argv: string[]): Promise<JsonRecord> => {
    const result = await runner.run(
      runner.ociCliPath,
      [...argv, "--output", "json"],
    );
    if (result.code !== 0) {
      throw new Error(
        `OCI drill request failed (${result.code}): ${
          redactOcid(result.stderr)
        }`,
      );
    }
    try {
      return result.stdout.trim() ? JSON.parse(result.stdout) as JsonRecord : {
        data: [],
      };
    } catch {
      throw new Error("OCI drill response was not JSON");
    }
  };
  const listArgs = (request: GroupRestoreResourceRequest): string[] => {
    const base = request.kind === "instance"
      ? [
        "compute",
        "instance",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--all",
      ]
      : request.kind === "boot-volume"
      ? [
        "bv",
        "boot-volume",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--availability-domain",
        plan.availabilityDomain,
        "--all",
      ]
      : [
        "bv",
        "volume",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--availability-domain",
        plan.availabilityDomain,
        "--all",
      ];
    return base;
  };
  const observe = async (
    request: GroupRestoreResourceRequest,
  ): Promise<GroupRestoreObservedResource[]> => {
    const rows = dataArray(
      await call(groupRestoreCliArgs(runner, listArgs(request))),
    );
    return rows.filter((row) =>
      row["display-name"] === request.requestName &&
      row["lifecycle-state"] !== "TERMINATED"
    ).map((row) => ({
      id: String(row.id ?? ""),
      displayName: String(row["display-name"] ?? ""),
    }));
  };
  return {
    observe,
    create: async (step) => {
      await call(step.argv);
      return observe(step.request);
    },
    delete: async (step, identity, argv) => {
      if (!identity.id) throw new Error("Cleanup identity is incomplete");
      await call(argv);
      const deadline = Date.now() + 600_000;
      while (true) {
        const request = requestFor(plan, step.kind);
        const live = await observe(request);
        if (!live.length) return live;
        if (Date.now() >= deadline) return live;
        await new Promise<void>((resolve) => setTimeout(resolve, 10_000));
      }
    },
  };
}
