/**
 * Journaled execution ports for an isolated Oracle volume-group restore drill.
 *
 * The provider calls are injected so the state machine can be tested without
 * credentials or a cloud side effect. The Pi supplies the OCI adapter at run
 * time. This module never treats a returned plan or metadata check as a live
 * restore proof: the only proof accepted is a separate, fully typed
 * `GroupRestoreAcceptanceReceipt` supplied by the operator, validated against
 * the reviewed plan. Creates and acceptance are refused once the durable
 * lifetime window elapsed; cleanup remains allowed but reports the condition
 * instead of silently extending the window.
 */
import {
  assertTimestampUtc,
  BOOT_MEMBER_SIZE_GB,
  buildGroupRestoreLaunchRequest,
  buildRestoredBootVolumeRequest,
  buildRestoredRootVolumeRequest,
  GROUP_RESTORE_APPROVAL_OPERATION,
  type GroupRestoreApproval,
  groupRestoreCleanupOrder,
  type GroupRestoreCleanupStep,
  groupRestoreCliArgs,
  groupRestoreDeadlineExceeded,
  groupRestoreDisplayName,
  type GroupRestoreEvidence,
  type GroupRestoreIdentity,
  type GroupRestoreJournal,
  type GroupRestoreLifetime,
  type GroupRestoreObservedResource,
  type GroupRestorePlan,
  groupRestorePlanDigest,
  type GroupRestoreResourceKind,
  type GroupRestoreResourceRequest,
  type GroupRestoreRunner,
  type GroupRestoreRunStep,
  type GroupRestoreTargetResources,
  journalGroupRestoreIntent,
  reconcileGroupRestoreResource,
  ROOT_MEMBER_SIZE_GB,
  validateGroupRestoreApproval,
  validateGroupRestoreEvidence,
  validateGroupRestoreJournal,
  validateGroupRestoreLifetime,
  validateGroupRestorePlan,
  validateGroupRestoreTargets,
} from "./oci-group-restore-drill.ts";
import {
  type DrillNetworkEvidence,
  verifyDrillRoutedNetwork,
} from "./isolated-drill.ts";
import { dataArray, dataObject, type JsonRecord, redactOcid } from "./oci.ts";

export interface GroupRestoreExecutionInput {
  plan: GroupRestorePlan;
  approval: GroupRestoreApproval;
  evidence: GroupRestoreEvidence;
  journal: GroupRestoreJournal;
  now: Date;
  /** Durable started/deadline window, persisted by the run wrapper. */
  lifetime: GroupRestoreLifetime;
}

/** Strict, fully typed restored-guest acceptance checklist. Every check is a
 * typed boolean and every listed key must be present and exactly `true`; no
 * free-form bag is accepted anywhere in the execution path. */
export interface GroupRestoreAcceptanceChecks {
  /** Production source remained online and unchanged throughout the drill. */
  productionOnline: boolean;
  /** The restored clone booted to a login/runtime. */
  targetBooted: boolean;
  ssh: boolean;
  mounts: boolean;
  bootParity: boolean;
  representativeData: boolean;
  applications: boolean;
  desktop: boolean;
  /** The clone was network-isolated from production. */
  isolation: boolean;
  /** Instance metadata 169.254.169.254 was blocked in the clone. */
  metadataBlocked: boolean;
  /** Duplicate sync/job copies in the clone were masked. */
  duplicateJobsMasked: boolean;
}

/** The only acceptance receipt the state machine accepts: the operator-supplied
 * typed proof, bound to the reviewed plan digest and suffix. */
export interface GroupRestoreAcceptanceReceipt {
  status: "RESTORE_DRILL_PROVED";
  observedAtUtc: string;
  suffix: string;
  planSha256: string;
  checks: GroupRestoreAcceptanceChecks;
  rootUuid: string;
  stagingUuid: string;
  rootPartitionStartSector: number;
  kernelSha256: string;
  initramfsSha256: string;
  grubSha256: string;
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
  acceptance?: GroupRestoreAcceptanceReceipt;
  lifetime: GroupRestoreLifetime;
  /** Reported instead of silently extending the lifetime window. */
  deadlineExceeded: boolean;
}

/** Exact created-resource subset of one partial create journal: only the
 * resources with a reconciled create identity are present. */
export interface GroupRestorePartialTargets {
  bootVolumeId?: string;
  rootVolumeId?: string;
  instanceId?: string;
}

/** Result of a receipt-free abort of an exact partial create journal. No
 * acceptance is ever invented and `restoreDrillProved` stays false; the abort
 * is only allowed after the durable lifetime elapsed. */
export interface GroupRestorePartialCleanupResult {
  state: "CLEANED";
  suffix: string;
  restoreDrillProved: false;
  journal: GroupRestoreJournal;
  targets: GroupRestorePartialTargets;
  lifetime: GroupRestoreLifetime;
  deadlineExceeded: true;
  /** Never present on this result: the abort is receipt-free. */
  acceptance?: GroupRestoreAcceptanceReceipt;
}

export interface GroupRestoreExecutionPorts {
  /** Observation-only poll for the exact request display name. */
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
  /** Prove the reviewed production source invariants (running, 2 OCPU/12 GB,
   * 200 GB live storage, one public IP, exact source IDs/attachments and
   * volume-group accounting). Called before the first create and after all
   * deletes; a throw fails the operation closed. */
  verifyProduction(): Promise<void>;
  /** Prove and prepare all isolation controls before the restored instance is
   * launched. The implementation re-reads the reviewed isolated network and
   * the exact restored volume identities through the injected runner, then
   * requires the caller-supplied copied-volume preparation/masking hook:
   * read-only network checks never mask duplicate jobs on the copies. The
   * hook receives the exact restored volume IDs. A missing or failed hook
   * must prevent the first clone boot. */
  verifyPreBootIsolation(
    targets: Pick<GroupRestoreTargetResources, "bootVolumeId" | "rootVolumeId">,
  ): Promise<void>;
  /** Actual current time for the caller's clock. Lifetime boundaries use this
   * per-provider-call clock, never a stale run-start timestamp. */
  now(): Date;
}

/** Durable journal sink used to publish intent before a provider mutation and
 * the reconciled identity immediately after it. Callers that do not need
 * persistence may omit it; the file-backed entry point always supplies one. */
export type GroupRestoreJournalWriter = (
  journal: GroupRestoreJournal,
) => Promise<void>;

const RESOURCE_KINDS: GroupRestoreResourceKind[] = [
  "boot-volume",
  "root-volume",
  "instance",
];

const ACCEPTANCE_CHECK_NAMES = [
  "productionOnline",
  "targetBooted",
  "ssh",
  "mounts",
  "bootParity",
  "representativeData",
  "applications",
  "desktop",
  "isolation",
  "metadataBlocked",
  "duplicateJobsMasked",
] as const;

const ACCEPTANCE_RECEIPT_NAMES = [
  "status",
  "observedAtUtc",
  "suffix",
  "planSha256",
  "checks",
  "rootUuid",
  "stagingUuid",
  "rootPartitionStartSector",
  "kernelSha256",
  "initramfsSha256",
  "grubSha256",
] as const;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

function assertExactRecordKeys(
  record: Record<string, unknown>,
  names: readonly string[],
  label: string,
): void {
  const keys = Object.keys(record).sort();
  const expected = [...names].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expected)) {
    throw new Error(`${label} has missing or unknown keys`);
  }
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

/** Validate the reviewed plan, approval, evidence, journal and runner before
 * any provider call. */
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
  ports: GroupRestoreExecutionPorts,
  plan: GroupRestorePlan,
  approval: GroupRestoreApproval,
  lifetime: GroupRestoreLifetime,
  persistJournal?: GroupRestoreJournalWriter,
): Promise<GroupRestoreJournal> {
  // The lifetime check uses the adapter clock so a deadline crossed by a long
  // create or observe can never be hidden by a stale run-start timestamp.
  const now = ports.now();
  validateGroupRestoreLifetime(lifetime, plan, now);
  const nowUtc = now.toISOString();
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
    const reconciled = reconcileGroupRestoreResource(
      journal,
      step.request,
      "create",
      live,
      nowUtc,
    );
    await persistJournal?.(reconciled);
    return reconciled;
  }
  const before = await ports.observe(step.request);
  // Observation can take long enough for either approval or the drill window
  // to expire. Re-read both clocks immediately before journaling and issuing
  // the provider mutation.
  const mutationNow = ports.now();
  await validateGroupRestoreApproval(plan, approval, mutationNow);
  validateGroupRestoreLifetime(lifetime, plan, mutationNow);
  const mutationNowUtc = mutationNow.toISOString();
  const intent = journalGroupRestoreIntent(
    journal,
    step.request,
    "create",
    mutationNowUtc,
    before,
  );
  await persistJournal?.(intent);
  const after = await ports.create(step);
  const reconciled = reconcileGroupRestoreResource(
    intent,
    step.request,
    "create",
    after,
    mutationNowUtc,
  );
  await persistJournal?.(reconciled);
  return reconciled;
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

/** Create or safely resume the two restored volumes and the isolated clone.
 * The injected production verifier runs before any create, and no create is
 * issued after the durable lifetime deadline: every create boundary re-checks
 * the lifetime against the live adapter clock, never a stale run-start time. */
export async function executeGroupRestoreCreates(
  input: GroupRestoreExecutionInput,
  runner: GroupRestoreRunner,
  ports: GroupRestoreExecutionPorts,
  persistJournal?: GroupRestoreJournalWriter,
): Promise<GroupRestoreExecutionResult> {
  const prepared = await prepareGroupRestoreExecution(input, runner);
  const admissionNow = ports.now();
  await validateGroupRestoreApproval(input.plan, input.approval, admissionNow);
  validateGroupRestoreLifetime(input.lifetime, input.plan, admissionNow);
  await ports.verifyProduction();
  let journal = input.journal;
  for (const step of prepared.steps) {
    journal = await executeCreate(
      journal,
      step,
      ports,
      input.plan,
      input.approval,
      input.lifetime,
      persistJournal,
    );
  }
  const volumes = restoredVolumesFromJournal(input.plan, journal);
  // This gate is intentionally before the instance create. Its implementation
  // must verify the isolated network and prepare the copied volumes (including
  // duplicate-job masks) before the restored guest can boot for the first time.
  const isolationStart = ports.now();
  await validateGroupRestoreApproval(
    input.plan,
    input.approval,
    isolationStart,
  );
  validateGroupRestoreLifetime(input.lifetime, input.plan, isolationStart);
  await ports.verifyPreBootIsolation(volumes);
  validateGroupRestoreLifetime(input.lifetime, input.plan, ports.now());
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
  journal = await executeCreate(
    journal,
    launch,
    ports,
    input.plan,
    input.approval,
    input.lifetime,
    persistJournal,
  );
  const targets = targetsFromJournal(input.plan, journal);
  return {
    state: "CREATED",
    suffix: input.plan.suffix,
    restoreDrillProved: false,
    journal,
    targets,
    lifetime: input.lifetime,
    deadlineExceeded: groupRestoreDeadlineExceeded(
      input.lifetime,
      ports.now(),
    ),
  };
}

function validateResultLifetimeShape(
  lifetime: GroupRestoreLifetime,
  plan: GroupRestorePlan,
): void {
  assertTimestampUtc(lifetime.startedAtUtc, "Result lifetime start timestamp");
  assertTimestampUtc(
    lifetime.deadlineAtUtc,
    "Result lifetime deadline timestamp",
  );
  if (
    Date.parse(lifetime.deadlineAtUtc) - Date.parse(lifetime.startedAtUtc) !==
      plan.maxDurationHours * 3_600_000
  ) {
    throw new Error("Result lifetime does not match the reviewed plan");
  }
}

/** Validate the durable resource portion of a CREATED result before it is
 * trusted by acceptance or cleanup. Persisted JSON is untrusted input; its
 * state flag alone cannot authorize a delete. */
function validateCreatedResult(
  result: GroupRestoreExecutionResult,
  plan: GroupRestorePlan,
  now?: Date,
): void {
  validateGroupRestorePlan(plan);
  if (
    result.state !== "CREATED" || result.restoreDrillProved !== false ||
    result.acceptance !== undefined || result.suffix !== plan.suffix ||
    result.deadlineExceeded !== false
  ) {
    throw new Error("Durable drill result is not an unaccepted CREATED result");
  }
  validateResultLifetimeShape(result.lifetime, plan);
  if (now !== undefined) {
    validateGroupRestoreLifetime(result.lifetime, plan, now);
  }
  validateGroupRestoreTargets(plan, result.targets);
  if (result.journal.length !== RESOURCE_KINDS.length) {
    throw new Error("Durable CREATED journal has unexpected entries");
  }
  for (const kind of RESOURCE_KINDS) {
    const request = requestFor(plan, kind);
    const entries = entriesFor(result.journal, request);
    if (
      entries.length !== 1 || entries[0]!.intent !== "create" ||
      !entries[0]!.identity ||
      entries[0]!.identity.name !== request.requestName
    ) {
      throw new Error(`Durable CREATED journal is invalid for ${kind}`);
    }
    assertTimestampUtc(entries[0]!.createdAtUtc, `${kind} create timestamp`);
  }
  const targetsByKind = {
    "boot-volume": result.targets.bootVolumeId,
    "root-volume": result.targets.rootVolumeId,
    instance: result.targets.instanceId,
  } as const;
  for (const kind of RESOURCE_KINDS) {
    const identity = entriesFor(result.journal, requestFor(plan, kind))[0]!
      .identity!;
    if (identity.id !== targetsByKind[kind]) {
      throw new Error(`Durable target identity differs for ${kind}`);
    }
  }
}

/** Strict acceptance validation: exact keys and typed true booleans, exact
 * UUID/hash shapes, a non-negative integer start sector, a non-future
 * observed timestamp and the exact plan binding. */
export async function validateGroupRestoreAcceptance(
  receipt: GroupRestoreAcceptanceReceipt,
  plan: GroupRestorePlan,
  now: Date,
): Promise<void> {
  validateGroupRestorePlan(plan);
  assertDate(now);
  assertExactRecordKeys(
    receipt as unknown as Record<string, unknown>,
    ACCEPTANCE_RECEIPT_NAMES,
    "Acceptance receipt",
  );
  if (receipt.status !== "RESTORE_DRILL_PROVED") {
    throw new Error("Acceptance status is not RESTORE_DRILL_PROVED");
  }
  if (receipt.suffix !== plan.suffix) {
    throw new Error("Acceptance suffix differs from the reviewed plan");
  }
  if (receipt.planSha256 !== await groupRestorePlanDigest(plan)) {
    throw new Error("Acceptance does not bind the reviewed plan");
  }
  assertTimestampUtc(receipt.observedAtUtc, "Acceptance timestamp");
  if (Date.parse(receipt.observedAtUtc) > now.getTime()) {
    throw new Error("Acceptance timestamp is in the future");
  }
  assertExactRecordKeys(
    receipt.checks as unknown as Record<string, unknown>,
    ACCEPTANCE_CHECK_NAMES,
    "Acceptance checks",
  );
  for (const name of ACCEPTANCE_CHECK_NAMES) {
    if ((receipt.checks as unknown as Record<string, unknown>)[name] !== true) {
      throw new Error(`Acceptance check ${name} must be true`);
    }
  }
  if (!UUID_PATTERN.test(receipt.rootUuid)) {
    throw new Error("Acceptance root UUID is not a UUID");
  }
  if (!UUID_PATTERN.test(receipt.stagingUuid)) {
    throw new Error("Acceptance staging UUID is not a UUID");
  }
  if (
    !Number.isInteger(receipt.rootPartitionStartSector) ||
    receipt.rootPartitionStartSector < 0
  ) {
    throw new Error(
      "Acceptance root partition start sector must be a non-negative integer",
    );
  }
  if (!SHA256_HEX_PATTERN.test(receipt.kernelSha256)) {
    throw new Error("Acceptance kernel SHA-256 is not 64 hex digits");
  }
  if (!SHA256_HEX_PATTERN.test(receipt.initramfsSha256)) {
    throw new Error("Acceptance initramfs SHA-256 is not 64 hex digits");
  }
  if (!SHA256_HEX_PATTERN.test(receipt.grubSha256)) {
    throw new Error("Acceptance GRUB SHA-256 is not 64 hex digits");
  }
}

/** Gate the live proof on a separate operator-supplied typed acceptance
 * receipt, bound to the reviewed plan and refused after the lifetime window. */
export async function acceptGroupRestoreExecution(
  result: GroupRestoreExecutionResult,
  plan: GroupRestorePlan,
  now: Date,
  receipt: GroupRestoreAcceptanceReceipt,
): Promise<GroupRestoreExecutionResult> {
  assertDate(now);
  if (
    result.state !== "CREATED" || result.restoreDrillProved !== false ||
    result.acceptance
  ) {
    throw new Error("The drill must have created targets before acceptance");
  }
  validateCreatedResult(result, plan, now);
  validateGroupRestoreLifetime(result.lifetime, plan, now);
  if (
    Date.parse(receipt.observedAtUtc) <
      Date.parse(result.lifetime.startedAtUtc)
  ) {
    throw new Error(
      "Acceptance observation predates the durably recorded drill window",
    );
  }
  await validateGroupRestoreAcceptance(receipt, plan, now);
  return {
    ...result,
    state: "RESTORE_DRILL_PROVED",
    restoreDrillProved: true,
    acceptance: receipt,
    deadlineExceeded: groupRestoreDeadlineExceeded(result.lifetime, now),
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

/** Shared per-entry cleanup validation: every journal entry must bind exactly
 * the reviewed drill resource (kind, suffix, generated display name), carry a
 * canonical UTC timestamp and a create/delete intent, and any recorded
 * identity must be bound to its request. */
function validateJournalEntries(
  journal: GroupRestoreJournal,
  plan: GroupRestorePlan,
): void {
  for (const entry of journal) {
    if (
      !RESOURCE_KINDS.includes(entry.request.kind) ||
      entry.request.suffix !== plan.suffix ||
      entry.request.requestName !==
        groupRestoreDisplayName(entry.request.kind, plan.suffix) ||
      !["create", "delete"].includes(entry.intent)
    ) {
      throw new Error("Cleanup journal contains an unbound resource entry");
    }
    assertTimestampUtc(entry.createdAtUtc, "Cleanup journal timestamp");
    if (entry.completedAtUtc !== undefined) {
      assertTimestampUtc(entry.completedAtUtc, "Cleanup completion timestamp");
    }
    if (entry.identity !== undefined) {
      if (
        typeof entry.identity.id !== "string" ||
        typeof entry.identity.name !== "string" ||
        entry.identity.name !== entry.request.requestName
      ) {
        throw new Error("Cleanup journal identity is not bound to its request");
      }
    }
  }
}

/** Exact, unambiguously journaled create kinds for one drill. Present kinds
 * must carry exactly one reconciled create identity and at most one delete
 * intent bound to it; absent kinds are skipped so a partial create journal
 * (created resources but no durable result) can be aborted without ever
 * widening cleanup to arbitrary resources. */
function journaledCreatedKinds(
  journal: GroupRestoreJournal,
  plan: GroupRestorePlan,
): GroupRestoreResourceKind[] {
  validateJournalEntries(journal, plan);
  const kinds: GroupRestoreResourceKind[] = [];
  for (const kind of RESOURCE_KINDS) {
    const request = requestFor(plan, kind);
    const entries = entriesFor(journal, request);
    const stale = journal.filter((entry) =>
      entry.request.suffix === plan.suffix &&
      entry.request.kind === kind &&
      entry.request.requestName !== request.requestName
    );
    if (stale.length !== 0) {
      throw new Error(`Stale journal intent for drill ${kind} resource`);
    }
    if (entries.length === 0) continue;
    const creates = entries.filter((entry) => entry.intent === "create");
    const deletes = entries.filter((entry) => entry.intent === "delete");
    if (creates.length !== 1 || !creates[0]!.identity) {
      throw new Error(
        `Cleanup requires one exact recorded create identity for drill ${kind}`,
      );
    }
    if (deletes.length > 1) {
      throw new Error(`Ambiguous delete intent for drill ${kind} resource`);
    }
    const createIdentity = creates[0]!.identity!;
    if (
      deletes.length === 1 &&
      (!deletes[0]!.identity || deletes[0]!.identity!.id !== createIdentity.id)
    ) {
      throw new Error(`Cleanup delete identity differs for ${kind}`);
    }
    kinds.push(kind);
  }
  return kinds;
}

/** Cleanup-specific journal check: a completed delete is a settled resource
 * (skip it at runtime), an unresolved delete is reconciled, and nothing may be
 * ambiguous or missing an exact recorded create identity. This validator
 * requires the complete three-resource journal used by the full-destroy path. */
function validateGroupRestoreCleanupJournal(
  journal: GroupRestoreJournal,
  plan: GroupRestorePlan,
  targets?: GroupRestoreTargetResources,
): void {
  const kinds = journaledCreatedKinds(journal, plan);
  for (const kind of RESOURCE_KINDS) {
    if (!kinds.includes(kind)) {
      throw new Error(
        `Cleanup requires one exact recorded create identity for drill ${kind}`,
      );
    }
    const createIdentity = exactCreatedIdentity(
      journal,
      requestFor(plan, kind),
    );
    if (targets !== undefined) {
      const targetId = kind === "boot-volume"
        ? targets.bootVolumeId
        : kind === "root-volume"
        ? targets.rootVolumeId
        : targets.instanceId;
      if (createIdentity.id !== targetId) {
        throw new Error(`Cleanup target identity differs for ${kind}`);
      }
    }
  }
}

/** Derive the exact partial target set from the journaled created kinds. Every
 * identity is re-checked against the protected plan identities, and the target
 * ids must be mutually distinct. */
function partialTargetsFromJournal(
  plan: GroupRestorePlan,
  journal: GroupRestoreJournal,
  kinds: GroupRestoreResourceKind[],
): GroupRestorePartialTargets {
  const targets: GroupRestorePartialTargets = {};
  for (const kind of kinds) {
    const identity = exactCreatedIdentity(journal, requestFor(plan, kind));
    assertSafeTargetId(plan, identity.id);
    if (kind === "boot-volume") {
      targets.bootVolumeId = identity.id;
    } else if (kind === "root-volume") {
      targets.rootVolumeId = identity.id;
    } else {
      targets.instanceId = identity.id;
    }
  }
  const ids = Object.values(targets).filter(
    (id): id is string => id !== undefined,
  );
  if (new Set(ids).size !== ids.length) {
    throw new Error("Partial cleanup target identities are not distinct");
  }
  return targets;
}

/** Delete only the exact recorded drill resources, in reverse dependency
 * order, publishing each delete intent before its provider delete and
 * reconciling each delete to a completed journal entry. The exact create
 * identities come from the journal and the delete forms are built by the
 * reviewed-plan helpers only: no arbitrary resource kind is ever widened in
 * here. A partial cleanup passes only the journaled kinds. */
async function executeGroupRestoreDeletes(
  journal: GroupRestoreJournal,
  plan: GroupRestorePlan,
  runner: GroupRestoreRunner,
  ports: GroupRestoreExecutionPorts,
  now: Date,
  persistJournal?: GroupRestoreJournalWriter,
  kinds: GroupRestoreResourceKind[] = RESOURCE_KINDS,
): Promise<GroupRestoreJournal> {
  const nowUtc = now.toISOString();
  for (const step of groupRestoreCleanupOrder(plan)) {
    if (!kinds.includes(step.kind)) continue;
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
      await persistJournal?.(journal);
      if (!deleteEntryCompleted(journal, request)) {
        // The exact recorded resource is still live after reconciliation:
        // retry the identical reviewed delete request exactly once in this
        // invocation (same plan-bound identity and argv, bounded by
        // ports.delete), then reconcile and persist again. No wider
        // identity, no create retry and no journal-order change is
        // introduced here; the durable intent stays the single journaled one.
        const retryArgv = buildGroupRestoreDeleteRequest(
          plan,
          step,
          identity,
          runner,
        );
        const after = await ports.delete(step, identity, retryArgv);
        journal = reconcileGroupRestoreResource(
          journal,
          request,
          "delete",
          after,
          nowUtc,
        );
        await persistJournal?.(journal);
        if (!deleteEntryCompleted(journal, request)) {
          throw new Error(
            "Exact delete intent is still live after one bounded retry; a later bounded retry must retry the same exact delete",
          );
        }
      }
      continue;
    }
    journal = journalGroupRestoreIntent(
      journal,
      request,
      "delete",
      nowUtc,
    );
    await persistJournal?.(journal);
    const argv = buildGroupRestoreDeleteRequest(plan, step, identity, runner);
    const after = await ports.delete(step, identity, argv);
    journal = reconcileGroupRestoreResource(
      journal,
      request,
      "delete",
      after,
      nowUtc,
    );
    await persistJournal?.(journal);
    if (!deleteEntryCompleted(journal, request)) {
      throw new Error("Provider delete was not confirmed absent");
    }
  }
  return journal;
}

/** Delete only the exact accepted drill resources, in reverse dependency
 * order, then prove production again. Cleanup stays allowed after the lifetime
 * deadline so cost can be stopped: the required state is the explicit accepted
 * result (never an invented one), and the result reports `deadlineExceeded`
 * instead of extending the window. The approval binding is re-validated
 * without the one-hour freshness rule, which only guards creates/acceptance.
 *
 * An unaccepted CREATED result may be aborted this way only after the durable
 * lifetime elapsed (receipt-free cost stop): the exact plan, evidence,
 * runner, targets and cleanup journal are still validated, every delete
 * intent is still durable before its provider call, production is verified
 * after deletion, and the CLEANED result keeps `restoreDrillProved` false
 * with no invented acceptance. Before the deadline an unaccepted cleanup is
 * refused. */
export async function cleanupGroupRestoreExecution(
  result: GroupRestoreExecutionResult,
  plan: GroupRestorePlan,
  approval: GroupRestoreApproval,
  evidence: GroupRestoreEvidence,
  runner: GroupRestoreRunner,
  ports: GroupRestoreExecutionPorts,
  now: Date,
  persistJournal?: GroupRestoreJournalWriter,
): Promise<GroupRestoreExecutionResult> {
  assertDate(now);
  const acceptedCleanup = result.state === "RESTORE_DRILL_PROVED" &&
    result.restoreDrillProved === true && result.acceptance !== undefined;
  const abortCleanup = result.state === "CREATED" &&
    result.restoreDrillProved === false &&
    result.acceptance === undefined;
  if (!acceptedCleanup && !abortCleanup) {
    throw new Error("Cleanup requires explicit restored-guest acceptance");
  }
  validateGroupRestorePlan(plan);
  if (result.suffix !== plan.suffix) {
    throw new Error("Durable drill result suffix differs from the plan");
  }
  validateResultLifetimeShape(result.lifetime, plan);
  validateGroupRestoreTargets(plan, result.targets);
  validateGroupRestoreEvidence(plan, evidence);
  validateGroupRestoreCleanupJournal(result.journal, plan, result.targets);
  groupRestoreCliArgs(runner, []);
  if (acceptedCleanup) {
    const acceptance = result.acceptance!;
    if (
      approval.exactOperation !== GROUP_RESTORE_APPROVAL_OPERATION ||
      approval.planSha256 !== await groupRestorePlanDigest(plan)
    ) {
      throw new Error("Cleanup approval does not bind the reviewed plan");
    }
    await validateGroupRestoreAcceptance(acceptance, plan, now);
    const acceptanceAt = Date.parse(acceptance.observedAtUtc);
    const lifetimeStart = Date.parse(result.lifetime.startedAtUtc);
    const lifetimeDeadline = Date.parse(result.lifetime.deadlineAtUtc);
    if (
      result.deadlineExceeded !== false || acceptanceAt < lifetimeStart ||
      acceptanceAt >= lifetimeDeadline
    ) {
      throw new Error(
        "Durable acceptance is outside the recorded drill window",
      );
    }
  } else {
    // Receipt-free abort: the drill was created but never accepted and its
    // durable window has elapsed. An unaccepted cleanup before the deadline
    // is refused; the abort is never an acceptance substitute.
    if (!groupRestoreDeadlineExceeded(result.lifetime, now)) {
      throw new Error(
        "Unaccepted cleanup before the drill deadline is refused",
      );
    }
  }
  const journal = await executeGroupRestoreDeletes(
    result.journal,
    plan,
    runner,
    ports,
    now,
    persistJournal,
  );
  await ports.verifyProduction();
  return {
    ...result,
    state: "CLEANED",
    journal,
    deadlineExceeded: groupRestoreDeadlineExceeded(
      result.lifetime,
      ports.now(),
    ),
  };
}

/** Receipt-free abort of an exact partial create journal: one or more exact,
 * reconciled CREATED resources with no durable result because the create
 * stage failed after those creates (isolation proof or clone launch). The
 * reviewed plan, evidence, runner and exact journal identities are validated
 * first; the abort deletes only journaled resources in dependency order
 * (instance if present, then root, then boot), is refused before the durable
 * lifetime elapsed, publishes every delete intent durably first, reconciles
 * any surviving delete intent, and proves production again after deletion.
 * The CLEANED result keeps `restoreDrillProved` false, carries no acceptance
 * and reports `deadlineExceeded` true; it never requires or invents an
 * acceptance receipt. */
export async function abortPartialGroupRestoreExecution(
  plan: GroupRestorePlan,
  evidence: GroupRestoreEvidence,
  runner: GroupRestoreRunner,
  ports: GroupRestoreExecutionPorts,
  lifetime: GroupRestoreLifetime,
  journal: GroupRestoreJournal,
  now: Date,
  persistJournal?: GroupRestoreJournalWriter,
): Promise<GroupRestorePartialCleanupResult> {
  assertDate(now);
  validateGroupRestorePlan(plan);
  validateGroupRestoreEvidence(plan, evidence);
  validateResultLifetimeShape(lifetime, plan);
  groupRestoreCliArgs(runner, []);
  // Receipt-free abort is only a cost stop after the durable window elapsed;
  // before the deadline the drill can still be resumed or accepted.
  if (!groupRestoreDeadlineExceeded(lifetime, now)) {
    throw new Error(
      "Unaccepted cleanup before the drill deadline is refused",
    );
  }
  const kinds = journaledCreatedKinds(journal, plan);
  if (kinds.length === 0) {
    throw new Error(
      "Partial cleanup requires at least one exact created drill resource",
    );
  }
  const targets = partialTargetsFromJournal(plan, journal, kinds);
  const cleanedJournal = await executeGroupRestoreDeletes(
    journal,
    plan,
    runner,
    ports,
    now,
    persistJournal,
    kinds,
  );
  await ports.verifyProduction();
  return {
    state: "CLEANED",
    suffix: plan.suffix,
    restoreDrillProved: false,
    journal: cleanedJournal,
    targets,
    lifetime,
    deadlineExceeded: true,
  };
}

/** One bounded read-only production probe for the live verifier. */
export interface GroupRestoreProductionProbe {
  name: string;
  kind: "object" | "array";
  args: string[];
}

/** Deterministic read-only probe argv (subcommand only; the caller adds the
 * injected runner discipline) that reads the exact production facts the
 * verifier requires. No drill, backup or production mutation appears here. */
export function groupRestoreProductionProbes(
  plan: GroupRestorePlan,
): GroupRestoreProductionProbe[] {
  return [
    {
      name: "instance",
      kind: "object",
      args: [
        "compute",
        "instance",
        "get",
        "--instance-id",
        plan.source.instanceId,
      ],
    },
    {
      name: "bootAttachments",
      kind: "array",
      args: [
        "compute",
        "boot-volume-attachment",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--availability-domain",
        plan.availabilityDomain,
        "--instance-id",
        plan.source.instanceId,
        "--all",
      ],
    },
    {
      name: "volumeAttachments",
      kind: "array",
      args: [
        "compute",
        "volume-attachment",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--availability-domain",
        plan.availabilityDomain,
        "--instance-id",
        plan.source.instanceId,
        "--all",
      ],
    },
    {
      name: "vnicAttachments",
      kind: "array",
      args: [
        "compute",
        "vnic-attachment",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--instance-id",
        plan.source.instanceId,
        "--all",
      ],
    },
    {
      name: "bootVolume",
      kind: "object",
      args: [
        "bv",
        "boot-volume",
        "get",
        "--boot-volume-id",
        plan.source.bootVolumeId,
      ],
    },
    {
      name: "rootVolume",
      kind: "object",
      args: ["bv", "volume", "get", "--volume-id", plan.source.rootVolumeId],
    },
    {
      name: "publicIps",
      kind: "array",
      args: [
        "network",
        "public-ip",
        "list",
        "--compartment-id",
        plan.source.compartmentId,
        "--scope",
        "REGION",
        // Reserved addresses are region-scoped; availability-domain scope is
        // for ephemeral IPs only. Limiting the probe to RESERVED keeps the
        // verifier's exactly-one check scoped to production's reserved IP.
        "--lifetime",
        "RESERVED",
        "--all",
      ],
    },
    {
      // The only supported filters for private-ip list are the exact subnet or
      // vnic id (there is no tenancy-wide unscoped or compartment filter), so
      // this probe is deterministically scoped to the reviewed production
      // subnet. The verifier still proves the compartment binding of each
      // returned row.
      name: "privateIps",
      kind: "array",
      args: [
        "network",
        "private-ip",
        "list",
        "--subnet-id",
        plan.productionSubnetId,
        "--all",
      ],
    },
    {
      name: "volumeGroup",
      kind: "object",
      args: [
        "bv",
        "volume-group",
        "get",
        "--volume-group-id",
        plan.volumeGroupId,
      ],
    },
  ];
}

/** Live production facts gathered by the injected runner (never by tests). */
export interface GroupRestoreProductionObservation {
  instance: JsonRecord;
  bootAttachments: JsonRecord[];
  volumeAttachments: JsonRecord[];
  vnicAttachments: JsonRecord[];
  bootVolume: JsonRecord;
  rootVolume: JsonRecord;
  publicIps: JsonRecord[];
  privateIps: JsonRecord[];
  /** Volume-group member accounting comes from the group object's required
   * `volume-ids` list; the CLI has no separate volume-group-member command. */
  volumeGroup: JsonRecord;
}

function assertNumberField(
  value: JsonRecord,
  name: string,
  expected: number,
): void {
  const field = value[name];
  if (typeof field !== "number" || field !== expected) {
    throw new Error(`Production ${name} differs from the reviewed source`);
  }
}

function exactSingleRow(
  rows: JsonRecord[],
  field: string,
  id: string,
  label: string,
): JsonRecord {
  const exact = rows.filter((row) => row[field] === id);
  if (exact.length !== 1 || rows.length !== 1) {
    throw new Error(`${label} is not exactly the reviewed source`);
  }
  return exact[0]!;
}

/** Pure proof that the reviewed source instance is still RUNNING at exactly
 * 2 OCPU/12 GB with 200 GB of live storage, one public IP bound to the
 * reviewed source, exact source IDs/attachments and volume-group accounting.
 * Never weakens the production-online invariant. */
export function verifyGroupRestoreProduction(
  plan: GroupRestorePlan,
  observation: GroupRestoreProductionObservation,
): void {
  const {
    instance,
    bootAttachments,
    volumeAttachments,
    vnicAttachments,
    bootVolume,
    rootVolume,
    publicIps,
    privateIps,
    volumeGroup,
  } = observation;
  validateGroupRestorePlan(plan);
  if (
    instance.id !== plan.source.instanceId ||
    instance["compartment-id"] !== plan.source.compartmentId ||
    instance["lifecycle-state"] !== "RUNNING" ||
    instance.shape !== "VM.Standard.A1.Flex" ||
    // The reviewed drill AD must be the source instance's own AD: the
    // attachment probes are scoped to it and the restored targets stay beside
    // the running source.
    instance["availability-domain"] !== plan.availabilityDomain
  ) {
    throw new Error("Production source instance identity changed");
  }
  const shapeConfig = instance["shape-config"] as JsonRecord | undefined;
  if (
    !shapeConfig || shapeConfig.ocpus !== 2 ||
    shapeConfig["memory-in-gbs"] !== 12
  ) {
    throw new Error("Production source shape is not exactly 2 OCPU / 12 GB");
  }
  const bootAttachment = exactSingleRow(
    bootAttachments,
    "boot-volume-id",
    plan.source.bootVolumeId,
    "Production boot attachment",
  );
  if (
    bootAttachment["instance-id"] !== plan.source.instanceId ||
    bootAttachment["lifecycle-state"] !== "ATTACHED"
  ) {
    throw new Error("Production boot attachment is not the reviewed source");
  }
  const rootAttachment = exactSingleRow(
    volumeAttachments,
    "volume-id",
    plan.source.rootVolumeId,
    "Production root attachment",
  );
  if (
    rootAttachment["instance-id"] !== plan.source.instanceId ||
    rootAttachment["attachment-type"] !== "paravirtualized" ||
    rootAttachment["lifecycle-state"] !== "ATTACHED"
  ) {
    throw new Error("Production root attachment is not the reviewed source");
  }
  if (
    bootVolume.id !== plan.source.bootVolumeId ||
    bootVolume["compartment-id"] !== plan.source.compartmentId
  ) {
    throw new Error("Production boot volume identity changed");
  }
  if (
    rootVolume.id !== plan.source.rootVolumeId ||
    rootVolume["compartment-id"] !== plan.source.compartmentId
  ) {
    throw new Error("Production root volume identity changed");
  }
  assertNumberField(bootVolume, "size-in-gbs", 50);
  assertNumberField(rootVolume, "size-in-gbs", 150);
  if (
    publicIps.length !== 1 ||
    publicIps[0]!.id !== plan.productionReservedIpId ||
    publicIps[0]!["lifecycle-state"] !== "ASSIGNED"
  ) {
    throw new Error("Production must hold exactly one assigned public IP");
  }
  // The one reserved public IP must be bound to the reviewed source instance:
  // its private-ip-id resolves to exactly one private IP in the reviewed
  // compartment whose vnic-id maps to exactly one ATTACHED VNIC attachment on
  // that exact instance.
  const boundPrivateIpId = publicIps[0]!["private-ip-id"];
  if (
    typeof boundPrivateIpId !== "string" || boundPrivateIpId.length === 0
  ) {
    throw new Error("Production public IP is not bound to a private IP");
  }
  const boundPrivateIps = privateIps.filter((ip) =>
    ip.id === boundPrivateIpId &&
    ip["compartment-id"] === plan.source.compartmentId
  );
  if (boundPrivateIps.length !== 1) {
    throw new Error(
      "Production public IP is not bound to exactly one private IP",
    );
  }
  const boundVnicId = boundPrivateIps[0]!["vnic-id"];
  if (typeof boundVnicId !== "string" || boundVnicId.length === 0) {
    throw new Error("Production public IP is not bound to a VNIC");
  }
  const boundVnics = vnicAttachments.filter((vnic) =>
    vnic["vnic-id"] === boundVnicId &&
    vnic["lifecycle-state"] === "ATTACHED"
  );
  if (boundVnics.length !== 1) {
    throw new Error(
      "Production public IP is not bound to exactly one attached VNIC",
    );
  }
  if (boundVnics[0]!["instance-id"] !== plan.source.instanceId) {
    throw new Error("Production public IP is not bound to the reviewed source");
  }
  if (volumeGroup.id !== plan.volumeGroupId) {
    throw new Error("Production volume group identity changed");
  }
  const rawMemberIds = volumeGroup["volume-ids"];
  if (
    !Array.isArray(rawMemberIds) ||
    rawMemberIds.some((id) => typeof id !== "string")
  ) {
    throw new Error("Production volume group has no valid volume member list");
  }
  const memberIds = (rawMemberIds as string[]).sort();
  const expectedIds = [plan.source.bootVolumeId, plan.source.rootVolumeId]
    .sort();
  if (
    memberIds.length !== 2 ||
    JSON.stringify(memberIds) !== JSON.stringify(expectedIds)
  ) {
    throw new Error("Production volume group accounting changed");
  }
}

/** The exact restored targets the pre-boot isolation gate receives. */
export type GroupRestorePreBootIsolationTargets = Pick<
  GroupRestoreTargetResources,
  "bootVolumeId" | "rootVolumeId"
>;

/** Caller-supplied copied-volume preparation for the pre-boot isolation gate.
 * The OCI adapter's read-only network and target-identity proofs never mask
 * duplicate jobs on the restored copies: only this required hook performs
 * that preparation/masking, and the gate stays fail-closed while it is absent
 * or throws. A Pi or helper recovery owner may satisfy it later; the
 * executable wrapper never substitutes a readiness flag for the hook. */
export interface GroupRestorePreBootIsolationAdapter {
  /** Prepare/mask the exact restored copies before the first clone boot. */
  prepareCopiedVolumes(
    targets: GroupRestorePreBootIsolationTargets,
  ): Promise<void>;
}

/** Read-only OCI observations of the exact restored target volumes. */
export interface GroupRestoreIsolationTargetObservation {
  bootVolume: JsonRecord;
  rootVolume: JsonRecord;
}

/** Pure fail-closed proof that the observed restored volumes are exactly the
 * non-production targets passed to the pre-boot gate: the exact journaled
 * identities, in the reviewed compartment, AVAILABLE, at the reviewed member
 * sizes, and never an alias of the source, group, backup, production or
 * isolated plan identities. */
export function verifyGroupRestoreIsolationTargets(
  plan: GroupRestorePlan,
  targets: GroupRestorePreBootIsolationTargets,
  observed: GroupRestoreIsolationTargetObservation,
): void {
  validateGroupRestorePlan(plan);
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
  if (
    !targets.bootVolumeId || !targets.rootVolumeId ||
    targets.bootVolumeId === targets.rootVolumeId
  ) {
    throw new Error("Pre-boot isolation targets are not two distinct volumes");
  }
  if (
    forbidden.includes(targets.bootVolumeId) ||
    forbidden.includes(targets.rootVolumeId)
  ) {
    throw new Error(
      "Pre-boot isolation targets reference a protected identity",
    );
  }
  if (
    observed.bootVolume.id !== targets.bootVolumeId ||
    observed.rootVolume.id !== targets.rootVolumeId
  ) {
    throw new Error("Restored target volumes differ from the gate targets");
  }
  if (
    observed.bootVolume["compartment-id"] !== plan.source.compartmentId ||
    observed.rootVolume["compartment-id"] !== plan.source.compartmentId
  ) {
    throw new Error(
      "Restored target volumes are outside the reviewed compartment",
    );
  }
  if (
    observed.bootVolume["lifecycle-state"] !== "AVAILABLE" ||
    observed.rootVolume["lifecycle-state"] !== "AVAILABLE"
  ) {
    throw new Error("Restored target volumes are not AVAILABLE");
  }
  if (
    observed.bootVolume["size-in-gbs"] !== BOOT_MEMBER_SIZE_GB ||
    observed.rootVolume["size-in-gbs"] !== ROOT_MEMBER_SIZE_GB
  ) {
    throw new Error(
      "Restored target volumes differ from the reviewed member sizes",
    );
  }
}

/** Fail-closed pure proof with a strictly limited scope: it proves only the
 * reviewed routed-network evidence (isolated VCN, subnet, exactly one
 * security list, route table, internet gateway and DHCP options as read
 * back live) and the exact non-production restored-volume identities bound
 * to the gate. It is not a full first-boot isolation proof: full isolation
 * also requires the copied-volume preparation hook and guest-side
 * metadata/link-local suppression, which this function does not prove. The
 * routed-network check is the single reused proof (never duplicated with
 * contradictory rules), and the caller-supplied preparation adapter must
 * still run before the gate admits the clone launch. */
export function verifyGroupRestorePreBootIsolation(
  plan: GroupRestorePlan,
  network: DrillNetworkEvidence,
  targets: GroupRestorePreBootIsolationTargets,
  observed: GroupRestoreIsolationTargetObservation,
): void {
  verifyDrillRoutedNetwork(plan, network);
  verifyGroupRestoreIsolationTargets(plan, targets, observed);
}

/** OCI adapter for the pre-boot isolation gate: deterministic read-only
 * probes through the injected runner (`network subnet/vcn/security-list/
 * route-table/internet-gateway/dhcp-options get`, then `bv boot-volume get`
 * and `bv volume get` on the exact target ids), followed by the required
 * caller-supplied copied-volume preparation hook. No mutation command ever
 * appears; a missing adapter or any failed proof throws before the instance
 * create can be resumed. */
export function groupRestorePreBootIsolationVerifier(
  plan: GroupRestorePlan,
  runner: GroupRestoreRunner,
  call: (argv: string[]) => Promise<JsonRecord>,
  adapter: GroupRestorePreBootIsolationAdapter | undefined,
): GroupRestoreExecutionPorts["verifyPreBootIsolation"] {
  const read = (args: string[]) => call(groupRestoreCliArgs(runner, args));
  return async (targets) => {
    if (!adapter) {
      throw new Error(
        "Pre-boot isolation gate is not configured: a copied-volume preparation adapter is required; clone launch is refused",
      );
    }
    const subnet = dataObject(
      await read([
        "network",
        "subnet",
        "get",
        "--subnet-id",
        plan.isolatedSubnetId,
      ]),
    );
    const securityListIds = subnet["security-list-ids"];
    if (
      !Array.isArray(securityListIds) || securityListIds.length !== 1 ||
      typeof securityListIds[0] !== "string"
    ) {
      throw new Error(
        "Isolated subnet does not bind exactly one reviewed security list",
      );
    }
    const routeTableId = subnet["route-table-id"];
    const dhcpOptionsId = subnet["dhcp-options-id"];
    if (
      typeof routeTableId !== "string" || routeTableId === "" ||
      typeof dhcpOptionsId !== "string" || dhcpOptionsId === ""
    ) {
      throw new Error(
        "Isolated subnet misses its reviewed route table or DHCP options",
      );
    }
    const routeTable = dataObject(
      await read([
        "network",
        "route-table",
        "get",
        "--route-table-id",
        routeTableId,
      ]),
    );
    const routeRules = routeTable["route-rules"];
    if (!Array.isArray(routeRules) || routeRules.length !== 1) {
      throw new Error(
        "Isolated route table does not bind exactly one reviewed route",
      );
    }
    const gatewayId = routeRules[0]!["network-entity-id"];
    if (typeof gatewayId !== "string" || gatewayId === "") {
      throw new Error("Isolated route does not bind an internet gateway");
    }
    const vcn = dataObject(
      await read([
        "network",
        "vcn",
        "get",
        "--vcn-id",
        plan.isolatedVcnId,
      ]),
    );
    const securityList = dataObject(
      await read([
        "network",
        "security-list",
        "get",
        "--security-list-id",
        String(securityListIds[0]),
      ]),
    );
    const internetGateway = dataObject(
      await read([
        "network",
        "internet-gateway",
        "get",
        "--ig-id",
        gatewayId,
      ]),
    );
    const dhcpOptions = dataObject(
      await read([
        "network",
        "dhcp-options",
        "get",
        "--dhcp-options-id",
        dhcpOptionsId,
      ]),
    );
    const bootVolume = dataObject(
      await read([
        "bv",
        "boot-volume",
        "get",
        "--boot-volume-id",
        targets.bootVolumeId,
      ]),
    );
    const rootVolume = dataObject(
      await read([
        "bv",
        "volume",
        "get",
        "--volume-id",
        targets.rootVolumeId,
      ]),
    );
    verifyGroupRestorePreBootIsolation(
      plan,
      {
        vcn,
        subnet,
        securityLists: [securityList],
        routeTable,
        internetGateway,
        dhcpOptions,
      },
      targets,
      { bootVolume, rootVolume },
    );
    // The read-only proofs never mask duplicate jobs on the copies: this
    // caller-supplied hook is the only thing allowed to prepare them, and it
    // runs after the proofs and before any instance create can be resumed.
    await adapter.prepareCopiedVolumes(targets);
  };
}

/** Short bounded budget for one delete poll, derived from the lifetime window
 * and capped so no hard-coded long cost window exists. */
export const DELETE_POLL_INTERVAL_MS = 10_000;
export const DELETE_POLL_BUDGET_MS = 60_000;

export function groupRestoreDeletePollBudgetMs(
  plan: GroupRestorePlan,
  lifetime: GroupRestoreLifetime | undefined,
  nowMs: number,
): number {
  const planWindow = Number.isFinite(plan.maxDurationHours)
    ? plan.maxDurationHours * 3_600_000
    : DELETE_POLL_BUDGET_MS;
  if (!lifetime) {
    return Math.min(planWindow, DELETE_POLL_BUDGET_MS);
  }
  const remaining = Date.parse(lifetime.deadlineAtUtc) - nowMs;
  if (!Number.isFinite(remaining)) return DELETE_POLL_BUDGET_MS;
  return Math.min(
    Math.max(remaining, 0),
    planWindow,
    DELETE_POLL_BUDGET_MS,
  );
}

export interface GroupRestorePortsOptions {
  lifetime?: GroupRestoreLifetime;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Caller-supplied copied-volume preparation/masking adapter for the exact
   * restored targets. The read-only network and target-identity proofs never
   * mask duplicate jobs; the pre-boot isolation gate fails closed while this
   * typed adapter is absent or throws, so an unprepared or duplicate-job
   * guest can never boot beside production. */
  preBootIsolation?: GroupRestorePreBootIsolationAdapter;
}

/** OCI adapter used by the Pi. It performs no calls until a state-machine
 * function invokes one of its methods. Every call carries the provider-wide
 * no-retry and bounded timeout discipline plus `--output json`; the live
 * production verifier and the pre-boot isolation gate (read-only network and
 * target proofs plus the required caller-supplied copied-volume preparation)
 * are implemented here and use only read-only probes. */
export function ociGroupRestorePorts(
  plan: GroupRestorePlan,
  runner: GroupRestoreRunner,
  options: GroupRestorePortsOptions = {},
): GroupRestoreExecutionPorts {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
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
    now: () => new Date(now()),
    create: async (step) => {
      await call(step.argv);
      return observe(step.request);
    },
    delete: async (step, identity, argv) => {
      if (!identity.id) throw new Error("Cleanup identity is incomplete");
      await call(argv);
      const started = now();
      const budget = groupRestoreDeletePollBudgetMs(
        plan,
        options.lifetime,
        started,
      );
      for (;;) {
        const request = requestFor(plan, step.kind);
        const live = await observe(request);
        if (!live.length) return live;
        if (now() - started >= budget) return live;
        await sleep(DELETE_POLL_INTERVAL_MS);
      }
    },
    verifyProduction: async () => {
      const observation = {} as Record<string, unknown>;
      for (const probe of groupRestoreProductionProbes(plan)) {
        const response = await call(groupRestoreCliArgs(runner, probe.args));
        observation[probe.name] = probe.kind === "object"
          ? dataObject(response)
          : dataArray(response);
      }
      verifyGroupRestoreProduction(
        plan,
        observation as unknown as GroupRestoreProductionObservation,
      );
    },
    verifyPreBootIsolation: groupRestorePreBootIsolationVerifier(
      plan,
      runner,
      call,
      options.preBootIsolation,
    ),
  };
}
