/**
 * Source-only contract for one isolated, trial-funded Oracle volume-group
 * restore drill: plan approval, member-metadata proof, deterministic OCI
 * request construction and an intent/identity journal guard.
 *
 * This is a planning and guard module, not a live cloud runner. It never
 * issues a provider call, never moves the production reserved IP or DNS, and
 * never claims live recovery: the returned states are PLAN_VALID,
 * METADATA_PROVED and the RUN_READY run guard, each with
 * restoreDrillProved always false. The injected runner surface
 * (GroupRestoreRunner) is the only live-capable interface: the primary
 * supplies the OCI CLI path, profile, region and a CommandRunner; this module
 * still only builds deterministic argv and guards. Full first-boot isolation,
 * capacity checks and the live guest acceptance checklist belong to the
 * existing drill adapters and the acceptance runbook.
 */
import { type CommandRunner, type JsonRecord, stringField } from "./oci.ts";
import { validateBackupPair } from "./oci-restore.ts";
import { controllerCidr } from "./isolated-drill.ts";
import type { BackupSource } from "./weekly-backup.ts";

export const HOME_REGION = "us-ashburn-1";
export const BOOT_MEMBER_SIZE_GB = 50;
export const ROOT_MEMBER_SIZE_GB = 150;
export const MAX_DRILL_HOURS = 4;
export const SUFFIX_PATTERN = /^\d{8}T\d{6}Z$/;
export const GROUP_RESTORE_APPROVAL_OPERATION =
  "one isolated trial-funded volume-group restore drill";
export const APPROVAL_MAX_AGE_MS = 60 * 60 * 1000;
/** Account/trial evidence must be observed within this window before use. */
export const TRIAL_EVIDENCE_MAX_AGE_MS = 15 * 60 * 1000;
/** Provider-wide CLI discipline: no retries, short bounds, JSON output is
 * appended by the adapter before the subcommand arguments are executed. */
export const OCI_CLI_DISCIPLINE_FLAGS = [
  "--no-retry",
  "--connection-timeout",
  "10",
  "--read-timeout",
  "60",
] as const;

export type GroupRestoreResourceKind =
  | "boot-volume"
  | "root-volume"
  | "instance";
export type GroupRestoreIntentKind = "create" | "delete";

/** Exact bound plan for one drill. Every identity is explicit: nothing is
 * derived from a live inventory at plan time. */
export interface GroupRestorePlan {
  source: BackupSource;
  availabilityDomain: string;
  volumeGroupId: string;
  volumeGroupBackupId: string;
  bootMemberBackupId: string;
  rootMemberBackupId: string;
  productionSubnetId: string;
  productionVcnId: string;
  productionReservedIpId: string;
  isolatedSubnetId: string;
  isolatedVcnId: string;
  controllerIpv4: string;
  suffix: string;
  maxDurationHours: number;
  spendingCapUsd: number;
}

export interface GroupRestoreApproval {
  approvedAtUtc: string;
  expiresAtUtc: string;
  exactOperation: "one isolated trial-funded volume-group restore drill";
  planSha256: string;
  subscriptionTier: "FREE_AND_TRIAL";
  paymentModel: "FREE_TRIAL";
  availableTrialCreditsUsd: number;
  estimatedCostUsd: number;
  trialExpiresAtUtc: string;
  observedAtUtc: string;
}

/** Durable started/deadline window for one drill. The run wrapper persists it
 * before the first provider mutation and the state machine refuses new creates
 * or acceptance once the deadline elapsed. */
export interface GroupRestoreLifetime {
  startedAtUtc: string;
  deadlineAtUtc: string;
}

/** Restored drill resources as created by this contract's request builders. */
export interface GroupRestoreTargetResources {
  bootVolumeId: string;
  rootVolumeId: string;
  instanceId: string;
}

export interface GroupRestoreEvidence {
  group: JsonRecord;
  bootMember: JsonRecord;
  rootMember: JsonRecord;
}

export interface GroupRestoreResourceRequest {
  suffix: string;
  kind: GroupRestoreResourceKind;
  requestName: string;
}

export interface GroupRestoreIdentity {
  id: string;
  name: string;
}

export interface GroupRestoreObservedResource {
  id: string;
  displayName: string;
}

/** One durable audit record. A create entry carries the exact provider
 * identity once the create is proved; a delete entry is completed only after
 * the recorded identity is watched away. */
export interface GroupRestoreJournalEntry {
  request: GroupRestoreResourceRequest;
  intent: GroupRestoreIntentKind;
  createdAtUtc: string;
  completedAtUtc?: string;
  identity?: GroupRestoreIdentity;
}

export type GroupRestoreJournal = GroupRestoreJournalEntry[];

export interface GroupRestoreCleanupStep {
  kind: GroupRestoreResourceKind;
  requestName: string;
  action: "delete";
}

export interface GroupRestoreMetadataState {
  state: "PLAN_VALID" | "METADATA_PROVED";
  suffix: string;
  /** This module only proves plan and metadata; live drills are never claimed. */
  restoreDrillProved: false;
}

const RESOURCE_KINDS: GroupRestoreResourceKind[] = [
  "boot-volume",
  "root-volume",
  "instance",
];
const DISPLAY_PREFIX: Record<GroupRestoreResourceKind, string> = {
  "boot-volume": "arch-oracle-drill-boot",
  "root-volume": "arch-oracle-drill-root",
  instance: "arch-oracle-drill",
};

function assertPlanned(value: string, name: string): void {
  if (!value || value.startsWith("<") || value.includes("_OCID>")) {
    throw new Error(`${name} is not bound in the drill plan`);
  }
}

function assertDistinctIds(ids: string[]): void {
  if (new Set(ids).size !== ids.length) {
    throw new Error("Planned resource IDs are not distinct");
  }
}

function planIdentityIds(plan: GroupRestorePlan): string[] {
  return [
    plan.source.instanceId,
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.source.compartmentId,
    plan.volumeGroupId,
    plan.volumeGroupBackupId,
    plan.bootMemberBackupId,
    plan.rootMemberBackupId,
    plan.productionSubnetId,
    plan.isolatedSubnetId,
    plan.productionVcnId,
    plan.isolatedVcnId,
    plan.productionReservedIpId,
  ];
}

/** Fail-closed plan checks. The restricted side-by-side target must never
 * reuse a production identity, the controller must be one public IPv4, and
 * the suffix, lifetime and spending cap must be exact. */
export function validateGroupRestorePlan(plan: GroupRestorePlan): void {
  assertPlanned(plan.volumeGroupId, "volumeGroupId");
  assertPlanned(plan.volumeGroupBackupId, "volumeGroupBackupId");
  assertPlanned(plan.bootMemberBackupId, "bootMemberBackupId");
  assertPlanned(plan.rootMemberBackupId, "rootMemberBackupId");
  assertPlanned(plan.availabilityDomain, "availabilityDomain");
  assertPlanned(plan.productionSubnetId, "productionSubnetId");
  assertPlanned(plan.productionVcnId, "productionVcnId");
  assertPlanned(plan.productionReservedIpId, "productionReservedIpId");
  assertPlanned(plan.isolatedSubnetId, "isolatedSubnetId");
  assertPlanned(plan.isolatedVcnId, "isolatedVcnId");
  assertPlanned(plan.source.instanceId, "source.instanceId");
  assertPlanned(plan.source.bootVolumeId, "source.bootVolumeId");
  assertPlanned(plan.source.rootVolumeId, "source.rootVolumeId");
  assertPlanned(plan.source.compartmentId, "source.compartmentId");
  if (plan.source.region !== HOME_REGION) {
    throw new Error("Drill source is outside the home region us-ashburn-1");
  }
  if (!SUFFIX_PATTERN.test(plan.suffix)) {
    throw new Error("Drill suffix is not one UTC stamp");
  }
  if (
    !Number.isFinite(plan.maxDurationHours) ||
    plan.maxDurationHours <= 0 ||
    plan.maxDurationHours > MAX_DRILL_HOURS
  ) {
    throw new Error("Drill maximum lifetime must be positive and at most 4h");
  }
  if (!Number.isFinite(plan.spendingCapUsd) || plan.spendingCapUsd <= 0) {
    throw new Error("Drill spending cap must be a positive USD amount");
  }
  controllerCidr(plan.controllerIpv4);
  assertDistinctIds(planIdentityIds(plan));
}

/** Member-metadata proof for the bound online capture. Group must be the
 * AVAILABLE FULL capture of the planned compartment with exactly two distinct
 * members; every member must prove its exact source volume, size, FULL type
 * and group-backup binding. */
export function validateGroupRestoreEvidence(
  plan: GroupRestorePlan,
  evidence: GroupRestoreEvidence,
): void {
  validateGroupRestorePlan(plan);
  const { group, bootMember, rootMember } = evidence;
  if (stringField(bootMember, "id") !== plan.bootMemberBackupId) {
    throw new Error("Boot member backup differs from the plan");
  }
  if (stringField(rootMember, "id") !== plan.rootMemberBackupId) {
    throw new Error("Root member backup differs from the plan");
  }
  if (
    stringField(group, "id") !== plan.volumeGroupBackupId ||
    stringField(group, "volume-group-id") !== plan.volumeGroupId
  ) {
    throw new Error("Volume group capture differs from the plan");
  }
  validateBackupPair(
    bootMember,
    rootMember,
    plan.suffix,
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.source.compartmentId,
    {
      group,
      volumeGroupId: plan.volumeGroupId,
      volumeGroupBackupId: plan.volumeGroupBackupId,
    },
  );
}

/** Canonical-JSON SHA-256 of the exact reviewed plan bytes, with the same
 * digest semantics as the existing drill plan digest: reordered or extended
 * plan objects require a fresh reviewed digest. */
export async function groupRestorePlanDigest(
  plan: GroupRestorePlan,
): Promise<string> {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(JSON.stringify(plan)),
      ),
    ),
  ].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Exact-approval binding over the reviewed plan digest with the standard
 * one-hour approval window, plus the typed account/trial evidence: the
 * subscription must be FREE_AND_TRIAL / FREE_TRIAL with finite observed
 * coverage that still covers the complete `maxDurationHours` window, fresh
 * (at most 15 minutes old), with positive credits at or above the approved
 * spending cap and the estimated cost bounded by that cap. Every timestamp
 * must be strict canonical UTC; loose or offset timestamp text is refused
 * before any Date.parse result is trusted. */
export async function validateGroupRestoreApproval(
  plan: GroupRestorePlan,
  approval: GroupRestoreApproval,
  now: Date,
): Promise<void> {
  validateGroupRestorePlan(plan);
  assertTimestampUtc(approval.approvedAtUtc, "Approval approved timestamp");
  assertTimestampUtc(approval.expiresAtUtc, "Approval expiry timestamp");
  assertTimestampUtc(approval.observedAtUtc, "Approval evidence timestamp");
  assertTimestampUtc(approval.trialExpiresAtUtc, "Trial expiry timestamp");
  const approvedAt = Date.parse(approval.approvedAtUtc);
  const expiresAt = Date.parse(approval.expiresAtUtc);
  const observedAt = Date.parse(approval.observedAtUtc);
  const trialExpiresAt = Date.parse(approval.trialExpiresAtUtc);
  const timestamp = now.getTime();
  if (
    approval.exactOperation !== GROUP_RESTORE_APPROVAL_OPERATION ||
    approval.planSha256 !== await groupRestorePlanDigest(plan) ||
    approval.subscriptionTier !== "FREE_AND_TRIAL" ||
    approval.paymentModel !== "FREE_TRIAL" ||
    !Number.isFinite(approval.availableTrialCreditsUsd) ||
    !Number.isFinite(approval.estimatedCostUsd) ||
    approval.availableTrialCreditsUsd < plan.spendingCapUsd ||
    approval.estimatedCostUsd <= 0 ||
    approval.estimatedCostUsd > plan.spendingCapUsd ||
    !Number.isFinite(approvedAt) || !Number.isFinite(expiresAt) ||
    !Number.isFinite(observedAt) || !Number.isFinite(trialExpiresAt) ||
    observedAt > timestamp ||
    timestamp - observedAt > TRIAL_EVIDENCE_MAX_AGE_MS ||
    trialExpiresAt - timestamp <= plan.maxDurationHours * 3_600_000 ||
    approvedAt > timestamp || timestamp >= expiresAt ||
    expiresAt - approvedAt > APPROVAL_MAX_AGE_MS ||
    timestamp - approvedAt > APPROVAL_MAX_AGE_MS
  ) {
    throw new Error(
      "Exact drill approval, fresh trial coverage or plan binding is absent, expired or does not match the plan",
    );
  }
}

/** Compute the durable lifetime window for one drill run: the plan's exact
 * `maxDurationHours` from the moment the wrapper starts the run. */
export function groupRestoreLifetime(
  now: Date,
  plan: GroupRestorePlan,
): GroupRestoreLifetime {
  if (!Number.isFinite(now.getTime())) {
    throw new Error("Run time is invalid");
  }
  return {
    startedAtUtc: now.toISOString(),
    deadlineAtUtc: new Date(
      now.getTime() + plan.maxDurationHours * 3_600_000,
    ).toISOString(),
  };
}

/** Refuse a malformed lifetime or one whose window has elapsed. This is the
 * only lifetime check used by creates and acceptance; cleanup may still run
 * after the deadline and reports the condition in its result. */
export function validateGroupRestoreLifetime(
  lifetime: GroupRestoreLifetime,
  plan: GroupRestorePlan,
  now: Date,
): void {
  if (!Number.isFinite(now.getTime())) {
    throw new Error("Run time is invalid");
  }
  assertTimestampUtc(lifetime.startedAtUtc, "Lifetime start timestamp");
  assertTimestampUtc(lifetime.deadlineAtUtc, "Lifetime deadline timestamp");
  const startedAt = Date.parse(lifetime.startedAtUtc);
  const deadlineAt = Date.parse(lifetime.deadlineAtUtc);
  if (startedAt > now.getTime()) {
    throw new Error("Durably recorded drill lifetime starts in the future");
  }
  if (deadlineAt - startedAt !== plan.maxDurationHours * 3_600_000) {
    throw new Error(
      "Durably recorded drill lifetime does not match the plan window",
    );
  }
  if (now.getTime() >= deadlineAt) {
    throw new Error(
      "Drill lifetime elapsed; new creates and acceptance are refused",
    );
  }
}

/** Whether the deadline has passed at `now`; reported in the result/journal
 * instead of silently extending the window. */
export function groupRestoreDeadlineExceeded(
  lifetime: GroupRestoreLifetime,
  now: Date,
): boolean {
  return now.getTime() >= Date.parse(lifetime.deadlineAtUtc);
}

/** Restored target volumes and clone must stay beside the running source and
 * never alias a production, group or member identity. */
export function validateGroupRestoreTargets(
  plan: GroupRestorePlan,
  targets: GroupRestoreTargetResources,
): void {
  validateGroupRestorePlan(plan);
  assertPlanned(targets.bootVolumeId, "targets.bootVolumeId");
  assertPlanned(targets.rootVolumeId, "targets.rootVolumeId");
  assertPlanned(targets.instanceId, "targets.instanceId");
  assertDistinctIds([
    targets.bootVolumeId,
    targets.rootVolumeId,
    targets.instanceId,
    ...planIdentityIds(plan),
  ]);
}

export function groupRestoreDisplayName(
  kind: GroupRestoreResourceKind,
  suffix: string,
): string {
  return `${DISPLAY_PREFIX[kind]}-${suffix}`;
}

export function groupRestorePlanState(
  plan: GroupRestorePlan,
): GroupRestoreMetadataState {
  validateGroupRestorePlan(plan);
  return {
    state: "PLAN_VALID",
    suffix: plan.suffix,
    restoreDrillProved: false,
  };
}

export function groupRestoreMetadataState(
  plan: GroupRestorePlan,
  evidence: GroupRestoreEvidence,
): GroupRestoreMetadataState {
  validateGroupRestoreEvidence(plan, evidence);
  return {
    state: "METADATA_PROVED",
    suffix: plan.suffix,
    restoreDrillProved: false,
  };
}

function assertNoProductionReferences(
  plan: GroupRestorePlan,
  args: string[],
): void {
  const productionIds = [
    plan.source.instanceId,
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.productionReservedIpId,
    plan.productionSubnetId,
    plan.productionVcnId,
  ];
  for (const id of productionIds) {
    if (args.includes(id)) {
      throw new Error("Request cannot reference a production resource");
    }
  }
}

/** Deterministic OCI CLI request that restores the 50 GB boot member as a
 * boot volume in the one approved availability domain. */
export function buildRestoredBootVolumeRequest(
  plan: GroupRestorePlan,
): string[] {
  validateGroupRestorePlan(plan);
  const args = [
    "bv",
    "boot-volume",
    "create",
    "--availability-domain",
    plan.availabilityDomain,
    "--compartment-id",
    plan.source.compartmentId,
    "--boot-volume-backup-id",
    plan.bootMemberBackupId,
    "--display-name",
    groupRestoreDisplayName("boot-volume", plan.suffix),
    "--vpus-per-gb",
    "10",
    "--wait-for-state",
    "AVAILABLE",
  ];
  assertNoProductionReferences(plan, args);
  return args;
}

/** Deterministic OCI CLI request that restores the 150 GB root member as a
 * block volume in the one approved availability domain. */
export function buildRestoredRootVolumeRequest(
  plan: GroupRestorePlan,
): string[] {
  validateGroupRestorePlan(plan);
  const args = [
    "bv",
    "volume",
    "create",
    "--availability-domain",
    plan.availabilityDomain,
    "--compartment-id",
    plan.source.compartmentId,
    "--volume-backup-id",
    plan.rootMemberBackupId,
    "--display-name",
    groupRestoreDisplayName("root-volume", plan.suffix),
    "--vpus-per-gb",
    "10",
    "--wait-for-state",
    "AVAILABLE",
  ];
  assertNoProductionReferences(plan, args);
  return args;
}

/** Deterministic OCI CLI request that launches the 2 OCPU / 12 GB A1 clone in
 * the isolated subnet from the restored boot with the restored root as one
 * paravirtualized attachment and an ephemeral public IP. The production
 * reserved IP is never referenced. Launch options are intentionally omitted:
 * OCI rejects overrides for a boot volume restored from this image, so the
 * provider must inherit the stored boot-image capabilities. */
export function buildGroupRestoreLaunchRequest(
  plan: GroupRestorePlan,
  bootVolumeId: string,
  rootVolumeId: string,
): string[] {
  validateGroupRestorePlan(plan);
  assertPlanned(bootVolumeId, "bootVolumeId");
  assertPlanned(rootVolumeId, "rootVolumeId");
  if (bootVolumeId === rootVolumeId) {
    throw new Error("Launch target volumes must be distinct");
  }
  const memberIds = [
    plan.source.bootVolumeId,
    plan.source.rootVolumeId,
    plan.bootMemberBackupId,
    plan.rootMemberBackupId,
  ];
  if (
    memberIds.includes(bootVolumeId) || memberIds.includes(rootVolumeId)
  ) {
    throw new Error(
      "Launch request cannot use production or member volume IDs",
    );
  }
  const args = [
    "compute",
    "instance",
    "launch",
    "--availability-domain",
    plan.availabilityDomain,
    "--compartment-id",
    plan.source.compartmentId,
    "--subnet-id",
    plan.isolatedSubnetId,
    "--shape",
    "VM.Standard.A1.Flex",
    "--shape-config",
    JSON.stringify({ ocpus: 2, memoryInGBs: 12 }),
    "--source-boot-volume-id",
    bootVolumeId,
    "--launch-volume-attachments",
    JSON.stringify([{ type: "paravirtualized", volumeId: rootVolumeId }]),
    "--display-name",
    groupRestoreDisplayName("instance", plan.suffix),
    "--assign-public-ip",
    "true",
    "--wait-for-state",
    "RUNNING",
  ];
  assertNoLaunchOptions(args);
  assertNoProductionReferences(plan, args);
  return args;
}

/** OCI rejects launch-option overrides for this restored boot volume. Refuse
 * the flag before any provider call so a future edit cannot reintroduce the
 * known-invalid request shape. */
function assertNoLaunchOptions(args: string[]): void {
  if (args.includes("--launch-options")) {
    throw new Error(
      "Launch request must omit unsupported launch-option overrides",
    );
  }
}

/** Deterministic teardown: detach/terminate the clone first, then release the
 * block volume, then the restored boot volume. Every delete remains gated by
 * the journal guard. */
export function groupRestoreCleanupOrder(
  plan: GroupRestorePlan,
): GroupRestoreCleanupStep[] {
  validateGroupRestorePlan(plan);
  return [
    {
      kind: "instance",
      requestName: groupRestoreDisplayName("instance", plan.suffix),
      action: "delete",
    },
    {
      kind: "root-volume",
      requestName: groupRestoreDisplayName("root-volume", plan.suffix),
      action: "delete",
    },
    {
      kind: "boot-volume",
      requestName: groupRestoreDisplayName("boot-volume", plan.suffix),
      action: "delete",
    },
  ];
}

function validateResourceRequest(request: GroupRestoreResourceRequest): void {
  if (!RESOURCE_KINDS.includes(request.kind)) {
    throw new Error("Unsupported drill resource kind");
  }
  if (!SUFFIX_PATTERN.test(request.suffix)) {
    throw new Error("Journal request suffix is not one UTC stamp");
  }
  assertPlanned(request.requestName, "requestName");
}

export function assertTimestampUtc(value: string, label: string): void {
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    throw new Error(`${label} is not a UTC timestamp`);
  }
}

function entriesFor(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
): GroupRestoreJournalEntry[] {
  return journal.filter((entry) =>
    entry.request.suffix === request.suffix &&
    entry.request.kind === request.kind &&
    entry.request.requestName === request.requestName
  );
}

function exactIdentity(
  identity: GroupRestoreIdentity | undefined,
): GroupRestoreIdentity {
  if (!identity || !identity.id || !identity.name) {
    throw new Error("Recorded drill resource identity is incomplete");
  }
  return identity;
}

function findCreateEntry(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
): GroupRestoreJournalEntry {
  const create = entriesFor(journal, request).find((entry) =>
    entry.intent === "create"
  );
  if (!create) {
    throw new Error("No intent record exists for this resource request");
  }
  return create;
}

/** Record a durable create/delete intent before any mutation. A create is
 * refused when a same-name live resource is unproved; a delete requires the
 * exact recorded create identity and behaves idempotently once completion was
 * already accepted. */
export function journalGroupRestoreIntent(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
  intent: GroupRestoreIntentKind,
  nowUtc: string,
  live: GroupRestoreObservedResource[] = [],
): GroupRestoreJournal {
  validateResourceRequest(request);
  assertTimestampUtc(nowUtc, "Journal timestamp");
  const entries = entriesFor(journal, request);
  const create = entries.find((entry) => entry.intent === "create");
  let deleteIdentity: GroupRestoreIdentity | undefined;
  const done = entries.some((entry) =>
    entry.intent === "delete" && Boolean(entry.completedAtUtc)
  );
  if (intent === "delete") {
    if (done) return journal;
    if (!create) {
      throw new Error(
        "Delete intent requires the exact recorded create identity",
      );
    }
    deleteIdentity = exactIdentity(create.identity);
    if (entries.length !== 1) {
      // A second intent or another create is ambiguous.
      throw new Error("Ambiguous journal state for this resource request");
    }
  } else {
    if (done) {
      throw new Error("This drill resource was already created and cleaned up");
    }
    if (entries.length !== 0) {
      throw new Error("Ambiguous journal state for this resource request");
    }
    const named = live.filter((resource) =>
      resource.displayName === request.requestName
    );
    if (named.length !== 0) {
      throw new Error("Same-name resource exists without a recorded identity");
    }
  }
  return [...journal, {
    request,
    intent,
    createdAtUtc: nowUtc,
    ...(deleteIdentity ? { identity: deleteIdentity } : {}),
  }];
}

/** Reconcile a provider observation against the journal. Creates record the
 * exact provider identity; deletes complete only after the recorded identity
 * is proved. Every path fails closed on missing intent, ambiguity, incomplete
 * identity or a same-name resource that is not the recorded drill resource. */
export function reconcileGroupRestoreResource(
  journal: GroupRestoreJournal,
  request: GroupRestoreResourceRequest,
  intent: GroupRestoreIntentKind,
  live: GroupRestoreObservedResource[],
  nowUtc: string,
): GroupRestoreJournal {
  validateResourceRequest(request);
  assertTimestampUtc(nowUtc, "Journal timestamp");
  const entries = entriesFor(journal, request);
  const creates = entries.filter((entry) => entry.intent === "create");
  const unresolvedDeletes = entries.filter((entry) =>
    entry.intent === "delete" && !entry.completedAtUtc
  );
  if (creates.length > 1 || unresolvedDeletes.length > 1) {
    throw new Error("Ambiguous journal state for this resource request");
  }
  const create = findCreateEntry(journal, request);
  const identity = create.identity ? exactIdentity(create.identity) : undefined;
  const named = live.filter((resource) =>
    resource.displayName === request.requestName
  );
  if (intent === "delete") {
    const deleteEntry = entries.find((entry) => entry.intent === "delete");
    if (!deleteEntry) {
      throw new Error("Missing delete intent record before delete");
    }
    if (!identity) {
      throw new Error("Recorded drill resource identity is incomplete");
    }
    const exact = named.filter((resource) => resource.id === identity.id);
    if (deleteEntry.completedAtUtc) {
      if (named.length === 0) return journal;
      throw new Error("Cleaned-up drill resource identity is live again");
    }
    if (named.length === 0) {
      return journal.map((entry) =>
        entry === deleteEntry ? { ...entry, completedAtUtc: nowUtc } : entry
      );
    }
    if (exact.length > 1) {
      throw new Error("Ambiguous journal state for this resource request");
    }
    if (exact.length === 0 || named.length > 1) {
      throw new Error("Same-name resource is not the recorded drill resource");
    }
    return journal;
  }
  if (
    entries.some((entry) =>
      entry.intent === "delete" && Boolean(entry.completedAtUtc)
    )
  ) {
    throw new Error("This drill resource was already created and cleaned up");
  }
  if (create.identity) {
    const exact = named.filter((resource) => resource.id === identity!.id);
    if (named.length === 0) {
      throw new Error(
        "Recorded create identity is absent from the live inventory",
      );
    }
    if (exact.length > 1) {
      throw new Error("Ambiguous journal state for this resource request");
    }
    if (exact.length === 0 || named.length > 1) {
      throw new Error("Same-name resource is not the recorded drill resource");
    }
    return journal;
  }
  if (named.length === 0) {
    throw new Error("Create returned no exact resource identity");
  }
  if (named.length > 1) {
    throw new Error("Ambiguous journal state for this resource request");
  }
  return journal.map((entry) =>
    entry === create
      ? { ...entry, identity: { id: named[0].id, name: request.requestName } }
      : entry
  );
}

/** Injected OCI command surface for the live drill stage. The primary owns
 * the CLI path, profile, home region and CommandRunner; this module never
 * reads private files, credentials or live state. */
export interface GroupRestoreRunner {
  ociCliPath: string;
  ociProfile: string;
  region: string;
  run: CommandRunner;
}

/** Deterministic OCI CLI argv for the exact injected runner surface:
 * provider-wide flags first (profile, region, no-retry and bounded
 * connection/read timeouts), then the reviewed subcommand request. Every
 * value must be bound to concrete non-placeholder text. The adapter appends
 * `--output json` for every call. */
export function groupRestoreCliArgs(
  runner: GroupRestoreRunner,
  args: string[],
): string[] {
  for (
    const [name, value] of [
      ["ociCliPath", runner.ociCliPath],
      ["ociProfile", runner.ociProfile],
      ["region", runner.region],
    ] as const
  ) {
    if (
      value === undefined || value === "" || value.includes("<") ||
      value.includes("OCID>")
    ) {
      throw new Error(`${name} is not bound in the drill runner`);
    }
  }
  if (runner.region !== HOME_REGION) {
    throw new Error(
      "Drill runner region is outside the home region us-ashburn-1",
    );
  }
  return [
    "--profile",
    runner.ociProfile,
    "--region",
    runner.region,
    ...OCI_CLI_DISCIPLINE_FLAGS,
    ...args,
  ];
}

/** Bounded, deterministic pre-run request: the exact plan, its reviewed
 * approval, the proved group capture, the distinct restored targets and the
 * primary-owned durable journal. Nothing here is derived from live state. */
export interface GroupRestoreRunInput {
  plan: GroupRestorePlan;
  approval: GroupRestoreApproval;
  evidence: GroupRestoreEvidence;
  targets: GroupRestoreTargetResources;
  journal: GroupRestoreJournal;
  now: Date;
  /** Durable window persisted by the wrapper; required for a resume. */
  lifetime?: GroupRestoreLifetime;
}

/** One deterministic create step of a guarded run. The primary journals the
 * create intent before executing `argv` through the injected runner and
 * reconciles the returned identity immediately after. */
export interface GroupRestoreRunStep {
  kind: GroupRestoreResourceKind;
  request: GroupRestoreResourceRequest;
  intent: "create";
  ociCliPath: string;
  argv: string[];
}

/** Fail-closed pre-run guard result. RUN_READY binds plan, approval, capture
 * metadata, targets and journal consistency; it never claims live restore
 * proof (`restoreDrillProved` stays false). */
export interface GroupRestoreRunGuard {
  state: "RUN_READY";
  suffix: string;
  restoreDrillProved: false;
  steps: GroupRestoreRunStep[];
  cleanup: GroupRestoreCleanupStep[];
}

function exactResourceRequest(
  plan: GroupRestorePlan,
  kind: GroupRestoreResourceKind,
): GroupRestoreResourceRequest {
  return {
    suffix: plan.suffix,
    kind,
    requestName: groupRestoreDisplayName(kind, plan.suffix),
  };
}

export function validateGroupRestoreJournal(
  journal: GroupRestoreJournal,
  plan: GroupRestorePlan,
): void {
  for (const kind of RESOURCE_KINDS) {
    const request = exactResourceRequest(plan, kind);
    const entries = entriesFor(journal, request);
    const stale = journal.filter((entry) =>
      entry.request.suffix === plan.suffix && entry.request.kind === kind &&
      entry.request.requestName !== request.requestName
    );
    if (stale.length !== 0) {
      throw new Error(`Stale journal intent for drill ${kind} resource`);
    }
    if (
      entries.some((entry) =>
        entry.intent === "delete" && Boolean(entry.completedAtUtc)
      )
    ) {
      throw new Error(
        `Drill ${kind} resource was already created and cleaned up`,
      );
    }
    if (entries.some((entry) => entry.intent === "delete")) {
      throw new Error(`Drill ${kind} resource has an unresolved delete intent`);
    }
    if (entries.filter((entry) => entry.intent === "create").length > 1) {
      throw new Error(`Ambiguous journal state for drill ${kind} resource`);
    }
  }
}

/** Pure pre-run guard: refuse stale or ambiguous intents, an expired
 * approval, mismatched group/member metadata, wrong target identity or any
 * unbound runner value before a single mutation. The returned steps are the
 * exact deterministic argv for the injected CommandRunner. */
export async function guardGroupRestoreRun(
  input: GroupRestoreRunInput,
  runner: GroupRestoreRunner,
): Promise<GroupRestoreRunGuard> {
  const { plan, approval, evidence, targets, journal, now } = input;
  validateGroupRestorePlan(plan);
  await validateGroupRestoreApproval(plan, approval, now);
  validateGroupRestoreEvidence(plan, evidence);
  validateGroupRestoreTargets(plan, targets);
  validateGroupRestoreJournal(journal, plan);
  if (input.lifetime !== undefined) {
    validateGroupRestoreLifetime(input.lifetime, plan, now);
  }
  const steps: GroupRestoreRunStep[] = [];
  for (const kind of RESOURCE_KINDS) {
    const request = exactResourceRequest(plan, kind);
    const argv = kind === "boot-volume"
      ? groupRestoreCliArgs(runner, buildRestoredBootVolumeRequest(plan))
      : kind === "root-volume"
      ? groupRestoreCliArgs(runner, buildRestoredRootVolumeRequest(plan))
      : groupRestoreCliArgs(
        runner,
        buildGroupRestoreLaunchRequest(
          plan,
          targets.bootVolumeId,
          targets.rootVolumeId,
        ),
      );
    steps.push({
      kind,
      request,
      intent: "create",
      ociCliPath: runner.ociCliPath,
      argv,
    });
  }
  return {
    state: "RUN_READY",
    suffix: plan.suffix,
    restoreDrillProved: false,
    steps,
    cleanup: groupRestoreCleanupOrder(plan),
  };
}
