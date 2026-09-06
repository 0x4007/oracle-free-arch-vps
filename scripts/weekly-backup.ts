import type {
  OnlineCaptureIdentity,
  SourceContinuityEvidence,
} from "./online-backup-contract.ts";
import { type JsonRecord, numberField, stringField } from "./oci.ts";

const SUFFIX_PATTERN = /^\d{8}T\d{6}Z$/;
const SOURCE_KEYS = [
  "instanceId",
  "bootVolumeId",
  "rootVolumeId",
  "compartmentId",
  "region",
] as const;

export interface BackupSource {
  instanceId: string;
  bootVolumeId: string;
  rootVolumeId: string;
  compartmentId: string;
  region: string;
}

export interface BackupPair {
  suffix: string;
  bootId: string;
  rootId: string;
  /** Set only when both members came from one OCI volume-group backup. */
  volumeGroupBackupId?: string;
}

export interface BackupPolicy {
  source: BackupSource;
  /** Existing, separately provisioned OCI volume group containing both disks. */
  volumeGroupId: string;
  standingApproval: {
    approvedAtUtc: string;
    exactOperation: "weekly paired backup rotation";
    source: BackupSource;
  };
  acceptedPair: BackupPair;
  // The initial pair stays until the separately recorded restore drill passes.
  retainPreviousPair: boolean;
  allowFifthSlot: boolean;
}

/** New journals use only these phases. Historical outage phases are deliberately
 * absent so they cannot be replayed by the online scheduler. */
export type BackupPhase =
  | "planned"
  | "backing-up"
  | "pair-available"
  | "source-accepted"
  | "retiring"
  | "complete"
  | "failed";

export interface BackupJournal {
  mode: "online";
  source: BackupSource;
  previousPair: BackupPair;
  suffix: string;
  phase: BackupPhase;
  createdAtUtc: string;
  updatedAtUtc: string;

  /** Durable group create intent and returned ID. Intent is saved before the
   * provider call and the ID is saved before any waiter is started. */
  volumeGroupBackupIntent?: boolean;
  volumeGroupBackupId?: string;
  captureIdentity?: OnlineCaptureIdentity;
  sourceContinuityBeforeCapture?: SourceContinuityEvidence;
  sourceContinuityAfterCapture?: SourceContinuityEvidence;

  sourceAcceptedAtUtc?: string;
  failure?: string;

  // Historical fields remain parseable for migration/archive readers. The
  // online engine never calls a stop, start, quiesce, or recovery operation.
  stoppedEpoch?: string;
  bootIntent?: boolean;
  rootIntent?: boolean;
  bootId?: string;
  rootId?: string;
  outageStartedAtUtc?: string;
  recoveryStatus?: "needed" | "running-accepted" | "failed";
}

export interface BackupSnapshot {
  source: BackupSource;
  instanceState: string;
  bootBackups: JsonRecord[];
  rootBackups: JsonRecord[];
  /** Every active member backup in the accounted tenancy. */
  allBackupCount: number;
  /** Every active group-backup wrapper in the accounted tenancy. */
  allVolumeGroupBackupCount?: number;
  freeBackupLimit: number;
  volumeGroups?: JsonRecord[];
  volumeGroupBackups?: JsonRecord[];
  sourceAttachmentsProved: boolean;
  sourceVolumeGroupProved?: boolean;
  /** Provider group-wrapper accounting is a live gate. Unknown is false. */
  groupAccountingProved?: boolean;
  freeEligibilityProved: boolean;
  writersAbsent: boolean;
}

/** The online provider adapter has no source outage or recovery methods. */
export interface BackupOperations {
  now(): Date;
  snapshot(): Promise<BackupSnapshot>;
  save(journal: BackupJournal): Promise<void>;
  observeSource(): Promise<SourceContinuityEvidence>;
  acceptSource(): Promise<void>;
  createBackupGroup(suffix: string): Promise<string>;
  waitBackupGroup(id: string): Promise<void>;
  deleteBackupGroup(
    id: string,
    members: Pick<BackupPair, "bootId" | "rootId">,
  ): Promise<void>;
  /** Used only for an old standalone pair. Grouped pairs use the method above. */
  deleteBackup(kind: "boot" | "root", id: string): Promise<void>;
}

export interface BackupRunControl {
  beforeCapture?: () => Promise<void>;
}

function equalSource(a: BackupSource, b: BackupSource): boolean {
  return Object.keys(a).length === SOURCE_KEYS.length &&
    SOURCE_KEYS.every((key) =>
      typeof a[key] === "string" && a[key] !== "" && a[key] === b[key]
    );
}

function equalOptional(a: string | undefined, b: string | undefined): boolean {
  return (a ?? "") === (b ?? "");
}

function equalPair(a: BackupPair, b: BackupPair): boolean {
  return a.suffix === b.suffix && a.bootId === b.bootId &&
    a.rootId === b.rootId &&
    equalOptional(a.volumeGroupBackupId, b.volumeGroupBackupId);
}

function parseUtc(value: unknown, label: string): number {
  if (typeof value !== "string") throw new Error(`${label} is not a timestamp`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} is not a timestamp`);
  return parsed;
}

function validId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export function validateStandingApproval(
  policy: BackupPolicy,
  now: Date,
): void {
  const approvedAt = parseUtc(
    policy.standingApproval.approvedAtUtc,
    "Standing approval timestamp",
  );
  if (
    policy.standingApproval.exactOperation !==
      "weekly paired backup rotation" ||
    approvedAt > now.getTime() ||
    !equalSource(policy.source, policy.standingApproval.source) ||
    !validId(policy.volumeGroupId)
  ) {
    throw new Error("Standing backup approval does not bind the exact source");
  }
  if (
    !SUFFIX_PATTERN.test(policy.acceptedPair.suffix) ||
    !validId(policy.acceptedPair.bootId) ||
    !validId(policy.acceptedPair.rootId) ||
    policy.acceptedPair.bootId === policy.acceptedPair.rootId ||
    (policy.acceptedPair.volumeGroupBackupId !== undefined &&
      !validId(policy.acceptedPair.volumeGroupBackupId))
  ) {
    throw new Error("Accepted backup pair is not configured");
  }
}

export function newBackupJournal(
  policy: BackupPolicy,
  now: Date,
): BackupJournal {
  validateStandingApproval(policy, now);
  const suffix = now.toISOString().replace(/[-:]/g, "").replace(
    /\.\d{3}Z$/,
    "Z",
  );
  if (suffix === policy.acceptedPair.suffix) {
    throw new Error("Backup suffix collision");
  }
  return {
    mode: "online",
    source: structuredClone(policy.source),
    previousPair: structuredClone(policy.acceptedPair),
    suffix,
    phase: "planned",
    createdAtUtc: now.toISOString(),
    updatedAtUtc: now.toISOString(),
  };
}

function memberFor(
  snapshot: BackupSnapshot,
  id: string,
): { item: JsonRecord; kind: "boot" | "root" } | undefined {
  const boot = (snapshot.bootBackups ?? []).filter((item) => item.id === id);
  const root = (snapshot.rootBackups ?? []).filter((item) => item.id === id);
  if (boot.length + root.length !== 1) {
    if (boot.length + root.length > 1) {
      throw new Error("Backup member ID is duplicated across OCI inventories");
    }
    return undefined;
  }
  return boot.length === 1
    ? { item: boot[0], kind: "boot" }
    : { item: root[0], kind: "root" };
}

function validateMember(
  item: JsonRecord,
  kind: "boot" | "root",
  source: BackupSource,
): void {
  if (stringField(item, "lifecycle-state") !== "AVAILABLE") {
    throw new Error(`The ${kind} backup is not AVAILABLE`);
  }
  if (stringField(item, "type") !== "FULL") {
    throw new Error(`The ${kind} backup is not FULL`);
  }
  if (numberField(item, "size-in-gbs") !== (kind === "boot" ? 50 : 150)) {
    throw new Error(`The ${kind} backup size changed`);
  }
  const sourceKey = kind === "boot" ? "boot-volume-id" : "volume-id";
  const sourceId = kind === "boot" ? source.bootVolumeId : source.rootVolumeId;
  if (
    item[sourceKey] !== sourceId ||
    item["compartment-id"] !== source.compartmentId
  ) {
    throw new Error(`The ${kind} backup source changed`);
  }
  parseUtc(item["time-created"], `${kind} backup time-created`);
}

function exactIds(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((item) => !validId(item))) {
    throw new Error(`${label} is not a list of IDs`);
  }
  return value as string[];
}

function findGroup(
  snapshot: BackupSnapshot,
  id: string,
): JsonRecord | undefined {
  const matches = (snapshot.volumeGroupBackups ?? []).filter((item) =>
    item.id === id
  );
  if (matches.length > 1) throw new Error("Volume group backup is duplicated");
  return matches[0];
}

function captureIdentityFromSnapshot(
  policy: BackupPolicy,
  snapshot: BackupSnapshot,
  groupBackupId: string,
  expectedSuffix?: string,
): OnlineCaptureIdentity {
  const groupBackup = findGroup(snapshot, groupBackupId);
  if (!groupBackup) {
    throw new Error("Volume group backup is absent from inventory");
  }
  if (
    groupBackup["volume-group-id"] !== policy.volumeGroupId ||
    groupBackup["compartment-id"] !== policy.source.compartmentId ||
    stringField(groupBackup, "type") !== "FULL" ||
    stringField(groupBackup, "lifecycle-state") !== "AVAILABLE"
  ) throw new Error("Volume group backup identity is not approved");
  const captureAt = parseUtc(
    groupBackup["time-created"],
    "Volume group backup time-created",
  );
  if (expectedSuffix && groupBackup["display-name"] !== undefined) {
    // Group display names are supplied as a helpful hint. Member display names
    // are provider generated and are never used for identity.
    const display = groupBackup["display-name"];
    if (
      typeof display === "string" && display.includes("golden-") &&
      !display.endsWith(expectedSuffix)
    ) throw new Error("Volume group backup suffix changed");
  }
  const memberIds = exactIds(
    groupBackup["volume-backup-ids"],
    "Volume group backup member IDs",
  );
  if (memberIds.length !== 2 || new Set(memberIds).size !== 2) {
    throw new Error("Volume group backup must contain exactly two members");
  }
  const first = memberFor(snapshot, memberIds[0]);
  const second = memberFor(snapshot, memberIds[1]);
  if (!first || !second || first.kind === second.kind) {
    throw new Error(
      "Volume group backup members are not one boot and one root",
    );
  }
  const boot = first.kind === "boot" ? first.item : second.item;
  const root = first.kind === "root" ? first.item : second.item;
  validateMember(boot, "boot", policy.source);
  validateMember(root, "root", policy.source);
  for (const member of [boot, root]) {
    if (member["volume-group-backup-id"] !== groupBackupId) {
      throw new Error("Volume group member is not bound to this group backup");
    }
    const memberAt = parseUtc(member["time-created"], "Member time-created");
    if (memberAt + 1000 < captureAt) {
      throw new Error("Volume group member predates its group capture");
    }
  }
  return {
    kind: "oci-volume-group",
    volumeGroupId: policy.volumeGroupId,
    volumeGroupBackupId: groupBackupId,
    captureTimeUtc: new Date(captureAt).toISOString(),
    bootBackupId: String(boot.id),
    rootBackupId: String(root.id),
    consistency: "crash-consistent",
  };
}

/** Validate an accepted pair against current inventory. Grouped pairs are
 * validated by actual group membership; names are never used for members. */
export function validateBackupPairForPolicy(
  snapshot: BackupSnapshot,
  pair: BackupPair,
  source: BackupSource,
  policy?: BackupPolicy,
): void {
  const boot = memberFor(snapshot, pair.bootId);
  const root = memberFor(snapshot, pair.rootId);
  if (!boot || !root || boot.kind !== "boot" || root.kind !== "root") {
    throw new Error("A required backup pair member is missing or mis-typed");
  }
  validateMember(boot.item, "boot", source);
  validateMember(root.item, "root", source);
  if (pair.volumeGroupBackupId !== undefined) {
    if (!policy) throw new Error("Grouped pair lacks its policy binding");
    const identity = captureIdentityFromSnapshot(
      policy,
      snapshot,
      pair.volumeGroupBackupId,
      pair.suffix,
    );
    if (
      identity.bootBackupId !== pair.bootId ||
      identity.rootBackupId !== pair.rootId
    ) throw new Error("Grouped pair member IDs do not match its group capture");
  }
}

function replacement(journal: BackupJournal): BackupPair {
  if (!journal.bootId || !journal.rootId || !journal.volumeGroupBackupId) {
    throw new Error("Online replacement capture is incomplete");
  }
  if (
    journal.bootId === journal.previousPair.bootId ||
    journal.rootId === journal.previousPair.rootId ||
    journal.bootId === journal.rootId
  ) throw new Error("Replacement pair reuses a retained backup ID");
  return {
    suffix: journal.suffix,
    bootId: journal.bootId,
    rootId: journal.rootId,
    volumeGroupBackupId: journal.volumeGroupBackupId,
  };
}

function continuity(value: SourceContinuityEvidence): void {
  if (
    !validId(value.bootId) || !value.serviceInvocations ||
    typeof value.serviceInvocations !== "object" ||
    Object.keys(value.serviceInvocations).length === 0
  ) throw new Error("Source continuity observation is incomplete");
  for (const id of Object.values(value.serviceInvocations)) {
    if (!validId(id)) throw new Error("Source service invocation is malformed");
  }
  parseUtc(value.observedAtUtc, "Source continuity observation time");
}

function sameContinuity(
  before: SourceContinuityEvidence,
  after: SourceContinuityEvidence,
): boolean {
  if (before.bootId !== after.bootId) return false;
  const a = before.serviceInvocations;
  const b = after.serviceInvocations;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length &&
    keys.every((key) => a[key] === b[key]);
}

function sourceProof(
  current: BackupSnapshot,
  policy: BackupPolicy,
  retiring = false,
): void {
  if (
    !equalSource(current.source, policy.source) ||
    !current.sourceAttachmentsProved ||
    !current.writersAbsent ||
    !current.sourceVolumeGroupProved ||
    !current.groupAccountingProved ||
    !current.freeEligibilityProved
  ) throw new Error("Source, group, eligibility or writer preflight failed");
  if (!retiring) {
    validateBackupPairForPolicy(
      current,
      policy.acceptedPair,
      policy.source,
      policy,
    );
  }
}

function ceiling(policy: BackupPolicy, snapshot: BackupSnapshot): number {
  return Math.min(snapshot.freeBackupLimit, policy.allowFifthSlot ? 5 : 4);
}

function candidateGroupIds(
  snapshot: BackupSnapshot,
  suffix: string,
): JsonRecord[] {
  const expected = `arch-online-golden-${suffix}`;
  return (snapshot.volumeGroupBackups ?? []).filter((item) =>
    item["display-name"] === expected
  );
}

/** Reconcile a group create intent. Empty or incomplete inventory never
 * authorizes another provider create: callers must diagnose the ambiguous
 * result and resume only after the exact ID is known. */
export function reconcileBackupGroupCreation(
  policy: BackupPolicy,
  journal: BackupJournal,
  snapshot: BackupSnapshot,
): string | undefined {
  const id = journal.volumeGroupBackupId;
  const intent = journal.volumeGroupBackupIntent === true;
  const candidates = candidateGroupIds(snapshot, journal.suffix);
  if (candidates.length > 1) {
    throw new Error("Duplicate group backup names require reconciliation");
  }
  if (id) {
    const exact = (snapshot.volumeGroupBackups ?? []).filter((item) =>
      item.id === id
    );
    if (exact.length !== 1) {
      throw new Error("Ambiguous group backup creation; do not retry creation");
    }
    return id;
  }
  if (intent) {
    if (candidates.length !== 1) {
      throw new Error("Ambiguous group backup creation; do not retry creation");
    }
    return stringField(candidates[0], "id");
  }
  if (candidates.length === 1) return stringField(candidates[0], "id");
  // Prove the selected group binding before permitting the first create.
  if (!snapshot.sourceVolumeGroupProved || !policy.volumeGroupId) {
    throw new Error("Source volume group is not proved");
  }
  return undefined;
}

export async function runBackupCycle(
  policy: BackupPolicy,
  journal: BackupJournal,
  ops: BackupOperations,
  control: BackupRunControl = {},
): Promise<void> {
  validateStandingApproval(policy, ops.now());
  if (journal.mode !== "online") {
    throw new Error("Legacy outage journal cannot run on the online path");
  }
  if (
    ![
      "planned",
      "backing-up",
      "pair-available",
      "source-accepted",
      "retiring",
      "complete",
      "failed",
    ].includes(journal.phase)
  ) throw new Error("Backup journal has an unknown online phase");
  if (
    !equalSource(journal.source, policy.source) ||
    !equalPair(journal.previousPair, policy.acceptedPair) ||
    !SUFFIX_PATTERN.test(journal.suffix) ||
    journal.suffix === journal.previousPair.suffix
  ) throw new Error("Backup journal belongs to another source or rotation");
  if (journal.phase === "failed") {
    throw new Error("Failed online cycle requires operator reconciliation");
  }
  const save = async (phase: BackupPhase = journal.phase) => {
    journal.phase = phase;
    journal.updatedAtUtc = ops.now().toISOString();
    await ops.save(structuredClone(journal));
  };
  const snapshot = async (retiring = false) => {
    const current = await ops.snapshot();
    sourceProof(current, policy, retiring);
    return current;
  };
  // A failed read-only recheck must not rewrite an accepted cycle.
  if (journal.phase === "complete") {
    const current = await snapshot(true);
    validateBackupPairForPolicy(
      current,
      replacement(journal),
      policy.source,
      policy,
    );
    return;
  }

  try {
    if (journal.phase === "planned") {
      const current = await snapshot();
      const limit = ceiling(policy, current);
      // A group creates exactly two member backup objects. Group-wrapper
      // accounting is separately proved by the primary before live approval.
      if (
        current.instanceState !== "RUNNING" ||
        !Number.isInteger(current.freeBackupLimit) ||
        current.allBackupCount + 2 > limit
      ) {
        throw new Error(
          "Source is not running or two backup slots are unavailable",
        );
      }
      await control.beforeCapture?.();
      const before = await ops.observeSource();
      continuity(before);
      journal.sourceContinuityBeforeCapture = structuredClone(before);
      await save("backing-up");
    }

    if (journal.phase === "backing-up") {
      const before = journal.sourceContinuityBeforeCapture ??
        await ops.observeSource();
      continuity(before);
      const current = await snapshot();
      if (current.instanceState !== "RUNNING") {
        throw new Error("Source must remain RUNNING for an online capture");
      }
      let groupBackupId = reconcileBackupGroupCreation(
        policy,
        journal,
        current,
      );
      if (!groupBackupId) {
        const limit = ceiling(policy, current);
        if (current.allBackupCount + 2 > limit) {
          throw new Error("Backup allowance changed before group creation");
        }
        await control.beforeCapture?.();
        // This save is the durable create intent and completes before OCI sees
        // the request. The returned ID is saved by the next save before wait.
        journal.volumeGroupBackupIntent = true;
        await save();
        groupBackupId = await ops.createBackupGroup(journal.suffix);
        if (!validId(groupBackupId)) {
          throw new Error("OCI returned no group backup ID");
        }
        journal.volumeGroupBackupId = groupBackupId;
        await save();
      } else if (journal.volumeGroupBackupId !== groupBackupId) {
        journal.volumeGroupBackupIntent = true;
        journal.volumeGroupBackupId = groupBackupId;
        await save();
      }
      await ops.waitBackupGroup(groupBackupId);
      const available = await snapshot();
      const identity = captureIdentityFromSnapshot(
        policy,
        available,
        groupBackupId,
        journal.suffix,
      );
      const after = await ops.observeSource();
      continuity(after);
      if (!sameContinuity(before, after)) {
        throw new Error(
          "Source boot or service invocation changed during capture",
        );
      }
      journal.volumeGroupBackupId = groupBackupId;
      journal.captureIdentity = identity;
      journal.bootId = identity.bootBackupId;
      journal.rootId = identity.rootBackupId;
      journal.sourceContinuityAfterCapture = structuredClone(after);
      await save("pair-available");
    }

    if (journal.phase === "pair-available") {
      const pair = replacement(journal);
      const current = await snapshot();
      validateBackupPairForPolicy(current, pair, policy.source, policy);
      const after = journal.sourceContinuityAfterCapture;
      if (after) {
        const now = await ops.observeSource();
        continuity(now);
        if (!sameContinuity(after, now)) {
          throw new Error(
            "Source boot or service invocation changed after capture",
          );
        }
      }
      await ops.acceptSource();
      if (after) {
        const accepted = await ops.observeSource();
        continuity(accepted);
        if (!sameContinuity(after, accepted)) {
          throw new Error(
            "Source boot or service invocation changed during acceptance",
          );
        }
      }
      journal.sourceAcceptedAtUtc = ops.now().toISOString();
      await save("source-accepted");
    }

    if (journal.phase === "source-accepted") {
      if (policy.retainPreviousPair) {
        await save("complete");
        return;
      }
      await save("retiring");
    }

    if (journal.phase === "retiring") {
      if (policy.retainPreviousPair) {
        throw new Error("Retention policy prohibits deletion");
      }
      if (!journal.sourceAcceptedAtUtc) {
        throw new Error("Source acceptance is absent");
      }
      const current = await snapshot(true);
      const replacementPair = replacement(journal);
      validateBackupPairForPolicy(
        current,
        replacementPair,
        policy.source,
        policy,
      );
      if (current.instanceState !== "RUNNING") {
        throw new Error("Source is not running during retention");
      }
      if (journal.previousPair.volumeGroupBackupId) {
        await ops.deleteBackupGroup(journal.previousPair.volumeGroupBackupId, {
          bootId: journal.previousPair.bootId,
          rootId: journal.previousPair.rootId,
        });
      } else {
        for (const kind of ["boot", "root"] as const) {
          const beforeDelete = await snapshot(true);
          validateBackupPairForPolicy(
            beforeDelete,
            replacementPair,
            policy.source,
            policy,
          );
          await ops.deleteBackup(
            kind,
            kind === "boot"
              ? journal.previousPair.bootId
              : journal.previousPair.rootId,
          );
        }
      }
      const remaining = await snapshot(true);
      validateBackupPairForPolicy(
        remaining,
        replacementPair,
        policy.source,
        policy,
      );
      for (
        const id of [journal.previousPair.bootId, journal.previousPair.rootId]
      ) {
        if (memberFor(remaining, id)) {
          throw new Error("Previous backup member remains after retention");
        }
      }
      if (
        journal.previousPair.volumeGroupBackupId &&
        (remaining.volumeGroupBackups ?? []).some((item) =>
          item.id === journal.previousPair.volumeGroupBackupId
        )
      ) throw new Error("Previous group backup remains after retention");
      await save("complete");
    }
  } catch (error) {
    journal.failure = error instanceof Error ? error.message : String(error);
    try {
      await save("failed");
    } catch (writeError) {
      throw new AggregateError(
        [error, writeError],
        "Online backup failed and its journal could not be persisted",
      );
    }
    // There is intentionally no source-recovery call here. The online path
    // never stops the source, so an online failure leaves it running.
    throw error;
  }
}
