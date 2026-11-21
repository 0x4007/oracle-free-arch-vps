import type { CatalogEntry } from "./backblaze-file-backup.ts";
import { validateBackupRuntimeCatalogEntry } from "./backup-v2-runtime-contract.ts";
import {
  type BackupV2ListedVersion,
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  type BackupV2ProtectedReferences,
  type BackupV2ReachabilityReader,
  parseBackupV2ObjectName,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
} from "./backup-v2-contract.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_LIMITS,
  BACKUP_V2_WORKSPACE,
} from "./backup-v2-profile.ts";
import {
  type BackupV2RetentionInventoryReader,
  type BackupV2RetentionVersion,
  readBackupV2RetentionInventory,
  retentionInteger,
  retentionOrder,
  retentionOwnedName,
  retentionOwnedResticName,
  retentionSha256,
  retentionVersionOrder,
  sameRetentionEvidence,
} from "./backup-v2-retention-inventory.ts";

export interface BackupV2ProtectionReader extends BackupV2ReachabilityReader {
  roleReferences(
    role: BackupV2ManifestRef,
  ): Promise<readonly BackupV2ObjectRef[]>;
}
export interface BackupV2ProtectionDryRun {
  pruneEnabled: false;
  objects: BackupV2ObjectRef[];
  unresolvedNames: string[];
}
/** Protection only; legacy/Oracle/unrelated Restic stay with their readers. */
export async function collectBackupV2ProtectedReferences(
  value: BackupV2ProtectedReferences,
  reader: BackupV2ProtectionReader,
  receipts: readonly BackupV2ManifestRef[],
): Promise<BackupV2ProtectionDryRun> {
  assertBackupV2Budget(
    "pruneCandidates",
    value.acceptedRoots.length + value.sealedRoleManifests.length +
      value.activeObjects.length + value.unresolvedPuts.length +
      receipts.length,
  );
  const objects = new Map<string, BackupV2ObjectRef>(),
    unresolved = new Set<string>();
  let bytes = 0;
  const add = (input: BackupV2ObjectRef) => {
    const ref = validateBackupV2ObjectRef(input), old = objects.get(ref.fileId);
    if (old && JSON.stringify(old) !== JSON.stringify(ref)) {
      throw new Error("Protected object identity conflicts");
    }
    if (!old) {
      assertBackupV2Budget(
        "pruneCandidates",
        objects.size + unresolved.size + 1,
      );
      bytes += new TextEncoder().encode(JSON.stringify(ref)).length;
      if (bytes > BACKUP_V2_WORKSPACE.retention) {
        throw new Error("Protection workspace exceeded");
      }
      objects.set(ref.fileId, ref);
    }
  };
  for (const input of value.acceptedRoots) {
    const root = validateBackupV2ManifestRef(input);
    if (parseBackupV2ObjectName(root.object.fileName).kind !== "manifest") {
      throw new Error("Protected root kind invalid");
    }
    add(root.object);
    for (const ref of await reader.references(root)) add(ref);
  }
  for (const input of value.sealedRoleManifests) {
    const role = validateBackupV2ManifestRef(input);
    if (parseBackupV2ObjectName(role.object.fileName).kind !== "manifest") {
      throw new Error("Protected role kind invalid");
    }
    add(role.object);
    for (const ref of await reader.roleReferences(role)) add(ref);
  }
  for (const input of receipts) {
    const receipt = validateBackupV2ManifestRef(input);
    if (parseBackupV2ObjectName(receipt.object.fileName).kind !== "receipt") {
      throw new Error("Protected receipt kind invalid");
    }
    add(receipt.object);
  }
  for (const ref of value.activeObjects) add(ref);
  for (const input of value.unresolvedPuts) {
    const intent = validateBackupV2PutIntent(input);
    if (!unresolved.has(intent.name)) {
      assertBackupV2Budget(
        "pruneCandidates",
        objects.size + unresolved.size + 1,
      );
      bytes += new TextEncoder().encode(intent.name).length;
      if (bytes > BACKUP_V2_WORKSPACE.retention) {
        throw new Error("Protection workspace exceeded");
      }
      unresolved.add(intent.name);
    }
  }
  return {
    pruneEnabled: false,
    objects: [...objects.values()],
    unresolvedNames: [...unresolved].sort(),
  };
}

export interface BackupV2RetentionPolicy {
  keepAccepted: number;
  orphanGraceHours: number;
  cleanLegacyOrphans: boolean;
  execute: boolean;
}

export const DEFAULT_BACKUP_V2_RETENTION_POLICY: Readonly<
  BackupV2RetentionPolicy
> = Object.freeze({
  keepAccepted: 2,
  orphanGraceHours: 72,
  cleanLegacyOrphans: false,
  execute: false,
});

export interface BackupV2RetiredRestic {
  prefix: string;
  retiredAtUtc: string;
  evidenceSha256: string;
}
export interface BackupV2RetentionJob {
  captureId: string;
  custody: "SETTLED_UNACCEPTED" | "PROTECTED";
  format?: "backup-v1" | "backup-v2";
  evidenceSha256?: string;
}

export interface BackupV2RetentionSnapshot {
  /** Caller holds this exact exclusive controller/source-settlement custody. */
  custody: { lockId: string; sourceBootId: string; sourceSettled: true };
  catalog: readonly unknown[];
  protection: BackupV2ProtectedReferences;
  receipts: readonly BackupV2ManifestRef[];
  policy: BackupV2RetentionPolicy;
  plannedAtUtc: string;
  jobs: readonly BackupV2RetentionJob[];
  retiredRestic?: BackupV2RetiredRestic;
  verifyCatalogOnly?: true;
}

export interface BackupV2RetentionReader
  extends BackupV2ProtectionReader, BackupV2RetentionInventoryReader {
  validateLegacy(value: unknown): CatalogEntry;
}

export const BACKUP_V2_RETENTION_EVIDENCE = {
  RETAINED_ACCEPTED: "Exact version in a retained verified catalog graph.",
  OBSOLETE_ACCEPTED:
    "Exact version exclusive to a graph selected for catalog retirement. No retained or unsettled reference.",
  UNFINISHED_LARGE_FILE:
    "Owned name, settled custody, no protected reference, complete aged part census.",
  UNACCEPTED_V2:
    "Owned v2 name, durable settled unaccepted job proof, absent from every accepted graph.",
  NONCURRENT_VERSION:
    "Owned non-current file version absent from every accepted graph or unsettled reference.",
  HIDE_MARKER:
    "Owned unpinned marker whose deletion cannot make an older upload visible.",
  LEGACY_ORPHAN:
    "Exact legacy name, no accepted graph reference, and settled unaccepted job or reviewed Restic retirement proof.",
  LEGACY_UNATTRIBUTED:
    "Restic-layout object without a matching reviewed repository retirement declaration.",
  PROTECTED:
    "Live, unsettled, unresolved or unproved custody. Object preserved.",
  UNCLASSIFIED: "Name or ownership unrecognized. Object preserved.",
} as const;

export type BackupV2RetentionCategory =
  keyof typeof BACKUP_V2_RETENTION_EVIDENCE;
export type BackupV2RetentionBlockReason =
  | "NO_ACCEPTED_GENERATION"
  | "DAMAGED_ACCEPTED_GENERATION"
  | "PLAN_CHANGED"
  | "IDENTITY_CHANGED"
  | "TRANSPORT_UNCERTAIN";

export interface BackupV2RetentionSummary {
  keptGenerations: number;
  damagedCaptureIds: string[];
  bucketBytes: number;
  categories: Record<BackupV2RetentionCategory, {
    objects: number;
    bytes: number;
    plannedObjects: number;
    plannedBytes: number;
  }>;
  blockReason: BackupV2RetentionBlockReason | null;
  deletedObjects: number;
  deletedBytes: number;
  reconciledAbsentObjects: number;
  reconciledAbsentBytes: number;
}

interface RetentionCandidate {
  object: BackupV2RetentionVersion;
  retiringCaptureIds?: string[];
  reason:
    | "OBSOLETE_ACCEPTED"
    | "UNFINISHED_LARGE_FILE"
    | "UNACCEPTED_V2"
    | "NONCURRENT_VERSION"
    | "HIDE_MARKER"
    | "LEGACY_ORPHAN";
}

export interface BackupV2RetentionPlan {
  schemaVersion: 2;
  format: "backup-v2-retention";
  dryRun: true;
  preconditionSha256: string;
  inventorySha256: string;
  policy: BackupV2RetentionPolicy;
  plannedAtUtc: string;
  cutoffUtc: string;
  verifyCatalogOnly?: true;
  retiredRestic?: BackupV2RetiredRestic;
  retainedCaptureIds: string[];
  retiredCaptureIds: string[];
  obsoleteLegacyCaptureIds: string[];
  evidence: typeof BACKUP_V2_RETENTION_EVIDENCE;
  candidates: RetentionCandidate[];
  summary: BackupV2RetentionSummary;
  digest: string;
}

export interface BackupV2RetentionJournalEntry {
  planSha256: string;
  ordinal: number;
  fileId: string;
  fileName: string;
  attempt: number;
  state: "INTENT" | "DELETED" | "ABSENT" | "PRESENT" | "AMBIGUOUS";
}

export interface BackupV2RetentionExecution {
  observeFresh(): Promise<BackupV2RetentionSnapshot>;
  reader: BackupV2RetentionReader;
  loadJournal(): Promise<readonly BackupV2RetentionJournalEntry[]>;
  /** Resolves after the complete record is persisted and fsynced. */
  appendDurable(entry: BackupV2RetentionJournalEntry): Promise<void>;
  removeExact(
    object: BackupV2RetentionVersion,
    signal?: AbortSignal,
  ): Promise<void>;
  now(): Date;
  signal?: AbortSignal;
}

const encoder = new TextEncoder();
const hourMs = 3_600_000;
const capturePattern =
  /^generation-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const shaPattern = /^[a-f0-9]{64}$/;
const reasons = Object.keys(
  BACKUP_V2_RETENTION_EVIDENCE,
) as BackupV2RetentionCategory[];

function invalid(): never {
  throw new Error("Retention identity, protection or precondition invalid");
}
function bounded(value: unknown, maximum = BACKUP_V2_WORKSPACE.retention) {
  if (encoder.encode(JSON.stringify(value)).length > maximum) invalid();
}
function canonicalUtc(value: unknown): string {
  if (
    typeof value !== "string" || !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) invalid();
  return value;
}
export function validateBackupV2RetentionPolicy(
  value: unknown,
): BackupV2RetentionPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const { maxDeleteFraction: _legacy, ...p } = value as
    & BackupV2RetentionPolicy
    & { maxDeleteFraction?: unknown };
  if (
    Object.keys(p).sort().join(",") !==
      "cleanLegacyOrphans,execute,keepAccepted,orphanGraceHours" ||
    !Number.isSafeInteger(p.keepAccepted) || p.keepAccepted < 1 ||
    p.keepAccepted > BACKUP_V2_LIMITS.pruneCandidates ||
    !Number.isSafeInteger(p.orphanGraceHours) || p.orphanGraceHours < 1 ||
    p.orphanGraceHours > 24 * 365 ||
    typeof p.cleanLegacyOrphans !== "boolean" || typeof p.execute !== "boolean"
  ) invalid();
  return p;
}
export function validateBackupV2RetiredRestic(
  value: unknown,
): BackupV2RetiredRestic {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const r = value as BackupV2RetiredRestic;
  if (
    Object.keys(r).sort().join(",") !== "evidenceSha256,prefix,retiredAtUtc" ||
    typeof r.prefix !== "string" ||
    !/^restic\/(?:[A-Za-z0-9_-]{1,128}\/)?$/.test(r.prefix) ||
    ["restic/backup-v2/", "restic/direct-v1/"].includes(r.prefix) ||
    typeof r.evidenceSha256 !== "string" || !shaPattern.test(r.evidenceSha256)
  ) invalid();
  canonicalUtc(r.retiredAtUtc);
  return structuredClone(r);
}
export function validateBackupV2RetentionJob(
  value: unknown,
): BackupV2RetentionJob {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const job = value as BackupV2RetentionJob;
  if (
    Object.keys(job).some((key) =>
      !["captureId", "custody", "format", "evidenceSha256"].includes(key)
    ) || typeof job.captureId !== "string" ||
    !capturePattern.test(job.captureId) ||
    (job.custody !== "PROTECTED" && job.custody !== "SETTLED_UNACCEPTED") ||
    (job.format !== undefined && job.format !== "backup-v1" &&
      job.format !== "backup-v2") ||
    (job.evidenceSha256 !== undefined &&
      (typeof job.evidenceSha256 !== "string" ||
        !shaPattern.test(job.evidenceSha256))) ||
    job.custody === "SETTLED_UNACCEPTED" && job.format === "backup-v1" &&
      !job.evidenceSha256
  ) invalid();
  return structuredClone(job);
}

function versionIdentity(value: BackupV2ObjectRef): BackupV2ListedVersion {
  const { sha256: _sha256, ...identity } = validateBackupV2ObjectRef(value);
  return identity;
}
function addReference(
  map: Map<string, BackupV2ListedVersion>,
  value: BackupV2ListedVersion,
) {
  const old = map.get(value.fileId);
  if (old && !sameRetentionEvidence(old, value)) invalid();
  map.set(value.fileId, value);
  assertBackupV2Budget("pruneCandidates", map.size);
}
function legacyReferences(value: CatalogEntry): BackupV2ListedVersion[] {
  return [
    { ...value.publishedIndex.object, action: "upload" },
    ...value.index.archives.flatMap((archive) =>
      archive.chunks.map((chunk) => ({
        fileId: chunk.fileId,
        fileName: chunk.name,
        contentLength: chunk.size,
        contentSha1: chunk.sha1,
        uploadTimestamp: chunk.uploadTimestamp,
        action: "upload" as const,
      }))
    ),
  ];
}

async function protectionState(
  input: BackupV2RetentionSnapshot,
  reader: BackupV2RetentionReader,
) {
  const snapshot = structuredClone(input), { custody } = snapshot;
  if (
    !custody || custody.sourceSettled !== true ||
    typeof custody.lockId !== "string" ||
    !/^[\x21-\x7e]{1,256}$/.test(custody.lockId) ||
    !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(
      custody.sourceBootId,
    ) || !Array.isArray(snapshot.catalog) || !Array.isArray(snapshot.jobs)
  ) invalid();
  bounded(snapshot);
  assertBackupV2Budget(
    "pruneCandidates",
    snapshot.catalog.length + snapshot.jobs.length,
  );
  const policy = validateBackupV2RetentionPolicy(snapshot.policy);
  const plannedAtUtc = canonicalUtc(snapshot.plannedAtUtc);
  if (
    snapshot.verifyCatalogOnly !== undefined &&
    (snapshot.verifyCatalogOnly !== true || policy.execute)
  ) invalid();
  const retiredRestic = snapshot.retiredRestic === undefined
    ? undefined
    : validateBackupV2RetiredRestic(snapshot.retiredRestic);
  const jobs = new Map<string, BackupV2RetentionJob>();
  for (const input of snapshot.jobs) {
    const job = validateBackupV2RetentionJob(input);
    if (jobs.has(job.captureId)) invalid();
    jobs.set(job.captureId, job);
  }
  const catalog = snapshot.catalog.map((entry) =>
    validateBackupRuntimeCatalogEntry(entry, reader.validateLegacy)
  );
  const captures = new Map<string, {
    captureId: string;
    acceptedAtUtc: string;
    format: "backup-v1" | "backup-v2";
    refs: BackupV2ListedVersion[];
  }>();
  const allRefs = new Map<string, BackupV2ListedVersion>();
  const v2Refs = new Map<string, BackupV2ObjectRef>();
  const v2Identity = (input: BackupV2ObjectRef) => {
    const ref = validateBackupV2ObjectRef(input);
    const prior = v2Refs.get(ref.fileId);
    if (prior && !sameRetentionEvidence(prior, ref)) invalid();
    v2Refs.set(ref.fileId, ref);
    return versionIdentity(ref);
  };
  for (const entry of catalog) {
    const captureId = entry.format === "backup-v1"
      ? entry.entry.index.generation
      : entry.envelope.request.captureId;
    if (
      captures.has(captureId) ||
      jobs.get(captureId)?.custody === "SETTLED_UNACCEPTED"
    ) {
      invalid();
    }
    const refs = entry.format === "backup-v1"
      ? legacyReferences(entry.entry)
      : [
        entry.selectedRoot.reference.object,
        entry.receiptReference.object,
        ...await reader.references(entry.selectedRoot.reference),
      ].map(v2Identity);
    for (const ref of refs) addReference(allRefs, ref);
    captures.set(captureId, {
      captureId,
      acceptedAtUtc: canonicalUtc(
        entry.format === "backup-v1"
          ? entry.entry.acceptedAtUtc
          : entry.acceptedAtUtc,
      ),
      format: entry.format,
      refs,
    });
  }
  const protectedSet = await collectBackupV2ProtectedReferences(
    snapshot.protection,
    reader,
    snapshot.receipts,
  );
  const protectedIds = new Set<string>();
  for (const value of protectedSet.objects) {
    addReference(allRefs, v2Identity(value));
    protectedIds.add(value.fileId);
  }
  return {
    policy,
    plannedAtUtc,
    verifyCatalogOnly: snapshot.verifyCatalogOnly,
    retiredRestic,
    captures,
    jobs,
    allRefs,
    protectedIds,
    unresolved: new Set(protectedSet.unresolvedNames),
    snapshotSha256: retentionSha256(snapshot),
  };
}

function age(version: BackupV2RetentionVersion) {
  return version.action === "start"
    ? version.lastPartUploadedAt
    : version.uploadTimestamp;
}

type ProtectionState = Awaited<ReturnType<typeof protectionState>>;
function catalogAvailability(
  state: ProtectionState,
  versions: Map<string, BackupV2RetentionVersion>,
  expected?: readonly string[],
) {
  const intact = [], damaged = [];
  for (const entry of state.captures.values()) {
    if (
      entry.refs.every((ref) =>
        sameRetentionEvidence(versions.get(ref.fileId) ?? null, ref)
      )
    ) intact.push(entry);
    else if (!expected || expected.includes(entry.captureId)) {
      damaged.push(entry.captureId);
    }
  }
  intact.sort((left, right) =>
    retentionOrder(right.acceptedAtUtc, left.acceptedAtUtc) ||
    retentionOrder(left.captureId, right.captureId)
  );
  return { intact, damaged: damaged.sort(retentionOrder) };
}

function planFromInventory(
  state: ProtectionState,
  inventory: BackupV2RetentionVersion[],
): BackupV2RetentionPlan {
  const versions = new Map(inventory.map((value) => [value.fileId, value]));
  const { intact, damaged } = catalogAvailability(state, versions);
  const protectedMissing = [...state.protectedIds].some((id) =>
    !sameRetentionEvidence(versions.get(id) ?? null, state.allRefs.get(id))
  );
  const cutoff = Date.parse(state.plannedAtUtc) -
    state.policy.orphanGraceHours * hourMs;
  const preserve = damaged.length > 0 || protectedMissing ||
    state.verifyCatalogOnly;
  const retained = preserve
    ? intact
    : intact.slice(0, state.policy.keepAccepted);
  let retired = preserve ? [] : intact.slice(state.policy.keepAccepted);
  const damagedRefs = new Set(
    damaged.flatMap((id) =>
      state.captures.get(id)!.refs.map((ref) => ref.fileId)
    ),
  );
  const pinned = (version: BackupV2RetentionVersion) =>
    damagedRefs.has(version.fileId) || state.protectedIds.has(version.fileId) ||
    state.unresolved.has(version.fileName) ||
    state.jobs.get(retentionOwnedName(version.fileName)?.captureId ?? "")
        ?.custody === "PROTECTED";
  const retainedRefs = new Set<string>();
  for (const entry of retained) {
    for (const ref of entry.refs) retainedRefs.add(ref.fileId);
  }
  // Retire an accepted graph only as a recovery unit. An unsettled or young
  // exclusive member preserves every proposed obsolete graph for this pass.
  if (
    retired.some((entry) =>
      state.jobs.get(entry.captureId)?.custody === "PROTECTED" ||
      entry.refs.some((ref) =>
        !retainedRefs.has(ref.fileId) && (
          pinned(versions.get(ref.fileId)!) ||
          age(versions.get(ref.fileId)!) > cutoff
        )
      )
    )
  ) {
    retained.push(...retired);
    retired = [];
    for (const entry of retained) {
      for (const ref of entry.refs) retainedRefs.add(ref.fileId);
    }
  }
  const obsolete = new Map<string, string[]>();
  for (const entry of retired) {
    for (const fileId of new Set(entry.refs.map((ref) => ref.fileId))) {
      const owners = obsolete.get(fileId) ?? [];
      owners.push(entry.captureId);
      obsolete.set(fileId, owners);
    }
  }
  const newest = new Map<string, number>();
  for (const ref of inventory) {
    if (ref.action === "start") continue;
    newest.set(
      ref.fileName,
      Math.max(newest.get(ref.fileName) ?? 0, ref.uploadTimestamp),
    );
  }
  const declared = (name: string) =>
    state.retiredRestic !== undefined &&
    retentionOwnedResticName(name, state.retiredRestic.prefix);
  const resticSettled = state.retiredRestic !== undefined &&
    Date.parse(state.retiredRestic.retiredAtUtc) <= cutoff &&
    !inventory.some((ref) => declared(ref.fileName) && age(ref) > cutoff);
  const categories = Object.fromEntries(reasons.map((reason) => [
    reason,
    { objects: 0, bytes: 0, plannedObjects: 0, plannedBytes: 0 },
  ])) as BackupV2RetentionSummary["categories"];
  const candidates: RetentionCandidate[] = [];
  const hides: BackupV2RetentionVersion[] = [];
  const remainingUploads = new Map<string, number>();
  let bucketBytes = 0;
  function stage(
    object: BackupV2RetentionVersion,
    reason: BackupV2RetentionCategory,
    candidate?: RetentionCandidate["reason"],
  ) {
    const tally = categories[reason];
    tally.objects++;
    tally.bytes += object.contentLength;
    if (candidate && !state.verifyCatalogOnly && age(object) <= cutoff) {
      tally.plannedObjects++;
      tally.plannedBytes += object.contentLength;
      candidates.push({
        object,
        reason: candidate,
        ...(candidate === "OBSOLETE_ACCEPTED"
          ? { retiringCaptureIds: obsolete.get(object.fileId)! }
          : {}),
      });
    } else if (object.action === "upload") {
      remainingUploads.set(
        object.fileName,
        Math.max(
          remainingUploads.get(object.fileName) ?? 0,
          object.uploadTimestamp,
        ),
      );
    }
  }
  for (const object of inventory) {
    bucketBytes = retentionInteger(bucketBytes + object.contentLength);
    const owner = retentionOwnedName(object.fileName);
    const jobRecord = owner && state.jobs.get(owner.captureId);
    const job = jobRecord && (jobRecord.format ?? "backup-v2") === owner?.format
      ? jobRecord.custody
      : undefined;
    const capture = owner && state.captures.get(owner.captureId);
    const accepted = capture?.format === owner?.format ? capture : undefined;
    const legacy = owner?.format === "backup-v1" || declared(object.fileName);
    if (retainedRefs.has(object.fileId)) {
      stage(object, "RETAINED_ACCEPTED");
    } else if (pinned(object)) {
      stage(object, "PROTECTED");
    } else if (obsolete.has(object.fileId)) {
      stage(object, "OBSOLETE_ACCEPTED", "OBSOLETE_ACCEPTED");
    } else if (
      !accepted && job !== "SETTLED_UNACCEPTED" && !declared(object.fileName)
    ) {
      stage(
        object,
        owner
          ? "PROTECTED"
          : object.fileName.startsWith("restic/")
          ? "LEGACY_UNATTRIBUTED"
          : "UNCLASSIFIED",
      );
    } else if (object.action === "start") {
      const settled = job === "SETTLED_UNACCEPTED" || accepted || resticSettled;
      stage(
        object,
        "UNFINISHED_LARGE_FILE",
        settled && (!legacy || state.policy.cleanLegacyOrphans)
          ? "UNFINISHED_LARGE_FILE"
          : undefined,
      );
    } else if (object.action === "hide") {
      hides.push(object);
    } else if (object.uploadTimestamp < newest.get(object.fileName)!) {
      stage(
        object,
        "NONCURRENT_VERSION",
        !legacy || (accepted || (state.policy.cleanLegacyOrphans &&
            (!declared(object.fileName) || resticSettled)))
          ? "NONCURRENT_VERSION"
          : undefined,
      );
    } else if (owner?.format === "backup-v2" && job === "SETTLED_UNACCEPTED") {
      stage(object, "UNACCEPTED_V2", "UNACCEPTED_V2");
    } else if (
      legacy && (job === "SETTLED_UNACCEPTED" || declared(object.fileName))
    ) {
      stage(
        object,
        "LEGACY_ORPHAN",
        state.policy.cleanLegacyOrphans &&
          (!declared(object.fileName) || resticSettled)
          ? "LEGACY_ORPHAN"
          : undefined,
      );
    } else {
      stage(object, "PROTECTED");
    }
  }
  for (const object of hides) {
    const owner = retentionOwnedName(object.fileName);
    const legacy = owner?.format === "backup-v1" || declared(object.fileName);
    const accepted = owner !== null &&
      state.captures.get(owner.captureId)?.format === owner.format;
    // Remove hidden data first. A current marker is safe only once every
    // upload at that name is gone. Tied timestamps do not prove ordering.
    const remaining = remainingUploads.get(object.fileName);
    const safe = remaining === undefined || remaining > object.uploadTimestamp;
    stage(
      object,
      "HIDE_MARKER",
      safe && (!legacy || accepted || (state.policy.cleanLegacyOrphans &&
          (!declared(object.fileName) || resticSettled)))
        ? "HIDE_MARKER"
        : undefined,
    );
  }
  candidates.sort((left, right) =>
    Number(left.object.action === "hide") -
      Number(right.object.action === "hide") ||
    retentionVersionOrder(left.object, right.object)
  );
  let blockReason: BackupV2RetentionBlockReason | null = null;
  if (damaged.length) blockReason = "DAMAGED_ACCEPTED_GENERATION";
  else if (protectedMissing) blockReason = "IDENTITY_CHANGED";
  else if (!retained.length) blockReason = "NO_ACCEPTED_GENERATION";
  const body: Omit<BackupV2RetentionPlan, "digest"> = {
    schemaVersion: 2,
    format: "backup-v2-retention",
    dryRun: true,
    preconditionSha256: state.snapshotSha256,
    inventorySha256: retentionSha256(inventory),
    policy: state.policy,
    plannedAtUtc: state.plannedAtUtc,
    cutoffUtc: new Date(cutoff).toISOString(),
    ...(state.verifyCatalogOnly ? { verifyCatalogOnly: true } : {}),
    ...(state.retiredRestic ? { retiredRestic: state.retiredRestic } : {}),
    retainedCaptureIds: retained.map((entry) => entry.captureId),
    retiredCaptureIds: retired.map((entry) => entry.captureId),
    obsoleteLegacyCaptureIds: retired.filter((entry) =>
      entry.format === "backup-v1"
    )
      .map((entry) => entry.captureId),
    evidence: BACKUP_V2_RETENTION_EVIDENCE,
    candidates,
    summary: {
      keptGenerations: retained.length,
      damagedCaptureIds: damaged,
      bucketBytes: state.verifyCatalogOnly ? 0 : bucketBytes,
      categories,
      blockReason,
      deletedObjects: 0,
      deletedBytes: 0,
      reconciledAbsentObjects: 0,
      reconciledAbsentBytes: 0,
    },
  };
  bounded(body, BACKUP_V2_LIMITS.journalBytes - 128);
  return { ...body, digest: retentionSha256(body) };
}

/** Captures a complete metadata census and derives all candidate identities
 * from the same snapshot. A blocked plan remains reviewable. */
export async function planBackupV2Retention(
  snapshot: BackupV2RetentionSnapshot,
  reader: BackupV2RetentionReader,
): Promise<BackupV2RetentionPlan> {
  const state = await protectionState(snapshot, reader);
  if (!state.verifyCatalogOnly) {
    return planFromInventory(
      state,
      await readBackupV2RetentionInventory(reader),
    );
  }
  const names = new Set([...state.allRefs.values()].map((ref) => ref.fileName));
  const listed = [];
  for (const name of names) {
    listed.push(...await readBackupV2RetentionInventory(reader, name, false));
    assertBackupV2Budget("pruneCandidates", listed.length);
  }
  return planFromInventory(state, listed.sort(retentionVersionOrder));
}

export function validateBackupV2RetentionPlan(
  input: unknown,
  digest: string,
): BackupV2RetentionPlan {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid();
  const plan = structuredClone(input) as BackupV2RetentionPlan;
  bounded(plan, BACKUP_V2_LIMITS.journalBytes);
  const { digest: saved, ...body } = plan;
  if (
    plan.schemaVersion !== 2 || plan.format !== "backup-v2-retention" ||
    plan.dryRun !== true || !shaPattern.test(digest) || saved !== digest ||
    retentionSha256(body) !== digest ||
    !shaPattern.test(plan.preconditionSha256) ||
    !shaPattern.test(plan.inventorySha256) || !Array.isArray(plan.candidates) ||
    !Array.isArray(plan.retainedCaptureIds) ||
    !Array.isArray(plan.retiredCaptureIds) ||
    !Array.isArray(plan.obsoleteLegacyCaptureIds) || !plan.summary
  ) invalid();
  validateBackupV2RetentionPolicy(plan.policy);
  canonicalUtc(plan.plannedAtUtc);
  canonicalUtc(plan.cutoffUtc);
  assertBackupV2Budget("pruneCandidates", plan.candidates.length);
  return plan;
}

type RetentionExecutionOutcome = {
  status: "COMPLETE" | "PARTIAL";
  summary: BackupV2RetentionSummary;
  retainedCaptureIds: string[];
};
class RetentionPreconditionError extends Error {}

/** Repeat uses the original plan and catalog even after partial deletion.
 * Reconstruct its complete baseline using only missing members with durable
 * intent. A new object, changed part, or unrelated absence blocks execution. */
export async function executeBackupV2Retention(
  input: BackupV2RetentionPlan,
  digest: string,
  caps: BackupV2RetentionExecution,
): Promise<RetentionExecutionOutcome> {
  const plan = validateBackupV2RetentionPlan(input, digest);
  const summary = structuredClone(plan.summary);
  let retainedCaptureIds = [...plan.retainedCaptureIds];
  const partial = (
    reason: BackupV2RetentionBlockReason,
  ): RetentionExecutionOutcome => ({
    status: "PARTIAL",
    summary: { ...summary, blockReason: reason },
    retainedCaptureIds,
  });
  if (!plan.policy.execute) return partial("PLAN_CHANGED");
  if (summary.blockReason) return partial(summary.blockReason);
  const byOrdinal = new Map<number, BackupV2RetentionJournalEntry>();
  const orphanIds = new Set(
    plan.candidates.filter(({ reason }) => reason !== "OBSOLETE_ACCEPTED")
      .map(({ object }) => object.fileId),
  );
  let ordinalToProcess = 0, journalBytes = 0;
  const apply = (entry: BackupV2RetentionJournalEntry) => {
    const object = plan.candidates[entry.ordinal]?.object;
    const previous = byOrdinal.get(entry.ordinal);
    if (
      !object || entry.ordinal !== ordinalToProcess ||
      entry.planSha256 !== digest ||
      entry.fileId !== object.fileId || entry.fileName !== object.fileName ||
      !Number.isSafeInteger(entry.attempt) || entry.attempt < 1 ||
      entry.attempt > 16 ||
      !["INTENT", "DELETED", "ABSENT", "PRESENT", "AMBIGUOUS"].includes(
        entry.state,
      )
    ) invalid();
    if (entry.state === "INTENT") {
      if (
        previous
          ? previous.state !== "PRESENT" ||
            entry.attempt !== previous.attempt + 1
          : entry.attempt !== 1
      ) invalid();
    } else {
      const externallyAbsent = entry.state === "ABSENT" &&
        orphanIds.has(entry.fileId) &&
        entry.attempt === (previous?.attempt ?? 1) &&
        (!previous || previous.state === "PRESENT");
      if (
        !externallyAbsent &&
        (!previous ||
          (previous.state !== "INTENT" && previous.state !== "AMBIGUOUS") ||
          previous.attempt !== entry.attempt)
      ) invalid();
    }
    journalBytes += encoder.encode(JSON.stringify(entry)).length + 1;
    assertBackupV2Budget("journalBytes", journalBytes);
    byOrdinal.set(entry.ordinal, entry);
    if (entry.state === "DELETED") {
      summary.deletedObjects++;
      summary.deletedBytes += object.contentLength;
      ordinalToProcess++;
    }
    if (entry.state === "ABSENT") {
      summary.reconciledAbsentObjects++;
      summary.reconciledAbsentBytes += object.contentLength;
      ordinalToProcess++;
    }
  };
  const append = async (
    ordinal: number,
    attempt: number,
    state: BackupV2RetentionJournalEntry["state"],
  ) => {
    const { fileId, fileName } = plan.candidates[ordinal].object;
    const entry = {
      planSha256: digest,
      ordinal,
      fileId,
      fileName,
      attempt,
      state,
    };
    await caps.appendDurable(entry);
    apply(entry);
  };
  const clock = () => {
    const now = caps.now().getTime();
    if (!Number.isFinite(now) || now < Date.parse(plan.plannedAtUtc)) invalid();
    return now;
  };
  const fresh = async () => {
    caps.signal?.throwIfAborted();
    try {
      clock();
      const observed = await caps.observeFresh();
      if (retentionSha256(observed) !== plan.preconditionSha256) invalid();
      return observed;
    } catch (error) {
      throw new RetentionPreconditionError("Retention custody changed", {
        cause: error,
      });
    }
  };
  let authority: ProtectionState;
  try {
    authority = await protectionState(await fresh(), caps.reader);
    const entries = await caps.loadJournal();
    if (!Array.isArray(entries)) invalid();
    bounded(entries, BACKUP_V2_LIMITS.journalBytes);
    for (const entry of entries) apply(entry);
  } catch {
    return partial("PLAN_CHANGED");
  }
  const inventory = async (name?: string) => {
    try {
      return await readBackupV2RetentionInventory(caps.reader, name);
    } catch {
      // A concurrent manual removal can invalidate one continuation cursor
      // or end an unfinished upload midway through the part census.
      caps.signal?.throwIfAborted();
      return await readBackupV2RetentionInventory(caps.reader, name);
    }
  };
  let listed: BackupV2RetentionVersion[];
  try {
    listed = await inventory();
  } catch {
    return partial("TRANSPORT_UNCERTAIN");
  }
  const present = new Map(listed.map((object) => [object.fileId, object]));
  const damaged = (versions: Map<string, BackupV2RetentionVersion>) => {
    const available = catalogAvailability(
      authority,
      versions,
      plan.retainedCaptureIds,
    );
    if (!available.damaged.length) return false;
    retainedCaptureIds = available.intact.map((entry) => entry.captureId);
    summary.keptGenerations = retainedCaptureIds.length;
    summary.damagedCaptureIds = available.damaged;
    return true;
  };
  if (damaged(present)) return partial("DAMAGED_ACCEPTED_GENERATION");
  const byName = new Map<string, BackupV2RetentionVersion[]>();
  for (const object of listed) {
    const versions = byName.get(object.fileName) ?? [];
    versions.push(object);
    byName.set(object.fileName, versions);
  }
  const original = [...listed];
  for (let ordinal = 0; ordinal < plan.candidates.length; ordinal++) {
    const { object } = plan.candidates[ordinal];
    const found = present.get(object.fileId);
    const previous = byOrdinal.get(ordinal)?.state;
    if (found) {
      if (
        previous === "DELETED" || previous === "ABSENT" ||
        !sameRetentionEvidence(found, object)
      ) return partial("IDENTITY_CHANGED");
    } else {
      if (
        (!previous || previous === "PRESENT") && !orphanIds.has(object.fileId)
      ) {
        return partial("IDENTITY_CHANGED");
      }
      original.push(object);
    }
  }
  original.sort(retentionVersionOrder);
  try {
    if (
      retentionSha256(original) !== plan.inventorySha256 ||
      planFromInventory(authority, original).digest !== digest
    ) return partial("PLAN_CHANGED");
  } catch {
    return partial("PLAN_CHANGED");
  }
  const forget = (object: BackupV2RetentionVersion) => {
    present.delete(object.fileId);
    byName.set(
      object.fileName,
      (byName.get(object.fileName) ?? []).filter((version) =>
        version.fileId !== object.fileId
      ),
    );
  };
  const matching = (
    current: BackupV2RetentionVersion[],
    expected: BackupV2RetentionVersion[],
  ) => {
    const actual = new Map(current.map((object) => [object.fileId, object]));
    const missing: BackupV2RetentionVersion[] = [];
    for (const prior of expected) {
      const observed = actual.get(prior.fileId);
      if (!observed) {
        if (!orphanIds.has(prior.fileId)) return false;
        missing.push(prior);
      } else if (!sameRetentionEvidence(observed, prior)) return false;
      actual.delete(prior.fileId);
    }
    if (actual.size) return false;
    for (const object of missing) forget(object);
    return true;
  };
  const exact = async (object: BackupV2RetentionVersion) => {
    const current = await inventory(object.fileName);
    return matching(current, byName.get(object.fileName) ?? []);
  };
  const retirementChecked = new Set<string>();
  const full = async () => {
    const current = await inventory();
    if (damaged(new Map(current.map((object) => [object.fileId, object])))) {
      return "DAMAGED_ACCEPTED_GENERATION" as const;
    }
    return matching(current, [...present.values()])
      ? null
      : "IDENTITY_CHANGED" as const;
  };
  for (
    let ordinal = ordinalToProcess;
    ordinal < plan.candidates.length;
    ordinal++
  ) {
    const { object, retiringCaptureIds } = plan.candidates[ordinal];
    let previous = byOrdinal.get(ordinal);
    try {
      await fresh();
      if (retiringCaptureIds?.some((id) => !retirementChecked.has(id))) {
        const block = await full();
        if (block) return partial(block);
        for (const id of retiringCaptureIds) retirementChecked.add(id);
      }
      if (!await exact(object)) return partial("IDENTITY_CHANGED");
      if (previous?.state === "INTENT" || previous?.state === "AMBIGUOUS") {
        const exists = present.has(object.fileId);
        await append(ordinal, previous.attempt, exists ? "PRESENT" : "ABSENT");
        if (!exists) continue;
        previous = byOrdinal.get(ordinal);
      }
      if (!present.has(object.fileId) && orphanIds.has(object.fileId)) {
        await append(ordinal, previous?.attempt ?? 1, "ABSENT");
        continue;
      }
      if (
        !present.has(object.fileId) ||
        age(object) > clock() - plan.policy.orphanGraceHours * hourMs
      ) return partial("IDENTITY_CHANGED");
      const attempt = (previous?.attempt ?? 0) + 1;
      if (attempt > 16) return partial("TRANSPORT_UNCERTAIN");
      await append(ordinal, attempt, "INTENT");
      await fresh();
      if (!await exact(object)) return partial("IDENTITY_CHANGED");
      if (!present.has(object.fileId)) {
        await append(ordinal, attempt, "ABSENT");
        continue;
      }
      caps.signal?.throwIfAborted();
      try {
        await caps.removeExact(structuredClone(object), caps.signal);
      } catch {
        if (
          orphanIds.has(object.fileId) && await exact(object) &&
          !present.has(object.fileId)
        ) {
          await append(ordinal, attempt, "ABSENT");
          continue;
        }
        await append(ordinal, attempt, "AMBIGUOUS");
        return partial("TRANSPORT_UNCERTAIN");
      }
      await append(ordinal, attempt, "DELETED");
      forget(object);
    } catch (error) {
      return partial(
        error instanceof RetentionPreconditionError
          ? "PLAN_CHANGED"
          : "TRANSPORT_UNCERTAIN",
      );
    }
  }
  try {
    await fresh();
    const block = await full();
    if (block) return partial(block);
  } catch (error) {
    return partial(
      error instanceof RetentionPreconditionError
        ? "PLAN_CHANGED"
        : "TRANSPORT_UNCERTAIN",
    );
  }
  return { status: "COMPLETE", summary, retainedCaptureIds };
}
