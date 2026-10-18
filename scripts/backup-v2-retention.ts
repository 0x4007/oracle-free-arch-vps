import { createHash } from "node:crypto";
import type { CatalogEntry } from "./backblaze-file-backup.ts";
import { validateBackupRuntimeCatalogEntry } from "./backup-v2-runtime-contract.ts";
import {
  type BackupV2Cursor,
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  type BackupV2ProtectedReferences,
  type BackupV2ReachabilityReader,
  parseBackupV2ObjectName,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
  validateBackupV2VersionPage,
} from "./backup-v2-contract.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_LIMITS,
  BACKUP_V2_WORKSPACE,
} from "./backup-v2-profile.ts";

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

export interface BackupV2RetentionSnapshot {
  /** Caller must hold this exact exclusive controller/source-settlement custody. */
  custody: { lockId: string; sourceBootId: string; sourceSettled: true };
  catalog: readonly unknown[];
  protection: BackupV2ProtectedReferences;
  receipts: readonly BackupV2ManifestRef[];
}
export interface BackupV2RetentionReader extends BackupV2ProtectionReader {
  validateLegacy(value: unknown): CatalogEntry;
  /** Complete fresh v2 namespace inventory, bounded by the existing page contract. */
  versionsPage(cursor: BackupV2Cursor | null): Promise<unknown>;
}
export interface BackupV2RetentionPlan {
  schemaVersion: 2;
  format: "backup-v2-retention";
  dryRun: true;
  preconditionSha256: string;
  retainedCaptureIds: string[];
  obsoleteLegacyCaptureIds: string[];
  candidates: BackupV2ObjectRef[];
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
  /** Resolves only after the complete record is persisted and fsynced. */
  appendDurable(entry: BackupV2RetentionJournalEntry): Promise<void>;
  removeExact(object: BackupV2ObjectRef, signal?: AbortSignal): Promise<void>;
  /** Caller settles the prior request, then checks this exact ID and full identity. */
  reconcileExact(
    object: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<"absent" | "present" | "unknown">;
  signal?: AbortSignal;
}

const encode = new TextEncoder();
const sha = (value: unknown) =>
  createHash("sha256").update(
    JSON.stringify(value, (_key, item) =>
      item && typeof item === "object" && !Array.isArray(item)
        ? Object.fromEntries(
          Object.keys(item).sort().map((key) => [key, item[key]]),
        )
        : item),
  ).digest("hex");
const hash = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function invalid(): never {
  throw new Error("Retention identity, protection or precondition invalid");
}
const order = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const compare = (a: BackupV2ObjectRef, b: BackupV2ObjectRef) =>
  order(a.fileName, b.fileName) || order(a.fileId, b.fileId);
const same = (a: unknown, b: unknown) => sha(a) === sha(b);
function addReference(
  map: Map<string, BackupV2ObjectRef>,
  value: BackupV2ObjectRef,
) {
  const ref = validateBackupV2ObjectRef(value), old = map.get(ref.fileId);
  if (old && !same(old, ref)) invalid();
  map.set(ref.fileId, ref);
  assertBackupV2Budget("pruneCandidates", map.size);
}
function bounded(value: unknown, maximum = BACKUP_V2_WORKSPACE.retention) {
  if (encode.encode(JSON.stringify(value)).length > maximum) invalid();
}
async function protectionState(
  input: BackupV2RetentionSnapshot,
  reader: BackupV2RetentionReader,
) {
  const snapshot = structuredClone(input), custody = snapshot.custody;
  if (
    !custody || custody.sourceSettled !== true ||
    typeof custody.lockId !== "string" ||
    !/^[\x21-\x7e]{1,256}$/.test(custody.lockId) ||
    !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(
      custody.sourceBootId,
    ) ||
    !Array.isArray(snapshot.catalog) || snapshot.catalog.length < 4
  ) invalid();
  assertBackupV2Budget("pruneCandidates", snapshot.catalog.length);
  bounded(snapshot);
  const catalog = snapshot.catalog.map((entry) =>
    validateBackupRuntimeCatalogEntry(entry, reader.validateLegacy)
  );
  const capture = (entry: typeof catalog[number]) =>
    entry.format === "backup-v1"
      ? entry.entry.index.generation
      : entry.envelope.request.captureId;
  const time = (entry: typeof catalog[number]) =>
    entry.format === "backup-v1"
      ? entry.entry.acceptedAtUtc
      : entry.acceptedAtUtc;
  if (new Set(catalog.map(capture)).size !== catalog.length) invalid();
  catalog.sort((a, b) =>
    order(time(b), time(a)) || order(capture(a), capture(b))
  );
  const retained = catalog.slice(0, 4), obsolete = catalog.slice(4);
  const roots = retained.flatMap((entry) =>
    entry.format === "backup-v2" ? [entry.selectedRoot.reference] : []
  );
  const receipts = retained.flatMap((entry) =>
    entry.format === "backup-v2" ? [entry.receiptReference] : []
  );
  const protectedSet = await collectBackupV2ProtectedReferences(
    {
      ...snapshot.protection,
      acceptedRoots: [...roots, ...snapshot.protection.acceptedRoots],
    },
    reader,
    [...receipts, ...snapshot.receipts],
  );
  protectedSet.objects.sort(compare);
  const preconditionSha256 = sha({
    custody,
    catalog,
    manifests: [
      ...snapshot.protection.acceptedRoots,
      ...snapshot.protection.sealedRoleManifests,
      ...snapshot.receipts,
    ]
      .map((ref) => validateBackupV2ManifestRef(ref)).sort((a, b) =>
        compare(a.object, b.object)
      ),
    protectedSet,
  });
  return {
    retainedCaptureIds: retained.map(capture),
    obsolete,
    protectedSet,
    preconditionSha256,
  };
}

async function inventory(reader: BackupV2RetentionReader) {
  const objects = new Map<
    string,
    ReturnType<typeof validateBackupV2VersionPage>["items"][number]
  >();
  const cursors = new Set<string>();
  let cursor: BackupV2Cursor | null = null, pages = 0, bytes = 0;
  do {
    assertBackupV2Budget(
      "pruneCandidates",
      ++pages * BACKUP_V2_LIMITS.listEntries,
    );
    const page = validateBackupV2VersionPage(await reader.versionsPage(cursor));
    for (const ref of page.items) {
      if (ref.action !== "upload" || objects.has(ref.fileId)) invalid();
      objects.set(ref.fileId, ref);
      assertBackupV2Budget("pruneCandidates", objects.size);
      bytes += encode.encode(JSON.stringify(ref)).length;
      if (bytes > BACKUP_V2_WORKSPACE.retention) invalid();
    }
    cursor = page.next;
    if (cursor) {
      const key = JSON.stringify(cursor);
      if (cursors.has(key)) invalid();
      cursors.add(key);
    }
  } while (cursor);
  return objects;
}
function requirePresent(
  ref: BackupV2ObjectRef,
  versions: Awaited<ReturnType<typeof inventory>>,
) {
  const found = versions.get(ref.fileId);
  const { sha256: _sha, ...expected } = ref;
  if (!found || !same(found, expected)) invalid();
}

/** Keeps newest four mixed-format accepted captures. Only exact references
 * reached from obsolete v2 roots can be candidates; unreferenced inventory is
 * never treated as a deletion list. Legacy pruning remains a separate caller. */
export async function planBackupV2Retention(
  snapshot: BackupV2RetentionSnapshot,
  reader: BackupV2RetentionReader,
): Promise<BackupV2RetentionPlan> {
  const state = await protectionState(snapshot, reader),
    versions = await inventory(reader);
  const protectedRefs = new Map(
    state.protectedSet.objects.map((ref) => [ref.fileId, ref]),
  );
  const unresolved = new Set(state.protectedSet.unresolvedNames);
  const obsolete = new Map<string, BackupV2ObjectRef>();
  for (const ref of state.protectedSet.objects) requirePresent(ref, versions);
  for (const entry of state.obsolete) {
    if (entry.format !== "backup-v2") continue;
    for (
      const ref of [
        entry.selectedRoot.reference.object,
        entry.receiptReference.object,
        ...await reader.references(entry.selectedRoot.reference),
      ]
    ) {
      const protectedRef = protectedRefs.get(ref.fileId);
      if (protectedRef && !same(protectedRef, validateBackupV2ObjectRef(ref))) {
        invalid();
      }
      addReference(obsolete, ref);
    }
  }
  for (const ref of obsolete.values()) requirePresent(ref, versions);
  const candidates = [...obsolete.values()].filter((ref) =>
    !protectedRefs.has(ref.fileId) && !unresolved.has(ref.fileName)
  ).sort(compare);
  const body = {
    schemaVersion: 2 as const,
    format: "backup-v2-retention" as const,
    dryRun: true as const,
    preconditionSha256: state.preconditionSha256,
    retainedCaptureIds: state.retainedCaptureIds,
    obsoleteLegacyCaptureIds: state.obsolete.flatMap((entry) =>
      entry.format === "backup-v1" ? [entry.entry.index.generation] : []
    ),
    candidates,
  };
  bounded([state.protectedSet, [...versions.values()], body]);
  bounded(body, BACKUP_V2_LIMITS.journalBytes);
  return { ...body, digest: sha(body) };
}

function checkedPlan(input: BackupV2RetentionPlan, digest: string) {
  const value = structuredClone(input), { digest: saved, ...body } = value;
  if (
    Object.keys(value).sort().join(",") !==
      "candidates,digest,dryRun,format,obsoleteLegacyCaptureIds,preconditionSha256,retainedCaptureIds,schemaVersion" ||
    value.schemaVersion !== 2 || value.format !== "backup-v2-retention" ||
    value.dryRun !== true ||
    !hash(digest) || saved !== digest || sha(body) !== digest ||
    !hash(value.preconditionSha256) ||
    !Array.isArray(value.retainedCaptureIds) ||
    value.retainedCaptureIds.length !== 4 ||
    new Set(value.retainedCaptureIds).size !== 4 ||
    !Array.isArray(value.obsoleteLegacyCaptureIds) ||
    !Array.isArray(value.candidates)
  ) invalid();
  const captures = [
    ...value.retainedCaptureIds,
    ...value.obsoleteLegacyCaptureIds,
  ];
  if (
    new Set(captures).size !== captures.length ||
    captures.some((id) =>
      typeof id !== "string" ||
      !/^generation-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id)
    )
  ) invalid();
  assertBackupV2Budget("pruneCandidates", value.candidates.length);
  value.candidates = value.candidates.map(validateBackupV2ObjectRef);
  if (
    new Set(value.candidates.map((ref) => ref.fileId)).size !==
      value.candidates.length ||
    !same(value.candidates, [...value.candidates].sort(compare))
  ) invalid();
  bounded(value, BACKUP_V2_LIMITS.journalBytes);
  return value;
}

/** Explicit injected execution only. A durable intent precedes every wire
 * delete; an unresolved intent is reconciled against its exact ID before any
 * repeat. Graphs are immutable; every effect refreshes their protected pins
 * and exclusive custody. Complete inventory is required at each invocation. */
export async function executeBackupV2Retention(
  input: BackupV2RetentionPlan,
  digest: string,
  caps: BackupV2RetentionExecution,
) {
  const plan = checkedPlan(input, digest),
    states = new Map<number, BackupV2RetentionJournalEntry>();
  let journalBytes = 0;
  const apply = (input: BackupV2RetentionJournalEntry) => {
    const entry = structuredClone(input),
      ref = plan.candidates[entry.ordinal],
      prior = states.get(entry.ordinal);
    if (
      entry.planSha256 !== digest || !ref || entry.fileId !== ref.fileId ||
      entry.fileName !== ref.fileName ||
      !Number.isSafeInteger(entry.ordinal) || entry.ordinal < 0 ||
      !Number.isSafeInteger(entry.attempt) || entry.attempt < 1 ||
      entry.attempt > 16 ||
      !["INTENT", "DELETED", "ABSENT", "PRESENT", "AMBIGUOUS"].includes(
        entry.state,
      )
    ) invalid();
    if (entry.state === "INTENT") {
      if (
        (!prior && entry.attempt !== 1) ||
        (prior &&
          (prior.state !== "PRESENT" || entry.attempt !== prior.attempt + 1))
      ) invalid();
    } else if (
      !prior || !["INTENT", "AMBIGUOUS"].includes(prior.state) ||
      entry.attempt !== prior.attempt
    ) invalid();
    journalBytes += encode.encode(JSON.stringify(entry)).length + 1;
    assertBackupV2Budget("journalBytes", journalBytes);
    states.set(entry.ordinal, entry);
  };
  const loaded = await caps.loadJournal();
  if (!Array.isArray(loaded)) invalid();
  bounded(loaded, BACKUP_V2_LIMITS.journalBytes);
  for (const entry of loaded) apply(entry);
  const append = async (
    ordinal: number,
    attempt: number,
    state: BackupV2RetentionJournalEntry["state"],
  ) => {
    const ref = plan.candidates[ordinal],
      entry = {
        planSha256: digest,
        ordinal,
        fileId: ref.fileId,
        fileName: ref.fileName,
        attempt,
        state,
      };
    apply(entry);
    await caps.appendDurable(structuredClone(entry));
  };
  const refresh = async () => {
    caps.signal?.throwIfAborted();
    const state = await protectionState(await caps.observeFresh(), caps.reader);
    if (
      state.preconditionSha256 !== plan.preconditionSha256 ||
      !same(state.retainedCaptureIds, plan.retainedCaptureIds)
    ) invalid();
    const protectedIds = new Set(
      state.protectedSet.objects.map((ref) => ref.fileId),
    );
    const unresolved = new Set(state.protectedSet.unresolvedNames);
    for (const ref of plan.candidates) {
      if (protectedIds.has(ref.fileId) || unresolved.has(ref.fileName)) {
        invalid();
      }
    }
    return state;
  };
  const initial = await refresh(), versions = await inventory(caps.reader);
  for (const ref of initial.protectedSet.objects) requirePresent(ref, versions);
  for (let ordinal = 0; ordinal < plan.candidates.length; ordinal++) {
    const ref = plan.candidates[ordinal], prior = states.get(ordinal);
    if (prior && ["DELETED", "ABSENT"].includes(prior.state)) {
      if (versions.has(ref.fileId)) invalid();
    } else if (versions.has(ref.fileId)) requirePresent(ref, versions);
    else if (!prior || !["INTENT", "AMBIGUOUS"].includes(prior.state)) {
      invalid();
    }
  }
  for (let ordinal = 0; ordinal < plan.candidates.length; ordinal++) {
    const ref = plan.candidates[ordinal];
    let prior = states.get(ordinal);
    if (prior && ["DELETED", "ABSENT"].includes(prior.state)) continue;
    await refresh();
    const actual = await caps.reconcileExact(structuredClone(ref), caps.signal);
    if (!["absent", "present", "unknown"].includes(actual)) invalid();
    if (actual === "unknown") {
      return { status: "AMBIGUOUS" as const, ordinal, digest };
    }
    if (prior && ["INTENT", "AMBIGUOUS"].includes(prior.state)) {
      await append(
        ordinal,
        prior.attempt,
        actual === "absent" ? "ABSENT" : "PRESENT",
      );
      if (actual === "absent") continue;
      prior = states.get(ordinal);
    } else if (actual !== "present") invalid();
    await refresh();
    const attempt = (prior?.attempt ?? 0) + 1;
    await append(ordinal, attempt, "INTENT");
    await refresh();
    caps.signal?.throwIfAborted();
    try {
      await caps.removeExact(structuredClone(ref), caps.signal);
    } catch {
      await append(ordinal, attempt, "AMBIGUOUS");
      return { status: "AMBIGUOUS" as const, ordinal, digest };
    }
    await append(ordinal, attempt, "DELETED");
  }
  return {
    status: "COMPLETE" as const,
    digest,
    deleted: plan.candidates.length,
  };
}
