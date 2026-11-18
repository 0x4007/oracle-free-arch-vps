/** Source-side metadata adapter. The caller owns authenticated graph production,
 * exclusive custody, root-only bounded filesystem IO and managed native work. */
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  parseBackupV2ObjectName,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
} from "./backup-v2-contract.ts";
import {
  type BackupV2ProtectionDescriptor,
  type BackupV2ProtectionPageRef,
  type BackupV2PruneInput,
  type BackupV2PrunePlanReference,
  type BackupV2PruneProgress,
  type BackupV2PruneResult,
  parseBackupV2ProtectionManifest,
  parseBackupV2ProtectionPage,
  validateBackupV2ProtectionDescriptor,
} from "./backup-v2-protection.ts";
import {
  type BackupV2RetentionJournalEntry,
  type BackupV2RetentionPlan,
  type BackupV2RetentionReader,
  executeBackupV2Retention,
  planBackupV2Retention,
  validateBackupV2RetentionJob,
  validateBackupV2RetentionPlan,
  validateBackupV2RetentionPolicy,
  validateBackupV2RetiredRestic,
} from "./backup-v2-retention.ts";
import {
  validateBackupRuntimeCatalogEntry,
  validateBackupV2Gate,
} from "./backup-v2-runtime-contract.ts";
import { BACKUP_V2_LIMITS, BACKUP_V2_WORKSPACE } from "./backup-v2-profile.ts";
import type { BackupV2Store } from "./backup-v2-store.ts";

export interface BackupV2SourcePrunerCapabilities {
  exactStore: Pick<
    BackupV2Store,
    | "bucketVersionsPage"
    | "unfinishedFilesPage"
    | "unfinishedPartsPage"
    | "removeRetentionVersion"
  >;
  /** Reads are root600, no symlinks, identity-bound and bounded before allocation. */
  readGraphManifest(
    descriptor: BackupV2ProtectionDescriptor,
  ): Promise<Uint8Array>;
  readGraphPage(
    descriptor: BackupV2ProtectionDescriptor,
    page: BackupV2ProtectionPageRef,
  ): Promise<Uint8Array>;
  readPlan(
    transactionId: string,
    reference: BackupV2PrunePlanReference,
  ): Promise<Uint8Array>;
  /** Create/fsync or verify byte-identical prior publication; never overwrite a reviewed plan. */
  writePlanDurable(transactionId: string, bytes: Uint8Array): Promise<void>;
  /** Reads the exact transaction's bounded journal, including a genuinely fresh empty journal. */
  loadJournal(
    transactionId: string,
  ): Promise<readonly BackupV2RetentionJournalEntry[]>;
  appendDurable(
    transactionId: string,
    entry: BackupV2RetentionJournalEntry,
  ): Promise<void>;
  observeFresh(): Promise<BackupV2PruneInput>;
  validateLegacy: BackupV2RetentionReader["validateLegacy"];
  progress(value: BackupV2PruneProgress): Promise<void>;
  now(): Date;
  signal?: AbortSignal;
}
const encoder = new TextEncoder(),
  decoder = new TextDecoder("utf-8", { fatal: true });
const encoded = (value: unknown) =>
  encoder.encode(JSON.stringify(value) + "\n");
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
const hash = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const uuid = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
function fail(): never {
  throw new Error("Backup v2 source prune evidence invalid or incomplete");
}
function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (
    Object.keys(r).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(r, key))
  ) fail();
  return r;
}
function list(value: unknown): unknown[] {
  if (
    !Array.isArray(value) || value.length > BACKUP_V2_LIMITS.pruneCandidates
  ) fail();
  return value;
}
function boundedBytes(value: unknown, maximum: number): Uint8Array {
  if (
    !(value instanceof Uint8Array) || value.length <= 0 ||
    value.length > maximum
  ) fail();
  return value;
}
function planReference(value: unknown): BackupV2PrunePlanReference {
  const r = record(value, ["sha256", "bytes", "digest"]);
  if (
    !hash(r.sha256) || !hash(r.digest) || !Number.isSafeInteger(r.bytes) ||
    (r.bytes as number) <= 0 ||
    (r.bytes as number) > BACKUP_V2_LIMITS.journalBytes
  ) fail();
  return { sha256: r.sha256, digest: r.digest, bytes: r.bytes as number };
}
export function validateBackupV2PruneInput(
  value: unknown,
  legacy: BackupV2RetentionReader["validateLegacy"],
): BackupV2PruneInput {
  if (encoded(value).length > BACKUP_V2_LIMITS.controlResponseBytes) fail();
  const r = record(structuredClone(value), [
    "schemaVersion",
    "format",
    "gate",
    "transactionId",
    "stage",
    "scratchCleanupRequestSha256",
    "snapshot",
    "graphs",
    "plan",
  ]);
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2-prune" ||
    !uuid(r.transactionId) || !["PLAN", "EXECUTE"].includes(String(r.stage)) ||
    r.scratchCleanupRequestSha256 !== null &&
      !hash(r.scratchCleanupRequestSha256)
  ) fail();
  const gate = validateBackupV2Gate(r.gate);
  if (gate.kind !== "prune" || gate.state !== "ACTIVE" || !gate.custody) fail();
  const snapshot = record(r.snapshot, [
      "custody",
      "catalog",
      "protection",
      "receipts",
      "policy",
      "plannedAtUtc",
      "jobs",
      ...(r.snapshot && Object.hasOwn(r.snapshot as object, "retiredRestic")
        ? ["retiredRestic"]
        : []),
      ...(r.snapshot && Object.hasOwn(r.snapshot as object, "verifyCatalogOnly")
        ? ["verifyCatalogOnly"]
        : []),
    ]),
    custody = record(snapshot.custody, [
      "lockId",
      "sourceBootId",
      "sourceSettled",
    ]),
    protection = record(snapshot.protection, [
      "acceptedRoots",
      "activeObjects",
      "sealedRoleManifests",
      "unresolvedPuts",
    ]),
    catalog = list(snapshot.catalog).map((entry) =>
      validateBackupRuntimeCatalogEntry(entry, legacy)
    );
  const captures = catalog.map((entry) =>
    entry.format === "backup-v1"
      ? entry.entry.index.generation
      : entry.envelope.request.captureId
  );
  if (
    new Set(captures).size !== catalog.length ||
    custody.sourceBootId !== gate.sourceBootId ||
    custody.sourceSettled !== true || typeof custody.lockId !== "string" ||
    !/^[\x21-\x7e]{1,256}$/.test(custody.lockId)
  ) fail();
  const plan = r.stage === "PLAN" ? null : planReference(r.plan);
  const policy = validateBackupV2RetentionPolicy(snapshot.policy);
  const plannedAtUtc = snapshot.plannedAtUtc;
  if (
    r.stage === "PLAN" && r.plan !== null ||
    r.stage === "EXECUTE" && !policy.execute ||
    Object.hasOwn(snapshot, "verifyCatalogOnly") &&
      (snapshot.verifyCatalogOnly !== true || policy.execute ||
        r.stage !== "PLAN" ||
        r.scratchCleanupRequestSha256 !== null) ||
    typeof plannedAtUtc !== "string" ||
    !Number.isFinite(Date.parse(plannedAtUtc)) ||
    new Date(plannedAtUtc).toISOString() !== plannedAtUtc
  ) fail();
  const jobs = list(snapshot.jobs).map(validateBackupV2RetentionJob);
  if (new Set(jobs.map((job) => job.captureId)).size !== jobs.length) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-prune",
    gate,
    transactionId: r.transactionId,
    stage: r.stage as "PLAN" | "EXECUTE",
    scratchCleanupRequestSha256: r.scratchCleanupRequestSha256,
    plan,
    snapshot: {
      custody: {
        lockId: custody.lockId,
        sourceBootId: gate.sourceBootId,
        sourceSettled: true,
      },
      catalog,
      policy,
      plannedAtUtc,
      jobs,
      ...(Object.hasOwn(snapshot, "retiredRestic")
        ? {
          retiredRestic: validateBackupV2RetiredRestic(snapshot.retiredRestic),
        }
        : {}),
      ...(snapshot.verifyCatalogOnly === true
        ? { verifyCatalogOnly: true }
        : {}),
      protection: {
        acceptedRoots: list(protection.acceptedRoots).map(
          validateBackupV2ManifestRef,
        ),
        activeObjects: list(protection.activeObjects).map(
          validateBackupV2ObjectRef,
        ),
        sealedRoleManifests: list(protection.sealedRoleManifests).map(
          validateBackupV2ManifestRef,
        ),
        unresolvedPuts: list(protection.unresolvedPuts).map(
          validateBackupV2PutIntent,
        ),
      },
      receipts: list(snapshot.receipts).map(validateBackupV2ManifestRef),
    },
    graphs: list(r.graphs).map(validateBackupV2ProtectionDescriptor),
  };
}

/** PLAN publishes metadata only. EXECUTE requires its exact file and fresh
 * source/controller custody. Both formats use the same bounded version plan. */
export async function runBackupV2SourcePruner(
  raw: BackupV2PruneInput,
  caps: BackupV2SourcePrunerCapabilities,
): Promise<BackupV2PruneResult> {
  const input = validateBackupV2PruneInput(raw, caps.validateLegacy);
  caps.signal?.throwIfAborted();
  let inventoryMembers = 0, graphBytes = 0, planBytes = 0, journalBytes = 0;
  const controlBytes = encoded(input).length;
  const budget = (extra = 0) => {
    if (
      controlBytes + graphBytes + planBytes + journalBytes + extra >
        BACKUP_V2_WORKSPACE.retention
    ) fail();
  };
  const advance = async (count: number) => {
    if (
      !Number.isSafeInteger(count) || count < 0 ||
      !Number.isSafeInteger(inventoryMembers + count)
    ) fail();
    if (count) {
      inventoryMembers += count;
      await caps.progress({ inventoryMembers });
    }
  };
  const cache = new Map<
    string,
    { descriptor: BackupV2ProtectionDescriptor; refs: BackupV2ObjectRef[] }
  >();
  const physical = new Map<string, BackupV2ObjectRef>();
  const rootKey = (value: BackupV2ManifestRef) =>
    JSON.stringify(validateBackupV2ManifestRef(value));
  const graphsFor = async (value: BackupV2PruneInput) => {
    const required = new Map<string, BackupV2ManifestRef>();
    const rootIds = new Map<string, BackupV2ManifestRef>();
    for (
      const root of [
        ...value.snapshot.catalog.flatMap((entry) =>
          entry.format === "backup-v2" ? [entry.selectedRoot.reference] : []
        ),
        ...value.snapshot.protection.acceptedRoots,
        ...value.snapshot.protection.sealedRoleManifests,
      ]
    ) {
      const old = rootIds.get(root.object.fileId);
      if (
        parseBackupV2ObjectName(root.object.fileName).kind !== "manifest" ||
        old && !isDeepStrictEqual(old, root)
      ) fail();
      rootIds.set(root.object.fileId, root);
      required.set(rootKey(root), root);
    }
    const graphs = new Map<string, BackupV2ObjectRef[]>();
    for (const descriptor of value.graphs) {
      caps.signal?.throwIfAborted();
      const key = rootKey(descriptor.root);
      if (!required.has(key) || graphs.has(key)) fail();
      const saved = cache.get(descriptor.manifestSha256);
      if (saved && !isDeepStrictEqual(saved.descriptor, descriptor)) fail();
      let refs = saved?.refs;
      if (!refs) {
        if (
          graphBytes + descriptor.manifestBytes + descriptor.totalPageBytes >
            BACKUP_V2_WORKSPACE.retention
        ) fail();
        graphBytes += descriptor.manifestBytes + descriptor.totalPageBytes;
        budget();
        const manifest = parseBackupV2ProtectionManifest(
          boundedBytes(
            await caps.readGraphManifest(descriptor),
            descriptor.manifestBytes,
          ),
          descriptor,
        );
        const unique = new Map<string, BackupV2ObjectRef>();
        let bytes = 0;
        for (const page of manifest.pages) {
          caps.signal?.throwIfAborted();
          const data = boundedBytes(
              await caps.readGraphPage(descriptor, page),
              page.bytes,
            ),
            parsed = parseBackupV2ProtectionPage(
              data,
              manifest,
              page.pageIndex,
            );
          bytes += data.length;
          for (const ref of parsed.objects) {
            const old = physical.get(ref.fileId);
            if (unique.has(ref.fileId) || old && !isDeepStrictEqual(old, ref)) {
              fail();
            }
            unique.set(ref.fileId, ref);
            physical.set(ref.fileId, ref);
            if (physical.size > BACKUP_V2_LIMITS.pruneCandidates) fail();
          }
          await advance(parsed.objects.length);
        }
        if (
          bytes !== descriptor.totalPageBytes ||
          unique.size !== descriptor.objectCount ||
          !isDeepStrictEqual(
            unique.get(descriptor.root.object.fileId),
            descriptor.root.object,
          )
        ) fail();
        refs = [...unique.values()];
        cache.set(descriptor.manifestSha256, { descriptor, refs });
      }
      graphs.set(key, refs);
    }
    if (graphs.size !== required.size) fail();
    for (const entry of value.snapshot.catalog) {
      if (entry.format === "backup-v2") {
        const refs = new Map(
          graphs.get(rootKey(entry.selectedRoot.reference))!.map((
            ref,
          ) => [ref.fileId, ref]),
        );
        for (
          const ref of [
            ...entry.selectedRoot.root.roles.map((role) =>
              role.manifest.object
            ),
            ...entry.selectedRoot.root.metadata,
          ]
        ) if (!isDeepStrictEqual(refs.get(ref.fileId), ref)) fail();
      }
    }
    return graphs;
  };
  const graphs = await graphsFor(input);
  const references = (root: BackupV2ManifestRef) => {
    const refs = graphs.get(rootKey(root));
    if (!refs) fail();
    return Promise.resolve(structuredClone(refs));
  };
  const reader: BackupV2RetentionReader = {
    references,
    roleReferences: references,
    validateLegacy: caps.validateLegacy,
    async bucketVersionsPage(cursor, prefix) {
      caps.signal?.throwIfAborted();
      const page = await caps.exactStore.bucketVersionsPage(
        cursor,
        prefix,
        caps.signal,
      );
      await advance(1 + page.items.length);
      return page;
    },
    async unfinishedFilesPage(cursor, prefix) {
      caps.signal?.throwIfAborted();
      const page = await caps.exactStore.unfinishedFilesPage(
        cursor,
        prefix,
        caps.signal,
      );
      await advance(1 + page.items.length);
      return page;
    },
    async unfinishedPartsPage(fileId, cursor) {
      caps.signal?.throwIfAborted();
      const page = await caps.exactStore.unfinishedPartsPage(
        fileId,
        cursor,
        caps.signal,
      );
      await advance(1 + page.items.length);
      return page;
    },
  };
  const readPlan = async (ref: BackupV2PrunePlanReference) => {
    const bytes = boundedBytes(
      await caps.readPlan(input.transactionId, ref),
      BACKUP_V2_LIMITS.journalBytes,
    );
    if (bytes.length !== ref.bytes || sha(bytes) !== ref.sha256) fail();
    const value = validateBackupV2RetentionPlan(
      JSON.parse(decoder.decode(bytes)),
      ref.digest,
    );
    planBytes = bytes.length;
    budget();
    await advance(1);
    return value;
  };
  let plan: BackupV2RetentionPlan,
    ref: BackupV2PrunePlanReference,
    state: BackupV2PruneResult["state"],
    summary: BackupV2PruneResult["summary"],
    retainedCaptureIds: string[];
  if (input.stage === "PLAN") {
    if (
      !Number.isFinite(caps.now().getTime()) ||
      Date.parse(input.snapshot.plannedAtUtc) > caps.now().getTime()
    ) fail();
    plan = await planBackupV2Retention(input.snapshot, reader);
    const bytes = encoded(plan);
    boundedBytes(bytes, BACKUP_V2_LIMITS.journalBytes);
    planBytes = bytes.length;
    budget();
    ref = { sha256: sha(bytes), bytes: bytes.length, digest: plan.digest };
    await caps.writePlanDurable(input.transactionId, bytes.slice());
    await advance(1);
    if (!isDeepStrictEqual(await readPlan(ref), plan)) fail();
    state = "PLAN_PROVED";
    summary = plan.summary;
    retainedCaptureIds = plan.retainedCaptureIds;
  } else {
    ref = input.plan!;
    plan = await readPlan(ref);
    try {
      const outcome = await executeBackupV2Retention(plan, ref.digest, {
        reader,
        signal: caps.signal,
        now: caps.now,
        async observeFresh() {
          caps.signal?.throwIfAborted();
          const fresh = validateBackupV2PruneInput(
            await caps.observeFresh(),
            caps.validateLegacy,
          );
          if (
            fresh.transactionId !== input.transactionId ||
            fresh.stage !== "EXECUTE" ||
            !isDeepStrictEqual(fresh.plan, input.plan) ||
            !isDeepStrictEqual(fresh.graphs, input.graphs) ||
            fresh.scratchCleanupRequestSha256 !==
              input.scratchCleanupRequestSha256 ||
            !isDeepStrictEqual({
              ...fresh.gate,
              updatedAtUtc: input.gate.updatedAtUtc,
            }, input.gate)
          ) fail();
          return fresh.snapshot;
        },
        async loadJournal() {
          const entries = await caps.loadJournal(input.transactionId);
          if (!Array.isArray(entries)) fail();
          for (const entry of entries) {
            record(entry, [
              "planSha256",
              "ordinal",
              "fileId",
              "fileName",
              "attempt",
              "state",
            ]);
          }
          journalBytes = encoded(entries).length;
          if (journalBytes > BACKUP_V2_LIMITS.journalBytes) fail();
          budget();
          await advance(entries.length);
          return structuredClone(entries);
        },
        async appendDurable(entry) {
          const bytes = encoded(entry).length,
            reserve = entry.state === "INTENT" ? bytes + 16 : 0;
          if (journalBytes + bytes + reserve > BACKUP_V2_LIMITS.journalBytes) {
            fail();
          }
          budget(bytes + reserve);
          await caps.appendDurable(input.transactionId, structuredClone(entry));
          journalBytes += bytes;
          await advance(1);
        },
        async removeExact(object, signal) {
          await caps.exactStore.removeRetentionVersion(
            object,
            signal,
            input.snapshot.retiredRestic?.prefix,
          );
          await advance(1);
        },
      });
      state = outcome.status === "COMPLETE" ? "COMPLETE" : "PARTIAL";
      summary = outcome.summary;
      retainedCaptureIds = outcome.retainedCaptureIds;
    } catch {
      state = "PARTIAL";
      summary = { ...plan.summary, blockReason: "PLAN_CHANGED" };
      retainedCaptureIds = plan.retainedCaptureIds;
    }
  }
  const now = caps.now();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-prune-result",
    gate: input.gate,
    transactionId: input.transactionId,
    stage: input.stage,
    state,
    plan: ref,
    retainedCaptureIds: [...retainedCaptureIds],
    retiredCaptureIds: state === "PARTIAL" ? [] : [...plan.retiredCaptureIds],
    obsoleteLegacyCaptureIds: state === "PARTIAL"
      ? []
      : [...plan.obsoleteLegacyCaptureIds],
    summary,
    finishedAtUtc: now.toISOString(),
  };
}
