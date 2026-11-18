import { createHash } from "node:crypto";
import { validateCatalogEntry } from "../scripts/backblaze-file-backup.ts";
import { generationChunkName } from "../scripts/backblaze-upload.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
} from "../scripts/backup-v2-runtime-contract.ts";
import { createBackupV2InventorySummary } from "../scripts/backup-v2-inventory.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ListedVersion,
  type BackupV2ManifestRef,
  backupV2ObjectName,
  type BackupV2ObjectRef,
  type BackupV2ProtectedReferences,
} from "../scripts/backup-v2-contract.ts";
import {
  type BackupV2RetentionExecution,
  type BackupV2RetentionJournalEntry,
  type BackupV2RetentionReader,
  type BackupV2RetentionSnapshot,
  collectBackupV2ProtectedReferences,
  DEFAULT_BACKUP_V2_RETENTION_POLICY,
  executeBackupV2Retention,
  planBackupV2Retention,
} from "../scripts/backup-v2-retention.ts";
import type { BackupV2RetentionPart } from "../scripts/backup-v2-retention-inventory.ts";
const C = "generation-00000000-0000-4000-8000-000000000001",
  A = "00000000-0000-4000-8000-000000000002",
  P = "00000000-0000-4000-8000-000000000003";
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function ref(
  id: string,
  kind: "data" | "manifest" | "receipt" = "data",
): BackupV2ObjectRef {
  return {
    fileId: id,
    fileName: backupV2ObjectName(C, A, kind, 0, P),
    contentLength: 1,
    contentSha1: "1".repeat(40),
    sha256: "2".repeat(64),
    uploadTimestamp: 1,
    action: "upload",
  };
}
const manifest = (id: string) => ({
  object: ref(id, "manifest"),
  plaintextSha256: "3".repeat(64),
});
type MutableProtection = {
  [K in keyof BackupV2ProtectedReferences]:
    BackupV2ProtectedReferences[K][number][];
};
const empty = (): MutableProtection => ({
  acceptedRoots: [],
  activeObjects: [],
  sealedRoleManifests: [],
  unresolvedPuts: [],
});
async function rejects(run: () => unknown) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed);
}
Deno.test("v2 protection dry run retains roots sealed roles receipts active refs and unresolved names", async () => {
  const input = empty();
  input.acceptedRoots.push(manifest("root"));
  input.sealedRoleManifests.push(manifest("role"));
  input.activeObjects.push(ref("active"));
  const name = backupV2ObjectName(C, A, "data", 2, P);
  input.unresolvedPuts.push({
    captureId: C,
    attemptId: A,
    role: "root",
    kind: "data",
    ordinal: 2,
    offset: 0,
    putId: P,
    createdAtUtc: "2026-10-18T10:00:00.000Z",
    name,
    slot: {
      index: 0,
      path: "/var/tmp/fixture/slot-0",
      device: 1,
      inode: 2,
      bytes: 1,
      sha1: "1".repeat(40),
      sha256: "2".repeat(64),
      uid: 0,
      mode: 384,
      links: 1,
    },
  });
  const result = await collectBackupV2ProtectedReferences(input, {
    references: () => Promise.resolve([ref("data")]),
    roleReferences: () => Promise.resolve([ref("data")]),
  }, [{ object: ref("receipt", "receipt"), plaintextSha256: "4".repeat(64) }]);
  assert(result.pruneEnabled === false);
  assert(result.objects.length === 5);
  assert(result.unresolvedNames[0] === name);
});
Deno.test("v2 protection refuses unreadable graphs conflicting identities and foreign namespaces", async () => {
  const input = empty();
  input.acceptedRoots.push(manifest("root"));
  await rejects(() =>
    collectBackupV2ProtectedReferences(input, {
      references: () => Promise.reject(new Error("unreadable")),
      roleReferences: () => Promise.resolve([]),
    }, [])
  );
  const conflicts = empty();
  conflicts.activeObjects.push(ref("same"), {
    ...ref("same"),
    sha256: "f".repeat(64),
  });
  await rejects(() =>
    collectBackupV2ProtectedReferences(conflicts, {
      references: () => Promise.resolve([]),
      roleReferences: () => Promise.resolve([]),
    }, [])
  );
  const foreign = empty();
  foreign.activeObjects.push({
    ...ref("foreign"),
    fileName: "restic/direct-v1/unrelated",
  });
  await rejects(() =>
    collectBackupV2ProtectedReferences(foreign, {
      references: () => Promise.resolve([]),
      roleReferences: () => Promise.resolve([]),
    }, [])
  );
});

const H = "2".repeat(64),
  START = "2026-10-18T04:00:00.000Z",
  END = "2026-10-18T04:01:00.000Z";
const capture = (point: number) =>
  `generation-00000000-0000-4000-8000-${String(point).padStart(12, "0")}`;
const accepted = (point: number) => `2026-10-18T04:0${point}:00.000Z`;
function object(
  point: number,
  kind: "data" | "manifest" | "receipt" | "tools" = "data",
  ordinal = 0,
): BackupV2ObjectRef {
  return {
    ...ref(`${point}-${kind}-${ordinal}`, kind === "tools" ? "data" : kind),
    fileName: backupV2ObjectName(capture(point), A, kind, ordinal, P),
  };
}
const link = (
  point: number,
  ordinal = 100,
  kind: "manifest" | "receipt" = "manifest",
): BackupV2ManifestRef => ({
  object: object(point, kind, ordinal),
  plaintextSha256: H,
});
function v2(point: number) {
  const request: BackupV2Request = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId: capture(point).replace("generation-", "job-"),
    captureId: capture(point),
    periodKey: "2026-10-18",
    requestedAtUtc: START,
    sourceRevision: "a".repeat(40),
    sourceConfigSha256: H,
    recipientSha256: H,
    recipientFingerprint: "A".repeat(40),
  };
  const summary = createBackupV2InventorySummary();
  summary.add({ path: new TextEncoder().encode("./etc/os-release") });
  const inventory = summary.finish();
  const root = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: request.profile,
    captureId: request.captureId,
    periodKey: request.periodKey,
    sourceRevision: request.sourceRevision,
    sourceConfigSha256: H,
    recipientSha256: H,
    recipientFingerprint: request.recipientFingerprint,
    roles: BACKUP_V2_ROLES.map((role, ordinal) => ({
      role,
      attemptId: A,
      manifest: link(point, ordinal),
      captureStartedAtUtc: START,
      captureFinishedAtUtc: END,
    })),
    metadata: [],
  };
  return {
    schemaVersion: 2,
    format: "backup-v2",
    envelope: { request, requestSha256: backupV2RequestSha256(request) },
    resultSha256: H,
    selectedRoot: { reference: link(point), root },
    acceptedAtUtc: accepted(point),
    receiptReference: link(point, 101, "receipt"),
    receipt: {
      schemaVersion: 2,
      format: "backup-v2",
      captureId: request.captureId,
      root: link(point),
      verifiedAtUtc: END,
      recipientSha256: H,
      recipientFingerprint: request.recipientFingerprint,
      verifierRevision: request.sourceRevision,
      configurationSha256: H,
      tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4.9" },
      archives: BACKUP_V2_ROLES.map((role) => ({
        role,
        format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
        ciphertextBytes: 1,
        ciphertextSha256: H,
        compressedBytes: 1,
        compressedSha256: H,
        inventory: role === "recovery" ? null : inventory,
        inputComplete: true,
        integrityChecked: true,
        decompressionComplete: true,
        gpgExitCode: 0,
        zstdExitCode: 0,
        tarExitCode: 0,
      })),
      bootSamples: BACKUP_V2_BOOT_SAMPLES.map((sample) => ({
        ...sample,
        bytes: 1,
        sha256: H,
      })),
      metadataSha256: H,
      sourceIndependent: true,
      decryptedRestoreProved: true,
      machineBootRestoreProved: false,
    },
  };
}
function legacy(point: number) {
  const index = {
    schemaVersion: 1,
    generation: capture(point),
    captureStartedAtUtc: START,
    captureFinishedAtUtc: END,
    uploadStartedAtUtc: END,
    uploadFinishedAtUtc: "2026-10-18T04:01:01.000Z",
    consistency: "live-file-copy",
    sourceShutdown: false,
    recipientFingerprint: "A".repeat(40),
    recipientSha256: H,
    archives: BACKUP_V2_ROLES.map((role) => ({
      role,
      format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
      bytes: 1,
      sha256: H,
      chunks: [{
        index: 0,
        name: generationChunkName(capture(point), role, 0),
        size: 1,
        sha256: H,
        sha1: "1".repeat(40),
        fileId: `legacy-${point}-${role}`,
        uploadTimestamp: 1,
      }],
    })),
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  const indexSha256 = createHash("sha256").update(JSON.stringify(index)).digest(
    "hex",
  );
  return {
    schemaVersion: 1,
    format: "backup-v1",
    entry: {
      index,
      publishedIndex: {
        generation: index.generation,
        object: {
          fileId: `index-${point}`,
          fileName: `restic/direct-v1/indexes/${capture(point)}/index.json.gpg`,
          contentLength: 1,
          contentSha1: "1".repeat(40),
          action: "upload",
          uploadTimestamp: 1,
        },
        ciphertextBytes: 1,
        ciphertextSha256: H,
        indexSha256,
        uploadVerified: true,
        decryptedRestoreProved: false,
        machineBootRestoreProved: false,
      },
      acceptedAtUtc: accepted(point),
      receipt: {
        schemaVersion: 1,
        generation: index.generation,
        indexSha256,
        recipientFingerprint: index.recipientFingerprint,
        recipientSha256: H,
        verifiedAtUtc: END,
        archives: BACKUP_V2_ROLES.map((role) => ({
          role,
          format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
          ciphertextBytes: 1,
          ciphertextSha256: H,
          compressedBytes: 1,
          compressedSha256: H,
          ...(role === "recovery" ? {} : { entries: 1 }),
        })),
        metadataSha256: H,
        bootSamples: BACKUP_V2_BOOT_SAMPLES.map((sample) => ({
          ...sample,
          bytes: 1,
          sha256: H,
        })),
        decryptedRestoreProved: true,
        machineBootRestoreProved: false,
      },
    },
  };
}

const NOW = "2026-11-18T19:00:00.000Z";
const CUTOFF = Date.parse(NOW) - 72 * 3_600_000;
const listed = ({ sha256: _sha256, ...value }: BackupV2ObjectRef) => value;

function fixture() {
  const shared = object(1),
    exclusive = object(1, "data", 1),
    page = object(1, "manifest", 20),
    unattached = object(1, "tools", 99);
  const graph = new Map([
    [link(1).object.fileId, [shared, exclusive, page]],
    [link(5).object.fileId, [shared]],
  ]);
  const cloud = new Map<string, BackupV2ListedVersion>();
  const put = (version: BackupV2ListedVersion) =>
    cloud.set(version.fileId, version);
  for (
    const ref of [
      shared,
      exclusive,
      page,
      unattached,
      link(1).object,
      link(1, 101, "receipt").object,
      link(5).object,
      link(5, 101, "receipt").object,
    ]
  ) put(listed(ref));
  for (const entry of [legacy(2), legacy(3), legacy(4)]) {
    put({ ...entry.entry.publishedIndex.object, action: "upload" });
    for (const archive of entry.entry.index.archives) {
      for (const chunk of archive.chunks) {
        put({
          fileId: chunk.fileId,
          fileName: chunk.name,
          contentLength: chunk.size,
          contentSha1: chunk.sha1,
          uploadTimestamp: chunk.uploadTimestamp,
          action: "upload",
        });
      }
    }
  }
  put({ ...listed(object(8)), fileName: "foreign/file", contentLength: 100 });
  const snapshot: BackupV2RetentionSnapshot = {
    custody: { lockId: "retention", sourceBootId: A, sourceSettled: true },
    catalog: [v2(1), legacy(2), legacy(3), legacy(4), v2(5)],
    protection: empty(),
    receipts: [],
    jobs: [],
    policy: { ...DEFAULT_BACKUP_V2_RETENTION_POLICY, execute: true },
    plannedAtUtc: NOW,
  };
  const parts = new Map<string, BackupV2RetentionPart[]>();
  const trace: (string | undefined)[] = [];
  const reader: BackupV2RetentionReader = {
    validateLegacy: validateCatalogEntry,
    references: (root) => {
      const refs = graph.get(root.object.fileId);
      if (!refs) throw Error("Unreadable root");
      return Promise.resolve(structuredClone(refs));
    },
    roleReferences: () => Promise.resolve([exclusive]),
    bucketVersionsPage(_cursor, prefix) {
      trace.push(prefix);
      return Promise.resolve({
        items: [...cloud.values()].filter((ref) =>
          !prefix || ref.fileName.startsWith(prefix)
        ),
        next: null,
      });
    },
    unfinishedFilesPage(_cursor, prefix) {
      return Promise.resolve({
        items: [...cloud.values()].filter((
          ref,
        ): ref is Extract<BackupV2ListedVersion, { action: "start" }> =>
          ref.action === "start" && (!prefix || ref.fileName.startsWith(prefix))
        ),
        next: null,
      });
    },
    unfinishedPartsPage: (fileId) =>
      Promise.resolve({ items: parts.get(fileId) ?? [], next: null }),
  };
  const journal: BackupV2RetentionJournalEntry[] = [];
  const removed: string[] = [], events: string[] = [];
  const caps: BackupV2RetentionExecution = {
    reader,
    now: () => new Date(NOW),
    observeFresh: () => Promise.resolve(snapshot),
    loadJournal: () => Promise.resolve(structuredClone(journal)),
    appendDurable: (entry) => {
      journal.push(structuredClone(entry));
      events.push(entry.state);
      return Promise.resolve();
    },
    removeExact: (ref) => {
      assert(cloud.has(ref.fileId));
      cloud.delete(ref.fileId);
      removed.push(ref.fileId);
      events.push("DELETE");
      return Promise.resolve();
    },
  };
  return {
    snapshot,
    reader,
    cloud,
    put,
    graph,
    shared,
    exclusive,
    page,
    unattached,
    journal,
    removed,
    events,
    caps,
    parts,
    trace,
    plan: () => planBackupV2Retention(snapshot, reader),
  };
}

Deno.test("retention selects newest two mixed-format accepted generations and keeps shared exact references", async () => {
  const f = fixture(), plan = await f.plan();
  assert(
    plan.dryRun &&
      plan.retainedCaptureIds.join() === [capture(5), capture(4)].join(),
  );
  assert(
    plan.retiredCaptureIds.length === 3 &&
      plan.obsoleteLegacyCaptureIds.length === 2,
  );
  assert(plan.candidates.length === 20 && plan.summary.bucketBytes === 132);
  assert(
    plan.candidates.every(({ object }) =>
      ![f.shared.fileId, f.unattached.fileId].includes(object.fileId)
    ),
  );
  const versions = [...f.cloud.values()].reverse();
  f.cloud.clear();
  for (const version of versions) f.put(version);
  assert((await f.plan()).digest === plan.digest);
  f.snapshot.catalog = [v2(5)];
  assert((await f.plan()).retainedCaptureIds.join() === capture(5));
  f.snapshot.catalog = [];
  assert((await f.plan()).summary.blockReason === "NO_ACCEPTED_GENERATION");
});

Deno.test("retention protects unsettled jobs, explicit active references and unknown v2 names", async () => {
  const f = fixture(), protection = empty();
  protection.activeObjects.push(f.exclusive);
  protection.sealedRoleManifests.push({ object: f.page, plaintextSha256: H });
  f.snapshot.protection = protection;
  f.snapshot.jobs = [{ captureId: capture(6), custody: "PROTECTED" }];
  f.put(listed(object(6)));
  f.put(listed(object(7)));
  const plan = await f.plan();
  assert(plan.retiredCaptureIds.length === 0 && plan.candidates.length === 0);
  assert(plan.retainedCaptureIds.length === 5);
  assert(plan.summary.categories.PROTECTED.objects >= 2);
});

Deno.test("whole-bucket retention plans old orphan classes and includes paged multipart bytes", async () => {
  const f = fixture();
  f.snapshot.policy.keepAccepted = 5;
  f.snapshot.jobs = [
    { captureId: capture(6), custody: "SETTLED_UNACCEPTED" },
    {
      captureId: capture(7),
      custody: "SETTLED_UNACCEPTED",
      format: "backup-v1",
      evidenceSha256: H,
    },
  ];
  const candidate = { ...listed(object(6)), uploadTimestamp: CUTOFF };
  f.put(candidate);
  f.put({ ...candidate, fileId: "noncurrent", uploadTimestamp: CUTOFF - 2 });
  f.put({
    ...candidate,
    fileId: "young",
    fileName: object(6, "data", 1).fileName,
    uploadTimestamp: CUTOFF + 1,
  });
  const hideName = object(6, "data", 2).fileName;
  f.put({
    ...candidate,
    fileId: "hidden",
    fileName: hideName,
    uploadTimestamp: CUTOFF - 1,
  });
  f.put({
    fileId: "hide",
    fileName: hideName,
    contentLength: 0,
    contentSha1: "",
    action: "hide",
    uploadTimestamp: CUTOFF,
  });
  const start = {
    fileId: "start",
    fileName: object(6, "data", 3).fileName,
    contentLength: 0,
    contentSha1: "",
    action: "start" as const,
    uploadTimestamp: 1,
  };
  f.put(start);
  f.reader.unfinishedPartsPage = (fileId, cursor) => {
    const part = (partNumber: number) => ({
      fileId,
      partNumber,
      contentLength: 10,
      contentSha1: "1".repeat(40),
      uploadTimestamp: fileId === "part-young" ? CUTOFF + 1 : CUTOFF,
    });
    return Promise.resolve(
      cursor === null
        ? { items: [part(1)], next: 2 }
        : { items: [part(2)], next: null },
    );
  };
  f.put({
    ...start,
    fileId: "part-young",
    fileName: object(6, "data", 4).fileName,
  });
  f.put({
    ...candidate,
    fileId: "legacy",
    fileName: generationChunkName(capture(7), "root", 0),
  });
  f.snapshot.retiredRestic = {
    prefix: "restic/old-repo/",
    evidenceSha256: H,
    retiredAtUtc: END,
  };
  f.put({ ...candidate, fileId: "restic", fileName: "restic/old-repo/config" });
  f.put({
    ...candidate,
    fileId: "unknown-layout",
    fileName: "restic/unowned/config",
  });
  const plan = await f.plan();
  const planned = new Map(
    plan.candidates.map(({ object, reason }) => [object.fileId, reason]),
  );
  assert(planned.get(candidate.fileId) === "UNACCEPTED_V2");
  assert(planned.get("noncurrent") === "NONCURRENT_VERSION");
  assert(
    planned.get("hide") === "HIDE_MARKER" &&
      planned.get("hidden") === "NONCURRENT_VERSION",
  );
  assert(planned.get("start") === "UNFINISHED_LARGE_FILE");
  assert(
    !planned.has("young") && !planned.has("part-young") &&
      !planned.has("legacy") && !planned.has("restic"),
  );
  assert(plan.summary.categories.UNFINISHED_LARGE_FILE.bytes === 40);
  assert(plan.summary.categories.LEGACY_ORPHAN.objects === 2);
  assert(plan.summary.bucketBytes === 179);
  f.snapshot.policy.cleanLegacyOrphans = true;
  const enabled = await f.plan();
  assert(enabled.candidates.some(({ object }) => object.fileId === "legacy"));
  assert(enabled.candidates.some(({ object }) => object.fileId === "restic"));
  assert(
    !enabled.candidates.some(({ object }) =>
      object.fileId === "unknown-layout"
    ),
  );
});

Deno.test("retention keeps a hide marker when planned upload deletion would reveal a protected older version", async () => {
  const f = fixture(), shared = { ...f.shared, fileName: object(6).fileName };
  f.graph.set(link(1).object.fileId, [shared, f.exclusive, f.page]);
  f.graph.set(link(5).object.fileId, [shared]);
  f.put(listed(shared));
  f.snapshot.jobs = [{ captureId: capture(6), custody: "SETTLED_UNACCEPTED" }];
  f.put({
    fileId: "hide",
    fileName: shared.fileName,
    contentLength: 0,
    contentSha1: "",
    action: "hide",
    uploadTimestamp: 2,
  });
  f.put({ ...listed(shared), fileId: "current", uploadTimestamp: 3 });
  const plan = await f.plan();
  assert(plan.candidates.some(({ object }) => object.fileId === "current"));
  assert(!plan.candidates.some(({ object }) => object.fileId === "hide"));
});

Deno.test("metadata damage preserves older intact points and verify-catalog reads only accepted names", async () => {
  const f = fixture();
  f.cloud.delete(link(5).object.fileId);
  const legacyChunk = f.cloud.get("legacy-4-root")!;
  f.put({ ...legacyChunk, contentSha1: "9".repeat(40) });
  let plan = await f.plan();
  assert(plan.summary.blockReason === "DAMAGED_ACCEPTED_GENERATION");
  assert(
    plan.summary.damagedCaptureIds.join() === [capture(4), capture(5)].join(),
  );
  assert(
    plan.summary.keptGenerations === 3 && plan.retiredCaptureIds.length === 0,
  );
  const result = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(result.status === "PARTIAL" && f.removed.length === 0);
  f.trace.length = 0;
  f.snapshot.verifyCatalogOnly = true;
  f.snapshot.policy.execute = false;
  f.reader.unfinishedFilesPage = () =>
    Promise.reject(Error("unexpected orphan query"));
  plan = await f.plan();
  assert(
    plan.verifyCatalogOnly && plan.candidates.length === 0 &&
      f.trace.every(Boolean),
  );
  assert(plan.summary.damagedCaptureIds.length === 2);
});

Deno.test("retention reports new accepted damage between irreversible older capture boundaries", async () => {
  const f = fixture(), plan = await f.plan(), remove = f.caps.removeExact;
  f.caps.removeExact = async (object) => {
    await remove(object);
    if (f.removed.length === 1) f.cloud.delete(link(5).object.fileId);
  };
  const result = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(result.summary.blockReason === "DAMAGED_ACCEPTED_GENERATION");
  assert(result.summary.damagedCaptureIds.join() === capture(5));
  assert(
    result.retainedCaptureIds.includes(capture(4)) &&
      result.retainedCaptureIds.includes(capture(3)),
  );
  assert(f.cloud.has("legacy-2-root") && f.cloud.has("legacy-3-root"));
});

Deno.test("retention refuses cap overruns, new or changed identities, and altered plan digests", async () => {
  const capped = fixture();
  capped.snapshot.policy.maxDeleteFraction = 0.1;
  const blocked = await capped.plan();
  assert(blocked.summary.blockReason === "CAP_EXCEEDED");
  assert(
    (await executeBackupV2Retention(blocked, blocked.digest, capped.caps))
      .status === "PARTIAL",
  );
  assert(capped.removed.length === 0);
  const f = fixture(), plan = await f.plan(), changed = structuredClone(plan);
  changed.candidates[0].object.contentLength++;
  await rejects(() => executeBackupV2Retention(changed, plan.digest, f.caps));
  f.snapshot.policy.maxDeleteFraction = 1;
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).summary
      .blockReason === "PLAN_CHANGED",
  );
  f.snapshot.policy.maxDeleteFraction = 0.5;
  f.cloud.delete("8-data-0");
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).summary
      .blockReason === "PLAN_CHANGED",
  );
  assert(f.removed.length === 0);
});

Deno.test("retention journals before deletion and recovers a lost response without repeating a wire delete", async () => {
  const f = fixture(), plan = await f.plan(), remove = f.caps.removeExact;
  f.caps.removeExact = async (ref) => {
    await remove(ref);
    throw Error("response lost");
  };
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "PARTIAL",
  );
  assert(f.events.join() === "INTENT,DELETE,AMBIGUOUS");
  f.caps.removeExact = remove;
  const resumed = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    resumed.status === "COMPLETE" &&
      resumed.summary.reconciledAbsentObjects === 1,
  );
  assert(
    f.journal[2].state === "ABSENT" &&
      f.removed.length === plan.candidates.length,
  );
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "COMPLETE",
  );
  assert(f.removed.length === plan.candidates.length);
});

Deno.test("retention treats reviewed orphans already gone before and during DELETE as successful absence", async () => {
  const f = fixture();
  f.snapshot.policy.keepAccepted = 5;
  f.snapshot.jobs = [{ captureId: capture(6), custody: "SETTLED_UNACCEPTED" }];
  const prior = listed(object(6, "data", 1)),
    raced = listed(object(6, "data", 2));
  f.put(prior);
  f.put(raced);
  const plan = await f.plan();
  f.cloud.delete(prior.fileId);
  f.caps.removeExact = (object) => {
    assert(object.fileId === raced.fileId);
    f.cloud.delete(raced.fileId);
    return Promise.reject(Error("file_not_present"));
  };
  const outcome = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    outcome.status === "COMPLETE" &&
      outcome.summary.reconciledAbsentObjects === 2,
  );
  assert(outcome.summary.deletedObjects === 0 && f.journal.length === 3);
});

Deno.test("retention rejects contradictory catalog roots, malformed listing cursor and foreign journal", async () => {
  const f = fixture(), plan = await f.plan();
  f.journal.push({
    planSha256: "0".repeat(64),
    ordinal: 0,
    fileId: plan.candidates[0].object.fileId,
    fileName: plan.candidates[0].object.fileName,
    attempt: 1,
    state: "INTENT",
  });
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "PARTIAL",
  );
  f.reader.bucketVersionsPage = () =>
    Promise.resolve({
      items: [],
      next: { fileName: f.shared.fileName, fileId: f.shared.fileId },
    });
  await rejects(f.plan);
  f.graph.get(link(1).object.fileId)!.push({
    ...f.shared,
    sha256: "f".repeat(64),
  });
  await rejects(f.plan);
  await rejects(() =>
    planBackupV2Retention({ ...f.snapshot, catalog: [v2(5), v2(5)] }, f.reader)
  );
  await rejects(() =>
    planBackupV2Retention({
      ...f.snapshot,
      custody: { ...f.snapshot.custody, sourceSettled: false as true },
    }, f.reader)
  );
  assert(f.removed.length === 0);
});

Deno.test("retention rechecks custody after intent and resumes a never-sent request through fresh presence", async () => {
  const f = fixture(), plan = await f.plan(), append = f.caps.appendDurable;
  f.caps.appendDurable = async (entry) => {
    await append(entry);
    if (entry.state === "INTENT") {
      f.snapshot.protection = { ...empty(), activeObjects: [f.exclusive] };
    }
  };
  const blocked = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(blocked.summary.blockReason === "PLAN_CHANGED");
  assert(f.journal[0].state === "INTENT" && f.removed.length === 0);
  f.caps.signal = AbortSignal.abort();
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "PARTIAL",
  );
  assert(f.removed.length === 0);
  f.caps.signal = undefined;
  f.snapshot.protection = empty();
  f.caps.appendDurable = append;
  const resumed = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(resumed.status === "COMPLETE");
  assert(f.journal[1].state === "PRESENT" && f.journal[2].attempt === 2);
});

Deno.test("retention resumes a missing post-wire result record and a transport failure with a still-present exact version", async () => {
  const f = fixture(), plan = await f.plan(), append = f.caps.appendDurable;
  f.caps.appendDurable = (entry) =>
    entry.state === "DELETED"
      ? Promise.reject(Error("result fsync failed"))
      : append(entry);
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "PARTIAL",
  );
  assert(f.journal[0].state === "INTENT" && f.removed.length === 1);
  f.caps.appendDurable = append;
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "COMPLETE",
  );
  assert(
    f.journal[1].state === "ABSENT" &&
      f.removed.length === plan.candidates.length,
  );
  const g = fixture(), separate = await g.plan(), remove = g.caps.removeExact;
  g.caps.removeExact = () => Promise.reject(Error("no response"));
  assert(
    (await executeBackupV2Retention(separate, separate.digest, g.caps))
      .status === "PARTIAL",
  );
  assert(g.journal[1].state === "AMBIGUOUS" && g.removed.length === 0);
  g.caps.removeExact = remove;
  assert(
    (await executeBackupV2Retention(separate, separate.digest, g.caps))
      .status === "COMPLETE",
  );
  assert(g.journal[2].state === "PRESENT" && g.journal[3].attempt === 2);
});

Deno.test("retention recensus settles a multipart orphan cancelled during its own parts listing", async () => {
  const f = fixture();
  f.snapshot.policy.keepAccepted = 5;
  f.snapshot.jobs = [{ captureId: capture(6), custody: "SETTLED_UNACCEPTED" }];
  const start = {
    fileId: "multipart-race",
    fileName: object(6).fileName,
    contentLength: 0,
    contentSha1: "",
    action: "start" as const,
    uploadTimestamp: 1,
  };
  f.put(start);
  const plan = await f.plan(), list = f.reader.unfinishedPartsPage;
  let reads = 0;
  f.reader.unfinishedPartsPage = (fileId, cursor) => {
    if (++reads === 2) {
      f.cloud.delete(fileId);
      return Promise.reject(Error("file_not_present"));
    }
    return list(fileId, cursor);
  };
  const outcome = await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    outcome.status === "COMPLETE" &&
      outcome.summary.reconciledAbsentObjects === 1,
  );
  assert(f.removed.length === 0);
});

Deno.test("retention follows opaque unfinished continuations and gaps in version and part cursors", async () => {
  const f = fixture();
  f.snapshot.policy.keepAccepted = 5;
  f.snapshot.jobs = [{ captureId: capture(6), custody: "SETTLED_UNACCEPTED" }];
  const fileId = "unfinished-id";
  const start = {
    fileId,
    fileName: object(6).fileName,
    action: "start" as const,
    uploadTimestamp: 1,
    contentLength: 0,
    contentSha1: "",
  };
  f.reader.bucketVersionsPage = (cursor) =>
    Promise.resolve(
      cursor === null
        ? {
          items: [],
          next: {
            fileName: "foreign/removed-before-next-page",
            fileId: "missing",
          },
        }
        : { items: [...f.cloud.values(), start], next: null },
    );
  f.reader.unfinishedFilesPage = (cursor) =>
    Promise.resolve(
      cursor === null
        ? { items: [], next: "opaque-continuation" }
        : { items: [start], next: null },
    );
  f.reader.unfinishedPartsPage = (id, cursor) =>
    Promise.resolve(
      cursor === null ? { items: [], next: 2 } : {
        items: [{
          fileId: id,
          partNumber: 3,
          contentLength: 10,
          contentSha1: "1".repeat(40),
          uploadTimestamp: 1,
        }],
        next: null,
      },
    );
  const plan = await f.plan();
  assert(plan.summary.bucketBytes === 142);
  assert(plan.candidates.some(({ object }) =>
    object.fileId === fileId &&
    object.action === "start" && object.contentLength === 10
  ));
  f.reader.unfinishedFilesPage = () =>
    Promise.resolve({ items: [], next: "repeated-token" });
  await rejects(f.plan);
});
