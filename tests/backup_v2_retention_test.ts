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
  executeBackupV2Retention,
  planBackupV2Retention,
} from "../scripts/backup-v2-retention.ts";
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
function fixture() {
  const shared = object(1),
    exclusive = object(1, "data", 1),
    page = object(1, "manifest", 20),
    orphan = object(1, "tools", 99);
  const graph = new Map([[link(1).object.fileId, [shared, exclusive, page]], [
    link(5).object.fileId,
    [shared],
  ]]);
  const cloud = new Map(
    [
      shared,
      exclusive,
      page,
      orphan,
      link(1).object,
      link(1, 101, "receipt").object,
      link(5).object,
      link(5, 101, "receipt").object,
    ].map((ref) => [ref.fileId, ref]),
  );
  const snapshot: BackupV2RetentionSnapshot = {
    custody: {
      lockId: "retention-transaction-1",
      sourceBootId: A,
      sourceSettled: true,
    },
    catalog: [v2(1), legacy(2), legacy(3), legacy(4), v2(5)],
    protection: empty(),
    receipts: [],
  };
  const reader: BackupV2RetentionReader = {
    validateLegacy: validateCatalogEntry,
    references: (root) => {
      const refs = graph.get(root.object.fileId);
      if (!refs) throw Error("Unreadable root");
      return Promise.resolve(structuredClone(refs));
    },
    roleReferences: () => Promise.resolve([exclusive]),
    versionsPage: () =>
      Promise.resolve({
        items: [...cloud.values()].map(({ sha256: _sha, ...ref }) => ref),
        next: null,
      }),
  };
  const journal: BackupV2RetentionJournalEntry[] = [],
    removed: string[] = [],
    events: string[] = [];
  const caps: BackupV2RetentionExecution = {
    reader,
    observeFresh: () => Promise.resolve(snapshot),
    loadJournal: () => Promise.resolve(structuredClone(journal)),
    appendDurable: (entry) => {
      journal.push(structuredClone(entry));
      events.push(entry.state);
      return Promise.resolve();
    },
    reconcileExact: (ref) =>
      Promise.resolve(cloud.has(ref.fileId) ? "present" : "absent"),
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
    graph,
    shared,
    exclusive,
    page,
    orphan,
    journal,
    removed,
    events,
    caps,
  };
}

Deno.test("retention plan binds mixed accepted roots and shared references, ignoring unattached inventory", async () => {
  const f = fixture(), plan = await planBackupV2Retention(f.snapshot, f.reader);
  assert(
    plan.dryRun && plan.retainedCaptureIds.length === 4 &&
      plan.candidates.length === 4,
  );
  assert(
    !plan.candidates.some((ref) =>
      [f.shared.fileId, f.orphan.fileId].includes(ref.fileId)
    ),
  );
  f.snapshot.catalog = [...f.snapshot.catalog].reverse();
  f.reader.versionsPage = () =>
    Promise.resolve({
      items: [...f.cloud.values()].reverse().map(({ sha256: _sha, ...ref }) =>
        ref
      ),
      next: null,
    });
  assert(
    (await planBackupV2Retention(f.snapshot, f.reader)).digest === plan.digest,
  );
  f.snapshot.catalog = [legacy(1), legacy(2), legacy(3), legacy(4), v2(5)];
  const legacyPlan = await planBackupV2Retention(f.snapshot, f.reader);
  assert(
    legacyPlan.candidates.length === 0 &&
      legacyPlan.obsoleteLegacyCaptureIds[0] === capture(1),
  );
});
Deno.test("retention protects reusable roles active objects unresolved PUT names and receipt references", async () => {
  const f = fixture(), protection = empty();
  protection.activeObjects.push(f.exclusive);
  protection.sealedRoleManifests.push({ object: f.page, plaintextSha256: H });
  const pending = link(1, 101, "receipt").object;
  protection.unresolvedPuts.push({
    captureId: C,
    attemptId: A,
    role: "root",
    kind: "receipt",
    ordinal: 101,
    offset: 0,
    putId: P,
    createdAtUtc: START,
    name: pending.fileName,
    slot: {
      index: 0,
      path: "/var/tmp/fixture/slot-0",
      device: 1,
      inode: 2,
      bytes: 1,
      sha1: "1".repeat(40),
      sha256: H,
      uid: 0,
      mode: 384,
      links: 1,
    },
  });
  f.snapshot.protection = protection;
  const plan = await planBackupV2Retention(f.snapshot, f.reader);
  assert(
    plan.candidates.length === 1 &&
      plan.candidates[0].fileId === link(1).object.fileId,
  );
});
Deno.test("retention rejects fewer than four unique roots unknown formats and unsettled custody", async () => {
  const f = fixture();
  f.snapshot.catalog = [legacy(2), legacy(3), v2(5)];
  await rejects(() => planBackupV2Retention(f.snapshot, f.reader));
  f.snapshot.catalog = [legacy(2), legacy(3), v2(5), v2(5)];
  await rejects(() => planBackupV2Retention(f.snapshot, f.reader));
  f.snapshot.catalog = [legacy(2), legacy(3), v2(5), {
    schemaVersion: 3,
    format: "backup-v3",
  }];
  await rejects(() => planBackupV2Retention(f.snapshot, f.reader));
  const g = fixture();
  g.snapshot.custody.sourceSettled = false as true;
  await rejects(() => planBackupV2Retention(g.snapshot, g.reader));
});
Deno.test("retention rejects incomplete inventory unreadable graphs conflicting identities and nonterminal pagination", async () => {
  const f = fixture();
  f.cloud.delete(f.shared.fileId);
  await rejects(() => planBackupV2Retention(f.snapshot, f.reader));
  const g = fixture();
  g.graph.delete(link(5).object.fileId);
  await rejects(() => planBackupV2Retention(g.snapshot, g.reader));
  const h = fixture();
  h.graph.get(link(1).object.fileId)!.push({
    ...h.shared,
    sha256: "f".repeat(64),
  });
  await rejects(() => planBackupV2Retention(h.snapshot, h.reader));
  const i = fixture();
  i.reader.versionsPage = () =>
    Promise.resolve({
      items: [],
      next: { fileName: i.shared.fileName, fileId: i.shared.fileId },
    });
  await rejects(() => planBackupV2Retention(i.snapshot, i.reader));
  const hidden = fixture();
  hidden.reader.versionsPage = () =>
    Promise.resolve({
      items: [{
        fileId: hidden.shared.fileId,
        fileName: hidden.shared.fileName,
        contentLength: 0,
        contentSha1: "",
        uploadTimestamp: 1,
        action: "hide",
      }],
      next: null,
    });
  await rejects(() => planBackupV2Retention(hidden.snapshot, hidden.reader));
  i.reader.versionsPage = () =>
    Promise.resolve({
      items: Array.from({ length: 101 }, () => {
        const { sha256: _sha, ...ref } = i.shared;
        return ref;
      }),
      next: null,
    });
  await rejects(() => planBackupV2Retention(i.snapshot, i.reader));
});
Deno.test("retention exact execution persists intent before deletion and resumes completed journals without another wire", async () => {
  const f = fixture(), plan = await planBackupV2Retention(f.snapshot, f.reader);
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "COMPLETE",
  );
  assert(
    f.removed.length === plan.candidates.length &&
      f.cloud.has(f.shared.fileId) && f.cloud.has(f.orphan.fileId),
  );
  for (let i = 0; i < f.events.length; i += 3) {
    assert(f.events.slice(i, i + 3).join() === "INTENT,DELETE,DELETED");
  }
  const records = f.journal.length;
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "COMPLETE",
  );
  assert(
    f.journal.length === records && f.removed.length === plan.candidates.length,
  );
});
Deno.test("retention refuses digest mutation and changed graph or custody before any delete", async () => {
  const f = fixture(), plan = await planBackupV2Retention(f.snapshot, f.reader);
  await rejects(() => executeBackupV2Retention(plan, "0".repeat(64), f.caps));
  const changed = structuredClone(plan);
  changed.candidates[0].sha256 = "f".repeat(64);
  await rejects(() => executeBackupV2Retention(changed, plan.digest, f.caps));
  f.snapshot.protection = { ...empty(), activeObjects: [f.exclusive] };
  await rejects(() => executeBackupV2Retention(plan, plan.digest, f.caps));
  f.snapshot.protection = empty();
  f.snapshot.custody.lockId = "different-custody";
  await rejects(() => executeBackupV2Retention(plan, plan.digest, f.caps));
  assert(f.removed.length === 0);
});
Deno.test("retention rechecks protection after durable intent and recovers a never-sent intent by exact presence", async () => {
  const f = fixture(),
    plan = await planBackupV2Retention(f.snapshot, f.reader),
    append = f.caps.appendDurable;
  f.caps.appendDurable = async (entry) => {
    await append(entry);
    if (entry.state === "INTENT") {
      f.snapshot.protection = {
        ...empty(),
        activeObjects: [plan.candidates[0]],
      };
    }
  };
  await rejects(() => executeBackupV2Retention(plan, plan.digest, f.caps));
  assert(f.removed.length === 0 && f.journal[0].state === "INTENT");
  f.snapshot.protection = empty();
  f.caps.appendDurable = append;
  await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    f.journal[1].state === "PRESENT" && f.journal[2].attempt === 2 &&
      f.removed.length === plan.candidates.length,
  );
});
Deno.test("retention reconciles a lost delete response as absent without blindly deleting again", async () => {
  const f = fixture(),
    plan = await planBackupV2Retention(f.snapshot, f.reader),
    remove = f.caps.removeExact;
  f.caps.removeExact = async (ref) => {
    await remove(ref);
    throw Error("response lost");
  };
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
      "AMBIGUOUS",
  );
  assert(f.removed.length === 1);
  f.caps.removeExact = remove;
  await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    f.journal[2].state === "ABSENT" &&
      f.removed.length === plan.candidates.length,
  );
});
Deno.test("retention leaves unknown outcomes blocked, then permits a fresh exact-presence retry", async () => {
  const f = fixture(),
    plan = await planBackupV2Retention(f.snapshot, f.reader),
    remove = f.caps.removeExact,
    reconcile = f.caps.reconcileExact;
  f.caps.removeExact = () => Promise.reject(Error("ambiguous before response"));
  await executeBackupV2Retention(plan, plan.digest, f.caps);
  f.caps.reconcileExact = () => Promise.resolve("unknown");
  assert(
    (await executeBackupV2Retention(plan, plan.digest, f.caps)).status ===
        "AMBIGUOUS" && f.removed.length === 0,
  );
  f.caps.removeExact = remove;
  f.caps.reconcileExact = reconcile;
  await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    f.journal[2].state === "PRESENT" && f.journal[3].attempt === 2 &&
      f.removed.length === plan.candidates.length,
  );
});
Deno.test("retention result fsync failure recovers from durable intent and rejects foreign journals or cancellation", async () => {
  const f = fixture(),
    plan = await planBackupV2Retention(f.snapshot, f.reader),
    append = f.caps.appendDurable;
  f.caps.appendDurable = (entry) =>
    entry.state === "DELETED"
      ? Promise.reject(Error("result fsync failed"))
      : append(entry);
  await rejects(() => executeBackupV2Retention(plan, plan.digest, f.caps));
  assert(f.removed.length === 1 && f.journal[0].state === "INTENT");
  f.caps.appendDurable = append;
  await executeBackupV2Retention(plan, plan.digest, f.caps);
  assert(
    f.journal[1].state === "ABSENT" &&
      f.removed.length === plan.candidates.length,
  );
  const g = fixture(),
    gplan = await planBackupV2Retention(g.snapshot, g.reader);
  g.journal.push({
    planSha256: "0".repeat(64),
    ordinal: 0,
    fileId: gplan.candidates[0].fileId,
    fileName: gplan.candidates[0].fileName,
    attempt: 1,
    state: "INTENT",
  });
  await rejects(() => executeBackupV2Retention(gplan, gplan.digest, g.caps));
  g.journal.length = 0;
  for (const state of ["INTENT", "DELETED"] as const) {
    g.journal.push({
      planSha256: gplan.digest,
      ordinal: "0" as unknown as number,
      fileId: gplan.candidates[0].fileId,
      fileName: gplan.candidates[0].fileName,
      attempt: 1,
      state,
    });
  }
  await rejects(() => executeBackupV2Retention(gplan, gplan.digest, g.caps));
  g.journal.length = 0;
  g.caps.signal = AbortSignal.abort();
  await rejects(() => executeBackupV2Retention(gplan, gplan.digest, g.caps));
  assert(g.removed.length === 0);
});
