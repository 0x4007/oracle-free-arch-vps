import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { validateCatalogEntry } from "../scripts/backblaze-file-backup.ts";
import { generationChunkName } from "../scripts/backblaze-upload.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ManifestRef,
  backupV2ObjectName,
  type BackupV2ObjectRef,
} from "../scripts/backup-v2-contract.ts";
import { createBackupV2InventorySummary } from "../scripts/backup-v2-inventory.ts";
import {
  BACKUP_V2_NAMESPACE,
  BACKUP_V2_PROFILE_ID,
} from "../scripts/backup-v2-profile.ts";
import {
  type BackupV2ProtectionBundle,
  type BackupV2PruneInput,
  buildBackupV2Protection,
} from "../scripts/backup-v2-protection.ts";
import type { BackupV2RetentionJournalEntry } from "../scripts/backup-v2-retention.ts";
import {
  type BackupV2CatalogEntry,
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2CatalogEntry,
  validateBackupV2Gate,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  type BackupV2SourcePrunerCapabilities,
  runBackupV2SourcePruner,
} from "../scripts/backup-v2-source-pruner.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(run: () => unknown) {
  let rejected = false;
  try {
    await run();
  } catch {
    rejected = true;
  }
  assert(rejected);
}
const H = "a".repeat(64),
  REV = "b".repeat(40),
  START = "2026-10-18T01:00:00.000Z",
  END = "2026-10-18T01:01:00.000Z";
const id = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const capture = (n: number) => `generation-${id(n)}`;
const accepted = (n: number) => `2026-10-18T01:0${n}:00.000Z`;
const encode = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value) + "\n");
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
function object(
  n: number,
  ordinal: number,
  kind: "manifest" | "data" | "receipt" | "tools" = "data",
): BackupV2ObjectRef {
  return {
    fileId: `${n}-${kind}-${ordinal}`,
    fileName: backupV2ObjectName(capture(n), id(20), kind, ordinal, id(30)),
    contentLength: 1,
    contentSha1: "c".repeat(40),
    uploadTimestamp: 1,
    sha256: H,
    action: "upload",
  };
}
const reference = (
  n: number,
  ordinal = 100,
  kind: "manifest" | "receipt" = "manifest",
): BackupV2ManifestRef => ({
  object: object(n, ordinal, kind),
  plaintextSha256: H,
});
function catalog(n: number): BackupV2CatalogEntry {
  const request: BackupV2Request = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    jobId: `job-${id(n)}`,
    captureId: capture(n),
    periodKey: "2026-10-18",
    requestedAtUtc: START,
    sourceRevision: REV,
    sourceConfigSha256: H,
    recipientSha256: H,
    recipientFingerprint: "A".repeat(40),
  };
  const summary = createBackupV2InventorySummary();
  summary.add({ path: new TextEncoder().encode("./etc/os-release") });
  const inventory = summary.finish();
  return validateBackupV2CatalogEntry({
    schemaVersion: 2,
    format: "backup-v2",
    envelope: { request, requestSha256: backupV2RequestSha256(request) },
    resultSha256: H,
    selectedRoot: {
      reference: reference(n),
      root: {
        schemaVersion: 2,
        format: "backup-v2",
        profile: request.profile,
        captureId: request.captureId,
        periodKey: request.periodKey,
        sourceRevision: REV,
        sourceConfigSha256: H,
        recipientSha256: H,
        recipientFingerprint: request.recipientFingerprint,
        roles: BACKUP_V2_ROLES.map((role, ordinal) => ({
          role,
          attemptId: id(20),
          manifest: reference(n, ordinal),
          captureStartedAtUtc: START,
          captureFinishedAtUtc: END,
        })),
        metadata: [],
      },
    },
    receiptReference: reference(n, 101, "receipt"),
    acceptedAtUtc: accepted(n),
    receipt: {
      schemaVersion: 2,
      format: "backup-v2",
      captureId: request.captureId,
      root: reference(n),
      verifiedAtUtc: END,
      recipientSha256: H,
      recipientFingerprint: request.recipientFingerprint,
      verifierRevision: REV,
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
  });
}
function legacy(n: number) {
  const index = {
    schemaVersion: 1,
    generation: capture(n),
    captureStartedAtUtc: START,
    captureFinishedAtUtc: END,
    uploadStartedAtUtc: END,
    uploadFinishedAtUtc: "2026-10-18T01:01:01.000Z",
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
        name: generationChunkName(capture(n), role, 0),
        size: 1,
        sha256: H,
        sha1: "c".repeat(40),
        fileId: `legacy-${n}-${role}`,
        uploadTimestamp: 1,
      }],
    })),
    uploadVerified: true,
    decryptedRestoreProved: false,
    machineBootRestoreProved: false,
  };
  const indexSha256 = sha(new TextEncoder().encode(JSON.stringify(index)));
  return {
    schemaVersion: 1 as const,
    format: "backup-v1" as const,
    entry: validateCatalogEntry({
      index,
      acceptedAtUtc: accepted(n),
      publishedIndex: {
        generation: capture(n),
        object: {
          fileId: `index-${n}`,
          fileName: `restic/direct-v1/indexes/${capture(n)}/index.json.gpg`,
          contentLength: 1,
          contentSha1: "c".repeat(40),
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
      receipt: {
        schemaVersion: 1,
        generation: capture(n),
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
    }),
  };
}

function fixture() {
  const entries = [1, 2, 3, 4, 5].map(catalog),
    transactionId = id(77),
    unitName = `arch-vps-b2-v2-prune-${id(5)}-${id(90)}.service`;
  const gate = validateBackupV2Gate({
    schemaVersion: 2,
    format: "backup-v2",
    owner: GATE_OWNER,
    envelope: entries[4].envelope,
    gateId: id(90),
    sourceBootId: id(80),
    kind: "prune",
    unitName,
    custody: {
      unitName,
      invocationId: "d".repeat(32),
      mainPid: 123,
      mainStartTicks: "456",
      cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`,
    },
    state: "ACTIVE",
    remoteHost: GATE_REMOTE_HOST,
    sourceLockPath: GATE_SOURCE_LOCK_PATH,
    createdAtUtc: END,
    updatedAtUtc: END,
  });
  const shared = object(1, 200),
    exclusive = object(1, 201),
    orphan = object(1, 999, "tools"),
    bundles = new Map<string, BackupV2ProtectionBundle>(),
    cloud = new Map<string, BackupV2ObjectRef>();
  for (const entry of entries) {
    const number = entries.indexOf(entry) + 1;
    const bundle = buildBackupV2Protection(entry.selectedRoot.reference, [
      ...entry.selectedRoot.root.roles.map((role) => role.manifest.object),
      ...(number === 1 ? [shared, exclusive] : number === 5 ? [shared] : []),
    ]);
    bundles.set(bundle.descriptor.manifestSha256, bundle);
    for (const page of bundle.pages) {
      for (const ref of page.value.objects) cloud.set(ref.fileId, ref);
    }
    cloud.set(
      entry.receiptReference.object.fileId,
      entry.receiptReference.object,
    );
  }
  cloud.set(orphan.fileId, orphan);
  const input: BackupV2PruneInput = {
    schemaVersion: 2,
    format: "backup-v2-prune",
    gate,
    transactionId,
    stage: "PLAN",
    plan: null,
    snapshot: {
      custody: {
        lockId: transactionId,
        sourceBootId: gate.sourceBootId,
        sourceSettled: true,
      },
      catalog: entries,
      protection: {
        acceptedRoots: [],
        activeObjects: [],
        sealedRoleManifests: [],
        unresolvedPuts: [],
      },
      receipts: [],
    },
    graphs: [...bundles.values()].map((bundle) => bundle.descriptor),
  };
  const plans = new Map<string, Uint8Array>(),
    journal: BackupV2RetentionJournalEntry[] = [],
    progress: number[] = [],
    removed: string[] = [];
  let lists = 0, reads = 0, writes = 0;
  const caps: BackupV2SourcePrunerCapabilities = {
    exactStore: {
      versionsPage(prefix) {
        assert(prefix === BACKUP_V2_NAMESPACE);
        lists++;
        return Promise.resolve({
          items: [...cloud.values()].map(({ sha256: _sha, ...ref }) => ref),
          next: null,
        });
      },
      reconcileExact(ref) {
        const found = cloud.get(ref.fileId);
        if (found && !isDeepStrictEqual(found, ref)) {
          throw Error("Identity drift");
        }
        return Promise.resolve(found ? "PRESENT" : "ABSENT");
      },
      removeExact(ref) {
        assert(cloud.has(ref.fileId));
        cloud.delete(ref.fileId);
        removed.push(ref.fileId);
        return Promise.resolve();
      },
    },
    readGraphManifest(descriptor) {
      reads++;
      const bundle = bundles.get(descriptor.manifestSha256);
      if (!bundle) throw Error("Missing manifest");
      return Promise.resolve(bundle.manifestBytes.slice());
    },
    readGraphPage(descriptor, page) {
      reads++;
      const bundle = bundles.get(descriptor.manifestSha256),
        bytes = bundle?.pages[page.pageIndex]?.bytes;
      if (!bytes) throw Error("Missing page");
      return Promise.resolve(bytes.slice());
    },
    readPlan(tx) {
      const bytes = plans.get(tx);
      if (!bytes) throw Error("Missing plan");
      return Promise.resolve(bytes.slice());
    },
    writePlanDurable(tx, bytes) {
      const old = plans.get(tx);
      if (old && !isDeepStrictEqual(old, bytes)) throw Error("Plan rewrite");
      plans.set(tx, bytes.slice());
      writes++;
      return Promise.resolve();
    },
    loadJournal() {
      return Promise.resolve(structuredClone(journal));
    },
    appendDurable(_tx, entry) {
      journal.push(structuredClone(entry));
      return Promise.resolve();
    },
    observeFresh() {
      return Promise.resolve(structuredClone(input));
    },
    validateLegacy: validateCatalogEntry,
    progress(value) {
      progress.push(value.inventoryMembers);
      return Promise.resolve();
    },
    now: () => new Date("2026-10-18T02:00:00.000Z"),
  };
  const execute = async () => {
    const planned = await runBackupV2SourcePruner(input, caps);
    input.stage = "EXECUTE";
    input.plan = planned.plan;
    return planned;
  };
  return {
    input,
    caps,
    entries,
    bundles,
    cloud,
    shared,
    exclusive,
    orphan,
    plans,
    journal,
    progress,
    removed,
    execute,
    stats: () => ({ lists, reads, writes }),
  };
}

Deno.test("source pruner PLAN verifies complete metadata and persists exact dry-run bytes without deletion", async () => {
  const f = fixture(),
    result = await runBackupV2SourcePruner(f.input, f.caps),
    bytes = f.plans.get(f.input.transactionId)!;
  assert(
    result.state === "PLAN_PROVED" && result.plan.sha256 === sha(bytes) &&
      result.plan.bytes === bytes.length && f.removed.length === 0 &&
      f.journal.length === 0,
  );
  assert(
    f.stats().reads === 10 && f.stats().writes === 1 && f.stats().lists === 1,
  );
  assert(
    f.progress.every((value, index) =>
      index === 0 || value > f.progress[index - 1]
    ),
  );
});
Deno.test("source pruner rejects missing tampered oversized and ambiguous graph documents before provider calls", async () => {
  const f = fixture();
  f.input.graphs.pop();
  await rejects(() => runBackupV2SourcePruner(f.input, f.caps));
  assert(f.stats().lists === 0);
  const g = fixture(), read = g.caps.readGraphPage;
  g.caps.readGraphPage = async (descriptor, page) => {
    const bytes = await read(descriptor, page);
    bytes[0] ^= 1;
    return bytes;
  };
  await rejects(() => runBackupV2SourcePruner(g.input, g.caps));
  assert(g.stats().lists === 0 && g.removed.length === 0);
  const h = fixture();
  h.caps.readGraphManifest = () => Promise.reject(Error("Absent metadata"));
  await rejects(() => runBackupV2SourcePruner(h.input, h.caps));
  const i = fixture();
  i.caps.readGraphPage = (_descriptor, page) =>
    Promise.resolve(new Uint8Array(page.bytes + 1));
  await rejects(() => runBackupV2SourcePruner(i.input, i.caps));
  const j = fixture();
  j.input.graphs.push(j.input.graphs[0]);
  await rejects(() => runBackupV2SourcePruner(j.input, j.caps));
});
Deno.test("source pruner requires root and direct role membership plus descriptors for extra protected roles", async () => {
  const f = fixture(),
    root = f.entries[0].selectedRoot.reference,
    bundle = buildBackupV2Protection(root, [f.exclusive]);
  f.bundles.set(bundle.descriptor.manifestSha256, bundle);
  f.input.graphs[0] = bundle.descriptor;
  await rejects(() => runBackupV2SourcePruner(f.input, f.caps));
  assert(f.stats().lists === 0);
  const g = fixture();
  g.input.snapshot.protection.sealedRoleManifests = [reference(6)];
  await rejects(() => runBackupV2SourcePruner(g.input, g.caps));
  assert(g.stats().lists === 0);
});
Deno.test("source pruner requires real plan readback and exact persisted bytes/digest at EXECUTE", async () => {
  const f = fixture();
  f.caps.writePlanDurable = () => Promise.resolve();
  await rejects(() => runBackupV2SourcePruner(f.input, f.caps));
  const g = fixture();
  await g.execute();
  const bytes = g.plans.get(g.input.transactionId)!;
  bytes[0] ^= 1;
  await rejects(() => runBackupV2SourcePruner(g.input, g.caps));
  assert(g.removed.length === 0);
  const h = fixture();
  await h.execute();
  h.input.plan!.digest = "0".repeat(64);
  await rejects(() => runBackupV2SourcePruner(h.input, h.caps));
  assert(h.removed.length === 0);
  const i = fixture();
  await i.execute();
  const wrongVersion = JSON.parse(
    new TextDecoder().decode(i.plans.get(i.input.transactionId)!),
  );
  wrongVersion.schemaVersion = 3;
  const invalid = encode(wrongVersion);
  i.plans.set(i.input.transactionId, invalid);
  i.input.plan = {
    ...i.input.plan!,
    sha256: sha(invalid),
    bytes: invalid.length,
  };
  await rejects(() => runBackupV2SourcePruner(i.input, i.caps));
  assert(i.removed.length === 0);
});
Deno.test("source pruner EXECUTE removes exact obsolete refs while preserving shared and orphan versions", async () => {
  const f = fixture();
  await f.execute();
  f.progress.length = 0;
  const result = await runBackupV2SourcePruner(f.input, f.caps);
  assert(
    result.state === "COMPLETE" && result.retainedCaptureIds.length === 4 &&
      f.removed.length === 10,
  );
  assert(
    f.cloud.has(f.shared.fileId) && f.cloud.has(f.orphan.fileId) &&
      f.journal.length === 20,
  );
  assert(
    f.progress.every((value, index) =>
      index === 0 || value > f.progress[index - 1]
    ),
  );
  assert(
    (await runBackupV2SourcePruner(f.input, f.caps)).state === "COMPLETE" &&
      f.removed.length === 10,
  );
});
Deno.test("source pruner rejects stale protection/gate custody and preserves partial state without another effect", async () => {
  const f = fixture();
  await f.execute();
  f.input.snapshot.protection.activeObjects = [f.exclusive];
  assert(
    (await runBackupV2SourcePruner(f.input, f.caps)).state === "PARTIAL" &&
      f.removed.length === 0,
  );
  const g = fixture();
  await g.execute();
  g.caps.observeFresh = () =>
    Promise.resolve({
      ...g.input,
      gate: { ...g.input.gate, sourceBootId: id(81) },
    });
  assert(
    (await runBackupV2SourcePruner(g.input, g.caps)).state === "PARTIAL" &&
      g.removed.length === 0,
  );
  const h = fixture();
  await h.execute();
  const plan = JSON.parse(
      new TextDecoder().decode(h.plans.get(h.input.transactionId)!),
    ),
    target = plan.candidates[0];
  h.caps.loadJournal = () =>
    Promise.resolve([{
      planSha256: plan.digest,
      ordinal: 0,
      fileId: target.fileId,
      fileName: target.fileName,
      attempt: 1,
      state: "INTENT",
      unexpected: true,
    } as unknown as BackupV2RetentionJournalEntry]);
  assert(
    (await runBackupV2SourcePruner(h.input, h.caps)).state === "PARTIAL" &&
      h.removed.length === 0,
  );
});
Deno.test("source pruner keeps an ambiguous journal and reconciles definite absence before resume", async () => {
  const f = fixture();
  await f.execute();
  const remove = f.caps.exactStore.removeExact;
  f.caps.exactStore.removeExact = async (ref) => {
    await remove(ref);
    throw Error("Response lost");
  };
  assert(
    (await runBackupV2SourcePruner(f.input, f.caps)).state === "PARTIAL" &&
      f.removed.length === 1 && f.journal[1].state === "AMBIGUOUS",
  );
  f.caps.exactStore.removeExact = remove;
  assert(
    (await runBackupV2SourcePruner(f.input, f.caps)).state === "COMPLETE" &&
      Number(f.removed.length) === 10 && f.journal[2].state === "ABSENT",
  );
});
Deno.test("source pruner rejects absent journals and stops on durable intent failure", async () => {
  const f = fixture();
  await f.execute();
  f.caps.loadJournal = () => Promise.reject(Error("Missing journal"));
  assert(
    (await runBackupV2SourcePruner(f.input, f.caps)).state === "PARTIAL" &&
      f.removed.length === 0,
  );
  const g = fixture();
  await g.execute();
  g.caps.appendDurable = () => Promise.reject(Error("Intent fsync failed"));
  assert(
    (await runBackupV2SourcePruner(g.input, g.caps)).state === "PARTIAL" &&
      g.removed.length === 0,
  );
});
Deno.test("source pruner preserves the mixed four-root floor and leaves legacy obsolete IDs to core", async () => {
  const f = fixture();
  f.input.snapshot.catalog = [catalog(3), catalog(4), catalog(5)];
  await rejects(() => runBackupV2SourcePruner(f.input, f.caps));
  assert(f.stats().lists === 0);
  const g = fixture();
  g.input.snapshot.catalog = [
    legacy(1),
    legacy(2),
    legacy(3),
    legacy(4),
    catalog(5),
  ];
  g.input.graphs = [g.input.graphs[4]];
  const result = await g.execute();
  assert(result.obsoleteLegacyCaptureIds[0] === capture(1));
  assert(
    (await runBackupV2SourcePruner(g.input, g.caps)).state === "COMPLETE" &&
      g.removed.length === 0,
  );
});
