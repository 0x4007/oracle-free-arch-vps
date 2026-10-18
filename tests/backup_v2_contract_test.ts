import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ObjectKind,
  backupV2ObjectName,
  parseBackupV2ObjectName,
  validateBackupV2ArchiveProof,
  validateBackupV2ChunkPage,
  validateBackupV2Cursor,
  validateBackupV2LeaseWindow,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2Progress,
  validateBackupV2PutIntent,
  validateBackupV2Receipt,
  validateBackupV2RoleManifest,
  validateBackupV2Root,
  validateBackupV2SealedSlot,
  validateBackupV2VersionPage,
} from "../scripts/backup-v2-contract.ts";
import {
  createBackupV2InventorySummary,
  encodeBackupV2InventoryRecord,
  summarizeBackupV2Inventory,
  validateBackupV2InventorySummary,
} from "../scripts/backup-v2-inventory.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_LIMITS,
  BACKUP_V2_PROFILE_ID,
  BACKUP_V2_SLOT_COUNT,
  BACKUP_V2_WORKSPACE,
  backupV2RequiredFreeBytes,
} from "../scripts/backup-v2-profile.ts";

function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function equal(actual: unknown, expected: unknown): void {
  assert(JSON.stringify(actual) === JSON.stringify(expected));
}
function throws(run: () => unknown): void {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
const C = "generation-00000000-0000-4000-8000-000000000001";
const A = "00000000-0000-4000-8000-000000000002";
const P = "00000000-0000-4000-8000-000000000003";
const SHA1 = "1".repeat(40), SHA = "2".repeat(64);
const START = "2026-10-18T04:05:00.000Z", END = "2026-10-18T04:06:00.000Z";
function ref(
  ordinal = 0,
  kind: BackupV2ObjectKind = "data",
  bytes = 17,
  captureId = C,
) {
  return {
    fileId: `file_${kind}_${ordinal}`,
    fileName: backupV2ObjectName(captureId, A, kind, ordinal, P),
    contentLength: bytes,
    contentSha1: SHA1,
    uploadTimestamp: 1,
    action: "upload" as const,
    sha256: SHA,
  };
}
function manifestRef(ordinal = 0, captureId = C) {
  return {
    object: ref(ordinal, "manifest", 17, captureId),
    plaintextSha256: SHA,
  };
}
function slot() {
  return {
    index: 0,
    path: "/var/tmp/backup-fixture/slot-0",
    device: 8,
    inode: 10,
    bytes: 17,
    sha1: SHA1,
    sha256: SHA,
    uid: 0,
    mode: 384,
    links: 1,
  };
}
function inventory() {
  const sum = createBackupV2InventorySummary();
  sum.add({ path: new TextEncoder().encode("./etc/os-release") });
  return sum.finish();
}
function roleManifest() {
  return {
    schemaVersion: 2,
    captureId: C,
    attemptId: A,
    role: "root",
    format: "tar.zst.gpg",
    ciphertextBytes: 17,
    ciphertextSha256: SHA,
    sourceConfigSha256: SHA,
    compatibilitySha256: SHA,
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
    captureStartedAtUtc: START,
    captureFinishedAtUtc: END,
    uploadStartedAtUtc: "2026-10-18T04:05:10.000Z",
    uploadFinishedAtUtc: END,
    pages: [{
      manifest: manifestRef(),
      firstOrdinal: 0,
      firstOffset: 0,
      chunkCount: 1,
      bytes: 17,
    }],
    inventory: inventory(),
    producer: {
      tarExitCode: 0,
      zstdExitCode: 0,
      gpgExitCode: 0,
      driftRecords: 0,
      driftSha256: SHA,
    },
    metadata: [],
  };
}
function root() {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    captureId: C,
    periodKey: "2026-10-18",
    sourceRevision: SHA1,
    sourceConfigSha256: SHA,
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
    roles: BACKUP_V2_ROLES.map((role, index) => ({
      role,
      attemptId: A,
      manifest: manifestRef(index),
      captureStartedAtUtc: START,
      captureFinishedAtUtc: END,
    })),
    metadata: [],
  };
}
function proof(role: typeof BACKUP_V2_ROLES[number] = "root") {
  return {
    role,
    format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
    ciphertextBytes: 17,
    ciphertextSha256: SHA,
    compressedBytes: 1,
    compressedSha256: SHA,
    inventory: role === "recovery" ? null : inventory(),
    inputComplete: true,
    integrityChecked: true,
    decompressionComplete: true,
    gpgExitCode: 0,
    zstdExitCode: 0,
    tarExitCode: 0,
  };
}
function receipt() {
  return {
    schemaVersion: 2,
    format: "backup-v2",
    captureId: C,
    root: manifestRef(),
    verifiedAtUtc: END,
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
    verifierRevision: SHA1,
    configurationSha256: SHA,
    tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4.9" },
    archives: BACKUP_V2_ROLES.map(proof),
    bootSamples: BACKUP_V2_BOOT_SAMPLES.map((sample) => ({
      ...sample,
      bytes: 1,
      sha256: SHA,
    })),
    metadataSha256: SHA,
    sourceIndependent: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
}

Deno.test("v2 profile bounds allocated workspace separately from required free reserve", () => {
  equal(BACKUP_V2_SLOT_COUNT, 2);
  equal(
    Object.values(BACKUP_V2_WORKSPACE).reduce((sum, value) => sum + value, 0),
    BACKUP_V2_LIMITS.workspaceBytes,
  );
  equal(backupV2RequiredFreeBytes(0, 0), 8_053_063_680);
  equal(
    backupV2RequiredFreeBytes(BACKUP_V2_LIMITS.workspaceBytes, 100),
    BACKUP_V2_LIMITS.protectedReserveBytes + 100,
  );
  for (const bad of [-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    throws(() => assertBackupV2Budget("slotBytes", bad));
    throws(() => backupV2RequiredFreeBytes(0, bad));
  }
  throws(() =>
    backupV2RequiredFreeBytes(BACKUP_V2_LIMITS.workspaceBytes + 1, 0)
  );
  throws(() => backupV2RequiredFreeBytes(0, Number.MAX_SAFE_INTEGER));
});
Deno.test("v2 names bind immutable logical identity and a distinct physical PUT", () => {
  const name = backupV2ObjectName(C, A, "data", 0, P);
  equal(parseBackupV2ObjectName(name), {
    captureId: C,
    attemptId: A,
    kind: "data",
    ordinal: 0,
    putId: P,
  });
  assert(name !== backupV2ObjectName(C, A, "data", 0, A));
  for (
    const bad of [
      name.replace("backup-v2", "direct-v1"),
      name + "/extra",
      name.replace("00000000/", "00005000/"),
      name.replace("/data/", "/../"),
    ]
  ) {
    throws(() => parseBackupV2ObjectName(bad));
  }
});
Deno.test("v2 exact refs and sealed slots reject marker, size, hash and unsafe identity", () => {
  equal(validateBackupV2ObjectRef(ref()), ref());
  for (
    const change of [
      { action: "hide" },
      { contentLength: 0 },
      { contentLength: BACKUP_V2_LIMITS.slotBytes + 1 },
      { sha256: SHA1 },
      { fileId: "x".repeat(513) },
      { ignored: true },
    ]
  ) {
    throws(() => validateBackupV2ObjectRef({ ...ref(), ...change }));
  }
  validateBackupV2SealedSlot(slot());
  for (
    const change of [{ index: 2 }, { uid: 1 }, { links: 2 }, { inode: 0 }, {
      mode: 420,
    }, { path: "/var/tmp/../secret" }]
  ) {
    throws(() => validateBackupV2SealedSlot({ ...slot(), ...change }));
  }
  throws(() =>
    validateBackupV2ManifestRef({
      ...manifestRef(),
      object: ref(0, "manifest", BACKUP_V2_LIMITS.manifestBytes + 1),
    })
  );
});
Deno.test("v2 intent is bound to its physical name and sealed byte range", () => {
  const intent = {
    captureId: C,
    role: "root",
    attemptId: A,
    kind: "data",
    ordinal: 0,
    offset: 0,
    putId: P,
    createdAtUtc: START,
    slot: slot(),
    name: ref().fileName,
  };
  validateBackupV2PutIntent(intent);
  for (
    const change of [{ putId: A }, { ordinal: 1 }, { attemptId: P }, {
      offset: BACKUP_V2_LIMITS.ciphertextBytes,
    }, { createdAtUtc: "2026-02-30T00:00:00.000Z" }]
  ) {
    throws(() => validateBackupV2PutIntent({ ...intent, ...change }));
  }
});
Deno.test("v2 paginated versions retain conflict markers and bound page/cursor shapes", () => {
  const { sha256: _digest, ...version } = ref();
  const page = {
    items: [version, {
      ...version,
      fileId: "hidden",
      action: "hide",
      contentLength: 0,
      contentSha1: "none",
    }, {
      ...version,
      fileId: "started",
      action: "start",
      contentLength: 0,
      contentSha1: "",
    }],
    next: { fileName: version.fileName, fileId: version.fileId },
  };
  equal(validateBackupV2VersionPage(page), page);
  throws(() =>
    validateBackupV2VersionPage({ ...page, items: Array(101).fill(version) })
  );
  throws(() =>
    validateBackupV2Cursor({
      fileName: "restic/direct-v1/foreign",
      fileId: "x",
    })
  );
  throws(() =>
    validateBackupV2VersionPage({
      ...page,
      next: { fileName: version.fileName },
    })
  );
});
Deno.test("v2 chunk pages reject gaps, cross-attempt references and discontinuous offsets", () => {
  const page = {
    schemaVersion: 2,
    captureId: C,
    attemptId: A,
    role: "root",
    pageIndex: 0,
    startOrdinal: 0,
    startOffset: 0,
    chunks: [{ ordinal: 0, offset: 0, object: ref() }, {
      ordinal: 1,
      offset: 17,
      object: ref(1),
    }],
  };
  validateBackupV2ChunkPage(page);
  throws(() => validateBackupV2ChunkPage({ ...page, chunks: [] }));
  for (
    const change of [{ ordinal: 2 }, { offset: 18 }, {
      object: { ...ref(1), fileName: backupV2ObjectName(C, P, "data", 1, A) },
    }]
  ) {
    throws(() =>
      validateBackupV2ChunkPage({
        ...page,
        chunks: [page.chunks[0], { ...page.chunks[1], ...change }],
      })
    );
  }
});
Deno.test("v2 role manifest permits true overlap but never v1 fabrication or unclassified tar failures", () => {
  const good = roleManifest();
  validateBackupV2RoleManifest(good);
  for (
    const change of [
      { uploadStartedAtUtc: "2026-10-18T04:04:59.000Z" },
      { uploadFinishedAtUtc: START },
      { schemaVersion: 1 },
      { ciphertextBytes: 18 },
      { inventory: null },
      { producer: { ...good.producer, tarExitCode: 1 } },
      { producer: { ...good.producer, gpgExitCode: 1 } },
    ]
  ) {
    throws(() => validateBackupV2RoleManifest({ ...good, ...change }));
  }
  validateBackupV2RoleManifest({
    ...good,
    producer: { ...good.producer, tarExitCode: 1, driftRecords: 1 },
  });
  throws(() =>
    validateBackupV2RoleManifest({
      ...good,
      role: "staging-boot",
      producer: { ...good.producer, tarExitCode: 1, driftRecords: 1 },
    })
  );
});
Deno.test("v2 root preserves reused role origins and times, exact role coverage and Sunday period", () => {
  const good = root();
  const originalCapture = C.replace(/1$/, "4");
  good.roles[0].manifest = manifestRef(0, originalCapture);
  good.roles[0].captureStartedAtUtc = "2026-10-17T04:00:00.000Z";
  const checked = validateBackupV2Root(good);
  equal(
    checked.roles[0].captureStartedAtUtc,
    good.roles[0].captureStartedAtUtc,
  );
  equal(
    checked.roles[0].manifest.object.fileName,
    good.roles[0].manifest.object.fileName,
  );
  throws(() => validateBackupV2Root({ ...good, roles: good.roles.slice(1) }));
  throws(() =>
    validateBackupV2Root({
      ...good,
      roles: [good.roles[1], good.roles[0], ...good.roles.slice(2)],
    })
  );
  throws(() => validateBackupV2Root({ ...good, periodKey: "2026-10-19" }));
});
Deno.test("v2 verification requires EOF, all native statuses, every role and all four exact boot results", () => {
  const good = receipt();
  validateBackupV2Receipt(good);
  for (
    const field of [
      "inputComplete",
      "integrityChecked",
      "decompressionComplete",
    ] as const
  ) {
    throws(() => validateBackupV2ArchiveProof({ ...proof(), [field]: false }));
  }
  for (const field of ["gpgExitCode", "zstdExitCode", "tarExitCode"] as const) {
    throws(() => validateBackupV2ArchiveProof({ ...proof(), [field]: 1 }));
  }
  for (
    const change of [
      { machineBootRestoreProved: true },
      { sourceIndependent: false },
      { archives: good.archives.slice(1) },
      { bootSamples: good.bootSamples.slice(1) },
      {
        bootSamples: [
          good.bootSamples[0],
          good.bootSamples[0],
          ...good.bootSamples.slice(2),
        ],
      },
      { root: manifestRef(0, C.replace(/1$/, "4")) },
    ]
  ) {
    throws(() => validateBackupV2Receipt({ ...good, ...change }));
  }
});
Deno.test("v2 progress excludes heartbeat-only fields and leases retain original episode deadlines", () => {
  const progress = {
    phase: "CAPTURING_AND_UPLOADING",
    observedMonotonicMs: 100.5,
    sourceBytes: 1,
    compressionInputBytes: 1,
    verifiedChunks: 0,
    decryptedBytes: 0,
    inventoryMembers: 1,
  };
  validateBackupV2Progress(progress);
  throws(() => validateBackupV2Progress({ ...progress, heartbeat: 1 }));
  throws(() => validateBackupV2Progress({ ...progress, phase: "UPLOADING" }));
  const lease = {
    observedMonotonicMs: 100,
    usefulProgressAtMs: 0,
    usefulProgressExpiresAtMs: 50,
    retryEpisode: { startedAtMs: 10, expiresAtMs: 20 },
  };
  equal(validateBackupV2LeaseWindow(lease), lease); // Expiry must be representable for fail-closed supervisor decisions.
  throws(() =>
    validateBackupV2LeaseWindow({ ...lease, usefulProgressAtMs: 101 })
  );
  throws(() =>
    validateBackupV2LeaseWindow({
      ...lease,
      retryEpisode: {
        startedAtMs: 0,
        expiresAtMs: BACKUP_V2_LIMITS.blockedTransportMs + 1,
      },
    })
  );
});
Deno.test("v2 inventory framing is unambiguous for newlines and preserves non-UTF8 bytes", async () => {
  const encoder = new TextEncoder();
  const a = createBackupV2InventorySummary(),
    b = createBackupV2InventorySummary();
  for (const name of ["a\nb", "c"]) a.add({ path: encoder.encode(name) });
  for (const name of ["a", "b\nc"]) b.add({ path: encoder.encode(name) });
  assert(a.finish().sha256 !== b.finish().sha256);
  const raw = new Uint8Array([46, 47, 255, 10]);
  const frame = encodeBackupV2InventoryRecord({
    path: raw,
    metadata: new Uint8Array([0, 255]),
  });
  equal([...frame.slice(8)], [...raw, 0, 255]);
  const result = await summarizeBackupV2Inventory((async function* () {
    yield { path: raw };
  })());
  equal(result.members, 1);
  equal(result.pathBytes, raw.length);
  validateBackupV2InventorySummary(result);
});
Deno.test("v2 inventory rejects traversal, NUL, oversize records and inconsistent summary without retaining names", () => {
  for (
    const path of [
      new Uint8Array(),
      new Uint8Array([0]),
      new TextEncoder().encode("/etc"),
      new TextEncoder().encode("./../etc"),
    ]
  ) {
    throws(() => encodeBackupV2InventoryRecord({ path }));
  }
  throws(() =>
    encodeBackupV2InventoryRecord({
      path: new Uint8Array([46]),
      metadata: new Uint8Array(BACKUP_V2_LIMITS.metadataRecordBytes),
    })
  );
  throws(() =>
    validateBackupV2InventorySummary({ ...inventory(), encodedBytes: 0 })
  );
  const sum = createBackupV2InventorySummary();
  sum.finish();
  throws(() => sum.add({ path: new Uint8Array([46]) }));
  throws(() => sum.finish());
});
