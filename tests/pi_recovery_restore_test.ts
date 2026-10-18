// Capability fakes contain no native, network or filesystem work.
// deno-lint-ignore-file require-await
import { createHash } from "node:crypto";
import {
  recoveryCatalogSelection,
  recoveryRelativeImports,
} from "../scripts/pi-recovery-restore.ts";
import {
  openV2RestoreReader,
  readV2RestoreReceipt,
  type StreamDecrypt,
} from "../scripts/backblaze-stream-restore.ts";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ObjectKind,
  backupV2ObjectName,
  validateBackupV2Receipt,
  validateBackupV2Root,
} from "../scripts/backup-v2-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2CatalogEntry,
} from "../scripts/backup-v2-runtime-contract.ts";

function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
async function rejects(fn: () => unknown | Promise<unknown>) {
  try {
    await fn();
  } catch {
    return;
  }
  throw Error("Expected refusal");
}
const bytes = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value));
const hash = (value: Uint8Array, algorithm = "sha256") =>
  createHash(algorithm).update(value).digest("hex");
const ID = "00000000-0000-4000-8000-000000000001",
  ATTEMPT = "00000000-0000-4000-8000-000000000002",
  PUT = "00000000-0000-4000-8000-000000000003";
const GENERATION = `generation-${ID}`,
  SHA = "a".repeat(64),
  START = "2026-10-18T04:00:00.000Z",
  END = "2026-10-18T04:01:00.000Z";
function reference(
  kind: BackupV2ObjectKind,
  ordinal: number,
  payload = new Uint8Array([1]),
) {
  return {
    object: {
      fileId: `${kind}-${ordinal}`,
      fileName: backupV2ObjectName(GENERATION, ATTEMPT, kind, ordinal, PUT),
      contentLength: payload.length,
      contentSha1: hash(payload, "sha1"),
      sha256: hash(payload),
      uploadTimestamp: 1,
      action: "upload" as const,
    },
    plaintextSha256: hash(payload),
  };
}
function fixture() {
  const request: BackupV2Request = {
    schemaVersion: 2 as const,
    format: "backup-v2" as const,
    profile: BACKUP_V2_PROFILE_ID,
    jobId: `job-${ID}`,
    captureId: GENERATION,
    periodKey: "2026-10-18",
    requestedAtUtc: START,
    sourceRevision: "a".repeat(40),
    sourceConfigSha256: SHA,
    recipientSha256: SHA,
    recipientFingerprint: "A".repeat(40),
  };
  const root = validateBackupV2Root({
    schemaVersion: 2 as const,
    format: "backup-v2" as const,
    profile: request.profile,
    captureId: GENERATION,
    periodKey: request.periodKey,
    sourceRevision: request.sourceRevision,
    sourceConfigSha256: SHA,
    recipientSha256: SHA,
    recipientFingerprint: request.recipientFingerprint,
    roles: BACKUP_V2_ROLES.map((role, index) => ({
      role,
      attemptId: ATTEMPT,
      manifest: reference("manifest", index),
      captureStartedAtUtc: START,
      captureFinishedAtUtc: END,
    })),
    metadata: [],
  });
  const rootBytes = bytes(root),
    rootReference = reference("manifest", 99, rootBytes);
  const receipt = validateBackupV2Receipt({
    schemaVersion: 2 as const,
    format: "backup-v2" as const,
    captureId: GENERATION,
    root: rootReference,
    verifiedAtUtc: END,
    recipientSha256: SHA,
    recipientFingerprint: request.recipientFingerprint,
    verifierRevision: request.sourceRevision,
    configurationSha256: SHA,
    tools: { tar: "1.35", zstd: "1.5.7", gpg: "2.4" },
    archives: BACKUP_V2_ROLES.map((role) => ({
      role,
      format: role === "recovery" ? "json.zst.gpg" : "tar.zst.gpg",
      ciphertextBytes: 1,
      ciphertextSha256: SHA,
      compressedBytes: 1,
      compressedSha256: SHA,
      inventory: role === "recovery" ? null : {
        encoding: "backup-v2-inventory-1",
        members: 1,
        pathBytes: 2,
        encodedBytes: 10,
        sha256: SHA,
      },
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
      sha256: SHA,
    })),
    metadataSha256: SHA,
    sourceIndependent: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  });
  const catalog = validateBackupV2CatalogEntry({
    schemaVersion: 2,
    format: "backup-v2",
    envelope: { request, requestSha256: backupV2RequestSha256(request) },
    resultSha256: SHA,
    selectedRoot: { root, reference: rootReference },
    receipt,
    receiptReference: reference("receipt", 0, bytes(receipt)),
    acceptedAtUtc: END,
  });
  const contents = new Map([[rootReference.object.fileId, rootBytes], [
    catalog.receiptReference.object.fileId,
    bytes(catalog.receipt),
  ]]);
  const objects = {
    async open(object: { fileId: string }) {
      const payload = contents.get(object.fileId);
      assert(payload);
      return new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(payload);
          c.close();
        },
      });
    },
  };
  const decrypt: StreamDecrypt = async (input, output) => {
    for await (const part of input) await output.write(part);
    return { integrityChecked: true };
  };
  return { catalog, objects, decrypt, contents };
}

Deno.test("recovery dispatch selects v2 root anchor before legacy index access", () => {
  const f = fixture(), selected = recoveryCatalogSelection(f.catalog);
  assert(
    selected.schemaVersion === 2 && selected.generation === GENERATION &&
      selected.indexSha256 === f.catalog.selectedRoot.reference.plaintextSha256,
  );
  assert(
    selected.recipientSha256 === SHA &&
      selected.recipientFingerprint === "A".repeat(40),
  );
});

Deno.test("recovery dispatch rejects unknown versions and malformed v2 without legacy fallback", async () => {
  let touched = false;
  const invalid = {
    schemaVersion: 2,
    format: "backup-v2",
    get index() {
      touched = true;
      throw Error("legacy access");
    },
  };
  await rejects(() => recoveryCatalogSelection(invalid));
  assert(!touched);
  await rejects(() =>
    recoveryCatalogSelection({ schemaVersion: 3, format: "backup-v3" })
  );
});

Deno.test("v2 target reader independently reads both trusted root and receipt without source capability", async () => {
  const f = fixture(),
    loaded = await openV2RestoreReader(f.catalog, f.objects, f.decrypt);
  assert(
    loaded.reader.root.captureId === GENERATION &&
      loaded.receipt.metadataSha256 === SHA,
  );
  const changed = structuredClone(f.catalog);
  changed.receipt.metadataSha256 = "b".repeat(64);
  await rejects(() => openV2RestoreReader(changed, f.objects, f.decrypt));
  f.contents.set(
    f.catalog.receiptReference.object.fileId,
    bytes({ changed: true }),
  );
  await rejects(() => openV2RestoreReader(f.catalog, f.objects, f.decrypt));
});

Deno.test("v2 target receipt refuses unconsumed ciphertext and partial crypto completion", async () => {
  const f = fixture();
  await rejects(() =>
    readV2RestoreReceipt(
      f.catalog.receiptReference,
      f.objects,
      async () => ({ integrityChecked: true }),
    )
  );
  await rejects(() =>
    readV2RestoreReceipt(
      f.catalog.receiptReference,
      f.objects,
      async (input, output) => {
        for await (const part of input) await output.write(part);
        throw Error("synthetic final integrity failure");
      },
    )
  );
});

Deno.test("recovery kit relative closure includes side effects, dynamic imports and exports and rejects escape", async () => {
  const imports = recoveryRelativeImports(
    "scripts/entry.ts",
    `import "./side.ts"; import {value} from "./reader.ts"; export * from "./contract.ts"; const lazy = import("./native.ts");`,
  );
  assert(
    JSON.stringify(imports) ===
      JSON.stringify([
        "scripts/side.ts",
        "scripts/reader.ts",
        "scripts/contract.ts",
        "scripts/native.ts",
      ]),
  );
  await rejects(() =>
    recoveryRelativeImports("scripts/entry.ts", `import "../../foreign.ts";`)
  );
  await rejects(() =>
    recoveryRelativeImports(
      "scripts/entry.ts",
      `export * from "./%2e%2e/foreign.ts";`,
    )
  );
});

const sourceRead =
  (await Deno.permissions.query({ name: "read", path: "scripts" })).state ===
    "granted";
Deno.test({
  name:
    "source-only recovery closure reaches v2 reader without publication module",
  ignore: !sourceRead,
  async fn() {
    const queue = ["scripts/backblaze-stream-restore.ts"],
      modules = new Set<string>();
    while (queue.length) {
      const module = queue.shift()!;
      if (modules.has(module)) continue;
      modules.add(module);
      assert(modules.size <= 100);
      const text = await Deno.readTextFile(module);
      for (
        const dependency of recoveryRelativeImports(module, text)
      ) if (!modules.has(dependency)) queue.push(dependency);
    }
    for (
      const required of [
        "backup-v2-recovery.ts",
        "backup-v2-store.ts",
        "backup-stream-verifier.ts",
        "backup-v2-contract.ts",
        "backblaze-machine-restore.ts",
      ]
    ) assert(modules.has(`scripts/${required}`));
    assert(!modules.has("scripts/backup-v2-index.ts"));
    console.log(
      JSON.stringify({
        sourceClosureModules: modules.size,
        publicationModule: false,
        installedPiReceiptProved: false,
      }),
    );
  },
});
