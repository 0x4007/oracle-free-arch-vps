import { createHash } from "node:crypto";
import {
  BACKUP_V2_BOOT_SAMPLES,
  BACKUP_V2_ROLES,
  type BackupV2ByteSink,
  type BackupV2Chunk,
  type BackupV2DecryptStream,
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  type BackupV2ObjectStore,
  type BackupV2Receipt,
  type BackupV2Role,
  type BackupV2RoleManifest,
  type BackupV2Root,
  parseBackupV2ObjectName,
  validateBackupV2ArchiveProof,
  validateBackupV2ChunkPage,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2Receipt,
  validateBackupV2RoleManifest,
  validateBackupV2Root,
  validateBackupV2SealedSlot,
} from "./backup-v2-contract.ts";
import { assertBackupV2Budget, BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import {
  assertBackupV2Directory,
  syncBackupV2Directory,
} from "./backup-v2-spool.ts";
import {
  type BackupStreamVerifierDependencies,
  verifyBackupStreamArchive,
} from "./backup-stream-verifier.ts";

export interface BackupV2ObjectReader {
  /** Complete exact-version readback must precede first decoder delivery.
   * Returned stream cancellation must settle and release only its owned slot. */
  open(
    object: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<ReadableStream<Uint8Array>>;
}
export interface BackupV2ReaderCapabilities {
  objects: BackupV2ObjectReader;
  decryptDocument: BackupV2DecryptStream;
  signal?: AbortSignal;
}
const encoder = new TextEncoder();
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
function fail(): never {
  throw new Error("Backup v2 cloud recovery binding invalid");
}
export interface BackupV2VerificationMetadata {
  schemaVersion: 2;
  format: "backup-v2-verification-metadata";
  captureId: string;
  metadataSha256: string;
  bootSamples: {
    role: "root" | "staging-boot";
    member: string;
    bytes: number;
    sha256: string;
  }[];
}
const hash = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function keys(value: unknown, names: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const object = value as Record<string, unknown>;
  if (
    Object.keys(object).length !== names.length ||
    names.some((name) => !Object.hasOwn(object, name))
  ) fail();
  return object;
}
export function validateBackupV2VerificationMetadata(
  value: unknown,
): BackupV2VerificationMetadata {
  const record = keys(value, [
    "schemaVersion",
    "format",
    "captureId",
    "metadataSha256",
    "bootSamples",
  ]);
  if (
    record.schemaVersion !== 2 ||
    record.format !== "backup-v2-verification-metadata" ||
    typeof record.captureId !== "string" ||
    !/^generation-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(
      record.captureId,
    ) ||
    !hash(record.metadataSha256) || !Array.isArray(record.bootSamples) ||
    record.bootSamples.length !== 4
  ) fail();
  const bootSamples = record.bootSamples.map((value, index) => {
    const sample = keys(value, ["role", "member", "bytes", "sha256"]),
      expected = BACKUP_V2_BOOT_SAMPLES[index];
    if (
      sample.role !== expected.role || sample.member !== expected.member ||
      !hash(sample.sha256) ||
      !Number.isSafeInteger(sample.bytes) || (sample.bytes as number) <= 0 ||
      (sample.bytes as number) > BACKUP_V2_LIMITS.logicalSourceBytes
    ) fail();
    return {
      role: expected.role,
      member: expected.member,
      bytes: sample.bytes as number,
      sha256: sample.sha256,
    };
  });
  for (let index = 0; index < 2; index++) {
    if (
      bootSamples[index].sha256 !== bootSamples[index + 2].sha256 ||
      bootSamples[index].bytes !== bootSamples[index + 2].bytes
    ) fail();
  }
  const result: BackupV2VerificationMetadata = {
    schemaVersion: 2,
    format: "backup-v2-verification-metadata",
    captureId: record.captureId,
    metadataSha256: record.metadataSha256,
    bootSamples,
  };
  assertBackupV2Budget(
    "manifestBytes",
    encoder.encode(JSON.stringify(result)).length,
  );
  return result;
}

function streamFrom<T>(
  iterator: AsyncGenerator<T>,
  cancel?: () => void,
): ReadableStream<T> {
  return new ReadableStream<T>({
    async pull(controller) {
      try {
        const item = await iterator.next();
        if (item.done) controller.close();
        else controller.enqueue(item.value);
      } catch (error) {
        controller.error(error);
      }
    },
    async cancel(reason) {
      cancel?.();
      await iterator.return(reason);
    },
  }, { highWaterMark: 0 });
}

/** Two owned download paths, independent of capture's spool/cache. A failed
 * GET preserves its partial and poisons this adapter until external settlement;
 * it never deletes an unbound partial or silently allocates a third slot. */
export async function createBackupV2FileObjectReader(
  directory: string,
  store: Pick<BackupV2ObjectStore, "getExactToFile">,
): Promise<BackupV2ObjectReader> {
  const parent = await assertBackupV2Directory(directory);
  for await (const _entry of Deno.readDir(directory)) fail();
  const active = new Set<number>();
  let poisoned = false;
  return {
    async open(value, signal) {
      const object = validateBackupV2ObjectRef(value);
      if (poisoned) fail();
      const index = active.has(0) ? active.has(1) ? -1 : 1 : 0;
      if (index < 0) fail();
      active.add(index);
      const path = `${directory}/read-slot-${index}.cipher`;
      let file: Deno.FsFile | undefined;
      try {
        await assertBackupV2Directory(directory, parent);
        const slot = validateBackupV2SealedSlot(
          await store.getExactToFile(
            object,
            { index: index as 0 | 1, path },
            signal,
          ),
        );
        if (
          slot.path !== path || slot.index !== index ||
          slot.bytes !== object.contentLength ||
          slot.sha1 !== object.contentSha1 || slot.sha256 !== object.sha256
        ) fail();
        file = await Deno.open(path, { read: true });
        const check = async () => {
          await assertBackupV2Directory(directory, parent);
          const info = await Deno.lstat(path), opened = await file!.stat();
          if (
            !info.isFile || info.isSymlink || info.uid !== 0 ||
            info.nlink !== 1 || (info.mode! & 0o777) !== 0o600 ||
            info.dev !== slot.device || info.ino !== slot.inode ||
            info.size !== slot.bytes || opened.dev !== info.dev ||
            opened.ino !== info.ino
          ) fail();
        };
        await check();
        let done = false;
        const close = async () => {
          if (done) return;
          try {
            await check();
            file!.close();
            await Deno.remove(path);
            await syncBackupV2Directory(directory);
            active.delete(index);
            done = true;
          } catch (error) {
            poisoned = true;
            try {
              file?.close();
            } catch { /* preserve */ }
            throw error;
          }
        };
        return new ReadableStream<Uint8Array>({
          async pull(controller) {
            try {
              signal?.throwIfAborted();
              const bytes = new Uint8Array(64 * 1024),
                count = await file!.read(bytes);
              if (count === null) {
                await close();
                controller.close();
              } else if (count <= 0) fail();
              else controller.enqueue(bytes.subarray(0, count));
            } catch (error) {
              try {
                await close();
              } catch { /* retain first error */ }
              controller.error(error);
            }
          },
          cancel: close,
        }, { highWaterMark: 0 });
      } catch (error) {
        poisoned = true;
        try {
          file?.close();
        } catch { /* preserve */ }
        throw error;
      }
    },
  };
}

function codec(capabilities: BackupV2ReaderCapabilities) {
  const objects = new Map<string, BackupV2ObjectRef>();
  let bytes = 0;
  const track = (value: BackupV2ObjectRef) => {
    const ref = validateBackupV2ObjectRef(value),
      existing = objects.get(ref.fileId);
    if (existing && JSON.stringify(existing) !== JSON.stringify(ref)) fail();
    if (!existing) {
      assertBackupV2Budget("logicalObjects", objects.size + 1);
      assertBackupV2Budget("ciphertextBytes", bytes + ref.contentLength);
      bytes += ref.contentLength;
      objects.set(ref.fileId, ref);
    }
    return ref;
  };
  async function* read(
    value: BackupV2ObjectRef,
    signal = capabilities.signal,
    completed?: () => void,
  ) {
    const ref = track(value),
      digest = createHash("sha256"),
      sha1 = createHash("sha1");
    let bytes = 0;
    signal?.throwIfAborted();
    const source = await capabilities.objects.open(ref, signal);
    for await (const chunk of source) {
      signal?.throwIfAborted();
      if (
        !(chunk instanceof Uint8Array) || !chunk.length ||
        chunk.length > BACKUP_V2_LIMITS.slotBytes
      ) fail();
      bytes += chunk.length;
      if (bytes > ref.contentLength) fail();
      digest.update(chunk);
      sha1.update(chunk);
      yield chunk;
    }
    if (
      bytes !== ref.contentLength || digest.digest("hex") !== ref.sha256 ||
      sha1.digest("hex") !== ref.contentSha1
    ) fail();
    completed?.();
  }
  const document = async <T>(
    reference: BackupV2ManifestRef | { object: BackupV2ObjectRef },
    validate: (value: unknown) => T,
  ): Promise<T> => {
    const object = track(reference.object);
    if (object.contentLength > BACKUP_V2_LIMITS.manifestBytes) fail();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    const sink: BackupV2ByteSink = {
      write(part) {
        bytes += part.length;
        assertBackupV2Budget("manifestBytes", bytes);
        chunks.push(part.slice());
        return Promise.resolve(part.length);
      },
    };
    let inputComplete = false;
    const ciphertext = streamFrom(read(object, capabilities.signal, () => {
      inputComplete = true;
    }));
    let result: { integrityChecked: true };
    try {
      result = await capabilities.decryptDocument(ciphertext, sink);
    } finally {
      if (!ciphertext.locked) await ciphertext.cancel();
    }
    if (!inputComplete || result?.integrityChecked !== true) fail();
    const plaintext = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      plaintext.set(chunk, offset);
      offset += chunk.length;
    }
    if (
      "plaintextSha256" in reference &&
      sha(plaintext) !== reference.plaintextSha256
    ) fail();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
      value = validate(JSON.parse(text));
    if (JSON.stringify(value) !== text) fail(); // Reject duplicate keys/noncanonical bytes.
    return value;
  };
  const role = async (reference: BackupV2ManifestRef) => {
    const ref = validateBackupV2ManifestRef(reference),
      name = parseBackupV2ObjectName(ref.object.fileName);
    if (name.kind !== "manifest") fail();
    const manifest = await document(ref, validateBackupV2RoleManifest);
    if (
      manifest.captureId !== name.captureId ||
      manifest.attemptId !== name.attemptId
    ) fail();
    for (const value of manifest.metadata) track(value);
    return manifest;
  };
  async function* chunks(
    manifest: BackupV2RoleManifest,
  ): AsyncGenerator<BackupV2Chunk> {
    for (let index = 0; index < manifest.pages.length; index++) {
      const expected = manifest.pages[index],
        page = await document(expected.manifest, validateBackupV2ChunkPage);
      if (
        page.captureId !== manifest.captureId ||
        page.attemptId !== manifest.attemptId || page.role !== manifest.role ||
        page.pageIndex !== index ||
        page.startOrdinal !== expected.firstOrdinal ||
        page.startOffset !== expected.firstOffset ||
        page.chunks.length !== expected.chunkCount ||
        page.chunks.reduce(
            (sum, chunk) => sum + chunk.object.contentLength,
            0,
          ) !== expected.bytes
      ) fail();
      for (const chunk of page.chunks) {
        track(chunk.object);
        yield chunk;
      }
    }
  }
  return {
    document,
    role,
    chunks,
    read,
    track,
    references: () => [...objects.values()].map((ref) => ({ ...ref })),
  };
}

export interface BackupV2Reader {
  readonly root: BackupV2Root;
  readonly rootRef: BackupV2ManifestRef;
  role(role: BackupV2Role): Promise<BackupV2RoleManifest>;
  verificationMetadata(): Promise<BackupV2VerificationMetadata>;
  ciphertext(role: BackupV2Role): ReadableStream<Uint8Array>;
  references(): Promise<readonly BackupV2ObjectRef[]>;
}
export async function createBackupV2Reader(
  reference: BackupV2ManifestRef,
  capabilities: BackupV2ReaderCapabilities,
): Promise<BackupV2Reader> {
  const rootRef = validateBackupV2ManifestRef(reference),
    documents = codec(capabilities);
  const rootName = parseBackupV2ObjectName(rootRef.object.fileName);
  if (rootName.kind !== "manifest") fail();
  const root = await documents.document(rootRef, validateBackupV2Root);
  if (root.captureId !== rootName.captureId) fail();
  for (const ref of root.metadata) documents.track(ref);
  const cache = new Map<BackupV2Role, BackupV2RoleManifest>();
  const role = async (name: BackupV2Role) => {
    if (!BACKUP_V2_ROLES.includes(name)) fail();
    if (!cache.has(name)) {
      const link = root.roles.find((item) => item.role === name)!;
      const value = await documents.role(link.manifest);
      if (
        value.role !== name || value.attemptId !== link.attemptId ||
        value.captureStartedAtUtc !== link.captureStartedAtUtc ||
        value.captureFinishedAtUtc !== link.captureFinishedAtUtc ||
        value.recipientSha256 !== root.recipientSha256 ||
        value.recipientFingerprint !== root.recipientFingerprint ||
        value.sourceConfigSha256 !== root.sourceConfigSha256
      ) fail();
      cache.set(name, value);
    }
    return structuredClone(cache.get(name)!);
  };
  const ciphertext = (name: BackupV2Role) => {
    const abort = new AbortController(),
      signal = capabilities.signal
        ? AbortSignal.any([capabilities.signal, abort.signal])
        : abort.signal;
    async function* bytes() {
      const manifest = await role(name), hash = createHash("sha256");
      let total = 0;
      for await (const chunk of documents.chunks(manifest)) {
        for await (const part of documents.read(chunk.object, signal)) {
          total += part.length;
          hash.update(part);
          yield part;
        }
      }
      if (
        total !== manifest.ciphertextBytes ||
        hash.digest("hex") !== manifest.ciphertextSha256
      ) fail();
    }
    return streamFrom(bytes(), () => abort.abort());
  };
  return {
    get root() {
      return structuredClone(root);
    },
    get rootRef() {
      return structuredClone(rootRef);
    },
    role,
    ciphertext,
    async verificationMetadata() {
      const object = root.metadata[0];
      if (
        !object || parseBackupV2ObjectName(object.fileName).kind !== "metadata"
      ) fail();
      const metadata = await documents.document(
        { object },
        validateBackupV2VerificationMetadata,
      );
      if (metadata.captureId !== root.captureId) fail();
      return metadata;
    },
    async references() {
      for (const name of BACKUP_V2_ROLES) {
        for await (const _chunk of documents.chunks(await role(name))) {
          /* validates graph without reading payload */
        }
      }
      return documents.references();
    },
  };
}

export async function backupV2RoleReferences(
  reference: BackupV2ManifestRef,
  capabilities: BackupV2ReaderCapabilities,
): Promise<readonly BackupV2ObjectRef[]> {
  const documents = codec(capabilities),
    manifest = await documents.role(reference);
  for await (const _chunk of documents.chunks(manifest)) {
    /* exact graph only */
  }
  return documents.references();
}
export interface BackupV2RootVerification {
  decrypt: BackupV2DecryptStream;
  native?: Omit<BackupStreamVerifierDependencies, "ciphertext" | "decrypt">;
  verifyArchive?: typeof verifyBackupStreamArchive;
  configurationSha256: string;
  verifierRevision: string;
  tools: { tar: string; zstd: string; gpg: string };
  now(): Date;
}
/** m03 produces the measured proofs. No controller/capture-cache imports and
 * no acceptance/gate clearing occurs here. The caller retains the trusted root. */
export async function verifyBackupV2Root(
  reader: BackupV2Reader,
  options: BackupV2RootVerification,
): Promise<BackupV2Receipt> {
  const root = reader.root, metadata = await reader.verificationMetadata();
  const archives: BackupV2Receipt["archives"] = [],
    bootSamples: BackupV2Receipt["bootSamples"] = [];
  const verify = options.verifyArchive ?? verifyBackupStreamArchive;
  for (const name of BACKUP_V2_ROLES) {
    const role = await reader.role(name);
    const samples = metadata.bootSamples.filter((item) => item.role === name)
      .map((item) => ({ ...item, member: encoder.encode(item.member) }));
    const result = await verify(role, {
      ...options.native,
      ciphertext: reader.ciphertext,
      decrypt: options.decrypt,
    }, {
      samples,
      ...(name === "recovery"
        ? { metadataSha256: metadata.metadataSha256 }
        : {}),
    });
    const proof = validateBackupV2ArchiveProof(result.proof);
    if (
      proof.role !== name || proof.format !== role.format ||
      proof.ciphertextBytes !== role.ciphertextBytes ||
      proof.ciphertextSha256 !== role.ciphertextSha256 ||
      JSON.stringify(proof.inventory) !== JSON.stringify(role.inventory)
    ) fail();
    if (
      name === "recovery" &&
      (!result.metadata || sha(result.metadata) !== metadata.metadataSha256)
    ) fail();
    if (result.samples.length !== samples.length) fail();
    for (let index = 0; index < samples.length; index++) {
      const actual = result.samples[index], expected = samples[index];
      if (
        actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes ||
        new TextDecoder().decode(actual.member) !==
          metadata.bootSamples.filter((item) => item.role === name)[index]
            .member
      ) fail();
      bootSamples.push({
        role: expected.role,
        member: new TextDecoder().decode(expected.member),
        bytes: actual.bytes,
        sha256: actual.sha256,
      });
    }
    archives.push(proof);
  }
  return validateBackupV2Receipt({
    schemaVersion: 2,
    format: "backup-v2",
    captureId: root.captureId,
    root: reader.rootRef,
    verifiedAtUtc: options.now().toISOString(),
    recipientSha256: root.recipientSha256,
    recipientFingerprint: root.recipientFingerprint,
    verifierRevision: options.verifierRevision,
    configurationSha256: options.configurationSha256,
    tools: options.tools,
    archives,
    bootSamples,
    metadataSha256: metadata.metadataSha256,
    sourceIndependent: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  });
}
