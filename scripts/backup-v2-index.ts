import { createHash } from "node:crypto";
import {
  type BackupV2VerificationMetadata,
  validateBackupV2VerificationMetadata,
} from "./backup-v2-recovery.ts";
export {
  type BackupV2VerificationMetadata,
  validateBackupV2VerificationMetadata,
} from "./backup-v2-recovery.ts";
import {
  BACKUP_V2_ROLES,
  type BackupV2Chunk,
  type BackupV2ManifestRef,
  backupV2ObjectName,
  type BackupV2PageRef,
  type BackupV2Receipt,
  type BackupV2RoleManifest,
  type BackupV2Root,
  validateBackupV2ChunkPage,
  validateBackupV2ManifestRef,
  validateBackupV2Receipt,
  validateBackupV2RoleManifest,
  validateBackupV2Root,
} from "./backup-v2-contract.ts";
import { assertBackupV2Budget, BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import {
  type BackupV2UploadContext,
  type BackupV2UploadIdentity,
  uploadSealedBackupV2Object,
} from "./backup-v2-upload.ts";

const encoder = new TextEncoder();
const digest = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
const hash = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function fail(): never {
  throw new Error("Backup v2 document binding or budget invalid");
}
/** A small record in the existing bounded control workspace, not a database.
 * The caller persists+fsyncs it before encryption and restores records on resume. */
export interface BackupV2DocumentBinding {
  identity: BackupV2UploadIdentity;
  ordinal: number;
  plaintextSha256: string;
}
export interface BackupV2DocumentEncryption {
  ciphertext: ReadableStream<Uint8Array>;
  /** Must settle after the complete native encryption status; cancellation
   * must drain/settle that producer inside its managed unit. */
  completed: Promise<void>;
}
export interface BackupV2DocumentPublisherCapabilities {
  upload: BackupV2UploadContext;
  encrypt(
    plaintext: Uint8Array,
    signal: AbortSignal,
  ): Promise<BackupV2DocumentEncryption>;
  persistBinding(binding: BackupV2DocumentBinding): Promise<void>;
  bindings: readonly BackupV2DocumentBinding[];
}
function bindingKey(identity: BackupV2UploadIdentity, ordinal: number): string {
  backupV2ObjectName(
    identity.captureId,
    identity.attemptId,
    identity.kind,
    ordinal,
    "00000000-0000-0000-0000-000000000000",
  );
  if (!BACKUP_V2_ROLES.includes(identity.role)) fail();
  return JSON.stringify([
    identity.captureId,
    identity.attemptId,
    identity.role,
    identity.kind,
    ordinal,
  ]);
}

/** Fixed m04 transaction reuse. Publication is serial and a failed publication
 * is poisoned; no retry may silently regenerate ciphertext for an old intent. */
export class BackupV2DocumentPublisher {
  readonly #caps: BackupV2DocumentPublisherCapabilities;
  readonly #bindings = new Map<string, BackupV2DocumentBinding>();
  #busy = false;
  #failed = false;
  constructor(capabilities: BackupV2DocumentPublisherCapabilities) {
    this.#caps = {
      ...capabilities,
      upload: {
        ...capabilities.upload,
        identity: { ...capabilities.upload.identity },
      },
    };
    if (capabilities.upload.spool.chunkBytes < BACKUP_V2_LIMITS.manifestBytes) {
      fail();
    }
    for (const binding of capabilities.bindings) {
      const key = bindingKey(binding.identity, binding.ordinal);
      if (!hash(binding.plaintextSha256) || this.#bindings.has(key)) fail();
      this.#bindings.set(key, structuredClone(binding));
    }
    this.#budget();
  }
  #budget(): void {
    assertBackupV2Budget("logicalObjects", this.#bindings.size);
    const bytes =
      encoder.encode(JSON.stringify([...this.#bindings.values()])).length +
      encoder.encode(JSON.stringify(this.#caps.upload.journal.snapshot()))
        .length;
    assertBackupV2Budget("journalBytes", bytes);
  }
  async #publish(
    value: unknown,
    ordinal: number,
    kind: "manifest" | "metadata" | "receipt",
  ): Promise<BackupV2ManifestRef> {
    if (
      this.#busy || this.#failed || this.#caps.upload.identity.kind !== kind
    ) fail();
    this.#busy = true;
    const controller = new AbortController(), context = this.#caps.upload;
    const signal = context.signal
      ? AbortSignal.any([context.signal, controller.signal])
      : controller.signal;
    let complete: Promise<{ success: boolean }> | undefined;
    try {
      signal.throwIfAborted();
      const bytes = encoder.encode(JSON.stringify(value));
      assertBackupV2Budget("manifestBytes", bytes.length);
      const plaintextSha256 = digest(bytes),
        key = bindingKey(context.identity, ordinal),
        old = this.#bindings.get(key);
      if (old && old.plaintextSha256 !== plaintextSha256) fail();
      const state = context.journal.state(context.identity, ordinal);
      if (state) {
        if (!old || !state.selected) fail();
        return validateBackupV2ManifestRef({
          object: state.selected,
          plaintextSha256,
        });
      }
      if (!old) {
        const binding = {
          identity: { ...context.identity },
          ordinal,
          plaintextSha256,
        };
        this.#bindings.set(key, binding);
        this.#budget();
        await this.#caps.persistBinding(structuredClone(binding));
      }
      const encrypted = await this.#caps.encrypt(bytes.slice(), signal);
      complete = encrypted.completed.then(
        () => ({ success: true }),
        () => ({ success: false }),
      );
      let total = 0;
      const boundedCiphertext = encrypted.ciphertext.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, output) {
            total += chunk.length;
            assertBackupV2Budget("manifestBytes", total);
            output.enqueue(chunk);
          },
        }),
      );
      let slot:
        | import("./backup-v2-contract.ts").BackupV2SealedSlot
        | undefined;
      for await (const sealed of context.spool.sealed(boundedCiphertext)) {
        if (slot) fail();
        slot = sealed;
      }
      const status = await complete;
      if (!slot || !status.success) fail();
      const object = await uploadSealedBackupV2Object(slot, ordinal, 0, {
        ...context,
        signal,
      });
      this.#budget();
      return validateBackupV2ManifestRef({ object, plaintextSha256 });
    } catch (error) {
      this.#failed = true;
      controller.abort(error);
      if (complete) await complete;
      throw error;
    } finally {
      this.#busy = false;
    }
  }
  async publishChunkPages(
    chunks: readonly BackupV2Chunk[],
  ): Promise<BackupV2PageRef[]> {
    assertBackupV2Budget("logicalObjects", chunks.length);
    if (!chunks.length) fail();
    const identity = this.#caps.upload.identity, pages: BackupV2PageRef[] = [];
    let offset = 0;
    // 256 descriptors leave headroom inside the1MiB encrypted-document cap;
    // actual plaintext and ciphertext size are still checked independently.
    for (let first = 0; first < chunks.length; first += 256) {
      const page = validateBackupV2ChunkPage({
        schemaVersion: 2,
        captureId: identity.captureId,
        attemptId: identity.attemptId,
        role: identity.role,
        pageIndex: pages.length,
        startOrdinal: first,
        startOffset: offset,
        chunks: chunks.slice(first, first + 256),
      });
      const manifest = await this.#publish(page, pages.length, "manifest");
      const bytes = page.chunks.reduce(
        (sum, chunk) => sum + chunk.object.contentLength,
        0,
      );
      pages.push({
        manifest,
        firstOrdinal: first,
        firstOffset: offset,
        chunkCount: page.chunks.length,
        bytes,
      });
      offset += bytes;
    }
    return pages;
  }
  publishRole(value: BackupV2RoleManifest): Promise<BackupV2ManifestRef> {
    const role = validateBackupV2RoleManifest(value),
      identity = this.#caps.upload.identity;
    if (
      role.captureId !== identity.captureId ||
      role.attemptId !== identity.attemptId || role.role !== identity.role
    ) fail();
    return this.#publish(role, role.pages.length, "manifest");
  }
  publishRoot(value: BackupV2Root): Promise<BackupV2ManifestRef> {
    const root = validateBackupV2Root(value),
      identity = this.#caps.upload.identity;
    if (
      root.captureId !== identity.captureId || identity.role !== "recovery" ||
      root.roles.some((role) => role.attemptId === identity.attemptId)
    ) fail();
    return this.#publish(root, 0, "manifest");
  }
  publishReceipt(value: BackupV2Receipt): Promise<BackupV2ManifestRef> {
    const receipt = validateBackupV2Receipt(value);
    if (
      receipt.captureId !== this.#caps.upload.identity.captureId ||
      this.#caps.upload.identity.role !== "recovery"
    ) fail();
    return this.#publish(receipt, 0, "receipt");
  }
  publishVerificationMetadata(
    value: BackupV2VerificationMetadata,
  ): Promise<BackupV2ManifestRef> {
    const metadata = validateBackupV2VerificationMetadata(value);
    if (
      metadata.captureId !== this.#caps.upload.identity.captureId ||
      this.#caps.upload.identity.role !== "recovery"
    ) fail();
    return this.#publish(metadata, 0, "metadata");
  }
}
