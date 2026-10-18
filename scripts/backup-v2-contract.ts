import type { B2Object } from "./backblaze-storage.ts";
import {
  type BackupV2InventorySummary,
  validateBackupV2InventorySummary,
} from "./backup-v2-inventory.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_LIMITS,
  BACKUP_V2_NAMESPACE,
  BACKUP_V2_PROFILE_ID,
} from "./backup-v2-profile.ts";

export const BACKUP_V2_ROLES = [
  "root",
  "efi",
  "staging-boot",
  "staging-efi",
  "oracle-root",
  "oracle-oled",
  "recovery",
] as const;
export type BackupV2Role = typeof BACKUP_V2_ROLES[number];
export type BackupV2ObjectKind =
  | "data"
  | "metadata"
  | "manifest"
  | "receipt"
  | "tools"
  | "inventory";
export type BackupV2Phase =
  | "PREFLIGHT"
  | "CAPTURING_AND_UPLOADING"
  | "CLOUD_COMPLETE"
  | "VERIFYING"
  | "ACCEPTED"
  | "PRUNING"
  | "CLEANED"
  | "FAILED"
  | "CANCELLATION_BLOCKED";
export interface BackupV2ObjectRef extends Omit<B2Object, "action"> {
  action: "upload";
  sha256: string;
}
export interface BackupV2ManifestRef {
  object: BackupV2ObjectRef;
  plaintextSha256: string;
}
export interface BackupV2SlotTarget {
  index: 0 | 1;
  path: string;
}
export interface BackupV2SealedSlot extends BackupV2SlotTarget {
  device: number;
  inode: number;
  bytes: number;
  sha1: string;
  sha256: string;
  uid: 0;
  mode: 384;
  links: 1;
}
export interface BackupV2PutIntent {
  captureId: string;
  role: BackupV2Role;
  attemptId: string;
  kind: BackupV2ObjectKind;
  ordinal: number;
  offset: number;
  putId: string;
  createdAtUtc: string;
  slot: BackupV2SealedSlot;
  name: string;
}
export interface BackupV2Cursor {
  fileName: string;
  fileId: string;
}
export type BackupV2ListedVersion =
  | (Omit<B2Object, "action"> & { action: "upload" })
  | (Omit<B2Object, "action"> & { action: "hide" })
  | (Omit<B2Object, "action"> & { action: "start" });
export interface BackupV2VersionPage {
  items: BackupV2ListedVersion[];
  next: BackupV2Cursor | null;
}
/** One wire request only. PUT returns a provider-bound candidate, not readback
 * proof. GET proves complete readback before returning a sealed slot. Callers
 * own durable intents, retries, reconciliation and reclaim. */
export interface BackupV2ObjectStore {
  putFileOnce(
    intent: BackupV2PutIntent,
    signal?: AbortSignal,
  ): Promise<BackupV2ObjectRef>;
  /** Stream and discard the complete exact-ID readback; verify name, length,
   * SHA1 and SHA256 before resolving. Allocate no payload file or slot and
   * never overwrite sealed upload bytes while both ciphertext slots are busy. */
  verifyExactReadback(
    object: BackupV2ObjectRef,
    signal?: AbortSignal,
  ): Promise<void>;
  getExactToFile(
    object: BackupV2ObjectRef,
    target: BackupV2SlotTarget,
    signal?: AbortSignal,
  ): Promise<BackupV2SealedSlot>;
  versionsPage(
    prefix: string,
    cursor: BackupV2Cursor | null,
    signal?: AbortSignal,
  ): Promise<BackupV2VersionPage>;
}
export interface BackupV2Chunk {
  ordinal: number;
  offset: number;
  object: BackupV2ObjectRef;
}
export interface BackupV2ChunkPage {
  schemaVersion: 2;
  captureId: string;
  attemptId: string;
  role: BackupV2Role;
  pageIndex: number;
  startOrdinal: number;
  startOffset: number;
  chunks: BackupV2Chunk[];
}
export interface BackupV2PageRef {
  manifest: BackupV2ManifestRef;
  firstOrdinal: number;
  firstOffset: number;
  chunkCount: number;
  bytes: number;
}
export interface BackupV2ProducerProof {
  tarExitCode: 0 | 1;
  zstdExitCode: 0;
  gpgExitCode: 0;
  driftRecords: number;
  driftSha256: string;
}
export interface BackupV2ArchiveDescriptor {
  role: BackupV2Role;
  format: "tar.zst.gpg" | "json.zst.gpg";
  ciphertextBytes: number;
  ciphertextSha256: string;
}
export interface BackupV2ArchiveSourceDescriptor
  extends BackupV2ArchiveDescriptor {
  /** Trusted legacy receipt expectation, when available; measured output is still required. */
  compressedPlaintext?: { bytes: number; sha256: string };
}
export interface BackupV2RoleManifest extends BackupV2ArchiveDescriptor {
  schemaVersion: 2;
  captureId: string;
  attemptId: string;
  sourceConfigSha256: string;
  compatibilitySha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
  captureStartedAtUtc: string;
  captureFinishedAtUtc: string;
  uploadStartedAtUtc: string;
  uploadFinishedAtUtc: string;
  pages: BackupV2PageRef[];
  inventory: BackupV2InventorySummary | null;
  producer: BackupV2ProducerProof;
  metadata: BackupV2ObjectRef[];
}
export interface BackupV2Root {
  schemaVersion: 2;
  format: "backup-v2";
  profile: typeof BACKUP_V2_PROFILE_ID;
  captureId: string;
  periodKey: string;
  sourceRevision: string;
  sourceConfigSha256: string;
  recipientSha256: string;
  recipientFingerprint: string;
  roles: {
    role: BackupV2Role;
    attemptId: string;
    manifest: BackupV2ManifestRef;
    captureStartedAtUtc: string;
    captureFinishedAtUtc: string;
  }[];
  metadata: BackupV2ObjectRef[];
}
export interface BackupV2ByteSink {
  write(bytes: Uint8Array): Promise<number>;
}
/** The factory may replay a role for bounded linked boot-member resolution. */
export type BackupV2CiphertextFactory = (
  role: BackupV2Role,
) => ReadableStream<Uint8Array>;
export type BackupV2DecryptStream = (
  ciphertext: ReadableStream<Uint8Array>,
  sink: BackupV2ByteSink,
) => Promise<{ integrityChecked: true }>;
export interface BackupV2SampleExpectation {
  role: "root" | "staging-boot";
  member: Uint8Array;
  sha256: string;
  contentMember?: Uint8Array;
  bytes?: number;
}
export const BACKUP_V2_BOOT_SAMPLES = [
  { role: "root", member: "./boot/Image" },
  { role: "root", member: "./boot/initramfs-linux.img" },
  { role: "staging-boot", member: "./arch-vmlinuz" },
  { role: "staging-boot", member: "./arch-initrd.img" },
] as const;
export interface BackupV2ArchiveProof extends BackupV2ArchiveDescriptor {
  compressedBytes: number;
  compressedSha256: string;
  inventory: BackupV2InventorySummary | null;
  inputComplete: true;
  integrityChecked: true;
  decompressionComplete: true;
  gpgExitCode: 0;
  zstdExitCode: 0;
  tarExitCode: 0;
}
export interface BackupV2Receipt {
  schemaVersion: 2;
  format: "backup-v2";
  captureId: string;
  root: BackupV2ManifestRef;
  verifiedAtUtc: string;
  recipientSha256: string;
  recipientFingerprint: string;
  verifierRevision: string;
  configurationSha256: string;
  tools: { tar: string; zstd: string; gpg: string };
  archives: BackupV2ArchiveProof[];
  bootSamples: {
    role: "root" | "staging-boot";
    member: string;
    bytes: number;
    sha256: string;
  }[];
  metadataSha256: string;
  sourceIndependent: true;
  decryptedRestoreProved: true;
  machineBootRestoreProved: false;
}
export interface BackupV2Progress {
  phase: BackupV2Phase;
  observedMonotonicMs: number;
  sourceBytes: number;
  compressionInputBytes: number;
  verifiedChunks: number;
  decryptedBytes: number;
  /** Cumulative tar-decoder output across at most three verification passes. */
  decodedBytes?: number;
  inventoryMembers: number;
}
export interface BackupV2LeaseWindow {
  observedMonotonicMs: number;
  usefulProgressAtMs: number;
  usefulProgressExpiresAtMs: number;
  retryEpisode: { startedAtMs: number; expiresAtMs: number } | null;
  transferEpisode?: BackupV2TransferEpisode | null;
}
export const BACKUP_V2_CONTROL_REQUEST_MS = 120_000;
export const BACKUP_V2_TRANSFER_SETTLEMENT_MS = 30_000;
export type BackupV2TransferPhase = "PUT" | "READBACK";
export interface BackupV2TransferEpisode {
  kind: "SEALED_TRANSFER";
  operationId: string;
  phase: BackupV2TransferPhase;
  sealedObjectIdentity: string;
  retainedBytes: number;
  startedAtMs: number;
  expiresAtMs: number;
}
/** Upper wait bound from actual M02 calls: authorization/upload-target/PUT,
 * or authorization/exact GET, then bounded native request settlement. */
export function backupV2TransferWindowMs(phase: BackupV2TransferPhase): number {
  if (phase !== "PUT" && phase !== "READBACK") fail();
  return (phase === "PUT" ? 2 : 1) * BACKUP_V2_CONTROL_REQUEST_MS +
    BACKUP_V2_LIMITS.blockedTransportMs + BACKUP_V2_TRANSFER_SETTLEMENT_MS;
}
export function validateBackupV2TransferEpisode(
  value: unknown,
  observedMonotonicMs: number,
): BackupV2TransferEpisode {
  const r = object(value, [
    "kind",
    "operationId",
    "phase",
    "sealedObjectIdentity",
    "retainedBytes",
    "startedAtMs",
    "expiresAtMs",
  ]);
  if (
    r.kind !== "SEALED_TRANSFER" ||
    (r.phase !== "PUT" && r.phase !== "READBACK")
  ) fail();
  const phase = r.phase,
    operationId = text(r.operationId, 1024),
    sealedObjectIdentity = text(r.sealedObjectIdentity, 1024);
  const retainedBytes = assertBackupV2Budget(
      "slotBytes",
      r.retainedBytes as number,
    ),
    startedAtMs = monotonic(r.startedAtMs),
    expiresAtMs = monotonic(r.expiresAtMs);
  if (
    retainedBytes < 1 || startedAtMs > monotonic(observedMonotonicMs) ||
    expiresAtMs < startedAtMs ||
    expiresAtMs - startedAtMs > backupV2TransferWindowMs(phase)
  ) fail();
  return {
    kind: "SEALED_TRANSFER",
    operationId,
    phase,
    sealedObjectIdentity,
    retainedBytes,
    startedAtMs,
    expiresAtMs,
  };
}
export interface BackupV2ReachabilityReader {
  references(root: BackupV2ManifestRef): Promise<readonly BackupV2ObjectRef[]>;
}
export interface BackupV2ProtectedReferences {
  acceptedRoots: readonly BackupV2ManifestRef[];
  activeObjects: readonly BackupV2ObjectRef[];
  sealedRoleManifests: readonly BackupV2ManifestRef[];
  unresolvedPuts: readonly BackupV2PutIntent[];
}

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const NAME = new RegExp(
  `^restic/backup-v2/(generation-${UUID})/(${UUID})/(data|metadata|manifest|receipt|tools|inventory)/([0-9]{8})/(${UUID})$`,
);
function fail(): never {
  throw new Error("Backup v2 contract is invalid");
}
function hasControlCharacter(value: string): boolean {
  return [...value].some((character) =>
    character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127
  );
}
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail();
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) fail();
  return record;
}
function text(value: unknown, maximum = 512): string {
  if (
    typeof value !== "string" || value.length === 0 || value.length > maximum ||
    hasControlCharacter(value) ||
    new TextEncoder().encode(value).length > maximum
  ) fail();
  return value;
}
function hash(value: unknown, length = 64): string {
  const result = text(value, length);
  if (!new RegExp(`^[0-9a-f]{${length}}$`).test(result)) fail();
  return result;
}
function integer(
  value: unknown,
  maximum = Number.MAX_SAFE_INTEGER,
  minimum = 0,
): number {
  if (
    typeof value !== "number" || !Number.isSafeInteger(value) ||
    value < minimum || value > maximum
  ) fail();
  return value;
}
function monotonic(value: unknown): number {
  if (
    typeof value !== "number" || !Number.isFinite(value) || value < 0 ||
    value > Number.MAX_SAFE_INTEGER
  ) fail();
  return value;
}
function utc(value: unknown): string {
  const result = text(value, 24);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(result) ||
    !Number.isFinite(Date.parse(result)) ||
    new Date(result).toISOString() !== result
  ) fail();
  return result;
}
function role(value: unknown): BackupV2Role {
  if (!BACKUP_V2_ROLES.includes(value as BackupV2Role)) fail();
  return value as BackupV2Role;
}
function uuid(value: unknown): string {
  const result = text(value, 36);
  if (!new RegExp(`^${UUID}$`).test(result)) fail();
  return result;
}
function capture(value: unknown): string {
  const result = text(value, 47);
  if (!new RegExp(`^generation-${UUID}$`).test(result)) fail();
  return result;
}
function fingerprint(value: unknown): string {
  const result = text(value, 64);
  if (!/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(result)) fail();
  return result;
}
function boundedArray(
  value: unknown,
  maximum: number = BACKUP_V2_LIMITS.logicalObjects,
): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) fail();
  return value;
}
function pageSize(value: unknown): void {
  if (
    new TextEncoder().encode(JSON.stringify(value)).length >
      BACKUP_V2_LIMITS.manifestBytes
  ) fail();
}
function format(
  value: unknown,
  archiveRole: BackupV2Role,
): "tar.zst.gpg" | "json.zst.gpg" {
  const expected = archiveRole === "recovery" ? "json.zst.gpg" : "tar.zst.gpg";
  if (value !== expected) fail();
  return expected;
}
export function backupV2ObjectName(
  captureId: string,
  attemptId: string,
  kind: BackupV2ObjectKind,
  ordinal: number,
  putId: string,
): string {
  const name = `${BACKUP_V2_NAMESPACE}${capture(captureId)}/${
    uuid(attemptId)
  }/${kind}/${
    integer(ordinal, BACKUP_V2_LIMITS.logicalObjects - 1).toString().padStart(
      8,
      "0",
    )
  }/${uuid(putId)}`;
  parseBackupV2ObjectName(name);
  return name;
}
export function parseBackupV2ObjectName(value: unknown) {
  const name = text(value, 1000), match = NAME.exec(name);
  if (!match || Number(match[4]) >= BACKUP_V2_LIMITS.logicalObjects) fail();
  return {
    captureId: match[1],
    attemptId: match[2],
    kind: match[3] as BackupV2ObjectKind,
    ordinal: Number(match[4]),
    putId: match[5],
  };
}
export function validateBackupV2ObjectRef(value: unknown): BackupV2ObjectRef {
  const r = object(value, [
    "fileId",
    "fileName",
    "contentLength",
    "contentSha1",
    "uploadTimestamp",
    "action",
    "sha256",
  ]);
  parseBackupV2ObjectName(r.fileName);
  if (r.action !== "upload") fail();
  const result: BackupV2ObjectRef = {
    fileId: text(r.fileId),
    fileName: r.fileName as string,
    contentLength: integer(r.contentLength, BACKUP_V2_LIMITS.slotBytes, 1),
    contentSha1: hash(r.contentSha1, 40),
    uploadTimestamp: integer(r.uploadTimestamp),
    action: "upload",
    sha256: hash(r.sha256),
  };
  if (
    new TextEncoder().encode(JSON.stringify(result)).length >
      BACKUP_V2_LIMITS.descriptorBytes
  ) fail();
  return result;
}
export function validateBackupV2ManifestRef(
  value: unknown,
): BackupV2ManifestRef {
  const r = object(value, ["object", "plaintextSha256"]);
  const ref = validateBackupV2ObjectRef(r.object);
  if (ref.contentLength > BACKUP_V2_LIMITS.manifestBytes) fail();
  return { object: ref, plaintextSha256: hash(r.plaintextSha256) };
}
export function validateBackupV2Cursor(value: unknown): BackupV2Cursor {
  const r = object(value, ["fileName", "fileId"]);
  parseBackupV2ObjectName(r.fileName);
  return { fileName: r.fileName as string, fileId: text(r.fileId) };
}
export function validateBackupV2VersionPage(
  value: unknown,
): BackupV2VersionPage {
  const r = object(value, ["items", "next"]);
  const items = boundedArray(r.items, BACKUP_V2_LIMITS.listEntries).map(
    (value): BackupV2ListedVersion => {
      const item = object(value, [
        "fileId",
        "fileName",
        "contentLength",
        "contentSha1",
        "uploadTimestamp",
        "action",
      ]);
      parseBackupV2ObjectName(item.fileName);
      if (
        item.action !== "upload" && item.action !== "hide" &&
        item.action !== "start"
      ) fail();
      if (
        typeof item.contentSha1 !== "string" || item.contentSha1.length > 40 ||
        hasControlCharacter(item.contentSha1)
      ) fail();
      return {
        fileId: text(item.fileId),
        fileName: item.fileName as string,
        contentLength: integer(item.contentLength, BACKUP_V2_LIMITS.slotBytes),
        contentSha1: item.action === "upload"
          ? hash(item.contentSha1, 40)
          : item.contentSha1,
        uploadTimestamp: integer(item.uploadTimestamp),
        action: item.action,
      };
    },
  );
  return {
    items,
    next: r.next === null ? null : validateBackupV2Cursor(r.next),
  };
}
export function validateBackupV2SealedSlot(value: unknown): BackupV2SealedSlot {
  const r = object(value, [
    "index",
    "path",
    "device",
    "inode",
    "bytes",
    "sha1",
    "sha256",
    "uid",
    "mode",
    "links",
  ]);
  const path = text(r.path, 1000);
  if (
    !path.startsWith("/") || path.endsWith("/") || path.includes("//") ||
    path.split("/").some((part) => part === "." || part === "..") ||
    r.uid !== 0 || r.mode !== 384 || r.links !== 1
  ) fail();
  return {
    index: integer(r.index, 1) as 0 | 1,
    path,
    device: integer(r.device),
    inode: integer(r.inode, Number.MAX_SAFE_INTEGER, 1),
    bytes: integer(r.bytes, BACKUP_V2_LIMITS.slotBytes, 1),
    sha1: hash(r.sha1, 40),
    sha256: hash(r.sha256),
    uid: 0,
    mode: 384,
    links: 1,
  };
}
export function validateBackupV2PutIntent(value: unknown): BackupV2PutIntent {
  const r = object(value, [
    "captureId",
    "role",
    "attemptId",
    "kind",
    "ordinal",
    "offset",
    "putId",
    "createdAtUtc",
    "slot",
    "name",
  ]);
  const parsed = parseBackupV2ObjectName(r.name);
  if (
    r.captureId !== parsed.captureId || r.attemptId !== parsed.attemptId ||
    r.kind !== parsed.kind || r.ordinal !== parsed.ordinal ||
    r.putId !== parsed.putId
  ) fail();
  const slot = validateBackupV2SealedSlot(r.slot),
    offset = integer(r.offset, BACKUP_V2_LIMITS.ciphertextBytes);
  assertBackupV2Budget("ciphertextBytes", offset + slot.bytes);
  return {
    ...parsed,
    role: role(r.role),
    offset,
    createdAtUtc: utc(r.createdAtUtc),
    slot,
    name: r.name as string,
  };
}
export function validateBackupV2ChunkPage(value: unknown): BackupV2ChunkPage {
  const r = object(value, [
    "schemaVersion",
    "captureId",
    "attemptId",
    "role",
    "pageIndex",
    "startOrdinal",
    "startOffset",
    "chunks",
  ]);
  if (r.schemaVersion !== 2) fail();
  const captureId = capture(r.captureId),
    attemptId = uuid(r.attemptId),
    archiveRole = role(r.role);
  let ordinal = integer(r.startOrdinal, BACKUP_V2_LIMITS.logicalObjects - 1),
    offset = integer(r.startOffset, BACKUP_V2_LIMITS.ciphertextBytes);
  const chunks = boundedArray(r.chunks).map((value) => {
    const chunk = object(value, ["ordinal", "offset", "object"]),
      ref = validateBackupV2ObjectRef(chunk.object);
    const name = parseBackupV2ObjectName(ref.fileName);
    if (
      chunk.ordinal !== ordinal || chunk.offset !== offset ||
      name.captureId !== captureId || name.attemptId !== attemptId ||
      name.kind !== "data" || name.ordinal !== ordinal
    ) fail();
    const result = { ordinal, offset, object: ref };
    ordinal++;
    offset += ref.contentLength;
    assertBackupV2Budget("ciphertextBytes", offset);
    return result;
  });
  if (!chunks.length) fail();
  const result: BackupV2ChunkPage = {
    schemaVersion: 2,
    captureId,
    attemptId,
    role: archiveRole,
    pageIndex: integer(r.pageIndex, BACKUP_V2_LIMITS.logicalObjects - 1),
    startOrdinal: r.startOrdinal as number,
    startOffset: r.startOffset as number,
    chunks,
  };
  pageSize(result);
  return result;
}
export function validateBackupV2RoleManifest(
  value: unknown,
): BackupV2RoleManifest {
  const r = object(value, [
    "schemaVersion",
    "captureId",
    "attemptId",
    "role",
    "format",
    "ciphertextBytes",
    "ciphertextSha256",
    "sourceConfigSha256",
    "compatibilitySha256",
    "recipientSha256",
    "recipientFingerprint",
    "captureStartedAtUtc",
    "captureFinishedAtUtc",
    "uploadStartedAtUtc",
    "uploadFinishedAtUtc",
    "pages",
    "inventory",
    "producer",
    "metadata",
  ]);
  if (r.schemaVersion !== 2) fail();
  const captureId = capture(r.captureId),
    attemptId = uuid(r.attemptId),
    archiveRole = role(r.role);
  const started = utc(r.captureStartedAtUtc),
    finished = utc(r.captureFinishedAtUtc),
    uploadStarted = utc(r.uploadStartedAtUtc),
    uploaded = utc(r.uploadFinishedAtUtc);
  if (
    started >= finished || uploadStarted < started || uploaded < finished ||
    uploadStarted > uploaded
  ) fail();
  let ordinal = 0, offset = 0;
  const pages = boundedArray(r.pages).map((value) => {
    const p = object(value, [
      "manifest",
      "firstOrdinal",
      "firstOffset",
      "chunkCount",
      "bytes",
    ]);
    const manifest = validateBackupV2ManifestRef(p.manifest),
      name = parseBackupV2ObjectName(manifest.object.fileName);
    if (
      name.captureId !== captureId || name.attemptId !== attemptId ||
      name.kind !== "manifest" || p.firstOrdinal !== ordinal ||
      p.firstOffset !== offset
    ) fail();
    const chunkCount = integer(
        p.chunkCount,
        BACKUP_V2_LIMITS.logicalObjects,
        1,
      ),
      bytes = integer(p.bytes, BACKUP_V2_LIMITS.ciphertextBytes, 1);
    if (bytes > chunkCount * BACKUP_V2_LIMITS.slotBytes || bytes < chunkCount) {
      fail();
    }
    const result = {
      manifest,
      firstOrdinal: ordinal,
      firstOffset: offset,
      chunkCount,
      bytes,
    };
    ordinal += chunkCount;
    offset += bytes;
    assertBackupV2Budget("logicalObjects", ordinal);
    assertBackupV2Budget("ciphertextBytes", offset);
    return result;
  });
  if (!pages.length || offset !== r.ciphertextBytes) fail();
  const p = object(r.producer, [
    "tarExitCode",
    "zstdExitCode",
    "gpgExitCode",
    "driftRecords",
    "driftSha256",
  ]);
  const driftRecords = integer(p.driftRecords, BACKUP_V2_LIMITS.members);
  if (
    p.zstdExitCode !== 0 || p.gpgExitCode !== 0 ||
    (p.tarExitCode !== 0 && p.tarExitCode !== 1) ||
    (p.tarExitCode === 1 && (archiveRole !== "root" || driftRecords === 0))
  ) fail();
  const inventory = r.inventory === null
    ? null
    : validateBackupV2InventorySummary(r.inventory);
  if (
    (archiveRole !== "recovery" && (!inventory || inventory.members === 0)) ||
    (archiveRole === "recovery" && inventory !== null)
  ) fail();
  const result: BackupV2RoleManifest = {
    schemaVersion: 2,
    captureId,
    attemptId,
    role: archiveRole,
    format: format(r.format, archiveRole),
    ciphertextBytes: offset,
    ciphertextSha256: hash(r.ciphertextSha256),
    sourceConfigSha256: hash(r.sourceConfigSha256),
    compatibilitySha256: hash(r.compatibilitySha256),
    recipientSha256: hash(r.recipientSha256),
    recipientFingerprint: fingerprint(r.recipientFingerprint),
    captureStartedAtUtc: started,
    captureFinishedAtUtc: finished,
    uploadStartedAtUtc: uploadStarted,
    uploadFinishedAtUtc: uploaded,
    pages,
    inventory,
    producer: {
      tarExitCode: p.tarExitCode,
      zstdExitCode: 0,
      gpgExitCode: 0,
      driftRecords,
      driftSha256: hash(p.driftSha256),
    },
    metadata: boundedArray(r.metadata).map(validateBackupV2ObjectRef),
  };
  pageSize(result);
  return result;
}
export function validateBackupV2Root(value: unknown): BackupV2Root {
  const r = object(value, [
    "schemaVersion",
    "format",
    "profile",
    "captureId",
    "periodKey",
    "sourceRevision",
    "sourceConfigSha256",
    "recipientSha256",
    "recipientFingerprint",
    "roles",
    "metadata",
  ]);
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2" ||
    r.profile !== BACKUP_V2_PROFILE_ID
  ) fail();
  const periodKey = text(r.periodKey, 10);
  const date = new Date(`${periodKey}T00:00:00.000Z`);
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(periodKey) ||
    !Number.isFinite(date.getTime()) ||
    date.toISOString().slice(0, 10) !== periodKey || date.getUTCDay() !== 0
  ) fail();
  const roles = boundedArray(r.roles, 7).map((value, index) => {
    const item = object(value, [
      "role",
      "attemptId",
      "manifest",
      "captureStartedAtUtc",
      "captureFinishedAtUtc",
    ]);
    const archiveRole = role(item.role),
      attemptId = uuid(item.attemptId),
      manifest = validateBackupV2ManifestRef(item.manifest);
    const name = parseBackupV2ObjectName(manifest.object.fileName),
      started = utc(item.captureStartedAtUtc),
      finished = utc(item.captureFinishedAtUtc);
    // A reused manifest may originate in a different capture. Never rewrite its interval.
    if (
      archiveRole !== BACKUP_V2_ROLES[index] || name.attemptId !== attemptId ||
      name.kind !== "manifest" || started >= finished
    ) fail();
    return {
      role: archiveRole,
      attemptId,
      manifest,
      captureStartedAtUtc: started,
      captureFinishedAtUtc: finished,
    };
  });
  if (roles.length !== 7) fail();
  const result: BackupV2Root = {
    schemaVersion: 2,
    format: "backup-v2",
    profile: BACKUP_V2_PROFILE_ID,
    captureId: capture(r.captureId),
    periodKey,
    sourceRevision: hash(r.sourceRevision, 40),
    sourceConfigSha256: hash(r.sourceConfigSha256),
    recipientSha256: hash(r.recipientSha256),
    recipientFingerprint: fingerprint(r.recipientFingerprint),
    roles,
    metadata: boundedArray(r.metadata).map(validateBackupV2ObjectRef),
  };
  pageSize(result);
  return result;
}
/** Structural validation is not empirical proof; only the verifier may produce this. */
export function validateBackupV2ArchiveProof(
  value: unknown,
): BackupV2ArchiveProof {
  const r = object(value, [
    "role",
    "format",
    "ciphertextBytes",
    "ciphertextSha256",
    "compressedBytes",
    "compressedSha256",
    "inventory",
    "inputComplete",
    "integrityChecked",
    "decompressionComplete",
    "gpgExitCode",
    "zstdExitCode",
    "tarExitCode",
  ]);
  const archiveRole = role(r.role),
    inventory = r.inventory === null
      ? null
      : validateBackupV2InventorySummary(r.inventory);
  if (
    r.inputComplete !== true || r.integrityChecked !== true ||
    r.decompressionComplete !== true || r.gpgExitCode !== 0 ||
    r.zstdExitCode !== 0 || r.tarExitCode !== 0 ||
    (archiveRole !== "recovery" && (!inventory || inventory.members === 0)) ||
    (archiveRole === "recovery" && inventory !== null)
  ) fail();
  return {
    role: archiveRole,
    format: format(r.format, archiveRole),
    ciphertextBytes: integer(
      r.ciphertextBytes,
      BACKUP_V2_LIMITS.ciphertextBytes,
      1,
    ),
    ciphertextSha256: hash(r.ciphertextSha256),
    compressedBytes: integer(
      r.compressedBytes,
      BACKUP_V2_LIMITS.ciphertextBytes,
      1,
    ),
    compressedSha256: hash(r.compressedSha256),
    inventory,
    inputComplete: true,
    integrityChecked: true,
    decompressionComplete: true,
    gpgExitCode: 0,
    zstdExitCode: 0,
    tarExitCode: 0,
  };
}
export function validateBackupV2Receipt(value: unknown): BackupV2Receipt {
  const r = object(value, [
    "schemaVersion",
    "format",
    "captureId",
    "root",
    "verifiedAtUtc",
    "recipientSha256",
    "recipientFingerprint",
    "verifierRevision",
    "configurationSha256",
    "tools",
    "archives",
    "bootSamples",
    "metadataSha256",
    "sourceIndependent",
    "decryptedRestoreProved",
    "machineBootRestoreProved",
  ]);
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2" ||
    r.sourceIndependent !== true || r.decryptedRestoreProved !== true ||
    r.machineBootRestoreProved !== false
  ) fail();
  const captureId = capture(r.captureId),
    root = validateBackupV2ManifestRef(r.root),
    name = parseBackupV2ObjectName(root.object.fileName);
  if (name.captureId !== captureId || name.kind !== "manifest") fail();
  const archives = boundedArray(r.archives, 7).map(
    validateBackupV2ArchiveProof,
  );
  if (
    archives.length !== 7 ||
    archives.some((archive, index) => archive.role !== BACKUP_V2_ROLES[index])
  ) fail();
  assertBackupV2Budget(
    "ciphertextBytes",
    archives.reduce((total, archive) => total + archive.ciphertextBytes, 0),
  );
  const bootSamples = boundedArray(r.bootSamples, 4).map((value, index) => {
    const s = object(value, ["role", "member", "bytes", "sha256"]),
      expected = BACKUP_V2_BOOT_SAMPLES[index];
    if (!expected || s.role !== expected.role || s.member !== expected.member) {
      fail();
    }
    return {
      role: expected.role,
      member: expected.member,
      bytes: integer(s.bytes, BACKUP_V2_LIMITS.logicalSourceBytes, 1),
      sha256: hash(s.sha256),
    };
  });
  if (bootSamples.length !== 4) fail();
  const tools = object(r.tools, ["tar", "zstd", "gpg"]);
  const result: BackupV2Receipt = {
    schemaVersion: 2,
    format: "backup-v2",
    captureId,
    root,
    verifiedAtUtc: utc(r.verifiedAtUtc),
    recipientSha256: hash(r.recipientSha256),
    recipientFingerprint: fingerprint(r.recipientFingerprint),
    verifierRevision: hash(r.verifierRevision, 40),
    configurationSha256: hash(r.configurationSha256),
    tools: {
      tar: text(tools.tar),
      zstd: text(tools.zstd),
      gpg: text(tools.gpg),
    },
    archives,
    bootSamples,
    metadataSha256: hash(r.metadataSha256),
    sourceIndependent: true,
    decryptedRestoreProved: true,
    machineBootRestoreProved: false,
  };
  pageSize(result);
  return result;
}
export function validateBackupV2Progress(value: unknown): BackupV2Progress {
  const r = object(value, [
    "phase",
    "observedMonotonicMs",
    "sourceBytes",
    "compressionInputBytes",
    "verifiedChunks",
    "decryptedBytes",
    "inventoryMembers",
    ...(value && typeof value === "object" &&
        Object.hasOwn(value, "decodedBytes")
      ? ["decodedBytes"]
      : []),
  ]);
  const phases: BackupV2Phase[] = [
    "PREFLIGHT",
    "CAPTURING_AND_UPLOADING",
    "CLOUD_COMPLETE",
    "VERIFYING",
    "ACCEPTED",
    "PRUNING",
    "CLEANED",
    "FAILED",
    "CANCELLATION_BLOCKED",
  ];
  if (!phases.includes(r.phase as BackupV2Phase)) fail();
  return {
    phase: r.phase as BackupV2Phase,
    observedMonotonicMs: monotonic(r.observedMonotonicMs),
    sourceBytes: integer(r.sourceBytes, BACKUP_V2_LIMITS.logicalSourceBytes),
    compressionInputBytes: integer(
      r.compressionInputBytes,
      BACKUP_V2_LIMITS.logicalSourceBytes,
    ),
    verifiedChunks: integer(r.verifiedChunks, BACKUP_V2_LIMITS.logicalObjects),
    decryptedBytes: integer(
      r.decryptedBytes,
      BACKUP_V2_LIMITS.decryptionWorkBytes,
    ),
    ...(Object.hasOwn(r, "decodedBytes")
      ? {
        decodedBytes: integer(
          r.decodedBytes,
          BACKUP_V2_LIMITS.decoderWorkBytes,
        ),
      }
      : {}),
    inventoryMembers: integer(r.inventoryMembers, BACKUP_V2_LIMITS.members),
  };
}
export function validateBackupV2LeaseWindow(
  value: unknown,
): BackupV2LeaseWindow {
  const r = object(value, [
    "observedMonotonicMs",
    "usefulProgressAtMs",
    "usefulProgressExpiresAtMs",
    "retryEpisode",
    ...(value && typeof value === "object" &&
        Object.hasOwn(value, "transferEpisode")
      ? ["transferEpisode"]
      : []),
  ]);
  const observedMonotonicMs = monotonic(r.observedMonotonicMs),
    usefulProgressAtMs = monotonic(r.usefulProgressAtMs),
    usefulProgressExpiresAtMs = monotonic(r.usefulProgressExpiresAtMs);
  if (
    usefulProgressAtMs > observedMonotonicMs ||
    usefulProgressExpiresAtMs < usefulProgressAtMs
  ) fail();
  let retryEpisode: BackupV2LeaseWindow["retryEpisode"] = null;
  if (r.retryEpisode !== null) {
    const e = object(r.retryEpisode, ["startedAtMs", "expiresAtMs"]),
      startedAtMs = monotonic(e.startedAtMs),
      expiresAtMs = monotonic(e.expiresAtMs);
    if (
      startedAtMs > observedMonotonicMs || expiresAtMs < startedAtMs ||
      expiresAtMs - startedAtMs > BACKUP_V2_LIMITS.blockedTransportMs
    ) fail();
    retryEpisode = { startedAtMs, expiresAtMs };
  }
  return {
    observedMonotonicMs,
    usefulProgressAtMs,
    usefulProgressExpiresAtMs,
    retryEpisode,
    ...(Object.hasOwn(r, "transferEpisode")
      ? {
        transferEpisode: r.transferEpisode === null
          ? null
          : validateBackupV2TransferEpisode(
            r.transferEpisode,
            observedMonotonicMs,
          ),
      }
      : {}),
  };
}
