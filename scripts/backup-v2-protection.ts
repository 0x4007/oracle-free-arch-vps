/** Bounded source/control copies of a verified cloud graph. No archive payload,
 * credential or decryption capability belongs in these documents. */
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  type BackupV2ProtectedReferences,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
} from "./backup-v2-contract.ts";
import { BACKUP_V2_LIMITS, BACKUP_V2_WORKSPACE } from "./backup-v2-profile.ts";
import type {
  BackupRuntimeCatalogEntry,
  BackupV2Gate,
} from "./backup-v2-runtime-contract.ts";

export const BACKUP_V2_PROTECTION_PAGE_OBJECTS = 100;
export const BACKUP_V2_PROTECTION_SOURCE_BASE =
  "/var/tmp/arch-vps-file-backup-runtime/protection";
export const BACKUP_V2_PROTECTION_CONTROL_BASE =
  ".private/file-backup/protection";
export interface BackupV2ProtectionPage {
  schemaVersion: 2;
  format: "backup-v2-protection-page";
  rootPlaintextSha256: string;
  pageIndex: number;
  objects: BackupV2ObjectRef[];
}
export interface BackupV2ProtectionPageRef {
  pageIndex: number;
  sha256: string;
  bytes: number;
  objects: number;
}
export interface BackupV2ProtectionManifest {
  schemaVersion: 2;
  format: "backup-v2-protection";
  root: BackupV2ManifestRef;
  pages: BackupV2ProtectionPageRef[];
  objectCount: number;
  totalPageBytes: number;
}
export interface BackupV2ProtectionDescriptor {
  schemaVersion: 2;
  format: "backup-v2-protection";
  root: BackupV2ManifestRef;
  manifestSha256: string;
  manifestBytes: number;
  pageCount: number;
  objectCount: number;
  totalPageBytes: number;
}
export interface BackupV2ProtectionBundle {
  descriptor: BackupV2ProtectionDescriptor;
  manifest: BackupV2ProtectionManifest;
  manifestBytes: Uint8Array;
  pages: { value: BackupV2ProtectionPage; bytes: Uint8Array }[];
}
export interface BackupV2PrunePlanReference {
  /** Exact persisted JSON bytes, distinct from M06's canonical plan digest. */
  sha256: string;
  bytes: number;
  digest: string;
}
/** Source-only maintenance input. PLAN/EXECUTE are versioned internal stages,
 * never new product flags. An execution plan is a separately hash-bound file. */
export interface BackupV2PruneInput {
  schemaVersion: 2;
  format: "backup-v2-prune";
  gate: BackupV2Gate;
  transactionId: string;
  stage: "PLAN" | "EXECUTE";
  snapshot: {
    custody: { lockId: string; sourceBootId: string; sourceSettled: true };
    catalog: BackupRuntimeCatalogEntry[];
    protection: BackupV2ProtectedReferences;
    receipts: BackupV2ManifestRef[];
  };
  graphs: BackupV2ProtectionDescriptor[];
  plan: BackupV2PrunePlanReference | null;
}
export interface BackupV2PruneProgress {
  /** Actual refs/inventory/journal/delete outcomes processed, never polls. */
  inventoryMembers: number;
}
export interface BackupV2PruneResult {
  schemaVersion: 2;
  format: "backup-v2-prune-result";
  gate: BackupV2Gate;
  transactionId: string;
  stage: "PLAN" | "EXECUTE";
  state: "PLAN_PROVED" | "COMPLETE" | "PARTIAL";
  plan: BackupV2PrunePlanReference;
  retainedCaptureIds: string[];
  obsoleteLegacyCaptureIds: string[];
  finishedAtUtc: string;
}

const bytes = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value) + "\n");
const sha = (value: Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
function fail(): never {
  throw new Error("Backup v2 protected graph invalid or incomplete");
}
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const r = value as Record<string, unknown>;
  if (
    Object.keys(r).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(r, key))
  ) fail();
  return r;
}
function count(value: unknown, max: number, min = 0): number {
  if (
    !Number.isSafeInteger(value) || (value as number) < min ||
    (value as number) > max
  ) fail();
  return value as number;
}
function hash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail();
  return value;
}
export function backupV2ProtectionPageName(index: number): string {
  return `page-${
    String(count(index, BACKUP_V2_LIMITS.pruneCandidates)).padStart(8, "0")
  }.json`;
}
export function validateBackupV2ProtectionDescriptor(
  value: unknown,
): BackupV2ProtectionDescriptor {
  const r = object(value, [
    "schemaVersion",
    "format",
    "root",
    "manifestSha256",
    "manifestBytes",
    "pageCount",
    "objectCount",
    "totalPageBytes",
  ]);
  if (r.schemaVersion !== 2 || r.format !== "backup-v2-protection") fail();
  const pageCount = count(r.pageCount, BACKUP_V2_LIMITS.pruneCandidates, 1),
    objectCount = count(r.objectCount, BACKUP_V2_LIMITS.pruneCandidates, 1);
  if (
    pageCount !== Math.ceil(objectCount / BACKUP_V2_PROTECTION_PAGE_OBJECTS)
  ) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-protection",
    root: validateBackupV2ManifestRef(r.root),
    manifestSha256: hash(r.manifestSha256),
    manifestBytes: count(
      r.manifestBytes,
      BACKUP_V2_LIMITS.controlResponseBytes,
      1,
    ),
    pageCount,
    objectCount,
    totalPageBytes: count(r.totalPageBytes, BACKUP_V2_WORKSPACE.retention, 1),
  };
}
export function backupV2ProtectionSourceDirectory(digest: string): string {
  return `${BACKUP_V2_PROTECTION_SOURCE_BASE}/${hash(digest)}`;
}
export function backupV2ProtectionControlDirectory(digest: string): string {
  return `${BACKUP_V2_PROTECTION_CONTROL_BASE}/${hash(digest)}`;
}
export function buildBackupV2Protection(
  rootInput: BackupV2ManifestRef,
  inputs: readonly BackupV2ObjectRef[],
): BackupV2ProtectionBundle {
  const root = validateBackupV2ManifestRef(rootInput),
    unique = new Map<string, BackupV2ObjectRef>();
  for (const input of [root.object, ...inputs]) {
    const ref = validateBackupV2ObjectRef(input), old = unique.get(ref.fileId);
    if (old && !isDeepStrictEqual(old, ref)) fail();
    unique.set(ref.fileId, ref);
    count(unique.size, BACKUP_V2_LIMITS.pruneCandidates);
  }
  const refs = [...unique.values()].sort((a, b) =>
      a.fileName.localeCompare(b.fileName) || a.fileId.localeCompare(b.fileId)
    ),
    pages: BackupV2ProtectionBundle["pages"] = [];
  for (
    let start = 0;
    start < refs.length;
    start += BACKUP_V2_PROTECTION_PAGE_OBJECTS
  ) {
    const value: BackupV2ProtectionPage = {
        schemaVersion: 2,
        format: "backup-v2-protection-page",
        rootPlaintextSha256: root.plaintextSha256,
        pageIndex: pages.length,
        objects: refs.slice(start, start + BACKUP_V2_PROTECTION_PAGE_OBJECTS),
      },
      encoded = bytes(value);
    count(encoded.length, BACKUP_V2_LIMITS.controlResponseBytes, 1);
    pages.push({ value, bytes: encoded });
  }
  const manifest: BackupV2ProtectionManifest = {
    schemaVersion: 2,
    format: "backup-v2-protection",
    root,
    pages: pages.map((page) => ({
      pageIndex: page.value.pageIndex,
      sha256: sha(page.bytes),
      bytes: page.bytes.length,
      objects: page.value.objects.length,
    })),
    objectCount: refs.length,
    totalPageBytes: pages.reduce((sum, page) => sum + page.bytes.length, 0),
  };
  const manifestBytes = bytes(manifest),
    descriptor = validateBackupV2ProtectionDescriptor({
      schemaVersion: 2,
      format: "backup-v2-protection",
      root,
      manifestSha256: sha(manifestBytes),
      manifestBytes: manifestBytes.length,
      pageCount: pages.length,
      objectCount: refs.length,
      totalPageBytes: manifest.totalPageBytes,
    });
  return { descriptor, manifest, manifestBytes, pages };
}
export function parseBackupV2ProtectionManifest(
  encoded: Uint8Array,
  descriptorInput: BackupV2ProtectionDescriptor,
): BackupV2ProtectionManifest {
  const d = validateBackupV2ProtectionDescriptor(descriptorInput);
  if (encoded.length !== d.manifestBytes || sha(encoded) !== d.manifestSha256) {
    fail();
  }
  const r = object(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded)),
    [
      "schemaVersion",
      "format",
      "root",
      "pages",
      "objectCount",
      "totalPageBytes",
    ],
  );
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2-protection" ||
    !isDeepStrictEqual(validateBackupV2ManifestRef(r.root), d.root) ||
    !Array.isArray(r.pages) || r.pages.length !== d.pageCount ||
    r.objectCount !== d.objectCount || r.totalPageBytes !== d.totalPageBytes
  ) fail();
  const pages = r.pages.map((value, index) => {
    const p = object(value, ["pageIndex", "sha256", "bytes", "objects"]);
    if (p.pageIndex !== index) fail();
    return {
      pageIndex: index,
      sha256: hash(p.sha256),
      bytes: count(p.bytes, BACKUP_V2_LIMITS.controlResponseBytes, 1),
      objects: count(p.objects, BACKUP_V2_PROTECTION_PAGE_OBJECTS, 1),
    };
  });
  if (
    pages.reduce((sum, p) => sum + p.objects, 0) !== d.objectCount ||
    pages.reduce((sum, p) => sum + p.bytes, 0) !== d.totalPageBytes
  ) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-protection",
    root: d.root,
    pages,
    objectCount: d.objectCount,
    totalPageBytes: d.totalPageBytes,
  };
}
export function parseBackupV2ProtectionPage(
  encoded: Uint8Array,
  manifest: BackupV2ProtectionManifest,
  index: number,
): BackupV2ProtectionPage {
  const ref = manifest.pages[count(index, manifest.pages.length - 1)];
  if (encoded.length !== ref.bytes || sha(encoded) !== ref.sha256) fail();
  const r = object(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded)),
    ["schemaVersion", "format", "rootPlaintextSha256", "pageIndex", "objects"],
  );
  if (
    r.schemaVersion !== 2 || r.format !== "backup-v2-protection-page" ||
    r.rootPlaintextSha256 !== manifest.root.plaintextSha256 ||
    r.pageIndex !== index || !Array.isArray(r.objects) ||
    r.objects.length !== ref.objects
  ) fail();
  return {
    schemaVersion: 2,
    format: "backup-v2-protection-page",
    rootPlaintextSha256: manifest.root.plaintextSha256,
    pageIndex: index,
    objects: r.objects.map(validateBackupV2ObjectRef),
  };
}
