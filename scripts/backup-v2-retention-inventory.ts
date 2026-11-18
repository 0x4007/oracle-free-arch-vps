import { createHash } from "node:crypto";
import { DIRECT_PREFIX } from "./backblaze-storage.ts";
import { UPLOAD_ROLE_ORDER } from "./backblaze-upload.ts";
import {
  type BackupV2Cursor,
  type BackupV2ListedVersion,
  parseBackupV2ObjectName,
} from "./backup-v2-contract.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_LIMITS,
  BACKUP_V2_WORKSPACE,
} from "./backup-v2-profile.ts";

export interface BackupV2RetentionPart {
  fileId: string;
  partNumber: number;
  contentLength: number;
  contentSha1: string;
  uploadTimestamp: number;
}

export type BackupV2RetentionVersion =
  | Exclude<
    BackupV2ListedVersion,
    { action: "start" }
  >
  | (Extract<BackupV2ListedVersion, { action: "start" }> & {
    partsSha256: string;
    lastPartUploadedAt: number;
  });

export interface BackupV2RetentionInventoryReader {
  bucketVersionsPage(cursor: BackupV2Cursor | null, prefix?: string): Promise<{
    items: BackupV2ListedVersion[];
    next: BackupV2Cursor | null;
  }>;
  unfinishedFilesPage(cursor: string | null, prefix?: string): Promise<{
    items: Extract<BackupV2ListedVersion, { action: "start" }>[];
    next: string | null;
  }>;
  unfinishedPartsPage(fileId: string, cursor: number | null): Promise<{
    items: BackupV2RetentionPart[];
    next: number | null;
  }>;
}

const encoder = new TextEncoder();
export const retentionOrder = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;
export const retentionVersionOrder = (
  left: BackupV2ListedVersion,
  right: BackupV2ListedVersion,
) =>
  retentionOrder(left.fileName, right.fileName) ||
  retentionOrder(left.fileId, right.fileId);
export function retentionSha256(value: unknown): string {
  return createHash("sha256").update(
    JSON.stringify(
      value,
      (_key, item) =>
        item && typeof item === "object" && !Array.isArray(item)
          ? Object.fromEntries(
            Object.keys(item).sort().map((key) => [key, item[key]]),
          )
          : item,
    ),
  ).digest("hex");
}
export function sameRetentionEvidence(left: unknown, right: unknown): boolean {
  return retentionSha256(left) === retentionSha256(right);
}
export function retentionInventoryError(): never {
  throw new Error("Backup v2 retention inventory is invalid or incomplete");
}
export function retentionText(value: unknown, maximum: number): string {
  if (
    typeof value !== "string" || !value ||
    encoder.encode(value).length > maximum ||
    Array.from(value).some((char) =>
      char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127
    )
  ) retentionInventoryError();
  return value;
}
export function retentionInteger(value: unknown, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    retentionInventoryError();
  }
  return value as number;
}
const capture = "generation-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}";
const legacyName = new RegExp(
  `^${DIRECT_PREFIX}(?:indexes/(${capture})/index\\.json\\.gpg|generations/(${capture})/(${
    UPLOAD_ROLE_ORDER.join("|")
  })/[0-9]{8})$`,
);
export function retentionOwnedName(fileName: string) {
  try {
    return {
      format: "backup-v2" as const,
      captureId: parseBackupV2ObjectName(fileName).captureId,
    };
  } catch {
    const legacy = legacyName.exec(fileName);
    return legacy
      ? { format: "backup-v1" as const, captureId: legacy[1] ?? legacy[2] }
      : null;
  }
}
export function retentionOwnedResticName(fileName: string, prefix: string) {
  if (!fileName.startsWith(prefix)) return false;
  const relative = fileName.slice(prefix.length);
  if (
    relative === "config" ||
    /^(?:index|keys|locks|snapshots)\/[a-f0-9]{64}$/.test(relative)
  ) return true;
  const pack = /^data\/([a-f0-9]{2})\/([a-f0-9]{64})$/.exec(relative);
  return pack !== null && pack[2].startsWith(pack[1]);
}
export function validateRetentionListedVersion(
  value: BackupV2ListedVersion,
): BackupV2ListedVersion {
  const fileName = retentionText(value.fileName, 1_000);
  const fileId = retentionText(value.fileId, 512);
  const uploadTimestamp = retentionInteger(value.uploadTimestamp, 1);
  const contentLength = retentionInteger(value.contentLength);
  const { action, contentSha1 } = value;
  if (
    action === "upload"
      ? !["none", "unverified"].includes(contentSha1) &&
        !/^[a-f0-9]{40}$/.test(contentSha1)
      : action !== "hide" && action !== "start" ||
        contentLength !== 0 || contentSha1 !== ""
  ) retentionInventoryError();
  return {
    fileName,
    fileId,
    uploadTimestamp,
    contentLength,
    contentSha1,
    action,
  };
}

async function parts(
  source: BackupV2RetentionInventoryReader,
  version: Extract<BackupV2ListedVersion, { action: "start" }>,
  advance: () => void,
): Promise<Extract<BackupV2RetentionVersion, { action: "start" }>> {
  const records: BackupV2RetentionPart[] = [];
  let next: number | null = null;
  let lastPartUploadedAt = version.uploadTimestamp;
  let contentLength = 0, priorPart = 0;
  do {
    advance();
    const page = await source.unfinishedPartsPage(version.fileId, next);
    if (
      page.items.length > BACKUP_V2_LIMITS.listEntries ||
      next !== null && page.items[0]?.partNumber !== next
    ) retentionInventoryError();
    for (const part of page.items) {
      if (
        part.fileId !== version.fileId ||
        !Number.isSafeInteger(part.partNumber) ||
        part.partNumber <= priorPart || part.partNumber > 10_000 ||
        !/^[a-f0-9]{40}$/.test(part.contentSha1)
      ) retentionInventoryError();
      priorPart = part.partNumber;
      contentLength = retentionInteger(
        contentLength + retentionInteger(part.contentLength, 1),
      );
      lastPartUploadedAt = Math.max(
        lastPartUploadedAt,
        retentionInteger(part.uploadTimestamp, version.uploadTimestamp),
      );
      records.push(part);
    }
    if (
      page.next !== null &&
      (!page.items.length || !Number.isSafeInteger(page.next) ||
        page.next <= priorPart || page.next > 10_000)
    ) retentionInventoryError();
    next = page.next;
  } while (next !== null);
  return {
    ...version,
    contentLength,
    partsSha256: retentionSha256(records),
    lastPartUploadedAt,
  };
}

/** Metadata only. Version starts carry zero bytes until joined to the
 * unfinished-file and parts listings. A partial or inconsistent census cannot
 * provide the denominator or prove absence. */
export async function readBackupV2RetentionInventory(
  reader: BackupV2RetentionInventoryReader,
  exactName?: string,
  includeUnfinished = true,
): Promise<BackupV2RetentionVersion[]> {
  if (exactName !== undefined) retentionText(exactName, 1_000);
  const versions = new Map<string, BackupV2RetentionVersion>();
  const starts = new Map<string, BackupV2ListedVersion>();
  const seen = new Set<string>();
  let pages = 0, metadataBytes = 0;
  const advance = () => {
    // A mostly empty parts page still costs a provider request.
    assertBackupV2Budget("pruneCandidates", ++pages);
  };
  const account = (version: BackupV2ListedVersion) => {
    metadataBytes += encoder.encode(JSON.stringify(version)).length;
    assertBackupV2Budget("pruneCandidates", seen.size);
    if (metadataBytes > BACKUP_V2_WORKSPACE.retention) {
      retentionInventoryError();
    }
  };
  let cursor: BackupV2Cursor | null = null;
  do {
    advance();
    const page = await reader.bucketVersionsPage(cursor, exactName);
    if (
      page.items.length > BACKUP_V2_LIMITS.listEntries ||
      cursor &&
        (page.items[0]?.fileId !== cursor.fileId ||
          page.items[0]?.fileName !== cursor.fileName)
    ) retentionInventoryError();
    for (const input of page.items) {
      const item = validateRetentionListedVersion(input);
      if (seen.has(item.fileId)) retentionInventoryError();
      if (exactName && !item.fileName.startsWith(exactName)) {
        retentionInventoryError();
      }
      seen.add(item.fileId);
      account(item);
      if (exactName && item.fileName !== exactName) continue;
      if (item.action === "start") {
        if (includeUnfinished) starts.set(item.fileId, item);
      } else versions.set(item.fileId, item);
    }
    if (page.next !== null) {
      retentionText(page.next.fileId, 512);
      retentionText(page.next.fileName, 1_000);
      if (
        !page.items.length || seen.has(page.next.fileId) ||
        exactName && !page.next.fileName.startsWith(exactName)
      ) retentionInventoryError();
    }
    cursor = page.next;
  } while (cursor !== null);
  if (!includeUnfinished) {
    return [...versions.values()].sort(retentionVersionOrder);
  }
  let next: string | null = null;
  const unfinishedSeen = new Set<string>();
  do {
    advance();
    const page = await reader.unfinishedFilesPage(next, exactName);
    if (
      page.items.length > BACKUP_V2_LIMITS.listEntries ||
      next !== null && page.items[0]?.fileId !== next
    ) retentionInventoryError();
    for (const input of page.items) {
      const item = validateRetentionListedVersion(input);
      if (
        item.action !== "start" || unfinishedSeen.has(item.fileId) ||
        exactName && !item.fileName.startsWith(exactName)
      ) retentionInventoryError();
      unfinishedSeen.add(item.fileId);
      if (exactName && item.fileName !== exactName) continue;
      const start = starts.get(item.fileId);
      if (
        seen.has(item.fileId) && !start ||
        start && !sameRetentionEvidence(start, item)
      ) retentionInventoryError();
      starts.delete(item.fileId);
      seen.add(item.fileId);
      const enriched = await parts(reader, item, advance);
      account(enriched);
      versions.set(item.fileId, enriched);
    }
    if (page.next !== null) {
      retentionText(page.next, 512);
      if (!page.items.length || unfinishedSeen.has(page.next)) {
        retentionInventoryError();
      }
    }
    next = page.next;
  } while (next !== null);
  if (starts.size) retentionInventoryError();
  return [...versions.values()].sort(retentionVersionOrder);
}
