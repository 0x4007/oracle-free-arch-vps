/** Private Pi publication and safe aggregate projections. */
import { createHash } from "node:crypto";
import type { BackupV2PrunePlanReference } from "./backup-v2-protection.ts";
import type {
  BackupV2RetentionPolicy,
  BackupV2RetentionSummary,
} from "./backup-v2-retention.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";

export const B2_RETENTION_ROOT = ".private/file-backup/retention";
export const B2_RETENTION_CONTROL_PATH = B2_RETENTION_ROOT +
  "/controller-v2.json";
export const B2_CATALOG_CONTROL_PATH = B2_RETENTION_ROOT +
  "/catalog-controller-v2.json";
export const B2_CATALOG_REPORT_PATH =
  ".private/reports/backblaze-catalog-verification.json";
export const B2_RETENTION_POLICY_PATH = B2_RETENTION_ROOT + "-policy.json";
export const B2_RETENTION_KEY_PATH = B2_RETENTION_ROOT + "-key.json";
export const B2_RETENTION_REPORT_PATH =
  ".private/reports/backblaze-retention.json";
export const B2_RETENTION_PAGE_BYTES = 128 * 1024;

export const B2_RETENTION_CATEGORIES = [
  "RETAINED_ACCEPTED",
  "OBSOLETE_ACCEPTED",
  "UNFINISHED_LARGE_FILE",
  "UNACCEPTED_V2",
  "NONCURRENT_VERSION",
  "HIDE_MARKER",
  "LEGACY_ORPHAN",
  "LEGACY_UNATTRIBUTED",
  "PROTECTED",
  "UNCLASSIFIED",
] as const;
export const B2_CATALOG_DAMAGED_ALERT = "B2_RETENTION_CATALOG_DAMAGED";
export const B2_RETENTION_ORPHAN_ALERT = "B2_RETENTION_ORPHANS_PRESENT";

export interface BackupV2PiRetentionReport {
  schemaVersion: 1;
  format: "backblaze-retention-report";
  transactionId: string;
  observedAtUtc: string;
  status: string;
  healthy: boolean;
  policy: BackupV2RetentionPolicy;
  plan: BackupV2PrunePlanReference & { path: string };
  summary: BackupV2RetentionSummary;
  retainedCaptureIds: string[];
  checkedCaptureIds?: string[];
}

const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const hash = /^[a-f0-9]{64}$/;

function invalid(): never {
  throw new Error("Private Backblaze retention report is unproved");
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    invalid();
  }
  return value;
}

export function retentionTransactionPath(
  transactionId: string,
  name: "plan" | "report" | "retirement",
): string {
  if (!uuid.test(transactionId)) invalid();
  return `${B2_RETENTION_ROOT}/${transactionId}/${name}.json`;
}

export function validateRetentionPlanReference(
  value: unknown,
): BackupV2PrunePlanReference {
  const ref = object(value), bytes = count(ref.bytes);
  if (
    typeof ref.sha256 !== "string" || !hash.test(ref.sha256) ||
    typeof ref.digest !== "string" || !hash.test(ref.digest) ||
    bytes < 1 || bytes > BACKUP_V2_LIMITS.journalBytes
  ) invalid();
  return { sha256: ref.sha256, bytes, digest: ref.digest };
}

/** Return only allowlisted count/byte/reason fields for journals and alerts. */
export function validateRetentionSummary(
  value: unknown,
): BackupV2RetentionSummary {
  const r = object(value), categories = object(r.categories);
  const checked = Object.fromEntries(B2_RETENTION_CATEGORIES.map((category) => {
    const item = object(categories[category]),
      objects = count(item.objects),
      bytes = count(item.bytes),
      plannedObjects = count(item.plannedObjects),
      plannedBytes = count(item.plannedBytes);
    if (plannedObjects > objects || plannedBytes > bytes) invalid();
    return [category, { objects, bytes, plannedObjects, plannedBytes }];
  })) as BackupV2RetentionSummary["categories"];
  const blockReason = r.blockReason;
  const ids = r.damagedCaptureIds;
  if (
    !Array.isArray(ids) || ids.length > BACKUP_V2_LIMITS.pruneCandidates ||
    ids.some((id) =>
      typeof id !== "string" || !id.startsWith("generation-") ||
      !uuid.test(id.slice(11))
    ) ||
    new Set(ids).size !== ids.length
  ) invalid();
  if (
    blockReason !== null && blockReason !== "CAP_EXCEEDED" &&
    blockReason !== "PLAN_CHANGED" && blockReason !== "IDENTITY_CHANGED" &&
    blockReason !== "TRANSPORT_UNCERTAIN" &&
    blockReason !== "NO_ACCEPTED_GENERATION" &&
    blockReason !== "DAMAGED_ACCEPTED_GENERATION"
  ) invalid();
  return {
    keptGenerations: count(r.keptGenerations),
    bucketBytes: count(r.bucketBytes),
    maxDeleteBytes: count(r.maxDeleteBytes),
    categories: checked,
    blockReason,
    damagedCaptureIds: [...ids],
    deletedObjects: count(r.deletedObjects),
    deletedBytes: count(r.deletedBytes),
    reconciledAbsentObjects: count(r.reconciledAbsentObjects),
    reconciledAbsentBytes: count(r.reconciledAbsentBytes),
  };
}

export function retentionOrphansFound(
  summary: BackupV2RetentionSummary,
): boolean {
  const categories = summary.categories;
  return categories.UNFINISHED_LARGE_FILE.objects > 0 ||
    categories.UNACCEPTED_V2.objects > 0 ||
    categories.NONCURRENT_VERSION.objects > 0 ||
    categories.HIDE_MARKER.objects > 0 ||
    categories.LEGACY_ORPHAN.objects > 0;
}

export function retentionAlertSummary(
  summary: BackupV2RetentionSummary,
): string {
  const categories = B2_RETENTION_CATEGORIES.flatMap((name) =>
    summary.categories[name].objects
      ? [`${name}=${summary.categories[name].bytes}B`]
      : []
  ).join(", ");
  return `Kept ${summary.keptGenerations} generations. Bucket ${summary.bucketBytes} bytes${
    categories ? ` (${categories})` : ""
  }. Deleted ${summary.deletedObjects} objects, ${summary.deletedBytes} bytes. Reconciled absent ${summary.reconciledAbsentObjects} objects, ${summary.reconciledAbsentBytes} bytes.`;
}

function sameFile(before: Deno.FileInfo, after: Deno.FileInfo): boolean {
  return before.dev === after.dev && before.ino === after.ino &&
    before.size === after.size &&
    before.mtime?.getTime() === after.mtime?.getTime() &&
    before.ctime?.getTime() === after.ctime?.getTime();
}

async function verifyPrivatePlan(
  path: string,
  reference: BackupV2PrunePlanReference,
): Promise<void> {
  const initial = await Deno.lstat(path);
  if (
    !initial.isFile || initial.isSymlink || initial.nlink !== 1 ||
    initial.mode === null || (initial.mode & 0o777) !== 0o600 ||
    initial.size !== reference.bytes
  ) invalid();
  const digest = createHash("sha256"),
    page = new Uint8Array(B2_RETENTION_PAGE_BYTES);
  using file = await Deno.open(path, { read: true });
  if (!sameFile(initial, await file.stat())) invalid();
  let count = 0;
  while (count < reference.bytes) {
    const bytes = await file.read(page);
    if (bytes === null || bytes < 1 || bytes > reference.bytes - count) {
      invalid();
    }
    digest.update(page.subarray(0, bytes));
    count += bytes;
  }
  if (
    await file.read(page) !== null ||
    !sameFile(initial, await Deno.lstat(path)) ||
    digest.digest("hex") !== reference.sha256
  ) invalid();
}

/** Stream only bounded control pages to Pi disk. Keep a previous verified plan
 * immutable, including across a crash after publication and before state save. */
export async function persistPrivateRetentionPlan(
  path: string,
  rawReference: BackupV2PrunePlanReference,
  readPage?: (offset: number) => Promise<Uint8Array>,
): Promise<void> {
  const reference = validateRetentionPlanReference(rawReference);
  try {
    await verifyPrivatePlan(path, reference);
    return;
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound) || !readPage) throw error;
  }
  const directory = path.slice(0, path.lastIndexOf("/"));
  await Deno.mkdir(directory, { recursive: true, mode: 0o700 });
  const dir = await Deno.lstat(directory);
  const expected = directory.startsWith("/")
    ? directory
    : `${Deno.cwd()}/${directory}`;
  if (
    !dir.isDirectory || dir.isSymlink || dir.mode === null ||
    (dir.mode & 0o077) !== 0 ||
    await Deno.realPath(directory) !== expected
  ) invalid();
  const temp = `${directory}/.plan-${crypto.randomUUID()}.tmp`;
  try {
    const digest = createHash("sha256");
    {
      using file = await Deno.open(temp, {
        createNew: true,
        write: true,
        mode: 0o600,
      });
      for (let offset = 0; offset < reference.bytes;) {
        const page = await readPage(offset);
        if (
          page.length !==
            Math.min(B2_RETENTION_PAGE_BYTES, reference.bytes - offset)
        ) invalid();
        digest.update(page);
        for (let written = 0; written < page.length;) {
          const size = await file.write(page.subarray(written));
          if (size < 1) invalid();
          written += size;
        }
        offset += page.length;
      }
      if (digest.digest("hex") !== reference.sha256) invalid();
      await file.sync();
    }
    await Deno.rename(temp, path);
    using parent = await Deno.open(directory, { read: true });
    await parent.sync();
    await verifyPrivatePlan(path, reference);
  } finally {
    await Deno.remove(temp).catch((error: unknown) => {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    });
  }
}
