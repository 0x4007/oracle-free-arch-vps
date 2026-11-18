/** Private Pi publication and safe aggregate projections. */
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { BackupV2PrunePlanReference } from "./backup-v2-protection.ts";
import type {
  BackupV2RetentionPolicy,
  BackupV2RetentionSummary,
} from "./backup-v2-retention.ts";
import { BACKUP_V2_LIMITS } from "./backup-v2-profile.ts";
import {
  backblazeReportExplanation,
  type BackblazeReportReason,
  backblazeReportReason,
  type BackblazeReportReasonFields,
} from "./backup-v2-report-reasons.ts";

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

export type BackblazeMaintenanceMode = "scheduled" | "plan" | "verify-catalog";

export interface BackblazeMaintenanceResult
  extends BackblazeReportReasonFields {
  status: string;
  observedAtUtc: string;
  healthy: boolean;
  retention?: BackupV2RetentionSummary;
  retentionTransactionId?: string;
  checkedCaptureIds?: string[];
}

export interface BackblazeMaintenanceReports {
  retention?: BackblazeMaintenanceResult;
  catalog?: BackblazeMaintenanceResult;
}

interface CatalogFact {
  captureId: string;
  observedAtUtc: string;
  state: "INTACT" | "DAMAGED";
}

interface BackblazeMaintenanceRecord extends BackblazeReportReasonFields {
  schemaVersion: 1;
  format: "backblaze-retention-report";
  transactionId?: string;
  observedAtUtc: string;
  status: string;
  healthy: boolean;
  catalogFacts?: CatalogFact[];
}

export interface BackupV2PiRetentionReport extends BackblazeMaintenanceRecord {
  transactionId: string;
  policy: BackupV2RetentionPolicy;
  plan: BackupV2PrunePlanReference & { path: string };
  summary: BackupV2RetentionSummary;
  retainedCaptureIds: string[];
  checkedCaptureIds?: string[];
}

const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const hash = /^[a-f0-9]{64}$/;
const maintenanceStatuses =
  /^B2_RETENTION_(?:BLOCKED|BUSY|LEGACY_CUSTODY_UNSETTLED|CATALOG_(?:VERIFIED|DAMAGED|VERIFICATION_REFUSED)|ORPHANS_PRESENT|PLAN_(?:ONLY|BLOCKED|REFUSED)|(?:PLAN|EXECUTE)_(?:REQUESTED|RUNNING|SETTLED|COMPLETE|PARTIAL|CANCELLATION_BLOCKED))$/;

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

function captureId(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("generation-") &&
    uuid.test(value.slice(11));
}

function reportTime(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

interface MaintenanceReportIO {
  read<T>(path: string): Promise<T | undefined>;
  write(path: string, value: unknown): Promise<void>;
}

export function maintenanceReportPath(mode: BackblazeMaintenanceMode): string {
  return mode === "verify-catalog"
    ? B2_CATALOG_REPORT_PATH
    : B2_RETENTION_REPORT_PATH;
}

export function maintenanceFailure(
  mode: BackblazeMaintenanceMode,
  now: Date,
  reason: BackblazeReportReason,
  status = mode === "verify-catalog"
    ? "B2_RETENTION_CATALOG_VERIFICATION_REFUSED"
    : mode === "plan"
    ? "B2_RETENTION_PLAN_REFUSED"
    : "B2_RETENTION_BLOCKED",
): BackblazeMaintenanceResult {
  return {
    status,
    observedAtUtc: now.toISOString(),
    healthy: false,
    ...backblazeReportExplanation(reason),
  };
}

function reportFacts(
  report: BackupV2PiRetentionReport,
): CatalogFact[] {
  // An interrupted execute may fall back to the plan's kept IDs without
  // revalidating them. An explicit damage result still proves those losses.
  const intact = report.status === "B2_RETENTION_EXECUTE_PARTIAL"
    ? []
    : report.retainedCaptureIds;
  return [
    ...intact.map((captureId) => ({
      captureId,
      observedAtUtc: report.observedAtUtc,
      state: "INTACT" as const,
    })),
    ...report.summary.damagedCaptureIds.map((captureId) => ({
      captureId,
      observedAtUtc: report.observedAtUtc,
      state: "DAMAGED" as const,
    })),
  ];
}

function newestCatalogFacts(
  ...lists: (readonly CatalogFact[])[]
): CatalogFact[] {
  const facts = new Map<string, CatalogFact>();
  for (const fact of lists.flat()) {
    const previous = facts.get(fact.captureId);
    if (
      !previous || previous.observedAtUtc < fact.observedAtUtc ||
      previous.observedAtUtc === fact.observedAtUtc && fact.state === "DAMAGED"
    ) facts.set(fact.captureId, fact);
  }
  return [...facts.values()];
}

function readCatalogFacts(value: unknown, nowUtc: string): CatalogFact[] {
  if (
    !Array.isArray(value) || value.length > BACKUP_V2_LIMITS.pruneCandidates
  ) invalid();
  const ids = new Set<string>();
  return value.map((value) => {
    const fact = object(value);
    const { captureId: id, observedAtUtc: observed, state } = fact;
    if (
      !captureId(id) || ids.has(id) || !reportTime(observed) ||
      observed > nowUtc || (state !== "INTACT" && state !== "DAMAGED")
    ) {
      invalid();
    }
    ids.add(id);
    return { captureId: id, observedAtUtc: observed, state };
  });
}

function maintenanceRecord(
  raw: BackblazeMaintenanceRecord | undefined,
  now: Date,
) {
  if (raw === undefined) return undefined;
  const { observedAtUtc, status, healthy, transactionId } = raw;
  if (
    raw.schemaVersion !== 1 || raw.format !== "backblaze-retention-report" ||
    !reportTime(observedAtUtc) || observedAtUtc > now.toISOString() ||
    typeof status !== "string" || !maintenanceStatuses.test(status) ||
    typeof healthy !== "boolean" ||
    transactionId !== undefined && !uuid.test(transactionId)
  ) invalid();
  const stored = raw.catalogFacts === undefined
    ? []
    : readCatalogFacts(raw.catalogFacts, now.toISOString());
  let terminal: BackupV2PiRetentionReport | undefined;
  if ("plan" in raw) {
    terminal = raw as BackupV2PiRetentionReport;
    const { plan, summary, retainedCaptureIds, checkedCaptureIds } = terminal;
    if (
      !transactionId ||
      plan.path !== retentionTransactionPath(transactionId, "plan") ||
      !Array.isArray(retainedCaptureIds) ||
      retainedCaptureIds.length > BACKUP_V2_LIMITS.pruneCandidates ||
      retainedCaptureIds.some((id) => !captureId(id)) ||
      checkedCaptureIds !== undefined &&
        (!Array.isArray(checkedCaptureIds) ||
          checkedCaptureIds.length > BACKUP_V2_LIMITS.pruneCandidates ||
          checkedCaptureIds.some((id) => !captureId(id)))
    ) invalid();
    validateRetentionPlanReference(plan);
    terminal = { ...terminal, summary: validateRetentionSummary(summary) };
  }
  const reason = !healthy || raw.reason !== undefined
    ? backblazeReportReason(
      raw.reason ?? terminal?.summary.blockReason,
      "B2_RETENTION_STATUS_UNPROVED",
    )
    : undefined;
  const result: BackblazeMaintenanceResult = {
    observedAtUtc,
    status,
    healthy,
    ...(reason ? backblazeReportExplanation(reason) : {}),
    ...(transactionId ? { retentionTransactionId: transactionId } : {}),
    ...(terminal ? { retention: terminal.summary } : {}),
    ...(terminal?.checkedCaptureIds
      ? { checkedCaptureIds: terminal.checkedCaptureIds }
      : {}),
  };
  return {
    result,
    catalogFacts: newestCatalogFacts(
      stored,
      terminal ? reportFacts(terminal) : [],
    ),
  };
}

/** A retention issue must not erase an earlier cloud observation. Only a
 * later result which checked that generation can clear its proven damage. */
export async function publishMaintenanceReport(
  io: MaintenanceReportIO,
  mode: BackblazeMaintenanceMode,
  result: BackblazeMaintenanceResult,
  now: Date,
  terminal?: BackupV2PiRetentionReport,
): Promise<void> {
  const path = maintenanceReportPath(mode);
  const saved = await io.read<BackblazeMaintenanceRecord>(path).catch(() =>
    undefined
  );
  let previous: ReturnType<typeof maintenanceRecord>;
  try {
    previous = maintenanceRecord(saved, now);
  } catch { /* A malformed earlier report cannot supply cloud evidence. */ }
  if (
    terminal && previous &&
    previous.result.retentionTransactionId !== terminal.transactionId &&
    previous.result.observedAtUtc > result.observedAtUtc
  ) return;
  const relatedFacts = newestCatalogFacts(
    previous?.catalogFacts ?? [],
    terminal ? reportFacts(terminal) : [],
  );
  const record: BackblazeMaintenanceRecord = {
    ...(terminal ?? {}),
    schemaVersion: 1,
    format: "backblaze-retention-report",
    status: result.status,
    healthy: result.healthy,
    observedAtUtc: result.observedAtUtc,
    ...(result.reason ? backblazeReportExplanation(result.reason) : {}),
    ...(result.retentionTransactionId
      ? { transactionId: result.retentionTransactionId }
      : {}),
    ...(relatedFacts.length ? { catalogFacts: relatedFacts } : {}),
  };
  if (!isDeepStrictEqual(saved, record)) {
    await io.write(path, record);
  }
}

export async function readBackblazeMaintenance(
  io: Pick<MaintenanceReportIO, "read">,
  now: Date,
): Promise<{ reports: BackblazeMaintenanceReports; damaged: string[] }> {
  const read = async (mode: BackblazeMaintenanceMode) => {
    try {
      return maintenanceRecord(await io.read(maintenanceReportPath(mode)), now);
    } catch {
      return {
        result: maintenanceFailure(mode, now, "B2_REPORT_INVALID"),
        catalogFacts: [],
      };
    }
  };
  const [retention, catalog] = await Promise.all([
    read("plan"),
    read("verify-catalog"),
  ]);
  return {
    reports: {
      ...(retention ? { retention: retention.result } : {}),
      ...(catalog ? { catalog: catalog.result } : {}),
    },
    damaged: newestCatalogFacts(
      retention?.catalogFacts ?? [],
      catalog?.catalogFacts ?? [],
    )
      .filter((fact) => fact.state === "DAMAGED").map((fact) => fact.captureId),
  };
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
