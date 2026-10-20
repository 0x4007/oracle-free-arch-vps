import { createHash } from "node:crypto";
import { assertBackupV2Budget } from "./backup-v2-profile.ts";

/** Native tar adapters decode their pinned output into raw filename bytes.
 * This is a framing/summary interface, not a tar parser or stored file list. */
export interface BackupV2InventoryRecord {
  path: Uint8Array;
  /** Optional canonical native metadata; no metadata is invented by this layer. */
  metadata?: Uint8Array;
}
export interface BackupV2InventorySummary {
  encoding: "backup-v2-inventory-1";
  members: number;
  pathBytes: number;
  encodedBytes: number;
  sha256: string;
}

export function encodeBackupV2InventoryRecord(
  record: BackupV2InventoryRecord,
): Uint8Array {
  const { path, metadata = new Uint8Array() } = record;
  if (
    !(path instanceof Uint8Array) || !(metadata instanceof Uint8Array) ||
    path.length === 0 ||
    path[0] === 47 || path.includes(0)
  ) throw new Error("Backup v2 inventory path is invalid");
  // Reject traversal without decoding or losing non-UTF8 filename bytes.
  let start = 0;
  for (let index = 0; index <= path.length; index++) {
    if (index === path.length || path[index] === 47) {
      if (index - start === 2 && path[start] === 46 && path[start + 1] === 46) {
        throw new Error("Backup v2 inventory path traverses its root");
      }
      start = index + 1;
    }
  }
  const length = 8 + path.length + metadata.length;
  assertBackupV2Budget("metadataRecordBytes", length);
  const frame = new Uint8Array(length);
  const header = new DataView(frame.buffer);
  header.setUint32(0, path.length);
  header.setUint32(4, metadata.length);
  frame.set(path, 8);
  frame.set(metadata, 8 + path.length);
  return frame;
}

export function validateBackupV2InventorySummary(
  value: unknown,
): BackupV2InventorySummary {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Backup v2 inventory summary is invalid");
  }
  const record = value as Record<string, unknown>;
  const keys = ["encoding", "members", "pathBytes", "encodedBytes", "sha256"];
  if (
    Object.keys(record).length !== keys.length ||
    keys.some((key) => !(key in record)) ||
    record.encoding !== "backup-v2-inventory-1" ||
    typeof record.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(record.sha256)
  ) throw new Error("Backup v2 inventory summary is invalid");
  const members = assertBackupV2Budget("members", record.members as number);
  const pathBytes = assertBackupV2Budget(
    "pathBytes",
    record.pathBytes as number,
  );
  const encodedBytes = assertBackupV2Budget(
    "inventoryBytes",
    record.encodedBytes as number,
  );
  if (pathBytes < members || encodedBytes < 8 * members + pathBytes) {
    throw new Error("Backup v2 inventory counts are inconsistent");
  }
  return {
    encoding: "backup-v2-inventory-1",
    members,
    pathBytes,
    encodedBytes,
    sha256: record.sha256,
  };
}

/** Constant retained state; limits are checked before hashing each bounded frame. */
export function createBackupV2InventorySummary() {
  const hash = createHash("sha256");
  let members = 0, pathBytes = 0, encodedBytes = 0, finished = false;
  return {
    add(record: BackupV2InventoryRecord): void {
      if (finished) {
        throw new Error("Backup v2 inventory summary is already final");
      }
      const frame = encodeBackupV2InventoryRecord(record);
      const nextMembers = assertBackupV2Budget("members", members + 1);
      const nextPaths = assertBackupV2Budget(
        "pathBytes",
        pathBytes + record.path.length,
      );
      const nextBytes = assertBackupV2Budget(
        "inventoryBytes",
        encodedBytes + frame.length,
      );
      hash.update(frame);
      members = nextMembers;
      pathBytes = nextPaths;
      encodedBytes = nextBytes;
    },
    finish(): BackupV2InventorySummary {
      if (finished) {
        throw new Error("Backup v2 inventory summary is already final");
      }
      finished = true;
      return {
        encoding: "backup-v2-inventory-1",
        members,
        pathBytes,
        encodedBytes,
        sha256: hash.digest("hex"),
      };
    },
  };
}

export async function summarizeBackupV2Inventory(
  records: AsyncIterable<BackupV2InventoryRecord>,
): Promise<BackupV2InventorySummary> {
  const summary = createBackupV2InventorySummary();
  for await (const record of records) summary.add(record);
  return summary.finish();
}
