/** Internal admission ceilings, not measured capacity or product settings. */
const MIB = 1024 ** 2;
const GIB = 1024 ** 3;
export const BACKUP_V2_PROFILE_ID = "backup-v2-20261018";
export const BACKUP_V2_NAMESPACE = "restic/backup-v2/";
export const BACKUP_V2_SLOT_COUNT = 2;
export const BACKUP_V2_LIMITS = Object.freeze({
  slotBytes: 64 * MIB,
  workspaceBytes: 2 * GIB,
  protectedReserveBytes: 5.5 * GIB,
  journalBytes: 64 * MIB,
  manifestBytes: MIB,
  descriptorBytes: 1024,
  listEntries: 100,
  listResponseBytes: 2 * MIB,
  controlResponseBytes: 2 * MIB,
  responseHeaderBytes: 64 * 1024,
  logicalObjects: 5000,
  physicalPuts: 16384,
  putsPerObject: 16,
  ciphertextBytes: 256 * GIB,
  physicallyPutBytes: 512 * GIB,
  members: 2_000_000,
  pathBytes: 128 * MIB,
  hardlinkedNames: 100_000,
  directoryListingBytes: 32 * MIB,
  sparseExtents: 100_000,
  metadataRecordBytes: MIB,
  depth: 256,
  logicalSourceBytes: 1024 * GIB,
  inventoryBytes: 512 * MIB,
  pruneCandidates: 100_000,
  decoderMemoryBytes: 128 * MIB,
  blockedTransportMs: 6 * 3_600_000,
});
export const BACKUP_V2_WORKSPACE = Object.freeze({
  slots: 128 * MIB,
  journal: 64 * MIB,
  activeInventory: 256 * MIB,
  preflight: 256 * MIB,
  retention: 256 * MIB,
  recoveryTools: 512 * MIB,
  control: 64 * MIB,
  diagnostics: 32 * MIB,
  subprocessTemporary: 128 * MIB,
  filesystemMargin: 352 * MIB,
});
export type BackupV2Budget = keyof typeof BACKUP_V2_LIMITS;

export function assertBackupV2Budget(
  budget: BackupV2Budget,
  value: number,
): number {
  if (
    !Number.isSafeInteger(value) || value < 0 ||
    value > BACKUP_V2_LIMITS[budget]
  ) {
    throw new Error(`Backup v2 ${budget} budget exceeded or invalid`);
  }
  return value;
}

/** Additional workspace only: already allocated bytes must not be counted twice. */
export function backupV2RequiredFreeBytes(
  allocatedWorkspaceBytes: number,
  productionWriterMarginBytes: number,
): number {
  assertBackupV2Budget("workspaceBytes", allocatedWorkspaceBytes);
  if (
    !Number.isSafeInteger(productionWriterMarginBytes) ||
    productionWriterMarginBytes < 0
  ) {
    throw new Error("Backup v2 production writer margin is invalid");
  }
  const required = BACKUP_V2_LIMITS.protectedReserveBytes +
    BACKUP_V2_LIMITS.workspaceBytes - allocatedWorkspaceBytes +
    productionWriterMarginBytes;
  if (!Number.isSafeInteger(required)) {
    throw new Error("Backup v2 free-space total overflows");
  }
  return required;
}
