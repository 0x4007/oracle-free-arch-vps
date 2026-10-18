import {
  type BackupV2ManifestRef,
  type BackupV2ObjectRef,
  type BackupV2ProtectedReferences,
  type BackupV2ReachabilityReader,
  parseBackupV2ObjectName,
  validateBackupV2ManifestRef,
  validateBackupV2ObjectRef,
  validateBackupV2PutIntent,
} from "./backup-v2-contract.ts";
import {
  assertBackupV2Budget,
  BACKUP_V2_WORKSPACE,
} from "./backup-v2-profile.ts";

export interface BackupV2ProtectionReader extends BackupV2ReachabilityReader {
  roleReferences(
    role: BackupV2ManifestRef,
  ): Promise<readonly BackupV2ObjectRef[]>;
}
export interface BackupV2ProtectionDryRun {
  pruneEnabled: false;
  objects: BackupV2ObjectRef[];
  unresolvedNames: string[];
}
/** Protection only. There is deliberately no deletion capability or enable
 * flag. Legacy roots/Oracle/unrelated Restic retention stay with their readers. */
export async function collectBackupV2ProtectedReferences(
  value: BackupV2ProtectedReferences,
  reader: BackupV2ProtectionReader,
  receipts: readonly BackupV2ManifestRef[],
): Promise<BackupV2ProtectionDryRun> {
  const objects = new Map<string, BackupV2ObjectRef>(),
    unresolved = new Set<string>();
  let bytes = 0;
  const add = (input: BackupV2ObjectRef) => {
    const ref = validateBackupV2ObjectRef(input), old = objects.get(ref.fileId);
    if (old && JSON.stringify(old) !== JSON.stringify(ref)) {
      throw new Error("Protected object identity conflicts");
    }
    if (!old) {
      assertBackupV2Budget(
        "pruneCandidates",
        objects.size + unresolved.size + 1,
      );
      bytes += new TextEncoder().encode(JSON.stringify(ref)).length;
      if (bytes > BACKUP_V2_WORKSPACE.retention) {
        throw new Error("Protection workspace exceeded");
      }
      objects.set(ref.fileId, ref);
    }
  };
  for (const input of value.acceptedRoots) {
    const root = validateBackupV2ManifestRef(input);
    if (parseBackupV2ObjectName(root.object.fileName).kind !== "manifest") {
      throw new Error("Protected root kind invalid");
    }
    add(root.object);
    for (const ref of await reader.references(root)) add(ref);
  }
  for (const input of value.sealedRoleManifests) {
    const role = validateBackupV2ManifestRef(input);
    if (parseBackupV2ObjectName(role.object.fileName).kind !== "manifest") {
      throw new Error("Protected role kind invalid");
    }
    add(role.object);
    for (const ref of await reader.roleReferences(role)) add(ref);
  }
  for (const input of receipts) {
    const receipt = validateBackupV2ManifestRef(input);
    if (parseBackupV2ObjectName(receipt.object.fileName).kind !== "receipt") {
      throw new Error("Protected receipt kind invalid");
    }
    add(receipt.object);
  }
  for (const ref of value.activeObjects) add(ref);
  for (const input of value.unresolvedPuts) {
    const intent = validateBackupV2PutIntent(input);
    if (!unresolved.has(intent.name)) {
      assertBackupV2Budget(
        "pruneCandidates",
        objects.size + unresolved.size + 1,
      );
      bytes += new TextEncoder().encode(intent.name).length;
      if (bytes > BACKUP_V2_WORKSPACE.retention) {
        throw new Error("Protection workspace exceeded");
      }
      unresolved.add(intent.name);
    }
  }
  return {
    pruneEnabled: false,
    objects: [...objects.values()],
    unresolvedNames: [...unresolved].sort(),
  };
}
