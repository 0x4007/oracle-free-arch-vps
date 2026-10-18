import {
  backupV2ObjectName,
  type BackupV2ObjectRef,
  type BackupV2ProtectedReferences,
} from "../scripts/backup-v2-contract.ts";
import { collectBackupV2ProtectedReferences } from "../scripts/backup-v2-retention.ts";
const C = "generation-00000000-0000-4000-8000-000000000001",
  A = "00000000-0000-4000-8000-000000000002",
  P = "00000000-0000-4000-8000-000000000003";
function assert(value: unknown): asserts value {
  if (!value) throw new Error("Assertion failed");
}
function ref(
  id: string,
  kind: "data" | "manifest" | "receipt" = "data",
): BackupV2ObjectRef {
  return {
    fileId: id,
    fileName: backupV2ObjectName(C, A, kind, 0, P),
    contentLength: 1,
    contentSha1: "1".repeat(40),
    sha256: "2".repeat(64),
    uploadTimestamp: 1,
    action: "upload",
  };
}
const manifest = (id: string) => ({
  object: ref(id, "manifest"),
  plaintextSha256: "3".repeat(64),
});
type MutableProtection = {
  [K in keyof BackupV2ProtectedReferences]:
    BackupV2ProtectedReferences[K][number][];
};
const empty = (): MutableProtection => ({
  acceptedRoots: [],
  activeObjects: [],
  sealedRoleManifests: [],
  unresolvedPuts: [],
});
async function rejects(run: () => unknown) {
  let failed = false;
  try {
    await run();
  } catch {
    failed = true;
  }
  assert(failed);
}
Deno.test("v2 protection dry run retains roots sealed roles receipts active refs and unresolved names", async () => {
  const input = empty();
  input.acceptedRoots.push(manifest("root"));
  input.sealedRoleManifests.push(manifest("role"));
  input.activeObjects.push(ref("active"));
  const name = backupV2ObjectName(C, A, "data", 2, P);
  input.unresolvedPuts.push({
    captureId: C,
    attemptId: A,
    role: "root",
    kind: "data",
    ordinal: 2,
    offset: 0,
    putId: P,
    createdAtUtc: "2026-10-18T10:00:00.000Z",
    name,
    slot: {
      index: 0,
      path: "/var/tmp/fixture/slot-0",
      device: 1,
      inode: 2,
      bytes: 1,
      sha1: "1".repeat(40),
      sha256: "2".repeat(64),
      uid: 0,
      mode: 384,
      links: 1,
    },
  });
  const result = await collectBackupV2ProtectedReferences(input, {
    references: () => Promise.resolve([ref("data")]),
    roleReferences: () => Promise.resolve([ref("data")]),
  }, [{ object: ref("receipt", "receipt"), plaintextSha256: "4".repeat(64) }]);
  assert(result.pruneEnabled === false);
  assert(result.objects.length === 5);
  assert(result.unresolvedNames[0] === name);
});
Deno.test("v2 protection refuses unreadable graphs conflicting identities and foreign namespaces", async () => {
  const input = empty();
  input.acceptedRoots.push(manifest("root"));
  await rejects(() =>
    collectBackupV2ProtectedReferences(input, {
      references: () => Promise.reject(new Error("unreadable")),
      roleReferences: () => Promise.resolve([]),
    }, [])
  );
  const conflicts = empty();
  conflicts.activeObjects.push(ref("same"), {
    ...ref("same"),
    sha256: "f".repeat(64),
  });
  await rejects(() =>
    collectBackupV2ProtectedReferences(conflicts, {
      references: () => Promise.resolve([]),
      roleReferences: () => Promise.resolve([]),
    }, [])
  );
  const foreign = empty();
  foreign.activeObjects.push({
    ...ref("foreign"),
    fileName: "restic/direct-v1/unrelated",
  });
  await rejects(() =>
    collectBackupV2ProtectedReferences(foreign, {
      references: () => Promise.resolve([]),
      roleReferences: () => Promise.resolve([]),
    }, [])
  );
});
