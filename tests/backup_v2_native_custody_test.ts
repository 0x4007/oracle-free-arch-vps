import {
  type BackupV2NativeChild,
  type BackupV2NativeCustodyRecord,
  backupV2NativeMain,
  parseBackupV2NativeCustody,
} from "../scripts/backup-v2-native-custody.ts";
import {
  type BackupV2Request,
  backupV2RequestSha256,
  validateBackupV2Gate,
} from "../scripts/backup-v2-runtime-contract.ts";
import {
  GATE_BACKUP_CGROUP_ROOT,
  GATE_OWNER,
  GATE_REMOTE_HOST,
  GATE_SOURCE_LOCK_PATH,
} from "../scripts/backblaze-controller-contract.ts";
import { BACKUP_V2_PROFILE_ID } from "../scripts/backup-v2-profile.ts";
const id = "00000000-0000-4000-8000-000000000001",
  other = "00000000-0000-4000-8000-000000000002";
const request: BackupV2Request = {
  schemaVersion: 2,
  format: "backup-v2",
  profile: BACKUP_V2_PROFILE_ID,
  jobId: `job-${id}`,
  captureId: `generation-${id}`,
  periodKey: "2026-10-18",
  requestedAtUtc: "2026-10-18T10:00:00.000Z",
  sourceRevision: "a".repeat(40),
  sourceConfigSha256: "a".repeat(64),
  recipientSha256: "b".repeat(64),
  recipientFingerprint: "C".repeat(40),
};
const unitName = `arch-vps-b2-v2-worker-${id}-${other}.service`;
const gate = validateBackupV2Gate({
  schemaVersion: 2,
  format: "backup-v2",
  owner: GATE_OWNER,
  envelope: { request, requestSha256: backupV2RequestSha256(request) },
  gateId: other,
  sourceBootId: id,
  kind: "worker",
  unitName,
  custody: {
    unitName,
    invocationId: "1".repeat(32),
    mainPid: 101,
    mainStartTicks: "123",
    cgroup: `${GATE_BACKUP_CGROUP_ROOT}/${unitName}`,
  },
  state: "ACTIVE",
  remoteHost: GATE_REMOTE_HOST,
  sourceLockPath: GATE_SOURCE_LOCK_PATH,
  createdAtUtc: request.requestedAtUtc,
  updatedAtUtc: request.requestedAtUtc,
});
const bound: BackupV2NativeCustodyRecord = {
  type: "BOUND",
  schemaVersion: 1,
  gate,
};
const identity: BackupV2NativeChild = {
  pid: 102,
  startTicks: "124",
  bootId: id,
  cgroup: gate.custody!.cgroup,
  kind: "gpg",
};
const unit: BackupV2NativeCustodyRecord = {
  type: "MOUNT",
  namespace: {
    scope: "UNIT",
    leader: backupV2NativeMain(gate),
    device: "4",
    inode: "1000",
    hostDevice: "4",
    hostInode: "1000",
  },
};
const bytes = (records: unknown[]) =>
  new TextEncoder().encode(
    records.map((r) => JSON.stringify(r)).join("\n") + "\n",
  );
function assert(value: unknown): asserts value {
  if (!value) throw Error("Assertion failed");
}
function rejects(run: () => unknown) {
  let failed = false;
  try {
    run();
  } catch {
    failed = true;
  }
  assert(failed);
}
Deno.test("native custody preserves incomplete facts and requires explicit host-shared namespace evidence", () => {
  const incomplete = parseBackupV2NativeCustody(bytes([bound]), gate);
  assert(incomplete.mounts.length === 0 && !incomplete.noPrivateMountProved);
  const active = parseBackupV2NativeCustody(
    bytes([bound, unit, { type: "CHILD", identity }]),
    gate,
  );
  assert(active.children[0].exit === null && !active.noPrivateMountProved);
  const done = parseBackupV2NativeCustody(
    bytes([bound, unit, { type: "CHILD", identity }, {
      type: "EXIT",
      identity,
      code: 0,
      signal: null,
    }, { type: "NO_PRIVATE_MOUNT" }]),
    gate,
  );
  assert(done.children[0].exit?.code === 0 && done.noPrivateMountProved);
  const later = parseBackupV2NativeCustody(bytes([bound, unit]), {
    ...gate,
    updatedAtUtc: "2026-10-18T10:01:00.000Z",
  });
  assert(later.gate.updatedAtUtc === gate.updatedAtUtc);
  rejects(() =>
    parseBackupV2NativeCustody(
      bytes([bound, { type: "NO_PRIVATE_MOUNT" }]),
      gate,
    )
  );
});
Deno.test("private producer namespaces bind actual born leaders before exit and never become synthetic none", () => {
  const leader = { ...identity, kind: "unshare" as const },
    mount = {
      type: "MOUNT",
      namespace: {
        scope: "PRODUCER",
        leader,
        device: "4",
        inode: "1001",
        hostDevice: "4",
        hostInode: "1000",
      },
    };
  const pending = parseBackupV2NativeCustody(
    bytes([bound, unit, { type: "CHILD", identity: leader }]),
    gate,
  );
  assert(pending.unresolvedNamespaceLeaders.length === 1);
  rejects(() =>
    parseBackupV2NativeCustody(
      bytes([bound, unit, { type: "CHILD", identity: leader }, {
        type: "NO_PRIVATE_MOUNT",
      }]),
      gate,
    )
  );
  const recorded = parseBackupV2NativeCustody(
    bytes([bound, unit, { type: "CHILD", identity: leader }, mount, {
      type: "EXIT",
      identity: leader,
      code: 0,
      signal: null,
    }]),
    gate,
  );
  assert(
    recorded.mounts.length === 2 &&
      recorded.unresolvedNamespaceLeaders.length === 0 &&
      !recorded.noPrivateMountProved,
  );
  rejects(() => parseBackupV2NativeCustody(bytes([bound, unit, mount]), gate));
  rejects(() =>
    parseBackupV2NativeCustody(
      bytes([bound, unit, { type: "CHILD", identity: leader }, {
        type: "EXIT",
        identity: leader,
        code: 0,
        signal: null,
      }, mount]),
      gate,
    )
  );
});
Deno.test("unit-private namespaces are recorded even when no unshare producer exists", () => {
  const privateUnit = {
    type: "MOUNT",
    namespace: { ...unit.namespace, inode: "1002" },
  };
  const value = parseBackupV2NativeCustody(bytes([bound, privateUnit]), gate);
  assert(
    value.mounts[0].inode !== value.mounts[0].hostInode &&
      !value.noPrivateMountProved,
  );
  rejects(() =>
    parseBackupV2NativeCustody(
      bytes([bound, privateUnit, { type: "NO_PRIVATE_MOUNT" }]),
      gate,
    )
  );
});
Deno.test("native custody rejects foreign identities, unframed tails, duplicate facts and invented closure", () => {
  const born = { type: "CHILD", identity },
    exit = { type: "EXIT", identity, code: 0, signal: null };
  for (
    const records of [
      [bound, born, born],
      [bound, exit],
      [bound, born, exit, exit],
      [bound, { type: "CHILD", identity: { ...identity, bootId: other } }],
      [bound, { type: "COMPLETE", escapedProcesses: 0 }],
    ]
  ) rejects(() => parseBackupV2NativeCustody(bytes(records), gate));
  const encoded = bytes([bound, born]);
  rejects(() =>
    parseBackupV2NativeCustody(encoded.subarray(0, encoded.length - 1), gate)
  );
});
